// Sending one `spend`, signed here, as the agent's own account, through the same endpoint list and
// failover as every view (rpcPost in chain.mjs). No near-cli: it sends through whatever RPC its own
// config names, which this project does not control, and a 429 there is exactly the failure the
// call budget in chain.mjs exists to prevent.
//
// The function-call key lives on AGENT_ACCOUNT with the wallet as receiver and only `spend`
// allowed: the contract derives the budget from the caller's id, so the transaction's signer
// must be the agent account itself. 60 TGas, because spend needs ~40 and 30 fails; zero deposit,
// because a function-call key cannot attach one. The key file is read here and never logged.
//
// `spend` never panics on a policy refusal: the transaction succeeds, no money moves, and the
// outcome is in the return value (and, authoritatively, on chain). So a successful transaction
// says nothing about whether anyone was paid.
//
// Every way this can end is named, because on camera "the chain refused it" and "we could not
// reach the chain" are very different statements (SendError.kind):
//   not-sent     nothing was sent, and we know it: the chain could not be reached before sending,
//                or no endpoint knows the transaction after every broadcast failed.
//   rejected     an endpoint refused the transaction before running it (bad nonce, key not found,
//                allowance used up). No money moved.
//   chain-failed the transaction ran and failed (e.g. out of gas): rolled back, nothing recorded.
//   unconfirmed  it was sent but we could not confirm what became of it. It may still land.
import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { rpcPost, AllEndpointsFailed } from "./chain.mjs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  let n = 0n;
  for (const c of s) {
    const v = B58.indexOf(c);
    if (v < 0) throw new Error("not base58");
    n = n * 58n + BigInt(v);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const zeros = s.length - s.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(zeros), body]);
}
export function b58encode(buf) {
  let n = BigInt("0x" + (buf.toString("hex") || "0"));
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of buf) { if (b === 0) out = "1" + out; else break; }
  return out;
}

// --- borsh, only the shapes a function-call transaction needs ---------------------------------
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u128 = (n) => { const b = Buffer.alloc(16); b.writeBigUInt64LE(BigInt(n) & 0xffffffffffffffffn); b.writeBigUInt64LE(BigInt(n) >> 64n, 8); return b; };
const str = (s) => { const b = Buffer.from(s, "utf8"); return Buffer.concat([u32(b.length), b]); };

// Transaction { signer_id, public_key, nonce, receiver_id, block_hash, actions: [FunctionCall] }
export function encodeTransaction({ signer, publicKey, nonce, receiver, blockHash, method, args, gas, deposit = 0n }) {
  const argBytes = Buffer.from(args, "utf8");
  return Buffer.concat([
    str(signer),
    Buffer.from([0]), publicKey,            // KeyType::ED25519 + 32 bytes
    u64(nonce),
    str(receiver),
    blockHash,                              // 32 bytes
    u32(1),                                 // one action
    Buffer.from([2]),                       // Action::FunctionCall
    str(method), u32(argBytes.length), argBytes, u64(gas), u128(deposit),
  ]);
}

export function signTransaction(txBytes, seed) {
  const hash = createHash("sha256").update(txBytes).digest();
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const signature = edSign(null, hash, key);
  return {
    txHash: b58encode(hash),
    signedBase64: Buffer.concat([txBytes, Buffer.from([0]), signature]).toString("base64"), // KeyType + 64 bytes
  };
}

export class SendError extends Error {
  constructor(kind, message, txHash = null) { super(message); this.kind = kind; this.txHash = txHash; }
}

export function readKeyFile(path) {
  const j = JSON.parse(readFileSync(path, "utf8"));
  const raw = b58decode(String(j.private_key).replace(/^ed25519:/, ""));
  if (raw.length !== 64) throw new Error("key file: expected a 64-byte ed25519 key");
  return { seed: raw.subarray(0, 32), publicKey: raw.subarray(32), publicKeyString: j.public_key };
}

const rpc = (method, params, opts) => rpcPost({ jsonrpc: "2.0", id: 1, method, params }, opts);

// What spend returned, from the transaction's final status. null when it is not JSON with a status.
export function outcomeOf(status) {
  try {
    const v = JSON.parse(Buffer.from(status.SuccessValue, "base64").toString("utf8"));
    return v && typeof v.status === "string" ? v : null;
  } catch { return null; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Ask the chain about one exact transaction. "unknown" means an endpoint that answered does not know
// it, which can simply mean that endpoint is behind: it never proves the transaction did not land.
export async function lookupTx({ hash, agent, rpcOpts = {} }) {
  try {
    const r = await rpc("tx", { tx_hash: hash, sender_account_id: agent, wait_until: "FINAL" }, rpcOpts);
    if (r.result) return { state: "found", result: r.result };
    return { state: r.error?.cause?.name === "UNKNOWN_TRANSACTION" ? "unknown" : "unreachable" };
  } catch { return { state: "unreachable" }; }
}

// A finished transaction as a lastAction patch: the contract's own outcome, or a chain failure.
export function describeResult(result) {
  const status = result?.status ?? {};
  if (status.Failure) {
    return { status: "error", errorKind: "chain-failed", reason: `the chain ran the transaction and it failed: ${JSON.stringify(status.Failure).slice(0, 220)}` };
  }
  const o = outcomeOf(status);
  if (o) return { status: o.status, code: o.code ?? null, reason: o.reason ?? null, errorKind: null };
  return { status: "unknown", errorKind: "unconfirmed", reason: "the transaction finished but its result could not be read" };
}

// An error from the broadcast that holds whatever any endpoint's view of the chain, as opposed to
// one ("InvalidNonce": that nonce is used, maybe by this very transaction) that is evidence the
// transaction landed. Only the first kind can support the word "rejected".
const definitelyInvalid = (error) =>
  error?.cause?.name === "INVALID_TRANSACTION" && !/InvalidNonce/.test(JSON.stringify(error.data ?? ""));

export async function sendSpend({ wallet, agent, keyFile, token, payee, amount, rpcOpts = {}, pollMs = 2000, onSigned = () => {} }) {
  const { seed, publicKey, publicKeyString } = readKeyFile(keyFile);

  // 1. A nonce and a recent block hash. Nothing has been sent yet, so any failure here is certain.
  let nonce, blockHash;
  try {
    const [k, blk] = await Promise.all([
      rpc("query", { request_type: "view_access_key", finality: "optimistic", account_id: agent, public_key: publicKeyString }, rpcOpts),
      rpc("block", { finality: "final" }, rpcOpts),
    ]);
    if (k.error || k.result?.error) throw new SendError("rejected", `cannot read this agent's key on chain: ${JSON.stringify(k.error ?? k.result.error).slice(0, 160)}`);
    nonce = BigInt(k.result.nonce) + 1n;
    blockHash = b58decode(blk.result.header.hash);
  } catch (e) {
    if (e instanceof SendError) throw e;
    throw new SendError("not-sent", `could not reach the chain to prepare the payment, so nothing was sent (${String(e.message ?? e).slice(0, 160)})`);
  }

  const tx = encodeTransaction({
    signer: agent, publicKey, nonce, receiver: wallet, blockHash, method: "spend",
    args: JSON.stringify({ token, payee, amount: String(amount) }), gas: 60_000_000_000_000n,
  });
  const { txHash, signedBase64 } = signTransaction(tx, seed);
  onSigned(txHash); // the hash exists from here; the caller records it before anything is broadcast

  // 2. Broadcast. From this point no failure may be named from the broadcast alone: the same
  //    signed transaction may have been included by an endpoint that then timed out, and a second
  //    endpoint answers that with InvalidNonce. So an unclean broadcast is followed by looking
  //    the hash up, and only the lookup, or a broadcast error that no endpoint's lag can explain,
  //    decides what the screen says. When in doubt: SENT · NOT CONFIRMED, never a stronger claim.
  let result = null, broadcastError = null;
  try {
    const r = await rpc("send_tx", { signed_tx_base64: signedBase64, wait_until: "FINAL" }, { ...rpcOpts, timeoutMs: 45_000 });
    if (r.result) result = r.result; else broadcastError = r.error ?? null;
  } catch (e) {
    if (!(e instanceof AllEndpointsFailed)) throw e;
  }

  for (let i = 0; !result && i < 5; i++) {
    const l = await lookupTx({ hash: txHash, agent, rpcOpts });
    if (l.state === "found") result = l.result;
    else await sleep(pollMs);
  }
  if (!result) {
    if (definitelyInvalid(broadcastError)) {
      throw new SendError("rejected", `the network refused the transaction before running it: ${JSON.stringify(broadcastError.data ?? broadcastError.cause?.name).slice(0, 200)}`, txHash);
    }
    throw new SendError("unconfirmed", "sent, but the chain could not confirm what became of it; it may still land", txHash);
  }

  // 3. Finished. A Failure here ran and rolled back; a SuccessValue may still be a refusal.
  if (result.status?.Failure) {
    throw new SendError("chain-failed", `the chain ran the transaction and it failed: ${JSON.stringify(result.status.Failure).slice(0, 220)}`, txHash);
  }
  return { txHash: result.transaction_outcome?.id ?? txHash, outcome: outcomeOf(result.status ?? {}) };
}
