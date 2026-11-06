import test from "node:test";
import assert from "node:assert/strict";
import { createHash, verify, generateKeyPairSync } from "node:crypto";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { b58decode, b58encode, encodeTransaction, signTransaction, sendSpend, SendError, outcomeOf } from "./send.mjs";

test("base58 round-trips, including leading zero bytes", () => {
  const b = Buffer.from([0, 0, 1, 2, 255, 254, 3]);
  assert.deepEqual(b58decode(b58encode(b)), b);
  assert.equal(b58encode(Buffer.from([0, 0])), "11");
});

test("a transaction encodes to the borsh layout NEAR expects and its signature verifies", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const seed = der.subarray(der.length - 32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const tx = encodeTransaction({ signer: "a.testnet", publicKey: pub, nonce: 7n, receiver: "w.testnet", blockHash: Buffer.alloc(32, 9), method: "spend", args: '{"x":1}', gas: 60_000_000_000_000n });
  // signer_id: u32 length + bytes
  assert.equal(tx.readUInt32LE(0), 9);
  assert.equal(tx.subarray(4, 13).toString(), "a.testnet");
  assert.equal(tx[13], 0); // ED25519
  assert.deepEqual(tx.subarray(14, 46), pub);
  assert.equal(tx.readBigUInt64LE(46), 7n);
  assert.equal(tx.readUInt32LE(54), 9);
  assert.equal(tx.subarray(58, 67).toString(), "w.testnet");
  assert.deepEqual(tx.subarray(67, 99), Buffer.alloc(32, 9));
  assert.equal(tx.readUInt32LE(99), 1); // one action
  assert.equal(tx[103], 2); // FunctionCall
  assert.equal(tx.subarray(108, 113).toString(), "spend");
  assert.equal(tx.length, 103 + 1 + 4 + 5 + 4 + 7 + 8 + 16);
  const { txHash, signedBase64 } = signTransaction(tx, seed);
  const signed = Buffer.from(signedBase64, "base64");
  assert.deepEqual(signed.subarray(0, tx.length), tx);
  assert.equal(signed[tx.length], 0);
  const sig = signed.subarray(tx.length + 1);
  assert.equal(sig.length, 64);
  assert.ok(verify(null, createHash("sha256").update(tx).digest(), publicKey, sig));
  assert.equal(txHash, b58encode(createHash("sha256").update(tx).digest()));
});

test("outcomeOf reads a refusal out of the final status and nothing else", () => {
  const v = Buffer.from('{"status":"refused","code":4,"reason":"r"}').toString("base64");
  assert.equal(outcomeOf({ SuccessValue: v }).code, 4);
  assert.equal(outcomeOf({ SuccessValue: "" }), null);
  assert.equal(outcomeOf({ SuccessValue: Buffer.from("123").toString("base64") }), null);
});

// --- every way a send can end, by its own name ------------------------------------------------

function keyFile() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const path = join(mkdtempSync(join(tmpdir(), "k-")), "k.json");
  writeFileSync(path, JSON.stringify({ public_key: `ed25519:${b58encode(pub)}`, private_key: `ed25519:${b58encode(Buffer.concat([seed, pub]))}` }), { mode: 0o600 });
  return path;
}
const BLOCK = b58encode(Buffer.alloc(32, 5));
const ok = (result) => ({ status: 200, json: async () => ({ result }) });
const err = (error) => ({ status: 200, json: async () => ({ error }) });
const limited = () => ({ status: 429, json: async () => ({ error: { code: -429, message: "rate limited" } }) });
const args = (k) => ({ wallet: "w.testnet", agent: "a.testnet", keyFile: k, token: "t.testnet", payee: "p.testnet", amount: "1", pollMs: 1 });

function net(handlers) {
  process.env.NEAR_RPC = "http://only.test";
  globalThis.fetch = async (_u, init) => {
    const m = JSON.parse(init.body);
    const h = handlers[m.method === "query" ? m.params.request_type : m.method];
    if (!h) throw new Error(`unexpected ${m.method}`);
    return h(m.params);
  };
}
const prep = { view_access_key: () => ok({ nonce: 41 }), block: () => ok({ header: { hash: BLOCK } }) };
const done = (status) => () => ok({ status, transaction_outcome: { id: "TXID" } });
const rejects = async (p, kind) => { try { await p; assert.fail("should have thrown"); } catch (e) { assert.ok(e instanceof SendError, String(e)); assert.equal(e.kind, kind, e.message); return e; } };

test("a refusal is a successful send with the chain's outcome", async () => {
  const v = Buffer.from('{"status":"refused","code":5,"reason":"over"}').toString("base64");
  net({ ...prep, send_tx: done({ SuccessValue: v }) });
  const r = await sendSpend(args(keyFile()));
  assert.equal(r.outcome.code, 5);
  assert.equal(r.txHash, "TXID");
});

test("the chain unreachable before sending is not-sent, with certainty", async () => {
  net({ ...prep, view_access_key: limited, block: limited });
  await rejects(sendSpend(args(keyFile())), "not-sent");
});

test("an endpoint refusing the transaction outright is rejected", async () => {
  net({ ...prep, send_tx: () => err({ cause: { name: "INVALID_TRANSACTION" }, data: { InvalidTxError: "InvalidNonce" } }) });
  const e = await rejects(sendSpend(args(keyFile())), "rejected");
  assert.match(e.message, /InvalidNonce/);
  assert.ok(e.txHash);
});

test("a transaction that ran and failed is chain-failed", async () => {
  net({ ...prep, send_tx: done({ Failure: { ActionError: { kind: "FunctionCallError: Exceeded the prepaid gas" } } }) });
  await rejects(sendSpend(args(keyFile())), "chain-failed");
});

test("a broadcast that times out but landed is found by its hash", async () => {
  const v = Buffer.from('{"status":"allowed"}').toString("base64");
  net({ ...prep, send_tx: () => err({ cause: { name: "TIMEOUT_ERROR" } }), tx: done({ SuccessValue: v }) });
  const r = await sendSpend(args(keyFile()));
  assert.equal(r.outcome.status, "allowed");
});

test("broadcast limited everywhere and the chain says it does not know the hash is not-sent", async () => {
  net({ ...prep, send_tx: limited, tx: () => err({ cause: { name: "UNKNOWN_TRANSACTION" } }) });
  const e = await rejects(sendSpend(args(keyFile())), "not-sent");
  assert.ok(e.txHash);
});

test("broadcast limited and the chain then unreachable is unconfirmed, never not-sent", async () => {
  net({ ...prep, send_tx: limited, tx: limited });
  const e = await rejects(sendSpend(args(keyFile())), "unconfirmed");
  assert.match(e.message, /may still land/);
});
