#!/usr/bin/env node
// An agent's ed25519 keypair, for scripts/grant-agent-key.sh.
//
//   node tools/agent-keygen.mjs <key-file>
//       writes {"public_key","private_key"} (the near-cli key-file shape agent/loop.mjs reads) to
//       <key-file> (mode 600, never overwrites) and prints ONLY the public key.
//
// Keep <key-file> outside the repo, by convention ~/.leash-testnet/akf-<name>.json.

import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";

const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(buf) {
  let n = BigInt("0x" + buf.toString("hex") || "0");
  let s = "";
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = "1" + s; else break; }
  return s;
}

const [keyFile] = process.argv.slice(2);
if (!keyFile) { console.error("usage: agent-keygen.mjs <key-file>"); process.exit(2); }
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const seed = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32);
const pub = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
const record = { public_key: `ed25519:${b58(pub)}`, private_key: `ed25519:${b58(Buffer.concat([seed, pub]))}` };
writeFileSync(keyFile, JSON.stringify(record), { mode: 0o600, flag: "wx" });
console.log(record.public_key);
