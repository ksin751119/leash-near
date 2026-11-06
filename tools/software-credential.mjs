#!/usr/bin/env node
// A SOFTWARE P-256 credential, for driving a deployment from a shell.
//
//   node tools/software-credential.mjs keygen <key-file>
//       writes a private JWK to <key-file> (mode 600) and prints the `register_credential` args
//   node tools/software-credential.mjs sign <key-file> <challenge-base64>
//       prints an assertion in the shape `set_rule` / `withdraw` take, signed over that challenge
//
// The contract cannot tell this from a hardware passkey, which is why only the FIRST
// `register_credential` is admin-alone and every later one needs a signature from a registered one. Use it for shakedowns and tests; a real demo registers a real device credential
// (tools/capture-assertion.html). Keep <key-file> outside the repo: it is a private key.

import { createHash, webcrypto } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [cmd, keyFile, challengeB64] = process.argv.slice(2);
const sha256 = (b) => createHash("sha256").update(b).digest();
const b64 = (b) => Buffer.from(b).toString("base64");
const b64url = (b) => Buffer.from(b).toString("base64url");
const ALG = { name: "ECDSA", namedCurve: "P-256" };

// WebCrypto signs as raw r||s; the contract wants DER.
function derInt(x) {
  let i = 0;
  while (i < x.length - 1 && x[i] === 0) i++;
  let body = Buffer.from(x.subarray(i));
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}
const derSig = (raw) => {
  const body = Buffer.concat([derInt(raw.subarray(0, 32)), derInt(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
};

const uncompressed = (jwk) =>
  Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
const credentialId = (jwk) => sha256(uncompressed(jwk)).subarray(0, 16);

if (cmd === "keygen" && keyFile) {
  const pair = await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  writeFileSync(keyFile, JSON.stringify(jwk), { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify({ id: b64(credentialId(jwk)), pubkey_sec1: b64(uncompressed(jwk)) }));
} else if (cmd === "sign" && keyFile && challengeB64) {
  const jwk = JSON.parse(readFileSync(keyFile, "utf8"));
  const challenge = Buffer.from(challengeB64, "base64");
  if (challenge.length !== 32) throw new Error(`challenge is ${challenge.length} bytes, expected 32`);
  const key = await webcrypto.subtle.importKey("jwk", jwk, ALG, false, ["sign"]);
  // rpIdHash ‖ flags (UP|UV) ‖ signCount, 37 bytes; the contract reads only the UV bit.
  const authData = Buffer.concat([sha256("leash.local"), Buffer.from([0x05]), Buffer.alloc(4)]);
  const clientData = JSON.stringify({
    type: "webauthn.get",
    challenge: b64url(challenge),
    origin: "https://leash.local",
    crossOrigin: false,
  });
  const message = Buffer.concat([authData, sha256(Buffer.from(clientData, "utf8"))]);
  const raw = Buffer.from(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message));
  console.log(
    JSON.stringify({
      credential_id: b64(credentialId(jwk)),
      authenticator_data: b64(authData),
      client_data_json: clientData,
      signature_der: b64(derSig(raw)),
    }),
  );
} else {
  console.error("usage: software-credential.mjs keygen <key-file> | sign <key-file> <challenge-base64>");
  process.exit(2);
}
