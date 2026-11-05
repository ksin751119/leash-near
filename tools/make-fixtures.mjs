#!/usr/bin/env node
// Generates the byte-exact WebAuthn assertion fixtures the contract's unit tests and the
// sandbox gas test read. Run it from anywhere:
//
//   node tools/make-fixtures.mjs
//
// Why generated and not captured from a browser: the unit tests must run headless in CI.
// `tools/capture-assertion.html` produces the same JSON shape from a real phone, so a real
// capture is a drop-in replacement for any of these files.
//
// Fully deterministic. The private key is derived from a fixed label, and `k` is derived
// from the message, so re-running this script rewrites the fixtures byte for byte and
// `git diff` stays empty. That is the point: a fixture change should be a deliberate
// change, visible in review.
//
// The ECDSA is hand-rolled on BigInt rather than taken from WebCrypto because WebCrypto's
// `sign` picks `k` at random, which would make every regeneration a diff. Every signature
// produced here is checked against WebCrypto's `verify` before it is written out, so the
// hand-rolled maths cannot quietly emit a bad fixture.
//
// The key material below is a TEST key. It is derived from a public string, it is in a
// public repo, and it protects nothing.

import { createHash, webcrypto } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// P-256 (secp256r1) group arithmetic, affine coordinates.
// ---------------------------------------------------------------------------

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const G = [
  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
];

const mod = (x, m = P) => ((x % m) + m) % m;

/** Modular inverse by the extended Euclidean algorithm. */
function inv(x, m = P) {
  let [r0, r1] = [mod(x, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}

/** Point addition; `null` is the point at infinity. */
function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const l =
    x1 === x2 && y1 === y2
      ? mod((3n * x1 * x1 + A) * inv(2n * y1))
      : mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}

function pointMul(k, p) {
  let acc = null;
  let addend = p;
  while (k > 0n) {
    if (k & 1n) acc = pointAdd(acc, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return acc;
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

const sha256 = (buf) => createHash("sha256").update(buf).digest();
const toBig = (buf) => BigInt("0x" + buf.toString("hex"));

/** 32-byte big-endian encoding of a field element. */
function fe32(x) {
  return Buffer.from(x.toString(16).padStart(64, "0"), "hex");
}

/** base64url, no padding — what WebAuthn uses inside clientDataJSON. */
const b64url = (buf) => buf.toString("base64url");

/** Standard base64 with padding — what near-sdk's Base64VecU8 expects on the wire. */
const b64 = (buf) => buf.toString("base64");

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

const KEY_LABEL = "leash-near webauthn fixture key v1";
const D = mod(toBig(sha256(KEY_LABEL)), N);
if (D === 0n) throw new Error("degenerate test key");
const Q = pointMul(D, G);

/** SEC1 uncompressed: 0x04 ‖ X ‖ Y, 65 bytes. This is what navigator.credentials gives
 *  us after we strip the COSE wrapper, and it is the form the contract is tested with. */
const PUBKEY_UNCOMPRESSED = Buffer.concat([Buffer.from([0x04]), fe32(Q[0]), fe32(Q[1])]);
/** SEC1 compressed: 0x02/0x03 ‖ X, 33 bytes. Emitted so a test can prove the contract
 *  accepts it too — 32 fewer bytes of state per credential. */
const PUBKEY_COMPRESSED = Buffer.concat([
  Buffer.from([Q[1] % 2n === 0n ? 0x02 : 0x03]),
  fe32(Q[0]),
]);

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * ECDSA P-256 over `msgHash` with a deterministic `k`.
 *
 * `k` comes from SHA-256 over a label, a counter and the message hash. That is not
 * RFC 6979 — it does not need to be. Nothing verifies how `k` was chosen; it only has to
 * be fixed so the fixtures are stable, and unpredictable enough that this test key is not
 * leaked by the fixtures themselves.
 *
 * `s` is NOT normalised to the low half of the group. Real authenticators do not
 * normalise, so neither do we.
 */
function signDer(msgHash) {
  const z = toBig(msgHash);
  for (let i = 0; i < 256; i++) {
    const k = mod(
      toBig(sha256(Buffer.concat([Buffer.from("leash-near fixture k v1"), Buffer.from([i]), msgHash]))),
      N,
    );
    if (k === 0n) continue;
    const point = pointMul(k, G);
    const r = mod(point[0], N);
    if (r === 0n) continue;
    const s = mod(inv(k, N) * (z + r * D), N);
    if (s === 0n) continue;
    return { r, s, der: der(r, s), raw: Buffer.concat([fe32(r), fe32(s)]) };
  }
  throw new Error("no usable k");
}

function derInt(x) {
  let hex = x.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let body = Buffer.from(hex, "hex");
  // DER INTEGER is signed, so a leading bit of 1 needs a 0x00 pad byte. Forgetting this
  // is the classic way to produce a signature that half the world rejects.
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

function der(r, s) {
  const body = Buffer.concat([derInt(r), derInt(s)]);
  if (body.length > 127) throw new Error("body too long for a short-form length"); // cannot happen for P-256
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** Independent check: WebCrypto must accept what the BigInt code produced. */
async function assertWebCryptoAccepts(message, raw) {
  const key = await webcrypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: b64url(fe32(Q[0])), y: b64url(fe32(Q[1])), ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await webcrypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    raw,
    message,
  );
  if (!ok) throw new Error("WebCrypto rejected a signature this script produced");
}

// ---------------------------------------------------------------------------
// WebAuthn encoding
// ---------------------------------------------------------------------------

const RP_ID = "leash.local";
const ORIGIN = "https://leash.local";
const CREDENTIAL_ID = sha256("leash-near fixture credential id v1").subarray(0, 16);

const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified (Face ID / fingerprint / device PIN)
const FLAG_AT = 0x40; // attested credential data follows — registration only

/**
 * authenticatorData for an assertion: 32-byte rpIdHash ‖ 1 flag byte ‖ 4-byte
 * big-endian signature counter. 37 bytes exactly; an assertion carries no attested
 * credential data and we request no extensions.
 */
function authenticatorData(flags, signCount) {
  const out = Buffer.alloc(37);
  sha256(RP_ID).copy(out, 0);
  out[32] = flags;
  out.writeUInt32BE(signCount, 33);
  return out;
}

/** The exact shape and key order Chrome and Safari emit. */
function clientDataJson(challenge) {
  return JSON.stringify({
    type: "webauthn.get",
    challenge: b64url(challenge),
    origin: ORIGIN,
    crossOrigin: false,
  });
}

/** What the authenticator actually signs: authenticatorData ‖ SHA-256(clientDataJSON). */
function signedMessage(authData, clientJson) {
  return Buffer.concat([authData, sha256(Buffer.from(clientJson, "utf8"))]);
}

const CHALLENGE_A = sha256("leash-near fixture challenge: rule A");
const CHALLENGE_B = sha256("leash-near fixture challenge: rule B");

/**
 * One fixture. `expectedChallenge` is what the caller will pass to `verify_assertion`;
 * `signedChallenge` is what actually went into clientDataJSON. They differ in exactly one
 * fixture, which is the point of that fixture.
 */
async function fixture({ name, note, flags, signCount, expectedChallenge, signedChallenge }) {
  const authData = authenticatorData(flags, signCount);
  const clientJson = clientDataJson(signedChallenge);
  const message = signedMessage(authData, clientJson);
  const sig = signDer(sha256(message));
  await assertWebCryptoAccepts(message, sig.raw);

  return {
    [name]: {
      // Every byte field is standard base64 so the whole object can be handed straight to
      // `probe_verify` as JSON args.
      note,
      credential_id: b64(CREDENTIAL_ID),
      pubkey_sec1: b64(PUBKEY_UNCOMPRESSED),
      challenge: b64(expectedChallenge),
      authenticator_data: b64(authData),
      client_data_json: clientJson,
      signature_der: b64(sig.der),
      meta: {
        generated_by: "tools/make-fixtures.mjs",
        rp_id: RP_ID,
        origin: ORIGIN,
        flags: `0x${flags.toString(16).padStart(2, "0")}`,
        user_present: Boolean(flags & FLAG_UP),
        user_verified: Boolean(flags & FLAG_UV),
        sign_count: signCount,
        signed_challenge: b64(signedChallenge),
        pubkey_sec1_form: "uncompressed (0x04 ‖ X ‖ Y, 65 bytes)",
        pubkey_sec1_compressed: b64(PUBKEY_COMPRESSED),
        signature_s_is_high: sig.s > N / 2n,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Emit
// ---------------------------------------------------------------------------

const outDir = join(dirname(fileURLToPath(import.meta.url)), "..", "tests-sandbox", "tests", "fixtures");
mkdirSync(outDir, { recursive: true });

const files = [
  await fixture({
    name: "assertion_valid",
    note:
      "A well-formed assertion: user present and user verified, challenge matches. Passing this " +
      "proves that the holder of this credential signed this exact challenge and that the " +
      "authenticator asserted user verification. It does not prove the credential is " +
      "hardware-backed — an assertion carries no attestation at all — so the guarantee is only " +
      "as strong as the registration step. This key is a software key from a generator script, " +
      "which is rather the point: the contract cannot tell, and does not claim to.",
    flags: FLAG_UP | FLAG_UV,
    signCount: 1,
    expectedChallenge: CHALLENGE_A,
    signedChallenge: CHALLENGE_A,
  }),
  await fixture({
    name: "assertion_uv_clear",
    note:
      "UV bit clear (flags 0x01, user present only): the device was touched but no biometric or " +
      "PIN was checked. Signature and challenge are both valid, so the only reason to reject " +
      "this is the missing UV bit.",
    flags: FLAG_UP,
    signCount: 2,
    expectedChallenge: CHALLENGE_A,
    signedChallenge: CHALLENGE_A,
  }),
  await fixture({
    name: "assertion_wrong_challenge",
    note:
      "A genuine assertion over a different rule's challenge (rule B) presented where rule A's " +
      "challenge is expected. This is the replay case: signature and UV bit are both fine.",
    flags: FLAG_UP | FLAG_UV,
    signCount: 3,
    expectedChallenge: CHALLENGE_A,
    signedChallenge: CHALLENGE_B,
  }),
];

for (const file of files) {
  const [name, body] = Object.entries(file)[0];
  const path = join(outDir, `${name}.json`);
  writeFileSync(path, JSON.stringify(body, null, 2) + "\n");
  console.log(`wrote ${path}`);
}

console.log("");
console.log("public key (uncompressed SEC1, hex):", PUBKEY_UNCOMPRESSED.toString("hex"));
console.log("public key (compressed SEC1, hex):  ", PUBKEY_COMPRESSED.toString("hex"));
console.log("challenge A (hex):", CHALLENGE_A.toString("hex"));
console.log("challenge B (hex):", CHALLENGE_B.toString("hex"));
