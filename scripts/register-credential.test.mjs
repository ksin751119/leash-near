// scripts/register-credential.sh against the fake near-cli. The chain it talks to enforces the
// rule the contract does: the first credential is admin-only, every later one needs an assertion
// from one already registered, over exactly the key being added.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as F from "./fake-rpc.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "register-"));
const bin = join(dir, "bin");
mkdirSync(bin);
writeFileSync(join(bin, "near"), `#!/bin/sh\nexec node ${join(root, "scripts/fake-near.mjs")} "$@"\n`);
chmodSync(join(bin, "near"), 0o755);
const depFile = join(dir, "deployment.json");
writeFileSync(depFile, JSON.stringify(F.deployment));
const newCred = { credential_id: "NEWPHONEcredential==", pubkey_sec1: "BAAA", rp_id: "localhost" };
let seq = 0;

async function register({ ids, env = {}, onChallenge, cred = newCred }) {
  const d = join(dir, `run${seq++}`);
  mkdirSync(d);
  const worldFile = join(d, "world.json");
  const credFile = join(d, "cred.json");
  const assertions = join(d, "assertions");
  writeFileSync(worldFile, JSON.stringify({ ids, nonce: 1, rec: null, calls: [] }));
  writeFileSync(credFile, JSON.stringify(cred));
  const child = spawn("bash", [join(root, "scripts/register-credential.sh"), "testnet", credFile, assertions], {
    cwd: root, env: { PATH: `${bin}:${process.env.PATH}`, HOME: process.env.HOME, FAKE_NEAR_WORLD: worldFile, LEASH_DEPLOYMENT: depFile, ...env } });
  let out = "", err = "";
  child.stdout.on("data", (c) => { out += c; for (const m of String(c).matchAll(/challenge:\s+(\S+)/g)) onChallenge?.(m[1], assertions); });
  child.stderr.on("data", (c) => (err += c));
  const code = await new Promise((ok) => child.on("close", ok));
  return { code, out, err, world: JSON.parse(readFileSync(worldFile, "utf8")), assertions };
}
const sign = (challenge, assertions, signer = F.REAL) => {
  mkdirSync(assertions, { recursive: true });
  writeFileSync(join(assertions, "register.json"), JSON.stringify({
    credential_id: signer, authenticator_data: "AA==", signature_der: "AA==",
    client_data_json: JSON.stringify({ type: "webauthn.get", challenge: Buffer.from(challenge, "base64").toString("base64url") }) }));
};

test("the first credential ever is the bootstrap: admin alone, and it says so", async () => {
  const r = await register({ ids: [] });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /BOOTSTRAP/);
  assert.deepEqual(r.world.ids, [newCred.credential_id]);
  assert.deepEqual(r.world.calls, [{ register: newCred.credential_id, assertion: false }]);
});

test("a later credential needs a signature from a registered one, and waits for it saying so", async () => {
  const r = await register({ ids: [F.REAL], onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /the admin key alone cannot add another/);
  assert.deepEqual(r.world.ids, [F.REAL, newCred.credential_id]);
  assert.equal(r.world.calls[0].assertion, true);
  assert.ok(existsSync(join(r.assertions, "register.json.used")));
});

test("nobody signs: nothing is registered, and the wait says for whom and how long", async () => {
  const r = await register({ ids: [F.REAL], env: { WAIT_TIMEOUT: "11" } });
  assert.equal(r.code, 1);
  assert.match(r.out, /still waiting for the signature from .*: 10s of 11s/);
  assert.match(r.err, /Nothing was changed/);
  assert.deepEqual(r.world.ids, [F.REAL]);
});

test("a signature over a different key is set aside and not sent", async () => {
  const r = await register({ ids: [F.REAL], env: { WAIT_TIMEOUT: "3" },
    onChallenge: (c, a) => sign(Buffer.from("some other registration").toString("base64"), a) });
  assert.equal(r.code, 1);
  assert.match(r.err, /signed a different challenge/);
  assert.deepEqual(r.world.ids, [F.REAL]);
  assert.ok(existsSync(join(r.assertions, "register.json.wrong")));
});

test("two registered credentials need CREDENTIAL_ID; an already-registered new one is refused", async () => {
  let r = await register({ ids: [F.REAL, F.SOFT] });
  assert.equal(r.code, 1);
  assert.match(r.err, /set CREDENTIAL_ID/);
  r = await register({ ids: [newCred.credential_id] });
  assert.equal(r.code, 1);
  assert.match(r.err, /already registered/);
});
