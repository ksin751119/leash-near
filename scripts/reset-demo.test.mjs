// Runs scripts/reset-demo.sh with a fake near-cli (scripts/fake-near.mjs) whose chain enforces
// the passkey gate the way the contract does. What is under test is the plan: how many face
// scans a reset costs from each starting state, that a tightening is never prompted, that a
// stale or wrong assertion is never used, and that a wait says what it is waiting for.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as F from "./fake-rpc.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "reset-"));
const bin = join(dir, "bin");
mkdirSync(bin);
writeFileSync(join(bin, "near"), `#!/bin/sh\nexec node ${join(root, "scripts/fake-near.mjs")} "$@"\n`);
chmodSync(join(bin, "near"), 0o755);
const depFile = join(dir, "deployment.json");
const vendorFile = join(dir, "vendors.json");
writeFileSync(depFile, JSON.stringify(F.deployment));
writeFileSync(vendorFile, JSON.stringify(F.vendors));

const target = () => ({ ...F.scriptedRule(), payees: [F.PAY1, F.PAY2].sort() });
let seq = 0;

// Starts a reset against a world. `onChallenge(challenge, k)` is the person: called each time the
// script prints a challenge, it may write the assertion file (or not).
async function reset({ rec, ids = [F.REAL], env = {}, onChallenge = () => {} }) {
  const d = join(dir, `run${seq++}`);
  mkdirSync(d);
  const worldFile = join(d, "world.json");
  const assertions = join(d, "assertions");
  writeFileSync(worldFile, JSON.stringify({ ids, nonce: 1, rec, calls: [] }).replaceAll("18446744073709552000", "18446744073709551615"));
  const child = spawn("bash", [join(root, "scripts/reset-demo.sh"), "testnet", assertions], {
    cwd: root,
    env: { PATH: `${bin}:${process.env.PATH}`, HOME: process.env.HOME, FAKE_NEAR_WORLD: worldFile, LEASH_DEPLOYMENT: depFile, AGENT_VENDORS: vendorFile, ...env },
  });
  let out = "", err = "";
  let scans = 0;
  child.stdout.on("data", (c) => {
    out += c;
    for (const m of String(c).matchAll(/challenge: (\S+)/g)) { scans += 1; onChallenge(m[1], { assertions, scans }); }
  });
  child.stderr.on("data", (c) => (err += c));
  const code = await new Promise((ok) => child.on("close", ok));
  return { code, out, err, world: JSON.parse(readFileSync(worldFile, "utf8").replaceAll("18446744073709551615", "18446744073709552000")), assertions };
}

// The person: signs whatever challenge was printed, as the assertion file the capture tool makes.
const sign = (challenge, { assertions }, over = {}) => {
  mkdirSync(assertions, { recursive: true });
  const client = { type: "webauthn.get", challenge: Buffer.from(challenge, "base64").toString("base64url") };
  writeFileSync(join(assertions, `${F.NODE}.json`), JSON.stringify({
    credential_id: F.REAL, authenticator_data: "AA==", client_data_json: JSON.stringify(client), signature_der: "AA==", ...over }));
};
const rec = (over = {}, spent = "0") => ({ rule: { ...target(), ...over }, spent });

test("no rule yet: one face scan, then the scripted rule with nothing spent", async () => {
  const r = await reset({ rec: null, onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /plan: 1 set_rule call\(s\), 1 of them need a face scan/);
  assert.match(r.out, /FACE SCAN 1 of 1/);
  assert.deepEqual(r.world.calls.map((c) => c.gated), [true]);
  assert.deepEqual(r.world.rec.rule, target());
  assert.equal(r.world.rec.spent, "0");
  assert.ok(existsSync(join(r.assertions, `${F.NODE}.json.used`)), "the assertion is renamed .used");
  assert.ok(!existsSync(join(r.assertions, `${F.NODE}.json`)));
});

test("already in the scripted state: nothing is sent and nobody is asked for anything", async () => {
  const r = await reset({ rec: rec() });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /Nothing to do/);
  assert.equal(r.world.calls.length, 0);
});

test("scripted rule but money spent: a widening to reopen the window, then a tightening with no prompt", async () => {
  const r = await reset({ rec: rec({}, "1500000"), onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /plan: 2 set_rule call\(s\), 1 of them need a face scan/);
  assert.deepEqual(r.world.calls.map((c) => [c.gated, c.assertion]), [[true, true], [false, false]]);
  assert.equal(r.world.calls[0].rule.period_limit, "2000001", "one unit looser than the target");
  assert.deepEqual(r.world.rec.rule, target());
  assert.equal(r.world.rec.spent, "0");
});

test("the live testnet state (a looser rule, 1.60 spent) resets with one face scan", async () => {
  const live = rec({ period_limit: "5000000" }, "1600000");
  const r = await reset({ rec: live, onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  const first = r.world.calls[0].rule;
  assert.equal(first.period_limit, "5000001");
  assert.deepEqual([...first.payees].sort(), [F.PAY1, F.PAY2].sort(), "the bump already lists the payee the target adds");
  assert.deepEqual(r.world.calls.map((c) => c.gated), [true, false]);
  assert.deepEqual(r.world.rec.rule, target());
  assert.equal(r.world.rec.spent, "0");
});

test("a payee the node lacks is a loosening, so the one gated step also reopens the window", async () => {
  const r = await reset({ rec: rec({ period_limit: "5000000", payees: [F.PAY1] }, "1600000"), onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.world.calls.map((c) => c.gated), [true]);
  assert.deepEqual(r.world.rec.rule, target());
  assert.equal(r.world.rec.spent, "0");
});

test("a looser scripted rule is a single widening", async () => {
  const r = await reset({ rec: rec({ period_limit: "1000000" }, "0"), onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.world.calls.map((c) => c.gated), [true]);
});

test("a tighter scripted rule and nothing spent is a tightening: no face scan", async () => {
  const r = await reset({ rec: rec({ period_limit: "9000000" }, "0") });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /0 of them need a face scan|1 set_rule call\(s\), 0 of them/);
  assert.deepEqual(r.world.calls.map((c) => c.gated), [false]);
});

test("a paused node is unpaused by a gated step, because unpausing is a loosening", async () => {
  const r = await reset({ rec: rec({ paused: true }, "0"), onChallenge: sign });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.world.calls.map((c) => c.gated), [true]);
  assert.equal(r.world.rec.rule.paused, false);
});

test("an assertion that signed a different challenge is set aside and never sent", async () => {
  const r = await reset({ rec: null, env: { WAIT_TIMEOUT: "3" },
    onChallenge: (c, k) => sign(Buffer.from("some other rule").toString("base64"), k) });
  assert.equal(r.code, 1);
  assert.match(r.err, /signed a different challenge/);
  assert.match(r.err, /gave up after 3s waiting for the face scan/);
  assert.equal(r.world.calls.length, 0);
  assert.ok(existsSync(join(r.assertions, `${F.NODE}.json.wrong`)));
});

test("a stale assertion left in the directory is moved aside, not reused", async () => {
  const d = join(dir, "stale-run");
  const r = await reset({ rec: null, env: { WAIT_TIMEOUT: "2" }, onChallenge: () => {} });
  assert.equal(r.code, 1);
  assert.match(r.err, /gave up after 2s/);
  assert.equal(r.world.calls.length, 0, "nothing was sent without a signature");
  // second run into the same directory, with a file already there
  const assertions = r.assertions;
  writeFileSync(join(assertions, `${F.NODE}.json`), JSON.stringify({ old: true }));
  const worldFile = join(assertions, "..", "world.json");
  const child = spawn("bash", [join(root, "scripts/reset-demo.sh"), "testnet", assertions], {
    cwd: root, env: { PATH: `${bin}:${process.env.PATH}`, HOME: process.env.HOME, FAKE_NEAR_WORLD: worldFile, LEASH_DEPLOYMENT: depFile, AGENT_VENDORS: vendorFile, WAIT_TIMEOUT: "2" } });
  let out = ""; child.stdout.on("data", (c) => (out += c));
  await new Promise((ok) => child.on("close", ok));
  assert.match(out, /moved an existing .* aside to .*\.stale/);
  assert.ok(existsSync(join(assertions, `${F.NODE}.json.stale`)));
});

test("a wait says what it is waiting for and for how long", async () => {
  const r = await reset({ rec: null, env: { WAIT_TIMEOUT: "11" } });
  assert.equal(r.code, 1);
  assert.match(r.out, /FACE SCAN 1 of 1/);
  assert.match(r.out, /open tools\/capture-assertion\.html/);
  assert.match(r.out, /save the JSON it prints as: .*leash-bud-test\.testnet\.json/);
  assert.match(r.out, /still waiting for the face scan 1\/1 .*: 10s of 11s/);
});

test("a rejected set_rule keeps the assertion out of reuse and fails loudly", async () => {
  const r = await reset({ rec: null, onChallenge: (c, k) => sign(c, k, { credential_id: "someone-else==" }) });
  assert.equal(r.code, 1);
  assert.match(r.err, /set_rule \(step 1\) failed/);
  assert.ok(existsSync(join(r.assertions, `${F.NODE}.json.failed`)));
  assert.equal(r.world.calls.length, 0);
});

test("two credentials need CREDENTIAL_ID; a CREDENTIAL_ID that is not registered is refused", async () => {
  let r = await reset({ rec: null, ids: [F.REAL, F.SOFT] });
  assert.equal(r.code, 1);
  assert.match(r.err, /2 credentials are registered .* set CREDENTIAL_ID/);
  r = await reset({ rec: null, ids: [F.REAL, F.SOFT], env: { CREDENTIAL_ID: "nope==" } });
  assert.equal(r.code, 1);
  assert.match(r.err, /CREDENTIAL_ID nope== is not registered/);
  r = await reset({ rec: null, ids: [] });
  assert.equal(r.code, 1);
  assert.match(r.err, /no credential is registered/);
});

test("bad usage fails before anything is read", async () => {
  const child = spawn("bash", [join(root, "scripts/reset-demo.sh"), "devnet"], { cwd: root, env: { PATH: `${bin}:${process.env.PATH}` } });
  let err = ""; child.stderr.on("data", (c) => (err += c));
  const code = await new Promise((ok) => child.on("close", ok));
  assert.equal(code, 1);
  assert.match(err, /unknown network 'devnet'/);
});

test("demo beat 4: widening costs one face scan and refills the ledger, coming back down costs none", async () => {
  const up = await reset({ rec: rec({}, "2000000"), env: { PERIOD_LIMIT: "3000000" }, onChallenge: sign });
  assert.equal(up.code, 0, up.out + up.err);
  assert.deepEqual(up.world.calls.map((c) => c.gated), [true]);
  assert.equal(up.world.rec.rule.period_limit, "3000000");
  assert.equal(up.world.rec.spent, "0", "an accepted widening opens a fresh window");
  const down = await reset({ rec: up.world.rec });
  assert.equal(down.code, 0, down.out + down.err);
  assert.match(down.out, /plan: 1 set_rule call\(s\), 0 of them need a face scan/);
  assert.deepEqual(down.world.calls.map((c) => [c.gated, c.assertion]), [[false, false]]);
  assert.deepEqual(down.world.rec.rule, target());
});

test("a PERIOD_LIMIT that is not a whole number is refused before anything is sent", async () => {
  const r = await reset({ rec: rec(), env: { PERIOD_LIMIT: "3.00" } });
  assert.equal(r.code, 1);
  assert.match(r.err, /PERIOD_LIMIT must be a whole number of base units/);
  assert.equal(r.world.calls.length, 0);
});
