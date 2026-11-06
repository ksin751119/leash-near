// Runs scripts/preflight.sh against a fake chain and fake agent processes. The point of these
// tests is the failing cases: every check must go red, with its reason, when the thing it
// guards is wrong, and none may go green because something was missing or empty.
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as F from "./fake-rpc.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "preflight-"));
const depFile = join(dir, "deployment.json");
const vendorFile = join(dir, "vendors.json");
writeFileSync(depFile, JSON.stringify(F.deployment));
writeFileSync(vendorFile, JSON.stringify(F.vendors));

async function run(mutate = () => {}, { env = {}, agents = {}, noAgents = false } = {}) {
  const world = F.goodWorld();
  mutate(world);
  const rpc = await F.startRpc(world);
  const alpha = noAgents ? null : await F.startAgent(F.ALPHA, agents.alpha);
  const beta = noAgents ? null : await F.startAgent(F.BETA, agents.beta);
  const urls = env.AGENT_URLS ?? `${agents.alphaUrl ?? alpha?.url} ${agents.betaUrl ?? beta?.url}`;
  try {
    return await new Promise((ok) => {
      const child = execFile("bash", [join(root, "scripts/preflight.sh")], {
        cwd: root,
        env: { PATH: process.env.PATH, HOME: process.env.HOME, NEAR_RPC: world.rateLimitFirst ? `${rpc.url},${rpc.url}` : rpc.url, LEASH_DEPLOYMENT: depFile, AGENT_VENDORS: vendorFile,
               AGENT_URLS: urls, REAL_DEVICE_CREDENTIAL_ID: F.REAL, ...env },
      }, (err, stdout, stderr) => ok({ code: err ? err.code : 0, out: stdout, err: stderr }));
      child.stdin?.end();
    });
  } finally {
    for (const s of [rpc.server, alpha?.server, beta?.server]) s?.close();
  }
}
const lines = (r, prefix) => r.out.split("\n").filter((l) => l.startsWith(prefix));
const failing = (r) => lines(r, "FAIL").join("\n") + "\n" + r.out.split("\n").filter((l) => l.startsWith("        ")).join("\n");

test("a deployment in the scripted state passes every check and says how many of each beat fit", async () => {
  const r = await run();
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /READY to record/);
  assert.equal(lines(r, "FAIL").length, 0);
  assert.match(r.out, /beat 1: 1 allowed payment\(s\) fit; beat 3: 3 allowed payment\(s\) fit/);
  assert.match(r.out, /headroom left 2\.00 of 2\.00; the script spends 2\.00/);
  assert.match(r.out, /beat 3  alpha .* expect refused code 6  would be refused code 6/);
  assert.match(r.out, /zero access keys of any kind/);
  assert.match(r.out, /per-tx 1\.00, period 2\.00, payees 2, not paused/, "the numbers it prints are the rule's, not a default");
});

test("a rate-limited endpoint falls over to the next, a missing answer is not a pass", async () => {
  const r = await run((w) => { w.rateLimitFirst = true; });
  // the first call is limited, then every call is answered, and the run is still green
  assert.equal(r.code, 0, r.out + r.err);
});

test("a wallet with ANY key fails, and a wallet whose key list cannot be read fails rather than counting zero", async () => {
  let r = await run((w) => { w.keys[F.WALLET] = [{ public_key: "ed25519:x", access_key: { nonce: 0, permission: "FullAccess" } }]; });
  assert.equal(r.code, 1);
  assert.match(failing(r), /wallet .* has 1 access key/);
  r = await run((w) => { w.keys[F.WALLET] = [{ public_key: "ed25519:x", access_key: { nonce: 0, permission: { FunctionCall: { allowance: "1", receiver_id: F.WALLET, method_names: ["spend"] } } } }]; });
  assert.match(failing(r), /has 1 access key/, "a function-call key on the wallet is also a key");
  r = await run((w) => { w.raw[`keys:${F.WALLET}`] = { error: { code: -32000, message: "boom" } }; });
  assert.equal(r.code, 1);
  assert.match(failing(r), /key list could not be read, so 'no keys' is NOT established/);
  assert.doesNotMatch(r.out, /zero access keys/);
});

test("an agent key is checked for kind, receiver, methods, count and allowance", async () => {
  const cases = [
    ["a full-access key", (w) => { w.keys[F.ALPHA] = [{ public_key: "ed25519:k", access_key: { nonce: 0, permission: "FullAccess" } }]; }, /not a function-call key/],
    ["the wrong receiver", (w) => { w.keys[F.ALPHA][0].access_key.permission.FunctionCall.receiver_id = F.TOKEN; }, /receiver is .*, not the wallet/],
    ["spend plus another method", (w) => { w.keys[F.BETA][0].access_key.permission.FunctionCall.method_names = ["spend", "withdraw"]; }, /methods are \["spend","withdraw"\]/],
    ["no method restriction", (w) => { w.keys[F.BETA][0].access_key.permission.FunctionCall.method_names = []; }, /methods are \[\]/],
    ["a second key", (w) => { w.keys[F.ALPHA].push(w.keys[F.ALPHA][0]); }, /holds 2 keys/],
    ["no key at all", (w) => { w.keys[F.ALPHA] = []; }, /holds 0 keys/],
    ["an allowance too small for the script", (w) => { w.keys[F.ALPHA][0].access_key.permission.FunctionCall.allowance = "10000000000000000000000"; }, /pays for 1 sends at 60 TGas/],
    ["an uncapped allowance", (w) => { w.keys[F.ALPHA][0].access_key.permission.FunctionCall.allowance = null; }, /no allowance cap/],
  ];
  for (const [name, mutate, re] of cases) {
    const r = await run(mutate);
    assert.equal(r.code, 1, name);
    assert.match(failing(r), re, name);
  }
});

test("the rule must be the scripted one, with headroom for exactly the beats", async () => {
  const withRec = (f) => (w) => { w.views[`${F.WALLET}.node_record`] = () => { const rec = { rule: F.scriptedRule(), epoch: 1, version: 1, window_began_ms: Date.now() - 60_000, spent: "0" }; f(rec); return rec; }; };
  let r = await run((w) => { w.views[`${F.WALLET}.node_record`] = () => null; });
  assert.match(failing(r), /no rule is in force/);
  r = await run(withRec((rec) => { rec.spent = "500000"; }));
  assert.equal(r.code, 1);
  assert.match(failing(r), /beat 3  beta .* expect allowed  would be refused code 6.*<-- WRONG/, "half a payment of headroom short fails the beat that needs it");
  r = await run(withRec((rec) => { rec.rule.period_limit = "5000000"; }));
  assert.match(failing(r), /period_limit: on chain "5000000", scripted "2000000"/);
  assert.match(failing(r), /expect refused code 6  would be allowed/, "too much headroom: the period refusal on camera would not happen");
  r = await run(withRec((rec) => { rec.rule.payees = [F.PAY1]; }));
  assert.match(failing(r), /payees: on chain/);
  r = await run(withRec((rec) => { rec.rule.paused = true; }));
  assert.match(failing(r), /paused: on chain true/);
  r = await run(withRec((rec) => { rec.window_began_ms = Date.now() - 86_400_000 + 5 * 60_000; }));
  assert.match(failing(r), /window ends in [0-4] minutes/);
  r = await run((w) => { w.views[`${F.WALLET}.is_paused`] = () => true; });
  assert.match(failing(r), /the account is paused/);
});

test("the token balance: too little, more than was funded, unreadable, and an exact expectation", async () => {
  let r = await run((w) => { w.views[`${F.TOKEN}.ft_balance_of`] = () => "1500000"; });
  assert.match(failing(r), /wallet holds 1\.50 .*the script pays out 2\.00/);
  r = await run((w) => { w.views[`${F.TOKEN}.ft_balance_of`] = () => "900000000"; });
  assert.match(failing(r), /MORE than the 500\.00 recorded as funded/);
  r = await run((w) => { w.raw[`${F.TOKEN}.ft_balance_of`] = { result: { error: "account not registered" } }; });
  assert.match(failing(r), /token balance could not be read/);
  r = await run((w) => { w.raw[`${F.TOKEN}.ft_balance_of`] = { result: { result: [...Buffer.from("not json")], logs: [] } }; });
  assert.match(failing(r), /token balance could not be read/);
  r = await run((w) => { w.views[`${F.TOKEN}.ft_balance_of`] = () => "400000000"; }, { env: { EXPECT_WALLET_BALANCE: "500000000" } });
  assert.match(failing(r), /you said to expect 500\.00/);
  r = await run((w) => { w.views[`${F.TOKEN}.ft_metadata`] = () => ({ decimals: 24 }); });
  assert.match(failing(r), /the token has 24 decimals/);
});

test("an agent process that does not answer is named, and the other is not", async () => {
  const r = await run(() => {}, { agents: { betaUrl: "http://127.0.0.1:1" } });
  assert.equal(r.code, 1);
  assert.match(failing(r), /agent 'beta' did not answer http:\/\/127\.0\.0\.1:1\/state/);
  assert.doesNotMatch(failing(r), /agent 'alpha'/);
  assert.match(r.out, /PASS  agent 'alpha'/);
});

test("an agent running as the wrong account, or whose chain reads are failing, is a failure", async () => {
  let r = await run(() => {}, { agents: { alpha: { agentAddr: F.BETA } } });
  assert.match(failing(r), /agent 'alpha' .* is running as '.*', expected alpha\./);
  r = await run(() => {}, { agents: { beta: { chain: { errors: ["decision_log: 429"] } } } });
  assert.match(failing(r), /agent 'beta' .* chain reads are failing/);
  r = await run(() => {}, { agents: { beta: { chain: {} } } });
  assert.match(failing(r), /agent 'beta' .* chain reads are failing/, "no errors field is not 'no errors'");
});

test("two credentials are required", async () => {
  const r = await run((w) => { w.views[`${F.WALLET}.credential_ids`] = () => [F.REAL]; });
  assert.equal(r.code, 1);
  assert.match(failing(r), /only 1 credential\(s\) registered; need at least 2/);
  assert.match(failing(r), /strands the funds forever/);
});

test("the human gate: unnamed, unregistered, the software credential, never used, and a real use", async () => {
  let r = await run(() => {}, { env: { REAL_DEVICE_CREDENTIAL_ID: "" } });
  assert.equal(r.code, 1);
  assert.match(failing(r), /HUMAN GATE: no real-device credential has been named/);
  r = await run(() => {}, { env: { REAL_DEVICE_CREDENTIAL_ID: "nope==" } });
  assert.match(failing(r), /HUMAN GATE: REAL_DEVICE_CREDENTIAL_ID is not registered/);
  r = await run(() => {}, { env: { REAL_DEVICE_CREDENTIAL_ID: F.SOFT } });
  assert.match(failing(r), /the FIRST credential registered is not the real device/, "naming the software one while the device is first");
  const softFirst = join(dir, "dep-soft-first.json");
  writeFileSync(softFirst, JSON.stringify({ ...F.deployment, credentials: [F.deployment.credentials[1], F.deployment.credentials[0]] }));
  r = await run(() => {}, { env: { LEASH_DEPLOYMENT: softFirst, REAL_DEVICE_CREDENTIAL_ID: F.SOFT } });
  assert.match(failing(r), /recorded in .* as 'SOFTWARE P-256, shakedown only', not as a device/);
  r = await run((w) => { w.views[`${F.WALLET}.credential_nonce`] = () => 0; });
  assert.match(failing(r), /never produced an assertion the chain accepted/);
  r = await run((w) => { w.views[`${F.WALLET}.credential_nonce`] = () => null; });
  assert.match(failing(r), /never produced an assertion|nonce could not be read/, "a null nonce is not 'used'");
  r = await run();
  assert.match(r.out, /PASS  HUMAN GATE: credential .* has had 2 assertion\(s\) verified on chain/);
  assert.match(r.out, /that the device is real is YOUR claim/);
});

test("a credential the deployment file does not describe makes the gate fail, never go quiet", async () => {
  const withDep = async (dep, mutate = () => {}) => {
    const file = join(dir, `dep-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(file, JSON.stringify(dep));
    return run(mutate, { env: { LEASH_DEPLOYMENT: file } });
  };
  // No credential record at all: the software-credential check could never fire.
  const { credentials, ...bare } = F.deployment;
  let r = await withDep(bare);
  assert.equal(r.code, 1);
  assert.match(failing(r), /records no credentials, so the software-credential check cannot fire/);
  assert.doesNotMatch(r.out, /PASS  HUMAN GATE/);
  // A registered credential nobody described.
  r = await withDep(F.deployment, (w) => { w.views[`${F.WALLET}.credential_ids`] = () => [F.REAL, F.SOFT, "MYSTERYcredential=="]; });
  assert.match(failing(r), /does not record, so nobody has said what they are/);
  // A named credential recorded with no kind.
  r = await withDep({ ...F.deployment, credentials: [{ id: F.REAL }, F.deployment.credentials[1]] });
  assert.match(failing(r), /not as a device/);
  // The older single-record form still works, and still demands every registered id be described.
  r = await withDep({ ...bare, credential: F.deployment.credentials[1] });
  assert.match(failing(r), /HUMAN GATE: credentials are registered that .* does not record/);
});

test("whichever single read fails, preflight still finishes, says so, and is not ready", async () => {
  const boom = { result: { error: "boom" } };
  const cases = [
    ["node_record", (w) => { w.raw[`${F.WALLET}.node_record`] = boom; }, /node record .* could not be read/],
    ["is_paused", (w) => { w.raw[`${F.WALLET}.is_paused`] = boom; }, /is_paused could not be read/],
    ["credential_ids", (w) => { w.raw[`${F.WALLET}.credential_ids`] = boom; }, /credential list could not be read/],
    ["credential_nonce", (w) => { w.raw[`${F.WALLET}.credential_nonce`] = boom; }, /nonce could not be read/],
    ["ft_balance_of", (w) => { w.raw[`${F.TOKEN}.ft_balance_of`] = boom; }, /token balance could not be read/],
    ["ft_metadata", (w) => { w.raw[`${F.TOKEN}.ft_metadata`] = boom; }, /decimals could not be read/],
    ["wallet keys", (w) => { w.raw[`keys:${F.WALLET}`] = { error: { code: -32000, message: "boom" } }; }, /wallet key list could not be read/],
    ["agent keys", (w) => { w.raw[`keys:${F.ALPHA}`] = { error: { code: -32000, message: "boom" } }; }, /alpha.* key list could not be read/],
    ["gas price", (w) => { w.gasPriceBroken = true; }, /gas price could not be read/],
    ["node_record without a window", (w) => { w.views[`${F.WALLET}.node_record`] = () => ({ rule: F.scriptedRule(), epoch: 1, version: 1, spent: "0" }); }, /no usable window/],
    ["node_record without spent", (w) => { w.views[`${F.WALLET}.node_record`] = () => ({ rule: F.scriptedRule(), epoch: 1, version: 1, window_began_ms: Date.now() - 60000 }); }, /not usable numbers/],
  ];
  const base = await run();
  const baseChecks = Number(/(\d+) checks/.exec(base.out)[1]);
  for (const [name, mutate, re] of cases) {
    const r = await run(mutate);
    assert.equal(r.code, 1, `${name}: expected exit 1\n${r.out}${r.err}`);
    assert.match(r.out, /\d+ checks, \d+ failed/, `${name}: the run must reach its summary, not die half way`);
    assert.doesNotMatch(r.out, /READY to record/, name);
    assert.match(failing(r), re, `${name}: no FAIL line says why`);
    assert.doesNotMatch(r.err, /unbound variable|syntax error|command not found/, `${name}: the shell itself failed: ${r.err}`);
    const checks = Number(/(\d+) checks/.exec(r.out)[1]);
    assert.ok(checks >= baseChecks - 6, `${name}: only ${checks} of ${baseChecks} checks ran`);
  }
});

test("the real device must be the FIRST credential registered, and the output says why the order matters", async () => {
  const file = join(dir, "dep-order.json");
  writeFileSync(file, JSON.stringify({ ...F.deployment, credentials: [...F.deployment.credentials].reverse() }));
  const r = await run(() => {}, { env: { LEASH_DEPLOYMENT: file } });
  assert.equal(r.code, 1);
  assert.match(failing(r), /the FIRST credential registered is not the real device/);
  assert.match(failing(r), /only the first registration is admin-alone/);
  assert.match(failing(r), /redeploy, and register the device first/);
  assert.doesNotMatch(r.out, /READY to record/);
  const ok = await run();
  assert.match(ok.out, /READY to record/);
  assert.match(ok.out, /only if the real device was registered FIRST/);
  assert.match(ok.out, /is the first credential recorded/);
});

test("a missing argument is an error of the script, not a default", async () => {
  let r = await run(() => {}, { env: { AGENT_URLS: "http://127.0.0.1:9" } });
  assert.equal(r.code, 2);
  assert.match(r.err, /AGENT_URLS must hold exactly two urls/);
  r = await run(() => {}, { env: { LEASH_DEPLOYMENT: join(dir, "missing.json") } });
  assert.equal(r.code, 2);
  assert.match(r.err, /cannot read/);
});

test("when no endpoint answers every chain check fails, none passes", async () => {
  const r = await run(() => {}, { env: { NEAR_RPC: "http://127.0.0.1:1" } });
  assert.equal(r.code, 1);
  assert.equal(lines(r, "PASS").filter((l) => !/agent '/.test(l)).length, 0, r.out);
  assert.match(r.out, /no endpoint answered/);
});

test("the script contains no silent zero default", () => {
  const src = readFileSync(join(root, "scripts/preflight.sh"), "utf8").split("\n").filter((l) => !l.trim().startsWith("#"));
  assert.deepEqual(src.filter((l) => /\|\|\s*echo|:-0\b|\|\|\s*true/.test(l)), []);
});
