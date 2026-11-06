// The wire between the chain and decide(): readView() must put every view decide() depends on
// where decide() looks. decide() and the cross-check are tested on hand-built view objects, so
// without this a dropped or renamed view call (the account pause was one) fails nothing, and the
// agent predicts "will pass" while the chain refuses.
import test from "node:test";
import assert from "node:assert/strict";
import { readView } from "./chain.mjs";
import { decide } from "./decide.mjs";
import { ALPHA, NODE, PAY1, RULE, REASONS, TOKEN, UNITS } from "./fixtures.mjs";

const WALLET = "wallet.testnet";

// Answers each view call with a distinct, recognisable value and records what was asked.
function stubFetch(answers) {
  const calls = [];
  globalThis.fetch = async (_url, init) => {
    const p = JSON.parse(init.body).params;
    const args = JSON.parse(Buffer.from(p.args_base64, "base64").toString());
    calls.push({ account: p.account_id, method: p.method_name, args });
    if (!(p.method_name in answers)) return { json: async () => ({ error: { message: `no stub for ${p.method_name}` } }) };
    const bytes = Buffer.from(JSON.stringify(answers[p.method_name]));
    return { json: async () => ({ result: { result: [...bytes] } }) };
  };
  return calls;
}

const rec = (o = {}) => ({ rule: RULE, epoch: 0, version: 1, window_began_ms: 1_000, spent: "7000000", ...o });
const answers = (over = {}) => ({
  node_for: NODE,
  node_record: rec(),
  is_paused: false,
  refusal_codes: REASONS,
  ...over,
});

test("readView carries every field decide() reads, from the right view call", async () => {
  const calls = stubFetch(answers({ is_paused: true, node_record: rec({ spent: "1234567" }) }));
  const v = await readView({ wallet: WALLET, agent: ALPHA, units: UNITS });
  assert.equal(v.accountPaused, true);
  assert.equal(v.spent, "1234567");
  assert.deepEqual(v.rule, RULE);
  assert.equal(v.node, NODE);
  assert.deepEqual(v.reasons, REASONS);
  assert.deepEqual(v.units, UNITS);
  assert.equal(typeof v.nowMs, "number");
  const asked = (m) => calls.find((c) => c.method === m);
  assert.ok(asked("is_paused"), "is_paused was never called");
  assert.equal(asked("is_paused").account, WALLET);
  assert.deepEqual(asked("node_for").args, { agent: ALPHA });
  assert.deepEqual(asked("node_record").args, { node: NODE });
  assert.equal(v.windowBeganMs, 1_000);
});

test("the account pause reaches the prediction end to end: chain says paused, decide says code 2", async () => {
  stubFetch(answers({ is_paused: true, node_record: rec({ spent: "0" }) }));
  const v = await readView({ wallet: WALLET, agent: ALPHA, units: UNITS });
  const d = decide(v, { token: TOKEN, payee: PAY1, amount: 100_000n });
  assert.equal(d.code, 2);
  stubFetch(answers({ is_paused: false, node_record: rec({ spent: "0" }) }));
  const ok = decide(await readView({ wallet: WALLET, agent: ALPHA, units: UNITS }), { token: TOKEN, payee: PAY1, amount: 100_000n });
  assert.equal(ok.verdict, "will-pass");
});

test("the spent and rule views reach the prediction too", async () => {
  stubFetch(answers({ node_record: rec({ spent: "9000000" }) }));
  const d = decide(await readView({ wallet: WALLET, agent: ALPHA, units: UNITS }), { token: TOKEN, payee: PAY1, amount: 2_000_000n });
  assert.equal(d.code, 6);
  assert.match(d.explain, /1\.00 left of 10\.00 USDC/);
  stubFetch(answers({ node_record: rec({ rule: { ...RULE, payees: [] } }) }));
  const e = decide(await readView({ wallet: WALLET, agent: ALPHA, units: UNITS }), { token: TOKEN, payee: PAY1, amount: 1n });
  assert.equal(e.code, 4);
});

test("an agent with no node reads no rule and spends nothing, and decide() says code 1", async () => {
  const calls = stubFetch(answers({ node_for: null }));
  const v = await readView({ wallet: WALLET, agent: "nodot", units: UNITS });
  assert.equal(v.node, null);
  assert.equal(v.rule, null);
  assert.equal(v.spent, "0");
  assert.ok(!calls.some((c) => c.method === "node_record"));
  assert.equal(decide(v, { token: TOKEN, payee: PAY1, amount: 1n }).code, 1);
});

test("a failing view call fails readView instead of yielding a half-built view", async () => {
  stubFetch(answers({ is_paused: undefined }));
  const a = answers();
  delete a.is_paused;
  stubFetch(a);
  await assert.rejects(readView({ wallet: WALLET, agent: ALPHA, units: UNITS }), /is_paused/);
});
