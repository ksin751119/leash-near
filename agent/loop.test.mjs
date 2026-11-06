import test from "node:test";
import assert from "node:assert/strict";
import { settle, sendAndRecord, publicState, keyFileWarning } from "./loop.mjs";
import { entry, log, view, ALPHA, BETA, PAY1, TOKEN, NODE, UNITS } from "./fixtures.mjs";

const inFlight = (over = {}) => ({
  status: "in-flight",
  agent: ALPHA,
  payee: PAY1,
  amount: "5000000",
  countBefore: 3,
  strangersBefore: 0,
  ...over,
});

// The latch bug from the last project: a payment the chain refused sat at IN FLIGHT because
// the code that cleared it only ran on success. The chain is the authority; a refusal it has
// recorded must be shown as refused.
test("a refusal recorded on-chain is shown as refused, not in-flight", () => {
  const chain = log({ decisions: [entry()], decision_count: 4 });
  const a = settle(inFlight(), chain);
  assert.equal(a.status, "refused");
  assert.equal(a.code, 6);
  assert.equal(a.reason, "over the limit for this period");
  assert.notEqual(a.status, "in-flight");
});

test("a refusal from the strangers ring settles an in-flight action too", () => {
  const chain = log({
    strangers: [entry({ node: null, outcome: { status: "refused", code: 1, reason: "no rule for this agent's node" } })],
    stranger_count: 1,
  });
  const a = settle(inFlight({ countBefore: 0, strangersBefore: 0 }), chain);
  assert.equal(a.status, "refused");
  assert.equal(a.code, 1);
});

test("an allowed and a failed record settle as allowed and failed", () => {
  const ok = entry({ outcome: { status: "allowed" } });
  assert.equal(settle(inFlight(), log({ decisions: [ok], decision_count: 4 })).status, "allowed");
  const bad = entry({ outcome: { status: "failed" } });
  assert.equal(settle(inFlight(), log({ decisions: [bad], decision_count: 4 })).status, "failed");
});

test("an in-flight action stays in-flight only while the chain has recorded nothing new", () => {
  assert.equal(settle(inFlight(), log({ decisions: [entry()], decision_count: 3 })).status, "in-flight");
});

test("another agent's newer record does not settle this agent's action", () => {
  const theirs = entry({ agent: BETA, outcome: { status: "allowed" } });
  assert.equal(settle(inFlight(), log({ decisions: [theirs], decision_count: 4 })).status, "in-flight");
});

test("sendAndRecord clears in-flight when the send throws, and when the chain refused", async () => {
  const state = { lastAction: null };
  const boom = async () => { throw new Error("rpc down"); };
  await sendAndRecord(state, { agent: ALPHA, payee: PAY1, amount: 5_000_000n, token: TOKEN }, { send: boom, readLog: async () => log({ decision_count: 3 }) });
  assert.notEqual(state.lastAction.status, "in-flight");
  assert.equal(state.lastAction.status, "error");

  const refused = async () => ({ txHash: "TX", outcome: { status: "refused", code: 6, reason: "over the limit for this period" } });
  let n = 0;
  const readLog = async () => (n++ === 0 ? log({ decision_count: 3 }) : log({ decisions: [entry()], decision_count: 4 }));
  await sendAndRecord(state, { agent: ALPHA, payee: PAY1, amount: 5_000_000n, token: TOKEN }, { send: refused, readLog });
  assert.equal(state.lastAction.status, "refused");
  assert.equal(state.lastAction.tx, "TX");
});

test("/state keeps a stale in-flight from showing once the chain has spoken", () => {
  const state = { name: "payments", agentAddr: ALPHA, lastAction: inFlight() };
  const chain = log({ decisions: [entry()], decision_count: 4 });
  const s = publicState(state, chain, view({ spent: "7000000" }));
  assert.equal(s.lastAction.status, "refused");
});

test("/state keeps strangers apart from agents and renders a null node as null", () => {
  const stranger = entry({ agent: "nodot", node: null, outcome: { status: "refused", code: 1, reason: "no rule for this agent's node" } });
  const chain = log({ decisions: [entry()], decision_count: 1, strangers: [stranger], stranger_count: 9 });
  const s = publicState({ name: "payments", agentAddr: ALPHA, lastAction: null }, chain, view());
  assert.equal(s.refusals.strangers[0].node, null);
  assert.equal(s.refusals.strangers[0].ring, "strangers");
  assert.equal(s.refusals.agents[0].ring, "decisions");
  assert.equal(s.refusals.strangerCount, 9);
  assert.deepEqual(Object.keys(s).sort(), ["agentAddr", "chain", "cohort", "lastAction", "name", "refusals", "txs"]);
  assert.equal(s.cohort.node, NODE);
  assert.equal(s.cohort.left, "3.00");
});

// --- the send finished but the chain cannot be read (a slow network, which is when we record) ---

const attempt = { agent: ALPHA, payee: PAY1, amount: 5_000_000n, token: TOKEN };
const unreadable = async () => { throw new Error("rpc timeout"); };

test("send returned a refusal but the log is unreadable: the return value settles it", async () => {
  const state = { lastAction: null };
  const send = async () => ({ txHash: "TX", outcome: { status: "refused", code: 5, reason: "over the per-transaction limit" } });
  await sendAndRecord(state, attempt, { send, readLog: unreadable });
  assert.equal(state.lastAction.status, "refused");
  assert.equal(state.lastAction.code, 5);
  assert.equal(state.lastAction.settledBy, "return-value");
});

test("send returned nothing usable and the log is unreadable: unknown, never in-flight", async () => {
  const state = { lastAction: null };
  await sendAndRecord(state, attempt, { send: async () => ({ txHash: "TX", outcome: null }), readLog: unreadable });
  assert.equal(state.lastAction.status, "unknown");
  assert.equal(state.lastAction.tx, "TX");
});

test("an unknown or error action is settled later when the chain shows the refusal", () => {
  for (const status of ["unknown", "error"]) {
    const a = settle(inFlight({ status, reason: "timed out" }), log({ decisions: [entry()], decision_count: 4 }));
    assert.equal(a.status, "refused", status);
    assert.equal(a.code, 6);
    assert.equal(a.reason, "over the limit for this period");
  }
});

test("/state settles an action that ended as error, once the chain has recorded it", () => {
  const state = { name: "payments", agentAddr: ALPHA, lastAction: inFlight({ status: "error", reason: "near-cli timed out" }) };
  const s = publicState(state, log({ decisions: [entry()], decision_count: 4 }), view());
  assert.equal(s.lastAction.status, "refused");
});

test("a final status is never rewritten by a later, different record", () => {
  const done = { ...inFlight(), status: "allowed" };
  assert.equal(settle(done, log({ decisions: [entry()], decision_count: 9 })), done);
});

test("when the pre-send read failed, countBefore is null (not Infinity) and the timestamp settles it", async () => {
  const state = { lastAction: null };
  let reads = 0;
  const readLog = async () => {
    if (reads++ === 0) throw new Error("rpc timeout");
    return log({ decisions: [entry({ timestamp_ms: Date.now() })], decision_count: 40 });
  };
  await sendAndRecord(state, attempt, { send: async () => ({ txHash: "TX", outcome: null }), readLog });
  assert.equal(state.lastAction.countBefore, null);
  assert.equal(state.lastAction.countKnown, false);
  assert.equal(JSON.parse(JSON.stringify(state.lastAction)).countBefore, null);
  assert.equal(state.lastAction.status, "refused");
  // An old record for the same attempt must not settle it.
  const old = settle({ ...inFlight(), countBefore: null, strangersBefore: null, at: Date.now() },
    log({ decisions: [entry({ timestamp_ms: Date.now() - 3_600_000 })], decision_count: 40 }));
  assert.equal(old.status, "in-flight");
});

// --- key file ---

test("a key file readable by others produces a loud warning, a private one does not", () => {
  assert.equal(keyFileWarning("/k.json", 0o100600), null);
  assert.match(keyFileWarning("/k.json", 0o100644), /WARNING.*644.*chmod 600/);
  assert.match(keyFileWarning("/k.json", 0o100660), /WARNING/);
});

test("what the agent understood is on lastAction from the moment it is in flight, and stays after", async () => {
  const state = { lastAction: null };
  let during;
  const send = async () => { during = state.lastAction; return { txHash: "TX", outcome: { status: "refused", code: 5, reason: "x" } }; };
  await sendAndRecord(state, { ...attempt, understood: "paying 5.00 USDC to Acme Studio (a.testnet)" }, { send, readLog: unreadable });
  assert.equal(during.status, "in-flight");
  assert.equal(during.understood, "paying 5.00 USDC to Acme Studio (a.testnet)");
  assert.equal(state.lastAction.understood, during.understood);
});

// --- which transaction caused which decision ---------------------------------------------

import { matchTxs } from "./loop.mjs";

test("a sent payment is linked to the decision it caused, by agent, payee and amount", () => {
  const e = entry({ amount: "5000000", timestamp_ms: 111 });
  const chain = log({ decisions: [e], decision_count: 4 });
  const sent = [{ agent: ALPHA, payee: PAY1, amount: "5000000", tx: "TXA", at: 100, countBefore: 3, strangersBefore: 0 }];
  assert.deepEqual(matchTxs(sent, chain), { [`${ALPHA}|111`]: "TXA" });
});

test("a decision from before the attempt is never claimed by it", () => {
  const old = entry({ amount: "5000000", timestamp_ms: 50 });
  const chain = log({ decisions: [old], decision_count: 3 });
  const sent = [{ agent: ALPHA, payee: PAY1, amount: "5000000", tx: "TXA", at: 100, countBefore: 3, strangersBefore: 0 }];
  assert.deepEqual(matchTxs(sent, chain), {});
});

test("two identical payments each get their own transaction", () => {
  const first = entry({ amount: "5000000", timestamp_ms: 111 });
  const second = entry({ amount: "5000000", timestamp_ms: 222 });
  const chain = log({ decisions: [second, first], decision_count: 5 });
  const base = { agent: ALPHA, payee: PAY1, amount: "5000000" };
  const sent = [
    { ...base, tx: "TX1", at: 100, countBefore: 3, strangersBefore: 0 },
    { ...base, tx: "TX2", at: 200, countBefore: 4, strangersBefore: 0 },
  ];
  assert.deepEqual(matchTxs(sent, chain), { [`${ALPHA}|111`]: "TX1", [`${ALPHA}|222`]: "TX2" });
});

test("an attempt with no transaction hash links nothing", () => {
  const chain = log({ decisions: [entry({ amount: "5000000" })], decision_count: 4 });
  assert.deepEqual(matchTxs([{ agent: ALPHA, payee: PAY1, amount: "5000000", tx: null, at: 1, countBefore: 3, strangersBefore: 0 }], chain), {});
});

test("/state passes the chain's own answers through for the page", () => {
  const chain = log({ decisions: [entry()], decision_count: 1 });
  const s = publicState({ name: "p", agentAddr: ALPHA, lastAction: null }, chain, view({ windowBeganMs: 5, accountPaused: false, readAt: { decision_log: 1 }, errors: [] }));
  assert.deepEqual(s.chain.reasons, view().reasons);
  assert.equal(s.chain.windowBeganMs, 5);
  assert.equal(s.chain.paused, false);
  assert.equal(s.chain.log, chain);
  assert.equal(s.chain.rule.period_limit, "10000000");
});

test("sendAndRecord keeps the transaction hash of what it sent, with the counts it needs to match it later", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null };
  await sendAndRecord(state, { agent: ALPHA, payee: PAY1, amount: 5_000_000n, token: TOKEN }, {
    send: async () => ({ txHash: "TXSENT", outcome: { status: "refused", code: 5, reason: "x" } }),
    readLog: async () => log({ decision_count: 3 }),
  });
  assert.equal(state.sent.length, 1);
  assert.equal(state.sent[0].tx, "TXSENT");
  assert.equal(state.sent[0].countBefore, 3);
});
