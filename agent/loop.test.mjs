import test from "node:test";
import assert from "node:assert/strict";
import { settle, sendAndRecord, publicState, keyFileWarning, resolveUnconfirmed, claimSlot } from "./loop.mjs";
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
  assert.equal(state.lastAction.settledBy, "transaction");
});

test("send returned nothing usable and the log is unreadable: unknown, never in-flight", async () => {
  const state = { lastAction: null };
  await sendAndRecord(state, attempt, { send: async () => ({ txHash: "TX", outcome: null }), readLog: unreadable });
  assert.equal(state.lastAction.status, "unknown");
  assert.equal(state.lastAction.tx, "TX");
});

// A network failure must never turn into a policy refusal on screen. The chain log can hold an
// identical refusal (a retried instruction, a minute apart) that has nothing to do with this
// attempt, so only an in-flight action is ever matched to the log, and only by the count taken just
// before the send. Reverting PROVISIONAL to include "error"/"unknown", or restoring the timestamp
// fallback, makes these fail.
test("a named ending is final: an identical refusal in the log does not turn it into REFUSED", () => {
  const sameRefusal = log({ decisions: [entry({ timestamp_ms: Date.now() - 30_000 })], decision_count: 4 });
  for (const errorKind of ["not-sent", "rejected", "chain-failed"]) {
    const a = inFlight({ status: "error", errorKind, reason: "x", at: Date.now() });
    assert.equal(settle(a, sameRefusal).status, "error", errorKind);
  }
  // same with the counts unknown, which used to fall back to a 60 s timestamp window
  const unknownCounts = inFlight({ status: "error", errorKind: "not-sent", countBefore: null, strangersBefore: null, at: Date.now() });
  assert.equal(settle(unknownCounts, sameRefusal).status, "error");
});

test("an unconfirmed send is not settled from the log; only its own hash resolves it", () => {
  const a = inFlight({ status: "unknown", errorKind: "unconfirmed", tx: "TXU" });
  assert.equal(settle(a, log({ decisions: [entry()], decision_count: 4 })).status, "unknown");
});

test("/state never turns an error into a refusal, even when the chain has an identical record", () => {
  const state = { name: "payments", agentAddr: ALPHA, lastAction: inFlight({ status: "error", errorKind: "not-sent", reason: "could not reach the chain" }) };
  const s = publicState(state, log({ decisions: [entry()], decision_count: 4 }), view());
  assert.equal(s.lastAction.status, "error");
  assert.equal(s.lastAction.errorKind, "not-sent");
});

test("an unconfirmed send is resolved by looking up its hash, and only while it is still on screen", async () => {
  const state = { lastAction: inFlight({ status: "unknown", errorKind: "unconfirmed", tx: "TXU" }) };
  const refusedResult = { status: { SuccessValue: Buffer.from('{"status":"refused","code":5,"reason":"over the per-transaction limit"}').toString("base64") } };
  const replies = [{ state: "unreachable" }, { state: "unknown" }, { state: "found", result: refusedResult }];
  let i = 0;
  const done = await resolveUnconfirmed(state, "TXU", { lookup: async () => replies[i++], waitMs: 0, sleep: async () => {} });
  assert.equal(done, true);
  assert.equal(state.lastAction.status, "refused");
  assert.equal(state.lastAction.settledBy, "transaction-lookup");
  // a newer instruction replaced the card: the resolver leaves it alone
  const state2 = { lastAction: inFlight({ status: "in-flight", tx: "OTHER" }) };
  assert.equal(await resolveUnconfirmed(state2, "TXU", { lookup: async () => ({ state: "found", result: refusedResult }), sleep: async () => {} }), false);
  assert.equal(state2.lastAction.status, "in-flight");
});

test("a chain failure found by lookup is named as one, not as a refusal", async () => {
  const state = { lastAction: inFlight({ status: "unknown", errorKind: "unconfirmed", tx: "TXU" }) };
  await resolveUnconfirmed(state, "TXU", { lookup: async () => ({ state: "found", result: { status: { Failure: { ActionError: {} } } } }), sleep: async () => {} });
  assert.equal(state.lastAction.status, "error");
  assert.equal(state.lastAction.errorKind, "chain-failed");
});

test("a final status is never rewritten by a later, different record", () => {
  const done = { ...inFlight(), status: "allowed" };
  assert.equal(settle(done, log({ decisions: [entry()], decision_count: 9 })), done);
});

test("when the pre-send read failed, countBefore is null (not Infinity) and nothing is matched by timestamp", async () => {
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
  assert.equal(state.lastAction.status, "unknown"); // not "refused": a fresh identical record proves nothing
  const stamp = settle({ ...inFlight(), countBefore: null, strangersBefore: null, at: Date.now() },
    log({ decisions: [entry({ timestamp_ms: Date.now() })], decision_count: 40 }));
  assert.equal(stamp.status, "in-flight");
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

test("an attempt whose pre-send counts are unknown links nothing, and does not throw", () => {
  const e = entry({ amount: "5000000", timestamp_ms: 111 });
  const chain = log({ decisions: [e], decision_count: 4 });
  const base = { agent: ALPHA, payee: PAY1, amount: "5000000", tx: "TXA", at: 100 };
  assert.deepEqual(matchTxs([{ ...base, countBefore: null, strangersBefore: null }], chain), {});
  // one count known and the other not is still unknown
  assert.deepEqual(matchTxs([{ ...base, countBefore: 3, strangersBefore: null }], chain), {});
  assert.deepEqual(matchTxs([{ ...base, countBefore: null, strangersBefore: 0 }], chain), {});
});

test("an unknown-count attempt does not hide or steal a link that is known", () => {
  const first = entry({ amount: "5000000", timestamp_ms: 111 });
  const second = entry({ amount: "5000000", timestamp_ms: 222 });
  const chain = log({ decisions: [second, first], decision_count: 5 });
  const base = { agent: ALPHA, payee: PAY1, amount: "5000000" };
  const sent = [
    { ...base, tx: "TXLOST", at: 100, countBefore: null, strangersBefore: null },
    { ...base, tx: "TXKNOWN", at: 200, countBefore: 4, strangersBefore: 0 },
  ];
  assert.deepEqual(matchTxs(sent, chain), { [`${ALPHA}|222`]: "TXKNOWN" });
});

test("/state still answers when a sent entry has unknown counts and the log is not empty", () => {
  const sent = [{ agent: ALPHA, payee: PAY1, amount: "5000000", tx: "TXA", at: 100, countBefore: null, strangersBefore: null }];
  const state = { name: "payments", agentAddr: ALPHA, lastAction: null, sent };
  const chain = log({ decisions: [entry({ amount: "5000000", timestamp_ms: 111 })], decision_count: 4 });
  const s = publicState(state, chain, view());
  assert.equal(s.name, "payments");
  assert.equal(s.cohort.recent.length, 1);
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

// --- how a send ended, and surviving a restart ---------------------------------------------

import { SendError } from "./send.mjs";
import { loadSent, saveSent } from "./sentstore.mjs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const pay = { agent: ALPHA, payee: PAY1, amount: 5_000_000n, token: TOKEN };

test("a send that never reached the chain is an error named not-sent, with no transaction", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null };
  await sendAndRecord(state, pay, { send: async () => { throw new SendError("not-sent", "could not reach the chain"); }, readLog: async () => log({ decision_count: 3 }) });
  assert.equal(state.lastAction.status, "error");
  assert.equal(state.lastAction.errorKind, "not-sent");
  assert.equal(state.lastAction.tx, null);
  assert.equal(state.sent, undefined);
});

test("a send we could not confirm stays unknown, keeps its hash, and is not settled by the log", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null };
  await sendAndRecord(state, pay, { send: async () => { throw new SendError("unconfirmed", "may still land", "TXU"); }, readLog: async () => log({ decision_count: 3 }) });
  assert.equal(state.lastAction.status, "unknown");
  assert.equal(state.lastAction.errorKind, "unconfirmed");
  assert.equal(state.lastAction.tx, "TXU");
  assert.equal(state.sent[0].tx, "TXU");
  const landed = log({ decisions: [entry({ amount: "5000000", timestamp_ms: 9 })], decision_count: 4 });
  assert.equal(settle(state.lastAction, landed).status, "unknown");
});

test("the hash is recorded as soon as it is signed, before the send returns", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null, sent: [] };
  let savedWhileSending;
  state.save = () => { savedWhileSending = state.sent.map((e) => e.tx); };
  await sendAndRecord(state, pay, {
    send: async (_i, hooks) => { hooks.onSigned("TXEARLY"); assert.deepEqual(savedWhileSending, ["TXEARLY"]); throw new Error("killed"); },
    readLog: async () => log({ decision_count: 3 }),
  });
  assert.equal(state.sent.length, 1); // not duplicated when the send ends
});

test("the transaction links are still there after a restart", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "restart-")), "s.json");
  const state = { name: "p", agentAddr: ALPHA, lastAction: null, sent: [] };
  state.save = () => saveSent(file, state.sent);
  const before = log({ decision_count: 3 });
  const after = log({ decisions: [entry({ amount: "5000000", timestamp_ms: 77 })], decision_count: 4 });
  let n = 0;
  await sendAndRecord(state, pay, { send: async () => ({ txHash: "TXKEEP", outcome: { status: "allowed" } }), readLog: async () => (n++ === 0 ? before : after) });
  const restarted = { name: "p", agentAddr: ALPHA, lastAction: null, sent: loadSent(file) };
  const s = publicState(restarted, after, view());
  assert.equal(s.txs[`${ALPHA}|77`], "TXKEEP");
});

// --- a hash that never landed must not steal a decision's link --------------------------------------

test("a rejected attempt's hash is forgotten, so a later identical payment links to its own transaction", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null, sent: [], save() {} };
  const before = log({ decision_count: 3 });
  await sendAndRecord(state, pay, {
    send: async (_i, h) => { h.onSigned("TXDEAD"); throw new SendError("rejected", "invalid signature", "TXDEAD"); },
    readLog: async () => before,
  });
  assert.deepEqual(state.sent.map((e) => e.tx), []);
  const landed = log({ decisions: [entry({ amount: "5000000", timestamp_ms: 55 })], decision_count: 4 });
  await sendAndRecord(state, pay, { send: async (_i, h) => { h.onSigned("TXLIVE"); return { txHash: "TXLIVE", outcome: { status: "refused", code: 5, reason: "x" } }; }, readLog: async () => before });
  assert.deepEqual(matchTxs(state.sent, landed), { [`${ALPHA}|55`]: "TXLIVE" });
});

test("a failure that provably moved nothing is forgotten; one that moved money, or may have, is kept", async () => {
  for (const [moved, kept] of [[false, false], [true, true], [null, true]]) {
    const state = { name: "p", agentAddr: ALPHA, lastAction: null, sent: [], save() {} };
    await sendAndRecord(state, pay, {
      send: async (_i, h) => { h.onSigned("TXF"); throw new SendError("chain-failed", "failed", "TXF", moved); },
      readLog: async () => log({ decision_count: 3 }),
    });
    assert.equal(state.sent.length, kept ? 1 : 0, `moved=${moved}`);
    assert.equal(state.lastAction.moved, moved);
  }
});

test("a lookup that finds a rolled-back transaction forgets its hash too", async () => {
  const state = { lastAction: inFlight({ status: "unknown", errorKind: "unconfirmed", tx: "TXU" }), sent: [{ tx: "TXU", agent: ALPHA, payee: PAY1, amount: "5000000", at: 1 }], save() {} };
  const failed = { final_execution_status: "FINAL", status: { Failure: {} }, receipts_outcome: [{ outcome: { executor_id: "w.testnet", status: { Failure: {} } } }] };
  await resolveUnconfirmed(state, "TXU", { ctx: { wallet: "w.testnet", token: TOKEN }, lookup: async () => ({ state: "found", result: failed }), sleep: async () => {} });
  assert.equal(state.lastAction.moved, false);
  assert.equal(state.sent.length, 0);
});

test("resolveUnconfirmed keeps waiting while the lookup is pending", async () => {
  const state = { lastAction: inFlight({ status: "unknown", errorKind: "unconfirmed", tx: "TXU" }) };
  const replies = [{ state: "pending" }, { state: "pending" }];
  let i = 0;
  const done = await resolveUnconfirmed(state, "TXU", { lookup: async () => replies[i++] ?? { state: "pending" }, tries: 2, sleep: async () => {} });
  assert.equal(done, false);
  assert.equal(state.lastAction.status, "unknown");
});

// --- two instructions in flight ---------------------------------------------------------------------

test("a second instruction keeps the card when the first finishes later", async () => {
  const state = { name: "p", agentAddr: ALPHA, lastAction: null, sent: [], save() {} };
  let finishFirst;
  const first = sendAndRecord(state, { ...pay, understood: "FIRST" }, {
    send: () => new Promise((r) => { finishFirst = () => r({ txHash: "T1", outcome: { status: "allowed" } }); }),
    readLog: async () => log({ decision_count: 3 }),
  });
  await new Promise((r) => setTimeout(r, 1));
  const second = sendAndRecord(state, { ...pay, understood: "SECOND" }, { send: () => new Promise(() => {}), readLog: async () => log({ decision_count: 3 }) });
  await new Promise((r) => setTimeout(r, 1));
  assert.equal(state.lastAction.understood, "SECOND");
  finishFirst();
  const r1 = await first;
  assert.equal(r1.status, "allowed");                       // the first caller still gets its own result
  assert.equal(state.lastAction.understood, "SECOND");      // and the card still shows the second instruction
  assert.equal(state.lastAction.status, "in-flight");
  void second;
});

test("a second instruction is turned away while the first is still sending", () => {
  const state = {};
  const release = claimSlot(state);
  assert.ok(release);
  assert.equal(claimSlot(state), null);
  release();
  assert.ok(claimSlot(state));
});
