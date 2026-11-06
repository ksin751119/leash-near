import test from "node:test";
import assert from "node:assert/strict";
import { settle, sendAndRecord, parseInstruction, publicState, keyFileWarning } from "./loop.mjs";
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
  assert.deepEqual(Object.keys(s).sort(), ["agentAddr", "cohort", "lastAction", "name", "refusals"]);
  assert.equal(s.cohort.node, NODE);
  assert.equal(s.cohort.left, "3.00");
});

test("parseInstruction finds an amount and a payee by vendor name or account id", () => {
  const vendors = [{ id: "pay1", name: "Acme Studio", aliases: ["acme"], account: PAY1 }];
  const a = parseInstruction("pay Acme 2.50 USDC", vendors, UNITS.decimals);
  assert.deepEqual([a.payee, a.amount, a.vendor], [PAY1, 2_500_000n, "Acme Studio"]);
  const b = parseInstruction("send 1 USDC to someone-else.testnet", vendors, UNITS.decimals);
  assert.deepEqual([b.payee, b.amount, b.vendor], ["someone-else.testnet", 1_000_000n, null]);
  assert.equal(parseInstruction("pay a stranger", vendors, 6).error.length > 0, true);
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

// --- the instruction parser ---

const vendors = [
  { id: "pay1", name: "Acme Studio", aliases: ["acme", "pay1"], account: PAY1 },
  { id: "pay2", name: "Inference API", aliases: ["inference", "api", "pay2"], account: "leash-pay2-1106fcff.testnet" },
];
const P2 = "leash-pay2-1106fcff.testnet";

test("digits in the payee's account id are not the amount, amount after the payee", () => {
  const r = parseInstruction(`send to ${P2} 0.10 USDC`, vendors, 6);
  assert.equal(r.amount, 100_000n);
  assert.equal(r.payee, P2);
});

test("digits in the payee's account id are not the amount, amount before the payee", () => {
  const r = parseInstruction(`send 0.10 USDC to ${P2}`, vendors, 6);
  assert.equal(r.amount, 100_000n);
  assert.equal(r.payee, P2);
});

test("an account id and no amount is an error, not 2.00 or 1106", () => {
  for (const t of [`send to ${P2}`, `pay ${P2} now`, "pay pay2"]) {
    assert.ok(parseInstruction(t, vendors, 6).error, t);
  }
});

test("a number inside a word is not an amount, and two different numbers are refused", () => {
  assert.equal(parseInstruction("pay1 3 USDC", vendors, 6).amount, 3_000_000n);
  assert.match(parseInstruction("pay Acme 3 USDC or 4 USDC", vendors, 6).error, /more than one/);
  assert.equal(parseInstruction("pay Acme 5.", vendors, 6).amount, 5_000_000n);
});

test("a vendor alias inside a longer word does not match", () => {
  assert.ok(parseInstruction("pay capital 1 USDC", vendors, 6).error);
});

// --- key file ---

test("a key file readable by others produces a loud warning, a private one does not", () => {
  assert.equal(keyFileWarning("/k.json", 0o100600), null);
  assert.match(keyFileWarning("/k.json", 0o100644), /WARNING.*644.*chmod 600/);
  assert.match(keyFileWarning("/k.json", 0o100660), /WARNING/);
});
