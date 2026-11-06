import test from "node:test";
import assert from "node:assert/strict";
import { settle, sendAndRecord, parseInstruction, publicState } from "./loop.mjs";
import { entry, log, view, ALPHA, BETA, PAY1, TOKEN, NODE, UNITS } from "./fixtures.mjs";

const inFlight = (over = {}) => ({
  status: "in-flight",
  agent: ALPHA,
  payee: PAY1,
  amount: "5000000",
  countBefore: 3,
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
