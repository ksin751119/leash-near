import { test } from "node:test";
import assert from "node:assert/strict";
import {
  shortId, formatUsdc, renderAction, renderDecisions, renderBudget, renderWalletKeys, renderAgentKeys,
  relativeTime, txUrl,
} from "./demo-render.mjs";

const WALLET = "leash-wal-1106fcff.testnet";
const NODE = "leash-bud-1106fcff.testnet";
const ALPHA = `alpha.${NODE}`;
const BETA = `beta.${NODE}`;
const PAY1 = "leash-pay1-1106fcff.testnet";

// The chain's own table. Tests read sentences out of it rather than writing them again.
const REASONS = [
  { code: 4, reason: "payee is not on the allow-list" },
  { code: 5, reason: "over the per-transaction limit" },
];

const dec = (o) => ({
  agent: ALPHA, node: NODE, payee: PAY1, amount: "100000", spent_after: "0", timestamp_ms: 1000,
  outcome: { status: "allowed" }, ...o,
});
const refused = (code, reason, o = {}) => dec({ outcome: { status: "refused", code, reason }, ...o });

// --- lastAction.status: every value ends somewhere honest -----------------------------

test("only in-flight is still in flight; every other status is final", () => {
  const phases = {};
  for (const status of ["in-flight", "allowed", "refused", "failed", "unknown", "error"]) {
    phases[status] = renderAction({ status, understood: "u" }, REASONS).inFlight;
  }
  assert.deepEqual(phases, {
    "in-flight": true, allowed: false, refused: false, failed: false, unknown: false, error: false,
  });
});

test("a refused action is not left saying in flight (the previous project's latch bug)", () => {
  const a = renderAction({ status: "refused", code: 5, reason: "over the per-transaction limit", understood: "u" }, REASONS);
  assert.equal(a.inFlight, false);
  assert.equal(a.tone, "refused");
  assert.doesNotMatch(a.label, /flight/i);
});

test("unknown and error are final but unresolved, and say so", () => {
  for (const status of ["unknown", "error"]) {
    const a = renderAction({ status, reason: "sent, but the chain has not recorded it yet", understood: "u" }, REASONS);
    assert.equal(a.inFlight, false);
    assert.equal(a.unresolved, true);
    assert.equal(a.tone, "unresolved");
    assert.match(a.label, /unresolved/i);
    assert.match(a.note, /not (in flight|still)|stopped waiting|no longer waiting/i);
  }
});

test("a status this page has never heard of is unresolved, not in flight", () => {
  const a = renderAction({ status: "settled-ish" }, REASONS);
  assert.equal(a.inFlight, false);
  assert.equal(a.unresolved, true);
  assert.match(a.note, /settled-ish/);
});

test("no action yet renders nothing rather than throwing", () => {
  assert.equal(renderAction(null, REASONS), null);
});

// --- what the agent understood, before and after --------------------------------------

test("the understood sentence is shown while in flight and after it settles", () => {
  const u = "paying 0.50 USDC to Acme Studio (leash-pay1-1106fcff.testnet)";
  for (const status of ["in-flight", "allowed", "refused", "failed", "unknown", "error"]) {
    assert.equal(renderAction({ status, understood: u }, REASONS).understood, u, status);
  }
});

test("an action with no understood sentence says the agent did not state one", () => {
  const a = renderAction({ status: "in-flight", understood: null }, REASONS);
  assert.match(a.understood, /did not (say|state)/i);
});

// --- a refusal is the product ---------------------------------------------------------

test("a refusal renders the chain's sentence, its code, and no money moved", () => {
  const a = renderAction({ status: "refused", code: 4, reason: "payee is not on the allow-list", tx: "TXHASH", amount: "100000", understood: "u" }, REASONS);
  assert.equal(a.reason, "payee is not on the allow-list");
  assert.equal(a.code, 4);
  assert.equal(a.moved, false);
  assert.match(a.note, /no money moved/i);
});

test("a refusal's link says the transaction succeeded and why that is the point", () => {
  const a = renderAction({ status: "refused", code: 4, tx: "TXHASH", understood: "u" }, REASONS);
  assert.equal(a.txUrl, txUrl("TXHASH"));
  assert.match(a.txUrl, /^https:\/\/explorer\.testnet\.near\.org\/transactions\/TXHASH$/);
  assert.match(a.txNote, /succeeded/i);
  assert.match(a.txNote, /refus/i);
});

test("the reason sentence comes from the chain's table when the record carries only a code", () => {
  const a = renderAction({ status: "refused", code: 5, understood: "u" }, REASONS);
  assert.equal(a.reason, "over the per-transaction limit");
});

test("a code the table does not have is said to be unknown, not invented", () => {
  const a = renderAction({ status: "refused", code: 99, understood: "u" }, REASONS);
  assert.match(a.reason, /not in the chain's table/);
});

test("a failed transfer says the chain gives no reason, instead of making one up", () => {
  const a = renderAction({ status: "failed", understood: "u" }, REASONS);
  assert.equal(a.tone, "failed");
  assert.match(a.note, /no reason/i);
});

test("an allowed payment says money moved", () => {
  const a = renderAction({ status: "allowed", understood: "u", tx: "T" }, REASONS);
  assert.equal(a.moved, true);
});

// --- decision_log: two rings, node can be null ----------------------------------------

const LOG = {
  decisions: [refused(4, "payee is not on the allow-list", { agent: BETA }), dec({})],
  decision_count: 2,
  strangers: [refused(1, "no rule for this agent's node", { agent: WALLET, node: "testnet" })],
  stranger_count: 1,
};

test("both rings are kept apart", () => {
  const r = renderDecisions(LOG, REASONS, 2000);
  assert.equal(r.agents.length, 2);
  assert.equal(r.strangers.length, 1);
  assert.equal(r.agents[0].ring, "agents");
  assert.equal(r.strangers[0].ring, "strangers");
});

test("every refusal row prints the chain's sentence", () => {
  const r = renderDecisions(LOG, REASONS, 2000);
  assert.equal(r.agents[0].reason, "payee is not on the allow-list");
  assert.equal(r.strangers[0].reason, "no rule for this agent's node");
  assert.equal(r.agents[1].reason, null);
});

test("a null node is rendered as no node, never as the agent's name", () => {
  const log = { ...LOG, strangers: [refused(1, "no rule for this agent's node", { agent: "nodot", node: null })] };
  const row = renderDecisions(log, REASONS, 2000).strangers[0];
  assert.equal(row.node, null);
  assert.match(row.nodeLabel, /no budget node/i);
  assert.doesNotMatch(row.nodeLabel, /nodot/);
});

test("counts report how many older entries each ring has dropped", () => {
  const r = renderDecisions({ ...LOG, decision_count: 27, stranger_count: 9 }, REASONS, 2000);
  assert.equal(r.agentsDropped, 25);
  assert.equal(r.strangersDropped, 8);
  assert.equal(r.strangerCount, 9);
});

test("an empty or missing log renders empty lists", () => {
  const r = renderDecisions(null, REASONS, 2000);
  assert.deepEqual([r.agents, r.strangers], [[], []]);
});

// --- the budget bar -------------------------------------------------------------------

const RULE = { period_limit: "5000000", per_tx_limit: "1000000", payees: [PAY1] };
const sum = (segs) => segs.reduce((t, s) => t + BigInt(s.raw), 0n);

test("the budget bar segments by agent and sums to spent_in_period", () => {
  const log = {
    decisions: [
      dec({ agent: ALPHA, amount: "1000000", timestamp_ms: 3000 }),
      refused(4, "x", { agent: BETA, amount: "100000", timestamp_ms: 2900 }),
      dec({ agent: BETA, amount: "200000", timestamp_ms: 2000 }),
      dec({ agent: ALPHA, amount: "100000", timestamp_ms: 1500 }),
    ],
    decision_count: 4, strangers: [], stranger_count: 0,
  };
  const b = renderBudget({ rule: RULE, spent: "1300000", windowBeganMs: 1000, log });
  assert.equal(b.spent, "1.30");
  assert.equal(b.limit, "5.00");
  assert.equal(sum(b.segments), 1300000n);
  assert.deepEqual(b.segments.map((s) => [s.agent, s.raw]), [[ALPHA, "1100000"], [BETA, "200000"]]);
  // the refusal did not spend anything
  assert.equal(b.segments.find((s) => s.agent === BETA).raw, "200000");
});

test("widths are percent of the limit and the segments never exceed the track", () => {
  const log = { decisions: [dec({ amount: "2500000", timestamp_ms: 2000 })], decision_count: 1, strangers: [], stranger_count: 0 };
  const b = renderBudget({ rule: RULE, spent: "2500000", windowBeganMs: 1000, log });
  assert.equal(b.segments[0].pct, 50);
  assert.equal(b.pct, 50);
});

test("spend the ring no longer shows is kept as its own segment so the bar still sums", () => {
  const log = { decisions: [dec({ agent: ALPHA, amount: "300000", timestamp_ms: 2000 })], decision_count: 30, strangers: [], stranger_count: 0 };
  const b = renderBudget({ rule: RULE, spent: "1300000", windowBeganMs: 1000, log });
  assert.equal(sum(b.segments), 1300000n);
  const other = b.segments.find((s) => s.agent === null);
  assert.equal(other.raw, "1000000");
  assert.match(other.label, /older|not in the log/i);
});

test("a failed transfer is not counted: the chain released the reservation", () => {
  const log = { decisions: [dec({ amount: "400000", timestamp_ms: 2000, outcome: { status: "failed" } })], decision_count: 1, strangers: [], stranger_count: 0 };
  const b = renderBudget({ rule: RULE, spent: "0", windowBeganMs: 1000, log });
  assert.equal(sum(b.segments), 0n);
});

test("entries from before the window began are not attributed to this window", () => {
  const log = { decisions: [dec({ amount: "400000", timestamp_ms: 500 })], decision_count: 1, strangers: [], stranger_count: 0 };
  const b = renderBudget({ rule: RULE, spent: "0", windowBeganMs: 1000, log });
  assert.equal(b.segments.length, 0);
});

test("a tiny spend is still visible but not overstated", () => {
  const rule = { ...RULE, period_limit: "1000000000" };
  const log = { decisions: [dec({ amount: "5000000", timestamp_ms: 2000 })], decision_count: 1, strangers: [], stranger_count: 0 };
  const b = renderBudget({ rule, spent: "5000000", windowBeganMs: 1000, log });
  assert.equal(b.segments[0].pct, 0.5);
});

test("no rule renders no bar and says so", () => {
  const b = renderBudget({ rule: null, spent: "0", windowBeganMs: null, log: null });
  assert.equal(b.hasRule, false);
  assert.deepEqual(b.segments, []);
});

// --- the headline: the wallet has no keys ---------------------------------------------

test("renders the wallet's empty key list as the headline fact", () => {
  const w = renderWalletKeys({ keys: [] }, WALLET);
  assert.equal(w.known, true);
  assert.equal(w.count, 0);
  assert.equal(w.tone, "zero");
  assert.match(w.headline, /no keys|zero keys|0 keys/i);
  assert.match(w.detail, /nobody can sign as it/i);
  assert.match(w.detail, /spend/);
});

test("a wallet that still has a key does not get the headline", () => {
  const w = renderWalletKeys({ keys: [{ public_key: "ed25519:AAA", access_key: { permission: "FullAccess" } }] }, WALLET);
  assert.equal(w.count, 1);
  assert.equal(w.tone, "keys");
  assert.doesNotMatch(w.headline, /no keys|zero keys|0 keys/i);
  assert.equal(w.keys[0].kind, "full access");
});

test("an unreadable key list is unknown, never zero", () => {
  const w = renderWalletKeys(null, WALLET);
  assert.equal(w.known, false);
  assert.equal(w.count, null);
  assert.equal(w.tone, "unknown");
  assert.doesNotMatch(w.headline, /no keys|zero keys|0 keys/i);
});

test("an agent account's single key is described from the RPC answer", () => {
  const list = { keys: [{ public_key: "ed25519:2PR2G", access_key: { permission: { FunctionCall: { receiver_id: WALLET, method_names: ["spend"], allowance: "1" } } } }] };
  const k = renderAgentKeys(list, ALPHA, WALLET);
  assert.equal(k.count, 1);
  assert.equal(k.keys[0].kind, `spend on ${WALLET}`);
  assert.equal(k.keys[0].restricted, true);
});

test("a full-access key on an agent is flagged, not described as spend-only", () => {
  const k = renderAgentKeys({ keys: [{ public_key: "ed25519:X", access_key: { permission: "FullAccess" } }] }, ALPHA, WALLET);
  assert.equal(k.keys[0].restricted, false);
  assert.equal(k.keys[0].kind, "full access");
});

// --- small things ---------------------------------------------------------------------

test("formatUsdc is integer arithmetic on the chain's strings", () => {
  assert.equal(formatUsdc("500000"), "0.50");
  assert.equal(formatUsdc("12345678901234567890"), "12345678901234.56");
  assert.equal(formatUsdc(null), "—");
});

test("shortId keeps the readable head and tail of a long account id", () => {
  assert.equal(shortId(ALPHA), ALPHA);
  assert.equal(shortId("a".repeat(70)).length < 70, true);
  assert.equal(shortId(null), "—");
});

test("relativeTime is coarse", () => {
  assert.equal(relativeTime(1000, 1060), "just now");
  assert.equal(relativeTime(0, 1060), "");
});

test("a spend key pointed at some other account is not called restricted", () => {
  const list = { keys: [{ public_key: "ed25519:2PR2G", access_key: { permission: { FunctionCall: { receiver_id: "elsewhere.testnet", method_names: ["spend"] } } } }] };
  assert.equal(renderAgentKeys(list, ALPHA, WALLET).keys[0].restricted, false);
});

// --- linking a log row to its transaction ---------------------------------------------

test("a row the agent sent links to its transaction", () => {
  const log = { decisions: [refused(4, "payee is not on the allow-list", { agent: BETA, timestamp_ms: 4242 })], decision_count: 1, strangers: [], stranger_count: 0 };
  const row = renderDecisions(log, REASONS, 5000, { [`${BETA}|4242`]: "TXHASH" }).agents[0];
  assert.equal(row.txUrl, txUrl("TXHASH"));
  assert.equal(row.noLink, null);
});

test("a row nobody here sent says why it has no link instead of a dead affordance", () => {
  const log = { decisions: [dec({ timestamp_ms: 1 })], decision_count: 1, strangers: [refused(1, "no rule for this agent's node", { agent: "x.testnet", timestamp_ms: 2 })], stranger_count: 1 };
  const r = renderDecisions(log, REASONS, 5000, {});
  assert.equal(r.agents[0].txUrl, null);
  assert.match(r.agents[0].noLink, /no transaction link/i);
  assert.equal(r.strangers[0].txUrl, null);
  assert.match(r.strangers[0].noLink, /stranger/i);
});

// --- how old the chain read is --------------------------------------------------------

import { renderAge } from "./demo-render.mjs";

test("renderAge says how old a read is, and says nothing was read when it was not", () => {
  assert.equal(renderAge(1000, 1000), "just now");
  assert.equal(renderAge(1000, 8000), "7s ago");
  assert.equal(renderAge(1000, 125000), "2m ago");
  assert.equal(renderAge(null, 5000), "not read yet");
});

// --- how a send ended, by its own name --------------------------------------------------

test("a send that never reached the chain says so, and that nothing moved", () => {
  const a = renderAction({ status: "error", errorKind: "not-sent", reason: "could not reach the chain to prepare the payment, so nothing was sent", understood: "u" }, REASONS);
  assert.equal(a.inFlight, false);
  assert.equal(a.unresolved, false);
  assert.equal(a.moved, false);
  assert.match(a.label, /NOT SENT/);
  assert.match(a.label, /chain/i);
});

// NEAR rolls back per receipt: a failed transaction does not say money did not move.
test("a failure whose receipts show nothing moved says rolled back", () => {
  const a = renderAction({ status: "error", errorKind: "chain-failed", moved: false, reason: "spend itself failed", understood: "u" }, REASONS);
  assert.match(a.label, /FAILED ON CHAIN/);
  assert.equal(a.moved, false);
  assert.notEqual(a.tone, "refused");
  assert.match(a.note, /before any money moved/);
});

test("a failure after the transfer succeeded says the money DID move, and never says it did not", () => {
  const a = renderAction({ status: "error", errorKind: "chain-failed", moved: true, tx: "T", reason: "callback ran out of gas", understood: "u" }, REASONS);
  assert.equal(a.moved, true);
  assert.match(a.label, /PAID/);
  assert.match(a.note, /DID move/);
  assert.doesNotMatch(`${a.label} ${a.note}`, /no money moved|rolled back/i);
  assert.ok(a.txUrl);
});

test("a failure the receipts cannot explain claims neither, and points at the receipts", () => {
  for (const moved of [null, undefined]) {
    const a = renderAction({ status: "error", errorKind: "chain-failed", moved, tx: "T", understood: "u" }, REASONS);
    assert.equal(a.moved, null);
    assert.match(a.label, /check the receipts/i);
    assert.doesNotMatch(`${a.label} ${a.note}`, /no money moved|rolled back|before any money/i);
    assert.match(a.note, /does not say whether the money moved/);
  }
});

test("a transaction refused before it ran is rejected, not refused by the contract", () => {
  const a = renderAction({ status: "error", errorKind: "rejected", reason: "InvalidNonce", understood: "u" }, REASONS);
  assert.match(a.label, /REJECTED/);
  assert.equal(a.moved, false);
  assert.equal(a.reason, "InvalidNonce");
});

test("sent but not confirmed is unresolved and says it may still land", () => {
  const a = renderAction({ status: "unknown", errorKind: "unconfirmed", reason: "sent, but the chain could not be reached to confirm", tx: "T", understood: "u" }, REASONS);
  assert.equal(a.unresolved, true);
  assert.equal(a.inFlight, false);
  assert.match(a.label, /NOT CONFIRMED/);
  assert.match(a.note, /may still land/i);
});
