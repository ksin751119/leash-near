// Pure functions from what the page read (agent /state, contract views, RPC key lists) to the
// strings and shapes it prints.
//
// They live in their own module so the layout's logic is testable without a browser. Nothing
// here decides anything: every verdict and every reason sentence is copied out of what the
// chain returned. The one table of sentences is `refusal_codes()`, passed in as `reasons`;
// no sentence about a refusal is written in this file, because a second copy drifts and then
// the screen lies.

// near.rocks, not explorer.testnet.near.org (a chooser page with no transaction on it) and not
// nearblocks (Cloudflare-gated against headless browsers, so an AI judge cannot open it). near.rocks
// renders without a gate and shows every receipt with its logs: an EVENT_JSON line whose
// `standard` is "leash" and whose `event` is "allowed", "settled" or "refused"
// and the returned decision. It shows no green tick; it shows no failure.
export const EXPLORER = "https://testnet.near.rocks";
export const txUrl = (hash) => `${EXPLORER}/tx/${hash}`;
export const accountUrl = (id) => `${EXPLORER}/account/${id}`;

// NEAR account ids run to 64 characters. Short enough ones are printed whole: an id is
// something a judge may want to compare with the explorer.
export const shortId = (id) =>
  typeof id === "string" && id.length > 40 ? `${id.slice(0, 22)}…${id.slice(-14)}` : (id ?? "—");

// Amounts are decimal strings from the chain; BigInt, because Number rounds past 2^53.
export function formatUsdc(raw, decimals = 6) {
  if (raw == null) return "—";
  try {
    const unit = 10n ** BigInt(decimals);
    const v = BigInt(raw);
    const cents = ((v % unit) * 100n) / unit;
    return `${v / unit}.${String(cents).padStart(2, "0")}`;
  } catch {
    return "—";
  }
}

export function relativeTime(atSec, nowSec) {
  const at = Number(atSec ?? 0);
  if (!at) return "";
  const d = Math.max(0, nowSec - at);
  if (d < 90) return "just now";
  if (d < 3600) return `${Math.round(d / 60)}m ago`;
  if (d < 86400) return `${Math.round(d / 3600)}h ago`;
  return `${Math.round(d / 86400)}d ago`;
}

// The chain's sentence for a code, from `refusal_codes()`.
function sentenceFor(code, reasons) {
  if (code == null) return null;
  const hit = (reasons ?? []).find((r) => r.code === code);
  return hit ? hit.reason : `code ${code} is not in the chain's table`;
}

// --- lastAction ------------------------------------------------------------------------

const UNDERSTOOD_MISSING = "the agent did not state what it understood";

// One status, one place it ends. Only "in-flight" is still moving. "unknown" and "error" are
// final but unresolved: the agent has stopped waiting and does not know the outcome, and a
// card that kept saying "in flight" for them is the bug this project's predecessor shipped.
export function renderAction(a, reasons) {
  if (!a) return null;
  const base = {
    status: a.status,
    understood: a.understood || UNDERSTOOD_MISSING,
    payee: a.payee ?? null,
    amount: a.amount == null ? null : formatUsdc(a.amount),
    vendor: a.vendor ?? null,
    code: a.code ?? null,
    reason: null,
    inFlight: false,
    unresolved: false,
    moved: null,
    txUrl: a.tx ? txUrl(a.tx) : null,
    txShort: a.tx ? `${a.tx.slice(0, 8)}…` : null,
    txNote: null,
    settledBy: a.settledBy ?? null,
  };
  switch (a.status) {
    case "in-flight":
      return { ...base, inFlight: true, tone: "pending", label: "IN FLIGHT",
        note: "Sent. Waiting for the chain to answer." };
    case "allowed":
      return { ...base, tone: "allowed", label: "ALLOWED", moved: true,
        note: "The contract allowed it and dispatched the transfer.",
        txNote: a.tx ? "Opens the transaction on the explorer." : null };
    case "refused":
      return { ...base, tone: "refused", label: "REFUSED BY THE CHAIN", moved: false,
        reason: a.reason ?? sentenceFor(a.code, reasons),
        note: "No money moved.",
        txNote: a.tx
          ? "This transaction SUCCEEDED, and that is the point. No receipt failed, and it logs an EVENT_JSON line, standard \"leash\", event \"refused\", carrying the reason. The contract returns the refusal instead of reverting, so the decision stays on the chain. A reverted transaction would have left no record at all."
          : null };
    case "failed":
      return { ...base, tone: "failed", label: "FAILED", moved: false,
        note: "The policy allowed it, then the token transfer failed and the reservation was released. NEAR gives the callback no reason, so there is none to show." };
    case "unknown":
    case "error": {
      // The agent names how a send ended (errorKind) when it knows. Four endings, four messages:
      // what the screen says on camera must tell "the chain said no" from "we could not reach it".
      const kind = a.errorKind;
      if (a.status === "error" && kind === "not-sent") {
        return { ...base, tone: "failed", label: "NOT SENT · chain unreachable", moved: false, reason: a.reason ?? null,
          note: "Nothing was sent and no money moved. The agent could not get a working answer from the chain. This is not a refusal." };
      }
      if (a.status === "error" && kind === "rejected") {
        return { ...base, tone: "failed", label: "REJECTED BEFORE IT RAN", moved: false, reason: a.reason ?? null,
          note: "The network refused the transaction itself, before the contract saw it. No money moved. This is not the contract refusing a payment." };
      }
      if (a.status === "error" && kind === "chain-failed") {
        // NEAR rolls back per receipt, not per transaction, so a failed transaction does not by
        // itself say whether money moved. The agent read the receipts (`moved`); say only that.
        const open = a.tx ? "Open the transaction and read its receipts." : null;
        if (a.moved === false) {
          return { ...base, tone: "failed", label: "FAILED ON CHAIN · rolled back", moved: false, reason: a.reason ?? null, txNote: null,
            note: "The receipts show the failure came before any money moved, and the contract recorded no decision. This is not a refusal." };
        }
        if (a.moved === true) {
          return { ...base, tone: "failed", label: "PAID · a later step failed", moved: true, reason: a.reason ?? null, txNote: open,
            note: "The token transfer succeeded, so the money DID move. A later step failed, which is why the transaction shows as failed. The contract's log should show this payment as ALLOWED. Check the transfer receipt before doing anything again." };
        }
        return { ...base, tone: "failed", label: "FAILED ON CHAIN · check the receipts", moved: null, reason: a.reason ?? null, txNote: open,
          note: "The transaction failed on chain. NEAR rolls back per receipt, not per transaction, so this alone does not say whether the money moved. Check the transfer receipt before trying again." };
      }
      if (a.status === "unknown" && kind === "unconfirmed") {
        return { ...base, unresolved: true, tone: "unresolved", label: "SENT · NOT CONFIRMED", reason: a.reason ?? null,
          note: "It was sent but the agent could not confirm what became of it, and it may still land. Not in flight: the agent has stopped waiting. This card checks the chain's log again every poll." };
      }
      return { ...base, unresolved: true, tone: "unresolved",
        label: a.status === "error" ? "UNRESOLVED · error" : "UNRESOLVED · outcome unknown",
        reason: a.reason ?? null,
        note: "This is not in flight: the agent has stopped waiting and does not know how it ended. It may still show up in the chain's log; this card checks again every poll." };
    }
    default:
      return { ...base, unresolved: true, tone: "unresolved",
        label: "UNRESOLVED · unrecognised status",
        note: `The agent reported status "${a.status}", which this page does not know. It is not shown as in flight.` };
  }
}

// --- decision_log ----------------------------------------------------------------------

const NO_NODE = "no budget node (this account id has no “.”)";

function renderRow(d, ring, reasons, nowSec, txs) {
  const o = d.outcome ?? {};
  const tx = txs?.[`${d.agent}|${d.timestamp_ms}`] ?? null;
  return {
    ring,
    agent: d.agent,
    // Null stays null. It is not the agent's name; there is no budget to name.
    node: d.node ?? null,
    nodeLabel: d.node == null ? NO_NODE : d.node,
    payee: d.payee,
    amount: formatUsdc(d.amount),
    raw: d.amount,
    status: o.status ?? "unknown",
    code: o.code ?? null,
    reason: o.status === "refused" ? (o.reason ?? sentenceFor(o.code, reasons)) : null,
    ago: relativeTime(Math.floor((d.timestamp_ms ?? 0) / 1000), nowSec),
    timestampMs: d.timestamp_ms ?? 0,
    // The contract cannot record its own transaction hash, so the chain has none to give. The
    // agent that sent a payment kept the hash; rows nobody here sent have no link, and say so.
    txUrl: tx ? txUrl(tx) : null,
    noLink: tx ? null : ring === "strangers"
      ? "no transaction link: a stranger's call, not sent by these agents"
      : "no transaction link: not sent in this session (an earlier run, or another process)",
  };
}

export function renderAge(atMs, nowMs) {
  if (!atMs) return "not read yet";
  const s = Math.max(0, Math.round((nowMs - atMs) / 1000));
  if (s < 2) return "just now";
  return s < 90 ? `${s}s ago` : `${Math.round(s / 60)}m ago`;
}

export function renderDecisions(log, reasons, nowMs = Date.now(), txs = {}) {
  const nowSec = Math.floor(nowMs / 1000);
  const agents = (log?.decisions ?? []).map((d) => renderRow(d, "agents", reasons, nowSec, txs));
  const strangers = (log?.strangers ?? []).map((d) => renderRow(d, "strangers", reasons, nowSec, txs));
  const count = Number(log?.decision_count ?? 0);
  const scount = Number(log?.stranger_count ?? 0);
  return {
    agents,
    strangers,
    agentCount: count,
    strangerCount: scount,
    agentsDropped: Math.max(0, count - agents.length),
    strangersDropped: Math.max(0, scount - strangers.length),
  };
}

// --- the shared budget -------------------------------------------------------------------

// Tenths of a percent, so 0.5 USDC of 1000 is 0.1% and not 0.
const pctOf = (raw, limit) => {
  try {
    if (BigInt(limit) <= 0n) return 0;
    return Number((BigInt(raw) * 1000n) / BigInt(limit)) / 10;
  } catch {
    return 0;
  }
};

// One bar, segmented by agent. `spent` is `spent_in_period` and is the authority on the total.
// The split is read from the decision ring: allowed payments since the window began, summed
// per agent. A refusal spent nothing and a failed transfer was released, so neither counts.
// If the ring has already dropped some of the spending, the remainder is shown as its own
// grey segment instead of being given to anyone, so the bar always sums to what the chain says.
export function renderBudget({ rule, spent, windowBeganMs, log, decimals = 6 }) {
  if (!rule) return { hasRule: false, segments: [], spent: formatUsdc(spent, decimals), limit: "—", pct: 0 };
  const total = BigInt(spent ?? 0);
  const since = Number(windowBeganMs ?? 0);
  const per = new Map();
  for (const d of log?.decisions ?? []) {
    if (d.outcome?.status !== "allowed") continue;
    if ((d.timestamp_ms ?? 0) < since) continue;
    per.set(d.agent, (per.get(d.agent) ?? 0n) + BigInt(d.amount));
  }
  const segments = [...per.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([agent, raw]) => ({ agent, raw: String(raw), amount: formatUsdc(raw, decimals), pct: pctOf(raw, rule.period_limit), label: agent }));
  const attributed = [...per.values()].reduce((t, v) => t + v, 0n);
  if (total > attributed) {
    const raw = total - attributed;
    segments.push({ agent: null, raw: String(raw), amount: formatUsdc(raw, decimals), pct: pctOf(raw, rule.period_limit), label: "older spending, no longer in the log" });
  }
  return {
    hasRule: true,
    spent: formatUsdc(total, decimals),
    limit: formatUsdc(rule.period_limit, decimals),
    perTx: formatUsdc(rule.per_tx_limit, decimals),
    pct: pctOf(total, rule.period_limit),
    segments,
    // The ring says more than the chain's total. Possible only if the two reads straddled a
    // spend; shown rather than hidden.
    overAttributed: attributed > total,
  };
}

// --- keys ----------------------------------------------------------------------------------

function describeKey(k, wallet) {
  const p = k.access_key?.permission;
  if (p === "FullAccess") return { key: k.public_key, kind: "full access", restricted: false };
  const fc = p?.FunctionCall;
  if (!fc) return { key: k.public_key, kind: "unrecognised permission", restricted: false };
  const methods = (fc.method_names ?? []).join(", ") || "any method";
  const restricted = fc.receiver_id === wallet && methods === "spend";
  return { key: k.public_key, kind: `${methods} on ${fc.receiver_id}`, restricted };
}

// The headline. Zero keys of any kind on the account that holds the money. An unreadable list
// is "unknown": the page must never turn a failed RPC into the strongest claim it makes.
export function renderWalletKeys(list, wallet) {
  if (!list || !Array.isArray(list.keys)) {
    return { known: false, count: null, tone: "unknown", keys: [],
      headline: "Cannot read the wallet's keys right now",
      detail: "The RPC did not answer, so this page makes no claim about the wallet's keys." };
  }
  const keys = list.keys.map((k) => describeKey(k, wallet));
  if (keys.length === 0) {
    return { known: true, count: 0, tone: "zero", keys,
      headline: "The wallet has zero keys",
      detail: "The account that holds the money has no access keys of any kind, so nobody can sign as it. Money leaves by exactly two doors: spend, which an agent calls from its own account and the contract decides, and withdraw, which needs a passkey. Neither opens for the admin key alone." };
  }
  return { known: true, count: keys.length, tone: "keys", keys,
    headline: `The wallet still has ${keys.length} key${keys.length === 1 ? "" : "s"}`,
    detail: "Someone can still sign as this account. It has not been frozen." };
}

// An agent's own account: the key it signs spend with. `wallet` is where that key is allowed
// to call, so a key that points anywhere else is not called restricted.
export function renderAgentKeys(list, agent, wallet) {
  if (!list || !Array.isArray(list.keys)) return { agent, known: false, count: null, keys: [] };
  const keys = list.keys.map((k) => describeKey(k, wallet));
  return { agent, known: true, count: keys.length, keys };
}
