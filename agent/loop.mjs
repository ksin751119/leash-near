// One agent process. Started with AGENT_NAME, AGENT_ACCOUNT, PORT; holds no key that signs as
// anything but AGENT_ACCOUNT, and has no channel to the other agent. The two share a budget
// only because their accounts share a parent, which the contract reads off the account id.
//
//   GET  /state     { name, agentAddr, lastAction, cohort, refusals }
//   POST /instruct  { text }  natural language -> one attempted payment
//
// The chain is the authority on what happened. `lastAction` is reconciled against
// decision_log() every time it is read, and again when a send finishes, and it can never be
// left "in-flight" by a send that ended any way at all: that was the previous project's
// latch bug (a refusal never cleared the in-flight card, because only success did).
import { createServer } from "node:http";
import { readFileSync, statSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { decide, formatUnits, parseUnits } from "./decide.mjs";
import { readLog as chainLog, readView as chainView, makeReader } from "./chain.mjs";
import { sendSpend, lookupTx, describeResult } from "./send.mjs";
import { loadSent, saveSent } from "./sentstore.mjs";
import { parseInstruction } from "./parse.mjs";

const here = dirname(fileURLToPath(import.meta.url));

// --- reconciling with the chain -------------------------------------------------------

const sameAttempt = (e, a) => e.agent === a.agent && e.payee === a.payee && e.amount === a.amount;

// Turn one chain record into the fields lastAction shows.
const fromRecord = (e) => ({
  status: e.outcome.status,
  code: e.outcome.code ?? null,
  reason: e.outcome.reason ?? null,
  spentAfter: e.spent_after,
});

// Only "in-flight" is re-checked against the chain's log: it is this process's belief that a send
// is still running, and the log may show the decision before the send call returns.
//
// "unknown" (sent, not confirmed) is NOT settled from the log. It has a transaction hash, and the
// only thing that may resolve it is a lookup of that hash (resolveUnconfirmed below). And the
// named endings (error: not-sent, rejected, chain-failed) are final: letting a log match settle
// them let a "could not reach the chain" card flip into "refused by the chain" because an
// identical refusal had happened a minute earlier. Those two statements must never be
// interchangeable on screen.
const PROVISIONAL = new Set(["in-flight"]);

// A provisional action is settled by the newest record, written since it was sent, for the same
// agent, payee and amount, counted from the log size taken just before the send. When that
// count is unknown (the pre-send read failed) nothing is matched: there is no timestamp
// fallback, because a stamp cannot tell this attempt from an identical earlier one. It stays
// in-flight until the send's own result arrives. Whatever the chain recorded wins, refusals
// included. Anything already final is returned untouched.
export function settle(action, chain) {
  if (!action || !PROVISIONAL.has(action.status)) return action;
  const known = action.countBefore != null && action.strangersBefore != null;
  if (!known) return action;
  const newer = (list, count, before) => list.slice(0, Math.max(0, count - before));
  const candidates = [
    ...newer(chain.decisions, chain.decision_count, action.countBefore),
    ...newer(chain.strangers, chain.stranger_count, action.strangersBefore),
  ];
  const hit = candidates.find((e) => sameAttempt(e, action));
  return hit ? { ...action, ...fromRecord(hit), settledBy: "chain" } : action;
}

// Which transaction caused which decision. The contract cannot record its own transaction hash
// (NEAR gives a contract no access to it), so the chain has none to offer; but this process knows
// the hash of every payment it sent. A decision is matched to an attempt the same way settle()
// does: same agent, payee and amount, among the entries written since the attempt began. Each
// decision is claimed by at most one attempt, oldest first. Keys are "<agent>|<timestamp_ms>".
// Only this agent's own attempts are here: another agent's decisions, and strangers', have no
// hash from this process, and the page says so.
export function matchTxs(sent, chain) {
  const out = {};
  const claimed = new Set();
  const key = (e) => `${e.agent}|${e.timestamp_ms}`;
  for (const a of sent) {
    if (!a.tx) continue;
    const known = a.countBefore != null && a.strangersBefore != null;
    const newer = (list, count, before) => list.slice(0, Math.max(0, count - before));
    const pool = known
      ? [...newer(chain.decisions, chain.decision_count, a.countBefore), ...newer(chain.strangers, chain.stranger_count, a.strangersBefore)]
      : [...chain.decisions, ...chain.strangers].filter((e) => e.timestamp_ms >= a.at - CLOCK_SKEW_MS);
    // newest first, so the last match is the oldest unclaimed one
    const hit = [...pool].reverse().find((e) => sameAttempt(e, a) && !claimed.has(key(e)));
    if (hit) { claimed.add(key(hit)); out[key(hit)] = a.tx; }
  }
  return out;
}

// Keeps the hash of a payment this process sent, and saves the record (state.save, set in start()).
function remember(state, entry) {
  state.sent ??= [];
  const i = state.sent.findIndex((e) => e.tx === entry.tx);
  if (i >= 0) state.sent[i] = entry; else state.sent.push(entry);
  if (state.sent.length > 40) state.sent.shift();
  state.save?.();
}

// Sends one payment and leaves state.lastAction in a final state no matter how it ends.
export async function sendAndRecord(state, intent, { send, readLog }) {
  const attempt = { agent: intent.agent, payee: intent.payee, amount: String(intent.amount) };
  let before = null;
  try { before = await readLog(); } catch { /* counts unknown: settle() then matches nothing */ }
  const action = (state.lastAction = {
    status: "in-flight",
    ...attempt,
    token: intent.token,
    vendor: intent.vendor ?? null,
    // What the agent says it understood, set before anything is sent so a misparse is on screen.
    understood: intent.understood ?? null,
    text: intent.text ?? null,
    prediction: intent.prediction ?? null,
    // null, with countKnown false, when the pre-send read failed: honest in JSON, and settle()
    // switches to matching on the timestamp.
    countKnown: before != null,
    countBefore: before?.decision_count ?? null,
    strangersBefore: before?.stranger_count ?? null,
    tx: null,
    at: Date.now(),
  });
  // Remember the hash the moment it exists (after signing, before the broadcast), so an agent
  // killed mid-send still has the link to what it may have sent.
  const onSigned = (hash) => {
    action.tx = hash;
    remember(state, { ...attempt, tx: hash, at: action.at, countBefore: action.countBefore, strangersBefore: action.strangersBefore });
  };
  try {
    const sent = await send(intent, { onSigned });
    action.tx = sent.txHash ?? action.tx;
    // spend's return value, from this transaction's own final result, is the chain speaking about
    // exactly this payment.
    state.lastAction = sent.outcome?.status
      ? { ...action, status: sent.outcome.status, code: sent.outcome.code ?? null, reason: sent.outcome.reason ?? null, settledBy: "transaction" }
      : { ...action, status: "unknown", errorKind: "unconfirmed", reason: "sent, but its result could not be read" };
    if (action.tx) remember(state, { ...attempt, tx: action.tx, at: action.at, countBefore: action.countBefore, strangersBefore: action.strangersBefore });
  } catch (err) {
    // SendError names how it ended (send.mjs); anything else is an unexpected failure of ours,
    // final and unnamed. "unconfirmed" is the one ending where the chain may still have the
    // payment; resolveUnconfirmed keeps asking for that exact hash.
    const kind = err?.kind ?? null;
    const status = kind === "unconfirmed" ? "unknown" : "error";
    state.lastAction = { ...action, status, errorKind: kind, tx: err?.txHash ?? action.tx, reason: String(err.message ?? err).slice(0, 300) };
    if (state.lastAction.tx) remember(state, { ...attempt, tx: state.lastAction.tx, at: action.at, countBefore: action.countBefore, strangersBefore: action.strangersBefore });
  }
  return state.lastAction;
}

// An unconfirmed send is resolved by asking the chain about its exact hash, never by guessing from
// the log. `lookup(hash)` is send.mjs's lookupTx. Stops as soon as the action on screen is no
// longer this one (a new instruction replaced it) or after `tries` rounds.
export async function resolveUnconfirmed(state, hash, { lookup, tries = 60, waitMs = 5_000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  for (let i = 0; i < tries; i++) {
    const a = state.lastAction;
    if (!a || a.tx !== hash || a.status !== "unknown") return false;
    const r = await lookup(hash).catch(() => ({ state: "unreachable" }));
    if (r.state === "found") {
      const d = describeResult(r.result);
      if (state.lastAction?.tx === hash) state.lastAction = { ...state.lastAction, ...d, settledBy: "transaction-lookup" };
      return true;
    }
    await sleep(waitMs);
  }
  return false;
}

// --- what /state returns ---------------------------------------------------------------

const row = (e, ring, units) => ({
  agent: e.agent,
  // Null when the caller's id has no ".", so there is no budget to name. Not the agent.
  node: e.node ?? null,
  payee: e.payee,
  amount: e.amount,
  amountFormatted: formatUnits(e.amount, units.decimals),
  status: e.outcome.status,
  code: e.outcome.code ?? null,
  reason: e.outcome.reason ?? null,
  spentAfter: e.spent_after,
  timestampMs: e.timestamp_ms,
  ring,
});

export function publicState(state, chain, view) {
  const { units } = view;
  const fmt = (n) => formatUnits(n, units.decimals);
  const rule = view.rule;
  const spent = BigInt(view.spent);
  const limit = rule ? BigInt(rule.period_limit) : 0n;
  const recent = chain.decisions.map((e) => row(e, "decisions", units));
  return {
    name: state.name,
    agentAddr: state.agentAddr,
    lastAction: settle(state.lastAction, chain),
    cohort: {
      node: view.node,
      symbol: units.symbol,
      perTx: rule ? fmt(rule.per_tx_limit) : null,
      period: rule ? fmt(rule.period_limit) : null,
      periodMs: rule?.period_ms ?? null,
      spent: fmt(spent),
      left: fmt(limit > spent ? limit - spent : 0n),
      payees: rule?.payees ?? [],
      paused: rule?.paused ?? false,
      // Every real agent that has acted on this budget, from the chain: the other agent shows
      // up here although this process never spoke to it.
      agents: [...new Set(recent.map((r) => r.agent))],
      recent,
    },
    // The chain's own answers, passed through as read, so the page needs no RPC of its own for
    // them. `readAt` says how old each is (epoch ms); `errors` lists views currently failing, in
    // which case the value is the last good one.
    chain: {
      node: view.node,
      rule,
      spent: view.spent,
      windowBeganMs: view.windowBeganMs ?? null,
      paused: view.accountPaused ?? null,
      reasons: view.reasons,
      log: chain,
      readAt: view.readAt ?? null,
      keys: view.keys ?? null,
      errors: view.errors ?? [],
    },
    txs: matchTxs(state.sent ?? [], chain),
    refusals: {
      agents: recent.filter((r) => r.status === "refused"),
      decisionCount: chain.decision_count,
      strangers: chain.strangers.map((e) => row(e, "strangers", units)),
      strangerCount: chain.stranger_count,
    },
  };
}

// --- instructions ------------------------------------------------------------------------

export { parseInstruction };

// The key file signs as the agent account. Anyone who can read it can spend its budget, so a
// file readable by group or others is something to say out loud before the first send.
export function keyFileWarning(path, mode) {
  if ((mode & 0o077) === 0) return null;
  return `WARNING: ${path} is mode ${(mode & 0o777).toString(8)}, not 600. Anyone who can read it can spend this agent's budget. Run: chmod 600 ${path}`;
}

// --- the process ---------------------------------------------------------------------------

function config() {
  const dep = JSON.parse(readFileSync(join(here, "..", "deployments", "testnet.json"), "utf8"));
  const name = (process.env.AGENT_NAME || "").trim();
  const agentAddr = (process.env.AGENT_ACCOUNT || "").trim();
  if (!name || !agentAddr) throw new Error("AGENT_NAME and AGENT_ACCOUNT are required");
  const keyFile = process.env.AGENT_KEY_FILE || join(homedir(), ".leash-testnet", `akf-${agentAddr.split(".")[0]}.json`);
  const warn = keyFileWarning(keyFile, statSync(keyFile).mode);
  if (warn) console.error(`\n!!! ${warn}\n`);
  return {
    name,
    agentAddr,
    port: Number(process.env.PORT || 8788),
    wallet: process.env.WALLET || dep.wallet,
    token: process.env.TOKEN || dep.token,
    units: { decimals: Number(process.env.TOKEN_DECIMALS || 6), symbol: process.env.TOKEN_SYMBOL || "USDC" },
    keyFile,
    sentFile: process.env.AGENT_SENT_FILE || join(here, `.sent-${agentAddr}.json`),
    vendors: JSON.parse(readFileSync(join(here, "vendors.json"), "utf8")),
  };
}

export function start(cfg = config()) {
  // Which transaction caused which decision survives a restart: a small file beside the agent.
  const sentFile = cfg.sentFile;
  const state = { name: cfg.name, agentAddr: cfg.agentAddr, lastAction: null, sent: loadSent(sentFile) };
  state.save = () => { if (!saveSent(sentFile, state.sent)) console.error(`WARNING: could not write ${sentFile}; transaction links will not survive a restart`); };
  // One reader per process, with the call budget described in chain.mjs.
  const reader = makeReader({ swr: true });
  const readView = (opts = {}) => chainView({ wallet: cfg.wallet, agent: cfg.agentAddr, units: cfg.units, reader, ...opts });
  const readLog = () => chainLog(cfg.wallet, reader);
  // Around a send the log must be current, not up to 5 s old: the pre-send count decides which
  // entries are "mine".
  const readLogFresh = () => chainLog(cfg.wallet, reader, { fresh: true });
  const send = (i, hooks) => sendSpend({ wallet: cfg.wallet, agent: cfg.agentAddr, keyFile: cfg.keyFile, token: i.token, payee: i.payee, amount: i.amount, ...hooks });

  const json = (res, code, body) => {
    res.writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" });
    res.end(JSON.stringify(body));
  };
  const readBody = (req) => new Promise((ok, no) => {
    let s = "";
    req.on("data", (c) => { s += c; if (s.length > 10_000) { no(new Error("body too large")); req.destroy(); } });
    req.on("end", () => ok(s));
    req.on("error", no);
  });

  // Warm the cache so the first /state does not pay for every cold read in sequence.
  Promise.all([readLog(), readView(), reader.call(cfg.wallet, "view_access_key_list"), reader.call(cfg.agentAddr, "view_access_key_list")]).catch(() => {});

  return createServer(async (req, res) => {
    try {
      if (req.method === "OPTIONS") return json(res, 204, {});
      if (req.method === "GET" && req.url === "/state") {
        const [chain, view] = await Promise.all([readLog(), readView()]);
        view.readAt = {
          decision_log: reader.readAt(cfg.wallet, "decision_log"),
          node_record: view.node ? reader.readAt(cfg.wallet, "node_record", { node: view.node }) : null,
          is_paused: reader.readAt(cfg.wallet, "is_paused"),
        };
        // Key lists, from the same reader (30 s cache). Failure leaves the field null, never empty:
        // an unreadable list must not turn into "zero keys" on the page.
        const keyOf = async (account) => {
          try { return { account, list: await reader.call(account, "view_access_key_list"), at: reader.readAt(account, "view_access_key_list") }; }
          catch { return null; }
        };
        view.keys = { wallet: await keyOf(cfg.wallet), self: await keyOf(cfg.agentAddr) };
        view.errors = reader.errors();
        return json(res, 200, publicState(state, chain, view));
      }
      if (req.method === "POST" && req.url === "/instruct") {
        let text;
        try { text = JSON.parse(await readBody(req)).text; } catch { return json(res, 400, { error: "send JSON: {\"text\": \"...\"}" }); }
        const parsed = parseInstruction(text, cfg.vendors, cfg.units.decimals, { symbol: cfg.units.symbol });
        if (parsed.error) return json(res, 422, { error: parsed.error });
        const intent = { agent: cfg.agentAddr, token: cfg.token, payee: parsed.payee, amount: parsed.amount, vendor: parsed.vendor, understood: parsed.understood, text };
        intent.prediction = decide(await readView(), intent);
        // Sends whatever the prediction says: the chain is what refuses, and the refusal is
        // the thing worth recording.
        const done = await sendAndRecord(state, intent, { send, readLog: readLogFresh });
        readView({ fresh: true }).catch(() => {}); // the budget just moved; refresh what /state serves
        if (done.status === "unknown" && done.tx) resolveUnconfirmed(state, done.tx, { lookup: (h) => lookupTx({ hash: h, agent: cfg.agentAddr }) });
        return json(res, 200, { prediction: intent.prediction, lastAction: done });
      }
      json(res, 404, { error: "not found" });
    } catch (err) {
      json(res, 500, { error: String(err.message ?? err).slice(0, 300) });
    }
  }).listen(cfg.port, () => console.log(`${cfg.name} (${cfg.agentAddr}) on :${cfg.port}`));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) start();
