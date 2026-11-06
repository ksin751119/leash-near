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
import { readLog as chainLog, readView as chainView } from "./chain.mjs";
import { sendSpend } from "./send.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_RE = /\b[a-z0-9][a-z0-9_.-]*\.(?:testnet|near)\b/;

// --- reconciling with the chain -------------------------------------------------------

const sameAttempt = (e, a) => e.agent === a.agent && e.payee === a.payee && e.amount === a.amount;

// Turn one chain record into the fields lastAction shows.
const fromRecord = (e) => ({
  status: e.outcome.status,
  code: e.outcome.code ?? null,
  reason: e.outcome.reason ?? null,
  spentAfter: e.spent_after,
});

// Statuses that are only this process's belief. "allowed", "refused" and "failed" are the
// chain's words; everything else is ours and is re-checked against the chain every time.
// "unknown" and "error" are here on purpose: a send that timed out or exited non-zero can
// still have landed and been refused, and a screen that keeps saying "error" while the chain
// says "refused" is the latch bug under another name.
const PROVISIONAL = new Set(["in-flight", "unknown", "error"]);

// Local clock vs block time: how far back a record may be stamped and still count as ours when
// the pre-send count is unknown.
const CLOCK_SKEW_MS = 60_000;

// A provisional action is settled by the newest record, written since it was sent, for the
// same agent, payee and amount. Whatever the chain recorded wins, refusals included. Anything
// already final is returned untouched.
export function settle(action, chain) {
  if (!action || !PROVISIONAL.has(action.status)) return action;
  const known = action.countBefore != null && action.strangersBefore != null;
  const newer = (list, count, before) => list.slice(0, Math.max(0, count - before));
  const candidates = known
    ? [
        ...newer(chain.decisions, chain.decision_count, action.countBefore),
        ...newer(chain.strangers, chain.stranger_count, action.strangersBefore),
      ]
    // The pre-send read failed, so "new since" cannot be counted; fall back to the stamp.
    : [...chain.decisions, ...chain.strangers].filter((e) => e.timestamp_ms >= action.at - CLOCK_SKEW_MS);
  const hit = candidates.find((e) => sameAttempt(e, action));
  return hit ? { ...action, ...fromRecord(hit), settledBy: "chain" } : action;
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
  try {
    const sent = await send(intent);
    action.tx = sent.txHash ?? null;
    let after = null;
    try { after = await readLog(); } catch { /* fall back to the return value below */ }
    let next = after ? settle(action, after) : action;
    // The chain has not shown the record yet, or could not be read. spend's own return value
    // is the chain speaking too (a refusal returns immediately), so use it, but say so.
    if (next.status === "in-flight" && sent.outcome?.status) {
      next = { ...next, status: sent.outcome.status, code: sent.outcome.code ?? null, reason: sent.outcome.reason ?? null, settledBy: "return-value" };
    }
    if (next.status === "in-flight") {
      next = { ...next, status: "unknown", reason: "sent, but the chain has not recorded it yet" };
    }
    state.lastAction = next;
  } catch (err) {
    state.lastAction = { ...action, status: "error", reason: String(err.message ?? err).slice(0, 300) };
  }
  return state.lastAction;
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
    refusals: {
      agents: recent.filter((r) => r.status === "refused"),
      decisionCount: chain.decision_count,
      strangers: chain.strangers.map((e) => row(e, "strangers", units)),
      strangerCount: chain.stranger_count,
    },
  };
}

// --- instructions ------------------------------------------------------------------------

// Account ids are cut out first: "leash-pay2-1106fcff.testnet" has a 2 and a 1106 in it, and
// reading either as the amount would send the wrong sum. Then the amount must be a number on
// its own, not part of a word ("pay1"), and exactly one distinct number must be present: if
// the text is ambiguous the right move is to ask, not to pick one.
const NUMBER_RE = /(?<![\w.])(\d+(?:\.\d+)?)(?:\s*(?:usdc|usd|dollars?)\b)?(?!\w|\.\d)/gi;

export function parseInstruction(text, vendors, decimals) {
  const lower = String(text ?? "").toLowerCase();
  const account = ACCOUNT_RE.exec(lower)?.[0];
  const prose = lower.replace(new RegExp(ACCOUNT_RE.source, "g"), " ");
  const numbers = [...new Set([...prose.matchAll(NUMBER_RE)].map((m) => m[1]))];
  if (numbers.length === 0) return { error: "I could not find an amount in that." };
  if (numbers.length > 1) return { error: `I found more than one amount (${numbers.join(", ")}); say it once.` };
  let amount;
  try { amount = parseUnits(numbers[0], decimals); } catch (e) { return { error: e.message }; }
  const word = (n) => new RegExp(`(?<![\\w-])${n.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`).test(prose);
  const vendor = vendors.find((v) => [v.name, ...(v.aliases ?? [])].some(word));
  if (account) {
    const known = vendors.find((v) => v.account === account);
    return { payee: account, amount, vendor: known?.name ?? null };
  }
  if (vendor) return { payee: vendor.account, amount, vendor: vendor.name };
  return { error: "I do not know who to pay: name a vendor I know, or give an account id." };
}

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
    network: process.env.NEAR_NETWORK || dep.network,
    wallet: process.env.WALLET || dep.wallet,
    token: process.env.TOKEN || dep.token,
    units: { decimals: Number(process.env.TOKEN_DECIMALS || 6), symbol: process.env.TOKEN_SYMBOL || "USDC" },
    keyFile,
    vendors: JSON.parse(readFileSync(join(here, "vendors.json"), "utf8")),
  };
}

export function start(cfg = config()) {
  const state = { name: cfg.name, agentAddr: cfg.agentAddr, lastAction: null };
  const readView = () => chainView({ wallet: cfg.wallet, agent: cfg.agentAddr, units: cfg.units });
  const readLog = () => chainLog(cfg.wallet);
  const send = (i) => sendSpend({ network: cfg.network, wallet: cfg.wallet, agent: cfg.agentAddr, keyFile: cfg.keyFile, token: i.token, payee: i.payee, amount: i.amount });

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

  return createServer(async (req, res) => {
    try {
      if (req.method === "OPTIONS") return json(res, 204, {});
      if (req.method === "GET" && req.url === "/state") {
        const [chain, view] = await Promise.all([readLog(), readView()]);
        return json(res, 200, publicState(state, chain, view));
      }
      if (req.method === "POST" && req.url === "/instruct") {
        let text;
        try { text = JSON.parse(await readBody(req)).text; } catch { return json(res, 400, { error: "send JSON: {\"text\": \"...\"}" }); }
        const parsed = parseInstruction(text, cfg.vendors, cfg.units.decimals);
        if (parsed.error) return json(res, 422, { error: parsed.error });
        const intent = { agent: cfg.agentAddr, token: cfg.token, payee: parsed.payee, amount: parsed.amount, vendor: parsed.vendor, text };
        intent.prediction = decide(await readView(), intent);
        // Sends whatever the prediction says: the chain is what refuses, and the refusal is
        // the thing worth recording.
        const done = await sendAndRecord(state, intent, { send, readLog });
        return json(res, 200, { prediction: intent.prediction, lastAction: done });
      }
      json(res, 404, { error: "not found" });
    } catch (err) {
      json(res, 500, { error: String(err.message ?? err).slice(0, 300) });
    }
  }).listen(cfg.port, () => console.log(`${cfg.name} (${cfg.agentAddr}) on :${cfg.port}`));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) start();
