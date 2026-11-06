// Read-only access to the wallet contract's views over plain JSON-RPC. No signing, no keys.
//
// # The call budget
//
// Public NEAR RPC endpoints rate-limit by IP and answer 429 (rpc.testnet.near.org and
// test.rpc.fastnear.com both did, while this was being built), and a 429 has no CORS header, so
// a browser reports it as a CORS failure. The previous version of this project had a recording
// interrupted by a rate limit. So reads here are budgeted, not just made.
//
// The budget: at idle, ALL processes together make at most about ONE RPC call per second.
//   - The page makes no chain calls of its own. It polls each agent's /state every 2 s, and
//     /state is served from this cache.
//   - Each agent keeps one reader (below). Behind /state, per agent, idle:
//         decision_log   every 5 s   0.20/s   (the page's only moving data)
//         node_record    every 10 s  0.10/s   (rule + spent + window start, ONE call)
//         is_paused      every 15 s  0.07/s
//         view_access_key_list for the wallet and for this agent's own account, every 30 s: 0.07/s
//                        (no contract method can list keys, so these are RPC queries; the agents
//                        read them rather than the page, because public endpoints send no CORS
//                        headers on the 429s and a browser then cannot even see why it failed)
//         node_for, refusal_codes    once (they cannot change for a given account / contract)
//     = about 0.44/s per agent, 0.87/s for two.
//   - The page makes none at all unless no agent answers (then only the key lists, 0.1/s).
//   - Total at idle: ~0.9 calls/s.
// Two concurrent /state requests share one in-flight call, so polling cannot multiply them. After
// a payment this agent sends, its own reads bypass the cache (`fresh`) so the result shows at
// once; that is three calls per instructed payment, not per second.
//
// A failed call is not retried for RETRY_AFTER_MS, and the last good value is served meanwhile
// and marked stale, so a 429 makes the page say "stale" instead of making it hammer harder.
// Tried in order; the one that last worked is tried first. rpc.testnet.near.org is left out on
// purpose: it answers "DEPRECATED, STOP USING IT" with 429s. NEAR_RPC may name one endpoint or
// several, comma-separated (a keyed endpoint, if there ever is one, goes first).
export const DEFAULT_RPCS = ["https://test.rpc.fastnear.com", "https://near-testnet.drpc.org", "https://archival-rpc.testnet.near.org"];
const endpoints = () => (process.env.NEAR_RPC ? process.env.NEAR_RPC.split(",").map((x) => x.trim()).filter(Boolean) : DEFAULT_RPCS);

// A rate limit or an unreachable endpoint is a reason to try the next one. A contract error (the
// view panicked, the account does not exist) is not: another endpoint would say the same.
const isTransient = (status, body, err) =>
  err != null || status === 429 || status >= 500 ||
  body?.error?.code === -429 || /rate limit|DEPRECATED|too many/i.test(JSON.stringify(body?.error ?? ""));

export const TTL_MS = {
  node_for: Infinity,
  refusal_codes: Infinity,
  decision_log: 5_000,
  node_record: 10_000,
  is_paused: 15_000,
  view_access_key_list: 30_000,
};
const RETRY_AFTER_MS = 5_000;

export function makeReader({ ttl = TTL_MS, serveStale = true, swr = false, now = Date.now, fetchFn = (...a) => globalThis.fetch(...a) } = {}) {
  const cache = new Map(); // key -> { value, at, promise, failedAt, error }
  const stats = { calls: 0 };
  let cur = 0; // index of the endpoint that last worked

  async function rpcCall(account, method, args) {
    const isKeys = method === "view_access_key_list";
    const payload = JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "query",
      params: isKeys
        ? { request_type: "view_access_key_list", finality: "optimistic", account_id: account }
        : {
          request_type: "call_function", finality: "optimistic", account_id: account, method_name: method,
          args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
        },
    });
    const list = endpoints();
    let body, lastErr;
    for (let i = 0; i < list.length; i++) {
      const url = list[(cur + i) % list.length];
      let res = null, b = null, err = null;
      stats.calls++;
      try {
        res = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json" }, body: payload, signal: AbortSignal.timeout(8_000) });
        b = await res.json();
      } catch (e) { err = e; }
      if (!isTransient(res?.status ?? 0, b, err)) { cur = (cur + i) % list.length; body = b; lastErr = null; break; }
      lastErr = err ? String(err.message ?? err) : `${url}: ${JSON.stringify(b?.error ?? res?.status).slice(0, 120)}`;
    }
    if (lastErr) throw new Error(`view ${method} failed on every endpoint: ${lastErr}`);
    if (body.error || body.result?.error) {
      throw new Error(`view ${method} failed: ${JSON.stringify(body.error ?? body.result.error).slice(0, 200)}`);
    }
    if (isKeys) return body.result;
    return JSON.parse(Buffer.from(body.result.result).toString("utf8"));
  }

  // `fresh` skips the cache (and the retry back-off) but still shares an in-flight call.
  async function call(account, method, args = {}, { fresh = false } = {}) {
    const key = `${account}|${method}|${JSON.stringify(args)}`;
    let e = cache.get(key);
    if (!e) cache.set(key, (e = { value: undefined, at: 0, promise: null, failedAt: 0, error: null }));
    const t = now();
    const ttlMs = ttl[method] ?? 0;
    const hasValue = e.at > 0;
    if (!fresh && hasValue && t - e.at < ttlMs) return e.value;
    if (e.promise) return hasValue && swr && !fresh ? e.value : e.promise;
    if (!fresh && e.failedAt && t - e.failedAt < RETRY_AFTER_MS) {
      if (hasValue && serveStale) return e.value; // stale, and `errors()` says so
      throw new Error(e.error);
    }
    e.promise = rpcCall(account, method, args)
      .then((v) => { e.value = v; e.at = now(); e.failedAt = 0; e.error = null; return v; })
      .catch((err) => {
        e.failedAt = now(); e.error = String(err.message ?? err);
        if (hasValue && serveStale) return e.value;
        throw err;
      })
      .finally(() => { e.promise = null; });
    // Stale-while-revalidate: with a value in hand, answer now and refresh behind it, so a slow
    // endpoint never makes /state slow. Only the very first read of each view has to wait.
    if (hasValue && swr && !fresh) { e.promise.catch(() => {}); return e.value; }
    return e.promise;
  }

  return {
    call,
    stats,
    // When each method was last read successfully, and which ones are failing right now.
    readAt: (account, method, args = {}) => cache.get(`${account}|${method}|${JSON.stringify(args)}`)?.at || null,
    errors: () => [...cache.entries()].filter(([, e]) => e.error).map(([k, e]) => ({ view: k.split("|")[1], error: e.error, since: e.failedAt })),
  };
}

// With no reader passed, every call goes to the network: that is what the tests stub.
const direct = makeReader({ ttl: {}, serveStale: false });

export const callView = (account, method, args = {}, reader = direct) => reader.call(account, method, args);

export const readLog = (wallet, reader = direct, opts) => reader.call(wallet, "decision_log", {}, opts);

// What decide() and /state need about one agent's budget. `reasons` is the chain's own
// refusal table, so no sentence is duplicated in JavaScript. `node_record` carries the rule, what
// is spent in the current window and when the window began, in one call.
export async function readView({ wallet, agent, units, reader = direct, fresh = false }) {
  const o = { fresh };
  const node = await reader.call(wallet, "node_for", { agent });
  const [accountPaused, rec, reasons] = await Promise.all([
    reader.call(wallet, "is_paused", {}, o),
    node ? reader.call(wallet, "node_record", { node }, o) : null,
    reader.call(wallet, "refusal_codes"),
  ]);
  return {
    node,
    rule: rec?.rule ?? null,
    spent: rec ? String(rec.spent) : "0",
    windowBeganMs: rec?.window_began_ms ?? null,
    accountPaused,
    nowMs: Date.now(),
    reasons,
    units,
  };
}
