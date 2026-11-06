// Read-only access to the wallet contract's views over plain JSON-RPC. No signing, no keys.
const RPC = () => process.env.NEAR_RPC || "https://rpc.testnet.near.org";

export async function callView(account, method, args = {}) {
  const res = await fetch(RPC(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "query",
      params: {
        request_type: "call_function",
        finality: "optimistic",
        account_id: account,
        method_name: method,
        args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
      },
    }),
  });
  const body = await res.json();
  if (body.error || body.result?.error) {
    throw new Error(`view ${method} failed: ${JSON.stringify(body.error ?? body.result.error).slice(0, 200)}`);
  }
  return JSON.parse(Buffer.from(body.result.result).toString("utf8"));
}

export const readLog = (wallet) => callView(wallet, "decision_log");

// What decide() and /state need about one agent's budget. `reasons` is the chain's own
// refusal table, so no sentence is duplicated in JavaScript.
export async function readView({ wallet, agent, units }) {
  const node = await callView(wallet, "node_for", { agent });
  const [accountPaused, rule, spent, reasons] = await Promise.all([
    callView(wallet, "is_paused"),
    node ? callView(wallet, "rule_of", { node }) : null,
    node ? callView(wallet, "spent_in_period", { node }) : "0",
    callView(wallet, "refusal_codes"),
  ]);
  return { node, rule, spent, accountPaused, nowMs: Date.now(), reasons, units };
}
