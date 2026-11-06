// A stand-in for the NEAR JSON-RPC and for the two agent processes, for scripts/preflight.test.mjs.
// It answers only what preflight.sh asks, from a `world` object each test builds, and it never
// invents an answer: a method the world has no entry for is an RPC error, so a check that
// quietly relied on an unconfigured value would fail loudly here too.
import { createServer } from "node:http";

export const WALLET = "leash-wal-test.testnet";
export const TOKEN = "leash-tok-test.testnet";
export const ADMIN = "leash-adm-test.testnet";
export const NODE = "leash-bud-test.testnet";
export const ALPHA = `alpha.${NODE}`;
export const BETA = `beta.${NODE}`;
export const PAY1 = "leash-pay1-test.testnet";
export const PAY2 = "leash-pay2-test.testnet";
export const REAL = "REALDEVICEcredentialAA==";
export const SOFT = "SOFTWAREcredentialBB==";

export const deployment = {
  network: "testnet", admin: ADMIN, wallet: WALLET, token: TOKEN, budget_node: NODE,
  payees: [PAY1, PAY2],
  agents: { [ALPHA]: "ed25519:alpha", [BETA]: "ed25519:beta" },
  credentials: [
    { id: REAL, kind: "DEVICE (passkey on a phone)" },
    { id: SOFT, kind: "SOFTWARE P-256, shakedown only" },
  ],
  funded_wallet_balance: "500000000",
};
export const vendors = [
  { id: "pay1", name: "Acme Studio", aliases: ["acme"], account: PAY1 },
  { id: "pay2", name: "Inference API", aliases: ["inference"], account: PAY2 },
];

export const scriptedRule = () => ({
  token: TOKEN, per_tx_limit: "1000000", period_limit: "2000000", period_ms: 86400000,
  window_start_ms: 0, window_end_ms: 18446744073709551615, payees: [PAY1, PAY2], paused: false,
});

const spendKey = (over = {}) => ({
  public_key: "ed25519:k", access_key: { nonce: 1, permission: { FunctionCall: {
    allowance: "250000000000000000000000", receiver_id: WALLET, method_names: ["spend"], ...over } } },
});

// A world in which everything is as the recording needs it.
export const goodWorld = () => ({
  gasPrice: "100000000",
  keys: { [WALLET]: [], [ALPHA]: [spendKey()], [BETA]: [spendKey()] },
  views: {
    [`${WALLET}.node_record`]: () => ({ rule: scriptedRule(), epoch: 1, version: 1, window_began_ms: Date.now() - 60_000, spent: "0" }),
    [`${WALLET}.is_paused`]: () => false,
    [`${WALLET}.credential_ids`]: () => [REAL, SOFT],
    // Registration order as the contract stamps it: the bootstrap is sequence 0.
    [`${WALLET}.credentials`]: () => [{ id: REAL, seq: 0 }, { id: SOFT, seq: 1 }],
    [`${WALLET}.credential_nonce`]: () => 2,
    [`${TOKEN}.ft_balance_of`]: () => "500000000",
    [`${TOKEN}.ft_metadata`]: () => ({ decimals: 6, symbol: "USDC" }),
  },
  rateLimitFirst: false,
  raw: {}, // "<account>.<method>" or "keys:<account>" -> a raw JSON-RPC body to return instead
});

export function startRpc(world) {
  const hits = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      hits.push(method);
      const reply = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id, ...o })); };
      if (world.rateLimitFirst && hits.length === 1) { res.writeHead(429); return res.end("Too Many Requests"); }
      if (method === "gas_price" && world.gasPriceBroken) return reply({ error: { code: -32000, message: "boom" } });
      if (method === "gas_price") return reply({ result: { gas_price: world.gasPrice } });
      const p = params;
      if (p.request_type === "view_access_key_list") {
        const raw = world.raw[`keys:${p.account_id}`];
        if (raw) return reply(raw);
        const keys = world.keys[p.account_id];
        return keys ? reply({ result: { keys } }) : reply({ error: { code: -32000, message: `unknown account ${p.account_id}` } });
      }
      if (p.request_type === "call_function") {
        const key = `${p.account_id}.${p.method_name}`;
        if (world.raw[key]) return reply(world.raw[key]);
        const fn = world.views[key];
        if (!fn) return reply({ result: { error: `no such method ${key}` } });
        const args = JSON.parse(Buffer.from(p.args_base64, "base64").toString());
        // u64::MAX does not survive a JS number; the chain would send it exactly.
        const text = JSON.stringify(fn(args)).replaceAll("18446744073709552000", "18446744073709551615");
        return reply({ result: { result: [...Buffer.from(text)], logs: [] } });
      }
      reply({ error: { code: -32601, message: "unsupported" } });
    });
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok({ url: `http://127.0.0.1:${server.address().port}`, server, hits })));
}

// An agent process's /state, as much of it as preflight reads.
export function startAgent(addr, over = {}) {
  const server = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ agentAddr: addr, chain: { errors: [] }, ...over }));
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok({ url: `http://127.0.0.1:${server.address().port}`, server })));
}
