// Shapes copied from real view output on the testnet deployment (2026-11-06).
export const NODE = "leash-bud-1106fcff.testnet";
export const ALPHA = `alpha.${NODE}`;
export const BETA = `beta.${NODE}`;
export const PAY1 = "leash-pay1-1106fcff.testnet";
export const PAY2 = "leash-pay2-1106fcff.testnet";
export const TOKEN = "leash-tok-1106fcff.testnet";
export const UNITS = { decimals: 6, symbol: "USDC" };

export const REASONS = [
  { code: 1, reason: "no rule for this agent's node" },
  { code: 2, reason: "paused" },
  { code: 3, reason: "not this node's token" },
  { code: 4, reason: "payee is not on the allow-list" },
  { code: 5, reason: "over the per-transaction limit" },
  { code: 6, reason: "over the limit for this period" },
  { code: 7, reason: "outside the node's active window" },
];

export const RULE = {
  token: TOKEN,
  per_tx_limit: "6000000",
  period_limit: "10000000",
  period_ms: 86400000,
  window_start_ms: 0,
  window_end_ms: 18446744073709551615,
  payees: [PAY1, PAY2],
  paused: false,
};

export const view = (over = {}) => ({
  node: NODE,
  rule: RULE,
  spent: "7000000",
  nowMs: 1_800_000_000_000,
  reasons: REASONS,
  units: UNITS,
  ...over,
});

export const entry = (over = {}) => ({
  agent: ALPHA,
  node: NODE,
  payee: PAY1,
  amount: "5000000",
  outcome: { status: "refused", code: 6, reason: "over the limit for this period" },
  spent_after: "7000000",
  timestamp_ms: 1_800_000_000_000,
  ...over,
});

export const log = (over = {}) => ({
  decisions: [],
  decision_count: 0,
  strangers: [],
  stranger_count: 0,
  ...over,
});
