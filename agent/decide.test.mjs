import test from "node:test";
import assert from "node:assert/strict";
import { decide, formatUnits, parseUnits } from "./decide.mjs";
import { view, PAY1, PAY2, TOKEN } from "./fixtures.mjs";

const intent = (over = {}) => ({ token: TOKEN, payee: PAY1, amount: 5_000_000n, ...over });

test("decide() explains a budget refusal in token units", () => {
  const d = decide(view(), intent());
  assert.equal(d.verdict, "will-be-refused");
  assert.equal(d.code, 6);
  assert.equal(d.reason, "over the limit for this period", "the sentence is the chain's, not ours");
  assert.match(d.explain, /3\.00 left of 10\.00 USDC, this is 5\.00/);
  assert.doesNotMatch(d.explain, /\d{6,}/, "no raw base units in the sentence");
});

test("an unknown vendor is predicted to be refused", () => {
  const d = decide(view(), intent({ payee: "stranger.testnet" }));
  assert.equal(d.verdict, "will-be-refused");
  assert.equal(d.code, 4);
  assert.match(d.explain, /stranger\.testnet/);
});

test("a payment inside every limit is will-pass, and says only the chain can confirm", () => {
  const d = decide(view({ spent: "0" }), intent({ payee: PAY2, amount: 1_000_000n }));
  assert.equal(d.verdict, "will-pass");
  assert.equal(d.code, null);
});

test("per-transaction limit is checked before the period, in the contract's order", () => {
  const d = decide(view({ spent: "0" }), intent({ amount: 7_000_000n }));
  assert.equal(d.code, 5);
  assert.match(d.explain, /7\.00/);
  assert.match(d.explain, /6\.00/);
});

test("no rule, paused, wrong token and closed window each map to the chain's code", () => {
  assert.equal(decide(view({ rule: null }), intent()).code, 1);
  assert.equal(decide(view({ rule: { ...view().rule, paused: true } }), intent()).code, 2);
  assert.equal(decide(view(), intent({ token: "other.testnet" })).code, 3);
  const closed = { ...view().rule, window_start_ms: 1, window_end_ms: 2 };
  assert.equal(decide(view({ rule: closed, spent: "0" }), intent()).code, 7);
});

test("amounts beyond 2^53 are compared exactly, never as floats", () => {
  const big = 9_007_199_254_740_993n; // 2^53 + 1
  const rule = { ...view().rule, per_tx_limit: String(big), period_limit: String(big * 2n) };
  assert.equal(decide(view({ rule, spent: "0" }), intent({ amount: big })).verdict, "will-pass");
  assert.equal(decide(view({ rule, spent: "0" }), intent({ amount: big + 1n })).code, 5);
});

test("formatUnits and parseUnits are exact and keep sub-cent amounts visible", () => {
  assert.equal(formatUnits(3_000_000n, 6), "3.00");
  assert.equal(formatUnits(10_000_000n, 6), "10.00");
  assert.equal(formatUnits(5n, 6), "0.000005", "truncating to 2 digits would print 0.00");
  assert.equal(formatUnits(1_500_000n, 6), "1.50");
  assert.equal(parseUnits("0.5", 6), 500_000n);
  assert.equal(parseUnits("12", 6), 12_000_000n);
  assert.throws(() => parseUnits("1.0000001", 6));
});
