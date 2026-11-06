// The pre-flight: predict, from the contract's view state, what `spend` will answer.
//
// This exists so the agent can explain itself before it sends, not to gate the send. The loop
// sends regardless and reconciles against what the chain recorded, so a prediction that is
// wrong costs a sentence on screen and nothing else.
//
// The checks run in the contract's own order (decision.rs REFUSALS), so a payment that fails
// several is predicted with the same code the chain will record. The SENTENCE for a code is
// never written here: it comes from `refusal_codes()` on the chain and arrives as
// `view.reasons`. Only the arithmetic and the numbers in the explanation are ours.
//
// Every amount is a BigInt in the token's base units. A float anywhere in here would be wrong
// for amounts past 2^53, and "close enough" is not a property a spending rule has.

export function parseUnits(text, decimals) {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(text).trim());
  if (!m) throw new Error(`not an amount: ${JSON.stringify(text)}`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`more than ${decimals} decimal places: ${text}`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0");
}

// Two decimals is what a person reads ("3.00"), but only when nothing is lost: 5 base units
// of a 6-decimal token printed as "0.00" would say the payment is free.
export function formatUnits(units, decimals) {
  const n = BigInt(units);
  const scale = 10n ** BigInt(decimals);
  const whole = n / scale;
  const frac = String(n % scale).padStart(decimals, "0");
  const short = frac.slice(0, 2).padEnd(2, "0");
  const lossless = /^0*$/.test(frac.slice(2));
  return `${whole}.${lossless ? short : frac}`;
}

const out = (view, code, explain) => ({
  verdict: "will-be-refused",
  code,
  reason: view.reasons?.find((r) => r.code === code)?.reason ?? `refusal code ${code}`,
  explain,
});

export function decide(view, intent) {
  const { rule, units } = view;
  const d = units.decimals;
  const fmt = (n) => formatUnits(n, d);
  const amount = BigInt(intent.amount);
  const sym = units.symbol;

  if (!rule) return out(view, 1, `${view.node ?? "this agent"} has no budget rule.`);
  // Code 2 is the account-wide pause OR the node's own flag (spend.rs CHECKS[0]).
  if (view.accountPaused || rule.paused) {
    return out(view, 2, view.accountPaused ? "the whole wallet is paused." : "this budget is paused.");
  }
  if (rule.token !== intent.token) {
    return out(view, 3, `${intent.token} is not the token this budget is in (${rule.token}).`);
  }
  if (!rule.payees.includes(intent.payee)) {
    return out(view, 4, `${intent.payee} is not on this budget's list of payees.`);
  }
  const perTx = BigInt(rule.per_tx_limit);
  if (amount > perTx) {
    return out(view, 5, `${fmt(amount)} ${sym} is over the ${fmt(perTx)} ${sym} limit on a single payment.`);
  }
  const periodLimit = BigInt(rule.period_limit);
  const spent = BigInt(view.spent);
  const left = periodLimit > spent ? periodLimit - spent : 0n;
  if (amount > left) {
    return out(view, 6, `${fmt(left)} left of ${fmt(periodLimit)} ${sym}, this is ${fmt(amount)}.`);
  }
  const now = BigInt(view.nowMs);
  if (now < BigInt(rule.window_start_ms) || now > BigInt(rule.window_end_ms)) {
    return out(view, 7, "this budget is outside its active window.");
  }
  return {
    verdict: "will-pass",
    code: null,
    reason: null,
    explain: `${fmt(amount)} ${sym} is inside every limit I can see (${fmt(left)} left of ${fmt(periodLimit)}); only the chain can confirm.`,
  };
}
