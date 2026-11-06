// Turning what a person typed into one payment: a CLOSED grammar, not a pattern-matcher.
//
// Three rounds of review each found a new free-text input that produced a wrong amount or the
// wrong payee, because every fix was one more pattern over text with unbounded variety. So the
// design is inverted: two sentence shapes are understood, the WHOLE instruction must match one
// of them, and everything else gets a question that says what was unclear. A closed grammar has
// a finite surface; there is no "other input" left to misread.
//
//   pay  <payee> <amount>             pay Acme 0.50 USDC
//   pay  <amount> to <payee>          send 0.10 USDC to leash-adm-1106fcff.testnet     (or "send")
//
//   <amount>  one decimal number, 1 to 6 places, no sign, no separators: 0.50, 12.5, 100.000001
//             optionally "$" before it and/or the word USDC after it ("0.50USDC" is fine)
//   <payee>   exactly one vendor name or alias from vendors.json, or exactly ONE whole token
//             that is a NEAR account id ending .testnet or .near. A token is cut at whitespace
//             only, so "evil.testnet.com" and "https://evil.testnet/x" are not accounts.
//
// Input must be printable ASCII (a fullwidth or Arabic digit is not a digit here) and short.
// The returned `understood` sentence is what the agent says it is about to do; the loop puts it
// on lastAction before anything is sent, so a misparse is on screen, not silent.
import { formatUnits, parseUnits } from "./decide.mjs";

export const MAX_INPUT_CHARS = 200;
// Largest amount this box will send, in whole tokens. A typo is a question, not a payment.
export const MAX_AMOUNT = "10000";

const VERBS = new Set(["pay", "send"]);
const ASCII_RE = /^[\x20-\x7e\t\r\n]*$/;
const ACCOUNT_RE = /^(?=.{2,64}$)[a-z0-9]+(?:[-_.][a-z0-9]+)*$/;
const ACCOUNT_SUFFIX_RE = /\.(?:testnet|near)$/;
const AMOUNT_RE = /^\$?((?:0|[1-9]\d{0,11})\.\d{1,6})(usdc)?$/;
// Words that change who pays whom or whether to pay at all. Only consulted to explain a
// refusal; a sentence in the grammar never contains them.
const NEGATION = new Set(["not", "never", "dont", "don't", "cancel", "stop", "no", "without", "unless", "instead"]);
const DIRECTION = new Set(["from", "refund", "owes", "owe", "receive", "get", "back", "me", "charge", "reimburse", "collect", "invoice"]);

const ask = (error) => ({ error });
const isAccount = (t) => ACCOUNT_RE.test(t) && ACCOUNT_SUFFIX_RE.test(t);

export function parseInstruction(text, vendors, decimals, opts = {}) {
  const symbol = opts.symbol ?? "USDC";
  const max = parseUnits(opts.maxAmount ?? MAX_AMOUNT, decimals);
  const raw = String(text ?? "");
  if (raw.length > MAX_INPUT_CHARS) return ask(`That is longer than ${MAX_INPUT_CHARS} characters; say it shorter.`);
  if (!ASCII_RE.test(raw)) return ask("I only read plain ASCII characters and digits 0-9; something in that is not.");
  const body = raw.trim().replace(/\s+/g, " ").toLowerCase().replace(/(usdc)\.$/, "$1");
  if (!body) return ask("What should I pay? Try: pay Acme 0.50 USDC");

  const tokens = body.split(" ");
  const byName = new Map();
  for (const v of vendors) for (const n of [v.name, ...(v.aliases ?? [])]) byName.set(n.toLowerCase(), v);
  const resolve = (toks) => {
    const phrase = toks.join(" ");
    if (byName.has(phrase)) return { payee: byName.get(phrase).account, vendor: byName.get(phrase).name };
    if (toks.length === 1 && isAccount(phrase)) {
      const known = vendors.find((v) => v.account === phrase);
      return { payee: phrase, vendor: known?.name ?? null };
    }
    return null;
  };
  // The amount at tokens[i]: one token ("0.50", "$0.50", "0.50usdc") or two ("0.50", "usdc").
  const amountAt = (i) => {
    const m = AMOUNT_RE.exec(tokens[i] ?? "");
    if (!m) return null;
    if (m[2]) return { digits: m[1], next: i + 1 };
    if (tokens[i + 1] === "usdc") return { digits: m[1], next: i + 2 };
    return { digits: m[1], next: i + 1 };
  };

  let found = null;
  if (VERBS.has(tokens[0])) {
    // pay <amount> to <payee>
    const a = amountAt(1);
    if (a && tokens[a.next] === "to") {
      const p = resolve(tokens.slice(a.next + 1));
      if (p) found = { ...p, digits: a.digits };
    }
    // pay <payee> <amount>, the amount running to the end of the sentence
    for (let k = 2; !found && k < tokens.length; k++) {
      const am = amountAt(k);
      const p = am && am.next === tokens.length ? resolve(tokens.slice(1, k)) : null;
      if (p) found = { ...p, digits: am.digits };
    }
  }

  if (!found) return ask(explainRefusal(tokens, resolve, vendors, byName));

  const amount = parseUnits(found.digits, decimals);
  if (amount > max) return ask(`${found.digits} ${symbol} is over the ${formatUnits(max, decimals)} ${symbol} this box will send; check the amount.`);
  if (amount === 0n) return ask("An amount of zero pays nothing; say how much.");
  const to = found.vendor ? `${found.vendor} (${found.payee})` : found.payee;
  return {
    payee: found.payee,
    amount,
    vendor: found.vendor,
    understood: `paying ${formatUnits(amount, decimals)} ${symbol} to ${to}`,
  };
}

// A question naming what was unclear. Only the wording depends on the diagnosis; the decision
// to ask was already made by the grammar not matching.
function explainRefusal(tokens, resolve, vendors, byName) {
  const known = vendors.map((v) => v.name).join(", ");
  const plain = (t) => t.replace(/[^a-z0-9']/g, "");
  const neg = tokens.find((t) => NEGATION.has(plain(t)));
  if (neg) return `I saw "${neg}" and won't guess what it changes. Say what to pay, positively: pay Acme 0.50 USDC`;
  const dir = tokens.find((t) => DIRECTION.has(plain(t)));
  if (dir) return `I saw "${dir}". I only pay out, from this budget, to one payee; I can't collect, refund or reverse. Say it as: pay Acme 0.50 USDC`;
  const numeric = tokens.slice(1).filter((t) => /\d/.test(t) && !isAccount(t) && !byName.has(t));
  const amounts = numeric.filter((t) => AMOUNT_RE.test(t));
  if (amounts.length > 1) {
    return `I found more than one amount (${amounts.join(", ")}); give one amount, like 0.50 USDC, once.`;
  }
  if (numeric.length) {
    return `I can't read ${numeric.map((t) => `"${t}"`).join(", ")} as an amount (a decimal like 0.50, 1-6 places, no sign, range or separators) or as a vendor or account id I know.`;
  }
  return `I only understand "pay <payee> <amount> USDC" or "send <amount> USDC to <payee>", where the amount has a decimal point (0.50) and the payee is one vendor I know (${known}) or one full .testnet/.near account id. I could not match: "${tokens.join(" ")}".`;
}
