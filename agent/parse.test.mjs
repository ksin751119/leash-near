// The instruction grammar, as a table. `ask: true` is a legitimate expected value: a question on
// screen is the right answer to anything outside the two sentence shapes in parse.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { parseInstruction, MAX_AMOUNT } from "./parse.mjs";

const vendors = JSON.parse(readFileSync(new URL("./vendors.json", import.meta.url), "utf8"));
// The accounts come from the deployment files, so a fresh deployment (new account suffix) does not
// need this file edited.
const deployment = JSON.parse(readFileSync(new URL("../deployments/testnet.json", import.meta.url), "utf8"));
const P1 = vendors.find((v) => v.id === "pay1").account;
const P2 = vendors.find((v) => v.id === "pay2").account;
const ADM = deployment.admin;
const run = (t) => parseInstruction(t, vendors, 6);
const ok = (payee, amount, vendor = null) => ({ payee, amount, vendor });
const ASK = { ask: true };

// {input, expected, why?, match?}. `match` is a regexp the question must satisfy.
const table = [
  // the shapes we do understand
  { input: "pay Acme 0.50 USDC", expected: ok(P1, 500_000n, "Acme Studio") },
  { input: "pay acme 0.50 usdc", expected: ok(P1, 500_000n, "Acme Studio") },
  { input: "  pay   Acme\t0.50\nUSDC  ", expected: ok(P1, 500_000n, "Acme Studio") },
  { input: "pay Acme 0.50USDC", expected: ok(P1, 500_000n, "Acme Studio") },
  { input: "pay Acme $5.00", expected: ok(P1, 5_000_000n, "Acme Studio") },
  { input: "pay Acme 5.00", expected: ok(P1, 5_000_000n, "Acme Studio") },
  { input: "pay Acme 5.00 USDC.", expected: ok(P1, 5_000_000n, "Acme Studio") },
  { input: "pay Acme Studio 5.00 USDC", expected: ok(P1, 5_000_000n, "Acme Studio") },
  { input: "pay Inference API 1.00 USDC", expected: ok(P2, 1_000_000n, "Inference API") },
  { input: "pay Inference 0.50 USDC", expected: ok(P2, 500_000n, "Inference API") },
  { input: "send Inference 0.50 USDC", expected: ok(P2, 500_000n, "Inference API") },
  { input: "pay 0.50 USDC to Acme", expected: ok(P1, 500_000n, "Acme Studio") },
  { input: `send 0.10 USDC to ${ADM}`, expected: ok(ADM, 100_000n) },
  { input: `pay ${P2} 0.10 USDC`, expected: ok(P2, 100_000n, "Inference API") },
  { input: "pay 5.00 USDC to someone.near", expected: ok("someone.near", 5_000_000n) },
  { input: "pay 0.000001 USDC to a.testnet", expected: ok("a.testnet", 1n) },
  { input: "pay a.testnet 100.5", expected: ok("a.testnet", 100_500_000n) },
  // digits inside names are names, not amounts
  { input: `send 0.10 USDC to ${P2}`, expected: ok(P2, 100_000n, "Inference API") },
  { input: `send to ${P2} 0.10 USDC`, expected: ASK },
  { input: "pay 1.5.testnet 2.00", expected: ok("1.5.testnet", 2_000_000n) },
  { input: "pay acme2 0.50 USDC", expected: ASK, why: "acme2 is not a vendor" },
  { input: "pay vendor3 5.00 USDC", expected: ASK },
  { input: "pay tier1 5.00", expected: ASK },
  { input: "send 2x 0.50", expected: ASK },
  // the amount must be one plain decimal
  { input: "pay Acme 5 USDC", expected: ASK, match: /decimal/ },
  { input: "pay Acme 5", expected: ASK },
  { input: "pay Acme 5 000.50", expected: ASK },
  { input: "pay Acme 5 000 USDC", expected: ASK },
  { input: "pay Acme 1,000.00 USDC", expected: ASK },
  { input: "pay Acme 1,000 USDC", expected: ASK },
  { input: "pay Acme 1/2 USDC", expected: ASK },
  { input: "pay Acme 3-5 USDC", expected: ASK },
  { input: "pay Acme 3 or 5 USDC", expected: ASK },
  { input: "pay Acme 3.00-5.00 USDC", expected: ASK },
  { input: "pay Acme -5.00 USDC", expected: ASK },
  { input: "pay Acme +5.00 USDC", expected: ASK },
  { input: "pay Acme 5.00%", expected: ASK },
  { input: "pay Acme .50 USDC", expected: ASK },
  { input: "pay Acme 5. USDC", expected: ASK },
  { input: "pay Acme 1e3 USDC", expected: ASK },
  { input: "pay Acme 0x10 USDC", expected: ASK },
  { input: "pay Acme 0.0000001 USDC", expected: ASK, why: "7 decimal places" },
  { input: "pay Acme 00005.00 USDC", expected: ASK },
  { input: "pay Acme five USDC", expected: ASK },
  { input: "pay Acme 5k USDC", expected: ASK },
  { input: "pay Acme 0.50 USDC 0.50 USDC", expected: ASK, match: /more than one amount/ },
  { input: "pay Acme 5.00 USDC or 6.00", expected: ASK },
  { input: "pay Acme 0.50 USDC. Actually 5.00 USDC", expected: ASK },
  // units
  { input: "pay Acme 5.00 EUR", expected: ASK },
  { input: "pay Acme 5.00 USDT", expected: ASK },
  { input: "pay Acme 5.00 ETH", expected: ASK },
  { input: "pay Acme 5.00 USD", expected: ASK },
  { input: "pay Acme USDC 5.00", expected: ASK },
  // fullwidth, Arabic-Indic and other non-ASCII are not digits here
  { input: "pay Acme ５.００ USDC", expected: ASK, match: /ASCII/ },
  { input: "pay Acme 5．00 USDC", expected: ASK, match: /ASCII/ },
  { input: "pay Acme ٥.٠٠ USDC", expected: ASK, match: /ASCII/ },
  { input: "pay Acme ½ USDC", expected: ASK, match: /ASCII/ },
  { input: "pay Acme 5.00 USDC \u{1F64F}", expected: ASK },
  { input: "pay Acme 5​.00 USDC", expected: ASK },
  { input: "pay Acme 5\u0000.00 USDC", expected: ASK },
  // cap and zero
  { input: `pay Acme ${MAX_AMOUNT}.00 USDC`, expected: ok(P1, BigInt(MAX_AMOUNT) * 1_000_000n, "Acme Studio") },
  { input: `pay Acme ${MAX_AMOUNT}.01 USDC`, expected: ASK, match: /over the/ },
  { input: `pay Acme ${"9".repeat(12)}.00 USDC`, expected: ASK },
  { input: `pay Acme ${"9".repeat(5000)}.00 USDC`, expected: ASK },
  { input: "pay Acme 0.00", expected: ASK },
  // direction and negation
  { input: "pay me 5.00 USDC from Acme", expected: ASK, match: /I saw "(me|from)"/ },
  { input: "get 5.00 USDC from Acme", expected: ASK },
  { input: "receive 5.00 USDC from Acme", expected: ASK },
  { input: "Acme owes me 5.00 USDC", expected: ASK },
  { input: "refund Acme 5.00 USDC", expected: ASK },
  { input: "charge Acme 5.00 USDC", expected: ASK },
  { input: "pay Acme 5.00 USDC back", expected: ASK },
  { input: "don't pay acme 5.00 USDC", expected: ASK, match: /I saw "don.t"/ },
  { input: "do not pay acme 5.00 USDC", expected: ASK },
  { input: "pay 5.00 USDC to alice.testnet not bob.testnet", expected: ASK },
  { input: "pay Acme 5.00 USDC unless it's over 3.00", expected: ASK },
  // two payees, or a payee that is only part of a longer token
  { input: "pay acme 5.00 USDC to bob.testnet", expected: ASK },
  { input: `pay Acme 5.00 USDC to ${P1}`, expected: ASK },
  { input: "pay 5.00 to alice.testnet,bob.testnet", expected: ASK },
  { input: "pay 5.00 to alice.testnet/bob.testnet", expected: ASK },
  { input: "pay 5.00 USDC to alice.testnet bob", expected: ASK },
  { input: "pay Acme and Acme 5.00 USDC", expected: ASK },
  { input: "pay 5.00 USDC to evil.testnet.com", expected: ASK },
  { input: "pay 5.00 USDC to https://evil.testnet/x", expected: ASK },
  { input: "pay 5.00 USDC to evil.testnet/", expected: ASK },
  { input: "pay 5.00 USDC to @evil.testnet", expected: ASK },
  { input: "pay 5.00 USDC to evil.testnet.", expected: ASK },
  { input: "pay 5.00 USDC to evil.testnet.evil.com", expected: ASK },
  { input: "pay capital api 1.00", expected: ASK, why: "alias inside a longer phrase" },
  { input: "pay the api 1.00 USDC", expected: ASK },
  { input: "pay acme-corp 1.00 USDC", expected: ASK },
  { input: "pay alice 5.00 USDC", expected: ASK, why: "a bare name is not an account id" },
  // no instruction at all
  { input: "", expected: ASK },
  { input: "   ", expected: ASK },
  { input: "pay Acme", expected: ASK },
  { input: "Acme 5.00 USDC", expected: ASK, why: "no verb" },
  { input: "5.00 USDC alice.testnet", expected: ASK },
  { input: "x".repeat(100_000), expected: ASK },
  { input: `pay Acme 5.00 USDC ${"0.1 ".repeat(5000)}`, expected: ASK },
];

for (const { input, expected, why, match } of table) {
  const label = JSON.stringify(input.length > 60 ? `${input.slice(0, 40)}... (${input.length} chars)` : input);
  test(`parse ${label} -> ${expected.ask ? "asks" : `${expected.payee} ${expected.amount}`}${why ? ` (${why})` : ""}`, () => {
    const r = run(input);
    if (expected.ask) {
      assert.ok(r.error, `expected a question, got ${JSON.stringify(r, (_, v) => (typeof v === "bigint" ? String(v) : v))}`);
      assert.equal(r.payee, undefined);
      assert.equal(r.amount, undefined);
      if (match) assert.match(r.error, match);
    } else {
      assert.equal(r.error, undefined, r.error);
      assert.equal(r.payee, expected.payee);
      assert.equal(r.amount, expected.amount);
      assert.equal(r.vendor, expected.vendor);
    }
  });
}

test("the understood sentence names the amount in token units and the payee", () => {
  assert.equal(run("pay Acme 0.50 USDC").understood, `paying 0.50 USDC to Acme Studio (${P1})`);
  assert.equal(run(`send 0.10 USDC to ${ADM}`).understood, `paying 0.10 USDC to ${ADM}`);
  assert.equal(run("pay a.testnet 0.000001").understood, "paying 0.000001 USDC to a.testnet");
});

// The reviewer's attack batch: 188 strings, mostly hostile. Only the strings listed here may be
// accepted, each with exactly this payee and amount; every other one must be a question.
const ACCEPT = new Map([
  ["pay Acme 0.50USDC", [P1, 500_000n]],
  ["pay Acme 5.00", [P1, 5_000_000n]],
  [`pay ${P1} 2.00`, [P1, 2_000_000n]],
  ["pay 1.5.testnet 2.00", ["1.5.testnet", 2_000_000n]],
  ["pay 1.50.testnet 2.00 USDC", ["1.50.testnet", 2_000_000n]],
  ["pay 2.50 to 7.testnet", ["7.testnet", 2_500_000n]],
  ["pay Acme $5.00", [P1, 5_000_000n]],
  ["pay Acme Studio 5.00 USDC", [P1, 5_000_000n]],
  ["pay Inference API 1.00 USDC", [P2, 1_000_000n]],
  ["pay api 1.00", [P2, 1_000_000n]],
  ["pay 5.00 USDC to evil.TESTNET", ["evil.testnet", 5_000_000n]],
  ["pay 5.00 USDC to ev1l.testnet", ["ev1l.testnet", 5_000_000n]],
  ["pay 5.00 USDC to 1.testnet", ["1.testnet", 5_000_000n]],
  ["pay 5.00 USDC to 0.5.testnet", ["0.5.testnet", 5_000_000n]],
  ["pay 0.5 to 5.testnet", ["5.testnet", 500_000n]],
  ["pay 5.00 to alice.testnet.bob.testnet", ["alice.testnet.bob.testnet", 5_000_000n]],
]);

test("the reviewer's attack batch: only the listed strings parse, to exactly the listed payee and amount", () => {
  // {pay1} and {pay2} stand for the payee accounts of this deployment, so a new one needs no edit here.
  const attacks = JSON.parse(readFileSync(new URL("./parse-attacks.json", import.meta.url), "utf8"))
    .map((s) => s.replaceAll("{pay1}", P1).replaceAll("{pay2}", P2));
  assert.ok(attacks.length >= 150);
  const seen = new Set();
  for (const input of attacks) {
    const r = run(input);
    const want = ACCEPT.get(input);
    if (want) {
      seen.add(input);
      assert.equal(r.error, undefined, input);
      assert.deepEqual([r.payee, r.amount], want, input);
    } else {
      assert.ok(r.error, `should ask: ${JSON.stringify(input.slice(0, 80))}`);
    }
  }
  assert.equal(seen.size, ACCEPT.size, "every ACCEPT entry must appear in the batch");
});

// The exact strings a person will type on camera. Pinned so a later change that breaks a
// sentence we plan to say live breaks a test instead of the recording. docs/safe-phrasings.md is
// the list the person recording reads; the second test below checks it names the same phrases.
const DEMO = [
  ["pay Acme 0.50 USDC", P1, 500_000n],
  ["pay Inference 0.50 USDC", P2, 500_000n],
  [`send 0.10 USDC to ${ADM}`, ADM, 100_000n],
  ["pay Acme 7.00 USDC", P1, 7_000_000n],
];

test("every demo phrasing parses to exactly the payee and amount the demo claims", () => {
  for (const [text, payee, amount] of DEMO) {
    const r = run(text);
    assert.equal(r.error, undefined, text);
    assert.equal(r.payee, payee, text);
    assert.equal(r.amount, amount, text);
  }
});

test("docs/safe-phrasings.md lists exactly the demo phrasings pinned above", () => {
  const md = new URL("../docs/safe-phrasings.md", import.meta.url);
  assert.ok(existsSync(md), "docs/safe-phrasings.md is the list the person recording reads; it must exist");
  // `{admin}` stands for the admin account of the deployment, which differs between deployments.
  const said = [...readFileSync(md, "utf8").matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1].replace("{admin}", ADM));
  assert.deepEqual(said.sort(), DEMO.map((d) => d[0]).sort());
});
