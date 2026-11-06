// The demo is written three times: as data (scripts/demo-beats.json, replayed by preflight.sh),
// as words (docs/demo-script.md), and as the list of sentences safe to type
// (docs/safe-phrasings.md). These tests keep the three, and the parser and the payment predictor
// they depend on, from drifting apart.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseInstruction } from "../agent/parse.mjs";
import { decide } from "../agent/decide.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const beats = JSON.parse(read("scripts/demo-beats.json"));
const vendors = JSON.parse(read("agent/vendors.json"));
const deployment = JSON.parse(read("deployments/testnet.json"));
const script = read("docs/demo-script.md");
const phrases = [...read("docs/safe-phrasings.md").matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1]);
const account = (id) => (id === "{admin}" ? deployment.admin : vendors.find((v) => v.id === id)?.account);
const rule = JSON.parse(execFileSync("scripts/demo-rule.sh", { cwd: root, encoding: "utf8" }));

test("every beat's sentence is one of the safe phrasings and is written in the demo script", () => {
  for (const b of beats.beats) {
    assert.ok(phrases.includes(b.text), `beat ${b.beat}: "${b.text}" is not in docs/safe-phrasings.md`);
    assert.ok(script.includes(b.text), `beat ${b.beat}: "${b.text}" is not in docs/demo-script.md`);
  }
});

test("every beat's sentence parses to the payee and amount the beat says", () => {
  for (const b of beats.beats) {
    const r = parseInstruction(b.text.replace("{admin}", deployment.admin), vendors, 6, { symbol: "USDC" });
    assert.equal(r.error, undefined, b.text);
    assert.equal(r.payee, account(b.payee), b.text);
    assert.equal(r.amount, BigInt(b.amount), b.text);
  }
});

test("replayed from nothing spent, the beats come out as scripted, every refusal with its code", () => {
  let spent = 0n;
  const reasons = [1, 2, 3, 4, 5, 6, 7].map((code) => ({ code, reason: `code ${code}` }));
  const seen = [];
  for (const b of beats.beats) {
    const view = { node: deployment.budget_node, rule, spent: String(spent), accountPaused: false, nowMs: Date.now(), reasons, units: { decimals: 6, symbol: "USDC" } };
    const d = decide(view, { token: rule.token, payee: account(b.payee), amount: BigInt(b.amount) });
    const got = d.verdict === "will-pass" ? "allowed" : "refused";
    assert.equal(got, b.expect, `beat ${b.beat}: ${b.text}`);
    if (b.expect === "refused") assert.equal(d.code, b.code, `beat ${b.beat}: ${b.text}`);
    if (got === "allowed") spent += BigInt(b.amount);
    seen.push(b.beat);
  }
  assert.equal(spent, BigInt(rule.period_limit), "the script ends with the period exactly used up, which is what makes the last refusal code 6");
  assert.deepEqual([...new Set(seen)], [1, 2, 3]);
});

test("the demo script and the scripted rule agree on the numbers it quotes", () => {
  assert.match(script, /1\.00 per payment, 2\.00 per day/);
  assert.equal(rule.per_tx_limit, "1000000");
  assert.equal(rule.period_limit, "2000000");
  assert.equal(rule.paused, false);
  assert.ok(!rule.payees.includes(deployment.admin), "the admin must not be on the allow-list, or beat 2 would pay it");
});

test("the demo script gives the commands the scripts actually take", () => {
  for (const cmd of ["scripts/reset-demo.sh testnet", "scripts/preflight.sh", "PERIOD_LIMIT=3000000", "REAL_DEVICE_CREDENTIAL_ID"]) {
    assert.ok(script.includes(cmd), `docs/demo-script.md should mention ${cmd}`);
  }
});
