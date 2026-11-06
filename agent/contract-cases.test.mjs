// The pre-flight must give the contract's answer for every case the contract itself was run on.
// contract-cases.json is written by `cargo test` (contract/src/spend.rs, cases_file_*) from the
// real evaluate(); if a check moves, cargo test fails until the file is regenerated, and this
// test then fails until decide() follows.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decide } from "./decide.mjs";
import { REASONS, UNITS } from "./fixtures.mjs";

const cases = JSON.parse(readFileSync(new URL("./contract-cases.json", import.meta.url), "utf8"));

test("the cases file is not empty and covers every refusal code", () => {
  assert.ok(cases.length >= 20);
  const seen = new Set(cases.map((c) => c.expected_code));
  for (const code of [null, 1, 2, 3, 4, 5, 6, 7]) assert.ok(seen.has(code), `no case expects ${code}`);
});

for (const c of cases) {
  test(`decide() agrees with the contract: ${c.name}`, () => {
    const view = {
      node: "n.testnet",
      rule: c.rule,
      spent: c.attempt.spent,
      nowMs: c.attempt.now_ms,
      accountPaused: c.attempt.account_paused,
      reasons: REASONS,
      units: UNITS,
    };
    const d = decide(view, { token: c.attempt.token, payee: c.attempt.payee, amount: BigInt(c.attempt.amount) });
    assert.equal(d.code, c.expected_code);
    assert.equal(d.verdict, c.expected_code === null ? "will-pass" : "will-be-refused");
  });
}
