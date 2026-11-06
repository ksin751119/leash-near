import test from "node:test";
import assert from "node:assert/strict";
import { parseSpendOutput } from "./send.mjs";

test("parseSpendOutput reads the tx id and a refusal's return value", () => {
  const out = `Transaction ID: 4o9CKTQcvQmxfFtCAjoQAseDkb4HV65fom6NH2ZH7qEp
Function execution return value:
{ "code": 4, "reason": "payee is not on the allow-list", "status": "refused" }
The "spend" call succeeded.`;
  const r = parseSpendOutput(out);
  assert.equal(r.txHash, "4o9CKTQcvQmxfFtCAjoQAseDkb4HV65fom6NH2ZH7qEp");
  assert.deepEqual(r.outcome, { code: 4, reason: "payee is not on the allow-list", status: "refused" });
});

test("parseSpendOutput returns null outcome rather than guessing", () => {
  assert.equal(parseSpendOutput("nothing useful").outcome, null);
});
