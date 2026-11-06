import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSent, saveSent, MAX_SENT } from "./sentstore.mjs";

const e = (i) => ({ agent: "a.t", payee: "p.t", amount: "1", tx: `TX${i}`, at: i, countBefore: i, strangersBefore: 0 });
const dir = () => mkdtempSync(join(tmpdir(), "sent-"));

test("what is saved is what comes back after a restart", () => {
  const p = join(dir(), "s.json");
  saveSent(p, [e(1), e(2)]);
  assert.deepEqual(loadSent(p), [e(1), e(2)]);
});

test("the file is bounded to the newest entries", () => {
  const p = join(dir(), "s.json");
  saveSent(p, Array.from({ length: MAX_SENT + 25 }, (_, i) => e(i)));
  const back = loadSent(p);
  assert.equal(back.length, MAX_SENT);
  assert.equal(back.at(-1).tx, `TX${MAX_SENT + 24}`);
  assert.ok(statSync(p).size < 20_000);
});

test("a missing, corrupt or hostile file is an empty record, and bad rows are dropped", () => {
  const d = dir();
  assert.deepEqual(loadSent(join(d, "nope.json")), []);
  writeFileSync(join(d, "bad.json"), "{not json");
  assert.deepEqual(loadSent(join(d, "bad.json")), []);
  writeFileSync(join(d, "mixed.json"), JSON.stringify({ sent: [e(1), { tx: 5 }, null, "x", e(2)] }));
  assert.deepEqual(loadSent(join(d, "mixed.json")), [e(1), e(2)]);
});

test("rows whose counts are malformed are dropped on load; null counts are kept", () => {
  const d = dir();
  const bad = [
    { ...e(1), countBefore: "3" }, { ...e(2), countBefore: -1 }, { ...e(3), strangersBefore: 1.5 },
    { ...e(4), countBefore: Number.MAX_VALUE }, { ...e(5), strangersBefore: undefined }, { ...e(6), countBefore: {} },
  ];
  const keep = { ...e(7), countBefore: null, strangersBefore: null };
  writeFileSync(join(d, "c.json"), JSON.stringify({ sent: [...bad, keep, e(8)] }));
  assert.deepEqual(loadSent(join(d, "c.json")), [keep, e(8)]);
});

test("the file is private to the owner", () => {
  const p = join(dir(), "s.json");
  saveSent(p, [e(1)]);
  assert.equal(statSync(p).mode & 0o077, 0);
  assert.ok(readFileSync(p, "utf8").includes("TX1"));
});
