// The README's rule: every security claim names the test that proves it. This checks the naming
// is real: each `file::test` reference points at a test that exists, and no row of a claims table
// is left without one. (It cannot check that the test proves the claim; reviewers read that.)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const REF = /`([\w./-]+\.(?:rs|mjs))::("[^`]*"|[A-Za-z0-9_]+)`/g;
const refs = [...readme.matchAll(REF)].map((m) => ({ file: m[1], name: m[2] }));

test("the README names tests, and a good number of them", () => {
  assert.ok(refs.length >= 60, `only ${refs.length} references found`);
});

test("every file::test reference in the README exists", () => {
  const missing = [];
  for (const { file, name } of refs) {
    const path = root + file;
    if (!existsSync(path)) { missing.push(`${file} does not exist`); continue; }
    const src = readFileSync(path, "utf8");
    const found = name.startsWith('"')
      ? src.includes(`test(${name}`)
      : new RegExp(`\\bfn ${name}\\b`).test(src);
    if (!found) missing.push(`${file}::${name}`);
  }
  assert.deepEqual(missing, []);
});

test("every row of a claims table carries a test reference", () => {
  const section = readme.slice(readme.indexOf("## What is claimed"), readme.indexOf("## What the passkey check proves"));
  const rows = section.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| Claim") && !l.startsWith("| ---"));
  assert.ok(rows.length >= 40, `only ${rows.length} claim rows`);
  const bare = rows.filter((r) => !new RegExp(REF.source).test(r));
  assert.deepEqual(bare, []);
});

test("the passkey wording is never alone: the caveat sits in the same section as the claim", () => {
  const text = readme.replace(/\s+/g, " ");
  assert.match(text, /cannot\*\* prove the credential is hardware-backed/);
  assert.match(text, /only as strong as registration\.\*\*/);
  assert.match(text, /the admin key cannot add one on its own/);
  assert.match(text, /\*\*cannot\*\* widen a rule, add a payee, unpause, withdraw, or mint itself a credential/);
  assert.match(text, /if every registered credential is lost or removed, the funds in the wallet are stuck forever/);
  assert.doesNotMatch(text, /a unique human/i);
});

test("the README names the real build command and says a bare cargo build fails", () => {
  assert.match(readme, /bare `cargo build` \*\*fails on the host, by design/);
  assert.match(readme, /scripts\/build-contract\.sh/);
});
