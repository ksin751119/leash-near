#!/usr/bin/env node
// A stand-in for near-cli that keeps its "chain" in the JSON file named by FAKE_NEAR_WORLD.
// Only the calls reset-demo.sh makes are understood. It enforces the one rule that matters here,
// the same way the contract does: a loosening set_rule without an assertion that signed the
// exact challenge for that rule is refused (exit 1); a tightening needs none. Every accepted
// transaction is appended to world.calls so a test can see what was sent, and in which order.
import { readFileSync, writeFileSync } from "node:fs";

const file = process.env.FAKE_NEAR_WORLD;
const world = JSON.parse(readFileSync(file, "utf8"));
// u64::MAX is the "no window" bound and does not survive a JS number; the real chain and the
// script both use the exact digits, so they are put back whenever this process prints or saves.
const exactJson = (v) => JSON.stringify(v).replaceAll("18446744073709552000", "18446744073709551615");
const save = () => writeFileSync(file, exactJson(world));
const a = process.argv.slice(2);
const mode = a[2], method = a[4], args = JSON.parse(a[a.indexOf("json-args") + 1]);
const canon = (r) => ({ ...r, payees: [...r.payees].sort() });
const challengeOf = (node, rule, cred) => Buffer.from(JSON.stringify({ node, rule: canon(rule), cred, nonce: world.nonce })).toString("base64");
const n = BigInt;
const regChallenge = (cred, signer) => Buffer.from(JSON.stringify({ register: cred, signer, nonce: world.nonce })).toString("base64");
const loosens = (c, p) =>
  p.token !== c.token || n(p.per_tx_limit) > n(c.per_tx_limit) || n(p.period_limit) > n(c.period_limit) ||
  p.period_ms < c.period_ms || p.window_start_ms < c.window_start_ms || p.window_end_ms > c.window_end_ms ||
  p.payees.some((x) => !c.payees.includes(x)) || (c.paused && !p.paused);

if (mode === "as-read-only") {
  const out = {
    credential_ids: () => world.ids,
    node_record: () => world.rec,
    challenge_for: () => challengeOf(args.node, args.rule, args.credential_id),
    challenge_for_register: () => regChallenge(args.cred, args.credential_id),
  }[method];
  if (!out) { console.error(`fake near: no view ${method}`); process.exit(1); }
  console.log(exactJson(out()));
} else if (mode === "as-transaction" && method === "register_credential") {
  if (world.ids.length > 0) {
    if (!args.assertion) { console.error("Smart contract panicked: registering another credential needs a passkey assertion from a registered credential; the admin key alone cannot add one"); process.exit(1); }
    const signed = JSON.parse(args.assertion.client_data_json).challenge.replace(/-/g, "+").replace(/_/g, "/");
    const want = regChallenge(args.cred, args.assertion.credential_id).replace(/=+$/, "");
    if (!world.ids.includes(args.assertion.credential_id) || signed !== want) { console.error("Smart contract panicked: assertion rejected"); process.exit(1); }
    world.nonce += 1;
  }
  world.ids.push(args.cred.id);
  world.calls.push({ register: args.cred.id, assertion: Boolean(args.assertion) });
  save();
  console.log("null");
} else if (mode === "as-transaction" && method === "set_rule") {
  const gated = world.rec === null || loosens(world.rec.rule, args.rule);
  if (gated) {
    if (!args.assertion) { console.error("Smart contract panicked: this change loosens the rule, so it needs a passkey assertion"); process.exit(1); }
    const signed = JSON.parse(args.assertion.client_data_json).challenge.replace(/-/g, "+").replace(/_/g, "/");
    const want = challengeOf(args.node, args.rule, args.assertion.credential_id).replace(/=+$/, "");
    if (signed !== want) { console.error("Smart contract panicked: assertion does not match the challenge"); process.exit(1); }
    world.nonce += 1;
  }
  world.rec = { rule: canon(args.rule), spent: gated ? "0" : world.rec.spent };
  world.calls.push({ rule: args.rule, gated, assertion: Boolean(args.assertion) });
  save();
  console.log("true");
} else {
  console.error(`fake near: unsupported ${a.join(" ")}`);
  process.exit(1);
}
