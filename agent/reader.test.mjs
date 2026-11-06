// The reader is the rate-limit defence: these pin the behaviours the call budget in chain.mjs
// depends on.
import test from "node:test";
import assert from "node:assert/strict";
import { makeReader, TTL_MS } from "./chain.mjs";

function setup(answer = () => "v") {
  let t = 1_000_000;
  const calls = [];
  const fetchFn = async (_u, init) => {
    const p = JSON.parse(init.body).params;
    calls.push(p.method_name);
    const out = answer(p.method_name, calls.length);
    if (out instanceof Error) return { json: async () => ({ error: { message: out.message } }) };
    return { json: async () => ({ result: { result: [...Buffer.from(JSON.stringify(out))] } }) };
  };
  const reader = makeReader({ ttl: TTL_MS, now: () => t, fetchFn });
  return { reader, calls, advance: (ms) => (t += ms) };
}

test("a second read inside the TTL costs no call", async () => {
  const { reader, calls, advance } = setup();
  await reader.call("w", "decision_log");
  advance(4_000);
  await reader.call("w", "decision_log");
  assert.equal(calls.length, 1);
  advance(1_100);
  await reader.call("w", "decision_log");
  assert.equal(calls.length, 2);
});

test("concurrent reads share one call", async () => {
  const { reader, calls } = setup();
  await Promise.all([reader.call("w", "decision_log"), reader.call("w", "decision_log"), reader.call("w", "decision_log")]);
  assert.equal(calls.length, 1);
});

test("static views are read once", async () => {
  const { reader, calls, advance } = setup();
  await reader.call("w", "refusal_codes");
  advance(86_400_000);
  await reader.call("w", "refusal_codes");
  assert.equal(calls.length, 1);
});

test("fresh bypasses the cache", async () => {
  const { reader, calls } = setup();
  await reader.call("w", "decision_log");
  await reader.call("w", "decision_log", {}, { fresh: true });
  assert.equal(calls.length, 2);
});

test("different arguments are different entries", async () => {
  const { reader, calls } = setup();
  await reader.call("w", "node_record", { node: "a" });
  await reader.call("w", "node_record", { node: "b" });
  assert.equal(calls.length, 2);
});

test("a failure serves the last good value as stale and backs off instead of hammering", async () => {
  let fail = false;
  const { reader, calls, advance } = setup(() => (fail ? new Error("429") : "good"));
  assert.equal(await reader.call("w", "decision_log"), "good");
  fail = true;
  advance(6_000);
  assert.equal(await reader.call("w", "decision_log"), "good"); // failed call, stale served
  assert.equal(calls.length, 2);
  assert.equal(reader.errors().length, 1);
  advance(1_000);
  await reader.call("w", "decision_log"); // inside the back-off: no call
  assert.equal(calls.length, 2);
  advance(5_000);
  fail = false;
  await reader.call("w", "decision_log");
  assert.equal(calls.length, 3);
  assert.equal(reader.errors().length, 0);
});

test("a failure with nothing cached throws, and is not retried inside the back-off", async () => {
  const { reader, calls } = setup(() => new Error("429"));
  await assert.rejects(reader.call("w", "decision_log"), /429/);
  await assert.rejects(reader.call("w", "decision_log"), /429/);
  assert.equal(calls.length, 1);
});

test("idle budget: one minute of /state polling every 2 s makes the calls the budget says", async () => {
  const { reader, calls, advance } = setup();
  // what /state asks for: the log, plus readView's node_for / is_paused / node_record / refusal_codes
  for (let i = 0; i < 30; i++) {
    await Promise.all([
      reader.call("w", "decision_log"),
      reader.call("w", "node_for", { agent: "a" }),
      reader.call("w", "is_paused"),
      reader.call("w", "node_record", { node: "n" }),
      reader.call("w", "refusal_codes"),
    ]);
    advance(2_000);
  }
  // 60 s on a fake clock, so the counts are exact: the log every third poll (5 s TTL, polled every
  // 2 s) = 10, node_record every fifth (10 s) = 6, is_paused every eighth (15 s) = 4, and
  // node_for / refusal_codes once, since they never expire. 22 in all. Halving a TTL changes a
  // number here, which is the point.
  const per = calls.reduce((m, c) => ((m[c] = (m[c] ?? 0) + 1), m), {});
  assert.deepEqual(per, { decision_log: 10, node_for: 1, is_paused: 4, node_record: 6, refusal_codes: 1 });
  assert.equal(calls.length, 22);
});

test("stale-while-revalidate: an expired value is answered at once and refreshed behind it", async () => {
  let t = 1_000_000;
  let release;
  let n = 0;
  const gate = () => new Promise((r) => (release = r));
  const fetchFn = async () => {
    n++;
    if (n > 1) await gate();
    return { json: async () => ({ result: { result: [...Buffer.from(JSON.stringify(`v${n}`))] } }) };
  };
  const reader = makeReader({ ttl: TTL_MS, now: () => t, fetchFn, swr: true });
  assert.equal(await reader.call("w", "decision_log"), "v1");
  t += 6_000;
  assert.equal(await reader.call("w", "decision_log"), "v1"); // does not wait for the held-open refresh
  assert.equal(await reader.call("w", "decision_log"), "v1"); // and does not start a second one
  assert.equal(n, 2);
  release();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(await reader.call("w", "decision_log"), "v2");
});

test("access key lists are cached for 30 s like any other view", async () => {
  let t = 1_000_000, n = 0;
  const fetchFn = async (_u, init) => {
    n++;
    assert.equal(JSON.parse(init.body).params.request_type, "view_access_key_list");
    return { json: async () => ({ result: { keys: [] } }) };
  };
  const reader = makeReader({ ttl: TTL_MS, now: () => t, fetchFn });
  assert.deepEqual(await reader.call("w", "view_access_key_list"), { keys: [] });
  t += 29_000;
  await reader.call("w", "view_access_key_list");
  assert.equal(n, 1);
  t += 2_000;
  await reader.call("w", "view_access_key_list");
  assert.equal(n, 2);
});

test("a 429 moves to the next endpoint and remembers which one worked; a contract error does not", async () => {
  process.env.NEAR_RPC = "http://a.test,http://b.test";
  try {
    const seen = [];
    const fetchFn = async (url, init) => {
      seen.push(url);
      const method = JSON.parse(init.body).params.method_name;
      if (url === "http://a.test") return { status: 429, json: async () => ({ error: { code: -429, message: "Rate limits exceeded" } }) };
      if (method === "boom") return { status: 200, json: async () => ({ result: { error: "panicked: no such thing" } }) };
      return { status: 200, json: async () => ({ result: { result: [...Buffer.from('"ok"')] } }) };
    };
    const reader = makeReader({ ttl: {}, fetchFn });
    assert.equal(await reader.call("w", "x1"), "ok");
    assert.deepEqual(seen, ["http://a.test", "http://b.test"]);
    seen.length = 0;
    assert.equal(await reader.call("w", "x2"), "ok");
    assert.deepEqual(seen, ["http://b.test"]); // starts from the one that worked
    seen.length = 0;
    await assert.rejects(reader.call("w", "boom"), /panicked/);
    assert.deepEqual(seen, ["http://b.test"]); // a contract error is not retried elsewhere
  } finally { delete process.env.NEAR_RPC; }
});

test("when every endpoint is limited, the error says so", async () => {
  process.env.NEAR_RPC = "http://a.test,http://b.test";
  try {
    const fetchFn = async () => ({ status: 429, json: async () => ({ error: { code: -429, message: "slow down" } }) });
    await assert.rejects(makeReader({ ttl: {}, fetchFn }).call("w", "x"), /every endpoint/);
  } finally { delete process.env.NEAR_RPC; }
});
