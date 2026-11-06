// tools/assertion-relay.mjs carries a capture from the browser back to the machine a script is
// waiting on. It runs once, during a recording, at the one moment a retake costs a face scan and
// a refilled budget — so the ways it can go wrong are worth pinning.
//
// These tests drive the real process over a real socket. There is no WebAuthn here: the relay
// never verifies anything, it only decides what is worth writing to disk and where.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { once } from "node:events";

const REPO = resolve(import.meta.dirname, "..");
const RELAY = join(REPO, "tools", "assertion-relay.mjs");
const CAPTURE = join(REPO, "tests-sandbox", "tests", "fixtures", "assertion_real_device.json");

/// A port high enough to be free and derived from the test, so two tests never collide.
let nextPort = 8820;

/// Start a relay and wait for it to say it is listening. Returns the child, its directory and a
/// `url`, and kills the child when the test ends.
async function relay(t, { stem = "bud.test", dir } = {}) {
  const port = nextPort++;
  const where = dir ?? (await mkdtemp(join(tmpdir(), "relay-")));
  const child = spawn("node", [RELAY, where, stem, String(port)], { cwd: REPO });
  t.after(() => child.kill());

  let out = "";
  for await (const chunk of child.stdout) {
    out += chunk;
    if (out.includes("relay on")) break;
  }
  assert.match(out, /relay on/, "the relay should say where it is listening");
  return { dir: where, url: `http://127.0.0.1:${port}`, target: join(where, `${stem}.json`), child };
}

async function post(url, body) {
  const res = await fetch(`${url}/save`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: res.status, text: await res.text() };
}

test("a capture from the page lands where the script is waiting", async (t) => {
  const r = await relay(t);
  const capture = JSON.parse(await readFile(CAPTURE, "utf8"));

  const res = await post(r.url, capture);
  assert.equal(res.status, 200);

  const written = JSON.parse(await readFile(r.target, "utf8"));
  assert.equal(written.credential_id, capture.credential_id);
  assert.equal(written.signature_der, capture.signature_der);
});

test("a body that is not JSON is refused and nothing is written", async (t) => {
  const r = await relay(t);
  const res = await post(r.url, "not json at all");
  assert.equal(res.status, 400);
  await assert.rejects(readFile(r.target), /ENOENT/, "no file should exist");
});

test("a capture missing a field verify_assertion needs is refused, and says which", async (t) => {
  const r = await relay(t);
  const capture = JSON.parse(await readFile(CAPTURE, "utf8"));
  delete capture.signature_der;

  const res = await post(r.url, capture);
  assert.equal(res.status, 400);
  assert.match(res.text, /signature_der/, "the refusal names the missing field");
  await assert.rejects(readFile(r.target), /ENOENT/);
});

// The scripts poll for the file and read any file that parses. A capture that arrived in pieces
// would read as a broken one, cost a face scan, and look like a failure of the passkey.
test("the file a script sees is complete or absent, never half written", async (t) => {
  const r = await relay(t);
  const capture = JSON.parse(await readFile(CAPTURE, "utf8"));
  await post(r.url, capture);

  const text = await readFile(r.target, "utf8");
  assert.doesNotThrow(() => JSON.parse(text), "the written file parses");
  assert.ok(text.endsWith("\n"), "written whole, newline and all");
});

test("a second capture replaces the first, because a nonce is spent once", async (t) => {
  const r = await relay(t);
  const capture = JSON.parse(await readFile(CAPTURE, "utf8"));
  await post(r.url, capture);
  await post(r.url, { ...capture, challenge: "c2Vjb25k" });

  const written = JSON.parse(await readFile(r.target, "utf8"));
  assert.equal(written.challenge, "c2Vjb25k");
});

test("the page is served, and nothing above tools/ is", async (t) => {
  const r = await relay(t);

  const page = await fetch(`${r.url}/capture-assertion.html`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Leash passkey capture/);

  for (const path of ["/../deployments/testnet.json", "/../../etc/passwd", "/..%2fCargo.toml"]) {
    const res = await fetch(`${r.url}${path}`);
    assert.equal(res.status, 404, `${path} should not be served`);
  }
});

test("a filename the relay will not write stops it at startup", async (t) => {
  const child = spawn("node", [RELAY, tmpdir(), "../escape", "8899"], { cwd: REPO });
  t.after(() => child.kill());

  let err = "";
  child.stderr.on("data", (c) => (err += c));
  const [code] = await once(child, "exit");

  assert.equal(code, 1, "it refuses rather than writing somewhere surprising");
  assert.match(err, /not a filename/);
});

test("with no filename given it takes the budget node from the deployment", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "relay-"));
  const deployment = join(dir, "deployment.json");
  await writeFile(deployment, JSON.stringify({ budget_node: "bud.leash.testnet" }));

  const port = nextPort++;
  const child = spawn("node", [RELAY, dir, "", String(port)], {
    cwd: REPO,
    env: { ...process.env, LEASH_DEPLOYMENT: deployment },
  });
  t.after(() => child.kill());

  let out = "";
  for await (const chunk of child.stdout) {
    out += chunk;
    if (out.includes("lands at")) break;
  }
  assert.match(out, /bud\.leash\.testnet\.json/, "the node comes from the deployment file");
});
