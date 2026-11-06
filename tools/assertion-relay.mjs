#!/usr/bin/env node
// Serve tools/ over HTTP and take a captured assertion back from the browser.
//
// # Why this exists
//
// scripts/reset-demo.sh prints a challenge and then waits for a file to appear on the machine
// it runs on. capture-assertion.html runs in a browser, which may be somewhere else entirely —
// over an SSH tunnel the page is on a laptop and the script is on a server, and the only way to
// close that gap by hand is to copy JSON between two machines in the middle of a recording.
// This relay closes it: the page POSTs its capture back and the file lands where the script is
// already looking.
//
// # Usage
//
//   node tools/assertion-relay.mjs <assertions-dir> <stem> [port]
//
// The stem is the filename a script is waiting for, without ".json": reset-demo.sh waits for the
// budget node, register-credential.sh waits for "register". Defaults: .assertions, the budget
// node in deployments/testnet.json, port 8799. Then open
// http://localhost:<port>/capture-assertion.html (through the tunnel, if any).
//
// # What it will not do
//
// It binds 127.0.0.1 only, so it is reachable through a tunnel or from the same machine and
// from nowhere else. The destination path is fixed at startup from the arguments: nothing in a
// request chooses a filename, so a request cannot address any other file. A POST body must
// parse as JSON and carry the six fields verify_assertion needs, or it is refused and nothing
// is written. The write is a temp file plus a rename, because reset-demo.sh polls for the file
// and must never read half of one.

import { createServer } from "node:http";
import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { join, extname, resolve, basename } from "node:path";

const TOOLS = resolve(import.meta.dirname);
const REPO = resolve(TOOLS, "..");

const REQUIRED = [
  "credential_id",
  "pubkey_sec1",
  "challenge",
  "authenticator_data",
  "client_data_json",
  "signature_der",
];

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const [, , dirArg, stemArg, portArg] = process.argv;
const DIR = resolve(REPO, dirArg || ".assertions");
const PORT = Number(portArg || 8799);

async function stem() {
  if (stemArg) return stemArg;
  const file = process.env.LEASH_DEPLOYMENT || "deployments/testnet.json";
  try {
    return JSON.parse(await readFile(resolve(REPO, file), "utf8")).budget_node;
  } catch {
    return null;
  }
}

const STEM = await stem();
if (!STEM) {
  console.error(
    "no filename: pass one as the second argument, or make deployments/testnet.json readable",
  );
  process.exit(1);
}
// An account id or "register". Checked rather than sanitised: a stem that does not match is a
// typo worth seeing, and the file a script waits for is never a strange name.
if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(STEM)) {
  console.error(`not a filename this relay will write: ${STEM}`);
  process.exit(1);
}

// Fixed at startup. No request can influence it.
const TARGET = join(DIR, `${STEM}.json`);

function send(res, code, body, type = "text/plain; charset=utf-8") {
  res.writeHead(code, { "content-type": type, "cache-control": "no-store" });
  res.end(body);
}

async function readBody(req, limit = 256 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error("body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function save(req, res) {
  let capture;
  try {
    capture = JSON.parse(await readBody(req));
  } catch (e) {
    return send(res, 400, `that is not JSON the relay can read: ${e.message}`);
  }
  const missing = REQUIRED.filter((k) => typeof capture?.[k] !== "string" || !capture[k]);
  if (missing.length) {
    return send(res, 400, `the capture is missing: ${missing.join(", ")}`);
  }
  await mkdir(DIR, { recursive: true });
  // reset-demo.sh polls this path; a partial file would read as a broken capture.
  const tmp = `${TARGET}.partial`;
  await writeFile(tmp, `${JSON.stringify(capture, null, 2)}\n`);
  await rename(tmp, TARGET);
  console.log(`saved a capture to ${TARGET}`);
  send(res, 200, `saved as ${TARGET}`);
}

async function serve(req, res) {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "POST" && url.pathname === "/save") return save(req, res);
  if (req.method !== "GET") return send(res, 405, "only GET and POST /save");

  // Serve a flat directory: a request names one file in tools/ and nothing else.
  const name = basename(url.pathname === "/" ? "capture-assertion.html" : url.pathname);
  try {
    const body = await readFile(join(TOOLS, name));
    send(res, 200, body, TYPES[extname(name)] || "application/octet-stream");
  } catch {
    send(res, 404, `no such file in tools/: ${name}`);
  }
}

createServer((req, res) => {
  serve(req, res).catch((e) => send(res, 500, `relay failed: ${e.message}`));
}).listen(PORT, "127.0.0.1", () => {
  console.log(`relay on http://localhost:${PORT}/capture-assertion.html`);
  console.log(`a capture sent from the page lands at ${TARGET}`);
});
