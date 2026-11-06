// The record of which transaction each payment was, kept in a small file so an agent restart (which
// happens between takes) does not turn every explorer link in the log into "no link".
//
// Bounded: the newest MAX_SENT entries, rewritten whole each time, so the file cannot grow past a
// few kilobytes. Written to a temporary file and renamed, so a crash mid-write leaves the old file
// intact rather than half a new one. It holds transaction hashes and public payment facts only,
// no key material. A missing, unreadable or malformed file is an empty record, not a crash.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export const MAX_SENT = 40;

// The two counts are how an entry is matched to a decision: a non-negative integer, or null when the
// pre-send read failed. Anything else (a string, a negative, NaN) is a malformed row and is dropped,
// so a hand-edited or damaged file cannot reach matchTxs and break /state on restart.
const count = (n) => n === null || (Number.isSafeInteger(n) && n >= 0);

const valid = (e) =>
  e && typeof e.tx === "string" && typeof e.agent === "string" && typeof e.payee === "string" && typeof e.amount === "string" &&
  Number.isFinite(e.at) && count(e.countBefore) && count(e.strangersBefore);

export function loadSent(path) {
  try {
    const j = JSON.parse(readFileSync(path, "utf8"));
    return (Array.isArray(j.sent) ? j.sent : []).filter(valid).slice(-MAX_SENT);
  } catch { return []; }
}

export function saveSent(path, sent) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ sent: sent.slice(-MAX_SENT) }), { mode: 0o600 });
    renameSync(tmp, path);
    return true;
  } catch { return false; }
}
