#!/usr/bin/env bash
# Rehearsal only: stand in for the human with the phone, using a SOFTWARE credential.
# Usage: tools/drive-software-credential.sh <key.jwk> <logfile> [timeout-seconds]
# Run it beside scripts/reset-demo.sh or scripts/register-credential.sh, whose output goes to
# <logfile> (`script ... 2>&1 | tee <logfile>` or `> <logfile>`). Each time one of them prints
#   challenge: <base64>   and   ... save the JSON ... as: <path>
# this signs the challenge with tools/software-credential.mjs and writes the assertion to <path>,
# which is exactly what tools/capture-assertion.html plus "save the file" does for a person. The
# scripts cannot tell the difference, so a rehearsal driven this way walks the same path as the
# real run. It proves nothing about a device: preflight's real-device check must still fail.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY=${1:?key.jwk} LOG=${2:?logfile} TIMEOUT=${3:-300}
handled=0 waited=0
while ((waited < TIMEOUT)); do
  n=$(grep -c '^ *challenge: ' "$LOG" 2>/dev/null || true)
  if ((n > handled)); then
    challenge=$(grep '^ *challenge: ' "$LOG" | tail -1 | sed 's/^ *challenge: *//' | tr -d ' ')
    out=$(grep ' as: ' "$LOG" | tail -1 | sed 's/.* as: //')
    [[ -n $challenge && -n $out ]] || { sleep 0.3; continue; }
    node tools/software-credential.mjs sign "$KEY" "$challenge" > "$out.tmp"
    mv "$out.tmp" "$out"
    echo "signed ${challenge:0:12}... -> $out"
    handled=$n
    waited=0
  fi
  sleep 0.5
  waited=$((waited + 1))
done
echo "no further challenge in ${TIMEOUT}s; stopping"
