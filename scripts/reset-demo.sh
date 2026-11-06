#!/usr/bin/env bash
# Put a fresh deployment into the demo state: the rules in a demo file applied to their nodes.
# Usage: scripts/reset-demo.sh <wallet> <admin> <demo.json> <assertions-dir> <testnet|mainnet>
# Env:   WAIT_TIMEOUT  seconds to wait for each assertion file (default 900)
#
# demo.json: [{"node": "ops.leash.testnet", "rule": { ...Rule JSON... }}, ...]
#
# # Where the passkey assertions come from
#
# The first `set_rule` for a node is a LOOSENING (a budget from nothing), so each one needs a
# passkey assertion, and this script cannot make one: only the passkey can. The gate is not
# weakened here. An assertion is bound to the exact rule, the node, the credential's CURRENT
# nonce and this wallet, so it cannot be generated in advance and cannot be reused: ONE FRESH
# ASSERTION PER NODE, produced while the script waits.
#
# For each node the script:
#   1. moves any existing <assertions-dir>/<node>.json aside (to .stale), so a re-run can never
#      reuse a dead assertion: it always asks for a fresh signature,
#   2. asks the wallet for the challenge (view `challenge_for`) and prints it,
#   3. waits (up to WAIT_TIMEOUT) for <assertions-dir>/<node>.json to appear AND parse as JSON
#      AND carry exactly the challenge it printed,
#   4. calls set_rule as the admin, then renames the file `.used`.
# Produce the file with tools/capture-assertion.html: paste the printed challenge, press
# Sign, and save the JSON it prints as <assertions-dir>/<node>.json.
#
# Needs the admin's key in the near-cli keychain, a registered credential
# (`register_credential`, admin only, no assertion), and `jq`.
set -euo pipefail

die() { echo "reset-demo.sh: $*" >&2; exit 1; }

[[ $# -eq 5 ]] || die "usage: reset-demo.sh <wallet> <admin> <demo.json> <assertions-dir> <testnet|mainnet>"
WALLET=$1 ADMIN=$2 DEMO=$3 DIR=$4 NETWORK=$5
TIMEOUT=${WAIT_TIMEOUT:-900}

case "$NETWORK" in testnet | mainnet) ;; *) die "unknown network '$NETWORK' (expected testnet or mainnet)" ;; esac
command -v jq >/dev/null || die "jq is required"
command -v near >/dev/null || die "near-cli is required"
[[ -f $DEMO ]] || die "demo file not found: $DEMO"
jq -e 'type == "array" and length > 0 and all(.[]; has("node") and has("rule"))' "$DEMO" >/dev/null \
  || die "$DEMO must be a non-empty array of {node, rule}"
mkdir -p "$DIR"

# A view call. stderr is shown, not discarded: a failing view is the thing you most need to see.
view() { # <method> <json-args>
  local out
  out=$(near contract call-function as-read-only "$WALLET" "$1" json-args "$2" \
    network-config "$NETWORK" now) || die "view $1 on $WALLET failed (output above)"
  printf '%s\n' "$out"
}

cred=$(view credential_ids '{}' | jq -r '.[0] // empty')
[[ -n $cred ]] || die "no credential is registered on $WALLET; register one first"

# The challenge a saved assertion actually signed, as standard base64 without padding. It is
# read out of clientDataJSON (base64url) because that is what the signature covers.
signed_challenge() { # <file>
  jq -r '.client_data_json | fromjson | .challenge' "$1" | tr '_-' '/+' | tr -d '='
}

n=$(jq 'length' "$DEMO")
for ((i = 0; i < n; i++)); do
  node=$(jq -r ".[$i].node" "$DEMO")
  rule=$(jq -c ".[$i].rule" "$DEMO")
  file="$DIR/$node.json"

  # Never reuse a file from an earlier run: its nonce may be spent.
  if [[ -e $file ]]; then
    mv -f "$file" "$file.stale"
    echo "moved an existing $file aside to $file.stale; a fresh signature is required"
  fi

  challenge=$(view challenge_for "$(jq -nc --arg n "$node" --argjson r "$rule" --arg c "$cred" \
    '{node:$n, rule:$r, credential_id:$c}')" | jq -r .) || die "challenge_for returned something that is not JSON"
  [[ -n $challenge && $challenge != null ]] || die "challenge_for returned no challenge for $node"
  want=$(printf '%s' "$challenge" | tr -d '=')

  echo "node $node ($((i + 1))/$n)"
  echo "  challenge: $challenge"
  echo "  sign it in tools/capture-assertion.html and save the JSON as: $file"
  echo "  (waiting up to ${TIMEOUT}s)"

  waited=0
  while true; do
    if [[ -s $file ]]; then
      # A browser may still be writing it: only a file that parses is taken as finished.
      if jq -e . "$file" >/dev/null 2>&1; then
        got=$(signed_challenge "$file" 2>/dev/null || true)
        if [[ $got == "$want" ]]; then break; fi
        mv -f "$file" "$file.wrong"
        echo "  $file signed a different challenge (moved to $file.wrong)." >&2
        echo "    signed:   ${got:-<unreadable>}" >&2
        echo "    expected: $want" >&2
        echo "  Wrong node, wrong rule, or a stale nonce. Sign the challenge above and save again." >&2
      fi
    fi
    if ((waited >= TIMEOUT)); then
      [[ -s $file ]] && echo "  note: $file exists but is not valid JSON (an incomplete save?)" >&2
      die "timed out after ${TIMEOUT}s waiting for $file (a valid assertion over: $challenge)"
    fi
    sleep 1
    waited=$((waited + 1))
  done

  # Only the four fields the contract reads; the capture tool adds notes and metadata.
  args=$(jq -nc --arg n "$node" --argjson r "$rule" --slurpfile a "$file" \
    '{node:$n, rule:$r, assertion:($a[0] | {credential_id, authenticator_data, client_data_json, signature_der})}')
  if ! near contract call-function as-transaction "$WALLET" set_rule json-args "$args" \
    prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
    sign-as "$ADMIN" network-config "$NETWORK" sign-with-keychain send; then
    mv -f "$file" "$file.failed"
    die "set_rule for $node failed (output above). The assertion was moved to $file.failed and will not be reused; the next run asks for a fresh one."
  fi
  mv -f "$file" "$file.used"
done
echo "demo state applied to $n node(s)"
