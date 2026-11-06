#!/usr/bin/env bash
# Put a fresh deployment into the demo state: the rules in a demo file applied to their nodes.
# Usage: scripts/reset-demo.sh <wallet> <admin> <demo.json> <assertions-dir> <testnet|mainnet>
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
#   1. asks the wallet for the challenge (view `challenge_for`) and prints it,
#   2. waits for <assertions-dir>/<node>.json to appear,
#   3. calls set_rule as the admin with that file as the assertion, then renames it `.used`.
# Produce the file with tools/capture-assertion.html: paste the printed challenge, press
# Sign, and save the JSON it prints as <assertions-dir>/<node>.json.
# Re-running after a failure is safe: a spent assertion is rejected, and the script simply asks
# for a fresh one.
#
# Needs the admin's key in the near-cli keychain, a registered credential
# (`register_credential`, admin only, no assertion), and `jq`.
set -euo pipefail

WALLET=${1:?usage: reset-demo.sh <wallet> <admin> <demo.json> <assertions-dir> <testnet|mainnet>}
ADMIN=${2:?admin account}
DEMO=${3:?demo.json}
DIR=${4:?directory for assertion files}
NETWORK=${5:?testnet or mainnet}
mkdir -p "$DIR"

view() { # <method> <json-args>
  near contract call-function as-read-only "$WALLET" "$1" json-args "$2" network-config "$NETWORK" now 2>/dev/null
}

cred=$(view credential_ids '{}' | jq -r '.[0] // empty')
[[ -n $cred ]] || { echo "reset-demo.sh: no credential is registered on $WALLET; register one first" >&2; exit 1; }

n=$(jq 'length' "$DEMO")
for ((i = 0; i < n; i++)); do
  node=$(jq -r ".[$i].node" "$DEMO")
  rule=$(jq -c ".[$i].rule" "$DEMO")
  file="$DIR/$node.json"

  challenge=$(view challenge_for "$(jq -nc --arg n "$node" --argjson r "$rule" --arg c "$cred" \
    '{node:$n, rule:$r, credential_id:$c}')" | jq -r .)
  echo "node $node ($((i + 1))/$n)"
  echo "  challenge: $challenge"
  echo "  sign it in tools/capture-assertion.html and save the JSON as: $file"
  while [[ ! -s $file ]]; do sleep 2; done

  args=$(jq -nc --arg n "$node" --argjson r "$rule" --slurpfile a "$file" \
    '{node:$n, rule:$r, assertion:$a[0]}')
  near contract call-function as-transaction "$WALLET" set_rule json-args "$args" \
    prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
    sign-as "$ADMIN" network-config "$NETWORK" sign-with-keychain send
  mv "$file" "$file.used"
done
echo "demo state applied to $n node(s)"
