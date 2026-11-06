#!/usr/bin/env bash
# Print the rule the scripted demo assumes, as one line of JSON: the limits in
# scripts/demo-beats.json, with the token and the payee accounts of this deployment.
# Used by reset-demo.sh (to apply it) and preflight.sh (to compare with the chain), so the two
# can never disagree about what "the scripted state" is.
# PERIOD_LIMIT=<base units> replaces the period limit: demo beat 4 uses it to widen (3.00, one
# face scan) and then to come back down (no override, no prompt) through reset-demo.sh.
# Env: PERIOD_LIMIT, LEASH_DEPLOYMENT (deployments/testnet.json), LEASH_BEATS (scripts/demo-beats.json),
#      AGENT_VENDORS (agent/vendors.json: payee id -> account)
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -n ${PERIOD_LIMIT:-} && ! ${PERIOD_LIMIT} =~ ^[1-9][0-9]{0,15}$ ]]; then
  echo "demo-rule.sh: PERIOD_LIMIT must be a whole number of base units, got '$PERIOD_LIMIT'" >&2; exit 1
fi
jq -c --arg override "${PERIOD_LIMIT:-}" --slurpfile d "${LEASH_DEPLOYMENT:-deployments/testnet.json}" --slurpfile v "${AGENT_VENDORS:-agent/vendors.json}" '
  ($v[0] | map({(.id): .account}) | add) as $by
  | (.rule | if $override != "" then .period_limit = $override else . end)
    + {token: $d[0].token,
             payees: ([.rule.payees[] | $by[.] // error("payee id " + . + " is not in the vendor list")] | sort)}' \
  "${LEASH_BEATS:-scripts/demo-beats.json}"
