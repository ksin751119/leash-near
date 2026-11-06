#!/usr/bin/env bash
# Put the budget node into the scripted demo state: the rule in scripts/demo-beats.json, with
# nothing spent. Run scripts/preflight.sh afterwards.
# Usage: scripts/reset-demo.sh <testnet|mainnet> [assertions-dir]     (default dir: .assertions)
# Env:   WAIT_TIMEOUT        seconds to wait for each face scan (default 900)
#        CREDENTIAL_ID       which registered credential will sign (required if more than one)
#        LEASH_DEPLOYMENT    deployment file (default deployments/testnet.json)
#        LEASH_BEATS, AGENT_VENDORS   as in scripts/demo-rule.sh
# Needs the admin's key in the near-cli keychain, a registered credential, and jq 1.7.
#
# # What a reset costs: one face scan per widening step
#
# Loosening a rule needs a passkey assertion, and the first rule for a node is a loosening (a
# budget from nothing). Spent budget only comes back through an accepted loosening, because
# that is the only thing that opens a fresh window (re-applying the identical rule does not:
# that was a hole, closed and pinned by tests). So:
#
#   no rule yet                   -> set_rule(scripted)                  1 face scan
#   scripted rule, nothing spent  -> nothing to do                       0
#   something is looser in the
#   scripted rule                 -> set_rule(scripted)                  1 face scan
#   otherwise, but money spent    -> set_rule(a rule that is one unit    1 face scan,
#                                    looser than both), which reopens    then one tightening
#                                    the window, then set_rule(scripted) with no prompt
#   otherwise, nothing spent      -> set_rule(scripted), a tightening    0
#
# The script prints the plan, and the number of face scans, before it asks for anything.
#
# # Where the assertion comes from
#
# This script cannot make one: only the passkey can. An assertion is bound to the exact rule, the
# node, the credential's CURRENT nonce and this wallet, so it cannot be made in advance and
# cannot be reused. For each gated step the script
#   1. moves any existing <dir>/<node>.json aside (.stale), so it always asks for a fresh signature,
#   2. asks the wallet for the challenge (view `challenge_for`) and prints it,
#   3. waits for <dir>/<node>.json to appear, parse as JSON AND carry exactly that challenge,
#      saying every 10 seconds what it is waiting for and for how long it has been,
#   4. calls set_rule as the admin and renames the file `.used`.
# Make the file with tools/capture-assertion.html: paste the challenge, press Sign, save the JSON.
# Serve that page with `node tools/assertion-relay.mjs` and the page can send the capture back
# itself, which is the only practical route when the browser is not on this machine.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "reset-demo.sh: $*" >&2; exit 1; }

[[ $# -ge 1 && $# -le 2 ]] || die "usage: reset-demo.sh <testnet|mainnet> [assertions-dir]"
NETWORK=$1 DIR=${2:-.assertions}
TIMEOUT=${WAIT_TIMEOUT:-900}
DEPLOYMENT=${LEASH_DEPLOYMENT:-deployments/testnet.json}
export LEASH_DEPLOYMENT=$DEPLOYMENT

case "$NETWORK" in testnet | mainnet) ;; *) die "unknown network '$NETWORK' (expected testnet or mainnet)" ;; esac
command -v jq >/dev/null || die "jq is required"
command -v near >/dev/null || die "near-cli is required"
[[ $(jq --version) =~ ^jq-1\.([7-9]|[1-9][0-9]) ]] || die "jq 1.7 or newer is required (older versions mangle the u64 window bound)"
[[ $TIMEOUT =~ ^[0-9]+$ ]] || die "WAIT_TIMEOUT must be a whole number of seconds, got '$TIMEOUT'"
WALLET=$(jq -er .wallet "$DEPLOYMENT") || die "$DEPLOYMENT has no wallet"
ADMIN=$(jq -er .admin "$DEPLOYMENT") || die "$DEPLOYMENT has no admin"
NODE=$(jq -er .budget_node "$DEPLOYMENT") || die "$DEPLOYMENT has no budget_node"
TARGET=$(scripts/demo-rule.sh) || die "could not build the scripted rule"
mkdir -p "$DIR"

# A view call. stderr is shown, not discarded: a failing view is the thing you most need to see.
view() { # <method> <json-args>
  local out
  out=$(near contract call-function as-read-only "$WALLET" "$1" json-args "$2" \
    network-config "$NETWORK" now) || die "view $1 on $WALLET failed (output above)"
  printf '%s\n' "$out"
}

ids=$(view credential_ids '{}')
count=$(jq 'length' <<<"$ids") || die "credential_ids returned something that is not a list: $ids"
[[ $count -gt 0 ]] || die "no credential is registered on $WALLET; register one first"

# ---- the plan -------------------------------------------------------------------------------

rec=$(view node_record "$(jq -nc --arg n "$NODE" '{node:$n}')")
PLAN=$(jq -c --argjson t "$TARGET" '
  def n: tonumber;
  # Parameters are bound to variables first: a filter argument is re-evaluated against whatever
  # `.` is at the point of use, which inside `any(...; ...)` is not the record.
  def loosens(c; p): c as $c | p as $p |
    $p.token != $c.token
    or ($p.per_tx_limit | n) > ($c.per_tx_limit | n)
    or ($p.period_limit | n) > ($c.period_limit | n)
    or $p.period_ms < $c.period_ms
    or $p.window_start_ms < $c.window_start_ms
    or $p.window_end_ms > $c.window_end_ms
    or any($p.payees[]; . as $x | ($c.payees | index($x)) == null)
    or ($c.paused and ($p.paused | not));
  # looser than both c and t in every field, strictly looser than c in the period limit.
  # Values are picked, never recomputed, so the u64 window bound keeps its exact digits.
  def above(c; t): c as $c | t as $t | {
      token: $t.token,
      per_tx_limit: (if ($c.per_tx_limit | n) > ($t.per_tx_limit | n) then $c.per_tx_limit else $t.per_tx_limit end),
      period_limit: (([$c.period_limit | n, $t.period_limit | n] | max) + 1 | tostring),
      period_ms: (if $c.period_ms < $t.period_ms then $c.period_ms else $t.period_ms end),
      window_start_ms: (if $c.window_start_ms < $t.window_start_ms then $c.window_start_ms else $t.window_start_ms end),
      window_end_ms: (if $c.window_end_ms > $t.window_end_ms then $c.window_end_ms else $t.window_end_ms end),
      payees: (($c.payees + $t.payees) | unique),
      paused: false };
  def canon: .payees |= sort;
  if . == null then [{rule: $t, gated: true, why: "this node has no rule yet; a budget from nothing is a loosening"}]
  elif loosens(.rule; $t) then [{rule: $t, gated: true, why: "the scripted rule is looser than the one in force"}]
  elif (.spent | n) > 0 then
    [{rule: above(.rule; $t), gated: true, why: "\(.spent) already spent; only an accepted loosening opens a fresh window"},
     {rule: $t, gated: false, why: "back down to the scripted rule; a tightening needs no prompt"}]
  elif (.rule | canon) != ($t | canon) then [{rule: $t, gated: false, why: "the scripted rule is tighter than the one in force; a tightening needs no prompt"}]
  else [] end' <<<"$rec") || die "could not plan from the node record: $rec"

steps=$(jq 'length' <<<"$PLAN")
scans=$(jq '[.[] | select(.gated)] | length' <<<"$PLAN")
echo "node $NODE on $WALLET"
if [[ $steps -eq 0 ]]; then
  echo "already in the scripted state (the scripted rule, nothing spent). Nothing to do."
  exit 0
fi
echo "plan: $steps set_rule call(s), $scans of them need a face scan"
jq -r 'to_entries[] | "  step \(.key + 1): \(if .value.gated then "FACE SCAN" else "no prompt " end)  \(.value.why)"' <<<"$PLAN"

# Which credential signs matters only if a step needs a face scan: a plan made of tightenings
# (the second half of demo beat 4) must run with no CREDENTIAL_ID, whatever is registered.
cred=
if [[ $scans -gt 0 ]]; then
  if [[ -n ${CREDENTIAL_ID:-} ]]; then
    jq -e --arg c "$CREDENTIAL_ID" 'index($c) != null' <<<"$ids" >/dev/null || die "CREDENTIAL_ID $CREDENTIAL_ID is not registered; registered: $(jq -c . <<<"$ids")"
    cred=$CREDENTIAL_ID
  elif [[ $count -eq 1 ]]; then
    cred=$(jq -r '.[0]' <<<"$ids")
  else
    die "$count credentials are registered and a gated step can only be signed by one of them: set CREDENTIAL_ID to the one whose device you will use. Registered: $(jq -c . <<<"$ids")"
  fi
fi
echo

# The challenge a saved assertion actually signed, as standard base64 without padding. It is
# read out of clientDataJSON (base64url) because that is what the signature covers.
signed_challenge() { # <file>
  jq -r '.client_data_json | fromjson | .challenge' "$1" | tr '_-' '/+' | tr -d '='
}

send_set_rule() { # <rule-json> [assertion-file]
  local args
  if [[ -n ${2:-} ]]; then
    args=$(jq -nc --arg n "$NODE" --argjson r "$1" --slurpfile a "$2" \
      '{node:$n, rule:$r, assertion:($a[0] | {credential_id, authenticator_data, client_data_json, signature_der})}')
  else
    args=$(jq -nc --arg n "$NODE" --argjson r "$1" '{node:$n, rule:$r}')
  fi
  near contract call-function as-transaction "$WALLET" set_rule json-args "$args" \
    prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
    sign-as "$ADMIN" network-config "$NETWORK" sign-with-keychain send
}

scan=0
for ((i = 0; i < steps; i++)); do
  rule=$(jq -c ".[$i].rule" <<<"$PLAN")
  gated=$(jq -r ".[$i].gated" <<<"$PLAN")
  file="$DIR/$NODE.json"

  if [[ $gated != true ]]; then
    echo "step $((i + 1))/$steps: tightening, no prompt"
    send_set_rule "$rule" || die "set_rule (step $((i + 1))) failed (output above)"
    continue
  fi

  scan=$((scan + 1))
  # Never reuse a file from an earlier run: its nonce may be spent.
  if [[ -e $file ]]; then
    mv -f "$file" "$file.stale"
    echo "moved an existing $file aside to $file.stale; a fresh signature is required"
  fi

  challenge=$(view challenge_for "$(jq -nc --arg n "$NODE" --argjson r "$rule" --arg c "$cred" \
    '{node:$n, rule:$r, credential_id:$c}')" | jq -r .) || die "challenge_for returned something that is not JSON"
  [[ -n $challenge && $challenge != null ]] || die "challenge_for returned no challenge for step $((i + 1))"
  want=$(printf '%s' "$challenge" | tr -d '=')

  echo "step $((i + 1))/$steps: FACE SCAN $scan of $scans"
  echo "  The rule being signed: $rule"
  echo "  challenge: $challenge"
  echo "  1. open tools/capture-assertion.html (HTTPS or localhost) on the device that holds the credential"
  echo "  2. paste the challenge, press Sign, unlock with your face or fingerprint"
  echo "  3. press \"Send to the waiting script\", or save the JSON it prints as: $file"
  echo "     (Send needs the page served by: node tools/assertion-relay.mjs $DIR $NODE)"

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
        echo "  Wrong rule, wrong step, or a stale nonce. Sign the challenge above and save again." >&2
      fi
    fi
    if ((waited >= TIMEOUT)); then
      [[ -s $file ]] && echo "  note: $file exists but is not valid JSON (an incomplete save?)" >&2
      die "gave up after ${TIMEOUT}s waiting for the face scan for step $((i + 1)) (a valid assertion over: $challenge). Nothing was changed by this step."
    fi
    if ((waited > 0 && waited % 10 == 0)); then
      echo "  still waiting for the face scan ${scan}/${scans} (file $file): ${waited}s of ${TIMEOUT}s"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "  got a valid assertion after ${waited}s; sending set_rule"

  if ! send_set_rule "$rule" "$file"; then
    mv -f "$file" "$file.failed"
    die "set_rule (step $((i + 1))) failed (output above). The assertion was moved to $file.failed and will not be reused; the next run asks for a fresh one."
  fi
  mv -f "$file" "$file.used"
done

# Trust the chain, not the exit codes: read the node back and say what it holds.
rec=$(view node_record "$(jq -nc --arg n "$NODE" '{node:$n}')")
jq -e --argjson t "$TARGET" '.spent == "0" and ((.rule | .payees |= sort) == ($t | .payees |= sort))' <<<"$rec" >/dev/null \
  || die "the node did NOT end in the scripted state. On chain: $(jq -c '{rule, spent}' <<<"$rec")"
echo "demo state applied: $NODE holds the scripted rule with nothing spent ($scans face scan(s)). Now run scripts/preflight.sh"
