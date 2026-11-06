#!/usr/bin/env bash
# Is this deployment ready to record? Reads the chain and the two agent processes, changes
# nothing, spends nothing. Safe to run as often as you like: about ten RPC calls and two local
# HTTP requests, a couple of seconds.
#
# Usage: scripts/preflight.sh
# Env (all optional except where it says so):
#   REAL_DEVICE_CREDENTIAL_ID  REQUIRED for the last check: the id of the registered credential
#                              you made on a real phone or laptop. See "the human gate" below.
#   LEASH_DEPLOYMENT           deployment file (default deployments/testnet.json)
#   LEASH_BEATS                scripted beats (default scripts/demo-beats.json)
#   AGENT_VENDORS              vendor list (default agent/vendors.json)
#   AGENT_URLS                 "<alpha-url> <beta-url>" (default http://127.0.0.1:8788 http://127.0.0.1:8789)
#   NEAR_RPC                   comma-separated RPC endpoints, tried in order (default as the agents)
#
# Every check prints PASS or FAIL with the numbers it saw, and the exit status is 1 if any failed.
# A check that cannot read what it needs FAILS, and says why: an RPC error, an empty answer or a
# missing variable is never read as zero and never as "nothing to complain about". (The previous
# version of this project went green because a missing argument defaulted to 0. There is no
# `|| echo 0` and no `${X:-0}` in this file; `grep -n '|| echo\|:-0' scripts/preflight.sh`
# should find nothing but this comment.)
#
# # The human gate
#
# The contract verifies that the holder of a registered credential signed an exact challenge
# and that the authenticator asserted user verification. It cannot tell a phone's secure
# enclave from a P-256 key made by a script: there is no attestation, and synced passkeys attest
# `none`. So "at least one credential is a real device" cannot be checked by a program. What
# this script can check is that the credential you name is registered, has been used for at
# least one assertion the chain accepted (its nonce is above zero), and is not the software
# credential recorded in the deployment file. That the device is real is YOUR claim, made by
# setting REAL_DEVICE_CREDENTIAL_ID, and the script says so in its output.
set -uo pipefail
cd "$(dirname "$0")/.."

DEPLOYMENT=${LEASH_DEPLOYMENT:-deployments/testnet.json}
BEATS=${LEASH_BEATS:-scripts/demo-beats.json}
VENDORS=${AGENT_VENDORS:-agent/vendors.json}
read -r -a AGENT_URL_LIST <<<"${AGENT_URLS:-http://127.0.0.1:8788 http://127.0.0.1:8789}"
IFS=, read -r -a ENDPOINTS <<<"${NEAR_RPC:-https://test.rpc.fastnear.com,https://near-testnet.drpc.org,https://archival-rpc.testnet.near.org}"
CURL_TIMEOUT=6
SEND_GAS_TGAS=60       # what an agent attaches to spend; the call needs about 40, see the README
SENDS_COVERED=3        # an agent's key must pay for its scripted sends this many times over
MIN_WINDOW_LEFT_MS=$((30 * 60 * 1000))  # the budget window must not roll over mid-recording
MAX_EXACT=9007199254740991              # jq does arithmetic in doubles; amounts above this are refused

FAILS=0 CHECKS=0
pass() { CHECKS=$((CHECKS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); printf 'FAIL  %s\n' "$1"; shift; for l in "$@"; do printf '        %s\n' "$l"; done; }
note() { printf '      %s\n' "$1"; }
die() { printf 'preflight.sh: %s\n' "$*" >&2; exit 2; }

command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"
command -v awk >/dev/null || die "awk is required"
[[ ${#ENDPOINTS[@]} -gt 0 ]] || die "NEAR_RPC names no endpoint"
[[ ${#AGENT_URL_LIST[@]} -eq 2 ]] || die "AGENT_URLS must hold exactly two urls (alpha, beta), got ${#AGENT_URL_LIST[@]}"
for f in "$DEPLOYMENT" "$BEATS" "$VENDORS"; do
  [[ -r $f ]] || die "cannot read $f"
  jq -e . "$f" >/dev/null 2>&1 || die "$f is not valid JSON"
done

# Required fields, read with -e so a missing one is an error rather than "null".
dep() { jq -er "$1" "$DEPLOYMENT" 2>/dev/null || die "$DEPLOYMENT has no usable $1"; }
WALLET=$(dep .wallet) TOKEN=$(dep .token) ADMIN=$(dep .admin) NODE=$(dep .budget_node)
dep '.agents | type == "object" and length >= 2' >/dev/null

# ---- the one place that talks to the network ------------------------------------------------

# rpc <method> <params-json>: prints the JSON-RPC body. A rate limit, a timeout or a non-JSON
# answer moves on to the next endpoint; a contract or protocol error is the answer and is
# returned as-is for the caller to judge.
# Errors travel through a file: the readers below run inside $(...), and a variable set in a
# subshell is gone by the time the caller wants to say why a check failed.
ERRFILE=$(mktemp) || die "cannot make a temp file"
trap 'rm -f "$ERRFILE"' EXIT
seterr() { printf '%s' "$1" >"$ERRFILE"; }
lasterr() { cat "$ERRFILE"; }

rpc() {
  local ep out last=
  for ep in "${ENDPOINTS[@]}"; do
    if ! out=$(curl -sS --max-time "$CURL_TIMEOUT" "$ep" -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" 2>&1); then
      last="$ep: ${out:0:120}"; continue
    fi
    if ! jq -e . >/dev/null 2>&1 <<<"$out"; then last="$ep: answered something that is not JSON: ${out:0:80}"; continue; fi
    if jq -e '(.error.code? == -429) or ((.error // {}) | tostring | test("rate limit|DEPRECATED|too many"; "i"))' <<<"$out" >/dev/null; then
      last="$ep: rate limited"; continue
    fi
    printf '%s' "$out"; return 0
  done
  seterr "no endpoint answered (last: ${last:-none tried})"
  return 1
}

# view <account> <method> <args-json>: prints the contract's JSON answer, or fails, leaving the reason for lasterr.
view() {
  local body b64 res
  local args=${3:-"{}"}
  b64=$(printf '%s' "$args" | base64 -w0)
  body=$(rpc query "{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$1\",\"method_name\":\"$2\",\"args_base64\":\"$b64\"}") \
    || return 1
  if jq -e '.error != null or .result.error != null' <<<"$body" >/dev/null; then
    seterr "$1.$2 returned an error: $(jq -c '.error // .result.error' <<<"$body" | cut -c1-200)"; return 1
  fi
  # No -e here: a view that answers `false` or `null` is a valid answer, not a failure.
  res=$(jq -c '.result.result | implode | fromjson' <<<"$body" 2>/dev/null) \
    || { seterr "$1.$2 answered with something that is not JSON"; return 1; }
  printf '%s' "$res"
}

# access_keys <account>: prints {keys:[...]} or fails, leaving the reason for lasterr.
access_keys() {
  local body
  body=$(rpc query "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$1\"}") \
    || return 1
  if ! jq -e '.result.keys | type == "array"' <<<"$body" >/dev/null 2>&1; then
    seterr "no key list for $1: $(jq -c '.error // .result.error // .result' <<<"$body" | cut -c1-200)"; return 1
  fi
  jq -c '.result' <<<"$body"
}

# ---- units -----------------------------------------------------------------------------------

fmt() { awk -v n="$1" 'BEGIN { printf "%.2f", n / 1000000 }'; }  # base units (6 decimals) -> "0.50"
digits() { [[ $1 =~ ^[0-9]+$ ]]; }  # a plain non-negative integer of any size (yocto allowances are 1e23)
exact() { awk -v n="$1" -v m="$MAX_EXACT" 'BEGIN { exit !(n ~ /^[0-9]+$/ && n + 0 <= m + 0) }'; }
codetxt() { if [[ $1 == 0 ]]; then printf ''; else printf ' code %s' "$1"; fi; }
toyocto_near() { awk -v n="$1" 'BEGIN { printf "%.4f", n / 1e24 }'; }

printf 'Leash preflight: wallet %s, budget node %s\n' "$WALLET" "$NODE"
printf 'deployment %s, beats %s\n\n' "$DEPLOYMENT" "$BEATS"

# ---- 1. the wallet has no keys ---------------------------------------------------------------

if out=$(access_keys "$WALLET"); then
  n=$(jq '.keys | length' <<<"$out")
  if [[ $n -eq 0 ]]; then pass "wallet $WALLET has zero access keys of any kind (nobody can sign as it)"
  else fail "wallet $WALLET has $n access key(s); it must have none" "$(jq -c '[.keys[] | {public_key, permission: (.access_key.permission | if type == "string" then . else "FunctionCall" end)}]' <<<"$out")"; fi
else fail "wallet key list could not be read, so 'no keys' is NOT established" "$(lasterr)"; fi

# ---- 2. each agent holds exactly one spend-only key -----------------------------------------

GAS_PRICE=
if body=$(rpc gas_price '[null]') && GAS_PRICE=$(jq -er '.result.gas_price' <<<"$body" 2>/dev/null) && exact "$GAS_PRICE"; then :
else GAS_PRICE=; fi

NAMES=$(jq -r '[.beats[].agent] | unique[]' "$BEATS") || die "$BEATS has no beats"
declare -A AGENT_ACCOUNT
for name in $NAMES; do
  acct=$(jq -r --arg p "$name." '.agents | keys | map(select(startswith($p))) | if length == 1 then .[0] else "" end' "$DEPLOYMENT")
  AGENT_ACCOUNT[$name]=$acct
  if [[ -z $acct ]]; then fail "agent '$name': $DEPLOYMENT lists no single agent account starting '$name.'"; continue; fi
  sends=$(jq --arg a "$name" '[.beats[] | select(.agent == $a)] | length' "$BEATS")
  if ! out=$(access_keys "$acct"); then fail "agent $acct: key list could not be read" "$(lasterr)"; continue; fi
  n=$(jq '.keys | length' <<<"$out")
  if [[ $n -ne 1 ]]; then fail "agent $acct holds $n keys; it must hold exactly one" "$(jq -c '[.keys[].public_key]' <<<"$out")"; continue; fi
  key=$(jq -c '.keys[0]' <<<"$out")
  problems=() allow_note=
  jq -e '.access_key.permission | type == "object" and has("FunctionCall")' <<<"$key" >/dev/null || problems+=("the key is not a function-call key (it is $(jq -c '.access_key.permission' <<<"$key" | cut -c1-60))")
  fc=$(jq -c '.access_key.permission.FunctionCall? // empty' <<<"$key")
  if [[ -n $fc ]]; then
    jq -e --arg w "$WALLET" '.receiver_id == $w' <<<"$fc" >/dev/null || problems+=("receiver is $(jq -r .receiver_id <<<"$fc"), not the wallet $WALLET")
    jq -e '.method_names == ["spend"]' <<<"$fc" >/dev/null || problems+=("methods are $(jq -c .method_names <<<"$fc"), not [\"spend\"] only")
    allow=$(jq -r '.allowance // empty' <<<"$fc")
    if [[ -z $allow ]]; then problems+=("the key has no allowance cap (null), grant-agent-key.sh always sets one")
    elif ! digits "$allow"; then problems+=("allowance '$allow' is not a usable number")
    elif [[ -z $GAS_PRICE ]]; then problems+=("gas price could not be read, so the allowance cannot be judged")
    else
      per_send=$(awk -v g="$GAS_PRICE" -v t="$SEND_GAS_TGAS" 'BEGIN { printf "%.0f", g * t * 1e12 }')
      covers=$(awk -v a="$allow" -v p="$per_send" 'BEGIN { printf "%d", a / p }')
      need=$((sends * SENDS_COVERED))
      [[ $covers -ge $need ]] || problems+=("allowance $(toyocto_near "$allow") NEAR pays for $covers sends at ${SEND_GAS_TGAS} TGas; ${sends} scripted sends x ${SENDS_COVERED} needs $need")
      allow_note="allowance $(toyocto_near "$allow") NEAR = $covers sends at ${SEND_GAS_TGAS} TGas (script needs $sends, with room for $((SENDS_COVERED - 1)) rehearsals)"
    fi
  fi
  if [[ ${#problems[@]} -eq 0 ]]; then pass "agent $acct holds exactly one key: function-call, receiver the wallet, [\"spend\"] only; $allow_note"
  else fail "agent $acct key is wrong" "${problems[@]}"; fi
done

# ---- 3. the rule, and what is left of it, beat by beat --------------------------------------

# The rule the beats assume (scripts/demo-rule.sh, the same one reset-demo.sh applies).
want_rule=$(LEASH_DEPLOYMENT=$DEPLOYMENT LEASH_BEATS=$BEATS AGENT_VENDORS=$VENDORS scripts/demo-rule.sh) \
  || die "could not build the scripted rule from $BEATS and $VENDORS"

if ! rec=$(view "$WALLET" node_record "{\"node\":\"$NODE\"}"); then
  fail "node record for $NODE could not be read" "$(lasterr)"
elif [[ $rec == null ]]; then
  fail "no rule is in force for $NODE" "run scripts/reset-demo.sh testnet (it costs one face scan)"
else
  spent=$(jq -r '.spent' <<<"$rec") limit=$(jq -r '.rule.period_limit' <<<"$rec")
  if ! exact "$spent" || ! exact "$limit"; then
    fail "spent/limit are not usable numbers (spent '$spent', limit '$limit')"
  else
    have_rule=$(jq -c '.rule | .payees |= sort' <<<"$rec")
    diffs=$(jq -nr --argjson h "$have_rule" --argjson w "$want_rule" '[$w | to_entries[] | select($h[.key] != .value) | "\(.key): on chain \($h[.key] | tojson), scripted \(.value | tojson)"] | .[]')
    if [[ -z $diffs ]]; then pass "the rule on $NODE is the scripted rule (per-tx $(fmt "$(jq -r .rule.per_tx_limit <<<"$rec")"), period $(fmt "$limit"), payees $(jq -c '.payees | length' <<<"$have_rule"), not paused)"
    else fail "the rule on $NODE is not the scripted rule" "$diffs"; fi

    # is_paused is the account-wide switch, separate from the rule's own flag.
    if p=$(view "$WALLET" is_paused '{}'); then
      [[ $p == false ]] && pass "the account-wide pause is off" || fail "the account is paused (is_paused = $p); unpausing needs a passkey assertion"
    else fail "is_paused could not be read" "$(lasterr)"; fi

    # Replay the beats against what is on chain, in the contract's own check order (paused 2,
    # payee 4, per-tx 5, period 6) and say how many of each beat fit.
    now_ms=$(($(date +%s%N) / 1000000))
    began=$(jq -r '.window_began_ms // empty' <<<"$rec") period_ms=$(jq -r '.rule.period_ms // empty' <<<"$rec")
    if ! digits "$began" || ! digits "$period_ms"; then
      fail "the node record has no usable window (window_began_ms '$began', period_ms '$period_ms'), so the window cannot be judged" "$(jq -c . <<<"$rec" | cut -c1-200)"
    else
      left_ms=$((began + period_ms - now_ms))
      if [[ $left_ms -ge $MIN_WINDOW_LEFT_MS ]]; then pass "the budget window has $((left_ms / 60000)) minutes left, so it will not refill mid-recording"
      else fail "the budget window ends in $((left_ms / 60000)) minutes; it would refill (spent resets to 0) during a take" "run scripts/reset-demo.sh testnet to open a fresh window"; fi
    fi

    replay=$(jq -r --argjson r "$have_rule" --argjson spent "$spent" --arg admin "$ADMIN" --slurpfile v "$VENDORS" '
      ($v[0] | map({(.id): .account}) | add) as $by
      | reduce .beats[] as $b ({spent: $spent, out: []};
          ($b.payee | if . == "{admin}" then $admin else $by[.] end) as $to
          | ($b.amount | tonumber) as $amt
          | (if $r.paused then 2
             elif ($r.payees | index($to)) == null then 4
             elif $amt > ($r.per_tx_limit | tonumber) then 5
             elif (.spent + $amt) > ($r.period_limit | tonumber) then 6
             else 0 end) as $code
          | (if $code == 0 then "allowed" else "refused" end) as $got
          | .out += [{beat: $b.beat, agent: $b.agent, text: ($b.text | sub("{admin}"; $admin)), amount: $amt,
                      expect: $b.expect, ecode: ($b.code // 0), got: $got, code: $code, before: .spent,
                      ok: ($got == $b.expect and $code == ($b.code // 0))}]
          | if $code == 0 then .spent += $amt else . end)
      | .out[] | [.beat, .agent, .text, .amount, .expect, .ecode, .got, .code, .before, .ok] | @tsv' "$BEATS") || replay=
    if [[ -z $replay ]]; then fail "could not replay the beats against the rule on chain"
    else
      bad=()
      while IFS=$'\t' read -r beat agent text amount expect ecode got code before ok; do
        line="beat $beat  $agent  \"$text\"  expect $expect$(codetxt "$ecode")  would be $got$(codetxt "$code")  (spent $(fmt "$before") of $(fmt "$limit"))"
        [[ $ok == true ]] || bad+=("$line  <-- WRONG")
        note "$line"
      done <<<"$replay"
      if [[ ${#bad[@]} -eq 0 ]]; then
        summary=$(jq -r --argjson spent "$spent" '
          [.beats[] | select(.expect == "allowed")] | group_by(.beat)
          | map("beat \(.[0].beat): \(length) allowed payment(s) fit") | join("; ")' "$BEATS")
        total=$(jq '[.beats[] | select(.expect == "allowed") | .amount | tonumber] | add' "$BEATS")
        refusals=$(jq '[.beats[] | select(.expect == "refused")] | length' "$BEATS")
        pass "headroom left $(fmt $((limit - spent))) of $(fmt "$limit"); the script spends $(fmt "$total"); every beat comes out as scripted ($summary; $refusals refusals, which cost nothing)"
        note "full takes remaining on this budget before a reset: $((total > 0 ? (limit - spent) / total : 0)) (the script ends with the period exhausted, so the next take needs scripts/reset-demo.sh)"
      else fail "the beats would not come out as scripted" "${bad[@]}"; fi
    fi
  fi
fi

# ---- 4. the token balance --------------------------------------------------------------------

outflow=$(jq '[.beats[] | select(.expect == "allowed") | .amount | tonumber] | add' "$BEATS")
if ! dec=$(view "$TOKEN" ft_metadata '{}'); then
  fail "the token's decimals could not be read, so the beats' amounts cannot be trusted" "$(lasterr)"
elif [[ $(jq -r '.decimals // "missing"' <<<"$dec") != 6 ]]; then
  fail "the token has $(jq -r '.decimals // "no"' <<<"$dec") decimals; the beats are written in 6-decimal amounts"
else
  pass "the token has 6 decimals, as the beats' amounts assume"
fi
if bal=$(view "$TOKEN" ft_balance_of "{\"account_id\":\"$WALLET\"}"); then
  bal=$(jq -r . <<<"$bal")
  funded=$(jq -r '.funded_wallet_balance // empty' "$DEPLOYMENT")
  if ! exact "$bal"; then fail "the token balance '$bal' is not a usable number"
  elif [[ -n ${EXPECT_WALLET_BALANCE:-} ]]; then
    [[ $bal == "$EXPECT_WALLET_BALANCE" ]] && pass "wallet holds exactly the expected $(fmt "$bal") (EXPECT_WALLET_BALANCE)" \
      || fail "wallet holds $(fmt "$bal"), you said to expect $(fmt "$EXPECT_WALLET_BALANCE")"
  elif [[ $bal -lt $outflow ]]; then fail "wallet holds $(fmt "$bal") $TOKEN, the script pays out $(fmt "$outflow")" "fund it: ft_transfer from the admin (the wallet needs a storage_deposit on the token first)"
  elif [[ -n $funded && $bal -gt $funded ]]; then fail "wallet holds $(fmt "$bal"), MORE than the $(fmt "$funded") recorded as funded in $DEPLOYMENT" "something paid in that this deployment's record does not know about"
  elif [[ -z $funded ]]; then fail "$DEPLOYMENT has no funded_wallet_balance, so there is nothing to compare the balance with" "wallet holds $(fmt "$bal"); record what you funded it with"
  else pass "wallet holds $(fmt "$bal") of the $(fmt "$funded") it was funded with ($(fmt $((funded - bal))) paid out in earlier takes); the script needs $(fmt "$outflow")"; fi
else fail "the wallet's token balance could not be read" "$(lasterr)"; fi

# ---- 5. the agent processes ------------------------------------------------------------------

i=0
for name in $NAMES; do
  url=${AGENT_URL_LIST[$i]}; i=$((i + 1))
  acct=${AGENT_ACCOUNT[$name]:-}
  if ! out=$(curl -sS --max-time "$CURL_TIMEOUT" "$url/state" 2>&1); then
    fail "agent '$name' did not answer $url/state" "${out:0:160}" "start it: AGENT_NAME=$name AGENT_ACCOUNT=$acct PORT=${url##*:} node agent/loop.mjs"; continue
  fi
  if ! jq -e . >/dev/null 2>&1 <<<"$out"; then fail "agent '$name' at $url answered /state with something that is not JSON" "${out:0:120}"; continue; fi
  got=$(jq -r '.agentAddr // empty' <<<"$out")
  errs=$(jq -c '.chain.errors // ["no chain.errors field"]' <<<"$out")
  if [[ $got != "$acct" ]]; then fail "agent '$name' at $url is running as '${got:-nothing}', expected $acct"
  elif [[ $errs != "[]" ]]; then fail "agent '$name' at $url answers /state but its chain reads are failing" "$errs"
  else pass "agent '$name' ($acct) answers $url/state and its chain reads are healthy"; fi
done

# ---- 6. credentials --------------------------------------------------------------------------

if ids=$(view "$WALLET" credential_ids '{}'); then
  count=$(jq 'length' <<<"$ids")
  if [[ $count -ge 2 ]]; then pass "$count credentials are registered (a lost passkey does not freeze the funds)"
  else fail "only $count credential(s) registered; need at least 2" \
    "withdrawal is passkey-gated, the wallet is frozen, and a second credential can only be registered with a signature from one that already exists" \
    "so losing the only credential strands the funds forever: register a second one now (scripts/register-credential.sh)"; fi

  # ---- 7. the human gate -----------------------------------------------------------------------
  # The deployment file records what each registered credential is (`credentials: [{id, kind}]`,
  # or the older single `credential`). Without that record the software-credential check cannot
  # fire, so a missing record is itself a failure, as is a registered credential nobody recorded.
  records=$(jq -c '((.credentials // []) + (if .credential then [.credential] else [] end))' "$DEPLOYMENT")
  unrecorded=$(jq -nc --argjson ids "$ids" --argjson r "$records" '[$ids[] | select(. as $i | ($r | map(.id) | index($i)) == null)]')
  if [[ $(jq 'length' <<<"$records") -eq 0 ]]; then
    fail "HUMAN GATE: $DEPLOYMENT records no credentials, so the software-credential check cannot fire" \
      "add \"credentials\": [{\"id\": ..., \"kind\": \"DEVICE\" or \"SOFTWARE\"}, ...] for every credential registered on the wallet" \
      "registered ids: $(jq -c . <<<"$ids")"
  elif [[ $unrecorded != "[]" ]]; then
    fail "HUMAN GATE: credentials are registered that $DEPLOYMENT does not record, so nobody has said what they are" "unrecorded: $unrecorded"
  elif [[ -z ${REAL_DEVICE_CREDENTIAL_ID:-} ]]; then
    fail "HUMAN GATE: no real-device credential has been named" \
      "the contract cannot tell a phone's secure enclave from a script's key, so a person has to vouch" \
      "register the credential you made with tools/capture-assertion.html on a real device, use it once" \
      "(reset-demo.sh does), then re-run with REAL_DEVICE_CREDENTIAL_ID=<its id>" \
      "registered ids: $(jq -c . <<<"$ids")"
  elif ! jq -e --arg c "$REAL_DEVICE_CREDENTIAL_ID" 'index($c) != null' <<<"$ids" >/dev/null; then
    fail "HUMAN GATE: REAL_DEVICE_CREDENTIAL_ID is not registered on $WALLET" "named: $REAL_DEVICE_CREDENTIAL_ID" "registered: $(jq -c . <<<"$ids")"
  else
    kind=$(jq -r --arg c "$REAL_DEVICE_CREDENTIAL_ID" '.[] | select(.id == $c) | .kind // "unlabelled"' <<<"$records")
    if [[ $kind == *SOFTWARE* || $kind == unlabelled ]]; then
      fail "HUMAN GATE: the credential you named is recorded in $DEPLOYMENT as '$kind', not as a device" "that is a script's key (or an unlabelled one), not a device"
    elif ! nonce=$(view "$WALLET" credential_nonce "{\"credential_id\":\"$REAL_DEVICE_CREDENTIAL_ID\"}"); then
      fail "HUMAN GATE: the credential's nonce could not be read" "$(lasterr)"
    elif ! exact "$nonce" || [[ $nonce -lt 1 ]]; then
      fail "HUMAN GATE: the named credential has never produced an assertion the chain accepted (nonce '$nonce')" \
        "its first use is the set_rule in scripts/reset-demo.sh; run that with this credential's device"
    else
      pass "HUMAN GATE: credential $REAL_DEVICE_CREDENTIAL_ID is registered, recorded as '$kind', and has had $nonce assertion(s) verified on chain"
      note "the chain verified the signatures; that the device is real is YOUR claim (REAL_DEVICE_CREDENTIAL_ID). Did the face scan happen on a phone or laptop, not a script?"
    fi
  fi
else
  fail "credential list could not be read, so 'two credentials' and the human gate are NOT established" "$(lasterr)"
fi

printf '\n%d checks, %d failed\n' "$CHECKS" "$FAILS"
if [[ $FAILS -eq 0 ]]; then echo "READY to record."; exit 0; fi
echo "NOT ready. Fix the FAIL lines above."; exit 1
