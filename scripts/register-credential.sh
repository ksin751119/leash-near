#!/usr/bin/env bash
# Register a passkey credential on the wallet.
# Usage: scripts/register-credential.sh <testnet|mainnet> <credential.json> [assertions-dir]
# Env:   CREDENTIAL_ID  the ALREADY-REGISTERED credential that signs (needed when two or more exist)
#        WAIT_TIMEOUT   seconds to wait for the face scan (default 900)
#        LEASH_DEPLOYMENT (default deployments/testnet.json)
# credential.json: {"id": "<base64>", "pubkey_sec1": "<base64>"}; the JSON saved by
# tools/capture-assertion.html (`credential_id`, `pubkey_sec1`) works as it is.
#
# # Who may register, and why this takes two steps
#
# The contract cannot tell a secure enclave from a script's key, so the passkey gate is only as
# strong as who may add a credential.
#   - The FIRST credential ever is registered by the admin alone. That is the bootstrap, the one
#     act of trust in the design: whoever holds the admin key at that moment chooses the key the
#     gate trusts. Do it on a machine you trust, with the device you mean to use.
#   - EVERY LATER one needs the admin AND a signature from a credential that is already
#     registered, over this exact new key. A stolen admin key therefore cannot add its own.
# Removing a credential is ungated (tightening), so losing every credential strands the funds:
# register a second one early.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "register-credential.sh: $*" >&2; exit 1; }

[[ $# -ge 2 && $# -le 3 ]] || die "usage: register-credential.sh <testnet|mainnet> <credential.json> [assertions-dir]"
NETWORK=$1 CRED_FILE=$2 DIR=${3:-.assertions}
TIMEOUT=${WAIT_TIMEOUT:-900}
DEPLOYMENT=${LEASH_DEPLOYMENT:-deployments/testnet.json}
case "$NETWORK" in testnet | mainnet) ;; *) die "unknown network '$NETWORK' (expected testnet or mainnet)" ;; esac
command -v jq >/dev/null || die "jq is required"
command -v near >/dev/null || die "near-cli is required"
[[ $TIMEOUT =~ ^[0-9]+$ ]] || die "WAIT_TIMEOUT must be a whole number of seconds, got '$TIMEOUT'"
[[ -r $CRED_FILE ]] || die "cannot read $CRED_FILE"
WALLET=$(jq -er .wallet "$DEPLOYMENT") || die "$DEPLOYMENT has no wallet"
ADMIN=$(jq -er .admin "$DEPLOYMENT") || die "$DEPLOYMENT has no admin"
CRED=$(jq -ce '{id: (.id // .credential_id), pubkey_sec1: .pubkey_sec1} | select(.id != null and .pubkey_sec1 != null)' "$CRED_FILE") \
  || die "$CRED_FILE has no id (or credential_id) and pubkey_sec1"
[[ -n $CRED ]] || die "$CRED_FILE has no id (or credential_id) and pubkey_sec1"
NEWID=$(jq -r .id <<<"$CRED")
mkdir -p "$DIR"

view() { # <method> <json-args>
  local out
  out=$(near contract call-function as-read-only "$WALLET" "$1" json-args "$2" network-config "$NETWORK" now) \
    || die "view $1 on $WALLET failed (output above)"
  printf '%s\n' "$out"
}
call() { # <json-args>
  near contract call-function as-transaction "$WALLET" register_credential json-args "$1" \
    prepaid-gas '100 Tgas' attached-deposit '0 NEAR' sign-as "$ADMIN" network-config "$NETWORK" sign-with-keychain send
}

ids=$(view credential_ids '{}')
count=$(jq 'length' <<<"$ids") || die "credential_ids returned something that is not a list: $ids"
jq -e --arg c "$NEWID" 'index($c) == null' <<<"$ids" >/dev/null || die "$NEWID is already registered"

if [[ $count -eq 0 ]]; then
  echo "No credential exists yet, so this is the BOOTSTRAP: the admin ($ADMIN) registers it alone."
  echo "Whoever holds the admin key now decides which key the passkey gate trusts."
  call "$(jq -nc --argjson c "$CRED" '{cred:$c}')" || die "register_credential failed (output above)"
else
  if [[ -n ${CREDENTIAL_ID:-} ]]; then
    jq -e --arg c "$CREDENTIAL_ID" 'index($c) != null' <<<"$ids" >/dev/null || die "CREDENTIAL_ID $CREDENTIAL_ID is not registered; registered: $(jq -c . <<<"$ids")"
    signer=$CREDENTIAL_ID
  elif [[ $count -eq 1 ]]; then
    signer=$(jq -r '.[0]' <<<"$ids")
  else
    die "$count credentials are registered: set CREDENTIAL_ID to the one whose device will sign. Registered: $(jq -c . <<<"$ids")"
  fi
  file="$DIR/register.json"
  if [[ -e $file ]]; then mv -f "$file" "$file.stale"; echo "moved an existing $file aside to $file.stale"; fi
  challenge=$(view challenge_for_register "$(jq -nc --argjson c "$CRED" --arg s "$signer" '{cred:$c, credential_id:$s}')" | jq -r .) \
    || die "challenge_for_register returned something that is not JSON"
  [[ -n $challenge && $challenge != null ]] || die "challenge_for_register returned no challenge"
  want=$(printf '%s' "$challenge" | tr -d '=')
  echo "A credential already exists, so the admin key alone cannot add another: $signer must sign this registration."
  echo "  registering: $NEWID"
  echo "  challenge:   $challenge"
  echo "  1. open tools/capture-assertion.html on the device that holds $signer"
  echo "  2. paste the challenge, press Sign, unlock, then press \"Send to the waiting script\""
  echo "     (Send needs: node tools/assertion-relay.mjs $DIR register), or save the JSON as: $file"
  waited=0
  while true; do
    if [[ -s $file ]] && jq -e . "$file" >/dev/null 2>&1; then
      got=$(jq -r '.client_data_json | fromjson | .challenge' "$file" 2>/dev/null | tr '_-' '/+' | tr -d '=' || true)
      [[ $got == "$want" ]] && break
      mv -f "$file" "$file.wrong"
      echo "  $file signed a different challenge (moved to $file.wrong). Sign the challenge above." >&2
    fi
    ((waited < TIMEOUT)) || die "gave up after ${TIMEOUT}s waiting for the signature over: $challenge. Nothing was changed."
    if ((waited > 0 && waited % 10 == 0)); then echo "  still waiting for the signature from $signer: ${waited}s of ${TIMEOUT}s"; fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "  got a valid assertion after ${waited}s; registering"
  args=$(jq -nc --argjson c "$CRED" --slurpfile a "$file" '{cred:$c, assertion:($a[0] | {credential_id, authenticator_data, client_data_json, signature_der})}')
  if ! call "$args"; then
    mv -f "$file" "$file.failed"
    die "register_credential failed (output above); the assertion was moved to $file.failed and will not be reused"
  fi
  mv -f "$file" "$file.used"
fi

ids=$(view credential_ids '{}')
jq -e --arg c "$NEWID" 'index($c) != null' <<<"$ids" >/dev/null || die "the credential is NOT registered after the call: $(jq -c . <<<"$ids")"
echo "registered $NEWID; the wallet now has $(jq 'length' <<<"$ids") credential(s)"
