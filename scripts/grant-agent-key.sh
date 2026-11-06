#!/usr/bin/env bash
# Give an agent its key: a function-call access key ON THE AGENT'S OWN ACCOUNT, with the wallet
# as its receiver and `spend` as its only method.
# Usage: scripts/grant-agent-key.sh <wallet-account> <agent-account> <agent-public-key> <testnet|mainnet> [allowance-in-NEAR]
#
# The key lives on the agent account, not on the wallet. `spend` identifies the caller by
# `predecessor_id` and derives the budget node from it (`pay.ops.x` -> `ops.x`). A key added to
# the WALLET signs as the wallet, so the contract would see the wallet as the caller, find no
# node, and refuse every payment with code 1 ("no rule for this agent's node"). Verified on
# testnet: that is the only answer such a key can ever get. A key on the agent account signs as
# the agent, and the transaction's receiver (the wallet) is what the key is restricted to.
#
# The agent generates its own keypair and hands over only the PUBLIC key (`ed25519:...`), so
# no secret passes through this script or its logs. A 64-byte secret key is refused.
#
# The agent account must already exist (only its parent can create it) and its full-access key
# must be in the near-cli keychain: that key signs the grant. Afterwards the script DELETES the
# agent account's full-access keys, leaving the restricted key as the only way in, because an
# agent that still holds a full-access key can do anything with its account. That makes the
# account's own NEAR balance (it pays the gas) unrecoverable; set KEEP_FULL_ACCESS=1 to skip the
# deletion. This has nothing to do with scripts/freeze.sh and may run before or after it.
#
# What the key can do is enforced by the NEAR protocol, not by this contract:
#   receiver_id  = the wallet   -> it cannot call the token contract, or any other account
#   method_names = ["spend"]    -> it cannot call set_rule, withdraw, add_payee, ...
#   allowance    = small        -> gas it may burn is capped (default 0.25 NEAR)
#   function-call keys cannot attach a deposit, add keys, deploy, or transfer NEAR
# `spend` needs about 60 TGas attached: it reserves 35 TGas for its two promises up front, and
# 30 TGas fails with "Exceeded the prepaid gas".
# The sandbox tests (tests-sandbox/tests/sandbox/keys.rs) show each refusal.
set -euo pipefail

die() { echo "grant-agent-key.sh: $*" >&2; exit 1; }

[[ $# -ge 4 && $# -le 5 ]] || die "usage: grant-agent-key.sh <wallet-account> <agent-account> <agent-public-key> <testnet|mainnet> [allowance-in-NEAR]"
WALLET=$1 AGENT=$2 PUBKEY=$3 NETWORK=$4 ALLOWANCE=${5:-0.25}

case "$NETWORK" in
  mainnet) RPC=https://rpc.mainnet.near.org ;;
  testnet) RPC=https://rpc.testnet.near.org ;;
  *) die "unknown network '$NETWORK' (expected testnet or mainnet)" ;;
esac
[[ $ALLOWANCE =~ ^[0-9]+(\.[0-9]{1,24})?$ ]] || die "allowance must be a number of NEAR, e.g. 0.25"
command -v jq >/dev/null && command -v node >/dev/null || die "jq and node are required"

# A NEAR ed25519 public key is 32 bytes; a secret key is 64 (and also starts "ed25519:", so the
# prefix proves nothing). Decode the base58 and count.
[[ $PUBKEY == ed25519:* ]] || die "expected an ed25519:... public key"
len=$(node -e '
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const c of process.argv[1]) { const d = A.indexOf(c); if (d < 0) { console.log(-1); process.exit(); } n = n * 58n + BigInt(d); }
  let bytes = 0; while (n > 0n) { n >>= 8n; bytes++; }
  for (const c of process.argv[1]) { if (c === "1") bytes++; else break; }
  console.log(bytes);' "${PUBKEY#ed25519:}")
case "$len" in
  32) ;;
  64) die "that is a 64-byte value: a SECRET key. Pass the public key; do not paste secrets." ;;
  -1) die "not valid base58" ;;
  *) die "decodes to $len bytes, not 32: not an ed25519 public key" ;;
esac

rpc() { # <params-json> -> prints .result, fails on an RPC error
  curl -fsS "$RPC" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":$1}" \
    | jq -e 'if .error then error(.error | tostring) else .result end'
}

# Granting needs a full-access key on the agent account. Say so before near-cli fails with
# something cryptic.
keys=$(rpc "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$AGENT\"}" \
  | jq -c '.keys') || die "could not read $AGENT's access keys from $RPC (does the account exist?)"
full=$(jq '[.[] | select(.access_key.permission == "FullAccess")] | length' <<<"$keys")
[[ $full -gt 0 ]] || die "$AGENT has no full-access key, so nothing can sign the grant (an agent account whose full-access keys are already deleted cannot be given another key)."

near account add-key "$AGENT" grant-function-call-access \
  --allowance "$ALLOWANCE NEAR" \
  --contract-account-id "$WALLET" \
  --function-names spend \
  use-manually-provided-public-key "$PUBKEY" \
  network-config "$NETWORK" sign-with-keychain send

# Read it back from the RPC rather than trusting the command: there is no contract view for
# access keys, so the chain's own record is the only evidence.
got=$(rpc "{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$AGENT\",\"public_key\":\"$PUBKEY\"}" \
  | jq -c '.permission.FunctionCall') || die "the key is not on chain after the grant"
echo "on chain: $got"
want_yocto=$(node -e '
  const [w, f = ""] = process.argv[1].split(".");
  console.log((BigInt(w) * 10n ** 24n + BigInt((f + "0".repeat(24)).slice(0, 24))).toString());' "$ALLOWANCE")
jq -e --arg w "$WALLET" --arg a "$want_yocto" \
  '.receiver_id == $w and .method_names == ["spend"] and .allowance == $a' <<<"$got" >/dev/null \
  || die "the key on chain is NOT restricted as intended (wanted receiver $WALLET, methods [spend], allowance $want_yocto yocto)"

if [[ -z ${KEEP_FULL_ACCESS:-} ]]; then
  for PK in $(rpc "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$AGENT\"}" \
    | jq -r '.keys[] | select(.access_key.permission == "FullAccess") | .public_key'); do
    echo "deleting full-access key $PK from $AGENT"
    near account delete-keys "$AGENT" public-keys "$PK" network-config "$NETWORK" sign-with-keychain send
  done
  left=$(rpc "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$AGENT\"}" \
    | jq -c '[.keys[] | .public_key]')
  [[ $left == "[\"$PUBKEY\"]" ]] || die "$AGENT should hold only $PUBKEY but holds $left"
  echo "$AGENT holds only the restricted key"
fi
