#!/usr/bin/env bash
# Give an agent its key on the wallet account: a function-call access key that can call
# `spend` on the wallet and nothing else.
# Usage: scripts/grant-agent-key.sh <wallet-account> <agent-public-key> <testnet|mainnet> [allowance]
#
# The agent generates its own keypair and hands over only the PUBLIC key (`ed25519:...`), so
# no secret passes through this script or its logs.
#
# **Run this BEFORE scripts/freeze.sh.** Adding a key needs a full-access key on the wallet,
# and freezing deletes them all; the contract has no add_key. After the freeze, a new agent
# key can never be granted.
#
# What the key can do is enforced by the NEAR protocol, not by this contract:
#   receiver_id  = the wallet   -> it cannot call the token contract, or any other account
#   method_names = ["spend"]    -> it cannot call set_rule, withdraw, add_payee, ...
#   allowance    = small        -> gas it may burn is capped (default 0.25 NEAR)
#   function-call keys cannot attach a deposit, add keys, deploy, or transfer NEAR
# The sandbox tests (tests-sandbox/tests/sandbox/keys.rs) show each refusal.
set -euo pipefail

WALLET=${1:?usage: grant-agent-key.sh <wallet-account> <agent-public-key> <testnet|mainnet> [allowance]}
PUBKEY=${2:?agent public key, e.g. ed25519:...}
NETWORK=${3:?testnet or mainnet}
ALLOWANCE=${4:-0.25 NEAR}

case "$NETWORK" in
  mainnet) RPC=https://rpc.mainnet.near.org ;;
  testnet) RPC=https://rpc.testnet.near.org ;;
  *) echo "unknown network '$NETWORK' (expected testnet or mainnet)" >&2; exit 2 ;;
esac

# A secret key pasted by mistake must not travel further.
[[ $PUBKEY == ed25519:* ]] || { echo "grant-agent-key.sh: expected an ed25519:... public key" >&2; exit 2; }
if [[ $PUBKEY == *secret* ]]; then echo "that looks like a secret key; pass the public key" >&2; exit 2; fi

near account add-key "$WALLET" grant-function-call-access \
  --allowance "$ALLOWANCE" \
  --contract-account-id "$WALLET" \
  --function-names spend \
  use-manually-provided-public-key "$PUBKEY" \
  network-config "$NETWORK" sign-with-keychain send

# Read it back from the RPC rather than trusting the command: there is no contract view for
# access keys, so the chain's own list is the only evidence.
got=$(curl -fsS "$RPC" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",
  \"params\":{\"request_type\":\"view_access_key\",\"finality\":\"final\",
              \"account_id\":\"$WALLET\",\"public_key\":\"$PUBKEY\"}}" \
  | jq -c '.result.permission.FunctionCall')
echo "on chain: $got"
jq -e --arg w "$WALLET" '.receiver_id == $w and .method_names == ["spend"]' <<<"$got" >/dev/null \
  || { echo "grant-agent-key.sh: the key on chain is NOT restricted as intended" >&2; exit 1; }
