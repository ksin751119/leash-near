#!/usr/bin/env bash
# Give an agent its key on the wallet account: a function-call access key that can call
# `spend` on the wallet and nothing else.
# Usage: scripts/grant-agent-key.sh <wallet-account> <agent-public-key> <testnet|mainnet> [allowance-in-NEAR]
#
# The agent generates its own keypair and hands over only the PUBLIC key (`ed25519:...`), so
# no secret passes through this script or its logs. A 64-byte secret key is refused.
#
# **Run this BEFORE scripts/freeze.sh.** Adding a key needs a full-access key on the wallet,
# and freezing deletes them all; the contract has no add_key, so a missing agent key can never
# be granted afterwards. The script checks and refuses on a frozen wallet.
#
# What the key can do is enforced by the NEAR protocol, not by this contract:
#   receiver_id  = the wallet   -> it cannot call the token contract, or any other account
#   method_names = ["spend"]    -> it cannot call set_rule, withdraw, add_payee, ...
#   allowance    = small        -> gas it may burn is capped (default 0.25 NEAR)
#   function-call keys cannot attach a deposit, add keys, deploy, or transfer NEAR
# The sandbox tests (tests-sandbox/tests/sandbox/keys.rs) show each refusal.
set -euo pipefail

die() { echo "grant-agent-key.sh: $*" >&2; exit 1; }

[[ $# -ge 3 && $# -le 4 ]] || die "usage: grant-agent-key.sh <wallet-account> <agent-public-key> <testnet|mainnet> [allowance-in-NEAR]"
WALLET=$1 PUBKEY=$2 NETWORK=$3 ALLOWANCE=${4:-0.25}

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

# Granting needs a full-access key on the wallet. If there are none, it is frozen, and no key
# can ever be added: say so before near-cli fails with something cryptic.
full=$(rpc "{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$WALLET\"}" \
  | jq '[.keys[] | select(.access_key.permission == "FullAccess")] | length') \
  || die "could not read $WALLET's access keys from $RPC"
[[ $full -gt 0 ]] || die "wallet already frozen — grant agent keys before freezing. $WALLET has no full-access key left, so no key can be added to it, by anyone, ever."

near account add-key "$WALLET" grant-function-call-access \
  --allowance "$ALLOWANCE NEAR" \
  --contract-account-id "$WALLET" \
  --function-names spend \
  use-manually-provided-public-key "$PUBKEY" \
  network-config "$NETWORK" sign-with-keychain send

# Read it back from the RPC rather than trusting the command: there is no contract view for
# access keys, so the chain's own record is the only evidence.
got=$(rpc "{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$WALLET\",\"public_key\":\"$PUBKEY\"}" \
  | jq -c '.permission.FunctionCall') || die "the key is not on chain after the grant"
echo "on chain: $got"
want_yocto=$(node -e '
  const [w, f = ""] = process.argv[1].split(".");
  console.log((BigInt(w) * 10n ** 24n + BigInt((f + "0".repeat(24)).slice(0, 24))).toString());' "$ALLOWANCE")
jq -e --arg w "$WALLET" --arg a "$want_yocto" \
  '.receiver_id == $w and .method_names == ["spend"] and .allowance == $a' <<<"$got" >/dev/null \
  || die "the key on chain is NOT restricted as intended (wanted receiver $WALLET, methods [spend], allowance $want_yocto yocto)"
