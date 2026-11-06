#!/usr/bin/env bash
# Delete every full-access key on the wallet account. After this the contract code can
# never change again, for anyone, and nobody can add a key to the wallet. IRREVERSIBLE.
# The agents' keys are not on the wallet (see grant-agent-key.sh: a key on the wallet signs AS
# the wallet, and `spend` would not know which agent is calling), so freezing leaves the wallet
# with no keys at all and does not interact with granting them.
# Usage: scripts/freeze.sh <wallet-account> <testnet|mainnet> --yes-i-mean-it
set -euo pipefail

WALLET=${1:?usage: freeze.sh <wallet-account> <testnet|mainnet> --yes-i-mean-it}
NETWORK=${2:?usage: freeze.sh <wallet-account> <testnet|mainnet> --yes-i-mean-it}
CONFIRM=${3:-}

case "$NETWORK" in
  mainnet) RPC=https://rpc.mainnet.near.org ;;
  testnet) RPC=https://rpc.testnet.near.org ;;
  *) echo "unknown network '$NETWORK' (expected testnet or mainnet)" >&2; exit 2 ;;
esac

if [ "$CONFIRM" != "--yes-i-mean-it" ]; then
  echo "refusing to run: this deletes every full-access key on $WALLET and cannot be undone." >&2
  echo "re-run with --yes-i-mean-it as the third argument." >&2
  exit 2
fi

# Ask the RPC for the access key list; near-cli's table output is not stable to parse.
list_keys() {
  curl -fsS "$RPC" -H 'content-type: application/json' -d "{
    \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",
    \"params\":{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$WALLET\"}}" \
    | jq -e '.result.keys'
}

full_access_keys() { jq -r '.[] | select(.access_key.permission == "FullAccess") | .public_key'; }
function_call_count() { jq '[.[] | select(.access_key.permission | type == "object" and has("FunctionCall"))] | length'; }

BEFORE=$(list_keys) || { echo "could not read the key list for $WALLET from $RPC" >&2; exit 1; }

for PK in $(echo "$BEFORE" | full_access_keys); do
  echo "deleting full-access key $PK"
  near account delete-keys "$WALLET" public-keys "$PK" \
    network-config "$NETWORK" sign-with-keychain send
done

# Verify against a fresh query; a filter that stopped matching must not look like success.
AFTER=$(list_keys) || { echo "could not re-read the key list for $WALLET" >&2; exit 1; }
REMAINING=$(echo "$AFTER" | full_access_keys)
if [ -n "$REMAINING" ]; then
  echo "FREEZE FAILED: full-access keys still on $WALLET:" >&2
  echo "$REMAINING" >&2
  exit 1
fi

echo "frozen: $WALLET has no full-access key and $(echo "$AFTER" | function_call_count) function-call key(s)"
