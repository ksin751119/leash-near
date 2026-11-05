#!/usr/bin/env bash
# Delete every full-access key on the wallet account. After this the contract code can
# never change again, for anyone. IRREVERSIBLE.
# Usage: scripts/freeze.sh <wallet-account> [network]
# Must run after scripts/deploy.sh and after the agent function-call keys are added.
set -euo pipefail

WALLET=${1:?wallet account id}
NETWORK=${2:-testnet}

case "$NETWORK" in
  mainnet) RPC=https://rpc.mainnet.near.org ;;
  *) RPC=https://rpc.testnet.near.org ;;
esac

# Ask the RPC for the access key list; near-cli's table output is not stable to parse.
KEYS=$(curl -fsS "$RPC" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",
  \"params\":{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$WALLET\"}}" \
  | jq -r '.result.keys[] | select(.access_key.permission == "FullAccess") | .public_key')

if [ -z "$KEYS" ]; then
  echo "no full-access keys found on $WALLET"
else
  for PK in $KEYS; do
    echo "deleting full-access key $PK"
    near account delete-key "$WALLET" "$PK" \
      network-config "$NETWORK" sign-with-keychain send
  done
fi

echo "remaining keys:"
near account list-keys "$WALLET" network-config "$NETWORK" now
