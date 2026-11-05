#!/usr/bin/env bash
# Deploy the Leash wallet contract to a fresh account and initialise it.
# Usage: scripts/deploy.sh <wallet-account> <admin-account> <token-account> [network]
# The wallet account must already exist and its full-access key must be in the local
# near-cli keychain. Run scripts/freeze.sh afterwards to delete that key.
set -euo pipefail

WALLET=${1:?wallet account id}
ADMIN=${2:?admin account id}
TOKEN=${3:?token contract id}
NETWORK=${4:-testnet}

# The admin must be a different account from the wallet, and this is a security requirement,
# not a convention. Every gated method is guarded by comparing the predecessor against the
# stored admin, and the agent's function-call keys live on the wallet account — so calls made
# with one arrive with the predecessor set to the wallet. An admin equal to the wallet would
# let an agent key satisfy every admin check: no gate, no passkey, an agent setting its own
# rules.
#
# The contract refuses this in `new` as well. It is checked here so the failure arrives before
# anything is deployed, rather than as a failed init call on an account that now holds code.
if [[ $ADMIN == "$WALLET" ]]; then
  cat >&2 <<MSG
deploy.sh: admin and wallet must be different accounts (both are "$WALLET").

The agent's function-call keys live on the wallet account, so an admin equal to it would let
an agent key pass every admin check in the contract — the passkey gate included. Use a
separate account you control for the admin. The contract refuses this too; stopping here just
saves you a deploy.
MSG
  exit 1
fi

cd "$(dirname "$0")/.."
# Not a bare `cargo build`: the wasm has to carry `--cfg near` or the deployed contract
# throws away every refusal reason, and `.cargo/config.toml` alone does not survive a
# RUSTFLAGS in the environment. build-contract.sh sets the flag itself and refuses to return
# a wasm that does not carry it.
WASM=$(scripts/build-contract.sh leash-contract)

near contract deploy "$WALLET" use-file "$WASM" \
  with-init-call new json-args "{\"admin\":\"$ADMIN\",\"token\":\"$TOKEN\"}" \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  network-config "$NETWORK" sign-with-keychain send
