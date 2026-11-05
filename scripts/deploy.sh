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
