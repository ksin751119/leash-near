#!/usr/bin/env bash
# Build a workspace member to wasm32 (release) and print the path to the wasm.
# Usage: scripts/build-contract.sh [package]   (default: leash-contract)
#
# Why this exists rather than a bare `cargo build`: the wasm must be compiled with
# `--cfg near`, or near-sdk falls back to pure-Rust environment calls and every panic message
# the contract produces is thrown away — see .cargo/config.toml for the full story.
#
# `.cargo/config.toml` sets the flag, but cargo ignores `rustflags` from config entirely
# whenever the RUSTFLAGS environment variable is set, even to the empty string. For
# `cargo test` that failure is loud, because the sandbox tests assert on rejection messages.
# On the deploy path it would be silent: a developer with RUSTFLAGS exported — `-D warnings`,
# a `-C target-cpu`, a CI default — would ship a frozen, non-upgradeable contract that refuses
# every operation without saying why, and nothing would warn them.
#
# So the flag is set here explicitly, appended to whatever RUSTFLAGS already holds, and the
# result is checked before anyone gets a path back.
set -euo pipefail

PACKAGE=${1:-leash-contract}
cd "$(dirname "$0")/.."

RUSTFLAGS="${RUSTFLAGS:-} --cfg near" \
  cargo build --release --target wasm32-unknown-unknown -p "$PACKAGE"

WASM="target/wasm32-unknown-unknown/release/${PACKAGE//-/_}.wasm"
[[ -f $WASM ]] || { echo "build-contract.sh: $WASM was not produced" >&2; exit 1; }

# The flag is load-bearing, so prove it reached the compiler rather than trusting that it
# did. With `--cfg near`, `env::panic_str` calls the host function `panic_utf8`, which appears
# in the wasm's import section. Without it, the same code compiles to a pure-Rust `panic!()`
# that aborts, the import is absent, and refusal reasons never reach the chain.
if ! grep -qa 'panic_utf8' "$WASM"; then
  cat >&2 <<'MSG'
build-contract.sh: the wasm does not import `panic_utf8`, so it was built WITHOUT `--cfg near`
and would discard every panic message on chain. Refusing to hand over this build.

Most likely cause: a RUSTFLAGS value that this script could not extend, or a near-sdk upgrade
that changed how the host calls are gated. See .cargo/config.toml.
MSG
  exit 1
fi

echo "$WASM"
