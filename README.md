# Leash

A NEAR wallet account that holds money, gives AI agents a key that can only call `spend`, and refuses any payment that breaks a rule the agents cannot reach.

## Passkeys on chain

Tightening a spending rule is free and immediate. Loosening one requires a signature from a registered credential: in the intended flow somebody unlocks their phone with Face ID, a fingerprint or the device PIN, the device signs, and the **contract** checks that signature. No server, no oracle, no bridge.

### What that check proves, exactly

A passing check establishes two things and no more: that the holder of a registered credential signed **this exact challenge**, and that the authenticator asserted **user verification** (the UV bit) at the moment of signing.

It **cannot** establish that the credential is hardware-backed rather than a software P-256 key. WebAuthn attestation is absent for synced passkeys — iCloud Keychain and Google Password Manager attest `none` — so the contract has no way to tell a secure enclave from a key minted in a script.

**The guarantee is therefore only as strong as the registration step: whoever registers a credential vouches that it is a real authenticator.** Given a credential that genuinely is one, a passing check means a human was present at that device and unlocked it — and even then not a *unique* human, since anyone enrolled on that device satisfies it. Neither half of that may be quoted without the other.

NEAR has host functions for ed25519 and secp256k1 but not for P-256, the curve WebAuthn signs with, so the curve arithmetic runs inside the wasm. That is the one part of this design that could have failed outright, so it was built first and measured:

**A WebAuthn assertion verifies on chain in 33.5 TGas** (33,455,534,471,332 gas) — about 11% of the 300 TGas a transaction gets. Measured by `verifying_a_real_assertion_fits_in_gas` in `tests-sandbox/tests/sandbox/widen_requires_passkey.rs`, which calls the contract's `probe_verify` in a NEAR sandbox and prints the figure. `probe_verify` runs the verification and nothing else, so this is the cost of the signature check on its own; Task 5 measures the whole `set_rule` path.

The fixtures under `tests-sandbox/tests/fixtures/` are generated rather than browser-captured, so the tests run headless:

```bash
node tools/make-fixtures.mjs     # deterministic: re-running it leaves git clean
```

`tools/capture-assertion.html` does the same from a real phone and prints the same JSON shape, so a real capture is a drop-in replacement for a generated fixture. It needs HTTPS or `localhost`.

## Build

```bash
cargo build --release --target wasm32-unknown-unknown -p leash-contract
cargo build --release --target wasm32-unknown-unknown -p test-token
```

## Test

`cargo test` runs every unit and sandbox test in the workspace. Sandbox tests build the contracts from source and download the NEAR sandbox binary on first run. The sandbox tests live in `tests-sandbox/`.

```bash
cargo test
cargo test --test account_is_frozen
cargo test --test test_token
cargo test --test widen_requires_passkey -- --nocapture   # prints the gas figure
```
