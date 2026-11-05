# Leash

A NEAR wallet account that holds money, gives AI agents a key that can only call `spend`, and refuses any payment that breaks a rule the agents cannot reach.

## Build

```bash
cargo build --release --target wasm32-unknown-unknown -p leash-contract
cargo build --release --target wasm32-unknown-unknown -p test-token
```

## Test

Sandbox tests build the contracts from source and download the NEAR sandbox binary on first run.

```bash
cargo test --test account_is_frozen
cargo test --test test_token
```
