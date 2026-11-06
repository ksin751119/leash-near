# Leash

A NEAR wallet account that holds money, gives AI agents a key that can only call `spend`, and refuses any payment that breaks a rule the agents cannot reach.

## Passkeys on chain

Tightening a spending rule is free and immediate. Loosening one requires a signature from a registered credential: in the intended flow somebody unlocks their phone with Face ID, a fingerprint or the device PIN, the device signs, and the **contract** checks that signature. No server, no oracle, no bridge.

### What that check proves, exactly

A passing check establishes two things and no more: that the holder of a registered credential signed **this exact challenge**, and that the authenticator asserted **user verification** (the UV bit) at the moment of signing.

It **cannot** establish that the credential is hardware-backed rather than a software P-256 key. WebAuthn attestation is absent for synced passkeys — iCloud Keychain and Google Password Manager attest `none` — so the contract has no way to tell a secure enclave from a key minted in a script.

**The guarantee is therefore only as strong as the registration step: whoever registers a credential vouches that it is a real authenticator.** Given a credential that genuinely is one, a passing check means a human was present at that device and unlocked it — and even then not a *unique* human, since anyone enrolled on that device satisfies it. Neither half of that may be quoted without the other.

NEAR has host functions for ed25519 and secp256k1 but not for P-256, the curve WebAuthn signs with, so the curve arithmetic runs inside the wasm. That is the one part of this design that could have failed outright, so it was built first and measured:

**A WebAuthn assertion verifies on chain in 33.8 TGas** — about 11% of the 300 TGas a transaction gets. Measured by `verifying_a_real_assertion_fits_in_gas` in `tests-sandbox/tests/sandbox/widen_requires_passkey.rs`, which calls the contract's `probe_verify` in a NEAR sandbox and prints the figure. `probe_verify` runs the verification and nothing else, so this is the cost of the signature check on its own.

A whole `set_rule` costs three different amounts depending on what it does, and one number for all three would hide which part is expensive:

| `set_rule` | Gas | What it pays for |
| --- | --- | --- |
| widening, and it introduces a payee | 39.1 TGas | the gate, plus a `storage_deposit` on the token and the callback that commits the rule |
| widening, no new payee | 34.5 TGas | the gate alone, committed in the same receipt |
| tightening | 2.3 TGas | no gate at all — the emergency brake |

So the passkey gate costs about 32.1 TGas and registering one payee about 4.6 TGas. Measured by `a_widening_set_rule_fits_in_gas` in `tests-sandbox/tests/sandbox/rules.rs`.

The payment path is far cheaper, because no signature is checked on it:

| `spend` | Gas | What it pays for |
| --- | --- | --- |
| allowed | 7.9 TGas | the seven checks, the reservation, `ft_transfer` on the token, and the callback that settles it |
| refused | 2.7 TGas | the seven checks and one ring-buffer write — no cross-contract call at all |

Measured by `a_payment_fits_in_gas` in `tests-sandbox/tests/sandbox/spend.rs`. Neither promise is given the caller's leftover gas (`with_unused_gas_weight(0)`), so the token contract is never handed the ~200 TGas an agent's `max_gas` call has spare. A refused payment is a *successful* transaction: the contract records the decision, emits an event and returns `{"status":"refused","code":4,"reason":"payee is not on the allow-list"}` rather than panicking, because a panic would roll back the record and leave nothing on chain to say why. Each of the seven codes has a test asserting all three things at once — the transaction succeeded, no balance moved, and the recorded decision names the code.

The decision log is two bounded rings, not one. `spend` is open to any caller on NEAR — the rule for the node derived from the caller's id is the whole of the authorisation, and a caller with no rule is answered with code 1 rather than turned away — so anyone can write to the log, and twenty calls from one stranger would evict every real decision from a single twenty-slot ring. Refusals of callers with no rule therefore go in their own four-slot ring: strangers can only evict strangers, code 1 stays visible, and `stranger_count()` is where a flood shows up. `strangers_cannot_evict_a_real_agents_decisions` pins it.

Every figure here is from the same sandbox on the same machine, so they are comparable to each other and are not a claim about any particular validator. They are quoted to one decimal because the exact gas count moves a little between runs: the sandbox creates accounts named `dev-<timestamp>-<random>`, and an account id's length is part of what a receipt costs. Run the tests above to see the current numbers.

They all assume the wasm is built with `--cfg near`; without it near-sdk compiles its environment calls to pure-Rust fallbacks, which costs slightly less and throws away every panic message. `scripts/build-contract.sh` sets that flag and refuses to hand over a wasm that does not carry it.

The fixtures under `tests-sandbox/tests/fixtures/` are generated rather than browser-captured, so the tests run headless:

```bash
node tools/make-fixtures.mjs     # deterministic: re-running it leaves git clean
```

`tools/capture-assertion.html` does the same from a real phone and prints the same JSON shape, so a real capture is a drop-in replacement for a generated fixture. It needs HTTPS or `localhost`.

## Build

```bash
scripts/build-contract.sh                 # the wallet contract
scripts/build-contract.sh test-token      # the NEP-141 used by the tests
```

Use the script rather than a bare `cargo build`. The wasm has to be compiled with `--cfg near`
or near-sdk falls back to pure-Rust environment calls and the deployed contract discards every
refusal reason; `.cargo/config.toml` sets the flag but cargo ignores config `rustflags` whenever
`RUSTFLAGS` is set in the environment, even to the empty string. The script sets it itself and
checks the result before printing a path. `scripts/deploy.sh` goes through it too.

## Test

`cargo test` runs every unit and sandbox test in the workspace. Sandbox tests build the contracts from source and download the NEAR sandbox binary on first run. The sandbox tests live in `tests-sandbox/`.

```bash
cargo test
cargo test --test account_is_frozen
cargo test --test test_token
cargo test --test widen_requires_passkey -- --nocapture   # prints the verification gas figure
cargo test --test rules -- --nocapture                    # prints the set_rule gas figures
cargo test --test spend -- --nocapture                    # prints the spend gas figures
cargo test --test concurrency -- --nocapture              # two agents, one budget
```
