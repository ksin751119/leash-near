# Leash on NEAR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A NEAR account that holds money, hands agents a key that can only call `spend`, and refuses payments that break a rule the agents cannot reach — with widening of that rule gated by an on-chain WebAuthn (passkey) signature.

**Architecture:** One contract (`leash-account`) deployed to `wallet.leash.testnet`, whose full-access keys are deleted after deployment so its code is frozen. Agents are subaccounts of a budget-name account; the budget node is derived from the caller's parent account, so membership needs no registry. Rules live in contract state, writable only by ADMIN, and any field that loosens requires a passkey assertion verified in-contract. Payments reserve headroom before dispatching `ft_transfer` and settle in the callback.

**Tech Stack:** Rust, `near-sdk` 5.x, `near-workspaces` for sandbox tests, `p256` + `sha2` (no_std, wasm32) for WebAuthn verification, NEP-141 (USDC on testnet), NEP-297 events, a static HTML/JS demo page reusing the previous project's visual design, Node agent processes reusing the previous project's loop shape.

**Spec:** `docs/superpowers/specs/2026-10-25-leash-near-design.md`

## Global Constraints

- Target `wasm32-unknown-unknown`, `near-sdk` 5.x, Rust 2021 edition.
- Every refusal path returns normally and records a decision. **No `env::panic_str` on a policy refusal** — panics roll back the record.
- Gas ceiling per `spend` call: 300 TGas total. `ft_transfer` dispatch budget 20 TGas, callback 15 TGas.
- `spend` must be callable with **zero attached deposit** (function-call keys cannot attach one). The contract attaches the NEP-141-required 1 yoctoNEAR itself.
- The ring buffer holds exactly the last 20 decisions. Bounded storage is a requirement, not an optimisation.
- Amounts are `U128` at the token's own decimals (USDC testnet: 6). No floats anywhere.
- Timestamps use `env::block_timestamp_ms()`; `period_ms` is in milliseconds.
- Security claims in the README must each name a test. A claim without a test is deleted from the README, not left unproven.
- Passkey wording: "a human was present" NEVER stands alone — the registration caveat appears in the same breath (the contract cannot prove a credential is hardware-backed; the guarantee is only as strong as registration). "A unique human" is never claimed. See the spec's "What this proves, stated precisely".
- The repo was `git init`-ed on **5 Nov 2026**; every commit lands inside the 1-14 Nov dev window.

## Review Focus

Input classes the spec implies but which no obvious happy-path test exercises. Each has a test added to the task that owns the code.

1. **An agent account id with no `.` separator** (`alice.testnet` calling directly, or a top-level id) — node derivation must refuse, not index out of bounds. *(Task 2)*
2. **A `spend` arriving while an earlier `spend`'s `ft_transfer` is still in flight** — the second must see the first's reservation. *(Task 6)*
3. **`ft_transfer` failing after a successful policy check** (unregistered payee, token contract down) — reservation released, decision recorded as failed, no silent loss of headroom. *(Task 6)*
4. **A passkey assertion replayed, or signed for a different rule** — nonce and challenge binding must both reject. *(Task 4)*
5. **A rule change that tightens one field and loosens another** (e.g. lower per-tx limit, higher period limit) — the comparator must classify the whole call as widening. *(Task 3)*

---

### Task 1: Repository skeleton and frozen-account proof

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `contract/Cargo.toml`, `contract/src/lib.rs`
- Create: `tests-sandbox/tests/sandbox/account_is_frozen.rs`
- Create: `scripts/deploy.sh`, `scripts/freeze.sh`
- Create: `README.md` (skeleton: title, one-line thesis, build/test commands)

**Interfaces:**
- Consumes: nothing.
- Produces: a `LeashAccount` contract struct with `#[near(contract_state)]`, `new(admin: AccountId, token: AccountId) -> Self`, and a workspace that builds to wasm32.

- [ ] **Step 1: Write the failing sandbox test**

```rust
// tests-sandbox/tests/sandbox/account_is_frozen.rs
#[tokio::test]
async fn deploying_new_code_fails_after_freeze() -> anyhow::Result<()> {
    let (worker, wallet) = deploy_and_freeze().await?;
    // wallet has zero full-access keys
    assert_eq!(full_access_key_count(&worker, wallet.id()).await?, 0);
    // redeploying the same wasm from the account itself is rejected
    let res = wallet.batch(wallet.id()).deploy(&wasm()).transact().await?;
    assert!(res.is_failure());
    Ok(())
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --test account_is_frozen`
Expected: FAIL — contract does not build / helper missing.

- [ ] **Step 3: Implement the contract skeleton and the freeze script**

`LeashAccount` holds `admin: AccountId`, `token: AccountId`, `paused: bool` and nothing else yet. `scripts/freeze.sh` deletes every full-access key on the wallet account via `near account delete-key` after deploy. The contract exposes **no** method that calls `Promise::deploy_contract` or `add_key` — that absence is what the test pins.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test account_is_frozen`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: contract skeleton and a test that the account is frozen"
```

---

### Task 2: Budget node derivation

**Files:**
- Create: `contract/src/node.rs`
- Test: `contract/src/node.rs` (unit tests inline)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn node_of(agent: &AccountId) -> Option<AccountId>` — returns everything after the first `.`, or `None` when the id has no separator or the remainder is empty.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn derives_parent() {
    assert_eq!(node_of(&"pay.ops.leash.testnet".parse().unwrap()).unwrap(), "ops.leash.testnet".parse().unwrap());
}
#[test] fn two_agents_share_one_node() {
    assert_eq!(node_of(&"pay.ops.leash.testnet".parse().unwrap()), node_of(&"subs.ops.leash.testnet".parse().unwrap()));
}
#[test] fn refuses_id_without_separator() {
    assert!(node_of(&"alice".parse().unwrap()).is_none());
}
#[test] fn refuses_trailing_separator_remainder() {
    assert!(node_of(&"a.".parse().unwrap()).is_none());
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p leash-contract node::`
Expected: FAIL — `node_of` not found.

- [ ] **Step 3: Implement `node_of`**

Split once on the first `.`; parse the remainder back into an `AccountId` and return `None` if that parse fails.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p leash-contract node::`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: derive a budget node from an agent account id"
```

---

### Task 3: Rule type and the widening comparator

**Files:**
- Create: `contract/src/rule.rs`
- Test: `contract/src/rule.rs` (unit tests inline)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct Rule { token: AccountId, per_tx_limit: u128, period_limit: u128, period_ms: u64, window_start_ms: u64, window_end_ms: u64, payees: Vec<AccountId>, paused: bool }` — **no `epoch` field**: the epoch belongs to the per-node stored record (Task 5), so the bytes a passkey signs are exactly the bytes the caller submitted
  - `pub enum Change { Tightening, Widening }`
  - `pub fn classify(current: &Rule, proposed: &Rule) -> Change`

- [ ] **Step 1: Write the failing tests**

One test per field from the spec's table, each asserting `Widening`, plus the inverse asserting `Tightening`, plus:

```rust
#[test] fn mixed_change_is_widening() {
    // per_tx_limit down, period_limit up
    assert_eq!(classify(&base(), &base().with_per_tx(50).with_period_limit(10_000)), Change::Widening);
}
#[test] fn identical_rule_is_tightening() {   // i.e. needs no passkey
    assert_eq!(classify(&base(), &base()), Change::Tightening);
}
#[test] fn removing_a_payee_is_tightening() { … }
#[test] fn shorter_period_is_widening() { … }   // more resets per unit time
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p leash-contract rule::`
Expected: FAIL — `classify` not found.

- [ ] **Step 3: Implement `classify` as a list of field comparators**

Each entry is a closure `(&Rule, &Rule) -> bool` answering "does this field loosen?". `classify` returns `Widening` if any returns true. Written as data so a new field cannot be added without an entry.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p leash-contract rule::`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: rule type and a field-by-field widening comparator"
```

---

### Task 4: WebAuthn assertion verification — the risk gate

**Files:**
- Create: `contract/src/webauthn.rs`
- Create: `tests-sandbox/tests/fixtures/assertion_valid.json`, `assertion_uv_clear.json`, `assertion_wrong_challenge.json` — **generated** by `tools/make-fixtures.mjs` (Node WebCrypto P-256, byte-exact WebAuthn encoding) so the unit tests run headless
- Create: `tools/make-fixtures.mjs`, `tools/capture-assertion.html`
- Test: `contract/src/webauthn.rs` (unit), `tests-sandbox/tests/sandbox/widen_requires_passkey.rs`

**Interfaces:**
- Consumes: `Rule` (Task 3).
- Produces: `pub struct Credential { id: Vec<u8>, pubkey_sec1: Vec<u8>, nonce: u64 }`,
  `pub struct Assertion { credential_id: Vec<u8>, authenticator_data: Vec<u8>, client_data_json: String, signature_der: Vec<u8> }` (the wire type every gated method takes), and
  `pub fn verify_assertion(cred: &Credential, expected_challenge: &[u8; 32], authenticator_data: &[u8], client_data_json: &str, sig_der: &[u8]) -> Result<(), VerifyError>`
  with `VerifyError::{UserNotVerified, ChallengeMismatch, BadType, BadSignature, Malformed}`.

- [ ] **Step 1: Build the capture tool and record fixtures**

`tools/make-fixtures.mjs` generates three byte-exact fixtures with WebCrypto P-256: valid; UV bit clear; challenge for a different rule. `tools/capture-assertion.html` registers a real passkey and prints a real assertion — it is not needed for the unit tests, but Task 10's preflight requires one real-device assertion to have been verified on-chain before recording.

- [ ] **Step 2: Write the failing unit tests**

```rust
#[test] fn accepts_a_real_assertion() { assert!(verify_assertion(&cred(), &challenge(), …).is_ok()); }
#[test] fn rejects_when_uv_bit_clear() { assert_eq!(…, Err(VerifyError::UserNotVerified)); }
#[test] fn rejects_challenge_for_another_rule() { assert_eq!(…, Err(VerifyError::ChallengeMismatch)); }
#[test] fn rejects_tampered_signature() { assert_eq!(…, Err(VerifyError::BadSignature)); }
```

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p leash-contract webauthn::`
Expected: FAIL — `verify_assertion` not found.

- [ ] **Step 4: Implement `verify_assertion`**

Check `authenticator_data[32] & 0x04` for UV; parse `client_data_json` with `serde_json`, require `type == "webauthn.get"` and base64url-decoded `challenge == expected_challenge`; verify ECDSA-P256 over `authenticator_data ‖ sha256(client_data_json)` with the `p256` crate's `VerifyingKey::from_sec1_bytes` and `verify_prehash`.

- [ ] **Step 5: Run to verify they pass**

Run: `cargo test -p leash-contract webauthn::`
Expected: PASS

- [ ] **Step 6: Write the gas test in the sandbox — this is the gate**

```rust
#[tokio::test]
async fn verifying_a_real_assertion_fits_in_gas() -> anyhow::Result<()> {
    // `set_rule` does not exist until Task 5, so the gate measures a non-mutating probe.
    let outcome = admin.call(wallet.id(), "probe_verify").args_json(valid_assertion()).max_gas().transact().await?;
    assert!(outcome.is_success());
    assert!(outcome.total_gas_burnt < Gas::from_tgas(300));
    Ok(())
}
```

`probe_verify(&self, credential_id, challenge, assertion) -> bool` changes no state and consumes no nonce; it exists so the P-256 cost can be measured before `set_rule` exists. Task 5 additionally asserts the whole `set_rule` path fits in 300 TGas, and that is the figure the README quotes.

- [ ] **Step 7: Run it and record the number**

Run: `cargo test --test widen_requires_passkey -- --nocapture`
Expected: PASS, with the burnt gas printed. **Write the measured figure into the README.**

> **Decision point — 9 Nov.** (Moved from 5 Nov: the plan assumed a 1 Nov start and work began
> 5 Nov.) If this test is not green by then, stop. Replace Task 4 with the timelock design
> (`queue_rule` + `apply_rule` after 24h, cancellable by ADMIN) and update the spec's decision
> table and the README with the reason. Do not keep pushing on gas past 9 Nov.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat: verify a WebAuthn assertion on-chain, with a gas measurement"
```

---

### Task 5: Rules in state — set_rule, payees, pause

**Files:**
- Modify: `contract/src/lib.rs`
- Create: `contract/src/state.rs`
- Test: `tests-sandbox/tests/sandbox/rules.rs`

**Interfaces:**
- Consumes: `Rule`, `classify` (Task 3), `verify_assertion`, `Credential` (Task 4).
- Produces:
  - `pub fn set_rule(&mut self, node: AccountId, rule: Rule, assertion: Option<Assertion>)`
  - `pub fn add_payee(&mut self, node: AccountId, payee: AccountId, assertion: Assertion) -> Promise` (also sends `storage_deposit` to the token contract for `payee`)
  - `pub fn remove_payee(&mut self, node: AccountId, payee: AccountId)`
  - `pub fn register_credential(&mut self, cred: Credential)`
  - views: `rule_of(node) -> Option<Rule>`, `payees_of(node) -> Vec<AccountId>`

- [ ] **Step 1: Write the failing sandbox tests**

```rust
#[tokio::test] async fn tightening_needs_no_assertion() { … assert!(res.is_success()); }
#[tokio::test] async fn widening_without_assertion_is_rejected() { … }
#[tokio::test] async fn widening_with_replayed_assertion_is_rejected() { /* same assertion twice */ }
#[tokio::test] async fn non_admin_cannot_set_any_rule() { … }
#[tokio::test] async fn setting_a_rule_bumps_the_epoch_and_zeroes_the_ledger() { … }
#[tokio::test] async fn adding_a_payee_registers_storage_on_the_token() { … }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test --test rules`
Expected: FAIL — methods not found.

- [ ] **Step 3: Implement the methods**

`set_rule` requires `predecessor_id == admin`; computes `classify`; when `Widening`, requires an assertion whose challenge is `sha256(borsh(proposed_rule) ‖ cred.nonce)` and increments the nonce on success; bumps `epoch` on every accepted change.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --test rules`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: rules in state, gated by admin and by the passkey on widening"
```

---

### Task 6: The payment path

**Files:**
- Modify: `contract/src/lib.rs`
- Create: `contract/src/spend.rs`, `contract/src/decision.rs`
- Test: `tests-sandbox/tests/sandbox/spend.rs`, `tests-sandbox/tests/sandbox/concurrency.rs`

**Interfaces:**
- Consumes: `node_of` (Task 2), `Rule` (Task 3), state accessors (Task 5).
- Produces:
  - `pub fn spend(&mut self, token: AccountId, payee: AccountId, amount: U128) -> PromiseOrValue<Outcome>` — the token argument is required, otherwise refusal code 3 (wrong token) is unreachable
  - `#[private] pub fn on_transfer(&mut self, node: AccountId, record_id: u64, amount: U128) -> Outcome`
  - `pub enum Outcome { Allowed, Refused(u8), Failed }` with codes 1–7 exactly as the spec's table
  - `pub struct Decision { agent, node, payee, amount, outcome, spent_after, timestamp_ms }`
  - views: `recent_decisions() -> Vec<Decision>` (≤20, newest first), `spent_in_period(node) -> U128`

- [ ] **Step 1: Write the failing refusal tests**

One test per code: no rule for the derived node (1), paused (2), wrong token (3), payee not on the list (4), over per-tx limit (5), over period limit (6), outside window (7). Each asserts three things:

```rust
assert!(res.is_success());                              // the transaction succeeded
assert_eq!(balance_before, balance_after);              // no money moved
assert_eq!(recent_decisions()[0].outcome, Refused(n));  // and the chain said why
```

- [ ] **Step 2: Write the failing allow and settlement tests**

```rust
#[tokio::test] async fn an_allowed_payment_transfers_and_settles() { … }
#[tokio::test] async fn a_failed_transfer_releases_the_reservation() {
    // payee removed from the token's storage registry so ft_transfer fails
    assert_eq!(spent_in_period(node), before);
    assert_eq!(recent_decisions()[0].outcome, Outcome::Failed);
}
#[tokio::test] async fn the_ring_buffer_holds_exactly_twenty() { /* 25 spends */ }
```

- [ ] **Step 3: Write the failing concurrency test**

```rust
#[tokio::test]
async fn two_agents_cannot_both_spend_the_last_of_the_budget() -> anyhow::Result<()> {
    // period_limit leaves room for exactly one payment
    let (a, b) = tokio::join!(agent1.call(…"spend"…), agent2.call(…"spend"…));
    let outcomes = [outcome_of(a?), outcome_of(b?)];
    assert_eq!(outcomes.iter().filter(|o| **o == Outcome::Allowed).count(), 1);
    assert!(spent_in_period(node).await? <= period_limit);
    Ok(())
}
```

- [ ] **Step 4: Run them and watch them fail**

Run: `cargo test --test spend --test concurrency`
Expected: FAIL — `spend` not found.

- [ ] **Step 5: Implement `spend` and `on_transfer`**

Order of checks is the spec's 1–7. On refusal: push a `Decision`, emit a NEP-297 event, return `Outcome::Refused(code)` — no panic. On allow: add to `spent[(node, bucket)]` **before** dispatching, then `ft_transfer` with 1 yoctoNEAR and 20 TGas, with `on_transfer` as the callback at 15 TGas. `on_transfer` finalises the record on success; on failure it subtracts the reservation back and marks the record `Failed`.

- [ ] **Step 6: Run to verify they pass**

Run: `cargo test --test spend --test concurrency`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: the payment path — refuse without panicking, reserve before transferring"
```

---

### Task 7: Withdraw, and the keys the agents get

**Files:**
- Modify: `contract/src/lib.rs`
- Create: `scripts/grant-agent-key.sh`, `scripts/reset-demo.sh`
- Test: `tests-sandbox/tests/sandbox/keys.rs`, `tests-sandbox/tests/sandbox/withdraw.rs`

**Interfaces:**
- Consumes: `verify_assertion` (Task 4), `spend` (Task 6).
- Produces: `pub fn withdraw(&mut self, to: AccountId, amount: U128, assertion: Assertion) -> Promise`.
- **No `keys_report` view** — no NEAR host function lets a contract enumerate its own access keys. Key facts come from RPC `view_access_key_list`: this task asserts them through near-workspaces, Task 9 reads them in `web/near.mjs`, Task 10's preflight checks them with the CLI.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn an_agent_key_cannot_call_anything_but_spend() {
    // same key, calling set_rule / withdraw / add_payee → all rejected by the protocol
}
#[tokio::test] async fn an_agent_key_cannot_call_the_token_contract_directly() { … }
#[tokio::test] async fn withdraw_without_an_assertion_is_rejected() { … }
#[tokio::test] async fn rpc_shows_zero_full_access_keys_after_freeze() { /* via the worker's access-key RPC, not a contract view */ }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test --test keys --test withdraw`
Expected: FAIL

- [ ] **Step 3: Implement `withdraw`; write the key-granting script**

`grant-agent-key.sh` adds a function-call key restricted to `receiver_id = wallet.leash.testnet`, `method_names = ["spend"]`, with a small gas allowance.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --test keys --test withdraw`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: passkey-gated withdraw, and agent keys that can only spend"
```

---

### Task 8: Agent processes

**Files:**
- Create: `agent/loop.mjs`, `agent/decide.mjs`, `agent/send.mjs`, `agent/vendors.json`, `agent/intents.json`
- Test: `agent/*.test.mjs`

**Interfaces:**
- Consumes: the contract's `spend` and view methods (Tasks 5–6).
- Produces: two processes started with `AGENT_NAME`, `AGENT_ACCOUNT`, `PORT`; each serves `GET /state` with `{ name, agentAddr, lastAction, cohort, refusals }` and accepts `POST /instruct {text}`.

- [ ] **Step 1: Write the failing tests**

```js
test("decide() explains a budget refusal in token units", …)      // "3.00 left of 10.00 USDC, this is 5.00"
test("an unknown vendor is predicted to be refused", …)
test("a refusal recorded on-chain is shown as refused, not in-flight", …)  // the latch bug from the last project
```

- [ ] **Step 2: Run them and watch them fail**

Run: `node --test agent/`
Expected: FAIL

- [ ] **Step 3: Implement the loop**

`decide()` predicts the outcome from the view state before sending; the loop sends regardless and reconciles against `recent_decisions()` so a refusal never sticks as "in flight".

- [ ] **Step 4: Run to verify they pass**

Run: `node --test agent/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: two agent processes sharing one budget"
```

---

### Task 9: Demo page

**Files:**
- Create: `web/demo.html`, `web/demo-render.mjs`, `web/near.mjs`
- Test: `web/demo-render.test.mjs`

**Interfaces:**
- Consumes: agent `/state` (Task 8) and the contract's view methods directly via RPC.
- Produces: a static page; no build step.

- [ ] **Step 1: Write the failing render tests**

```js
test("renders a refusal with its reason name and no amount moved", …)
test("the budget bar segments by agent and sums to spent_in_period", …)
test("renders zero full-access keys as the headline fact", …)   // from RPC view_access_key_list, not a contract view
```

- [ ] **Step 2: Run them and watch them fail**

Run: `node --test web/`
Expected: FAIL

- [ ] **Step 3: Implement the renderers and the page**

Port the previous project's layout and palette; data comes from view calls, polled every 2s. No indexer, no API key.

- [ ] **Step 4: Run to verify they pass**

Run: `node --test web/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: demo page reading contract state directly"
```

---

### Task 10: Deploy, preflight, and the README

**Files:**
- Create: `scripts/preflight.sh`, `docs/demo-script.md`, `docs/architecture.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything.
- Produces: a one-command reset to a known demo state, and a README whose every security claim names its test.

- [ ] **Step 1: Write `preflight.sh`**

Checks, each failing loudly (no silent `|| 0`): wallet has zero full-access keys; both agent keys exist and are `spend`-only; rule present with headroom for exactly the scripted beats; both agent processes answer `/state`; the token balance is what the script expects; **at least two credentials are registered** (the spec's mitigation for a lost passkey).

- [ ] **Step 2: Run it against a fresh testnet deploy**

Run: `./scripts/reset-demo.sh && ./scripts/preflight.sh`
Expected: every check green.

- [ ] **Step 3: Write the README**

Each claim followed by the test that proves it, e.g. "the agent key cannot touch the token contract — `tests-sandbox/tests/sandbox/keys.rs::an_agent_key_cannot_call_the_token_contract_directly`". Include the measured gas figure from Task 4 (33.46 TGas), the passkey wording WITH its registration caveat as the spec states it — never the bare "a human was present" — and the lost-credential caveat.

- [ ] **Step 4: Full test run**

Run: `cargo test && node --test agent/ && node --test web/`
Expected: all green; record the counts in the README.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs: README, architecture, demo script, and a preflight that fails loudly"
```

---

### Task 11: Record and submit

- [ ] **Step 1: Rehearse the five beats against `docs/demo-script.md`**
- [ ] **Step 2: Record in segments; keep the total under five minutes**
- [ ] **Step 3: Upload the video; post it on X saying it was built at NEAR HACKATHON**
- [ ] **Step 4: Submit the repo link and the X post link through the form before 14 Nov 23:59 UTC**
- [ ] **Step 5: Tag the submitted commit**

```bash
git tag -a submission -m "NEAR Hackathon submission" && git push --tags
```
