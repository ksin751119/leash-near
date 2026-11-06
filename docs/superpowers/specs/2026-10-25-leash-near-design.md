# Leash on NEAR — design

**Date:** 2026-10-25
**Event:** NEAR Hackathon, 1–14 Nov 2026 (dev window), results by 18 Nov
**Tracks:** AI Security & Defense (primary), Social Money (secondary)
**Status:** approved in brainstorming, awaiting implementation plan

---

## What this exists to solve

NEAR already looks like it has agent permissions, and that is exactly the trap.

An account can hand out a **function-call access key** pinned to one `receiver_id`, one set
of `method_names`, and an `allowance`. It reads like a spending limit. It is not. Per the
protocol docs, the allowance is **"the amount of NEAR allowed to be spent on gas"** — gas and
transaction fees only. Nothing in the key restricts how much value the called contract moves.

So the naive agent setup on NEAR is:

```
agent key ── (receiver_id = usdc.near, method = ft_transfer) ──▶ drains the account
             allowance 0.25 N is untouched; it only ever paid for gas
```

The constraint and the thing being constrained are still the same object: whatever the agent
is allowed to call decides how much money moves. **Leash moves the decision into a place the
agent cannot reach, and makes the payment path read it.**

This is the same thesis as the Ethereum version (ETHOnline 2026), re-derived for NEAR's
account model. Nothing is ported; the primitives are different enough that the design is new.

---

## Decisions already taken (brainstorming, 2026-10-20 → 10-25)

| # | Decision | Why | Rejected alternative |
|---|---|---|---|
| 1 | **Pure NEAR.** Money and rules both on NEAR. | Two weeks, solo. Chain Signatures adds MPC latency and failure modes to a live demo. | Rules on NEAR, money on Ethereum via Chain Signatures — listed in the README as the next step, not built. |
| 2 | **Widening a rule requires a passkey signature verified on-chain.** | Keeps the "a human was present" beat from the previous demo without inventing a trust assumption — qualified by the registration caveat in "What this proves, stated precisely". | World ID: its identity-tree root lives on World Chain and NEAR has no message channel to it; we would have to run the relayer ourselves and the uniqueness claim would rest on our own server. Rejected on honesty grounds. |
| 3 | **Fallback: 24h timelock on widening.** Decision point **5 Nov**. | On-chain P-256/WebAuthn verification is the one genuinely novel piece of engineering here. It gets built first and it gets a hard abandon date. | Building it last and discovering on 13 Nov that it does not fit in gas. |
| 4 | **The wallet account holds no full-access key.** | NEAR lets an account delete every full-access key. Code then cannot be redeployed and behaviour is fixed — including against the owner. Money has exactly one exit: `spend`. | Keeping an owner key "just in case", which reduces the claim to "the agent has no permission" — strictly weaker and already done on Ethereum. |
| 5 | **The budget unit is the agent's parent account.** | Only `ops.leash.testnet` can create `pay.ops.leash.testnet`. Membership of a budget is enforced by the protocol's naming rule, so there is no registry, no binding transaction, and no lookup. | An explicit `bind_agent` registry, i.e. re-implementing on NEAR something NEAR already guarantees. |
| 6 | **Rules live in the wallet contract's own state, writable only by ADMIN.** | NEAR cross-contract calls are asynchronous; reading rules from a separate contract would put a block boundary between judgement and payment. | A separate rules contract read per spend. |
| 7 | **No indexer. Last 20 decisions in a bounded ring buffer, read by view call.** | View calls are free, synchronous, unthrottled. The previous demo's subgraph hit a 429 mid-recording. | A subgraph / Goldsky pipeline as a demo dependency. Optional afterwards, never load-bearing. |
| 8 | **Reuse the previous demo page's visual design**, new data source. | It is already designed and tested; two weeks is short. | Designing a second UI from scratch. |

---

## Accounts and keys

```
leash.testnet                  ADMIN. Full-access key, held by a human.
│                              Owns the namespace. Writes rules. Creates agent accounts.
│
├── wallet.leash.testnet       THE MONEY. Holds NEP-141 USDC. Runs leash-account.wasm.
│                              ZERO KEYS OF ANY KIND after freezing. Code is frozen, and
│                              nobody can sign as this account.
│
└── ops.leash.testnet          A BUDGET. An account that exists to be a name and a parent.
    │
    ├── pay.ops.leash.testnet   AGENT 1 (payments process). Holds ONE key: function-call,
    │                           receiver wallet.leash.testnet, methods ["spend"].
    └── subs.ops.leash.testnet  AGENT 2 (subscriptions process). Same, its own key.
```

Each agent holds **one function-call access key on its own account**, with
`receiver_id = wallet.leash.testnet` and `method_names = ["spend"]`, and no other key. The
protocol — not our code — makes it impossible for that key to call `usdc.testnet` at all.

**Why the key is on the agent's account and not on the wallet.** `spend` identifies the caller
by `predecessor_id` and derives the budget node from it. A key on the wallet signs *as the
wallet*, so the contract would see the wallet as the caller, derive no node, and refuse every
payment with code 1; this was found, not assumed, on testnet. Signing as `pay.ops.…` with a key
whose receiver is the wallet is what makes the caller the agent while the protocol still pins
the key to `spend` on the wallet. The wallet account itself therefore needs no key after
deployment, and has none: freezing it leaves an account whose keys list is empty. Granting an
agent's key and freezing the wallet are independent steps, in either order.

Spending needs gas: `spend` reserves 20 + 15 TGas for `ft_transfer` and its callback before it
starts, so an agent attaches at least ~40 TGas (60 is safe; 30 fails with "Exceeded the
prepaid gas"). Allowed payments burn about 8.5 TGas of that.

Two further facts that shape the API:

- **Function-call keys cannot attach a NEAR deposit.** So `spend` must be callable with zero
  deposit; the 1 yoctoNEAR that `ft_transfer` requires is attached by the contract from the
  wallet account's own balance.
- `predecessor_id` on a `spend` call is the agent account. The budget node is derived as
  everything after the first `.` — `pay.ops.leash.testnet` → `ops.leash.testnet`. A caller
  whose id has no `.` separator, or whose derived parent has no rule, is refused.

### What ADMIN cannot do

ADMIN can repoint rules and mint agent accounts. ADMIN **cannot move the money**: it holds no
key on `wallet.leash.testnet`, and the wallet account has no key at all for anyone to steal. ADMIN also cannot widen a rule alone — widening needs the passkey — and that holds only because
**ADMIN cannot add a credential alone either**: after the first credential, `register_credential`
needs an assertion from one already registered (see "Credential registration" below). Without that,
a stolen admin key could register its own software credential and then sign any widening or
withdrawal with it. What a stolen admin key CAN do: tighten rules, pause, remove payees, and remove credentials
(which can strand the funds, never steal them). What it cannot do: widen, withdraw, or mint itself a credential.

### The honest boundary

Owner recovery goes through `withdraw`, which is gated exactly like a widening: passkey
signature required. There is no backdoor and no recovery path that skips it. **If every
registered credential is lost, the funds are stuck**, and nobody can mint a replacement, because a
new credential has to be signed for by an existing one. Removal is ungated (it only takes capability
away), so a stolen admin key could also strand the funds by removing every credential; it still
cannot take them. This is stated plainly in the README rather than papered over; for a hackathon
testnet demo it is the right trade, and the mitigation is real now: register two credentials, on
different devices.

---

## The payment path

```
agent ──spend(token, payee, amount)──▶ wallet.leash.testnet
   │
   ├─ 1. does predecessor_id derive to a node with a rule?      → refuse 1
   ├─ 2. is the account paused?                                 → refuse 2
   ├─ 3. is the token the rule's token?                         → refuse 3
   ├─ 4. is the payee on the node's allow-list?                 → refuse 4
   ├─ 5. amount > per-tx limit?                                 → refuse 5
   ├─ 6. spent_in_period + amount > period limit?               → refuse 6
   ├─ 7. outside the rule's active window?                      → refuse 7
   │
   ├─ refused → record the decision, emit an event, RETURN NORMALLY. No panic.
   └─ allowed → reserve, then ft_transfer, then settle in the callback
```

**Refusals do not panic.** A panic would roll back the ring-buffer write and leave a failed
transaction with no on-chain record of *why*. The refusal is the product; it has to be
durable and legible. (The previous version made the same choice for the same reason, and the
demo depended on it.)

### Asynchrony is the real work here

`ft_transfer` is a cross-contract call. Between the check and the transfer's resolution,
other `spend` calls can arrive. The sequence is:

1. **Reserve** — add `amount` to `spent[node][period]` *before* dispatching the transfer, so a
   second concurrent agent sees the reservation and cannot double-spend the same headroom.
2. **Dispatch** `ft_transfer` with 1 yoctoNEAR and a fixed gas budget.
3. **Settle in the callback** — on success, finalise the record as `executed`. On failure,
   **release the reservation** and record the decision as `failed` with the promise's error.

This is the one place where a bug silently loses money or silently loses a limit. It gets
dedicated sandbox tests, including two agents spending concurrently in the same block.

### Payee registration

NEP-141 `ft_transfer` fails if the receiver has no storage deposit on the token contract. So the
invariant is **"on the allow-list" means "can be paid"**: every path that writes a payee pays
`storage_deposit` for it first and commits the rule only in the callback, all-or-nothing. Without
this, a legitimate payment fails for a reason unrelated to policy and the demo looks broken.

Both paths, not just one. `add_payee` and `set_rule` are equally able to introduce a payee —
`set_rule` can introduce several at once — and Task 5's first implementation enforced the
invariant in `add_payee` only, which left every rule set through `set_rule` carrying payees that
could not receive a transfer. A tightening can never introduce a payee (any addition is a
loosening by `classify`), so the emergency brake still applies synchronously.

A payee counts as registered only **against the token it was registered on**, so changing a
rule's `token` makes every payee need registering again even though the account list is
untouched. A diff over payee accounts alone misses that and commits with no deposits at all,
leaving the whole list against a token none of them is registered on. `changing_the_token_re_
registers_every_payee` pins it. (One operational consequence: switching the token on a node with
more than `MAX_NEW_PAYEES_PER_CALL` payees needs the list trimmed first, because every one of
them has to be re-registered in that call.)

Pinned by `every_payee_on_the_list_is_registered_whichever_path_added_it`,
`a_rule_whose_payee_cannot_be_registered_is_not_applied`,
`a_failed_storage_deposit_leaves_the_payee_off_the_list` and
`a_tightening_does_not_wait_on_the_token`.

---

## Shared budget

```
NodeRecord { rule, epoch, version, window_began_ms, spent }   // one per node, no agent in it
```

The budget ledger is an **explicit accumulator**, not a figure derived from the clock:

```
on each spend:
    if now_ms >= window_began_ms + period_ms:
        window_began_ms += period_ms * ((now_ms - window_began_ms) / period_ms)
        spent = 0
    spent += amount
```

The window advances by whole multiples of `period_ms`, so windows stay anchored to the first one
and do not drift forward with traffic. It rolls on its own with no transaction from anyone.

**Only an accepted loosening resets the ledger** — `spent = 0`, `window_began_ms = now` — and
that also advances `epoch`. A loosening is gated on a passkey, so a reset always costs a
signature. Tightenings and payee changes leave the ledger exactly where it is.

**Corrected twice in Task 5, both times after review.** The design originally said
`period_bucket = (epoch << 32) | (now_ms / period_ms)` with the epoch advanced by every
`set_rule`. Three things were wrong with it, and the first two were security holes — each one let
ADMIN refill a node's budget with no passkey at all, which would make `period_limit` not a limit
and "loosening needs a human" not true:

1. **Every accepted `set_rule` advanced the epoch, including a tightening.** Tightening is
   ungated by design, and re-applying the byte-identical rule classifies as a tightening, so the
   ledger could be reset on demand, unlimited times, for free. Fixed by advancing the epoch only
   on an accepted widening.
2. **The bucket was `now_ms / period_ms`.** Fixing the epoch alone is not enough: *lengthening*
   `period_ms` is a tightening by `classify`, and it changes the divisor, so the next read lands
   on a different key and shows zero. Fixed by recording the window start instead of dividing —
   changing `period_ms` now changes only when the next roll happens.
3. **The packed form overflowed.** `now_ms` is about 1.7e12, so any `period_ms` below roughly 400
   made the quotient exceed `u32::MAX` and carry into the epoch bits, landing on another epoch's
   ledger. `period_ms` is caller-supplied and only has to be non-zero, so it was reachable.

A fourth, non-security problem went with them: the map form needed an entry per
`(node, epoch, period)` and nothing ever reclaimed them, so the contract staked them forever.
One accumulator per node has no such growth.

Pinned by `state::tests::a_widening_resets_the_ledger_and_bumps_the_epoch`,
`a_tightening_does_not_reset_the_ledger_or_bump_the_epoch`,
`re_applying_the_same_rule_many_times_frees_nothing`,
`lengthening_the_period_in_a_tightening_frees_nothing`,
`the_window_advances_by_whole_periods_and_does_not_drift` and
`a_one_millisecond_period_rolls_correctly`.

Consequences, both intended:

- **Many agents, one node.** Two processes with no channel between them draw down one number.
  Atomicity comes from the chain — no shared database, no lock, no coordinator. This is the
  Social Money beat.
- **One agent, one node.** An agent's node is derived from its own name, so an agent cannot
  sit under two budgets and hop to the second when the first runs dry.

---

## Widening versus tightening

Every `set_rule` compares the proposed rule to the current one, field by field:

| Field | Widening if |
|---|---|
| `per_tx_limit` | increases |
| `period_limit` | increases |
| `period` | shortens (more resets per unit time) |
| `window` | starts earlier or ends later |
| `payees` | any addition |
| `token` | any change |
| `paused` | true → false |

Any widening field ⇒ the whole call needs a valid passkey assertion. Pure tightening is free
and immediate, callable by ADMIN alone. **Tightening must never be gated**: the moment you
notice something wrong is the moment you must be able to clamp down, and a gate there is a
gate on the emergency brake.

The same asymmetry applies to the two things outside `Rule` that take capability away or hand
it back:

- **The account-wide pause.** `set_paused(true)` is ADMIN-only and ungated; `set_paused(false)`
  needs an assertion, signed under its own action tag. Refusal code 2 means paused-by-account
  **or** paused-by-rule.
- **Credential registration and removal.** `register_credential` is ADMIN-only for the very first
  credential and ADMIN **plus an assertion from an existing credential** for every later one, under
  its own action tag over the new credential's id, key and nonce (it is the trust boundary — see
  below); `remove_credential` is ADMIN-only and ungated, because removing a
  credential only takes capability away. Removal has to exist: without it the cap on
  credentials would be a *lifetime* budget on an account whose code cannot be redeployed, and
  after enough rotations no loosening would ever be possible again. A removed credential is
  kept as a tombstone rather than deleted, so its id can never be re-registered at nonce 0 and
  re-arm old assertions, while the slot it held is free for a new credential.

The comparator is pure, total, and unit-tested per field — it is the security boundary of the
whole design, so it is written as data (a list of field comparators), not as a long `if`.

---

## Passkey verification (the risky part)

The contract stores one or more registered credentials: `credential_id`, the P-256 public key,
and a monotonic `nonce`.

To widen, the client sends `authenticator_data`, `client_data_json`, and the signature. The
contract:

1. Checks the **UV bit** (`authenticator_data[32] & 0x04`) — the authenticator verified a
   human at signing time (biometric or PIN).
2. Parses `client_data_json`, checks `type == "webauthn.get"` and that `challenge` equals the
   value defined in `contract/src/challenge.rs` — the signature authorises **this exact rule
   change, for this node, on this deployment**, once.

   **Corrected in Task 5:** this was originally `sha256(borsh(proposed_rule) ‖ nonce)`, which
   binds too little. Two nodes carrying identical rules would produce identical challenges, so a
   signature meant to widen one would widen the other; and two deployments of this contract would
   accept each other's signatures. The challenge therefore binds four things — the action, the
   node, the normalised rule, the credential's nonce, and `env::current_account_id()` — with
   every variable-length part length-prefixed so the encoding is injective. The authoritative
   byte layout is the module doc comment on `contract/src/challenge.rs`; the view method
   `challenge_for(node, rule, credential_id)` returns the bytes so clients need not reimplement
   it, and `challenge_for_matches_the_documented_layout` checks that view against an independent
   implementation of the layout.

   The rule that is hashed is always one the contract parsed from JSON and re-serialised itself,
   never bytes the caller supplied: `Rule`'s derived `BorshDeserialize` does not re-sort or dedupe
   `payees`, so two different byte strings can mean the same rule.

   **Each gated operation signs under its own action tag**, and the separation is load-bearing:
   `set_rule` (which resets the spend ledger), `add_payee` (which does not) and
   `set_paused(false)`. An interim version let `set_rule` and `add_payee` share a tag, on the
   reasoning that both reach the same state — which stopped being true the moment a loosening
   started resetting the ledger, because a shared tag would then let an assertion signed to add
   one payee be redirected into a rule change that also wipes the ledger. Pinned by
   `an_add_payee_assertion_cannot_set_a_rule`, `a_set_rule_assertion_cannot_add_a_payee` and
   `an_unpause_assertion_cannot_widen_a_rule`.
3. Verifies ECDSA-P256 over `authenticator_data ‖ sha256(client_data_json)` against the stored
   public key, using the `p256` crate compiled to wasm32.
4. Increments the nonce.

### What this proves, stated precisely

It proves that the holder of a **registered credential** signed this exact challenge, and
that the authenticator asserted user verification (the UV bit) at signing time — someone
passed that device's biometric or PIN check.

It does **not** prove uniqueness, and it does not prove *which* human; anyone enrolled on
that device can satisfy it. It also **cannot prove the credential is hardware-backed**: there
is no attestation, synced passkeys attest `none`, and a software P-256 key produces a
signature this contract accepts. A reviewer demonstrated exactly that against our own
`probe_verify`, with no device and no human.

So the guarantee is only as strong as the **registration step**: whoever registers a
credential vouches that it is a real authenticator. That makes admin-only credential
registration a security requirement, not a convenience. And it has to bind the admin key too:
**the first credential is registered by the admin alone (the bootstrap, the one unavoidable act of
trust, documented as such), and every later credential needs an assertion from a registered one.**
"First" means first ever, revoked credentials included, so removing every credential does not reopen
the bootstrap. `the_admin_key_alone_cannot_register_a_second_credential` pins it.

### `#[private]` is not relied on alone

near-sdk's `#[private]` checks that the predecessor is the contract's own account. In the
intended deployment that is sufficient: the agents' keys are on their own accounts and the
frozen wallet has no key, so nobody can sign as the wallet and only the contract's own
promises arrive with that predecessor. (An earlier version of this spec said the agents' keys
lived on the wallet and concluded `#[private]` was nearly useless. That premise was wrong, and
a key on the wallet could not have worked at all: see "Accounts and keys".)

The checks below stay anyway, as depth, because `#[private]` is only as good as the claim that
no key exists on the wallet, and that is a property of how the account was deployed, not of
the code. Before the freeze the deployer's full-access key signs as the wallet, and a key added
there by mistake would pass `#[private]` with no admin check and no assertion. So: a
state-writing method that is not a promise target is not an exported contract method at all
(keep it out of the `#[near]` impl), and the ones that must be exported — `on_payees_registered`
and `on_transfer` — pair `#[private]` with a check that the promise results they were told to
expect are present. A direct call has none, and a function-call access key cannot build a
promise chain. `commit_rule_is_not_an_exported_method` and
`on_payees_registered_cannot_be_driven_by_an_agent_key` pin both halves (the latter builds a
key on the wallet, which a correct deployment never has), and the `#[near]` impl carries a
table of every `&mut self` method and what guards it.

### The admin must be a different account from the wallet

Every gated method is guarded by `assert_admin`, which compares the predecessor against the
stored admin. An admin equal to the wallet would be satisfied by anything that signs as the
wallet (the deployer's key before the freeze, or a key added by mistake), taking the passkey
gate with it, and after the freeze by nobody at all. It is depth rather than the main defence,
since a correct deployment has no such signer.

`new` refuses it, so no deployment can be in that state, and `scripts/deploy.sh` refuses it
before building anything so the failure does not arrive as a half-finished deploy.
`the_admin_may_not_be_the_wallet_account` pins the contract half.

Wording rule: "a human was present" never appears without the registration caveat in the
same breath, and "a unique human" is never claimed at all. (The previous project had to
delete an unbacked claim late in the week; the fix is to never write one — including here,
where the first draft of this very section overclaimed.)

### Risk gate

Build this first, on day 1–3. The measurable success criterion: **a sandbox test in which a
real browser-generated assertion is verified on-chain within the 300 TGas limit.** If that
test is not green by **5 Nov**, drop to the timelock design (≈2 days of work, story intact)
and say so in the README's design-decisions section.

---

## Observability

A bounded ring buffer of the last 20 decisions lives in contract state:

```rust
struct Decision {
    agent: AccountId, node: AccountId, payee: AccountId,
    amount: Balance, outcome: Outcome,       // Allowed | Refused(code) | Failed
    spent_after: Balance, timestamp_ms: u64,
}
```

Exposed by `view` methods (`recent_decisions`, `rule_of`, `spent_in_period`, `payees_of`,
`keys_report`). View calls are free and synchronous, so the demo page reads state directly
with no indexer, no API key, and nothing to rate-limit. Bounded length also bounds storage
staking.

Events (NEP-297) are emitted in parallel so a real indexer *could* be attached later; the
demo does not depend on one.

---

## Testing

- **Unit (Rust):** the widening comparator per field; node derivation from account ids,
  including malformed ones; period-bucket arithmetic across rollovers and epoch bumps; the
  WebAuthn parser against fixtures captured from a real browser (valid, tampered challenge,
  UV bit clear, replayed nonce).
- **Sandbox (`near-workspaces`):** the full payment path; each refusal code; a refusal
  produces a successful transaction with a recorded decision and no balance change;
  **two agents spending concurrently against one node**; `ft_transfer` failure releases the
  reservation; a function-call key cannot call anything but `spend`, and is held on the agent's own
  account; after key removal the wallet account has no keys at all and `deploy_contract` on it
  fails.
- **The claim tests.** Each sentence the README makes as a security claim has a test named
  after it. If a claim has no test, it comes out of the README.

---

## Demo

Five beats, recorded in segments (no one-take constraint this time; no 4-minute cap either,
but keep it under five minutes).

0. **Evidence first.** `near account list-keys wallet.leash.testnet` → an empty table. "The
   account that holds the money has no keys. Nobody can sign as it, including me. The only way
   out for the money is `spend`, and `spend` is called from the agents' own accounts and
   decided by the contract." Then `near account list-keys pay.ops.leash.testnet` → one key,
   function-call, `spend` on the wallet and nothing else.
1. **A payment that passes.** Agent 1 pays a known vendor; transaction link.
2. **A payment the chain refuses.** Agent 1 is instructed to pay an unknown payee. The
   transaction succeeds, no money moves, the reason appears on screen and in the ledger.
3. **One budget, two agents.** Agent 2 (a separate process, separate key, no channel to
   agent 1) consumes the remaining headroom. Agent 1's next payment is refused for the
   period limit. Nothing coordinated this.
4. **Widening needs a human; tightening does not.** Raise the limit → Face ID → verified
   on-chain. Then lower the limit → immediate, no prompt.

Submission needs: public repo + a public X post saying it was built at NEAR HACKATHON with
the video attached, both via the form before **14 Nov 23:59 UTC**.

---

## Deliberately not built

Cross-chain settlement via Chain Signatures; a policy-composition system (`PolicySet` on the
Ethereum version) — one rule type is enough to carry the thesis in two weeks; multi-token
budgets; a real indexer; a mainnet deployment; agent-to-agent negotiation.

Each is a README line under "what we would build next", with the reason.

---

## Risks

| Risk | Mitigation |
|---|---|
| P-256 verification does not fit in gas, or the crate does not build for wasm32 | Built first; hard decision point 5 Nov; timelock fallback already designed |
| Async settlement bug double-spends headroom | Reserve-before-dispatch; concurrency tests are part of the definition of done |
| Testnet instability during recording | Record in segments; a dry-run script that resets state to a known point |
| Scope creep from the Ethereum version's feature set | The "deliberately not built" list above is the contract with myself |

---

## Open question for the plan

Whether the ADMIN key and the passkey credential should be allowed to be the same human in
the demo. They are in practice (it is one person), but the narration should be explicit that
they are separate *capabilities* — a stolen ADMIN key alone cannot widen anything, withdraw, or
register a credential of its own. It can still remove credentials, and removing the last one strands
the funds permanently: it cannot steal, but it can lock. The narration says "cannot steal", never
"cannot hurt".
