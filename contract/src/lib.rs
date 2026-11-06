pub mod challenge;
pub mod decision;
pub mod node;
pub mod rule;
pub mod spend;
pub mod state;
pub mod webauthn;

use crate::challenge::{
    gate_challenge, set_rule_payload, ACTION_ADD_PAYEE, ACTION_SET_RULE, ACTION_UNPAUSE,
};
use crate::decision::{Decision, DecisionLog, Outcome, RefusalView, REFUSALS};
use crate::node::node_of;
use crate::rule::{classify, Change, Rule};
use crate::spend::{evaluate, Attempt};
use crate::state::{Reservation, State, MAX_CREDENTIALS};
use crate::webauthn::{verify_assertion, Assertion, Credential};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{
    env, ext_contract, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError, PromiseOrValue,
};

/// Storage deposit paid to the token contract so a payee can receive `ft_transfer`. 0.00125
/// NEAR is the usual NEP-141 figure; a token that wants more rejects the call and the payee
/// does not go on the list.
const PAYEE_STORAGE_DEPOSIT: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);

/// Gas for one `storage_deposit` on the token, and for the callback that reads the results.
/// Deliberately generous: these are ADMIN operations called a handful of times, and the
/// alternative to generous is an admin staring at a half-applied change.
const STORAGE_DEPOSIT_GAS: Gas = Gas::from_tgas(10);
const COMMIT_CALLBACK_GAS: Gas = Gas::from_tgas(15);

/// How many payees one call may introduce. Each costs a `storage_deposit` receipt, so the
/// bound is gas: at [`STORAGE_DEPOSIT_GAS`] apiece plus the gate's ~34 TGas and the callback,
/// eight fits inside the 300 TGas a transaction gets with room to spare.
///
/// A longer list is built up over several calls — which is what `add_payee` is for — and each
/// one needs its own assertion. `rule::MAX_PAYEES` is the cap on the list itself.
const MAX_NEW_PAYEES_PER_CALL: usize = 8;

/// Bound on the bytes read back from one `storage_deposit`. Nothing reads the value — a
/// NEP-141 `StorageBalance` is two numbers and fits easily — so this only has to be big
/// enough that a well-behaved token is not misread. Exceeding it still counts as success; see
/// `on_payees_registered`.
const STORAGE_DEPOSIT_RESULT_LIMIT: usize = 512;

/// The one yoctoNEAR NEP-141 requires on `ft_transfer`, so that a transfer is always signed
/// by a full-access key — or, here, attached by the contract from the wallet account's own
/// balance. **A function-call access key cannot attach a deposit at all**, which is why
/// `spend` is not `#[payable]` and must work with nothing attached.
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

/// Gas for the payment path. `ft_transfer` on a NEP-141 is a balance read and two writes;
/// 20 TGas is several times what the test token needs and leaves headroom for a token that
/// does more. The callback only releases a reservation and rewrites one ring-buffer slot.
///
/// These are the whole of what each promise gets: both are dispatched with
/// `.with_unused_gas_weight(0)`, so the leftover of whatever an agent attached — a `max_gas`
/// call leaves well over 200 TGas of it — is **not** handed to the token contract. Reserving
/// before dispatching already makes a re-entrant `spend` safe, so this is not the defence; it
/// is simply not giving an arbitrary contract 200 TGas to play with for no reason. Without the
/// weight these would be minimums rather than budgets, and the figures below would not be the
/// figures. `a_payment_fits_in_gas` measures the whole call against the 300 TGas limit.
const FT_TRANSFER_GAS: Gas = Gas::from_tgas(20);
const TRANSFER_CALLBACK_GAS: Gas = Gas::from_tgas(15);

/// Bound on the bytes read back from `ft_transfer`. NEP-141's `ft_transfer` returns nothing;
/// the value is never read here, only whether the promise failed, so — as with
/// `STORAGE_DEPOSIT_RESULT_LIMIT` — a result that exceeds this still counts as success.
const FT_TRANSFER_RESULT_LIMIT: usize = 512;

/// The slice of NEP-141 this contract calls. `ext_contract` generates the `ext_ft` builder
/// from it; the trait itself is never implemented here, hence the allow.
#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn storage_deposit(&mut self, account_id: Option<AccountId>);
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

/// The wallet account's contract. The account that hosts it has its full-access keys
/// deleted after deploy, so this code is fixed for good. For that reason the contract
/// deliberately has no method that deploys code or adds a key
/// (no `Promise::deploy_contract`, no `add_key`): tests-sandbox/tests/sandbox/account_is_frozen.rs pins it.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct LeashAccount {
    admin: AccountId,
    token: AccountId,
    paused: bool,
    state: State,
}

/// The exported contract surface.
///
/// # Audit: what guards each state-writing method
///
/// `#[private]` is weaker here than it looks. It checks that the predecessor is this account,
/// and in this design the agent's function-call keys live **on this account** — so a key here
/// arrives with exactly that predecessor and passes. A `&mut self` method whose only guard is
/// `#[private]` is therefore reachable by an agent key, with no admin check and no assertion.
/// Review found `commit_rule` in exactly that state; it is now outside this block, so the
/// exported method does not exist.
///
/// Every `&mut self` method in this block, and what actually stops an agent key:
///
/// | Method | Guard |
/// | --- | --- |
/// | `new` | `#[init]` without `ignore_state`, so it cannot re-run on a live account; and it refuses an `admin` equal to this account, which would make every `assert_admin` below vacuous |
/// | `register_credential` | `assert_admin` |
/// | `remove_credential` | `assert_admin` |
/// | `set_rule` | `assert_admin`, plus the passkey gate on a loosening |
/// | `add_payee` | `assert_admin`, plus the passkey gate |
/// | `remove_payee` | `assert_admin` |
/// | `set_paused` | `assert_admin`, plus the passkey gate on unpausing |
/// | `on_payees_registered` | `#[private]` **and** a check that the promise results it was told to expect are present — see its own doc comment |
/// | `spend` | **Nothing. Deliberately open to any caller** — the rule for the node derived from `predecessor_id` is the only authorisation there is, and a caller with no rule is refused with code 1. The one thing that openness does let an unknown caller write is a decision record, so those go in their own small ring and cannot evict a configured node's; see `state::push_stranger_decision` |
/// | `on_transfer` | `#[private]` **and** a check that exactly one promise result is present — the same pairing as `on_payees_registered`, for the same reason |
///
/// Everything else here takes `&self` and writes nothing. `on_payees_registered` and
/// `on_transfer` are the only promise targets, so they are the only two places `#[private]` is
/// load-bearing — and in both, `#[private]` alone would be satisfied by an agent key.
/// Anything added to this block that writes state belongs in that table.
#[near]
impl LeashAccount {
    /// Initialise the wallet.
    ///
    /// **`admin` must be an account whose keys are not on this one, and that is a security
    /// requirement rather than a convention.** Every gated method in this contract is guarded
    /// by `assert_admin`, which compares `env::predecessor_account_id()` against the stored
    /// admin. The agent's function-call keys live **on this account**, so calls made with one
    /// arrive with the predecessor set to this account — and if the admin were this account,
    /// every one of those comparisons would succeed for an agent key. `assert_admin` would
    /// stop protecting anything, and the passkey gate with it: an agent could set its own
    /// rules.
    ///
    /// That is the same mistake as relying on `#[private]` here (see the audit table on this
    /// impl block), and it is the last place the premise could have been broken, so it is
    /// refused at the door rather than left to a deploy script. `scripts/deploy.sh` refuses it
    /// too, so the failure arrives before anything is deployed.
    #[init]
    pub fn new(admin: AccountId, token: AccountId) -> Self {
        require!(
            admin != env::current_account_id(),
            "admin must be a different account from the wallet: the agent's function-call keys \
             live on the wallet account, so an admin equal to it would let an agent key satisfy \
             every admin check"
        );
        Self {
            admin,
            token,
            paused: false,
            state: State::new(),
        }
    }

    pub fn get_admin(&self) -> AccountId {
        self.admin.clone()
    }

    pub fn get_token(&self) -> AccountId {
        self.token.clone()
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    // ===================================================================================
    // Credentials
    // ===================================================================================

    /// Register a passkey that may authorise loosening changes. **ADMIN only.**
    ///
    /// This is the trust boundary of the entire passkey design, and the admin check is the
    /// whole of it. The contract cannot prove a credential is hardware-backed: an assertion
    /// carries no attestation, synced passkeys (iCloud Keychain, Google Password Manager)
    /// attest `none`, and a software P-256 key produces a signature this contract accepts —
    /// the sandbox tests sign with exactly such a key. So "a registered credential signed
    /// this" means only as much as the registration did, and the only thing standing between
    /// an attacker and a self-minted credential is who may register one.
    ///
    /// Not reachable by an agent's function-call key on two counts: that key's method
    /// allow-list does not include this method, and even if it did, calls made with a key on
    /// the wallet account arrive with `predecessor_id == <the wallet>`, which is not the
    /// admin. `an_agent_function_call_key_cannot_register_a_credential` pins both.
    ///
    /// Re-registering an id is refused. Re-registration would reset the nonce, and a reset
    /// nonce re-arms every assertion ever signed under that credential. Rotation means a new
    /// credential id.
    ///
    /// The contract account pays the storage staking, which is why the count is capped.
    pub fn register_credential(&mut self, cred: Credential) {
        self.assert_admin();
        require!(
            self.state.known_credential(cred.id()).is_none(),
            "that credential id is already known to this contract, revoked or not; \
             rotate to a new id instead"
        );
        require!(
            self.state.active_credential_count() < MAX_CREDENTIALS,
            "too many active credentials; remove one first"
        );
        self.state.insert_credential(cred);
    }

    /// Revoke a registered passkey. **ADMIN only, never gated** — removing a credential only
    /// takes capability away, and a gate on that is a gate on the emergency brake.
    ///
    /// This is the recovery path for a lost or compromised device, and it has to exist. The
    /// first version of this contract had no removal method and refused to re-register a used
    /// id, which on an account whose code cannot be redeployed made
    /// [`MAX_CREDENTIALS`](state::MAX_CREDENTIALS) a *lifetime* budget: after eight rotations
    /// no loosening would ever have been possible again, with no way out. The account would
    /// have bricked itself slowly.
    ///
    /// The entry is not deleted, only marked revoked. Deleting it would free the id for
    /// re-registration starting at nonce 0, and that would re-arm every assertion ever signed
    /// under it. So the slot is freed for a new credential while the old id stays permanently
    /// out of circulation — which is what rotation should mean.
    pub fn remove_credential(&mut self, credential_id: Base64VecU8) {
        self.assert_admin();
        require!(
            self.state.revoke_credential(credential_id.as_ref()),
            "no such active credential"
        );
    }

    /// The ids of credentials that can authorise something, base64. The demo page needs them
    /// to ask the browser for an assertion from a specific credential. Revoked ids are not
    /// listed, because asking a browser for one would be asking for a signature that cannot
    /// be used.
    pub fn credential_ids(&self) -> Vec<Base64VecU8> {
        self.state
            .active_credential_ids()
            .into_iter()
            .map(Base64VecU8::from)
            .collect()
    }

    /// Every credential this contract has ever held, revoked ones included, so a rotation is
    /// visible rather than silent.
    pub fn credentials(&self) -> Vec<Credential> {
        self.state.all_credentials()
    }

    /// The nonce a client must bake into its next challenge for this credential, or `None` if
    /// it is not registered **or has been revoked** — a revoked credential has no next
    /// challenge, so answering with a number would be misleading.
    pub fn credential_nonce(&self, credential_id: Base64VecU8) -> Option<u64> {
        self.state
            .active_credential(credential_id.as_ref())
            .map(Credential::nonce)
    }

    /// The exact 32 bytes a credential must sign to authorise `rule` for `node`, base64.
    ///
    /// `rule` arrives as JSON and is therefore normalised before it is hashed, so this
    /// returns the challenge for the rule the contract would actually store — not for the
    /// bytes the caller happened to send. The byte layout is documented in
    /// `contract/src/challenge.rs`; this method exists so neither the demo page nor
    /// `tools/capture-assertion.html` has to reimplement it.
    ///
    /// Panics if the credential is not registered or has been revoked: a challenge computed
    /// against a guessed nonce is worse than no answer.
    pub fn challenge_for(
        &self,
        node: AccountId,
        rule: Rule,
        credential_id: Base64VecU8,
    ) -> Base64VecU8 {
        self.challenge(
            ACTION_SET_RULE,
            &set_rule_payload(&node, &rule),
            credential_id.as_ref(),
        )
    }

    /// The 32 bytes to sign to authorise `add_payee(node, payee)`, base64.
    ///
    /// A different action tag from `challenge_for`, because `set_rule` resets the spend ledger
    /// and `add_payee` does not — see `contract/src/challenge.rs`. The resulting rule is
    /// derived here from stored state, so a client cannot get that part wrong.
    pub fn challenge_for_add_payee(
        &self,
        node: AccountId,
        payee: AccountId,
        credential_id: Base64VecU8,
    ) -> Base64VecU8 {
        let current = self
            .state
            .rule_of(&node)
            .unwrap_or_else(|| env::panic_str("that node has no rule to add a payee to"));
        let proposed = current
            .with_payee(payee)
            .unwrap_or_else(|e| env::panic_str(&e));
        self.challenge(
            ACTION_ADD_PAYEE,
            &set_rule_payload(&node, &proposed),
            credential_id.as_ref(),
        )
    }

    /// The 32 bytes to sign to authorise `set_paused(false)`, base64. The payload is empty:
    /// unpausing is account-wide, so there is no node and no rule to bind.
    pub fn challenge_for_unpause(&self, credential_id: Base64VecU8) -> Base64VecU8 {
        self.challenge(ACTION_UNPAUSE, &[], credential_id.as_ref())
    }

    // ===================================================================================
    // Rules
    // ===================================================================================

    /// Set `node`'s spending rule. **ADMIN only.** A loosening additionally needs a passkey
    /// assertion; a tightening needs nothing.
    ///
    /// `rule` arrives as JSON, so it is normalised by `Rule::try_new` on the way in, and the
    /// challenge is computed over `borsh` of *that* value. The contract never hashes bytes a
    /// caller supplied: `Rule`'s derived `BorshDeserialize` does not re-sort or dedupe
    /// `payees`, so two different byte strings can mean the same rule, and a signature over
    /// one of them must not become a signature over a rule nobody checked.
    ///
    /// **A tightening is never gated.** The moment you notice something is wrong is the
    /// moment you must be able to clamp down, and a gate on the emergency brake is worse
    /// than no gate at all. `classify` calls an identical rule a tightening, so re-applying
    /// a rule needs no signature either — intended.
    ///
    /// A node with no rule yet is treated as a loosening, because a budget where there was
    /// none is one. So the first rule for a node needs a signature.
    ///
    /// **Only an accepted loosening resets the spend ledger**, which it does by bumping the
    /// node's epoch and starting a new window. That reset is itself a loosening — it hands a
    /// full period's headroom back — so it must only ever happen on the gated path. An
    /// earlier version reset it on every accepted call, which let ADMIN refill a node's
    /// budget by re-applying the identical rule, with no passkey and as often as it liked;
    /// `period_limit` was not a limit. See `contract/src/state.rs`.
    ///
    /// Returns immediately for a tightening (nothing to register — a tightening can never
    /// introduce a payee, since any addition is a loosening by `classify`), so the emergency
    /// brake stays synchronous. A loosening that introduces payees registers them on the
    /// token first and commits in a callback; see `commit_rule`.
    ///
    /// An assertion passed alongside a tightening is ignored rather than rejected, and its
    /// nonce is left unspent.
    pub fn set_rule(
        &mut self,
        node: AccountId,
        rule: Rule,
        assertion: Option<Assertion>,
    ) -> PromiseOrValue<bool> {
        self.assert_admin();
        let change = match self.state.rule_of(&node) {
            Some(current) => classify(&current, &rule),
            None => Change::Widening,
        };
        if change == Change::Widening {
            let assertion = assertion.unwrap_or_else(|| {
                env::panic_str("this change loosens the rule, so it needs a passkey assertion")
            });
            self.consume_assertion(
                &assertion,
                ACTION_SET_RULE,
                &set_rule_payload(&node, &rule),
            );
        }
        self.commit_rule(node, rule, change == Change::Widening)
    }

    /// Add `payee` to `node`'s allow-list. **ADMIN only, and always gated:** adding a payee
    /// loosens the rule.
    ///
    /// There is no rule argument. What gets signed over is the stored rule with `payee`
    /// added, derived inside the contract, so again nothing caller-supplied is hashed. The
    /// action tag is [`ACTION_ADD_PAYEE`], **not** `set_rule`'s: the two reach different
    /// states now that `set_rule` resets the ledger, so a shared tag would let an assertion
    /// signed to add a payee be redirected into a rule change that also wipes the ledger.
    ///
    /// Does not reset the ledger: the payee list has nothing to do with the budget
    /// arithmetic, and free headroom would be a loosening nobody signed for.
    pub fn add_payee(&mut self, node: AccountId, payee: AccountId, assertion: Assertion) -> Promise {
        self.assert_admin();
        let current = self
            .state
            .rule_of(&node)
            .unwrap_or_else(|| env::panic_str("that node has no rule to add a payee to"));
        let proposed = current
            .with_payee(payee.clone())
            .unwrap_or_else(|e| env::panic_str(&e));
        // Also catches the no-op: adding a payee that is already listed classifies as a
        // tightening, and burning an assertion on nothing is worse than a clear error.
        require!(
            classify(&current, &proposed) == Change::Widening,
            "that payee is already on the list"
        );
        self.consume_assertion(
            &assertion,
            ACTION_ADD_PAYEE,
            &set_rule_payload(&node, &proposed),
        );

        match self.commit_rule(node, proposed, false) {
            PromiseOrValue::Promise(p) => p,
            // Unreachable: the `Widening` check above means `payee` is new to the list, so
            // `commit_rule` always has exactly one payee to register.
            PromiseOrValue::Value(_) => {
                env::panic_str("internal: add_payee introduced no new payee")
            }
        }
    }

    /// Settle `commit_rule`. Returns whether the rule was applied.
    ///
    /// Two ways this applies nothing and says so rather than panicking: a `storage_deposit`
    /// failed, or the node's record changed while the deposits were in flight, so the rule
    /// the assertion was verified against is no longer the current one. In both cases the
    /// admin must retry with a fresh assertion — the old one's nonce is spent.
    ///
    /// # Why `#[private]` is not enough here
    ///
    /// This is the one method in the contract that must stay exported, because it is a promise
    /// target. It is also the one place where `#[private]` is load-bearing — and in *this*
    /// design `#[private]` means less than it looks like it means. It checks that the
    /// predecessor is this account, and the agent's function-call keys live **on this
    /// account**, so an agent key arrives with exactly that predecessor. On its own,
    /// `#[private]` would let any key on the wallet account call this with an arbitrary rule
    /// and `reset_ledger: true` — an unsigned rule change and a budget wipe.
    ///
    /// So it is paired with a check that this really is a callback: `deposits` is how many
    /// `storage_deposit` promises `commit_rule` dispatched, and the promise results actually
    /// present must match. A direct function call has none, and a function-call access key
    /// cannot build a promise chain, so there is no way to fake one.
    ///
    /// `rule` arrives through the promise as the contract's own bytes rather than a caller's,
    /// and is re-parsed from JSON on the way in, so it is normalised again regardless.
    #[private]
    pub fn on_payees_registered(
        &mut self,
        node: AccountId,
        rule: Rule,
        version: Option<u64>,
        reset_ledger: bool,
        deposits: u64,
    ) -> bool {
        require!(
            deposits > 0 && env::promise_results_count() == deposits,
            "this method is a callback; it is not callable directly"
        );
        for i in 0..deposits {
            // The return value is of no interest — only whether the deposit went through.
            // A `TooLong` therefore counts as success: the promise succeeded and merely
            // returned more than fits the bound. Only `Failed` means the deposit did not
            // happen.
            if matches!(
                env::promise_result_checked(i, STORAGE_DEPOSIT_RESULT_LIMIT),
                Err(PromiseError::Failed)
            ) {
                env::log_str(&format!(
                    "commit_rule: storage_deposit {} of {deposits} failed, {node}'s rule not \
                     applied; every payee on the list must be able to receive a transfer",
                    i + 1
                ));
                return false;
            }
        }
        if self.state.version_of(&node) != version {
            env::log_str(&format!(
                "commit_rule: {node}'s rule changed while the deposits were in flight, not \
                 applied; retry with a fresh assertion"
            ));
            return false;
        }
        self.state
            .put_rule(&node, rule, reset_ledger, env::block_timestamp_ms());
        true
    }

    /// Take `payee` off `node`'s allow-list. **ADMIN only, never gated** — removing a payee
    /// is a tightening, and tightening is the emergency brake.
    ///
    /// Synchronous: it introduces no payee, so there is nothing to register and no reason to
    /// make the brake wait on another contract.
    ///
    /// Idempotent: removing a payee that is not on the list succeeds and changes nothing.
    /// "Make sure this payee cannot be paid" must not fail because it is already true.
    ///
    /// No ledger reset, for the same reason as `add_payee`.
    pub fn remove_payee(&mut self, node: AccountId, payee: AccountId) {
        self.assert_admin();
        let current = self
            .state
            .rule_of(&node)
            .unwrap_or_else(|| env::panic_str("that node has no rule to remove a payee from"));
        let proposed = current.without_payee(&payee);
        if proposed == current {
            return;
        }
        // An invariant, not an input check: `without_payee` can only shorten the list, so a
        // widening here would mean the comparator or `without_payee` is broken.
        require!(
            classify(&current, &proposed) == Change::Tightening,
            "internal: removing a payee must tighten"
        );
        self.state
            .put_rule(&node, proposed, false, env::block_timestamp_ms());
    }

    // ===================================================================================
    // The account-wide pause
    // ===================================================================================

    /// Pause or unpause the whole account. **ADMIN only.** Pausing is free; unpausing needs a
    /// passkey assertion.
    ///
    /// The same asymmetry as everywhere else in this contract, applied to the one switch that
    /// covers every node at once: `set_paused(true)` takes capability away and must work
    /// instantly, because a gate on the emergency brake is worse than no gate. `set_paused
    /// (false)` hands it back and is therefore gated.
    ///
    /// The assertion is signed under [`ACTION_UNPAUSE`] over an empty payload — there is no
    /// node and no rule to bind, so the nonce and the contract id are the whole of it. The
    /// separate tag is what stops an unpause assertion being redirected into a rule change,
    /// and the other way round; `an_unpause_assertion_cannot_widen_a_rule` pins it.
    ///
    /// Task 6's refusal code 2 means paused-by-account **or** paused-by-rule.
    pub fn set_paused(&mut self, paused: bool, assertion: Option<Assertion>) {
        self.assert_admin();
        if !paused {
            let assertion = assertion.unwrap_or_else(|| {
                env::panic_str("unpausing the account loosens it, so it needs a passkey assertion")
            });
            self.consume_assertion(&assertion, ACTION_UNPAUSE, &[]);
        }
        self.paused = paused;
    }

    // ===================================================================================
    // The payment path
    // ===================================================================================

    /// Pay `payee` `amount` of `token`, if this caller's node allows it. **Open to any
    /// caller, and that is the design** — the rule for the node derived from
    /// `predecessor_account_id` is the whole of the authorisation, so a caller with no rule
    /// is refused with code 1 rather than rejected at the door.
    ///
    /// # A refusal is not an error
    ///
    /// Every policy refusal **returns normally**: it writes a [`Decision`] to the ring
    /// buffer, emits an event, and answers `Outcome::Refused(code)` in a transaction that
    /// succeeds. Nothing here panics on a refusal, and that is the single most important
    /// property of this method. `env::panic_str` would roll back the ring-buffer write and
    /// leave a failed transaction with no on-chain record of *why* — and the refusal is the
    /// product, so it has to be durable and legible. (Contrast the ADMIN methods above, which
    /// panic freely: a failed admin call is not a product feature.)
    ///
    /// The seven codes and the order they are checked in live in `spend.rs`; the sentence
    /// each one reads as lives in `decision.rs`, and a refusal carries both on the wire.
    ///
    /// # Why `token` is an argument
    ///
    /// Because otherwise refusal code 3 could not exist. A contract that assumed its own
    /// `token` would silently pay out of whatever the rule names, and "this node may only
    /// spend USDC" would be a sentence with no check behind it. The caller says which token
    /// it believes it is spending, and the rule decides whether it is right.
    ///
    /// # Reserve, then dispatch
    ///
    /// `ft_transfer` is a cross-contract call, and other `spend` calls arrive while it is in
    /// flight. So `amount` goes onto the node's `spent` **before** the transfer is dispatched:
    /// a second agent in the same block sees the reservation and is refused with code 6
    /// rather than spending the same headroom twice. If the transfer then fails, `on_transfer`
    /// puts the reservation back. This is the one place in the contract where a bug silently
    /// loses money or silently loses a limit.
    ///
    /// # Zero deposit
    ///
    /// Not `#[payable]`: a function-call access key cannot attach a deposit, and an agent
    /// holds exactly such a key. The one yoctoNEAR that NEP-141 requires on `ft_transfer` is
    /// attached by this contract out of the wallet account's own balance.
    ///
    /// # What the caller gets back
    ///
    /// `Outcome` either way, so a caller reads one shape: `{"status":"refused","code":4,
    /// "reason":"…"}` immediately on a refusal, or the callback's `{"status":"allowed"}` /
    /// `{"status":"failed"}` once the transfer has resolved.
    pub fn spend(
        &mut self,
        token: AccountId,
        payee: AccountId,
        amount: U128,
    ) -> PromiseOrValue<Outcome> {
        let agent = env::predecessor_account_id();
        let node = node_of(&agent);
        let now_ms = env::block_timestamp_ms();
        // Both `None` for a caller whose id does not derive to a node at all, which
        // `evaluate` refuses with the same code as a node that has no rule: from the chain's
        // side the two are one fact, that this caller has no budget.
        let rule = node.as_ref().and_then(|n| self.state.rule_of(n));
        let spent = node.as_ref().map_or(0, |n| self.state.spent_in_period(n, now_ms));

        let verdict = evaluate(
            rule.as_ref(),
            &Attempt {
                token: &token,
                payee: &payee,
                amount: amount.0,
                spent,
                now_ms,
                account_paused: self.paused,
            },
        );

        if let Err(code) = verdict {
            let entry = Decision {
                agent,
                node,
                payee,
                amount: amount.0,
                outcome: Outcome::Refused(code),
                // The untouched figure: a refusal reserves nothing.
                spent_after: spent,
                timestamp_ms: now_ms,
            };
            // A caller with no rule goes in its own small ring. `spend` is open to anyone on
            // NEAR, so without the split, twenty calls from one stranger would evict every
            // real decision from the log the demo reads — see `push_stranger_decision`. The
            // condition is literally "no rule", which is exactly when `evaluate` answers
            // code 1.
            if rule.is_none() {
                decision::emit(
                    decision::EVENT_REFUSED,
                    decision::RING_STRANGERS,
                    self.state.strangers_written(),
                    &entry,
                );
                self.state.push_stranger_decision(entry);
            } else {
                self.record(decision::EVENT_REFUSED, entry);
            }
            return PromiseOrValue::Value(Outcome::Refused(code));
        }

        // `evaluate` returning `Ok` means it found a rule, which means it had a node.
        let node =
            node.unwrap_or_else(|| env::panic_str("internal: an allowed payment with no node"));

        // The reservation, before anything is dispatched.
        self.state.add_spent(&node, amount.0, now_ms);
        let spent_after = self.state.spent_in_period(&node, now_ms);
        // Read after the reservation, because `add_spent` rolls an elapsed window first. The
        // callback needs to know which ledger this reservation belongs to — the window and
        // the epoch together — so that a release cannot land on one that rolled or was reset
        // in the meantime; see `State::release_reservation`.
        let reserved = self
            .state
            .reservation_of(&node, now_ms)
            .unwrap_or_else(|| env::panic_str("internal: a reserved node with no ledger"));

        let record_id = self.record(
            decision::EVENT_ALLOWED,
            Decision {
                agent,
                node: Some(node.clone()),
                payee: payee.clone(),
                amount: amount.0,
                outcome: Outcome::Allowed,
                spent_after,
                timestamp_ms: now_ms,
            },
        );

        PromiseOrValue::Promise(
            ext_ft::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                // Nothing of the caller's leftover gas goes to the token contract.
                .with_unused_gas_weight(0)
                .ft_transfer(payee, amount, None)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(TRANSFER_CALLBACK_GAS)
                        .with_unused_gas_weight(0)
                        .on_transfer(node, record_id, amount, reserved),
                ),
        )
    }

    /// Settle a dispatched payment. Returns what actually happened.
    ///
    /// On success the record stands as `Allowed` and an event says so. On failure the
    /// reservation is **released** and the record is rewritten as `Failed`.
    ///
    /// `Failed` carries no error text, and that is not laziness: a NEAR callback is told only
    /// *that* a promise failed — `PromiseResult::Failed` has no payload — so any message here
    /// would be invented. The reason is in the failed receipt, which the explorer shows.
    ///
    /// # Why `#[private]` is not enough here
    ///
    /// The same reason as `on_payees_registered`, and it is worth saying twice. `#[private]`
    /// checks that the predecessor is this account, and the agent's function-call keys live
    /// **on this account** — so an agent key arrives with exactly that predecessor and sails
    /// through. On its own, `#[private]` would let any key on the wallet account call this
    /// with any `node`, `amount`, `record_id` and `reserved` it liked: free headroom on a
    /// node, and a rewritten decision log.
    ///
    /// So it is paired with a check that this really is a callback. `ft_transfer` is dispatched
    /// as exactly one promise, so exactly one promise result must be present; a direct
    /// function call has none, and a function-call access key cannot build a promise chain.
    /// `on_transfer_cannot_be_driven_by_an_agent_key` calls it from a key on the wallet
    /// account — the strongest form of the test, because `#[private]` is satisfied for that
    /// caller and the callback check is the only thing left to refuse it.
    #[private]
    pub fn on_transfer(
        &mut self,
        node: AccountId,
        record_id: u64,
        amount: U128,
        reserved: Reservation,
    ) -> Outcome {
        require!(
            env::promise_results_count() == 1,
            "this method is a callback; it is not callable directly"
        );
        // Only `Failed` means the transfer did not happen. A result too long for the bound
        // still succeeded, and nothing here reads the value — NEP-141's `ft_transfer` returns
        // none.
        let failed = matches!(
            env::promise_result_checked(0, FT_TRANSFER_RESULT_LIMIT),
            Err(PromiseError::Failed)
        );
        if !failed {
            // Nothing to rewrite: the record already says `Allowed`, and overwriting its
            // `spent_after` with the figure as it stands now would credit this payment with
            // whatever other agents have spent in the meantime.
            self.announce(decision::EVENT_SETTLED, record_id, &node, amount.0);
            return Outcome::Allowed;
        }

        let now_ms = env::block_timestamp_ms();
        let released = self
            .state
            .release_reservation(&node, amount.0, &reserved, now_ms);
        if !released {
            // The ledger the reservation belonged to is gone — the window rolled, or a signed
            // widening reset it — so its `spent` was zeroed with it and there is nothing to
            // give back. Taking the amount off the *current* ledger would hand out headroom
            // nobody paid for.
            env::log_str(&format!(
                "on_transfer: {node}'s transfer of {} failed after its budget ledger moved on \
                 (reserved against window {} epoch {}); nothing to release",
                amount.0, reserved.window_began_ms, reserved.epoch
            ));
        }
        let spent_after = self.state.spent_in_period(&node, now_ms);
        self.state
            .settle_decision(record_id, Outcome::Failed, spent_after);
        self.announce(decision::EVENT_FAILED, record_id, &node, amount.0);
        Outcome::Failed
    }

    // ===================================================================================
    // Views
    // ===================================================================================

    /// The last 20 decisions of callers whose node has a rule, newest first. A view call is
    /// free, synchronous and unthrottled, so there is no indexer anywhere in this project.
    ///
    /// Refusals of callers with **no** rule are not here; they are in
    /// `recent_stranger_decisions`, so that a stranger cannot evict these. `decision_log`
    /// returns both.
    ///
    /// An `Allowed` entry means policy allowed it and the transfer was dispatched. It becomes
    /// `Failed` if the transfer failed, one block later; it is not rewritten on success, so
    /// `Allowed` covers both "settled" and the one block where it is still in flight. The
    /// events distinguish the two for anyone who needs it.
    pub fn recent_decisions(&self) -> Vec<Decision> {
        self.state.recent_decisions()
    }

    /// How many decisions have ever been recorded. The ring holds the last 20, so this is the
    /// only way to tell 20 from 2,000.
    ///
    /// A plain number, not a decimal string: the string convention is for token balances,
    /// which overflow a JavaScript number, and a count of payments does not.
    pub fn decision_count(&self) -> u64 {
        self.state.decisions_written()
    }

    /// The last few refusals of callers whose derived node has **no rule** — refusal code 1 —
    /// newest first, out of their own small ring.
    ///
    /// Separate from `recent_decisions` because `spend` is open to anyone on NEAR: without the
    /// split, twenty calls from a stranger would evict every real decision from the log this
    /// demo reads. These refusals are still worth showing — "an unknown agent is refused, and
    /// you can see it" is part of what the contract is for — so they are kept, in a space
    /// where they can only crowd out each other.
    pub fn recent_stranger_decisions(&self) -> Vec<Decision> {
        self.state.recent_stranger_decisions()
    }

    /// How many callers with no rule have ever been refused. Where a flood shows up: the ring
    /// stays four long, this number does not.
    pub fn stranger_count(&self) -> u64 {
        self.state.strangers_written()
    }

    /// Both logs and both counts in one call, which is what the demo page reads.
    pub fn decision_log(&self) -> DecisionLog {
        DecisionLog {
            decisions: self.state.recent_decisions(),
            decision_count: self.state.decisions_written(),
            strangers: self.state.recent_stranger_decisions(),
            stranger_count: self.state.strangers_written(),
        }
    }

    /// Every reason this contract can refuse a payment: the code and the sentence, from the
    /// one table in `decision.rs`. Published so the demo page can render reasons without
    /// keeping its own copy of the mapping, which would drift the first time one is reworded.
    pub fn refusal_codes(&self) -> Vec<RefusalView> {
        REFUSALS
            .iter()
            .map(|r| RefusalView { code: r.code, reason: r.reason.to_string() })
            .collect()
    }

    /// The node an agent account draws on: everything after the first `.`. `None` for an id
    /// with no separator, which is refused with code 1. Exposed so the demo page can show
    /// which budget a key belongs to before it spends anything.
    pub fn node_for(&self, agent: AccountId) -> Option<AccountId> {
        node_of(&agent)
    }

    pub fn rule_of(&self, node: AccountId) -> Option<Rule> {
        self.state.rule_of(&node)
    }

    pub fn payees_of(&self, node: AccountId) -> Vec<AccountId> {
        self.state
            .rule_of(&node)
            .map(|r| r.payees().to_vec())
            .unwrap_or_default()
    }

    /// How many accepted loosenings this node has had. `None` if it has no rule.
    ///
    /// Each one started the budget ledger fresh, and each one needed a passkey, so this is
    /// also the number of times a human signed off a reset. A tightening does not advance it.
    pub fn epoch_of(&self, node: AccountId) -> Option<u32> {
        self.state.record_of(&node).map(|r| r.epoch)
    }

    /// What `node` has spent in the budget window containing this block. Zero for a node with
    /// no rule, zero in a window that has rolled, and zero right after an accepted loosening.
    /// A tightening leaves it alone.
    pub fn spent_in_period(&self, node: AccountId) -> U128 {
        U128(self.state.spent_in_period(&node, env::block_timestamp_ms()))
    }

    /// When the current budget window began, in ms. `None` for a node with no rule. The
    /// window ends at this plus the rule's `period_ms`; the demo page draws the bar from it.
    pub fn window_began_ms(&self, node: AccountId) -> Option<u64> {
        self.state.window_began_ms(&node, env::block_timestamp_ms())
    }

    /// Everything the demo page needs about one node in a single view call: the rule, the
    /// epoch, the version, the window start and what has been spent in it.
    pub fn node_record(&self, node: AccountId) -> Option<state::NodeRecord> {
        let mut r = self.state.record_of(&node).cloned()?;
        // The stored figures can be stale until the next spend rolls the window. Report what
        // a spend arriving now would see, not what was last written.
        r.spent = self.state.spent_in_period(&node, env::block_timestamp_ms());
        r.window_began_ms = self
            .state
            .window_began_ms(&node, env::block_timestamp_ms())
            .unwrap_or(r.window_began_ms);
        Some(r)
    }

    /// Every node that has a rule, for the demo page's overview.
    pub fn node_ids(&self) -> Vec<AccountId> {
        self.state.node_ids()
    }

    /// Verify a WebAuthn assertion and report whether it passed. Changes no state, consumes
    /// no nonce, checks no caller.
    ///
    /// It exists to measure what P-256 verification costs inside the contract, and it stays
    /// after the gated methods land as the project's gas-measurement surface: it is the one
    /// place where the cost of the curve arithmetic can be read without the rest of a
    /// transaction's cost mixed in.
    ///
    /// A `true` means the holder of this public key signed this exact challenge and the
    /// authenticator asserted user verification. It does **not** mean the key is
    /// hardware-backed: this probe takes a public key as an argument, so anyone can pass one
    /// they minted in a script and get a `true` with no device and no human involved. That is
    /// not a weakness in the verification — it is where the trust boundary actually sits. See
    /// the `webauthn` module header.
    ///
    /// Anything malformed returns `false` rather than panicking.
    pub fn probe_verify(
        &self,
        pubkey_sec1: Base64VecU8,
        challenge: Base64VecU8,
        authenticator_data: Base64VecU8,
        client_data_json: String,
        signature_der: Base64VecU8,
    ) -> bool {
        let Ok(challenge) = <[u8; 32]>::try_from(challenge.0.as_slice()) else {
            return false;
        };
        // The credential id is irrelevant to verification: the probe takes the public key
        // directly instead of looking a credential up in state.
        let Ok(cred) = Credential::try_new(Vec::new(), pubkey_sec1.into(), 0) else {
            return false;
        };
        verify_assertion(
            &cred,
            &challenge,
            authenticator_data.as_ref(),
            &client_data_json,
            signature_der.as_ref(),
        )
        .is_ok()
    }
}

/// Internal helpers. Outside the `#[near]` block, so none of these is an exported contract
/// method — which for anything that writes state is the only reliable protection in this
/// design. See `commit_rule` and `on_payees_registered` for why `#[private]` is not.
impl LeashAccount {
    /// Commit a rule for `node`, registering any payee it introduces on the token first.
    /// Returns whether the rule was applied.
    ///
    /// **Not in the `#[near]` impl, deliberately.** It used to be, guarded by `#[private]`,
    /// which was a hole: `#[private]` only checks that the predecessor is this account, and in
    /// this design the agent's function-call keys live on this account. So
    /// `commit_rule(node, any_rule, reset_ledger: true)` was an exported method reachable by
    /// an agent key with no `assert_admin` and no assertion — an arbitrary rule and a budget
    /// wipe. The only thing stopping it was the `method_names = ["spend"]` restriction on the
    /// key, which is a real defence but lived in a deploy script, one typo away from gone.
    /// It is never a promise target, so the fix is for the exported method not to exist at
    /// all. `commit_rule_is_not_an_exported_method` pins that.
    ///
    /// Why a callback at all: NEP-141 `ft_transfer` fails for a receiver with no storage
    /// deposit on the token, so a payee that is on the allow-list but not registered would
    /// make a legitimate payment fail for a reason that has nothing to do with policy — which
    /// on recording day reads as a broken product, not a policy decision. So the invariant is
    /// **"on the list" means "can be paid, with this rule's token"**, and it holds on every
    /// path that writes a payee.
    ///
    /// An earlier version enforced it in `add_payee` only, while `set_rule` wrote any payee
    /// list it liked with no registration at all. Both paths go through here now.
    ///
    /// All-or-nothing: if any deposit fails the rule is not applied at all, so the list never
    /// contains a payee that cannot receive a transfer. Deposits that did succeed stay
    /// registered on the token — 0.00125 NEAR for an account that is not on the list, which is
    /// harmless and leaves no contract state orphaned.
    ///
    /// Nothing is written before the dispatch, so a failure has nothing to roll back. The
    /// assertion's nonce is already spent by the time this is called and is never given back:
    /// a nonce that could be un-spent is a replay window. The admin retries with a fresh one.
    fn commit_rule(
        &mut self,
        node: AccountId,
        rule: Rule,
        reset_ledger: bool,
    ) -> PromiseOrValue<bool> {
        let stored = self.state.rule_of(&node);
        // A payee is "already registered" only against the token it was registered on. A rule
        // change that switches `token` therefore makes every payee new again, even though the
        // account list is untouched: a storage deposit on the old token says nothing about the
        // new one, and without this the whole list would end up unregistered and the first
        // payment would fail for a reason that is not policy. (A token change is always a
        // widening by `classify`, so this path is gated.)
        let same_token = stored
            .as_ref()
            .is_some_and(|prev| prev.token() == rule.token());
        let already: Vec<AccountId> = if same_token {
            stored.map(|r| r.payees().to_vec()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let new_payees: Vec<AccountId> = rule
            .payees()
            .iter()
            .filter(|p| !already.contains(p))
            .cloned()
            .collect();

        if new_payees.is_empty() {
            self.state
                .put_rule(&node, rule, reset_ledger, env::block_timestamp_ms());
            return PromiseOrValue::Value(true);
        }
        require!(
            new_payees.len() <= MAX_NEW_PAYEES_PER_CALL,
            "too many payees to register in one call; add them in smaller batches (note that \
             changing a rule's token makes every payee need registering again)"
        );

        let token = rule.token().clone();
        let mut deposits = ext_ft::ext(token.clone())
            .with_attached_deposit(PAYEE_STORAGE_DEPOSIT)
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .storage_deposit(Some(new_payees[0].clone()));
        for payee in &new_payees[1..] {
            deposits = deposits.and(
                ext_ft::ext(token.clone())
                    .with_attached_deposit(PAYEE_STORAGE_DEPOSIT)
                    .with_static_gas(STORAGE_DEPOSIT_GAS)
                    .storage_deposit(Some(payee.clone())),
            );
        }

        let version = self.state.version_of(&node);
        PromiseOrValue::Promise(deposits.then(
            Self::ext(env::current_account_id())
                .with_static_gas(COMMIT_CALLBACK_GAS)
                .on_payees_registered(
                    node,
                    rule,
                    version,
                    reset_ledger,
                    new_payees.len() as u64,
                ),
        ))
    }

    /// Write `entry` to the decision ring, emit `event` for it, and return the id the ring
    /// gave it. The id is what `on_transfer` uses to find the record again.
    ///
    /// The two always happen together, so neither `spend` nor the callback can log a decision
    /// without announcing it or announce one it never logged.
    fn record(&mut self, event: &str, entry: Decision) -> u64 {
        let id = self.state.push_decision(entry.clone());
        decision::emit(event, decision::RING_DECISIONS, id, &entry);
        id
    }

    /// Emit `event` for decision `record_id`, carrying the whole record when the ring still
    /// holds it.
    ///
    /// It may not: twenty later decisions can land while one transfer is in flight, and the
    /// ring is exactly twenty. The settlement still happened, so it is still announced — with
    /// what the callback knows rather than nothing at all. See `decision::emit_evicted`.
    fn announce(&self, event: &str, record_id: u64, node: &AccountId, amount: u128) {
        match self.state.decision(record_id) {
            Some(entry) => decision::emit(event, decision::RING_DECISIONS, record_id, entry),
            None => decision::emit_evicted(event, record_id, node, amount),
        }
    }

    /// Every method in this task is an ADMIN operation, so every one of them starts here.
    ///
    /// `predecessor_account_id`, not `signer_account_id`: the predecessor is who called us,
    /// which is what an authorisation check wants. The signer is whoever signed the
    /// transaction at the top of the chain, and a contract in between could be anyone.
    fn assert_admin(&self) {
        require!(
            env::predecessor_account_id() == self.admin,
            "only the admin may change rules"
        );
    }

    /// The challenge an active credential must sign for `action` over `payload`, base64.
    /// Shared by the three `challenge_for*` views so they cannot disagree with
    /// `consume_assertion` about the nonce or the contract id.
    fn challenge(&self, action: &str, payload: &[u8], credential_id: &[u8]) -> Base64VecU8 {
        let nonce = self
            .state
            .active_credential(credential_id)
            .map(Credential::nonce)
            .unwrap_or_else(|| env::panic_str("no such active credential"));
        gate_challenge(action, payload, nonce, &env::current_account_id())
            .to_vec()
            .into()
    }

    /// Verify an assertion against the challenge for `action` over `payload`, and spend the
    /// credential's nonce. Panics on anything wrong — these are ADMIN operations, not the
    /// agent payment path, so a clear panic is the right failure. (The no-panic rule is
    /// `spend`'s, in Task 6.)
    ///
    /// The nonce is spent only after the signature verifies, so a rejected assertion costs
    /// nothing; and it is spent in the same call that applies the change, so a panic further
    /// on rolls both back together.
    ///
    /// `action` is what keeps one operation's signature from authorising another — see
    /// `contract/src/challenge.rs`.
    fn consume_assertion(&mut self, assertion: &Assertion, action: &str, payload: &[u8]) {
        let id: Vec<u8> = assertion.credential_id.clone().into();
        // Cloned because `verify_assertion` borrows the credential while spending the nonce
        // needs `&mut self.state`. A credential is about 100 bytes.
        let cred = self
            .state
            .active_credential(&id)
            .cloned()
            .unwrap_or_else(|| env::panic_str("no such active credential"));

        let expected = gate_challenge(action, payload, cred.nonce(), &env::current_account_id());
        verify_assertion(
            &cred,
            &expected,
            assertion.authenticator_data.as_ref(),
            &assertion.client_data_json,
            assertion.signature_der.as_ref(),
        )
        .unwrap_or_else(|e| env::panic_str(&format!("assertion rejected: {e:?}")));

        self.state.spend_nonce(&id);
    }
}
