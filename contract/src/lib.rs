pub mod challenge;
pub mod node;
pub mod rule;
pub mod state;
pub mod webauthn;

use crate::challenge::{
    gate_challenge, set_rule_payload, ACTION_ADD_PAYEE, ACTION_SET_RULE, ACTION_UNPAUSE,
};
use crate::rule::{classify, Change, Rule};
use crate::state::{State, MAX_CREDENTIALS};
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

/// The slice of NEP-141 this contract calls. `ext_contract` generates the `ext_ft` builder
/// from it; the trait itself is never implemented here, hence the allow.
#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn storage_deposit(&mut self, account_id: Option<AccountId>);
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

#[near]
impl LeashAccount {
    #[init]
    pub fn new(admin: AccountId, token: AccountId) -> Self {
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

    /// Commit a rule for `node`, registering any payee it introduces on the token first.
    /// Returns whether the rule was applied.
    ///
    /// Why a callback at all: NEP-141 `ft_transfer` fails for a receiver with no storage
    /// deposit on the token, so a payee that is on the allow-list but not registered would
    /// make a legitimate payment fail for a reason that has nothing to do with policy — which
    /// on recording day reads as a broken product, not a policy decision. So the invariant is
    /// **"on the list" means "can be paid"**, and it holds on every path that writes a payee.
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
    #[private]
    pub fn commit_rule(
        &mut self,
        node: AccountId,
        rule: Rule,
        reset_ledger: bool,
    ) -> PromiseOrValue<bool> {
        let already: Vec<AccountId> = self
            .state
            .rule_of(&node)
            .map(|r| r.payees().to_vec())
            .unwrap_or_default();
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
            "too many new payees in one call; add them in smaller batches"
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
                .on_payees_registered(node, rule, version, reset_ledger),
        ))
    }

    /// Settle `commit_rule`. Returns whether the rule was applied.
    ///
    /// Two ways this applies nothing and says so rather than panicking: a `storage_deposit`
    /// failed, or the node's record changed while the deposits were in flight, so the rule
    /// the assertion was verified against is no longer the current one. In both cases the
    /// admin must retry with a fresh assertion — the old one's nonce is spent.
    ///
    /// `rule` comes back through the promise as the contract's own bytes, not a caller's, and
    /// `#[private]` means only this contract can call this method. It is re-parsed from JSON
    /// on the way in, so it is normalised again regardless.
    #[private]
    pub fn on_payees_registered(
        &mut self,
        node: AccountId,
        rule: Rule,
        version: Option<u64>,
        reset_ledger: bool,
    ) -> bool {
        let deposits = env::promise_results_count();
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
    // Views
    // ===================================================================================

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

/// Internal helpers. Outside the `#[near]` block, so none of these is callable.
impl LeashAccount {
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
