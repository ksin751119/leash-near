pub mod challenge;
pub mod node;
pub mod rule;
pub mod state;
pub mod webauthn;

use crate::challenge::{gate_challenge, set_rule_payload, ACTION_SET_RULE};
use crate::rule::{classify, Change, Rule};
use crate::state::{State, MAX_CREDENTIALS};
use crate::webauthn::{verify_assertion, Assertion, Credential};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{
    env, ext_contract, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};

/// Storage deposit paid to the token contract so a payee can receive `ft_transfer`. 0.00125
/// NEAR is the usual NEP-141 figure; a token that wants more rejects the call and the payee
/// does not go on the list.
const PAYEE_STORAGE_DEPOSIT: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);

/// Gas for the token's `storage_deposit`, and for the callback that reads its result.
/// Deliberately generous: `add_payee` is an ADMIN operation called a handful of times, and
/// the alternative to generous is an admin staring at a half-applied change.
const STORAGE_DEPOSIT_GAS: Gas = Gas::from_tgas(10);
const ADD_PAYEE_CALLBACK_GAS: Gas = Gas::from_tgas(10);

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
            self.state.credential(cred.id()).is_none(),
            "that credential id is already registered; rotate to a new id instead"
        );
        require!(
            self.state.credential_count() < MAX_CREDENTIALS,
            "too many registered credentials"
        );
        self.state.insert_credential(cred);
    }

    /// The registered credential ids, base64. The demo page needs them to ask the browser
    /// for an assertion from a specific credential.
    pub fn credential_ids(&self) -> Vec<Base64VecU8> {
        self.state
            .credential_ids()
            .into_iter()
            .map(Base64VecU8::from)
            .collect()
    }

    /// The nonce a client must bake into its next challenge for this credential, or `None`
    /// if it is not registered.
    pub fn credential_nonce(&self, credential_id: Base64VecU8) -> Option<u64> {
        self.state
            .credential(credential_id.as_ref())
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
    /// Panics if the credential is not registered: a challenge computed against a guessed
    /// nonce is worse than no answer.
    pub fn challenge_for(
        &self,
        node: AccountId,
        rule: Rule,
        credential_id: Base64VecU8,
    ) -> Base64VecU8 {
        let nonce = self
            .state
            .credential(credential_id.as_ref())
            .map(Credential::nonce)
            .unwrap_or_else(|| env::panic_str("no such registered credential"));
        gate_challenge(
            ACTION_SET_RULE,
            &set_rule_payload(&node, &rule),
            nonce,
            &env::current_account_id(),
        )
        .to_vec()
        .into()
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
    /// Every accepted call advances the node's epoch, which starts a fresh spent ledger
    /// rather than letting old spending count against the new rule.
    ///
    /// An assertion passed alongside a tightening is ignored rather than rejected, and its
    /// nonce is left unspent.
    pub fn set_rule(&mut self, node: AccountId, rule: Rule, assertion: Option<Assertion>) {
        self.assert_admin();
        let change = match self.state.rule_of(&node) {
            Some(current) => classify(&current, &rule),
            None => Change::Widening,
        };
        if change == Change::Widening {
            let assertion = assertion.unwrap_or_else(|| {
                env::panic_str("this change loosens the rule, so it needs a passkey assertion")
            });
            self.consume_assertion(&assertion, &set_rule_payload(&node, &rule));
        }
        self.state.put_rule(&node, rule, true);
    }

    /// Add `payee` to `node`'s allow-list and register it for storage on the token.
    /// **ADMIN only, and always gated:** adding a payee loosens the rule.
    ///
    /// There is no rule argument. What gets signed over is the stored rule with `payee`
    /// added, derived inside the contract, so again nothing caller-supplied is hashed. The
    /// challenge is the same one `set_rule` uses — see `challenge.rs` for why that is
    /// deliberate.
    ///
    /// NEP-141 `ft_transfer` fails for a receiver with no storage deposit, so putting a payee
    /// on the list also pays `storage_deposit` for it on the token named in the rule. Without
    /// that, a legitimate payment later fails for a reason that has nothing to do with policy
    /// and the whole demo reads as a policy bug.
    ///
    /// That is a cross-contract call, so it can fail. The payee therefore goes on the list in
    /// the **callback**, only if the deposit succeeded — "on the list" keeps meaning "can be
    /// paid". The assertion's nonce is spent before the dispatch and is never given back: a
    /// nonce that could be un-spent is a replay window.
    ///
    /// The deposit comes out of this contract account's own balance, so an admin calling with
    /// a function-call key (which cannot attach NEAR) still works.
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
        self.consume_assertion(&assertion, &set_rule_payload(&node, &proposed));

        let version = self
            .state
            .version_of(&node)
            .expect("the node's record was read a moment ago");

        ext_ft::ext(current.token().clone())
            .with_attached_deposit(PAYEE_STORAGE_DEPOSIT)
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .storage_deposit(Some(payee.clone()))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(ADD_PAYEE_CALLBACK_GAS)
                    .on_payee_registered(node, payee, version),
            )
    }

    /// Settle `add_payee`. Returns whether the payee went on the list.
    ///
    /// Three ways this does nothing and says so rather than panicking: the storage deposit
    /// failed, the node's rule changed while the deposit was in flight (so the rule that was
    /// signed for is no longer the current one), or the node lost its rule entirely. In each
    /// case the admin must retry with a fresh assertion — the old one's nonce is spent.
    #[private]
    pub fn on_payee_registered(
        &mut self,
        node: AccountId,
        payee: AccountId,
        version: u64,
        #[callback_result] deposit: Result<near_sdk::serde_json::Value, PromiseError>,
    ) -> bool {
        if deposit.is_err() {
            env::log_str(&format!(
                "add_payee: storage_deposit failed, {payee} not added to {node}"
            ));
            return false;
        }
        if self.state.version_of(&node) != Some(version) {
            env::log_str(&format!(
                "add_payee: {node}'s rule changed while the deposit was in flight, \
                 {payee} not added; retry with a fresh assertion"
            ));
            return false;
        }
        // Re-derived from the stored rule, which the version check has just proved is the
        // one the assertion was verified against.
        let Some(current) = self.state.rule_of(&node) else {
            env::log_str(&format!("add_payee: {node} has no rule, {payee} not added"));
            return false;
        };
        match current.with_payee(payee.clone()) {
            Ok(proposed) => {
                // Not an epoch bump: the payee list has nothing to do with the budget
                // arithmetic, and a fresh ledger would be a loosening nobody signed for.
                self.state.put_rule(&node, proposed, false);
                true
            }
            Err(e) => {
                env::log_str(&format!("add_payee: {payee} not added to {node}: {e}"));
                false
            }
        }
    }

    /// Take `payee` off `node`'s allow-list. **ADMIN only, never gated** — removing a payee
    /// is a tightening, and tightening is the emergency brake.
    ///
    /// Idempotent: removing a payee that is not on the list succeeds and changes nothing.
    /// "Make sure this payee cannot be paid" must not fail because it is already true.
    ///
    /// No epoch bump, for the same reason as `add_payee`.
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
        self.state.put_rule(&node, proposed, false);
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

    /// The node's ledger epoch, or `None` if it has no rule. Advanced by `set_rule` only.
    pub fn epoch_of(&self, node: AccountId) -> Option<u32> {
        self.state.record_of(&node).map(|r| r.epoch)
    }

    /// What `node` has spent in the current period of its current epoch. Zero for a node
    /// with no rule, and zero immediately after a `set_rule` — the epoch bump moves the node
    /// onto a fresh ledger.
    pub fn spent_in_period(&self, node: AccountId) -> U128 {
        U128(self.state.spent_in_period(&node, env::block_timestamp_ms()))
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

    /// Verify an assertion against the challenge for `payload`, and spend the credential's
    /// nonce. Panics on anything wrong — these are ADMIN operations, not the agent payment
    /// path, so a clear panic is the right failure. (The no-panic rule is `spend`'s, in
    /// Task 6.)
    ///
    /// The nonce is spent only after the signature verifies, so a rejected assertion costs
    /// nothing; and it is spent in the same call that applies the change, so a panic further
    /// on rolls both back together.
    fn consume_assertion(&mut self, assertion: &Assertion, payload: &[u8]) {
        let id: Vec<u8> = assertion.credential_id.clone().into();
        // Cloned because `verify_assertion` borrows the credential while spending the nonce
        // needs `&mut self.state`. A credential is about 100 bytes.
        let cred = self
            .state
            .credential(&id)
            .cloned()
            .unwrap_or_else(|| env::panic_str("no such registered credential"));

        let expected = gate_challenge(
            ACTION_SET_RULE,
            payload,
            cred.nonce(),
            &env::current_account_id(),
        );
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
