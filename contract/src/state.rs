//! Contract state: one record per budget node, the spent ledger, and the registered
//! credentials.
//!
//! # What lives where, and why
//!
//! `Rule` has no `epoch` and no `version`: the bytes a passkey signs must be exactly the
//! rule, so anything the contract keeps alongside a rule lives in [`NodeRecord`] instead.
//!
//! - **`epoch`** is part of the spent ledger's key. `set_rule` advances it, which starts a
//!   fresh ledger for the node rather than letting old spending count against a new rule (or
//!   a new rule retroactively free headroom already used). `add_payee` and `remove_payee`
//!   leave it alone: the payee list has nothing to do with the budget arithmetic, and a bump
//!   there would hand the node a fresh period limit nobody signed for.
//! - **`version`** counts every accepted change to the record. It exists so a cross-contract
//!   callback can tell whether the rule it was dispatched against is still the current one
//!   (see `on_payee_registered`); `epoch` cannot do that job, because payee changes do not
//!   bump it.
//!
//! # The spent ledger's key
//!
//! The design doc writes the ledger key as a packed `u64`:
//! `period_bucket = (epoch << 32) | (now_ms / period_ms)`. That packing is unsafe for small
//! periods: `now_ms` is about 1.7e12 today, so any `period_ms` below ~400 makes
//! `now_ms / period_ms` exceed `u32::MAX` and carry into the epoch bits — silently moving a
//! node onto another epoch's ledger. `period_ms` is caller-supplied and only has to be
//! non-zero, so that is reachable.
//!
//! A composite key avoids the question entirely: `(node, epoch, period)` with the period as
//! a full `u64`. Same semantics, no overflow to reason about. See [`LedgerKey`].
//!
//! # Storage bounds
//!
//! The contract account pays the storage staking for all of this, so nothing here may grow
//! without a bound someone chose:
//!
//! - `credentials` is capped at [`MAX_CREDENTIALS`], and a credential is ~100 bytes.
//! - A rule's payee list is capped at `rule::MAX_PAYEES`.
//! - `nodes` grows only when ADMIN configures a new node, and only ADMIN can.
//! - `spent` gains one 16-byte entry per `(node, epoch, period)` that is actually spent in.
//!   That grows slowly and forever: a node on a daily period spending every day adds one
//!   entry a day, and `set_rule` adds a fresh epoch's worth. Bounded in practice by the
//!   demo's lifetime, and worth a pruning method if this ever ran for years. Task 6 owns the
//!   writes, so it is the right place to revisit it.

use crate::rule::Rule;
use crate::webauthn::Credential;
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{near, AccountId, BorshStorageKey};

/// How many passkeys may be registered at once. More than one matters — a single credential
/// is a single point of failure for the emergency path — but the list is bounded because the
/// contract pays to hold it.
pub const MAX_CREDENTIALS: usize = 8;

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum Prefix {
    Nodes,
    Spent,
    Credentials,
}

/// A node's rule plus the two counters that must not be inside the rule.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub rule: Rule,
    /// Advanced by `set_rule`. Part of the spent ledger's key.
    pub epoch: u32,
    /// Advanced by every accepted change. A concurrency token for callbacks.
    pub version: u64,
}

/// `(node, epoch, period)`. Borsh-encoded into the storage key, so the field order here is
/// what separates one node's ledger from another's.
#[near(serializers = [borsh])]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LedgerKey {
    pub node: AccountId,
    pub epoch: u32,
    pub period: u64,
}

#[near(serializers = [borsh])]
pub struct State {
    nodes: IterableMap<AccountId, NodeRecord>,
    spent: LookupMap<LedgerKey, u128>,
    credentials: IterableMap<Vec<u8>, Credential>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            nodes: IterableMap::new(Prefix::Nodes),
            spent: LookupMap::new(Prefix::Spent),
            credentials: IterableMap::new(Prefix::Credentials),
        }
    }

    // --- nodes ------------------------------------------------------------------------

    pub fn record_of(&self, node: &AccountId) -> Option<&NodeRecord> {
        self.nodes.get(node)
    }

    pub fn rule_of(&self, node: &AccountId) -> Option<Rule> {
        self.nodes.get(node).map(|r| r.rule.clone())
    }

    pub fn version_of(&self, node: &AccountId) -> Option<u64> {
        self.nodes.get(node).map(|r| r.version)
    }

    /// Store `rule` for `node`. `bump_epoch` advances the ledger epoch — true for
    /// `set_rule`, false for a payee change (see the module doc comment).
    ///
    /// `version` always advances, so a callback can detect any intervening change.
    pub fn put_rule(&mut self, node: &AccountId, rule: Rule, bump_epoch: bool) {
        let next = match self.nodes.get(node) {
            Some(prev) => NodeRecord {
                rule,
                // Saturating rather than wrapping: wrapping would walk the epoch back onto
                // a ledger that has already been spent in. 2^32 admin rule changes is not a
                // reachable number, and if it were, a stuck epoch is the safe failure.
                epoch: if bump_epoch { prev.epoch.saturating_add(1) } else { prev.epoch },
                version: prev.version.saturating_add(1),
            },
            None => NodeRecord { rule, epoch: 0, version: 0 },
        };
        self.nodes.insert(node.clone(), next);
    }

    /// Every configured node, for the demo page's overview. Bounded by ADMIN's own actions.
    pub fn node_ids(&self) -> Vec<AccountId> {
        self.nodes.keys().cloned().collect()
    }

    // --- the spent ledger -------------------------------------------------------------

    /// The ledger key for `node` at `now_ms` under its current rule and epoch.
    /// `None` when the node has no rule, since the period comes from the rule.
    pub fn ledger_key(&self, node: &AccountId, now_ms: u64) -> Option<LedgerKey> {
        let r = self.nodes.get(node)?;
        // `period_ms == 0` is rejected by `Rule::try_new`, so this cannot divide by zero.
        Some(LedgerKey {
            node: node.clone(),
            epoch: r.epoch,
            period: now_ms / r.rule.period_ms(),
        })
    }

    /// What this node has spent in the current period of the current epoch.
    pub fn spent_in_period(&self, node: &AccountId, now_ms: u64) -> u128 {
        self.ledger_key(node, now_ms)
            .and_then(|k| self.spent.get(&k).copied())
            .unwrap_or(0)
    }

    /// Reserve `amount` against the node's current period. Task 6's `spend` calls this
    /// before dispatching a transfer; Task 5 has it so the epoch's effect on the ledger can
    /// be tested at all.
    ///
    /// Saturating: the caller checks the limit first, and a silent wrap here would hand out
    /// unlimited headroom.
    pub fn add_spent(&mut self, node: &AccountId, amount: u128, now_ms: u64) {
        if let Some(key) = self.ledger_key(node, now_ms) {
            let next = self.spent.get(&key).copied().unwrap_or(0).saturating_add(amount);
            self.spent.insert(key, next);
        }
    }

    /// Release a reservation whose transfer failed. Saturating for the same reason.
    pub fn sub_spent(&mut self, node: &AccountId, amount: u128, now_ms: u64) {
        if let Some(key) = self.ledger_key(node, now_ms) {
            let next = self.spent.get(&key).copied().unwrap_or(0).saturating_sub(amount);
            self.spent.insert(key, next);
        }
    }

    // --- credentials ------------------------------------------------------------------

    pub fn credential(&self, id: &[u8]) -> Option<&Credential> {
        self.credentials.get(&id.to_vec())
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len() as usize
    }

    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.credentials.keys().cloned().collect()
    }

    /// Insert a credential under its own id. The caller checks that the id is new — see
    /// `register_credential`, where re-registration is refused because it would reset the
    /// nonce and re-arm every assertion ever signed under that id.
    pub fn insert_credential(&mut self, cred: Credential) {
        self.credentials.insert(cred.id().to_vec(), cred);
    }

    /// Spend the nonce of a credential that has just verified an assertion.
    pub fn spend_nonce(&mut self, id: &[u8]) {
        self.credentials
            .get_mut(&id.to_vec())
            .expect("credential was looked up a moment ago")
            .spend_nonce();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn acct(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn rule(per_tx: u128, period_limit: u128, period_ms: u64) -> Rule {
        Rule::try_new(
            acct("usdc.testnet"),
            per_tx,
            period_limit,
            period_ms,
            0,
            u64::MAX,
            vec![acct("alice.testnet")],
            false,
        )
        .unwrap()
    }

    /// `State` holds near-sdk collections, which read and write the storage of whatever VM
    /// context is current, so these tests need one.
    fn with_env() {
        testing_env!(VMContextBuilder::new().build());
    }

    const DAY: u64 = 86_400_000;

    /// The heart of the epoch design, and the half the sandbox test cannot reach until
    /// `spend` exists in Task 6: a rule change starts a fresh ledger.
    #[test]
    fn setting_a_rule_zeroes_the_spent_ledger() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        let now = 5 * DAY;

        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        s.add_spent(&node, 7_500, now);
        assert_eq!(s.spent_in_period(&node, now), 7_500);

        // A tightening, at the same instant and the same period: only the epoch moved.
        s.put_rule(&node, rule(500, 5_000, DAY), true);
        assert_eq!(s.record_of(&node).unwrap().epoch, 1);
        assert_eq!(s.spent_in_period(&node, now), 0, "the new epoch inherited the old ledger");
    }

    /// And the old epoch's figure is still there, not destroyed — the bump moves the node
    /// onto a fresh ledger rather than erasing history.
    #[test]
    fn an_epoch_bump_leaves_the_old_ledger_intact() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        let now = 5 * DAY;

        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        s.add_spent(&node, 7_500, now);
        s.put_rule(&node, rule(1_000, 10_000, DAY), true);

        let old = LedgerKey { node: node.clone(), epoch: 0, period: 5 };
        assert_eq!(s.spent.get(&old).copied(), Some(7_500));
        assert_eq!(s.spent_in_period(&node, now), 0);
    }

    /// A payee change must not move the node onto a fresh ledger: nothing about the budget
    /// arithmetic changed, and a free period limit is a loosening nobody signed for.
    #[test]
    fn a_payee_change_leaves_the_ledger_alone() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        let now = 5 * DAY;

        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        s.add_spent(&node, 7_500, now);

        let widened = s.rule_of(&node).unwrap().with_payee(acct("bob.testnet")).unwrap();
        s.put_rule(&node, widened, false);

        assert_eq!(s.record_of(&node).unwrap().epoch, 0);
        assert_eq!(s.record_of(&node).unwrap().version, 1, "version advances anyway");
        assert_eq!(s.spent_in_period(&node, now), 7_500, "a payee change freed headroom");
    }

    /// The low half of the ledger key rolls over on its own, with no transaction from
    /// anyone.
    #[test]
    fn the_period_rolls_over_without_a_rule_change() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");

        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        s.add_spent(&node, 7_500, 5 * DAY);
        assert_eq!(s.spent_in_period(&node, 5 * DAY + DAY - 1), 7_500, "same day");
        assert_eq!(s.spent_in_period(&node, 6 * DAY), 0, "next day");
        assert_eq!(s.spent_in_period(&node, 5 * DAY), 7_500, "and the old day is untouched");
    }

    /// The reason the ledger key is a composite and not the spec's `(epoch << 32) | period`:
    /// with a small period the quotient exceeds `u32::MAX`, and in the packed form it would
    /// carry into the epoch bits and land on another epoch's ledger.
    #[test]
    fn a_tiny_period_does_not_collide_with_another_epoch() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        let now = 1_700_000_000_000u64; // roughly now, in ms

        s.put_rule(&node, rule(1_000, 10_000, 1), true); // 1 ms periods
        assert!(now > u64::from(u32::MAX), "the quotient must overflow u32 for this to bite");
        s.add_spent(&node, 7_500, now);

        let key = s.ledger_key(&node, now).unwrap();
        assert_eq!(key.epoch, 0, "the period must not have carried into the epoch");
        assert_eq!(key.period, now);
        assert_eq!(s.spent_in_period(&node, now), 7_500);

        // The packed form would have put this at epoch 395, period 1_604_418_048.
        let packed_epoch = (now >> 32) as u32;
        assert_ne!(packed_epoch, 0, "the packed form really would have collided");
    }

    #[test]
    fn a_node_with_no_rule_has_no_ledger_and_no_spending() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        assert!(s.ledger_key(&node, 1_000).is_none());
        assert_eq!(s.spent_in_period(&node, 1_000), 0);
        // And a reservation against a node with no rule goes nowhere rather than panicking.
        s.add_spent(&node, 500, 1_000);
        assert_eq!(s.spent_in_period(&node, 1_000), 0);
    }

    #[test]
    fn two_nodes_keep_separate_ledgers() {
        with_env();
        let mut s = State::new();
        let a = acct("ops.leash.testnet");
        let b = acct("eng.leash.testnet");
        s.put_rule(&a, rule(1_000, 10_000, DAY), true);
        s.put_rule(&b, rule(1_000, 10_000, DAY), true);
        s.add_spent(&a, 7_500, 5 * DAY);
        assert_eq!(s.spent_in_period(&a, 5 * DAY), 7_500);
        assert_eq!(s.spent_in_period(&b, 5 * DAY), 0);
    }

    #[test]
    fn releasing_a_reservation_gives_the_headroom_back() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        s.add_spent(&node, 900, 0);
        s.sub_spent(&node, 900, 0);
        assert_eq!(s.spent_in_period(&node, 0), 0);
        // And it floors at zero rather than wrapping to u128::MAX.
        s.sub_spent(&node, 900, 0);
        assert_eq!(s.spent_in_period(&node, 0), 0);
    }

    #[test]
    fn the_first_rule_starts_at_epoch_zero_and_version_zero() {
        with_env();
        let mut s = State::new();
        let node = acct("ops.leash.testnet");
        s.put_rule(&node, rule(1_000, 10_000, DAY), true);
        let r = s.record_of(&node).unwrap();
        assert_eq!((r.epoch, r.version), (0, 0));
    }

    #[test]
    fn a_spent_nonce_never_goes_back() {
        with_env();
        let mut s = State::new();
        let cred = Credential::try_new(vec![1, 2, 3], valid_pubkey(), 0).unwrap();
        s.insert_credential(cred);
        assert_eq!(s.credential(&[1, 2, 3]).unwrap().nonce(), 0);
        s.spend_nonce(&[1, 2, 3]);
        s.spend_nonce(&[1, 2, 3]);
        assert_eq!(s.credential(&[1, 2, 3]).unwrap().nonce(), 2);
    }

    /// A real SEC1 point, so `Credential::try_new` accepts it: the generator of P-256.
    fn valid_pubkey() -> Vec<u8> {
        let mut k = vec![0x04];
        k.extend_from_slice(
            &hex(b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        );
        k.extend_from_slice(
            &hex(b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        );
        k
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        s.chunks(2)
            .map(|c| {
                let d = |b: u8| (b as char).to_digit(16).unwrap() as u8;
                d(c[0]) << 4 | d(c[1])
            })
            .collect()
    }
}
