//! Contract state: one record per budget node, and the registered credentials.
//!
//! # What lives where, and why
//!
//! `Rule` has no counters of its own: the bytes a passkey signs must be exactly the rule, so
//! everything the contract keeps alongside a rule lives in [`NodeRecord`].
//!
//! ```text
//! NodeRecord { rule, epoch, version, window_began_ms, spent }
//! ```
//!
//! - **`window_began_ms` and `spent`** are the budget ledger: an explicit accumulator, not a
//!   figure derived from the clock. See "The ledger" below — this is the part that makes
//!   `period_limit` an actual limit.
//! - **`epoch`** counts the accepted *loosenings*, each of which starts the ledger fresh. It
//!   is an observable, not a key: nothing is looked up by it. `epoch_of` exposes it so the
//!   demo can say "this budget has been reset twice, both times by a human with a passkey".
//! - **`version`** counts every accepted change, loosening or tightening. It exists so a
//!   cross-contract callback can tell whether the rule it was dispatched against is still the
//!   current one (see `on_payees_registered`); `epoch` cannot do that job, because tightenings
//!   and payee changes do not bump it.
//!
//! # The ledger
//!
//! ```text
//! on each spend:
//!     if now_ms >= window_began_ms + period_ms:
//!         window_began_ms += period_ms * ((now_ms - window_began_ms) / period_ms)
//!         spent = 0
//!     spent += amount
//! ```
//!
//! The window advances by **whole multiples** of `period_ms`, so windows stay anchored to the
//! first one and do not drift forward with traffic. A node that spends at 23:59 every day
//! keeps the same daily boundary rather than sliding it later each time.
//!
//! ## Why not derive the window from the clock
//!
//! The first version of this file keyed a ledger map on `(node, epoch, now_ms / period_ms)`,
//! following the design doc. Two holes, both found in review, and both of them let ADMIN
//! refill a node's budget with no passkey at all — which would make `period_limit` not a
//! limit and "loosening needs a human" not true:
//!
//! 1. **The epoch was bumped by every accepted `set_rule`, including a tightening.**
//!    Tightening is ungated by design, so re-applying the byte-identical rule — which
//!    `classify` calls a tightening — moved the node onto a fresh ledger. Unlimited repeats,
//!    no signature. Fixed by bumping the epoch only on an accepted widening, which is gated.
//! 2. **The bucket was `now_ms / rule.period_ms`.** Fixing the epoch alone is not enough:
//!    *lengthening* `period_ms` is a tightening by `classify`, and it changes the divisor, so
//!    the very next read lands on a different key and shows zero. Fixed by not having a
//!    divisor — the window start is recorded, so changing `period_ms` changes only when the
//!    next roll happens.
//!
//! A third problem went away with them: the derived key overflowed. `now_ms` is about 1.7e12,
//! so any `period_ms` below roughly 400 made `now_ms / period_ms` exceed `u32::MAX`, and in
//! the design doc's packed `(epoch << 32) | bucket` form that carried into the epoch bits.
//! `period_ms` is caller-supplied and only has to be non-zero, so it was reachable.
//!
//! And a fourth: the derived form needed a map entry per `(node, epoch, period)`, nothing ever
//! reclaimed them, and the contract staked them forever. One accumulator per node has no such
//! growth at all.
//!
//! # Storage bounds
//!
//! The contract account pays the storage staking for all of this, so nothing here may grow
//! without a bound someone chose:
//!
//! - `credentials` holds at most [`MAX_CREDENTIALS`] *active* credentials, each ~100 bytes.
//!   Revoked ones stay as tombstones (see `Credential::revoked`), so the map grows by one
//!   entry per credential ever registered — admin-driven, ~100 bytes a rotation.
//! - A rule's payee list is capped at `rule::MAX_PAYEES`.
//! - `nodes` grows only when ADMIN configures a new node, one bounded record each.

use crate::rule::Rule;
use crate::decision::{Decision, Outcome, RING_CAPACITY};
use crate::webauthn::Credential;
use near_sdk::store::{IterableMap, Vector};
use near_sdk::{near, AccountId, BorshStorageKey};

/// How many passkeys may be registered and usable at once. More than one matters — a single
/// credential is a single point of failure for the emergency path — but the list is bounded
/// because the contract pays to hold it.
///
/// This caps *active* credentials, and is not a lifetime budget: `remove_credential` frees a
/// slot. The first version had no removal method, which on an account that cannot be
/// redeployed meant eight rotations and then no loosening ever again, with no way out.
pub const MAX_CREDENTIALS: usize = 8;

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum Prefix {
    Nodes,
    Credentials,
    // Appended, not inserted: these are borsh discriminants, so reordering them would point
    // the live maps at each other's storage.
    Decisions,
}

/// A node's rule, its ledger, and the two counters that must not live inside the rule.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub rule: Rule,
    /// Accepted loosenings. Advanced only by a widening `set_rule`, which is gated.
    pub epoch: u32,
    /// Every accepted change. A concurrency token for callbacks.
    pub version: u64,
    /// Start of the current budget window, in ms. Advanced by whole periods as time passes,
    /// and reset to "now" by an accepted widening.
    pub window_began_ms: u64,
    /// Spent inside the window that began at `window_began_ms`. May be stale: if that window
    /// has since elapsed, the effective figure is zero. Read it through
    /// [`State::spent_in_period`], which accounts for that without writing.
    #[serde(with = "crate::rule::u128_dec")]
    pub spent: u128,
}

#[near(serializers = [borsh])]
pub struct State {
    nodes: IterableMap<AccountId, NodeRecord>,
    credentials: IterableMap<Vec<u8>, Credential>,
    /// The decision ring. At most [`RING_CAPACITY`] entries; slot `id % RING_CAPACITY` holds
    /// decision `id`. See [`State::push_decision`].
    decisions: Vector<Decision>,
    /// How many decisions have ever been written. Also the id the next one gets, which is
    /// what lets a callback find its own record without a second index.
    decisions_written: u64,
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
            credentials: IterableMap::new(Prefix::Credentials),
            decisions: Vector::new(Prefix::Decisions),
            decisions_written: 0,
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

    /// Store `rule` for `node`.
    ///
    /// `reset_ledger` must be true **only** for an accepted widening, which is gated on a
    /// passkey. It zeroes `spent`, starts a new window at `now_ms`, and bumps `epoch`. That is
    /// a loosening in its own right — it hands the node a full period's headroom back — so it
    /// must never happen on a path no signature authorised.
    ///
    /// With `reset_ledger` false the ledger is left exactly as it stands, including a window
    /// already due to roll; the next spend rolls it, under the new rule's period.
    ///
    /// `version` always advances, so a callback can detect any intervening change.
    pub fn put_rule(&mut self, node: &AccountId, rule: Rule, reset_ledger: bool, now_ms: u64) {
        let next = match self.nodes.get(node) {
            Some(prev) if reset_ledger => NodeRecord {
                rule,
                // Saturating rather than wrapping: this is an observable counter, and a stuck
                // one is a better failure than one that walks backwards. 2^32 signed
                // loosenings is not a reachable number.
                epoch: prev.epoch.saturating_add(1),
                version: prev.version.saturating_add(1),
                window_began_ms: now_ms,
                spent: 0,
            },
            Some(prev) => NodeRecord {
                rule,
                epoch: prev.epoch,
                version: prev.version.saturating_add(1),
                window_began_ms: prev.window_began_ms,
                spent: prev.spent,
            },
            // A node's first rule is always a widening (there is nothing to tighten from), so
            // this starts a window either way.
            None => NodeRecord {
                rule,
                epoch: 0,
                version: 0,
                window_began_ms: now_ms,
                spent: 0,
            },
        };
        self.nodes.insert(node.clone(), next);
    }

    /// Every configured node, for the demo page's overview. Bounded by ADMIN's own actions.
    pub fn node_ids(&self) -> Vec<AccountId> {
        self.nodes.keys().cloned().collect()
    }

    // --- the ledger -------------------------------------------------------------------

    /// Whether `node`'s recorded window has elapsed by `now_ms`. False for a node with no
    /// rule, which has no window.
    fn window_elapsed(&self, node: &AccountId, now_ms: u64) -> bool {
        self.nodes.get(node).is_some_and(|r| {
            // `period_ms == 0` is rejected by `Rule::try_new`, so a window always has width.
            now_ms.saturating_sub(r.window_began_ms) >= r.rule.period_ms()
        })
    }

    /// Roll `node`'s window forward if it has elapsed, zeroing `spent`.
    ///
    /// Advances by whole multiples of `period_ms`, so windows stay anchored to the first one
    /// instead of drifting forward to whenever traffic happens to arrive.
    fn roll_window(&mut self, node: &AccountId, now_ms: u64) {
        if !self.window_elapsed(node, now_ms) {
            return;
        }
        let Some(r) = self.nodes.get_mut(node) else {
            return;
        };
        let period = r.rule.period_ms();
        let elapsed = now_ms.saturating_sub(r.window_began_ms);
        let whole = elapsed / period;
        // `whole * period <= elapsed`, so this cannot pass `now_ms`. Saturating anyway,
        // because an arithmetic surprise here would silently move a budget window.
        r.window_began_ms = r.window_began_ms.saturating_add(whole.saturating_mul(period));
        r.spent = 0;
    }

    /// What `node` has spent in the window containing `now_ms`. Does not write: an elapsed
    /// window reads as zero, and the stale recorded figure is cleared by the next spend.
    pub fn spent_in_period(&self, node: &AccountId, now_ms: u64) -> u128 {
        if self.window_elapsed(node, now_ms) {
            return 0;
        }
        self.nodes.get(node).map_or(0, |r| r.spent)
    }

    /// Start of the window containing `now_ms`, accounting for rolls not yet written.
    /// `None` for a node with no rule.
    pub fn window_began_ms(&self, node: &AccountId, now_ms: u64) -> Option<u64> {
        let r = self.nodes.get(node)?;
        let period = r.rule.period_ms();
        let elapsed = now_ms.saturating_sub(r.window_began_ms);
        Some(
            r.window_began_ms
                .saturating_add((elapsed / period).saturating_mul(period)),
        )
    }

    /// Reserve `amount` against the window containing `now_ms`, rolling the window first if
    /// it has elapsed. Task 6's `spend` calls this before dispatching a transfer.
    ///
    /// Saturating: the caller checks the limit first, and a silent wrap here would hand out
    /// unlimited headroom.
    pub fn add_spent(&mut self, node: &AccountId, amount: u128, now_ms: u64) {
        self.roll_window(node, now_ms);
        if let Some(r) = self.nodes.get_mut(node) {
            r.spent = r.spent.saturating_add(amount);
        }
    }

    /// Release a reservation whose transfer failed. Rolls first, for the same reason, and
    /// floors at zero rather than wrapping.
    ///
    /// Prefer [`State::release_reservation`] for a transfer that failed: it checks that the
    /// reservation still belongs to the current window first.
    pub fn sub_spent(&mut self, node: &AccountId, amount: u128, now_ms: u64) {
        self.roll_window(node, now_ms);
        if let Some(r) = self.nodes.get_mut(node) {
            r.spent = r.spent.saturating_sub(amount);
        }
    }

    /// Release a reservation that was made in the window beginning at `reserved_window_ms`.
    /// Returns whether anything was released.
    ///
    /// **The window check is the point of this method.** A reservation is made in `spend` and
    /// released in the callback, which runs in a later block — so a period boundary, or an
    /// accepted widening, can fall between the two. A plain `sub_spent` would then take the
    /// amount off whatever window is current *now*, handing a node free headroom it never
    /// paid for: reserve 500 at the end of a period, roll, another agent spends 500 in the new
    /// period, our transfer fails, and the new period's ledger reads zero. With a one-second
    /// test period that is routine rather than theoretical.
    ///
    /// If the window has moved on there is nothing to release: the reservation's window is
    /// gone, and `roll_window` already zeroed its `spent` (or an accepted widening did).
    pub fn release_reservation(
        &mut self,
        node: &AccountId,
        amount: u128,
        reserved_window_ms: u64,
        now_ms: u64,
    ) -> bool {
        if self.window_began_ms(node, now_ms) != Some(reserved_window_ms) {
            return false;
        }
        self.sub_spent(node, amount, now_ms);
        true
    }

    // --- the decision ring ------------------------------------------------------------

    /// Record `decision` and return its id.
    ///
    /// The id is how many decisions have ever been written, so decision `id` lives in slot
    /// `id % RING_CAPACITY` and is still there exactly while `id + RING_CAPACITY >
    /// decisions_written`. That is the whole index: no second map, and no id stored inside
    /// the record for a callback to match on.
    ///
    /// The ring is why the log cannot grow: the contract account stakes the storage, and
    /// after [`RING_CAPACITY`] entries every write overwrites one.
    pub fn push_decision(&mut self, decision: Decision) -> u64 {
        let id = self.decisions_written;
        if (self.decisions.len() as u64) < RING_CAPACITY {
            self.decisions.push(decision);
        } else {
            self.decisions.set((id % RING_CAPACITY) as u32, decision);
        }
        self.decisions_written = id.saturating_add(1);
        id
    }

    /// Finalise decision `id` — the callback's job. Returns false if the ring has moved past
    /// it, which is not an error: `RING_CAPACITY` later decisions have been recorded since,
    /// and the honest log of the last twenty no longer includes this one. The reservation is
    /// released regardless; that accounting does not live here.
    pub fn settle_decision(&mut self, id: u64, outcome: Outcome, spent_after: u128) -> bool {
        if id >= self.decisions_written || id + RING_CAPACITY <= self.decisions_written {
            return false;
        }
        let Some(d) = self.decisions.get_mut((id % RING_CAPACITY) as u32) else {
            return false;
        };
        d.outcome = outcome;
        d.spent_after = spent_after;
        true
    }

    /// Decision `id`, while the ring still holds it. `None` once `RING_CAPACITY` later
    /// decisions have evicted it.
    pub fn decision(&self, id: u64) -> Option<&Decision> {
        if id >= self.decisions_written || id + RING_CAPACITY <= self.decisions_written {
            return None;
        }
        self.decisions.get((id % RING_CAPACITY) as u32)
    }

    /// The last [`RING_CAPACITY`] decisions, newest first.
    pub fn recent_decisions(&self) -> Vec<Decision> {
        let first = self.decisions_written.saturating_sub(RING_CAPACITY);
        (first..self.decisions_written)
            .rev()
            .filter_map(|id| self.decisions.get((id % RING_CAPACITY) as u32).cloned())
            .collect()
    }

    /// How many decisions have ever been recorded, which the ring itself cannot show once it
    /// is full. Also the id the next one will get.
    pub fn decisions_written(&self) -> u64 {
        self.decisions_written
    }

    // --- credentials ------------------------------------------------------------------

    /// A credential that may authorise a loosening. `None` if the id is unknown **or
    /// revoked**: a revoked entry survives only to keep its id and spent nonce out of
    /// circulation, and must never satisfy an authorisation.
    pub fn active_credential(&self, id: &[u8]) -> Option<&Credential> {
        self.credentials.get(&id.to_vec()).filter(|c| !c.revoked())
    }

    /// Any credential under this id, revoked or not. Used by `register_credential` to refuse a
    /// known id, and by the `credentials` view.
    pub fn known_credential(&self, id: &[u8]) -> Option<&Credential> {
        self.credentials.get(&id.to_vec())
    }

    /// Active credentials only — what [`MAX_CREDENTIALS`] caps.
    pub fn active_credential_count(&self) -> usize {
        self.credentials.values().filter(|c| !c.revoked()).count()
    }

    /// Ids of the active credentials, which is what a client needs to request an assertion.
    pub fn active_credential_ids(&self) -> Vec<Vec<u8>> {
        self.credentials
            .iter()
            .filter(|(_, c)| !c.revoked())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Every credential this contract has ever held, revoked ones included, so the demo can
    /// say "two active, one revoked" instead of silently hiding a rotation.
    pub fn all_credentials(&self) -> Vec<Credential> {
        self.credentials.values().cloned().collect()
    }

    /// Insert a credential under its own id. The caller checks that the id is unknown — see
    /// `register_credential`, where any known id is refused because re-registration would
    /// reset the nonce and re-arm every assertion ever signed under it.
    pub fn insert_credential(&mut self, cred: Credential) {
        self.credentials.insert(cred.id().to_vec(), cred);
    }

    /// Revoke a credential. Returns false if the id is unknown or already revoked.
    ///
    /// The entry is **not** deleted. Deleting it would free the id for re-registration at
    /// nonce 0, re-arming every assertion ever signed under it; the tombstone keeps the spent
    /// nonce forever while freeing the slot it occupied for a new credential.
    pub fn revoke_credential(&mut self, id: &[u8]) -> bool {
        match self.credentials.get_mut(&id.to_vec()) {
            Some(c) if !c.revoked() => {
                c.revoke();
                true
            }
            _ => false,
        }
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

    const DAY: u64 = 86_400_000;
    const NODE: &str = "ops.leash.testnet";

    fn acct(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn rule_with(per_tx: u128, period_limit: u128, period_ms: u64) -> Rule {
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

    fn rule() -> Rule {
        rule_with(1_000, 10_000, DAY)
    }

    /// `State` holds near-sdk collections, which read and write the storage of whatever VM
    /// context is current, so these tests need one.
    fn with_env() {
        testing_env!(VMContextBuilder::new().build());
    }

    /// A node with a rule, 7,500 of its 10,000 spent, five days in.
    fn spent_node() -> (State, AccountId) {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        s.put_rule(&node, rule(), true, 5 * DAY);
        s.add_spent(&node, 7_500, 5 * DAY);
        assert_eq!(s.spent_in_period(&node, 5 * DAY), 7_500);
        (s, node)
    }

    // --- the ledger reset, from both sides --------------------------------------------
    //
    // These two sit side by side on purpose. The whole security argument is that only the
    // gated path can reset a budget, so both halves need pinning: that a widening does, and
    // that a tightening does not.

    /// A human signed for a fresh start, so the ledger starts fresh. Deliberate, and one
    /// sentence for the demo to narrate: new rule, new budget.
    #[test]
    fn a_widening_resets_the_ledger_and_bumps_the_epoch() {
        let (mut s, node) = spent_node();
        let now = 5 * DAY + 1_000;

        // Raising per_tx_limit is a widening, so `set_rule` required an assertion for it.
        s.put_rule(&node, rule_with(2_000, 10_000, DAY), true, now);

        let r = s.record_of(&node).unwrap();
        assert_eq!(r.epoch, 1, "an accepted widening must advance the epoch");
        assert_eq!(r.window_began_ms, now, "the new window must start now");
        assert_eq!(s.spent_in_period(&node, now), 0, "the new window must start at zero");
    }

    /// The hole this replaced: a tightening is ungated, so if it reset the ledger then ADMIN
    /// could refill a node's budget as often as it liked with no passkey, and `period_limit`
    /// would not be a limit.
    #[test]
    fn a_tightening_does_not_reset_the_ledger_or_bump_the_epoch() {
        let (mut s, node) = spent_node();
        let now = 5 * DAY + 1_000;

        s.put_rule(&node, rule_with(500, 5_000, DAY), false, now);

        let r = s.record_of(&node).unwrap();
        assert_eq!(r.epoch, 0, "a tightening must not advance the epoch");
        assert_eq!(r.window_began_ms, 5 * DAY, "a tightening must not move the window");
        assert_eq!(
            s.spent_in_period(&node, now),
            7_500,
            "a tightening must not give headroom back"
        );
    }

    /// Re-applying the byte-identical rule is the cheapest form of that attack: `classify`
    /// calls it a tightening, so it needs no signature, and it can be repeated forever.
    #[test]
    fn re_applying_the_same_rule_many_times_frees_nothing() {
        let (mut s, node) = spent_node();
        for i in 0..10 {
            s.put_rule(&node, rule(), false, 5 * DAY + i);
        }
        assert_eq!(s.record_of(&node).unwrap().epoch, 0);
        assert_eq!(s.record_of(&node).unwrap().version, 10);
        assert_eq!(
            s.spent_in_period(&node, 5 * DAY + 10),
            7_500,
            "ten free rule changes must not have refilled the budget"
        );
    }

    /// The second half of the same hole, and the reason the window is recorded rather than
    /// derived: *lengthening* the period is a tightening by `classify`, and under the old
    /// `now_ms / period_ms` bucket it changed the divisor and read zero.
    #[test]
    fn lengthening_the_period_in_a_tightening_frees_nothing() {
        let (mut s, node) = spent_node();
        let now = 5 * DAY + 1_000;

        s.put_rule(&node, rule_with(1_000, 10_000, 7 * DAY), false, now);

        assert_eq!(
            s.spent_in_period(&node, now),
            7_500,
            "a longer period must not give headroom back"
        );
        // It changes when the next roll happens and nothing else: the window still began on
        // day 5, and now runs for seven days instead of one.
        assert_eq!(s.spent_in_period(&node, 11 * DAY), 7_500, "still inside the window");
        assert_eq!(s.spent_in_period(&node, 12 * DAY), 0, "the window has rolled");
    }

    /// And shortening it, which `classify` calls a widening, so it arrives with
    /// `reset_ledger` true and the fresh start is something a passkey signed for.
    #[test]
    fn shortening_the_period_is_a_widening_and_resets() {
        let (mut s, node) = spent_node();
        let now = 5 * DAY + 1_000;
        s.put_rule(&node, rule_with(1_000, 10_000, DAY / 2), true, now);
        assert_eq!(s.spent_in_period(&node, now), 0);
        assert_eq!(s.record_of(&node).unwrap().epoch, 1);
    }

    /// A payee change must not touch the ledger either: nothing about the budget arithmetic
    /// changed, and free headroom is a loosening nobody signed for.
    #[test]
    fn a_payee_change_leaves_the_ledger_alone() {
        let (mut s, node) = spent_node();
        let widened = s.rule_of(&node).unwrap().with_payee(acct("bob.testnet")).unwrap();
        s.put_rule(&node, widened, false, 5 * DAY + 1_000);

        let r = s.record_of(&node).unwrap();
        assert_eq!(r.epoch, 0, "a payee change must not advance the epoch");
        assert_eq!(r.version, 1, "but version advances anyway, for the callback token");
        assert_eq!(
            s.spent_in_period(&node, 5 * DAY + 1_000),
            7_500,
            "a payee change must not free headroom"
        );
    }

    // --- the window ------------------------------------------------------------------

    /// The window rolls on its own, with no transaction from anyone.
    #[test]
    fn the_window_rolls_without_a_rule_change() {
        let (s, node) = spent_node();
        assert_eq!(s.spent_in_period(&node, 6 * DAY - 1), 7_500, "same window");
        assert_eq!(s.spent_in_period(&node, 6 * DAY), 0, "next window");
        assert_eq!(s.spent_in_period(&node, 7 * DAY), 0, "and the one after");
    }

    /// Windows advance by whole periods, so they stay anchored to the first one rather than
    /// sliding forward to whenever traffic happened to arrive. A node that spends late every
    /// day keeps the same daily boundary.
    #[test]
    fn the_window_advances_by_whole_periods_and_does_not_drift() {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        s.put_rule(&node, rule(), true, 0);

        // Spend near the end of day 0, then day 1, then day 2.
        for day in 0..3u64 {
            let late = day * DAY + DAY - 1;
            s.add_spent(&node, 100, late);
            assert_eq!(
                s.window_began_ms(&node, late),
                Some(day * DAY),
                "the window must stay anchored to midnight"
            );
            assert_eq!(s.spent_in_period(&node, late), 100, "each window counts only its own");
        }
        assert_eq!(s.record_of(&node).unwrap().window_began_ms, 2 * DAY);
    }

    /// A gap of many periods lands on the containing window, not the next one.
    #[test]
    fn a_long_gap_lands_on_the_containing_window() {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        s.put_rule(&node, rule(), true, 0);
        s.add_spent(&node, 100, 0);

        let much_later = 1_000 * DAY + 12 * 3_600_000; // midday on day 1000
        s.add_spent(&node, 250, much_later);
        assert_eq!(s.window_began_ms(&node, much_later), Some(1_000 * DAY));
        assert_eq!(s.spent_in_period(&node, much_later), 250);
    }

    /// A 1 ms period: the old derived bucket overflowed `u32` here and, in the design doc's
    /// packed form, carried into the epoch bits. There is no divisor now, so nothing to
    /// overflow.
    #[test]
    fn a_one_millisecond_period_rolls_correctly() {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        let now = 1_700_000_000_000u64; // roughly now, in ms
        assert!(now > u64::from(u32::MAX), "the old quotient really did overflow u32");

        s.put_rule(&node, rule_with(1_000, 10_000, 1), true, now);
        s.add_spent(&node, 500, now);
        assert_eq!(s.spent_in_period(&node, now), 500);
        assert_eq!(s.spent_in_period(&node, now + 1), 0, "a 1 ms window rolls after 1 ms");
        assert_eq!(s.record_of(&node).unwrap().epoch, 0);
    }

    /// `spent_in_period` must not write. An elapsed window reads as zero, and reading it must
    /// not move the recorded window — a view call that mutated state would be a nasty
    /// surprise for the demo page, which polls.
    #[test]
    fn reading_an_elapsed_window_changes_nothing() {
        let (mut s, node) = spent_node();
        assert_eq!(s.spent_in_period(&node, 9 * DAY), 0);
        assert_eq!(
            s.record_of(&node).unwrap().window_began_ms,
            5 * DAY,
            "a read must not move the window"
        );
        assert_eq!(s.record_of(&node).unwrap().spent, 7_500, "a read must not clear the figure");
        // The stale figure is cleared by the next spend, not by the read.
        s.add_spent(&node, 1, 9 * DAY);
        assert_eq!(s.spent_in_period(&node, 9 * DAY), 1);
        assert_eq!(s.record_of(&node).unwrap().window_began_ms, 9 * DAY);
    }

    #[test]
    fn a_node_with_no_rule_has_no_window_and_no_spending() {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        assert!(s.window_began_ms(&node, 1_000).is_none());
        assert_eq!(s.spent_in_period(&node, 1_000), 0);
        // And a reservation against a node with no rule goes nowhere rather than panicking.
        s.add_spent(&node, 500, 1_000);
        assert_eq!(s.spent_in_period(&node, 1_000), 0);
    }

    #[test]
    fn two_nodes_keep_separate_ledgers() {
        with_env();
        let mut s = State::new();
        let a = acct(NODE);
        let b = acct("eng.leash.testnet");
        s.put_rule(&a, rule(), true, 5 * DAY);
        s.put_rule(&b, rule(), true, 5 * DAY);
        s.add_spent(&a, 7_500, 5 * DAY);
        assert_eq!(s.spent_in_period(&a, 5 * DAY), 7_500);
        assert_eq!(s.spent_in_period(&b, 5 * DAY), 0);
    }

    #[test]
    fn releasing_a_reservation_gives_the_headroom_back() {
        let (mut s, node) = spent_node();
        s.sub_spent(&node, 500, 5 * DAY);
        assert_eq!(s.spent_in_period(&node, 5 * DAY), 7_000);
        // And it floors at zero rather than wrapping to u128::MAX.
        s.sub_spent(&node, 10_000, 5 * DAY);
        assert_eq!(s.spent_in_period(&node, 5 * DAY), 0);
    }

    // --- releasing a reservation, window-aware ----------------------------------------

    /// The ordinary case: the transfer failed inside the window that reserved the money.
    #[test]
    fn a_failed_transfer_in_the_same_window_releases() {
        let (mut s, node) = spent_node();
        let window = s.window_began_ms(&node, 5 * DAY).unwrap();
        assert!(s.release_reservation(&node, 500, window, 5 * DAY));
        assert_eq!(s.spent_in_period(&node, 5 * DAY), 7_000);
    }

    /// The case a plain subtraction gets wrong, and it is the one that would hand out free
    /// money: the callback lands after the window has rolled. The reservation belonged to the
    /// window that has just been zeroed, so there is nothing to give back — taking it off the
    /// new window would be headroom nobody paid for.
    #[test]
    fn a_reservation_from_a_rolled_window_is_not_released_against_the_new_one() {
        let (mut s, node) = spent_node();
        let old_window = s.window_began_ms(&node, 5 * DAY).unwrap();

        // The window rolls, and another agent spends 500 of the new period.
        let later = 6 * DAY;
        s.add_spent(&node, 500, later);
        assert_eq!(s.spent_in_period(&node, later), 500);

        // Now the old reservation's transfer fails.
        assert!(!s.release_reservation(&node, 7_500, old_window, later));
        assert_eq!(
            s.spent_in_period(&node, later),
            500,
            "a stale reservation must not be credited against the new window"
        );
    }

    /// An accepted widening resets the ledger, which also moves the window start. A
    /// reservation made before it is just as stale.
    #[test]
    fn a_reservation_from_before_a_widening_is_not_released() {
        let (mut s, node) = spent_node();
        let old_window = s.window_began_ms(&node, 5 * DAY).unwrap();
        let now = 5 * DAY + 1_000;
        s.put_rule(&node, rule_with(2_000, 10_000, DAY), true, now);
        s.add_spent(&node, 300, now);

        assert!(!s.release_reservation(&node, 7_500, old_window, now));
        assert_eq!(s.spent_in_period(&node, now), 300);
    }

    // --- the decision ring ------------------------------------------------------------

    fn decision(amount: u128) -> Decision {
        Decision {
            agent: acct("pay.ops.leash.testnet"),
            node: Some(acct(NODE)),
            payee: acct("alice.testnet"),
            amount,
            outcome: Outcome::Allowed,
            spent_after: amount,
            timestamp_ms: 1_000,
        }
    }

    #[test]
    fn decisions_come_back_newest_first() {
        with_env();
        let mut s = State::new();
        for i in 1..=3u128 {
            s.push_decision(decision(i));
        }
        let got: Vec<u128> = s.recent_decisions().iter().map(|d| d.amount).collect();
        assert_eq!(got, vec![3, 2, 1]);
    }

    /// Bounded storage is a requirement of the design, not an optimisation: the contract
    /// account stakes every byte of this log.
    #[test]
    fn the_ring_holds_exactly_twenty() {
        with_env();
        let mut s = State::new();
        for i in 1..=25u128 {
            s.push_decision(decision(i));
        }
        let got: Vec<u128> = s.recent_decisions().iter().map(|d| d.amount).collect();
        assert_eq!(got.len(), RING_CAPACITY as usize);
        assert_eq!(got.first(), Some(&25), "newest first");
        assert_eq!(got.last(), Some(&6), "and the five oldest are gone");
        assert_eq!(s.decisions_written(), 25);
    }

    #[test]
    fn ids_count_from_zero_and_identify_the_slot() {
        with_env();
        let mut s = State::new();
        assert_eq!(s.push_decision(decision(1)), 0);
        assert_eq!(s.push_decision(decision(2)), 1);
        assert_eq!(s.decisions_written(), 2);
    }

    #[test]
    fn settling_rewrites_the_outcome_in_place() {
        with_env();
        let mut s = State::new();
        let id = s.push_decision(decision(100));
        s.push_decision(decision(200));

        assert!(s.settle_decision(id, Outcome::Failed, 0));
        let all = s.recent_decisions();
        assert_eq!(all[1].outcome, Outcome::Failed, "the settled record, not its neighbour");
        assert_eq!(all[1].spent_after, 0);
        assert_eq!(all[0].outcome, Outcome::Allowed, "the newer record is untouched");
    }

    /// A callback whose record has been pushed out of the ring must not write over whatever
    /// decision now occupies its slot. Releasing the reservation is a separate concern and
    /// still happens — see `on_transfer`.
    #[test]
    fn settling_an_evicted_decision_changes_nothing() {
        with_env();
        let mut s = State::new();
        let id = s.push_decision(decision(1));
        for i in 2..=21u128 {
            s.push_decision(decision(i));
        }
        assert!(!s.settle_decision(id, Outcome::Failed, 0), "id 0 is gone from the ring");
        // Slot 0 now holds decision 20 (id 20, amount 21), which must still read Allowed.
        let newest = &s.recent_decisions()[0];
        assert_eq!(newest.amount, 21);
        assert_eq!(newest.outcome, Outcome::Allowed);
    }

    #[test]
    fn settling_an_id_that_was_never_written_changes_nothing() {
        with_env();
        let mut s = State::new();
        s.push_decision(decision(1));
        assert!(!s.settle_decision(5, Outcome::Failed, 0));
        assert_eq!(s.recent_decisions()[0].outcome, Outcome::Allowed);
    }

    #[test]
    fn an_empty_ring_reads_as_no_decisions() {
        with_env();
        let s = State::new();
        assert!(s.recent_decisions().is_empty());
        assert_eq!(s.decisions_written(), 0);
    }

    #[test]
    fn the_first_rule_starts_a_window_at_epoch_zero() {
        with_env();
        let mut s = State::new();
        let node = acct(NODE);
        s.put_rule(&node, rule(), true, 5 * DAY);
        let r = s.record_of(&node).unwrap();
        assert_eq!((r.epoch, r.version, r.window_began_ms, r.spent), (0, 0, 5 * DAY, 0));
    }

    // --- credentials -----------------------------------------------------------------

    #[test]
    fn a_spent_nonce_never_goes_back() {
        with_env();
        let mut s = State::new();
        s.insert_credential(Credential::try_new(vec![1, 2, 3], valid_pubkey(), 0).unwrap());
        assert_eq!(s.active_credential(&[1, 2, 3]).unwrap().nonce(), 0);
        s.spend_nonce(&[1, 2, 3]);
        s.spend_nonce(&[1, 2, 3]);
        assert_eq!(s.active_credential(&[1, 2, 3]).unwrap().nonce(), 2);
    }

    /// Revocation hides the credential from authorisation, frees its slot, and keeps the id
    /// and its spent nonce in state so the id can never come back at nonce 0.
    #[test]
    fn revoking_hides_a_credential_but_keeps_its_nonce() {
        with_env();
        let mut s = State::new();
        s.insert_credential(Credential::try_new(vec![1], valid_pubkey(), 0).unwrap());
        s.spend_nonce(&[1]);
        assert_eq!(s.active_credential_count(), 1);

        assert!(s.revoke_credential(&[1]));
        assert!(s.active_credential(&[1]).is_none(), "a revoked credential must not authorise");
        assert_eq!(s.active_credential_count(), 0, "its slot must be free");
        assert!(s.active_credential_ids().is_empty());

        let tombstone = s.known_credential(&[1]).expect("the tombstone must survive");
        assert!(tombstone.revoked());
        assert_eq!(tombstone.nonce(), 1, "the spent nonce must be remembered");

        // Revoking twice is not worth panicking over, but it reports nothing done.
        assert!(!s.revoke_credential(&[1]));
        assert!(!s.revoke_credential(&[9, 9]), "and an unknown id reports nothing done");
    }

    #[test]
    fn a_freed_slot_can_be_filled_by_a_different_id() {
        with_env();
        let mut s = State::new();
        for i in 0..MAX_CREDENTIALS {
            s.insert_credential(Credential::try_new(vec![i as u8], valid_pubkey(), 0).unwrap());
        }
        assert_eq!(s.active_credential_count(), MAX_CREDENTIALS);
        s.revoke_credential(&[0]);
        assert_eq!(s.active_credential_count(), MAX_CREDENTIALS - 1);
        s.insert_credential(Credential::try_new(vec![99], valid_pubkey(), 0).unwrap());
        assert_eq!(s.active_credential_count(), MAX_CREDENTIALS);
        // The tombstone survives, so the revoked id is still out of circulation.
        assert!(s.known_credential(&[0]).is_some());
        assert_eq!(s.all_credentials().len(), MAX_CREDENTIALS + 1);
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
