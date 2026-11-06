//! What the chain says about one payment attempt, and the bounded log it says it into.
//!
//! # The refusal is the product
//!
//! A refused payment is not an error. It is the thing this contract exists to do, so it has
//! to survive as a readable record: `spend` returns normally on every policy refusal, writes
//! a [`Decision`] here, and emits an event. A panic would roll the record back and leave a
//! failed transaction with no on-chain explanation at all — see `spend` in `lib.rs`.
//!
//! # One table, not two
//!
//! A refusal reaches the outside world as a number *and* a sentence, from [`REFUSALS`]. If
//! the contract published only the number, every UI would carry its own copy of the mapping
//! and drift from this file the first time a reason was reworded. So [`Outcome`]'s JSON
//! carries the reason with the code, and `refusal_codes()` publishes the whole table.
//!
//! # Storage
//!
//! The contract account pays the storage staking for the log, so it is a ring of exactly
//! [`RING_CAPACITY`] entries: the newest write evicts the oldest. Bounded storage is a
//! requirement of the design, not an optimisation.

use crate::rule::u128_dec;
use near_sdk::serde_json::{self, json};
use near_sdk::{env, near, AccountId};

/// The `standard` and `version` on every event this contract emits, per NEP-297.
const EVENT_STANDARD: &str = "leash";
const EVENT_VERSION: &str = "1.0.0";

/// The four things that can happen to a payment attempt, as event names.
///
/// `allowed` is emitted when the reservation is made and the transfer dispatched; `settled`
/// or `failed` follows one block later from the callback. An indexer that sees `allowed` with
/// no settlement after it is looking at a transaction that ran out of gas in the callback.
pub const EVENT_REFUSED: &str = "refused";
pub const EVENT_ALLOWED: &str = "allowed";
pub const EVENT_SETTLED: &str = "settled";
pub const EVENT_FAILED: &str = "failed";

/// The two bounded logs a decision can land in, as they are named on the wire. A consumer
/// reads them back through `recent_decisions()` and `recent_stranger_decisions()`
/// respectively, so the event says which one to look in.
pub const RING_DECISIONS: &str = "decisions";
pub const RING_STRANGERS: &str = "strangers";

/// Emit a NEP-297 event carrying one whole decision, and the ring it was recorded in.
///
/// Events are emitted *in parallel* with the ring buffer, never instead of it: the demo reads
/// state with free view calls and depends on no indexer at all. These exist so that a real
/// indexer could be attached later.
pub fn emit(event: &str, ring: &str, record_id: u64, d: &Decision) {
    let mut data = serde_json::to_value(d).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("ring".to_string(), json!(ring));
        obj.insert("record_id".to_string(), json!(record_id));
    }
    emit_raw(event, data);
}

/// Emit a settlement whose record the ring has already evicted — twenty later decisions
/// arrived while one transfer was in flight. The reservation accounting still happened, so an
/// indexer must still hear about it even though the on-chain log of the last twenty cannot
/// show it.
pub fn emit_evicted(event: &str, record_id: u64, node: &AccountId, amount: u128) {
    emit_raw(
        event,
        json!({
            "ring": RING_DECISIONS,
            "record_id": record_id,
            "node": node,
            "amount": amount.to_string(),
            "evicted": true,
        }),
    );
}

fn emit_raw(event: &str, data: serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_VERSION,
            "event": event,
            "data": [data],
        })
    ));
}

/// How many decisions the ring buffer holds. The demo page reads them all in one view call,
/// and the account stakes the storage for every one of them, so this is a chosen number
/// rather than a growing one.
pub const RING_CAPACITY: u64 = 20;

/// How many refusals of callers with **no rule** are kept, in their own ring.
///
/// `spend` is open to any caller on NEAR — that is the design, and a caller with no rule is
/// answered with code 1 rather than turned away. The consequence is that anyone can write to
/// the log, and [`RING_CAPACITY`] calls from one stranger would evict every real decision from
/// it. So those refusals go in a separate, deliberately tiny ring: strangers can only evict
/// strangers, and the evidence the demo reads cannot be blanked by an onlooker with a testnet
/// account. Four is enough to show the refusal happening and small enough that the flood is
/// obvious in `stranger_count()` rather than hidden in a long list.
pub const STRANGER_RING_CAPACITY: u64 = 4;

/// The seven refusal codes, by name. The numbers are part of the contract's public surface —
/// the agent processes branch on them — so they are written once, here, and never derived
/// from the position of anything.
pub mod code {
    pub const NO_RULE: u8 = 1;
    pub const PAUSED: u8 = 2;
    pub const WRONG_TOKEN: u8 = 3;
    pub const PAYEE_NOT_ALLOWED: u8 = 4;
    pub const OVER_PER_TX_LIMIT: u8 = 5;
    pub const OVER_PERIOD_LIMIT: u8 = 6;
    pub const OUTSIDE_WINDOW: u8 = 7;
}

/// One row of the refusal table: the code that goes on chain and the reason a human reads.
pub struct Refusal {
    pub code: u8,
    pub reason: &'static str,
}

/// Every reason this contract can refuse a payment, in the order the checks run.
///
/// The order is the spec's and it is load-bearing in one direction only: a `spend` that fails
/// several checks is refused with the *first* code in this list, so a demo recording always
/// shows the same reason for the same attempt.
pub const REFUSALS: [Refusal; 7] = [
    Refusal { code: code::NO_RULE, reason: "no rule for this agent's node" },
    Refusal { code: code::PAUSED, reason: "paused" },
    Refusal { code: code::WRONG_TOKEN, reason: "not this node's token" },
    Refusal { code: code::PAYEE_NOT_ALLOWED, reason: "payee is not on the allow-list" },
    Refusal { code: code::OVER_PER_TX_LIMIT, reason: "over the per-transaction limit" },
    Refusal { code: code::OVER_PERIOD_LIMIT, reason: "over the limit for this period" },
    Refusal { code: code::OUTSIDE_WINDOW, reason: "outside the node's active window" },
];

/// The sentence for a refusal code, or `None` for a code this contract does not issue.
pub fn reason_for(code: u8) -> Option<&'static str> {
    REFUSALS.iter().find(|r| r.code == code).map(|r| r.reason)
}

/// The refusal table on the wire, for the `refusal_codes()` view. The demo page fetches it
/// instead of hard-coding a copy.
#[near(serializers = [json])]
pub struct RefusalView {
    pub code: u8,
    pub reason: String,
}

/// What became of one payment attempt.
///
/// `Refused` carries the code. `Failed` carries nothing, and that is not an omission: a NEAR
/// callback is told only *that* a promise failed, never why — `PromiseResult::Failed` has no
/// payload — so a message here would be invented rather than reported.
#[near(serializers = [borsh, json])]
#[serde(into = "OutcomeView", try_from = "OutcomeView")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Policy allowed it, the reservation was made and the transfer dispatched.
    Allowed,
    /// Policy refused it, with one of the codes in [`REFUSALS`].
    Refused(u8),
    /// Policy allowed it and `ft_transfer` failed. The reservation has been released.
    Failed,
}

/// `Outcome` on the wire: a status, and for a refusal both the code and its reason.
///
/// Deliberately not the derived enum shape (`{"Refused":4}`). A client that gets the number
/// alone has to keep its own copy of the reason table, which is one reword away from lying to
/// a viewer.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct OutcomeView {
    /// `allowed`, `refused` or `failed`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<Outcome> for OutcomeView {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Allowed => Self { status: "allowed".into(), code: None, reason: None },
            Outcome::Refused(c) => Self {
                status: "refused".into(),
                code: Some(c),
                // A code with no row in the table would be a bug in this contract rather
                // than something a client should have to interpret, so say so plainly.
                reason: Some(reason_for(c).unwrap_or("unknown refusal code").to_string()),
            },
            Outcome::Failed => Self { status: "failed".into(), code: None, reason: None },
        }
    }
}

impl TryFrom<OutcomeView> for Outcome {
    type Error = String;
    /// Only ever used when something reads an `Outcome` back off the wire — the sandbox tests
    /// do, so that they assert against the shape clients actually receive. `reason` is
    /// ignored on the way in: the code is the authority.
    fn try_from(v: OutcomeView) -> Result<Self, String> {
        match (v.status.as_str(), v.code) {
            ("allowed", _) => Ok(Outcome::Allowed),
            ("failed", _) => Ok(Outcome::Failed),
            ("refused", Some(c)) => Ok(Outcome::Refused(c)),
            ("refused", None) => Err("a refused outcome must carry its code".into()),
            (other, _) => Err(format!("unknown outcome status {other:?}")),
        }
    }
}

/// Both logs and both counts in one view call, so a client never has to decide which of two
/// calls to make or stitch the answers together itself.
///
/// `decisions` is what agents with a configured node did; `strangers` is callers with no rule
/// at all, in their own small ring so that they cannot evict the former. The counts are how
/// many have *ever* been recorded, which is the only way to see a flood: twenty stranger
/// calls leave `strangers` four long and `stranger_count` at twenty.
#[near(serializers = [json])]
pub struct DecisionLog {
    pub decisions: Vec<Decision>,
    pub decision_count: u64,
    pub strangers: Vec<Decision>,
    pub stranger_count: u64,
}

/// One entry in the ring buffer: everything the demo page shows about one attempt.
///
/// `node` is `None` when the caller's account id does not derive to a node at all (an id with
/// no `.`), which is half of refusal code 1. There is genuinely no node to name in that case,
/// and naming the agent instead would read as a configured node that was refused.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Decision {
    /// The caller: `predecessor_account_id` on the `spend` call.
    pub agent: AccountId,
    /// The budget the caller draws on, derived from its id. See `node::node_of`.
    pub node: Option<AccountId>,
    pub payee: AccountId,
    #[serde(with = "u128_dec")]
    pub amount: u128,
    pub outcome: Outcome,
    /// What the node had spent in its window once this decision was accounted for: the
    /// reservation included on `Allowed`, released again on `Failed`, untouched on a refusal.
    #[serde(with = "u128_dec")]
    pub spent_after: u128,
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::serde_json;

    /// The table is the contract's public numbering. If a row moves, this fails.
    #[test]
    fn the_codes_are_one_to_seven_in_order() {
        let codes: Vec<u8> = REFUSALS.iter().map(|r| r.code).collect();
        assert_eq!(codes, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn every_code_constant_has_a_row() {
        for c in [
            code::NO_RULE,
            code::PAUSED,
            code::WRONG_TOKEN,
            code::PAYEE_NOT_ALLOWED,
            code::OVER_PER_TX_LIMIT,
            code::OVER_PERIOD_LIMIT,
            code::OUTSIDE_WINDOW,
        ] {
            assert!(reason_for(c).is_some(), "code {c} has no reason");
        }
        assert_eq!(reason_for(0), None);
        assert_eq!(reason_for(8), None);
    }

    #[test]
    fn no_two_rows_share_a_reason() {
        for (i, a) in REFUSALS.iter().enumerate() {
            for b in REFUSALS.iter().skip(i + 1) {
                assert_ne!(a.reason, b.reason, "two codes read the same to a human");
            }
        }
    }

    /// A refusal on the wire carries the number *and* the sentence, so no client has to keep
    /// its own copy of the table.
    #[test]
    fn a_refusal_serialises_with_its_reason() {
        let j = serde_json::to_value(Outcome::Refused(code::PAYEE_NOT_ALLOWED)).unwrap();
        assert_eq!(j["status"], "refused");
        assert_eq!(j["code"], 4);
        assert_eq!(j["reason"], "payee is not on the allow-list");
    }

    #[test]
    fn allowed_and_failed_carry_no_code() {
        for (o, status) in [(Outcome::Allowed, "allowed"), (Outcome::Failed, "failed")] {
            let j = serde_json::to_value(o).unwrap();
            assert_eq!(j["status"], status);
            assert!(j.get("code").is_none(), "{status} should carry no code: {j}");
            assert!(j.get("reason").is_none(), "{status} should carry no reason: {j}");
        }
    }

    #[test]
    fn an_outcome_survives_a_round_trip() {
        for o in [Outcome::Allowed, Outcome::Failed, Outcome::Refused(7)] {
            let s = serde_json::to_string(&o).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&s).unwrap(), o, "round trip of {s}");
        }
    }

    #[test]
    fn a_refused_outcome_without_a_code_is_rejected() {
        let r = serde_json::from_str::<Outcome>(r#"{"status":"refused"}"#);
        assert!(r.is_err(), "a refusal with no code must not deserialise");
    }

    /// Borsh is what the ring buffer is stored as, so a decision has to come back out of
    /// storage byte-identical.
    #[test]
    fn a_decision_survives_borsh() {
        let d = Decision {
            agent: "pay.ops.leash.testnet".parse().unwrap(),
            node: Some("ops.leash.testnet".parse().unwrap()),
            payee: "alice.testnet".parse().unwrap(),
            amount: u128::MAX,
            outcome: Outcome::Refused(6),
            spent_after: 42,
            timestamp_ms: 1_700_000_000_000,
        };
        let bytes = near_sdk::borsh::to_vec(&d).unwrap();
        let back: Decision = near_sdk::borsh::from_slice(&bytes).unwrap();
        assert_eq!(back.agent, d.agent);
        assert_eq!(back.node, d.node);
        assert_eq!(back.amount, u128::MAX);
        assert_eq!(back.outcome, Outcome::Refused(6));
        assert_eq!(back.spent_after, 42);
        assert_eq!(back.timestamp_ms, d.timestamp_ms);
    }

    /// Balances go on the wire as decimal strings, because a JavaScript number loses
    /// precision above 2^53 and these are token amounts.
    #[test]
    fn amounts_are_strings_on_the_wire() {
        let d = Decision {
            agent: "pay.ops.leash.testnet".parse().unwrap(),
            node: None,
            payee: "alice.testnet".parse().unwrap(),
            amount: 1,
            outcome: Outcome::Refused(1),
            spent_after: 0,
            timestamp_ms: 0,
        };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j["amount"], "1");
        assert_eq!(j["spent_after"], "0");
        assert!(j["node"].is_null(), "an underivable node is null, not a stand-in");
    }
}
