//! Two agents, one budget, no coordinator.
//!
//! This is the claim the whole shared-budget design rests on: two processes with no channel
//! between them draw down one number, and the chain is the only thing keeping them honest.
//! No database, no lock, no leader election — the budget is a counter in contract state and
//! atomicity comes from how NEAR executes receipts.
//!
//! What makes it work is the order inside `spend`: the amount is added to the node's `spent`
//! **before** `ft_transfer` is dispatched. Receipts in a block execute one after another
//! against the state the previous one left, so the second agent sees the first one's
//! reservation and is refused with code 6 — not because our code took a lock, but because the
//! reservation is already in state by the time it reads it.
//!
//! Checking the limit and *then* transferring, with the ledger written in the callback, would
//! fail here: both agents would read the same zero and both would be allowed.

mod common;

use common::{
    agents, balance_of, deploy_with_token, recent_decisions, register_passkey, rule, rule_json,
    set_rule_signed, spend, spent_in_period, Agents, Fixture, Passkey,
};
use leash_contract::decision::Outcome;
use near_workspaces::result::ExecutionFinalResult;
use serde_json::json;

const DAY: u64 = 86_400_000;
const ALICE: &str = "alice.testnet";

/// A node whose period limit leaves room for exactly one payment of `per_tx`.
///
/// `per_tx_limit == period_limit` is the sharp case: each agent's payment is individually
/// legal and only one of them can happen.
async fn ready(per_tx: u128) -> anyhow::Result<(Fixture, Agents)> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register_passkey(&fx, &pk).await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(&fx, &pk, &ag.node, &rule(&token, per_tx, per_tx, DAY, 0, u64::MAX, &[ALICE], false))
        .await?;
    Ok((fx, ag))
}

/// The outcome a `spend` call returned, through the wire shape a client sees.
fn outcome_of(res: ExecutionFinalResult) -> anyhow::Result<Outcome> {
    let v: serde_json::Value = res.json()?;
    let s = serde_json::to_string(&v)?;
    Ok(near_sdk::serde_json::from_str(&s)?)
}

/// The test this whole design exists to pass: both agents ask for the last of the budget at
/// the same moment, and exactly one of them gets it.
#[tokio::test]
async fn two_agents_cannot_both_spend_the_last_of_the_budget() -> anyhow::Result<()> {
    let (fx, ag) = ready(600).await?;
    let token = fx.token.id().to_string();

    let (a, b) = tokio::join!(
        spend(&fx, &ag.pay, &token, ALICE, 600),
        spend(&fx, &ag.subs, &token, ALICE, 600),
    );
    let (a, b) = (a?, b?);
    assert!(a.is_success(), "pay's transaction failed outright: {a:#?}");
    assert!(b.is_success(), "subs's transaction failed outright: {b:#?}");

    let outcomes = [outcome_of(a)?, outcome_of(b)?];
    println!("concurrent outcomes: {outcomes:?}");
    assert_eq!(
        outcomes.iter().filter(|o| **o == Outcome::Allowed).count(),
        1,
        "exactly one of the two must be allowed, got {outcomes:?}"
    );
    // The other one is refused for the right reason: the budget, not the token or the payee.
    assert!(
        outcomes.contains(&Outcome::Refused(6)),
        "the loser must be refused with code 6, got {outcomes:?}"
    );

    assert_eq!(spent_in_period(&fx, &ag.node).await?, 600, "the ledger must show one payment");
    assert!(spent_in_period(&fx, &ag.node).await? <= 600, "the period limit must hold");
    assert_eq!(balance_of(&fx, ALICE).await?, 600, "exactly one payment may have landed");

    // Both attempts are in the log, so the demo can show the refusal next to the payment.
    let log = recent_decisions(&fx).await?;
    assert_eq!(log.len(), 2, "both attempts must be recorded: {log:#?}");
    let agents_in_log: Vec<&str> = log.iter().filter_map(|d| d["agent"].as_str()).collect();
    assert!(agents_in_log.contains(&ag.pay.id().as_str()));
    assert!(agents_in_log.contains(&ag.subs.id().as_str()));
    Ok(())
}

/// The other side of the same coin: when there is room for both, the reservation must not
/// refuse a payment that the budget can afford. A guard that over-refuses is as wrong as one
/// that under-refuses, and it would be the easy way to make the test above pass.
#[tokio::test]
async fn two_agents_can_both_spend_when_the_budget_allows_it() -> anyhow::Result<()> {
    let (fx, ag) = ready(600).await?;
    let token = fx.token.id().to_string();
    // Room for two payments of 300 and nothing more.
    let tight = rule(&token, 300, 600, DAY, 0, u64::MAX, &[ALICE], false);
    fx.admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": ag.node, "rule": rule_json(&tight), "assertion": null }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let (a, b) = tokio::join!(
        spend(&fx, &ag.pay, &token, ALICE, 300),
        spend(&fx, &ag.subs, &token, ALICE, 300),
    );
    let outcomes = [outcome_of(a?)?, outcome_of(b?)?];
    assert_eq!(outcomes, [Outcome::Allowed, Outcome::Allowed], "both should fit: {outcomes:?}");
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 600);
    assert_eq!(balance_of(&fx, ALICE).await?, 600);
    Ok(())
}

/// Four concurrent attempts against room for one. The budget is a counter, not a mutex, so
/// more callers must not make it leakier.
#[tokio::test]
async fn four_concurrent_attempts_still_spend_the_budget_once() -> anyhow::Result<()> {
    let (fx, ag) = ready(500).await?;
    let token = fx.token.id().to_string();

    // Four calls at once from two accounts — what a flaky retry loop looks like.
    //
    // The amounts differ by a yocto each, and that is not decoration: NEAR deduplicates by
    // transaction hash, so two byte-identical calls from one account are **one** transaction
    // submitted twice, and the second `transact()` is handed the first one's result. With four
    // identical calls this test reads as two allowed payments when only one happened. Each
    // amount is under the per-transaction limit of 500 and only one of them fits in the
    // period limit of 500.
    let (a, b, c, d) = tokio::join!(
        spend(&fx, &ag.pay, &token, ALICE, 500),
        spend(&fx, &ag.subs, &token, ALICE, 499),
        spend(&fx, &ag.pay, &token, ALICE, 498),
        spend(&fx, &ag.subs, &token, ALICE, 497),
    );
    let (a, b, c, d) = (a?, b?, c?, d?);
    let hashes = [a.outcome().transaction_hash, b.outcome().transaction_hash, c.outcome().transaction_hash, d.outcome().transaction_hash];
    let outcomes = [outcome_of(a)?, outcome_of(b)?, outcome_of(c)?, outcome_of(d)?];
    println!("four concurrent outcomes: {outcomes:?}");
    for h in &hashes {
        println!("  tx {h}");
    }
    assert_eq!(
        hashes.iter().collect::<std::collections::HashSet<_>>().len(),
        4,
        "the four calls must be four distinct transactions, or this test proves nothing"
    );
    assert_eq!(
        outcomes.iter().filter(|o| **o == Outcome::Allowed).count(),
        1,
        "exactly one may be allowed, got {outcomes:?}"
    );
    // Exactly one payment landed, and which one it was depends on the order the chunk put
    // them in — so assert the invariant, not the winner.
    let spent = spent_in_period(&fx, &ag.node).await?;
    assert!((497..=500).contains(&spent), "one payment's worth should be spent, got {spent}");
    assert!(spent <= 500, "the period limit must hold");
    assert_eq!(balance_of(&fx, ALICE).await?, spent, "the ledger and the token must agree");
    Ok(())
}

/// One budget, two agents, no coordinator: the node's limit is not a per-agent limit. One
/// agent spending it all leaves the other with nothing, and that is the shared-budget claim
/// stated as a test.
#[tokio::test]
async fn the_budget_belongs_to_the_node_not_to_the_agent() -> anyhow::Result<()> {
    let (fx, ag) = ready(1_000).await?;
    let token = fx.token.id().to_string();

    let res = spend(&fx, &ag.pay, &token, ALICE, 1_000).await?;
    assert_eq!(outcome_of(res)?, Outcome::Allowed);

    let res = spend(&fx, &ag.subs, &token, ALICE, 1).await?;
    assert!(res.is_success(), "the second agent's transaction must still succeed: {res:#?}");
    assert_eq!(
        outcome_of(res)?,
        Outcome::Refused(6),
        "the second agent must draw on the same exhausted budget"
    );
    assert_eq!(balance_of(&fx, ALICE).await?, 1_000);
    Ok(())
}
