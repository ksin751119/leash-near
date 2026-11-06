//! The payment path: the seven refusals, an allowed payment, and what happens to a
//! reservation when the transfer fails.
//!
//! # What these tests are really pinning
//!
//! `spend.rs`'s unit tests already prove that the *policy* answers correctly, with no chain
//! involved. What can only be checked here is the thing the product is made of:
//!
//! ```text
//! assert!(res.is_success());                    // the transaction succeeded
//! assert_eq!(balance_before, balance_after);    // no money moved
//! assert_eq!(newest_outcome, Refused(n));       // and the chain said why
//! ```
//!
//! All three together. A refusal that panicked would satisfy the second line and fail the
//! first and third — and a panicking refusal is exactly what this contract must not do, because
//! `env::panic_str` rolls back the ring-buffer write and leaves a failed transaction with no
//! on-chain explanation. The refusal is the product.

mod common;

use common::{
    agents, balance_of, build_wasm, decision_log, deploy_with_token, newest_outcome,
    outcome_of_newest, pause_account, recent_decisions, recent_for_code, recent_strangers,
    register_passkey, restricted_key, rule, rule_json, set_rule_signed, spend, spent_in_period,
    why, Agents, Fixture, Passkey, HOST_PANIC_IMPORT,
};
use leash_contract::decision::Outcome;
use leash_contract::rule::Rule;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, Gas, SecretKey};
use near_workspaces::Account;
use serde_json::json;

const DAY: u64 = 86_400_000;
const ALICE: &str = "alice.testnet";
const MALLORY: &str = "mallory.testnet";

/// A generous rule for `ALICE`, so that each test can break exactly one thing about it.
fn base_rule(token: &str) -> Rule {
    rule(token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false)
}

/// Deploy the wallet and the token, create `pay.ops.…` and `subs.ops.…`, and give their
/// shared node `base_rule`.
async fn ready() -> anyhow::Result<(Fixture, Passkey, Agents)> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register_passkey(&fx, &pk).await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(&fx, &pk, &ag.node, &base_rule(&token)).await?;
    Ok((fx, pk, ag))
}

/// The value a `spend` call returned, read back through the wire shape a client sees.
fn returned_outcome(res: ExecutionFinalResult) -> anyhow::Result<Outcome> {
    let v: serde_json::Value = res.json()?;
    let s = serde_json::to_string(&v)?;
    Ok(near_sdk::serde_json::from_str(&s)?)
}

/// The demo's triple, in one place: the transaction succeeded, nothing moved, and the chain
/// recorded why. Also checks the returned value and the node's ledger, both of which a
/// refusal must leave alone.
///
/// Code 1 is read out of the stranger ring rather than the main one — see
/// `strangers_cannot_evict_a_real_agents_decisions` for why there are two.
async fn assert_refused(
    fx: &Fixture,
    node: &str,
    caller: &Account,
    token: &str,
    payee: &str,
    amount: u128,
    code: u8,
) -> anyhow::Result<()> {
    let payee_before = balance_of(fx, payee).await?;
    let wallet_before = balance_of(fx, fx.wallet.id().as_str()).await?;
    let spent_before = spent_in_period(fx, node).await?;

    let res = spend(fx, caller, token, payee, amount).await?;
    assert!(
        res.is_success(),
        "a refusal must arrive in a SUCCESSFUL transaction, or there is nothing on chain to \
         read: {res:#?}"
    );
    assert_eq!(
        balance_of(fx, payee).await?,
        payee_before,
        "the payee's balance moved on a refusal"
    );
    assert_eq!(
        balance_of(fx, fx.wallet.id().as_str()).await?,
        wallet_before,
        "the wallet's balance moved on a refusal"
    );
    assert_eq!(
        outcome_of_newest(&recent_for_code(fx, code).await?)?,
        Outcome::Refused(code),
        "the recorded decision does not say code {code}"
    );
    assert_eq!(
        spent_in_period(fx, node).await?,
        spent_before,
        "a refusal must reserve nothing"
    );
    assert_eq!(returned_outcome(res)?, Outcome::Refused(code), "the returned value");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The seven refusals
// ---------------------------------------------------------------------------------------

/// Code 1, the "no budget" half: the caller's id derives to a node, and that node has no rule.
#[tokio::test]
async fn a_node_with_no_rule_is_refused_with_one() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    // No `set_rule` at all. The payee is not even registered on the token, which is the point:
    // the refusal must come from policy, before anything is dispatched.
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 1, 1).await?;
    Ok(())
}

/// Code 1, the other half: an account id with no `.` derives to no node whatsoever. The
/// decision records `node: null` rather than naming the caller, because there is genuinely no
/// budget to name.
#[tokio::test]
async fn an_id_that_derives_to_no_node_is_refused_with_one() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // A top-level account: `agentless` has no separator, so `node_of` returns `None`.
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    let stranger = fx
        .worker
        .create_tla("agentless".parse()?, sk)
        .await?
        .into_result()?;

    assert_refused(&fx, &ag.node, &stranger, &token, ALICE, 1, 1).await?;
    let newest = &recent_strangers(&fx).await?[0];
    assert!(newest["node"].is_null(), "an underivable node must record as null: {newest}");
    assert_eq!(newest["agent"], json!("agentless"));
    Ok(())
}

/// Code 2, account-wide. Pausing is ungated — it is the emergency brake — so this is one
/// admin call away at any time.
#[tokio::test]
async fn a_paused_account_is_refused_with_two() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    pause_account(&fx).await?;
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 100, 2).await?;
    Ok(())
}

/// Code 2, per node: the account is running, this one node is not. Setting `paused` on a rule
/// is a tightening, so it needs no assertion either.
#[tokio::test]
async fn a_paused_node_is_refused_with_two() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    let paused = rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], true);
    fx.admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": ag.node, "rule": rule_json(&paused), "assertion": null }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 100, 2).await?;
    Ok(())
}

/// Code 3. The whole reason `spend` takes a `token` argument: without it the contract would
/// pay out of whatever the rule named and "this node may only spend USDC" would be a sentence
/// with no check behind it.
#[tokio::test]
async fn another_token_is_refused_with_three() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    // A second, real token contract, so this is not refused for being a nonexistent account.
    let other = fx.worker.dev_deploy(&build_wasm("test-token")?).await?;
    other
        .call("new")
        .args_json(json!({ "owner_id": fx.wallet.id(), "total_supply": "1000", "decimals": 6 }))
        .transact()
        .await?
        .into_result()?;
    assert_refused(&fx, &ag.node, &ag.pay, other.id().as_str(), ALICE, 100, 3).await?;
    Ok(())
}

/// Code 4. An empty allow-list means pay nobody; a list with `alice` on it means pay alice.
#[tokio::test]
async fn a_payee_off_the_list_is_refused_with_four() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    assert_refused(&fx, &ag.node, &ag.pay, &token, MALLORY, 100, 4).await?;
    Ok(())
}

/// Code 5. Exactly the limit is allowed, one above it is not.
#[tokio::test]
async fn over_the_per_tx_limit_is_refused_with_five() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 1_001, 5).await?;

    // And the boundary itself goes through, so the refusal above is the limit and not an
    // off-by-one somewhere.
    let res = spend(&fx, &ag.pay, &token, ALICE, 1_000).await?;
    assert!(res.is_success(), "a payment of exactly the limit was refused: {res:#?}");
    assert_eq!(returned_outcome(res)?, Outcome::Allowed);
    Ok(())
}

/// Code 6. Three payments of 400 against a period limit of 1,000: the third is refused even
/// though each one is under the per-transaction limit. This is the budget doing its job.
#[tokio::test]
async fn over_the_period_limit_is_refused_with_six() -> anyhow::Result<()> {
    let (fx, pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    // A tightening of `period_limit`, so no assertion needed; `set_rule_signed` would also
    // work but would reset the ledger, which is the opposite of what this test measures.
    let tight = rule(&token, 1_000, 1_000, DAY, 0, u64::MAX, &[ALICE], false);
    fx.admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": ag.node, "rule": rule_json(&tight), "assertion": null }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    let _ = pk;

    for i in 1..=2 {
        let res = spend(&fx, &ag.pay, &token, ALICE, 400).await?;
        assert!(res.is_success(), "payment {i} of 400 failed: {res:#?}");
        assert_eq!(returned_outcome(res)?, Outcome::Allowed, "payment {i} of 400");
    }
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 800);

    // 800 + 400 > 1,000, so the third is refused — and the other agent on the same node is
    // refused too, because the budget is shared.
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 400, 6).await?;
    assert_refused(&fx, &ag.node, &ag.subs, &token, ALICE, 400, 6).await?;

    // What is left still goes through.
    let res = spend(&fx, &ag.subs, &token, ALICE, 200).await?;
    assert!(res.is_success(), "the remaining 200 was refused: {res:#?}");
    assert_eq!(returned_outcome(res)?, Outcome::Allowed);
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 1_000);
    Ok(())
}

/// Code 7. The window is an absolute interval in ms, inclusive at both ends; this one closed
/// before the sandbox's clock reached it.
#[tokio::test]
async fn outside_the_window_is_refused_with_seven() -> anyhow::Result<()> {
    let (fx, pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    // Narrowing the window is a tightening, so this needs no assertion. The interval is in
    // 1970, which every block timestamp is past.
    let closed = rule(&token, 1_000, 10_000, DAY, 1, 2, &[ALICE], false);
    fx.admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": ag.node, "rule": rule_json(&closed), "assertion": null }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    let _ = pk;
    assert_refused(&fx, &ag.node, &ag.pay, &token, ALICE, 100, 7).await?;
    Ok(())
}

/// Every code the contract publishes is reachable, and the demo page can fetch the sentences
/// rather than keeping its own copy of them.
#[tokio::test]
async fn the_contract_publishes_the_reason_for_every_code() -> anyhow::Result<()> {
    let (fx, _pk, _ag) = ready().await?;
    let table: Vec<serde_json::Value> = fx.wallet.view("refusal_codes").await?.json()?;
    assert_eq!(table.len(), 7);
    for (i, row) in table.iter().enumerate() {
        assert_eq!(row["code"], json!(i as u8 + 1));
        assert!(
            row["reason"].as_str().is_some_and(|s| !s.is_empty()),
            "code {} has no reason: {row}",
            i + 1
        );
    }
    println!("refusal_codes(): {}", serde_json::to_string_pretty(&table)?);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// An allowed payment
// ---------------------------------------------------------------------------------------

/// The happy path, from the key an agent process actually holds: a function-call key
/// restricted to `spend`, with **no deposit attached** — it cannot attach one. The contract
/// pays NEP-141's one yoctoNEAR itself.
#[tokio::test]
async fn an_allowed_payment_transfers_and_settles() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    let agent = restricted_key(&fx, &ag.pay).await?;

    let wallet_before = balance_of(&fx, fx.wallet.id().as_str()).await?;
    let alice_before = balance_of(&fx, ALICE).await?;

    let res = spend(&fx, &agent, &token, ALICE, 750).await?;
    assert!(res.is_success(), "an allowed payment failed: {res:#?}");

    let logs: Vec<String> = res.logs().iter().map(|l| l.to_string()).collect();
    assert_eq!(returned_outcome(res)?, Outcome::Allowed);

    assert_eq!(balance_of(&fx, ALICE).await?, alice_before + 750, "the payee was not paid");
    assert_eq!(
        balance_of(&fx, fx.wallet.id().as_str()).await?,
        wallet_before - 750,
        "the money did not come out of the wallet"
    );
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 750, "the ledger did not record it");

    let newest = &recent_decisions(&fx).await?[0];
    assert_eq!(newest["outcome"]["status"], json!("allowed"));
    assert_eq!(newest["agent"], json!(ag.pay.id().as_str()));
    assert_eq!(newest["node"], json!(ag.node));
    assert_eq!(newest["payee"], json!(ALICE));
    assert_eq!(newest["amount"], json!("750"));
    assert_eq!(newest["spent_after"], json!("750"));
    assert!(newest["timestamp_ms"].as_u64().is_some_and(|t| t > 0));

    // Both halves of the event stream: the reservation, then the settlement.
    let events: Vec<&String> = logs.iter().filter(|l| l.starts_with("EVENT_JSON:")).collect();
    assert!(
        events.iter().any(|l| l.contains(r#""event":"allowed""#)),
        "no allowed event: {logs:#?}"
    );
    assert!(
        events.iter().any(|l| l.contains(r#""event":"settled""#)),
        "no settled event: {logs:#?}"
    );
    for e in events {
        println!("{e}");
    }
    Ok(())
}

/// A payment to a listed payee must never fail for an unregistered-receiver reason. The
/// invariant is "on the list" means "can be paid": both `set_rule` and `add_payee` pay the
/// token's `storage_deposit` before the payee reaches the list.
#[tokio::test]
async fn a_listed_payee_can_always_be_paid() -> anyhow::Result<()> {
    let (fx, pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // `bob.testnet` has never touched this token, and arrives purely through the rule.
    let wider = rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE, "bob.testnet"], false);
    set_rule_signed(&fx, &pk, &ag.node, &wider).await?;

    let res = spend(&fx, &ag.pay, &token, "bob.testnet", 10).await?;
    assert!(res.is_success(), "paying a freshly listed payee failed: {res:#?}");
    assert_eq!(returned_outcome(res)?, Outcome::Allowed);
    assert_eq!(balance_of(&fx, "bob.testnet").await?, 10);
    Ok(())
}

/// The reservation comes back when the transfer fails, and the record says `failed` rather
/// than claiming a payment that never happened.
///
/// The failure is forced by asking for more of the token than the wallet holds, so
/// `ft_transfer` panics inside the token contract. Everything on this side — policy, the
/// reservation, the dispatch — worked; only the transfer did not.
#[tokio::test]
async fn a_failed_transfer_releases_the_reservation() -> anyhow::Result<()> {
    let (fx, pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    let held = balance_of(&fx, fx.wallet.id().as_str()).await?;

    // Limits above the wallet's whole balance, so policy allows an amount the token cannot
    // move. A widening, so it is signed.
    let big = rule(&token, held * 2, held * 4, DAY, 0, u64::MAX, &[ALICE], false);
    set_rule_signed(&fx, &pk, &ag.node, &big).await?;

    let spent_before = spent_in_period(&fx, &ag.node).await?;
    let alice_before = balance_of(&fx, ALICE).await?;
    let amount = held + 1;

    let res = spend(&fx, &ag.pay, &token, ALICE, amount).await?;
    // A failed transfer is still a SUCCESSFUL transaction — the same property the seven
    // refusal tests assert. Only the returned `status` says the money did not move, and a
    // caller that reads the transaction's status instead would call this a crash.
    assert!(
        res.is_success(),
        "a failed transfer must still arrive in a successful transaction: {res:#?}"
    );
    for l in res.logs() {
        println!("  log: {l}");
    }

    assert_eq!(
        spent_in_period(&fx, &ag.node).await?,
        spent_before,
        "the reservation was not released"
    );
    assert_eq!(balance_of(&fx, ALICE).await?, alice_before, "money moved on a failed transfer");
    assert_eq!(
        balance_of(&fx, fx.wallet.id().as_str()).await?,
        held,
        "the wallet's balance changed on a failed transfer"
    );
    assert_eq!(newest_outcome(&fx).await?, Outcome::Failed);

    // And the node can still spend what it was always allowed to spend: a failed transfer
    // must not cost the budget anything.
    let res = spend(&fx, &ag.pay, &token, ALICE, 500).await?;
    assert!(res.is_success(), "a payment after a failed one was refused: {res:#?}");
    assert_eq!(returned_outcome(res)?, Outcome::Allowed);
    assert_eq!(spent_in_period(&fx, &ag.node).await?, spent_before + 500);
    Ok(())
}

/// A zero-amount payment is a documented shape rather than an eighth refusal code: policy has
/// nothing to object to, so it is dispatched and NEP-141 rejects it. It records as `failed`,
/// moves no money, and releases a reservation of zero.
#[tokio::test]
async fn a_zero_amount_payment_fails_at_the_token() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    let res = spend(&fx, &ag.pay, &token, ALICE, 0).await?;
    assert!(
        res.is_success(),
        "a zero-amount payment must still arrive in a successful transaction: {res:#?}"
    );
    assert_eq!(returned_outcome(res)?, Outcome::Failed);
    assert_eq!(newest_outcome(&fx).await?, Outcome::Failed);
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 0);
    assert_eq!(balance_of(&fx, ALICE).await?, 0);
    Ok(())
}

/// The other way a reservation could leak: the reservation is written in one receipt and
/// released in another, so what happens if the second one never runs for want of gas?
///
/// It cannot be starved. `ft_transfer` and the callback are dispatched with *static* gas,
/// taken out of what the caller attached at dispatch time — so either there is enough and the
/// callback is guaranteed its 15 TGas, or there is not and the `spend` receipt itself fails,
/// rolling back the reservation with it. There is no middle where the money is reserved and
/// nothing comes back to release it.
#[tokio::test]
async fn too_little_gas_reserves_nothing() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // Below the 20 + 15 TGas the two promises need, so the dispatch cannot even be built.
    let res = ag
        .pay
        .call(fx.wallet.id(), "spend")
        .args_json(json!({ "token": token, "payee": ALICE, "amount": "100" }))
        .gas(Gas::from_tgas(10))
        .transact()
        .await?;
    assert!(res.is_failure(), "a payment with 10 TGas should not go through: {res:#?}");

    assert_eq!(spent_in_period(&fx, &ag.node).await?, 0, "a reservation outlived its receipt");
    assert_eq!(balance_of(&fx, ALICE).await?, 0, "money moved");
    assert!(
        recent_decisions(&fx).await?.is_empty(),
        "the whole receipt must roll back, decision included"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The ring buffer
// ---------------------------------------------------------------------------------------

/// Bounded storage is a requirement of the design, not an optimisation: the contract account
/// stakes every byte of the decision log, and the account cannot be redeployed to fix it.
#[tokio::test]
async fn the_ring_buffer_holds_exactly_twenty() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // 25 refusals, each with a different amount so the ring's contents are identifiable.
    for i in 1..=25u128 {
        let res = spend(&fx, &ag.pay, &token, MALLORY, i).await?;
        assert!(res.is_success(), "refusal {i} did not succeed: {res:#?}");
    }

    let all = recent_decisions(&fx).await?;
    assert_eq!(all.len(), 20, "the ring must hold exactly twenty");
    assert_eq!(all[0]["amount"], json!("25"), "newest first");
    assert_eq!(all[19]["amount"], json!("6"), "and the five oldest are gone");

    let count: u64 = fx.wallet.view("decision_count").await?.json()?;
    assert_eq!(count, 25, "the count must still know how many there were");
    Ok(())
}

/// The attack the two rings exist to stop.
///
/// `spend` is open to any caller on NEAR — the rule for the derived node is the whole of the
/// authorisation, and a caller with no rule is *answered* with code 1 rather than turned away.
/// So anyone with a testnet account and a few hundred microNEAR can write to the decision log,
/// and twenty such calls into a twenty-slot ring would evict every real decision from it. The
/// ring is the demo's evidence: the screen that shows what the chain refused and why reads
/// from it, so one bored onlooker could blank it mid-recording.
///
/// Strangers therefore go in their own small ring and can only evict each other. Code 1 stays
/// visible — "an unknown agent is refused, and you can see it" is part of the story — and
/// `stranger_count` is where the flood shows up.
#[tokio::test]
async fn strangers_cannot_evict_a_real_agents_decisions() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // Three real decisions: an allowed payment and two refusals that a demo would be showing.
    spend(&fx, &ag.pay, &token, ALICE, 100).await?.into_result()?;
    spend(&fx, &ag.pay, &token, MALLORY, 100).await?.into_result()?;
    spend(&fx, &ag.pay, &token, ALICE, 5_000).await?.into_result()?;
    let before = recent_decisions(&fx).await?;
    assert_eq!(before.len(), 3);

    // One stranger, 20 calls — enough to fill the main ring exactly once over.
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    let onlooker = fx
        .worker
        .create_tla("onlooker".parse()?, sk)
        .await?
        .into_result()?;
    for i in 1..=20u128 {
        let res = spend(&fx, &onlooker, &token, ALICE, i).await?;
        assert!(res.is_success(), "stranger call {i} did not succeed: {res:#?}");
        assert_eq!(returned_outcome(res)?, Outcome::Refused(1), "stranger call {i}");
    }

    // Every real decision is exactly where it was.
    let after = recent_decisions(&fx).await?;
    assert_eq!(after, before, "a stranger evicted a real agent's decisions");

    // And the refusals are still visible, in their own bounded space.
    let strangers = recent_strangers(&fx).await?;
    assert_eq!(strangers.len(), 4, "the stranger ring must stay small");
    assert_eq!(strangers[0]["amount"], json!("20"), "newest first");
    assert_eq!(strangers[0]["outcome"]["code"], json!(1));
    assert!(strangers[0]["node"].is_null(), "a top-level caller derives to no node");

    let log = decision_log(&fx).await?;
    assert_eq!(log["decision_count"], json!(3));
    assert_eq!(log["stranger_count"], json!(20), "the count is where a flood shows up");
    assert_eq!(log["decisions"].as_array().map(Vec::len), Some(3));
    assert_eq!(log["strangers"].as_array().map(Vec::len), Some(4));
    println!(
        "after 20 stranger calls: decisions={} (count {}), strangers={} (count {})",
        log["decisions"].as_array().unwrap().len(),
        log["decision_count"],
        log["strangers"].as_array().unwrap().len(),
        log["stranger_count"],
    );
    println!("the real decisions, untouched: {}", serde_json::to_string_pretty(&after)?);
    Ok(())
}

/// The other half: a node that *has* a rule is not a stranger, however little it is allowed
/// to spend. Its refusals belong in the main ring, where the demo shows them.
#[tokio::test]
async fn a_configured_node_is_never_a_stranger() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    // Code 4: a rule exists, the payee is not on it.
    assert_refused(&fx, &ag.node, &ag.pay, &token, MALLORY, 100, 4).await?;
    assert_eq!(recent_decisions(&fx).await?.len(), 1);
    assert!(recent_strangers(&fx).await?.is_empty(), "a configured node is not a stranger");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------------------

/// `on_transfer` is a promise target, so it must stay exported — and `#[private]` alone does
/// not protect it. `#[private]` checks that the predecessor is this account, and the agent's
/// function-call keys live **on this account**, so an agent key arrives with exactly that
/// predecessor and satisfies it.
///
/// This test therefore calls `on_transfer` from a key **on the wallet account**, which is the
/// only form of the test that proves anything: a call from another account would be refused by
/// `#[private]` regardless, and would say nothing about the pairing that actually defends this
/// method — that the promise result it expects must really be there.
///
/// What an attacker would be after: `on_transfer(node, record_id, amount, window)` releases a
/// reservation, so a direct call is free headroom on any node, as often as it likes, plus a
/// rewritten decision log.
#[tokio::test]
async fn on_transfer_cannot_be_driven_by_an_agent_key() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();

    // Spend something first, so there is a reservation to try to release and a record to try
    // to rewrite.
    spend(&fx, &ag.pay, &token, ALICE, 600).await?.into_result()?;
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 600);
    let window: Option<u64> = fx
        .wallet
        .view("window_began_ms")
        .args_json(json!({ "node": ag.node }))
        .await?
        .json()?;
    let epoch: Option<u32> = fx
        .wallet
        .view("epoch_of")
        .args_json(json!({ "node": ag.node }))
        .await?
        .json()?;
    // The real reservation's ledger, so the call is as convincing as an attacker could make
    // it: nothing about the arguments is wrong, and it is still refused.
    let reserved = json!({
        "window_began_ms": window.expect("the node has a window"),
        "epoch": epoch.expect("the node has an epoch"),
    });

    // A deliberately over-broad function-call key on the wallet account, so the call reaches
    // the contract and `#[private]` is satisfied by it.
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    fx.wallet
        .batch()
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend", "on_transfer"], None),
        )
        .transact()
        .await?
        .into_result()?;
    let attacker = Account::from_secret_key(fx.wallet.id().clone(), sk, &fx.worker);

    for (record_id, amount) in [(0u64, "600"), (0, "1000000"), (7, "600")] {
        let res = attacker
            .call(fx.wallet.id(), "on_transfer")
            .args_json(json!({
                "node": ag.node,
                "record_id": record_id,
                "amount": amount,
                "reserved": reserved,
            }))
            .max_gas()
            .transact()
            .await?;
        assert!(
            res.is_failure(),
            "an agent key drove the callback (record_id={record_id}, amount={amount}): {res:#?}"
        );
        let msg = why(res);
        assert!(
            msg.contains("not callable directly"),
            "refused, but not by the callback check: {msg}"
        );
    }

    // Nothing was released and nothing was rewritten.
    assert_eq!(
        spent_in_period(&fx, &ag.node).await?,
        600,
        "a direct callback call changed the ledger"
    );
    assert_eq!(newest_outcome(&fx).await?, Outcome::Allowed, "the record was rewritten");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Gas
// ---------------------------------------------------------------------------------------

/// The figures the README quotes, and the reason the gas constants are what they are. Both
/// paths have to fit inside the 300 TGas a transaction gets, and an agent attaches that much.
#[tokio::test]
async fn a_payment_fits_in_gas() -> anyhow::Result<()> {
    let (fx, _pk, ag) = ready().await?;
    let token = fx.token.id().to_string();
    let agent = restricted_key(&fx, &ag.pay).await?;

    let allowed = spend(&fx, &agent, &token, ALICE, 100).await?;
    assert!(allowed.is_success(), "the measured payment failed: {allowed:#?}");
    let allowed_gas = allowed.total_gas_burnt;

    let refused = spend(&fx, &agent, &token, MALLORY, 100).await?;
    assert!(refused.is_success(), "the measured refusal failed: {refused:#?}");
    let refused_gas = refused.total_gas_burnt;

    let tgas = |g: Gas| g.as_gas() as f64 / 1e12;
    println!(
        "spend (allowed: policy + reservation + ft_transfer + callback): {allowed_gas} ({:.2} TGas)",
        tgas(allowed_gas)
    );
    println!(
        "spend (refused: policy + one ring-buffer write, no promise):    {refused_gas} ({:.2} TGas)",
        tgas(refused_gas)
    );

    let limit = Gas::from_tgas(300);
    assert!(allowed_gas < limit, "an allowed payment does not fit in 300 TGas");
    assert!(refused_gas < limit, "a refusal does not fit in 300 TGas");
    // A refusal never leaves the contract, so it must be far cheaper than a payment. If this
    // ever stops holding, something in the refusal path is doing cross-contract work.
    assert!(
        refused_gas < allowed_gas,
        "a refusal ({refused_gas}) should cost less than a payment ({allowed_gas})"
    );
    Ok(())
}

/// Every negative test in this file asserts on the *reason* a call was refused, which only
/// works if the wasm carries `--cfg near`. Mirrors the same check in `rules.rs`, because this
/// file would silently lose its evidence without it too.
#[tokio::test]
async fn the_payment_path_wasm_talks_to_the_host_panic_function() -> anyhow::Result<()> {
    let wasm = build_wasm("leash-contract")?;
    assert!(
        wasm.windows(HOST_PANIC_IMPORT.len()).any(|w| w == HOST_PANIC_IMPORT),
        "the wasm does not import panic_utf8, so refusal reasons would be discarded on chain"
    );
    Ok(())
}
