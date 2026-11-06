//! Owner withdrawal: money leaving the wallet outside the rules, gated by a passkey.
//!
//! # The accounting question, answered by the tests
//!
//! A withdrawal does **not** touch the per-node spend ledger. It is not a node's spending —
//! no agent asked for it, no rule allowed it, and charging it to a node's `period_limit` would
//! let the owner emptying the wallet starve every agent's budget for the day. So the ledger
//! tests here assert the converse: `spent_in_period` is identical before and after, whether
//! the transfer lands or fails, which also means a failed withdrawal has nothing to release
//! and nothing to corrupt.
//!
//! What a withdrawal *does* write is the credential's nonce, spent in the same receipt that
//! dispatches the transfer. That one is deliberately not refunded when the transfer fails: the
//! signature was consumed, and a refund path would be a state-writing callback for the sake of
//! convenience. A failed withdrawal costs one fresh assertion to retry.

mod common;

use common::{
    agents, balance_of, deploy_with_token, gate_challenge, nonce_of, register_passkey, rule,
    set_rule_signed, sign_rule, spent_in_period, why, withdraw_payload, AssertionJson, Fixture,
    Passkey, ACTION_ADD_PAYEE, ACTION_SET_RULE, ACTION_UNPAUSE, ACTION_WITHDRAW,
};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::NearToken;
use near_workspaces::Account;
use serde_json::json;

const ALICE: &str = "alice.testnet";
const DAY: u64 = 86_400_000;

/// A deployment with a registered passkey and the owner's own account registered on the token,
/// so there is somewhere to withdraw to.
async fn ready() -> anyhow::Result<(Fixture, Passkey, Account)> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register_passkey(&fx, &pk).await?;
    let owner = fx.worker.dev_create_account().await?;
    fx.token
        .call("storage_deposit")
        .args_json(json!({ "account_id": owner.id() }))
        .deposit(NearToken::from_millinear(10))
        .transact()
        .await?
        .into_result()?;
    Ok((fx, pk, owner))
}

async fn sign_withdraw(
    fx: &Fixture,
    pk: &Passkey,
    to: &str,
    amount: u128,
) -> anyhow::Result<AssertionJson> {
    let nonce = nonce_of(fx, pk).await?;
    Ok(pk.assert_over(&gate_challenge(
        ACTION_WITHDRAW,
        &withdraw_payload(fx.token.id().as_str(), to, amount),
        nonce,
        fx.wallet.id().as_str(),
    )))
}

async fn withdraw(
    fx: &Fixture,
    caller: &Account,
    to: &str,
    amount: u128,
    assertion: AssertionJson,
) -> anyhow::Result<ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "withdraw")
        .args_json(json!({ "to": to, "amount": amount.to_string(), "assertion": assertion }))
        .max_gas()
        .transact()
        .await?)
}

#[tokio::test]
async fn withdraw_without_an_assertion_is_rejected() -> anyhow::Result<()> {
    let (fx, _pk, owner) = ready().await?;
    let before = balance_of(&fx, owner.id().as_str()).await?;

    // No `assertion` field at all, and a null one: neither may move money.
    for args in [
        json!({ "to": owner.id(), "amount": "1000" }),
        json!({ "to": owner.id(), "amount": "1000", "assertion": null }),
    ] {
        let res = fx
            .admin
            .call(fx.wallet.id(), "withdraw")
            .args_json(args)
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_failure(), "a withdrawal with no assertion succeeded: {res:#?}");
        println!("withdraw without an assertion: {}", why(res));
    }
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, before);
    Ok(())
}

#[tokio::test]
async fn only_the_admin_may_withdraw_even_with_a_valid_assertion() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let stranger = fx.worker.dev_create_account().await?;
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = withdraw(&fx, &stranger, owner.id().as_str(), 1_000, a).await?;
    assert!(res.is_failure(), "a stranger withdrew: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "not the admin check: {msg}");
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 0);
    Ok(())
}

#[tokio::test]
async fn a_signed_withdrawal_moves_the_money_and_spends_the_nonce() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let wallet = fx.wallet.id().to_string();
    let wallet_before = balance_of(&fx, &wallet).await?;
    let nonce_before = nonce_of(&fx, &pk).await?;

    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 250_000).await?;
    let res = withdraw(&fx, &fx.admin, owner.id().as_str(), 250_000, a.clone()).await?;
    assert!(res.is_success(), "a signed withdrawal failed: {res:#?}");
    let landed: bool = res.json()?;
    assert!(landed, "the transfer was reported as not landed");

    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 250_000);
    assert_eq!(balance_of(&fx, &wallet).await?, wallet_before - 250_000);
    assert_eq!(nonce_of(&fx, &pk).await?, nonce_before + 1);

    // The same assertion again is a replay.
    let res = withdraw(&fx, &fx.admin, owner.id().as_str(), 250_000, a).await?;
    assert!(res.is_failure(), "a withdrawal assertion was replayed: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 250_000);
    Ok(())
}

#[tokio::test]
async fn a_withdrawal_assertion_binds_the_amount_and_the_recipient() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let other = fx.worker.dev_create_account().await?;

    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = withdraw(&fx, &fx.admin, owner.id().as_str(), 2_000, a.clone()).await?;
    assert!(res.is_failure(), "a bigger amount rode on a smaller signature: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));

    let res = withdraw(&fx, &fx.admin, other.id().as_str(), 1_000, a).await?;
    assert!(res.is_failure(), "another recipient rode on the signature: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 0);
    Ok(())
}

/// The decision this task turned on: a withdrawal is not a node's spending. A node's budget
/// must be exactly where it was, so the owner taking money out cannot starve an agent.
#[tokio::test]
async fn a_withdrawal_does_not_touch_any_nodes_ledger() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(
        &fx,
        &pk,
        &ag.node,
        &rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false),
    )
    .await?;
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 0);

    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 400_000).await?;
    withdraw(&fx, &fx.admin, owner.id().as_str(), 400_000, a).await?.into_result()?;
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 0, "a withdrawal was charged to a node");
    Ok(())
}

/// A transfer the token refuses — here, the wallet's whole balance plus one — is still a
/// successful transaction that says so, and leaves every figure where it was.
#[tokio::test]
async fn a_failed_withdrawal_leaves_state_consistent() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(
        &fx,
        &pk,
        &ag.node,
        &rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false),
    )
    .await?;
    let wallet = fx.wallet.id().to_string();
    let wallet_before = balance_of(&fx, &wallet).await?;
    let nonce_before = nonce_of(&fx, &pk).await?;
    let too_much = wallet_before + 1;

    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), too_much).await?;
    let res = withdraw(&fx, &fx.admin, owner.id().as_str(), too_much, a).await?;
    assert!(res.is_success(), "a failed transfer must still be a successful transaction: {res:#?}");
    let landed: bool = res.json()?;
    assert!(!landed, "a failed transfer was reported as landed");

    assert_eq!(balance_of(&fx, &wallet).await?, wallet_before);
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 0);
    assert_eq!(spent_in_period(&fx, &ag.node).await?, 0);
    // The signature was consumed; a retry needs a fresh one, and a fresh one works.
    assert_eq!(nonce_of(&fx, &pk).await?, nonce_before + 1);
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    withdraw(&fx, &fx.admin, owner.id().as_str(), 1_000, a).await?.into_result()?;
    assert_eq!(balance_of(&fx, owner.id().as_str()).await?, 1_000);

    // An unregistered recipient fails the same way.
    let stranger = fx.worker.dev_create_account().await?;
    let a = sign_withdraw(&fx, &pk, stranger.id().as_str(), 1_000).await?;
    let res = withdraw(&fx, &fx.admin, stranger.id().as_str(), 1_000, a).await?;
    assert!(res.is_success());
    assert!(!res.json::<bool>()?);
    assert_eq!(balance_of(&fx, &wallet).await?, wallet_before - 1_000);
    Ok(())
}

#[tokio::test]
async fn a_withdrawal_fits_in_gas() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = withdraw(&fx, &fx.admin, owner.id().as_str(), 1_000, a).await?;
    assert!(res.is_success(), "{res:#?}");
    let gas = res.total_gas_burnt;
    println!("withdraw (gate + ft_transfer + callback): {gas} ({:.2} TGas)", gas.as_gas() as f64 / 1e12);
    assert!(gas < near_workspaces::types::Gas::from_tgas(300));
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Signatures cannot be redirected between operations
// ---------------------------------------------------------------------------------------

/// A withdrawal signature must not become a rule change.
#[tokio::test]
async fn a_withdraw_assertion_cannot_set_a_rule() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let token = fx.token.id().to_string();
    let r = rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false);
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = fx
        .admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": "ops.testnet", "rule": common::rule_json(&r), "assertion": a }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a withdraw assertion set a rule: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    Ok(())
}

/// ... nor add a payee ...
#[tokio::test]
async fn a_withdraw_assertion_cannot_add_a_payee() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(&fx, &pk, &ag.node, &rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false))
        .await?;
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = fx
        .admin
        .call(fx.wallet.id(), "add_payee")
        .args_json(json!({ "node": ag.node, "payee": "bob.testnet", "assertion": a }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a withdraw assertion added a payee: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    Ok(())
}

/// ... nor unpause the account.
#[tokio::test]
async fn a_withdraw_assertion_cannot_unpause() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    common::pause_account(&fx).await?;
    let a = sign_withdraw(&fx, &pk, owner.id().as_str(), 1_000).await?;
    let res = fx
        .admin
        .call(fx.wallet.id(), "set_paused")
        .args_json(json!({ "paused": false, "assertion": a }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a withdraw assertion unpaused the account: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    let paused: bool = fx.wallet.view("is_paused").await?.json()?;
    assert!(paused);
    Ok(())
}

/// And the other way: a rule-change, payee or unpause signature must not move money.
#[tokio::test]
async fn no_other_assertion_can_withdraw() -> anyhow::Result<()> {
    let (fx, pk, owner) = ready().await?;
    let to = owner.id().as_str();
    let token = fx.token.id().to_string();

    // set_rule: the same node bytes would not matter; any set_rule assertion carries its tag.
    let r = rule(&token, 1_000, 10_000, DAY, 0, u64::MAX, &[ALICE], false);
    let a = sign_rule(&fx, &pk, "ops.testnet", &r).await?;
    let res = withdraw(&fx, &fx.admin, to, 1_000, a).await?;
    assert!(res.is_failure(), "a set_rule assertion withdrew: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));

    // add_payee and unpause tags over the withdrawal's own payload: the strongest form, since
    // payload, nonce and contract all match and only the tag differs.
    for tag in [ACTION_ADD_PAYEE, ACTION_UNPAUSE, ACTION_SET_RULE] {
        let nonce = nonce_of(&fx, &pk).await?;
        let a = pk.assert_over(&gate_challenge(
            tag,
            &withdraw_payload(&token, to, 1_000),
            nonce,
            fx.wallet.id().as_str(),
        ));
        let res = withdraw(&fx, &fx.admin, to, 1_000, a).await?;
        assert!(res.is_failure(), "a {tag} assertion withdrew: {res:#?}");
        assert!(why(res).contains("ChallengeMismatch"), "refused, but not by the tag ({tag})");
    }
    assert_eq!(balance_of(&fx, to).await?, 0);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------------------

/// `#[private]` is satisfied by any key on the wallet account, so the callback's own check
/// that a promise result is present is all that stands here. Called from a key ON the wallet.
#[tokio::test]
async fn on_withdrawn_cannot_be_driven_by_a_key_on_the_wallet() -> anyhow::Result<()> {
    use near_workspaces::types::{AccessKey, SecretKey};
    let (fx, _pk, owner) = ready().await?;
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    fx.wallet
        .batch()
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend", "on_withdrawn"], None),
        )
        .transact()
        .await?
        .into_result()?;
    let attacker = Account::from_secret_key(fx.wallet.id().clone(), sk, &fx.worker);
    let res = attacker
        .call(fx.wallet.id(), "on_withdrawn")
        .args_json(json!({ "to": owner.id(), "amount": "1000" }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a key on the wallet drove the callback: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("not callable directly"), "refused, but not by the callback check: {msg}");
    Ok(())
}
