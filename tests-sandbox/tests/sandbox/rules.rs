//! Rules in contract state, and the passkey gate on every loosening change.
//!
//! What these tests are for: `classify` already decides, in unit tests, what counts as a
//! loosening. Here the question is whether the *contract* refuses to act on one without a
//! signature — and whether the signature it accepts is bound tightly enough that it cannot
//! be lifted from one rule change and used for another.
//!
//! The passkey is a software P-256 key minted by the test (see `common::Passkey`). The
//! contract cannot tell that from a secure enclave and never claims to; that is precisely
//! why `register_credential` is admin-only, and two tests here pin it.

mod common;

use common::{
    deploy_with_token, gate_challenge, set_rule_payload, why, AssertionJson, Fixture, Passkey,
    ACTION_SET_RULE, FLAG_UP,
};
use leash_contract::rule::Rule;
use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
use near_workspaces::types::{AccessKey, Gas, SecretKey};
use near_workspaces::Account;
use serde_json::json;

/// The node every test configures. It need not exist as an account: a node is a budget
/// name derived from an agent's id, not a thing that signs.
const NODE: &str = "ops.leash.testnet";
const OTHER_NODE: &str = "eng.leash.testnet";

fn acct(s: &str) -> near_sdk::AccountId {
    s.parse().expect("valid account id")
}

/// A rule's JSON, as the contract's own serializer writes it. Going through the contract's
/// `Rule` type rather than a hand-built object means the test cannot accidentally submit a
/// field the contract does not have.
fn rule_json(r: &Rule) -> serde_json::Value {
    serde_json::from_str(&near_sdk::serde_json::to_string(r).expect("Rule serialises"))
        .expect("serde_json agrees with near_sdk's")
}

/// `Rule::try_new` with string payees. It panics on an invalid rule: every rule written out
/// in this file is meant to be valid, and a typo that makes one invalid should name itself
/// rather than arrive as a failed contract call ten lines later.
#[allow(clippy::too_many_arguments)]
fn rule(
    token: &str,
    per_tx_limit: u128,
    period_limit: u128,
    period_ms: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    payees: &[&str],
    paused: bool,
) -> Rule {
    Rule::try_new(
        acct(token),
        per_tx_limit,
        period_limit,
        period_ms,
        window_start_ms,
        window_end_ms,
        payees.iter().map(|p| acct(p)).collect(),
        paused,
    )
    .expect("the test wrote an invalid rule")
}

/// The rule the tests start from: a modest daily budget for one payee.
fn base_rule(token: &str) -> Rule {
    rule(token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false)
}

/// The most restrictive rule there is: pay nobody, zero, paused.
fn shut_rule(token: &str) -> Rule {
    rule(token, 0, 0, 86_400_000, 0, 0, &[], true)
}

// ---------------------------------------------------------------------------------------
// Helpers over the deployed contract
// ---------------------------------------------------------------------------------------

async fn register(fx: &Fixture, pk: &Passkey) -> anyhow::Result<()> {
    fx.admin
        .call(fx.wallet.id(), "register_credential")
        .args_json(pk.registration())
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

async fn nonce_of(fx: &Fixture, pk: &Passkey) -> anyhow::Result<u64> {
    let n: Option<u64> = fx
        .wallet
        .view("credential_nonce")
        .args_json(json!({ "credential_id": STANDARD.encode(&pk.credential_id) }))
        .await?
        .json()?;
    n.ok_or_else(|| anyhow::anyhow!("credential is not registered"))
}

/// Sign `rule` for `node` at the credential's current nonce.
async fn sign_rule(
    fx: &Fixture,
    pk: &Passkey,
    node: &str,
    rule: &Rule,
) -> anyhow::Result<AssertionJson> {
    let nonce = nonce_of(fx, pk).await?;
    let challenge = gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(node, rule),
        nonce,
        fx.wallet.id().as_str(),
    );
    Ok(pk.assert_over(&challenge))
}

async fn set_rule(
    fx: &Fixture,
    caller: &Account,
    node: &str,
    rule: &Rule,
    assertion: Option<AssertionJson>,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": node, "rule": rule_json(rule), "assertion": assertion }))
        .max_gas()
        .transact()
        .await?)
}

/// `set_rule` with a freshly signed assertion, asserting it lands. Returns nothing: every
/// caller only needs it to have happened.
async fn set_rule_signed(fx: &Fixture, pk: &Passkey, node: &str, rule: &Rule) -> anyhow::Result<()> {
    let a = sign_rule(fx, pk, node, rule).await?;
    let res = set_rule(fx, &fx.admin, node, rule, Some(a)).await?;
    anyhow::ensure!(res.is_success(), "signed set_rule failed: {res:#?}");
    Ok(())
}

async fn rule_of(fx: &Fixture, node: &str) -> anyhow::Result<Option<serde_json::Value>> {
    Ok(fx
        .wallet
        .view("rule_of")
        .args_json(json!({ "node": node }))
        .await?
        .json()?)
}

async fn payees_of(fx: &Fixture, node: &str) -> anyhow::Result<Vec<String>> {
    Ok(fx
        .wallet
        .view("payees_of")
        .args_json(json!({ "node": node }))
        .await?
        .json()?)
}

async fn epoch_of(fx: &Fixture, node: &str) -> anyhow::Result<Option<u32>> {
    Ok(fx
        .wallet
        .view("epoch_of")
        .args_json(json!({ "node": node }))
        .await?
        .json()?)
}

async fn spent_in_period(fx: &Fixture, node: &str) -> anyhow::Result<String> {
    Ok(fx
        .wallet
        .view("spent_in_period")
        .args_json(json!({ "node": node }))
        .await?
        .json()?)
}

/// A fixture with a credential registered and `NODE` already carrying `base_rule`.
async fn ready() -> anyhow::Result<(Fixture, Passkey)> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(&fx, &pk, NODE, &base_rule(&token)).await?;
    Ok((fx, pk))
}

// ---------------------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------------------

/// The emergency brake is never gated. ADMIN alone, no assertion, immediate — including
/// re-applying the identical rule, which `classify` calls a tightening on purpose.
#[tokio::test]
async fn tightening_needs_no_assertion() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();

    // Lower both limits and drop the only payee: unambiguously tighter.
    let tighter = rule(&token, 1, 1, 86_400_000, 0, u64::MAX, &[], false);
    let res = set_rule(&fx, &fx.admin, NODE, &tighter, None).await?;
    assert!(res.is_success(), "tightening was refused: {res:#?}");
    assert_eq!(payees_of(&fx, NODE).await?, Vec::<String>::new());

    // And the same rule again, with no assertion: still free.
    let res = set_rule(&fx, &fx.admin, NODE, &tighter, None).await?;
    assert!(res.is_success(), "re-applying a rule was refused: {res:#?}");

    // All the way shut, still free.
    let res = set_rule(&fx, &fx.admin, NODE, &shut_rule(&token), None).await?;
    assert!(res.is_success(), "shutting the node down was refused: {res:#?}");
    Ok(())
}

#[tokio::test]
async fn widening_without_assertion_is_rejected() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();

    // per_tx_limit up from 1_000: one field, unambiguously looser.
    let wider = rule(&token, 2_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    let res = set_rule(&fx, &fx.admin, NODE, &wider, None).await?;
    assert!(res.is_failure(), "widening went through with no assertion: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("needs a passkey assertion"), "refused, but not by the gate: {msg}");

    // And nothing moved.
    let stored = rule_of(&fx, NODE).await?.expect("rule is still there");
    assert_eq!(stored["per_tx_limit"], json!("1000"));
    Ok(())
}

/// Replay protection keys on the credential's nonce, never on the signature bytes: ECDSA
/// signatures are malleable, so a dedupe keyed on the signature could be defeated by
/// flipping `s`. The nonce goes into the challenge, so the same assertion presented twice
/// fails the second time because the expected challenge has moved on.
#[tokio::test]
async fn widening_with_replayed_assertion_is_rejected() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();

    let wider = rule(&token, 2_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);

    let nonce_before = nonce_of(&fx, &pk).await?;
    let assertion = sign_rule(&fx, &pk, NODE, &wider).await?;

    let first = set_rule(&fx, &fx.admin, NODE, &wider, Some(assertion.clone())).await?;
    assert!(first.is_success(), "a validly signed widening was refused: {first:#?}");
    assert_eq!(nonce_of(&fx, &pk).await?, nonce_before + 1, "the nonce did not advance");

    // Tighten back, so the replay below is once again a widening and would do something.
    set_rule(&fx, &fx.admin, NODE, &base_rule(&token), None)
        .await?
        .into_result()?;

    let replay = set_rule(&fx, &fx.admin, NODE, &wider, Some(assertion)).await?;
    assert!(replay.is_failure(), "the same assertion was accepted twice: {replay:#?}");
    // The nonce moved on, so the challenge the contract now expects is a different one —
    // which is the shape the replay guard is meant to have.
    let msg = why(replay);
    assert!(msg.contains("ChallengeMismatch"), "the replay was refused, but not as a stale challenge: {msg}");
    let stored = rule_of(&fx, NODE).await?.expect("rule is still there");
    assert_eq!(stored["per_tx_limit"], json!("1000"), "the replay changed the rule");
    Ok(())
}

/// The challenge binds the node, so a signature for one node's rule is useless against
/// another node carrying the identical rule. Without this the admin's signature for a
/// generous engineering budget would also widen the operations budget.
#[tokio::test]
async fn an_assertion_for_another_node_is_rejected() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let same_rule = base_rule(&token);

    // Signed for NODE (where it is already the current rule), presented for OTHER_NODE
    // (which has no rule at all, so this would be a widening).
    let assertion = sign_rule(&fx, &pk, NODE, &same_rule).await?;
    let res = set_rule(&fx, &fx.admin, OTHER_NODE, &same_rule, Some(assertion)).await?;
    assert!(res.is_failure(), "one node's signature widened another node: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("ChallengeMismatch"), "refused, but not because the node is bound into the challenge: {msg}");
    assert!(rule_of(&fx, OTHER_NODE).await?.is_none());
    Ok(())
}

/// A rule where there was none is a loosening from nothing, so it needs a signature too.
#[tokio::test]
async fn the_first_rule_for_a_node_needs_an_assertion() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();

    let res = set_rule(&fx, &fx.admin, NODE, &base_rule(&token), None).await?;
    assert!(res.is_failure(), "a node was given a budget with no signature: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("needs a passkey assertion"), "refused, but not by the gate: {msg}");
    assert!(rule_of(&fx, NODE).await?.is_none());

    set_rule_signed(&fx, &pk, NODE, &base_rule(&token)).await?;
    assert!(rule_of(&fx, NODE).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn an_assertion_without_the_uv_bit_is_rejected() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let wider = rule(&token, 5_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);

    let nonce = nonce_of(&fx, &pk).await?;
    let challenge = gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(NODE, &wider),
        nonce,
        fx.wallet.id().as_str(),
    );
    // User present (a touch) but not verified: no biometric, no PIN.
    let assertion = pk.assert_over_with_flags(&challenge, FLAG_UP);

    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(assertion)).await?;
    assert!(res.is_failure(), "a touch was accepted as an unlock: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("UserNotVerified"), "refused, but not for the UV bit: {msg}");
    assert_eq!(nonce_of(&fx, &pk).await?, nonce, "a rejected assertion burnt a nonce");
    Ok(())
}

/// An unregistered credential cannot widen anything, however well it signs.
#[tokio::test]
async fn an_unregistered_credential_cannot_widen() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();
    let stranger = Passkey::new("an attacker's own key");
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);

    // Signed correctly over the right challenge at nonce 0 — the only thing wrong with it
    // is that nobody registered this key.
    let challenge = gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(NODE, &wider),
        0,
        fx.wallet.id().as_str(),
    );
    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(stranger.assert_over(&challenge))).await?;
    assert!(res.is_failure(), "an unregistered key widened a rule: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("no such registered credential"), "refused, but not for being unregistered: {msg}");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Who may call
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn non_admin_cannot_set_any_rule() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let stranger = fx.worker.dev_create_account().await?;

    // Not even a tightening, and not even with a perfectly good assertion.
    let tighter = rule(&token, 1, 1, 86_400_000, 0, u64::MAX, &[], false);
    let res = set_rule(&fx, &stranger, NODE, &tighter, None).await?;
    assert!(res.is_failure(), "a stranger tightened a rule: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "refused, but not by the admin check: {msg}");

    let wider = rule(&token, 2_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    let a = sign_rule(&fx, &pk, NODE, &wider).await?;
    let res = set_rule(&fx, &stranger, NODE, &wider, Some(a)).await?;
    assert!(res.is_failure(), "a stranger widened a rule with a valid assertion: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "refused, but not by the admin check: {msg}");

    let stored = rule_of(&fx, NODE).await?.expect("rule is still there");
    assert_eq!(stored["per_tx_limit"], json!("1000"));
    Ok(())
}

/// The trust boundary of the whole passkey story. The contract cannot prove a credential is
/// hardware-backed — there is no attestation, synced passkeys attest `none`, and the
/// software key these tests sign with verifies perfectly well. So the only thing between an
/// attacker and a self-minted credential is who may register one.
#[tokio::test]
async fn register_credential_is_admin_only() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let stranger = fx.worker.dev_create_account().await?;
    let attacker_key = Passkey::new("an attacker's own key");

    let res = stranger
        .call(fx.wallet.id(), "register_credential")
        .args_json(attacker_key.registration())
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a stranger registered a credential: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "refused, but not by the admin check: {msg}");
    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert!(ids.is_empty(), "state holds a credential nobody was allowed to add");

    // The positive half, so this test cannot pass by the method simply not working.
    let admin_key = Passkey::new("admin phone");
    register(&fx, &admin_key).await?;
    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert_eq!(ids, vec![STANDARD.encode(&admin_key.credential_id)]);
    Ok(())
}

/// The agent holds a function-call key on the wallet account itself, so its calls arrive
/// with `predecessor_id == <the wallet>`. Two things must stop it: the key's method
/// allow-list, and — if that allow-list were ever widened — the admin check.
#[tokio::test]
async fn an_agent_function_call_key_cannot_register_a_credential() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let attacker_key = Passkey::new("an attacker's own key");

    // The real agent key: restricted to `spend`.
    let spend_only = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    // A deliberately over-broad key, to reach the contract's own check rather than the
    // protocol's. If the admin check were missing, this one would succeed.
    let over_broad = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    fx.wallet
        .batch()
        .add_key(
            spend_only.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend"], None),
        )
        .add_key(
            over_broad.public_key(),
            AccessKey::function_call_access(
                fx.wallet.id(),
                &["spend", "register_credential", "set_rule"],
                None,
            ),
        )
        .transact()
        .await?
        .into_result()?;

    // The two keys are stopped by two different things, and the test says which is which:
    // a key whose allow-list does not name the method never reaches the contract at all
    // (the node refuses to even broadcast it), while a key that does name it reaches the
    // contract and is turned away by the admin check.
    for (name, sk, blocked_by_the_protocol) in [
        ("spend-only", spend_only, true),
        ("over-broad", over_broad, false),
    ] {
        let agent = Account::from_secret_key(fx.wallet.id().clone(), sk, &fx.worker);
        let attempt = agent
            .call(fx.wallet.id(), "register_credential")
            .args_json(attacker_key.registration())
            .max_gas()
            .transact()
            .await;
        match attempt {
            Err(e) => {
                assert!(
                    blocked_by_the_protocol,
                    "the {name} key was refused before execution, which this test did not \
                     expect: {e}"
                );
                // The whole chain, not just the top line: the reason is in the cause.
                let msg = format!("{e:?}");
                assert!(
                    msg.contains("MethodNameMismatch"),
                    "the {name} key was refused, but not by its method allow-list: {msg}"
                );
            }
            Ok(outcome) => {
                assert!(
                    !blocked_by_the_protocol,
                    "the {name} key reached the contract, which this test did not expect"
                );
                assert!(
                    outcome.is_failure(),
                    "the {name} agent key registered a credential: {outcome:#?}"
                );
                // And it is the admin check that stopped it, not something incidental.
                let msg = why(outcome);
                assert!(
                    msg.contains("only the admin may change rules"),
                    "the {name} key was refused, but not by the admin check: {msg}"
                );
            }
        }
    }

    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert!(ids.is_empty(), "an agent key got a credential into state");
    Ok(())
}

/// Re-registering an id would reset its nonce, and a reset nonce re-arms every assertion
/// ever signed under it. Refused outright; rotation means a new credential id.
#[tokio::test]
async fn a_credential_cannot_be_re_registered() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;

    let res = fx
        .admin
        .call(fx.wallet.id(), "register_credential")
        .args_json(pk.registration())
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a credential id was re-registered: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("already registered"), "refused, but not for being a duplicate id: {msg}");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The epoch and the ledger
// ---------------------------------------------------------------------------------------

/// The epoch lives in the per-node record, not in `Rule`, and `set_rule` advances it. It is
/// part of the spent ledger's key, so advancing it starts a fresh ledger rather than
/// retroactively freeing or consuming headroom.
///
/// Nothing can put a non-zero figure into the ledger until `spend` lands in Task 6, so the
/// ledger half of this is checked in-process by `state::tests::setting_a_rule_zeroes_the_
/// spent_ledger`, which writes to it directly. What this test pins is the epoch bump and
/// that the view reads zero off a fresh epoch.
#[tokio::test]
async fn setting_a_rule_bumps_the_epoch_and_zeroes_the_ledger() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();

    assert_eq!(epoch_of(&fx, NODE).await?, None, "an unconfigured node has no epoch");

    set_rule_signed(&fx, &pk, NODE, &base_rule(&token)).await?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "the first rule starts at epoch 0");
    assert_eq!(spent_in_period(&fx, NODE).await?, "0");

    let tighter = rule(&token, 500, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    set_rule(&fx, &fx.admin, NODE, &tighter, None).await?.into_result()?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(1), "a tightening bumps the epoch too");
    assert_eq!(spent_in_period(&fx, NODE).await?, "0");

    set_rule(&fx, &fx.admin, NODE, &tighter, None).await?.into_result()?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(2), "every accepted set_rule bumps it");

    // A payee change does not touch the budget arithmetic, so it must not bump the epoch:
    // a bump would hand the node a fresh period limit nobody signed for.
    let a = sign_add_payee(&fx, &pk, NODE, "bob.testnet").await?;
    add_payee(&fx, &fx.admin, NODE, "bob.testnet", a).await?.into_result()?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(2), "add_payee must not bump the epoch");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Payees
// ---------------------------------------------------------------------------------------

async fn add_payee(
    fx: &Fixture,
    caller: &Account,
    node: &str,
    payee: &str,
    assertion: AssertionJson,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "add_payee")
        .args_json(json!({ "node": node, "payee": payee, "assertion": assertion }))
        .max_gas()
        .transact()
        .await?)
}

/// Sign the rule that results from adding `payee`, which is what `add_payee` commits to.
async fn sign_add_payee(
    fx: &Fixture,
    pk: &Passkey,
    node: &str,
    payee: &str,
) -> anyhow::Result<AssertionJson> {
    let stored = rule_of(fx, node).await?.expect("node has a rule");
    let mut payees: Vec<near_sdk::AccountId> = stored["payees"]
        .as_array()
        .expect("payees is a list")
        .iter()
        .map(|v| acct(v.as_str().expect("an account id")))
        .collect();
    payees.push(acct(payee));
    let proposed = Rule::try_new(
        acct(stored["token"].as_str().expect("token")),
        stored["per_tx_limit"].as_str().expect("per_tx_limit").parse()?,
        stored["period_limit"].as_str().expect("period_limit").parse()?,
        stored["period_ms"].as_u64().expect("period_ms"),
        stored["window_start_ms"].as_u64().expect("window_start_ms"),
        stored["window_end_ms"].as_u64().expect("window_end_ms"),
        payees,
        stored["paused"].as_bool().expect("paused"),
    )
    .map_err(anyhow::Error::msg)?;
    sign_rule(fx, pk, node, &proposed).await
}

/// NEP-141 `ft_transfer` fails for a receiver with no storage deposit, so putting a payee on
/// the allow-list also registers it on the token. Without this a legitimate payment fails
/// for a reason that has nothing to do with policy, and the demo looks like a policy bug.
#[tokio::test]
async fn adding_a_payee_registers_storage_on_the_token() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let payee = fx.worker.dev_create_account().await?;
    let payee_id = payee.id().to_string();

    let before: Option<serde_json::Value> = fx
        .token
        .view("storage_balance_of")
        .args_json(json!({ "account_id": payee_id }))
        .await?
        .json()?;
    assert!(before.is_none(), "the payee was already registered");

    let a = sign_add_payee(&fx, &pk, NODE, &payee_id).await?;
    let res = add_payee(&fx, &fx.admin, NODE, &payee_id, a).await?;
    assert!(res.is_success(), "add_payee failed: {res:#?}");

    let after: Option<serde_json::Value> = fx
        .token
        .view("storage_balance_of")
        .args_json(json!({ "account_id": payee_id }))
        .await?
        .json()?;
    assert!(after.is_some(), "add_payee did not register the payee on the token");

    let mut payees = payees_of(&fx, NODE).await?;
    payees.sort();
    let mut want = vec!["alice.testnet".to_string(), payee_id];
    want.sort();
    assert_eq!(payees, want);
    Ok(())
}

#[tokio::test]
async fn adding_a_payee_without_an_assertion_is_impossible() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    // `assertion` is not optional on `add_payee`, so the only way to try this is to omit
    // the argument entirely — which the deserializer must refuse.
    let res = fx
        .admin
        .call(fx.wallet.id(), "add_payee")
        .args_json(json!({ "node": NODE, "payee": "bob.testnet" }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "add_payee ran with no assertion: {res:#?}");
    assert_eq!(payees_of(&fx, NODE).await?, vec!["alice.testnet".to_string()]);
    Ok(())
}

/// If the token's `storage_deposit` fails, the payee must not end up on the list: the whole
/// reason to call it is to keep "on the list" meaning "can be paid". The assertion is spent
/// either way — a nonce is never un-consumed, because that would re-arm the assertion.
#[tokio::test]
async fn a_failed_storage_deposit_leaves_the_payee_off_the_list() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;

    // A rule naming a token contract that does not exist, so the cross-contract call fails.
    let missing_token = "nosuch.token.testnet";
    set_rule_signed(&fx, &pk, NODE, &base_rule(missing_token)).await?;

    let nonce_before = nonce_of(&fx, &pk).await?;
    let a = sign_add_payee(&fx, &pk, NODE, "bob.testnet").await?;
    let res = add_payee(&fx, &fx.admin, NODE, "bob.testnet", a).await?;
    assert!(
        res.is_success(),
        "a failed storage_deposit should be handled, not blow up the call: {res:#?}"
    );
    assert!(!res.json::<bool>()?, "the callback claimed success");
    assert_eq!(
        payees_of(&fx, NODE).await?,
        vec!["alice.testnet".to_string()],
        "the payee was added even though it cannot receive a transfer"
    );
    assert_eq!(
        nonce_of(&fx, &pk).await?,
        nonce_before + 1,
        "the assertion must stay spent, so it cannot be replayed"
    );
    Ok(())
}

/// A payee that is already listed is a no-op, and a no-op must not burn an assertion.
#[tokio::test]
async fn adding_a_payee_that_is_already_listed_is_rejected() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let nonce_before = nonce_of(&fx, &pk).await?;

    // Signed over the rule that "adding alice" produces — which is the current rule, since
    // alice is already on the list.
    let a = sign_add_payee(&fx, &pk, NODE, "alice.testnet").await?;
    let res = add_payee(&fx, &fx.admin, NODE, "alice.testnet", a).await?;
    assert!(res.is_failure(), "a duplicate payee was accepted: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("already on the list"), "refused, but not as a duplicate: {msg}");
    assert_eq!(
        nonce_of(&fx, &pk).await?,
        nonce_before,
        "a no-op burnt an assertion"
    );
    Ok(())
}

#[tokio::test]
async fn removing_a_payee_needs_no_assertion() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;

    let res = fx
        .admin
        .call(fx.wallet.id(), "remove_payee")
        .args_json(json!({ "node": NODE, "payee": "alice.testnet" }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "removing a payee was refused: {res:#?}");
    assert_eq!(payees_of(&fx, NODE).await?, Vec::<String>::new());

    // Idempotent: "make sure this payee is gone" must not fail because it already is.
    let res = fx
        .admin
        .call(fx.wallet.id(), "remove_payee")
        .args_json(json!({ "node": NODE, "payee": "alice.testnet" }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "removing an absent payee failed: {res:#?}");

    let stranger = fx.worker.dev_create_account().await?;
    let res = stranger
        .call(fx.wallet.id(), "remove_payee")
        .args_json(json!({ "node": NODE, "payee": "alice.testnet" }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a stranger removed a payee: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "refused, but not by the admin check: {msg}");
    Ok(())
}

/// Pausing a node is a tightening, so it is free. Unpausing is a loosening and is gated —
/// the asymmetry the whole design rests on, on one field.
#[tokio::test]
async fn pausing_is_free_but_unpausing_needs_a_passkey() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let running = base_rule(&token);
    let paused = rule(&token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], true);

    set_rule(&fx, &fx.admin, NODE, &paused, None).await?.into_result()?;
    assert_eq!(rule_of(&fx, NODE).await?.expect("rule")["paused"], json!(true));

    let res = set_rule(&fx, &fx.admin, NODE, &running, None).await?;
    assert!(res.is_failure(), "unpausing went through with no assertion: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("needs a passkey assertion"), "refused, but not by the gate: {msg}");
    assert_eq!(rule_of(&fx, NODE).await?.expect("rule")["paused"], json!(true));

    set_rule_signed(&fx, &pk, NODE, &running).await?;
    assert_eq!(rule_of(&fx, NODE).await?.expect("rule")["paused"], json!(false));
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The challenge layout, and what it costs
// ---------------------------------------------------------------------------------------

/// `challenge_for` is what the demo page and `tools/capture-assertion.html` call to get the
/// bytes to sign. This checks it against `common::gate_challenge`, which is written from the
/// documented layout rather than from the contract's code — so the layout is pinned by two
/// independent implementations, and a change to either shows up here.
#[tokio::test]
async fn challenge_for_matches_the_documented_layout() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    // Payees out of order on purpose: the contract normalises before it hashes.
    let signed_rule = rule(&token, 7, 8, 9, 10, 11, &["b.testnet", "a.testnet"], false);

    let from_contract: String = fx
        .wallet
        .view("challenge_for")
        .args_json(json!({
            "node": NODE,
            "rule": rule_json(&signed_rule),
            "credential_id": STANDARD.encode(&pk.credential_id),
        }))
        .await?
        .json()?;

    let nonce = nonce_of(&fx, &pk).await?;
    let ours = gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(NODE, &signed_rule),
        nonce,
        fx.wallet.id().as_str(),
    );
    assert_eq!(from_contract, STANDARD.encode(ours));

    // And the same rule under a different node must give different bytes.
    let other: String = fx
        .wallet
        .view("challenge_for")
        .args_json(json!({
            "node": OTHER_NODE,
            "rule": rule_json(&signed_rule),
            "credential_id": STANDARD.encode(&pk.credential_id),
        }))
        .await?
        .json()?;
    assert_ne!(from_contract, other);
    Ok(())
}

/// The figure the README quotes for the gated path: a widening `set_rule` end to end —
/// transaction, contract load, JSON parse, `classify`, P-256 verification and the state
/// write. `probe_verify` measured the curve arithmetic alone at 33.46 TGas in Task 4.
#[tokio::test]
async fn a_widening_set_rule_fits_in_gas() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let wider = rule(&token, 100_000, 1_000_000, 3_600_000, 0, u64::MAX, &["alice.testnet", "bob.testnet"], false);

    let a = sign_rule(&fx, &pk, NODE, &wider).await?;
    let outcome = set_rule(&fx, &fx.admin, NODE, &wider, Some(a)).await?;
    assert!(outcome.is_success(), "the measured call failed: {outcome:#?}");
    let widening = outcome.total_gas_burnt;

    // The same method with no assertion to verify, for the difference.
    let tighter = rule(&token, 1, 1, 86_400_000, 0, u64::MAX, &[], false);
    let tightening = set_rule(&fx, &fx.admin, NODE, &tighter, None)
        .await?
        .total_gas_burnt;

    println!(
        "set_rule (widening, with a passkey assertion): {widening} ({:.2} TGas)",
        widening.as_gas() as f64 / 1e12
    );
    println!(
        "set_rule (tightening, no assertion):           {tightening} ({:.2} TGas)",
        tightening.as_gas() as f64 / 1e12
    );
    println!(
        "  the gate costs: {:.2} TGas",
        (widening.as_gas().saturating_sub(tightening.as_gas())) as f64 / 1e12
    );

    assert!(
        widening < Gas::from_tgas(80),
        "a widening set_rule burnt {widening}, over the 80 TGas regression guard (the \
         protocol limit is 300 TGas; this bound sits far below it so a regression shows up \
         here first)"
    );
    Ok(())
}
