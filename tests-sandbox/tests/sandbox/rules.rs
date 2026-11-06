//! Rules in contract state, and the passkey gate on every loosening change.
//!
//! What these tests are for: `classify` already decides, in unit tests, what counts as a
//! loosening. Here the question is whether the *contract* refuses to act on one without a
//! signature — and whether the signature it accepts is bound tightly enough that it cannot
//! be lifted from one rule change and used for another.
//!
//! The passkey is a software P-256 key minted by the test (see `common::Passkey`). The
//! contract cannot tell that from a secure enclave and never claims to; that is precisely
//! why registering a credential is guarded: the first one by the admin alone (the bootstrap), every
//! later one by an assertion from a credential that already exists. Tests below pin both halves.

mod common;

use common::{
    build_wasm, deploy_with_token, gate_challenge, register_attempt, register_passkey_via,
    register_payload, set_rule_payload, sign_registration, why, AssertionJson, Fixture, Passkey,
    ACTION_ADD_PAYEE, ACTION_REGISTER, ACTION_SET_RULE, ACTION_UNPAUSE, ACTION_WITHDRAW, FLAG_UP,
    HOST_PANIC_IMPORT,
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

/// The interesting part of a failure, for printing: the `ExecutionError`/`MethodResolveError`
/// payload without the receipt dump around it.
fn one_line(msg: &str) -> String {
    for marker in ["MethodResolveError(", "ExecutionError(\""] {
        if let Some(i) = msg.find(marker) {
            let rest = &msg[i + marker.len()..];
            let end = rest.find(['"', ')']).unwrap_or(rest.len());
            return format!("{}{}", marker.trim_end_matches(['(', '"']), format!(": {}", &rest[..end]));
        }
    }
    msg.chars().take(160).collect()
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

/// Sign `payload` under `action` at the credential's current nonce.
async fn sign(
    fx: &Fixture,
    pk: &Passkey,
    action: &str,
    payload: &[u8],
) -> anyhow::Result<AssertionJson> {
    let nonce = nonce_of(fx, pk).await?;
    Ok(pk.assert_over(&gate_challenge(
        action,
        payload,
        nonce,
        fx.wallet.id().as_str(),
    )))
}

/// Sign `rule` for `node` as a `set_rule`.
async fn sign_rule(
    fx: &Fixture,
    pk: &Passkey,
    node: &str,
    rule: &Rule,
) -> anyhow::Result<AssertionJson> {
    sign(fx, pk, ACTION_SET_RULE, &set_rule_payload(node, rule)).await
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

async fn window_began_ms(fx: &Fixture, node: &str) -> anyhow::Result<Option<u64>> {
    Ok(fx
        .wallet
        .view("window_began_ms")
        .args_json(json!({ "node": node }))
        .await?
        .json()?)
}

/// `storage_balance_of` on the token: `Some` iff the account can receive an `ft_transfer`.
async fn is_registered_on_token(fx: &Fixture, account: &str) -> anyhow::Result<bool> {
    let bal: Option<serde_json::Value> = fx
        .token
        .view("storage_balance_of")
        .args_json(json!({ "account_id": account }))
        .await?
        .json()?;
    Ok(bal.is_some())
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

/// Every field of a rule, loosened on its own, is refused without an assertion, even from the
/// admin. The base is first tightened to a rule with room to loosen in every direction (a window
/// that is not already open-ended), so no variant is accidentally a no-op or a tightening.
#[tokio::test]
async fn widening_without_assertion_is_rejected() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();

    let current = rule(&token, 1_000, 10_000, 86_400_000, 1_000, 9_000_000, &["alice.testnet"], false);
    let res = set_rule(&fx, &fx.admin, NODE, &current, None).await?;
    assert!(res.is_success(), "tightening to the test's starting rule was refused: {res:#?}");
    let before = rule_of(&fx, NODE).await?.expect("rule");

    let variants = [
        ("per_tx_limit up", rule(&token, 2_000, 10_000, 86_400_000, 1_000, 9_000_000, &["alice.testnet"], false)),
        ("period_limit up", rule(&token, 1_000, 20_000, 86_400_000, 1_000, 9_000_000, &["alice.testnet"], false)),
        ("period_ms shorter", rule(&token, 1_000, 10_000, 43_200_000, 1_000, 9_000_000, &["alice.testnet"], false)),
        ("window starts earlier", rule(&token, 1_000, 10_000, 86_400_000, 0, 9_000_000, &["alice.testnet"], false)),
        ("window ends later", rule(&token, 1_000, 10_000, 86_400_000, 1_000, 10_000_000, &["alice.testnet"], false)),
        ("a payee added", rule(&token, 1_000, 10_000, 86_400_000, 1_000, 9_000_000, &["alice.testnet", "bob.testnet"], false)),
        ("a payee swapped", rule(&token, 1_000, 10_000, 86_400_000, 1_000, 9_000_000, &["bob.testnet"], false)),
        ("another token", rule("other.testnet", 1_000, 10_000, 86_400_000, 1_000, 9_000_000, &["alice.testnet"], false)),
    ];
    for (what, wider) in variants {
        let res = set_rule(&fx, &fx.admin, NODE, &wider, None).await?;
        assert!(res.is_failure(), "{what}: loosening went through with no assertion: {res:#?}");
        let msg = why(res);
        assert!(msg.contains("needs a passkey assertion"), "{what}: refused, but not by the gate: {msg}");
    }

    // And nothing moved.
    assert_eq!(rule_of(&fx, NODE).await?.expect("rule is still there"), before);
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
    assert_eq!(stored["per_tx_limit"], json!("1000"), "the rule must be unchanged after a refused replay");
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
    assert!(msg.contains("no such active credential"), "refused, but not for being unregistered: {msg}");
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
    assert!(ids.is_empty(), "no credential must reach state from a non-admin call");

    // The positive half, so this test cannot pass by the method simply not working.
    let admin_key = Passkey::new("admin phone");
    register(&fx, &admin_key).await?;
    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert_eq!(ids, vec![STANDARD.encode(&admin_key.credential_id)]);
    Ok(())
}

/// The agents' keys are on their own accounts, so a real agent's call arrives with the agent as
/// predecessor. This test uses keys on the wallet instead, which a correct deployment never
/// has, because that is the caller the admin check has to refuse if the deployment is ever
/// wrong: first the key's method allow-list, and — if that allow-list were widened — the admin
/// check.
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
    assert!(ids.is_empty(), "no credential must reach state from an agent key");
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
    assert!(msg.contains("already known"), "refused, but not for being a duplicate id: {msg}");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Who may add a credential: the trust boundary of the passkey gate
// ---------------------------------------------------------------------------------------
//
// The contract cannot tell a software key from a hardware passkey, so if the admin key alone
// could register a credential, a stolen admin key could mint its own and sign a widening or a
// withdrawal with it, and "widening needs a passkey" would constrain nobody. So only the FIRST
// credential is admin-only; every later one needs an assertion from one that already exists.

/// The centre of the project. A stolen admin key, with everything it can do, still cannot add a
/// credential, and so cannot widen a rule with one.
#[tokio::test]
async fn the_admin_key_alone_cannot_register_a_second_credential() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();
    let attacker = Passkey::new("an attacker's own key");

    // Admin alone, no assertion.
    let res = register_attempt(&fx, &fx.admin, &attacker, None).await?;
    assert!(res.is_failure(), "the admin key alone registered a second credential: {res:#?}");
    let msg = why(res);
    println!("admin alone, no assertion: refused: {msg}");
    assert!(msg.contains("the admin key alone cannot add one"), "refused, but not for the missing assertion: {msg}");

    // Admin plus an assertion signed by the attacker's OWN, unregistered, key over its own
    // registration: a perfectly valid signature from a key the contract has never heard of.
    let forged = attacker.assert_over(&gate_challenge(
        ACTION_REGISTER,
        &register_payload(&attacker.credential_id, &attacker.pubkey_sec1(), 0),
        0,
        fx.wallet.id().as_str(),
    ));
    let res = register_attempt(&fx, &fx.admin, &attacker, Some(forged)).await?;
    assert!(res.is_failure(), "a self-signed registration was accepted: {res:#?}");
    let msg = why(res);
    println!("admin + the attacker's self-signed assertion: refused: {msg}");
    assert!(msg.contains("no such active credential"), "refused, but not because the signer is unknown: {msg}");

    // And the attacker's key is therefore useless for a widening.
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    let a = attacker.assert_over(&gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(NODE, &wider),
        0,
        fx.wallet.id().as_str(),
    ));
    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(a)).await?;
    assert!(res.is_failure(), "a never-registered key widened a rule: {res:#?}");
    assert!(why(res).contains("no such active credential"));

    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert_eq!(ids.len(), 1, "no second credential may have reached state");
    Ok(())
}

/// The positive half, so the test above cannot pass by registration simply being broken.
#[tokio::test]
async fn a_registered_credential_can_authorise_a_second_one() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let spare = Passkey::new("spare phone");
    let before = nonce_of(&fx, &pk).await?;

    register_passkey_via(&fx, &pk, &spare).await?;
    let ids: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    println!("registered with an assertion from the first credential: {ids:?}");
    assert_eq!(ids.len(), 2);
    assert_eq!(nonce_of(&fx, &pk).await?, before + 1, "the signing credential's nonce is spent");

    // And the new credential really can authorise something.
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    set_rule_signed(&fx, &spare, NODE, &wider).await?;
    Ok(())
}

/// The signature authorises exactly this key: not another id, not another public key, and not a
/// second use.
#[tokio::test]
async fn a_registration_assertion_binds_the_new_key_and_is_single_use() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let (b, c) = (Passkey::new("phone b"), Passkey::new("phone c"));
    let for_b = sign_registration(&fx, &pk, &b).await?;

    let res = register_attempt(&fx, &fx.admin, &c, Some(for_b.clone())).await?;
    assert!(res.is_failure(), "an assertion for one key registered another: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));
    assert_eq!(fx.wallet.view("credential_ids").await?.json::<Vec<String>>()?.len(), 1);

    // The same id with a different public key is a different registration too.
    let mut swapped = b.registration();
    swapped["cred"]["pubkey_sec1"] = c.registration()["cred"]["pubkey_sec1"].clone();
    swapped["assertion"] = json!(for_b.clone());
    let res = fx.admin.call(fx.wallet.id(), "register_credential").args_json(swapped).max_gas().transact().await?;
    assert!(res.is_failure(), "the id was registered with someone else's public key: {res:#?}");
    assert!(why(res).contains("ChallengeMismatch"));

    // Control: it does register b, once.
    register_attempt(&fx, &fx.admin, &b, Some(for_b.clone())).await?.into_result()?;
    let res = register_attempt(&fx, &fx.admin, &c, Some(for_b)).await?;
    assert!(res.is_failure(), "a spent registration assertion was accepted again: {res:#?}");
    Ok(())
}

/// Registration has its own action tag, in both directions, tried against every other tag with
/// the registration's own payload (the most adversarial case: only the tag differs).
#[tokio::test]
async fn a_registration_assertion_cannot_do_anything_else_and_nothing_else_registers() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let spare = Passkey::new("spare phone");
    let reg_payload = register_payload(&spare.credential_id, &spare.pubkey_sec1(), 0);

    // Other tags cannot register.
    for (name, tag) in [
        ("set_rule", ACTION_SET_RULE),
        ("add_payee", ACTION_ADD_PAYEE),
        ("unpause", ACTION_UNPAUSE),
        ("withdraw", ACTION_WITHDRAW),
    ] {
        let a = sign(&fx, &pk, tag, &reg_payload).await?;
        let res = register_attempt(&fx, &fx.admin, &spare, Some(a)).await?;
        assert!(res.is_failure(), "a {name} assertion registered a credential: {res:#?}");
        let msg = why(res);
        assert!(msg.contains("ChallengeMismatch"), "{name}: refused, but not by the tag: {msg}");
    }
    assert_eq!(fx.wallet.view("credential_ids").await?.json::<Vec<String>>()?.len(), 1);

    // A registration assertion cannot do any of the four other things.
    let reg = sign_registration(&fx, &pk, &spare).await?;
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(reg.clone())).await?;
    assert!(res.is_failure() && why(res).contains("ChallengeMismatch"), "set_rule accepted a registration assertion");
    let res = add_payee(&fx, &fx.admin, NODE, "bob.testnet", reg.clone()).await?;
    assert!(res.is_failure() && why(res).contains("ChallengeMismatch"), "add_payee accepted a registration assertion");
    set_paused(&fx, &fx.admin, true, None).await?.into_result()?;
    let res = set_paused(&fx, &fx.admin, false, Some(reg.clone())).await?;
    assert!(res.is_failure() && why(res).contains("ChallengeMismatch"), "unpause accepted a registration assertion");
    let res = fx
        .admin
        .call(fx.wallet.id(), "withdraw")
        .args_json(json!({ "to": "alice.testnet", "amount": "1", "assertion": reg.clone() }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure() && why(res).contains("ChallengeMismatch"), "withdraw accepted a registration assertion");

    // Control: it still registers.
    register_attempt(&fx, &fx.admin, &spare, Some(reg)).await?.into_result()?;
    Ok(())
}

/// Revoking is ungated, so a stolen admin key CAN strand the funds by revoking every credential
/// (it cannot steal them). What it must not be able to do is then re-open the bootstrap and put
/// its own key in: "first registration" means first ever, revoked credentials included.
#[tokio::test]
async fn removing_every_credential_does_not_reopen_the_bootstrap() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let attacker = Passkey::new("an attacker's own key");
    let a = sign_registration(&fx, &pk, &attacker).await?;
    remove_credential(&fx, &fx.admin, &pk).await?.into_result()?;
    assert!(fx.wallet.view("credential_ids").await?.json::<Vec<String>>()?.is_empty());

    let res = register_attempt(&fx, &fx.admin, &attacker, None).await?;
    assert!(res.is_failure(), "the bootstrap reopened after every credential was removed: {res:#?}");
    assert!(why(res).contains("the admin key alone cannot add one"));
    // Even an assertion signed while the credential was still valid is dead once it is removed.
    let res = register_attempt(&fx, &fx.admin, &attacker, Some(a)).await?;
    assert!(res.is_failure(), "a removed credential authorised a registration: {res:#?}");
    assert!(why(res).contains("no such active credential"));
    assert!(fx.wallet.view("credential_ids").await?.json::<Vec<String>>()?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The epoch and the ledger
// ---------------------------------------------------------------------------------------
//
// The next two tests sit side by side on purpose, and the asymmetry between them is the
// whole point: resetting a node's budget hands a full period's headroom back, which is a
// loosening, so only the gated path may do it.
//
// An earlier version reset the ledger on every accepted `set_rule`. Tightening is ungated by
// design, and re-applying the byte-identical rule classifies as a tightening — so ADMIN
// could refill a node's budget with no passkey, as often as it liked, and `period_limit`
// stopped being a limit. See `contract/src/state.rs`.
//
// Nothing can put a non-zero figure into the ledger until `spend` lands in Task 6, so these
// check the epoch and the window, and the figures themselves are pinned in-process by
// `state::tests::a_widening_resets_the_ledger_and_bumps_the_epoch` and
// `..._a_tightening_does_not_reset_the_ledger_or_bump_the_epoch`, which write to the ledger
// directly.

/// A human signed for it, so the budget starts fresh. One sentence for the demo: new rule,
/// new budget.
#[tokio::test]
async fn a_widening_bumps_the_epoch_and_zeroes_the_ledger() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();

    assert_eq!(epoch_of(&fx, NODE).await?, None, "an unconfigured node has no epoch");
    assert_eq!(window_began_ms(&fx, NODE).await?, None, "and no window");

    set_rule_signed(&fx, &pk, NODE, &base_rule(&token)).await?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "the first rule starts at epoch 0");
    let first_window = window_began_ms(&fx, NODE).await?.expect("a window opened");
    assert_eq!(spent_in_period(&fx, NODE).await?, "0");

    // Raising per_tx_limit: a loosening, so it needs an assertion and resets the ledger.
    let wider = rule(&token, 5_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    set_rule_signed(&fx, &pk, NODE, &wider).await?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(1), "an accepted widening advances the epoch");
    assert!(
        window_began_ms(&fx, NODE).await?.expect("a window") >= first_window,
        "the window must have restarted"
    );
    assert_eq!(spent_in_period(&fx, NODE).await?, "0");
    Ok(())
}

/// Nobody signed for it, so nothing is given back. This is the one that was wrong.
#[tokio::test]
async fn a_tightening_bumps_nothing_and_keeps_the_ledger() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let window_before = window_began_ms(&fx, NODE).await?.expect("a window");

    let tighter = rule(&token, 500, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);
    set_rule(&fx, &fx.admin, NODE, &tighter, None).await?.into_result()?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "a tightening must not advance the epoch");
    assert_eq!(
        window_began_ms(&fx, NODE).await?,
        Some(window_before),
        "a tightening must not restart the window"
    );

    // Re-applying the identical rule, repeatedly: the cheapest form of the attack, since
    // `classify` calls it a tightening and it needs no signature.
    for _ in 0..5 {
        set_rule(&fx, &fx.admin, NODE, &tighter, None).await?.into_result()?;
    }
    assert_eq!(
        epoch_of(&fx, NODE).await?,
        Some(0),
        "five free rule changes must not have advanced the epoch"
    );
    assert_eq!(
        window_began_ms(&fx, NODE).await?,
        Some(window_before),
        "five free rule changes must not have restarted the window"
    );

    // And a payee change does not touch the budget arithmetic either.
    let a = sign_add_payee(&fx, &pk, NODE, "bob.testnet").await?;
    add_payee(&fx, &fx.admin, NODE, "bob.testnet", a).await?.into_result()?;
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "add_payee must not advance the epoch");
    assert_eq!(
        window_began_ms(&fx, NODE).await?,
        Some(window_before),
        "add_payee must not restart the window"
    );
    Ok(())
}

/// `node_record` is one view call for everything the demo page draws, so it must agree with
/// the individual views rather than being a second, drifting source of truth.
#[tokio::test]
async fn node_record_agrees_with_the_individual_views() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let record: serde_json::Value = fx
        .wallet
        .view("node_record")
        .args_json(json!({ "node": NODE }))
        .await?
        .json()?;

    assert_eq!(record["epoch"].as_u64(), epoch_of(&fx, NODE).await?.map(u64::from));
    assert_eq!(record["spent"].as_str(), Some(spent_in_period(&fx, NODE).await?.as_str()));
    assert_eq!(record["window_began_ms"].as_u64(), window_began_ms(&fx, NODE).await?);
    assert_eq!(record["rule"], rule_of(&fx, NODE).await?.expect("a rule"));
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
    // ACTION_ADD_PAYEE, not ACTION_SET_RULE: `set_rule` resets the spend ledger and
    // `add_payee` does not, so the two must not share a tag.
    sign(fx, pk, ACTION_ADD_PAYEE, &set_rule_payload(node, &proposed)).await
}

/// **The invariant: every payee on a node's allow-list can receive an `ft_transfer`.**
///
/// NEP-141 `ft_transfer` fails for a receiver with no storage deposit on the token, so a
/// payee that is listed but unregistered makes a legitimate payment fail for a reason that
/// has nothing to do with policy. On recording day that reads as a broken product.
///
/// Two paths write a payee and the invariant has to hold on both. An earlier version
/// enforced it in `add_payee` only, while `set_rule` wrote any list it liked with no
/// registration at all — and the test helpers used that path, so every test's primary payee
/// was unregistered and Task 6's first transfer would have failed for a non-policy reason.
#[tokio::test]
async fn every_payee_on_the_list_is_registered_whichever_path_added_it() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();

    assert!(!is_registered_on_token(&fx, "alice.testnet").await?, "precondition");
    assert!(!is_registered_on_token(&fx, "carol.testnet").await?, "precondition");

    // Path 1: set_rule introduces two payees at once.
    let two = rule(
        &token,
        1_000,
        10_000,
        86_400_000,
        0,
        u64::MAX,
        &["alice.testnet", "carol.testnet"],
        false,
    );
    set_rule_signed(&fx, &pk, NODE, &two).await?;

    // Path 2: add_payee introduces a third.
    let a = sign_add_payee(&fx, &pk, NODE, "bob.testnet").await?;
    add_payee(&fx, &fx.admin, NODE, "bob.testnet", a).await?.into_result()?;

    let payees = payees_of(&fx, NODE).await?;
    assert_eq!(payees.len(), 3, "all three payees are listed: {payees:?}");
    for payee in &payees {
        assert!(
            is_registered_on_token(&fx, payee).await?,
            "{payee} is on the list but cannot receive a transfer"
        );
    }
    Ok(())
}

/// The same invariant from the failing side on the `set_rule` path: if a payee cannot be
/// registered, the rule is not applied at all. Half a rule is worse than none — it would put
/// a payee on the list that cannot be paid.
#[tokio::test]
async fn a_rule_whose_payee_cannot_be_registered_is_not_applied() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;

    // A token contract that does not exist, so the cross-contract call fails.
    let doomed = base_rule("nosuch.token.testnet");
    let nonce_before = nonce_of(&fx, &pk).await?;
    let a = sign_rule(&fx, &pk, NODE, &doomed).await?;
    let res = set_rule(&fx, &fx.admin, NODE, &doomed, Some(a)).await?;

    assert!(
        res.is_success(),
        "a failed storage_deposit should be handled, not blow up the call: {res:#?}"
    );
    assert!(!res.json::<bool>()?, "the callback claimed the rule was applied");
    assert!(
        rule_of(&fx, NODE).await?.is_none(),
        "the rule was applied even though its payee cannot be paid"
    );
    assert_eq!(
        nonce_of(&fx, &pk).await?,
        nonce_before + 1,
        "the assertion must stay spent, so it cannot be replayed"
    );
    Ok(())
}

/// A payee is only registered against the token it was registered on, so changing a rule's
/// `token` makes every payee need registering again even though the account list is untouched.
///
/// `commit_rule` diffs payee accounts, and without this it took the empty-diff early return
/// and committed with zero deposits: the whole list would then be listed against a token none
/// of them is registered on, and the first payment would fail for a reason that is not policy
/// — the exact failure the deposit exists to prevent, reintroduced by the one field nobody
/// thinks of as a payee change.
///
/// A token change is always a widening by `classify`, so this path is gated.
#[tokio::test]
async fn changing_the_token_re_registers_every_payee() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;

    // A second token contract, so the switch is to something real.
    let other_token = fx.worker.dev_deploy(&build_wasm("test-token")?).await?;
    other_token
        .call("new")
        .args_json(json!({
            "owner_id": fx.wallet.id(), "total_supply": "1000000000000", "decimals": 6
        }))
        .transact()
        .await?
        .into_result()?;

    let payees = ["alice.testnet", "carol.testnet"];
    let first = rule(
        &fx.token.id().to_string(),
        1_000,
        10_000,
        86_400_000,
        0,
        u64::MAX,
        &payees,
        false,
    );
    set_rule_signed(&fx, &pk, NODE, &first).await?;
    for p in payees {
        assert!(is_registered_on_token(&fx, p).await?, "{p} not registered on the first token");
    }

    // Same payee list, different token.
    let switched = rule(
        &other_token.id().to_string(),
        1_000,
        10_000,
        86_400_000,
        0,
        u64::MAX,
        &payees,
        false,
    );
    set_rule_signed(&fx, &pk, NODE, &switched).await?;
    assert_eq!(
        rule_of(&fx, NODE).await?.expect("a rule")["token"],
        json!(other_token.id().to_string())
    );

    for p in payees {
        let registered: Option<serde_json::Value> = other_token
            .view("storage_balance_of")
            .args_json(json!({ "account_id": p }))
            .await?
            .json()?;
        assert!(
            registered.is_some(),
            "{p} is on the list but is not registered on the rule's new token"
        );
    }
    Ok(())
}

/// A tightening introduces no payee — any addition is a loosening by `classify` — so it has
/// nothing to register and must stay synchronous. The emergency brake does not wait on
/// another contract.
#[tokio::test]
async fn a_tightening_does_not_wait_on_the_token() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();

    let tighter = rule(&token, 1, 1, 86_400_000, 0, u64::MAX, &[], false);
    let res = set_rule(&fx, &fx.admin, NODE, &tighter, None).await?;
    assert!(res.is_success(), "tightening was refused: {res:#?}");
    // One receipt for the call itself and no cross-contract call after it. `receipt_outcomes`
    // counts the receipts the transaction produced; a dispatched storage_deposit plus its
    // callback would add two more.
    assert_eq!(
        res.receipt_outcomes().len(),
        1,
        "a tightening dispatched a cross-contract call: {:#?}",
        res.receipt_outcomes()
    );
    assert_eq!(payees_of(&fx, NODE).await?, Vec::<String>::new());
    Ok(())
}

/// One call may only introduce a bounded number of payees, because each one costs a
/// `storage_deposit` receipt and the whole transaction has 300 TGas. A longer list is built
/// up over several calls.
#[tokio::test]
async fn a_rule_introducing_too_many_payees_at_once_is_refused() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;
    let token = fx.token.id().to_string();

    let nine: Vec<String> = (0..9).map(|i| format!("p{i}.testnet")).collect();
    let refs: Vec<&str> = nine.iter().map(String::as_str).collect();
    let too_many = rule(&token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &refs, false);

    let a = sign_rule(&fx, &pk, NODE, &too_many).await?;
    let res = set_rule(&fx, &fx.admin, NODE, &too_many, Some(a)).await?;
    assert!(res.is_failure(), "nine new payees in one call were accepted: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("too many payees to register"), "refused, but not for the batch size: {msg}");

    // Eight is the documented bound, and it works.
    let eight: Vec<String> = (0..8).map(|i| format!("p{i}.testnet")).collect();
    let refs: Vec<&str> = eight.iter().map(String::as_str).collect();
    let ok = rule(&token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &refs, false);
    set_rule_signed(&fx, &pk, NODE, &ok).await?;
    assert_eq!(payees_of(&fx, NODE).await?.len(), 8);
    for payee in payees_of(&fx, NODE).await? {
        assert!(is_registered_on_token(&fx, &payee).await?, "{payee} was not registered");
    }
    Ok(())
}

/// `add_payee` registers the payee it adds. The narrower half of
/// `every_payee_on_the_list_is_registered_whichever_path_added_it`, kept because the plan
/// names it and it checks the before/after rather than only the after.
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

/// The `add_payee` half of the invariant: if the token's `storage_deposit` fails, the payee
/// must not end up on the list, because the whole reason to call it is to keep "on the list"
/// meaning "can be paid". The assertion is spent either way — a nonce is never un-consumed,
/// since that would re-arm the assertion.
///
/// The starting rule names a token contract that does not exist **and lists no payees**, so
/// `set_rule` has nothing to register and applies synchronously; the failure then happens in
/// `add_payee` rather than in the rule change, which is what this test is about. The
/// `set_rule` half is `a_rule_whose_payee_cannot_be_registered_is_not_applied`.
#[tokio::test]
async fn a_failed_storage_deposit_leaves_the_payee_off_the_list() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register(&fx, &pk).await?;

    let missing_token = "nosuch.token.testnet";
    let no_payees = rule(missing_token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &[], false);
    set_rule_signed(&fx, &pk, NODE, &no_payees).await?;
    assert_eq!(payees_of(&fx, NODE).await?, Vec::<String>::new());

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
        Vec::<String>::new(),
        "a payee that cannot receive a transfer must not be on the list"
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
/// the asymmetry the whole design rests on, on one `Rule` field. The account-wide switch is
/// `pausing_the_account_is_free_but_unpausing_needs_a_passkey`.
#[tokio::test]
async fn pausing_a_node_is_free_but_unpausing_needs_a_passkey() -> anyhow::Result<()> {
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
// Credential rotation
// ---------------------------------------------------------------------------------------

async fn remove_credential(
    fx: &Fixture,
    caller: &Account,
    pk: &Passkey,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "remove_credential")
        .args_json(json!({ "credential_id": STANDARD.encode(&pk.credential_id) }))
        .max_gas()
        .transact()
        .await?)
}

/// Removing a credential is a tightening, so it is ungated — and it has to exist. Without it,
/// `MAX_CREDENTIALS` is a *lifetime* budget on an account whose code cannot be redeployed:
/// after eight rotations no loosening would ever be possible again, with no way out.
#[tokio::test]
async fn a_removed_credential_cannot_authorise_a_widening() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);

    // Sign while it is still valid, so the only thing wrong with the assertion below is that
    // the credential has since been removed.
    let a = sign_rule(&fx, &pk, NODE, &wider).await?;

    remove_credential(&fx, &fx.admin, &pk).await?.into_result()?;
    assert!(
        fx.wallet
            .view("credential_ids")
            .await?
            .json::<Vec<String>>()?
            .is_empty(),
        "the removed credential is still listed as usable"
    );
    assert_eq!(nonce_of(&fx, &pk).await.ok(), None, "a removed credential has no next nonce");

    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(a)).await?;
    assert!(res.is_failure(), "a removed credential widened a rule: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("no such active credential"), "refused, but not for removal: {msg}");
    Ok(())
}

/// The slot comes back, so rotation is unlimited even though eight is the cap at any moment.
#[tokio::test]
async fn removing_a_credential_frees_a_slot_for_a_new_one() -> anyhow::Result<()> {
    let fx = deploy_with_token().await?;

    // Fill every slot.
    let keys: Vec<Passkey> = (0..8).map(|i| Passkey::new(&format!("phone {i}"))).collect();
    register(&fx, &keys[0]).await?; // the bootstrap: admin alone
    for pk in &keys[1..] {
        register_passkey_via(&fx, &keys[0], pk).await?; // every later one needs a signature
    }
    let ninth = Passkey::new("phone 8");
    let res = register_attempt(&fx, &fx.admin, &ninth, Some(sign_registration(&fx, &keys[0], &ninth).await?)).await?;
    assert!(res.is_failure(), "a ninth credential was registered: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("too many active credentials"), "refused, but not for the cap: {msg}");

    // Free one, and the ninth fits.
    remove_credential(&fx, &fx.admin, &keys[0]).await?.into_result()?;
    register_passkey_via(&fx, &keys[1], &ninth).await?;
    let usable: Vec<String> = fx.wallet.view("credential_ids").await?.json()?;
    assert_eq!(usable.len(), 8);
    assert!(usable.contains(&STANDARD.encode(&ninth.credential_id)));
    assert!(!usable.contains(&STANDARD.encode(&keys[0].credential_id)));

    // The removed credential is still remembered, so its id cannot come back at nonce 0.
    let all: Vec<serde_json::Value> = fx.wallet.view("credentials").await?.json()?;
    assert_eq!(all.len(), 9, "the revoked credential must be retained, not deleted");
    assert_eq!(
        all.iter().filter(|c| c["revoked"] == json!(true)).count(),
        1,
        "exactly one revoked credential"
    );

    // And re-registering the removed id is still refused.
    let res = fx
        .admin
        .call(fx.wallet.id(), "register_credential")
        .args_json(keys[0].registration())
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "a removed credential id was re-registered: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("already known"), "refused, but not as a known id: {msg}");
    Ok(())
}

#[tokio::test]
async fn remove_credential_is_admin_only() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let stranger = fx.worker.dev_create_account().await?;

    let res = remove_credential(&fx, &stranger, &pk).await?;
    assert!(res.is_failure(), "a stranger removed a credential: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "not the admin check: {msg}");
    assert_eq!(fx.wallet.view("credential_ids").await?.json::<Vec<String>>()?.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The account-wide pause
// ---------------------------------------------------------------------------------------

async fn is_paused(fx: &Fixture) -> anyhow::Result<bool> {
    Ok(fx.wallet.view("is_paused").await?.json()?)
}

async fn set_paused(
    fx: &Fixture,
    caller: &Account,
    paused: bool,
    assertion: Option<AssertionJson>,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "set_paused")
        .args_json(json!({ "paused": paused, "assertion": assertion }))
        .max_gas()
        .transact()
        .await?)
}

/// The same asymmetry as everywhere else, on the one switch that covers every node at once.
#[tokio::test]
async fn pausing_the_account_is_free_but_unpausing_needs_a_passkey() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    assert!(!is_paused(&fx).await?);

    set_paused(&fx, &fx.admin, true, None).await?.into_result()?;
    assert!(is_paused(&fx).await?, "pausing did not take");

    let res = set_paused(&fx, &fx.admin, false, None).await?;
    assert!(res.is_failure(), "the account was unpaused with no assertion: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("needs a passkey assertion"), "refused, but not by the gate: {msg}");
    assert!(is_paused(&fx).await?, "a refused unpause must leave the account paused");

    let a = sign(&fx, &pk, ACTION_UNPAUSE, &[]).await?;
    set_paused(&fx, &fx.admin, false, Some(a)).await?.into_result()?;
    assert!(!is_paused(&fx).await?, "a signed unpause did not take");
    Ok(())
}

#[tokio::test]
async fn set_paused_is_admin_only() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let stranger = fx.worker.dev_create_account().await?;

    let res = set_paused(&fx, &stranger, true, None).await?;
    assert!(res.is_failure(), "a stranger paused the account: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("only the admin may change rules"), "not the admin check: {msg}");
    assert!(!is_paused(&fx).await?);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Signatures cannot be redirected between operations
// ---------------------------------------------------------------------------------------
//
// Each gated operation signs under its own action tag. These three tests are the reason the
// tags are separate rather than shared: every pair of operations reaches a different state,
// so a signature for one must not authorise another.

/// `add_payee` leaves the spend ledger alone and `set_rule` resets it, so an assertion signed
/// to add a payee must not be redirectable into a rule change that also wipes the ledger —
/// headroom the signer never agreed to hand back.
#[tokio::test]
async fn an_add_payee_assertion_cannot_set_a_rule() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();

    // The rule that `add_payee(bob)` would produce, signed under the add_payee tag.
    let a = sign_add_payee(&fx, &pk, NODE, "bob.testnet").await?;
    let same_rule = rule(
        &token,
        1_000,
        10_000,
        86_400_000,
        0,
        u64::MAX,
        &["alice.testnet", "bob.testnet"],
        false,
    );

    let res = set_rule(&fx, &fx.admin, NODE, &same_rule, Some(a)).await?;
    assert!(res.is_failure(), "an add_payee assertion was accepted by set_rule: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("ChallengeMismatch"), "refused, but not by the action tag: {msg}");
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "a refused set_rule must not have reset the ledger");
    Ok(())
}

/// And the other way round.
#[tokio::test]
async fn a_set_rule_assertion_cannot_add_a_payee() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let same_rule = rule(
        &token,
        1_000,
        10_000,
        86_400_000,
        0,
        u64::MAX,
        &["alice.testnet", "bob.testnet"],
        false,
    );

    let a = sign_rule(&fx, &pk, NODE, &same_rule).await?;
    let res = add_payee(&fx, &fx.admin, NODE, "bob.testnet", a).await?;
    assert!(res.is_failure(), "a set_rule assertion was accepted by add_payee: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("ChallengeMismatch"), "refused, but not by the action tag: {msg}");
    assert_eq!(payees_of(&fx, NODE).await?, vec!["alice.testnet".to_string()]);
    Ok(())
}

/// An unpause assertion commits to no node and no rule, so without separate tags it would be
/// the most reusable signature in the contract.
#[tokio::test]
async fn an_unpause_assertion_cannot_widen_a_rule() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();
    let wider = rule(&token, 9_000, 10_000, 86_400_000, 0, u64::MAX, &["alice.testnet"], false);

    let a = sign(&fx, &pk, ACTION_UNPAUSE, &[]).await?;
    let res = set_rule(&fx, &fx.admin, NODE, &wider, Some(a)).await?;
    assert!(res.is_failure(), "an unpause assertion widened a rule: {res:#?}");
    let msg = why(res);
    assert!(msg.contains("ChallengeMismatch"), "refused, but not by the action tag: {msg}");

    // And a set_rule assertion cannot unpause the account.
    set_paused(&fx, &fx.admin, true, None).await?.into_result()?;
    let a = sign_rule(&fx, &pk, NODE, &wider).await?;
    let res = set_paused(&fx, &fx.admin, false, Some(a)).await?;
    assert!(res.is_failure(), "a set_rule assertion unpaused the account: {res:#?}");
    assert!(is_paused(&fx).await?);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The exported surface
// ---------------------------------------------------------------------------------------
//
// `#[private]` only checks that the predecessor is this account. In a correct deployment that
// keeps everyone out: the agents' keys are on their own accounts and the frozen wallet has no
// keys. But that is a fact about the deployment, not about this code, and a key on the wallet
// would pass `#[private]` with no admin check and no assertion. So no state-writing method
// relies on it alone.
//
// `commit_rule` was such a method, and it takes a rule and a `reset_ledger` flag, so it was
// an unsigned rule change and a budget wipe behind the deployment being right. The fix is for
// the exported method not to exist.

/// The admin is a **different account** from the wallet.
///
/// `assert_admin` compares the predecessor against the stored admin. If the admin were the
/// wallet, every admin check would succeed for anything that signs as the wallet (the
/// deployer's key before the freeze, or a key added by mistake), and after the freeze for
/// nobody. A correct deployment never has a key on the wallet for an agent, so this is depth,
/// but it is the last place a wrong deployment could have gone unnoticed.
///
/// Refused at initialisation, so a deployment cannot be in that state at all.
#[tokio::test]
async fn the_admin_may_not_be_the_wallet_account() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let wallet = worker.dev_deploy(&common::wasm()?).await?;
    let token: near_workspaces::AccountId = format!("usdc.{}", worker.root_account()?.id()).parse()?;

    let res = wallet
        .call("new")
        .args_json(json!({ "admin": wallet.id(), "token": token }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "the wallet was initialised as its own admin: {res:#?}");
    let msg = why(res);
    assert!(
        msg.contains("admin must be a different account from the wallet"),
        "refused, but not for admin == wallet: {msg}"
    );
    println!("initialising with admin == wallet: {}", one_line(&msg));

    // The contract really is uninitialised, not half-initialised: a view call panics on the
    // missing state rather than reporting an admin.
    let read = wallet.view("get_admin").await;
    assert!(read.is_err(), "state exists after a refused initialisation");

    // And a different admin works, so this test cannot pass by `new` simply being broken.
    let admin = worker.dev_create_account().await?;
    wallet
        .call("new")
        .args_json(json!({ "admin": admin.id(), "token": token }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        wallet.view("get_admin").await?.json::<String>()?,
        admin.id().to_string()
    );
    Ok(())
}

/// `commit_rule` must not be an exported contract method at all. Calling it by name has to
/// fail at method resolution, not at an access check — "the method is not there" is a
/// property of the compiled wasm, whereas "the caller was rejected" depends on who is asking.
#[tokio::test]
async fn commit_rule_is_not_an_exported_method() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();
    let anything = rule(&token, u128::MAX, u128::MAX, 1, 0, u64::MAX, &["attacker.testnet"], false);

    // The arguments `commit_rule` used to take, from an account that is not the admin.
    let stranger = fx.worker.dev_create_account().await?;
    let res = stranger
        .call(fx.wallet.id(), "commit_rule")
        .args_json(json!({ "node": NODE, "rule": rule_json(&anything), "reset_ledger": true }))
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_failure(), "commit_rule is still callable: {res:#?}");
    let msg = why(res);
    assert!(
        msg.contains("MethodNotFound"),
        "commit_rule still exists as a method and was refused some other way: {msg}"
    );
    // Printed so the reason is visible in the test output, not just asserted on.
    println!("calling commit_rule by name: {}", one_line(&msg));

    // And nothing moved.
    let stored = rule_of(&fx, NODE).await?.expect("the rule is still there");
    assert_eq!(stored["per_tx_limit"], json!("1000"));
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0));
    Ok(())
}

/// `on_payees_registered` is the one method that must stay exported, because it is a promise
/// target — so it is the one place `#[private]` is load-bearing, and `#[private]` alone is not
/// enough. It is paired with a check that the promise results it was told to expect are
/// actually present. A direct function call has none, and a function-call access key cannot
/// build a promise chain, so there is no way to fake one.
///
/// This test uses a key on the wallet account, which is the strongest form: `#[private]`
/// passes for it, so what rejects the call is the callback check and nothing else.
#[tokio::test]
async fn on_payees_registered_cannot_be_driven_by_an_agent_key() -> anyhow::Result<()> {
    let (fx, _pk) = ready().await?;
    let token = fx.token.id().to_string();
    let anything = rule(&token, u128::MAX, u128::MAX, 1, 0, u64::MAX, &["attacker.testnet"], false);

    // A deliberately over-broad function-call key on the wallet account, so the call reaches
    // the contract and `#[private]` is satisfied by it.
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    fx.wallet
        .batch()
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend", "on_payees_registered"], None),
        )
        .transact()
        .await?
        .into_result()?;
    let agent = Account::from_secret_key(fx.wallet.id().clone(), sk, &fx.worker);

    // Both ways an attacker would try it: claim no deposits so the result loop is skipped,
    // or claim one and supply none.
    for deposits in [0u64, 1] {
        let res = agent
            .call(fx.wallet.id(), "on_payees_registered")
            .args_json(json!({
                "node": NODE,
                "rule": rule_json(&anything),
                "version": 0,
                "reset_ledger": true,
                "deposits": deposits,
            }))
            .max_gas()
            .transact()
            .await?;
        assert!(
            res.is_failure(),
            "an agent key drove the callback with deposits={deposits}: {res:#?}"
        );
        let msg = why(res);
        assert!(
            msg.contains("not callable directly"),
            "refused with deposits={deposits}, but not by the callback check: {msg}"
        );
        println!("agent key calling on_payees_registered (deposits={deposits}): {}", one_line(&msg));
    }

    let stored = rule_of(&fx, NODE).await?.expect("the rule is still there");
    assert_eq!(stored["per_tx_limit"], json!("1000"), "the rule must be unchanged");
    assert_eq!(epoch_of(&fx, NODE).await?, Some(0), "the ledger must not have been reset");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The build itself
// ---------------------------------------------------------------------------------------

/// Every negative test in this file asserts on the *reason* a call was refused, and that only
/// works if the wasm was built with `--cfg near`. Without it near-sdk compiles `panic_str` to
/// a pure-Rust `panic!()`, which under `panic = "abort"` becomes a wasm trap with the message
/// discarded — and on the deploy path nothing would say so.
///
/// `--cfg near` makes `panic_str` call the host function `panic_utf8`, which then appears in
/// the wasm's import section. This is the canary: if a near-sdk upgrade changes how the host
/// calls are gated, or a build stops passing the flag, this fails before the twelve
/// message-asserting tests start failing for a reason nobody can see.
#[tokio::test]
async fn the_contract_wasm_talks_to_the_host_panic_function() -> anyhow::Result<()> {
    let wasm = build_wasm("leash-contract")?;
    assert!(
        wasm.windows(HOST_PANIC_IMPORT.len()).any(|w| w == HOST_PANIC_IMPORT),
        "the built wasm does not import `panic_utf8`, so it was built without `--cfg near` \
         and would discard every refusal reason on chain"
    );
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

/// The figures the README quotes. Three paths, because they cost very different things and
/// quoting one number for "set_rule" would hide which part is expensive:
///
/// 1. a widening that introduces a payee — the gate, plus a `storage_deposit` on the token
///    and the callback that commits the rule
/// 2. a widening that introduces none — the gate alone, committed synchronously
/// 3. a tightening — no gate at all, the emergency brake
///
/// `probe_verify` measured the curve arithmetic on its own in Task 4.
#[tokio::test]
async fn a_widening_set_rule_fits_in_gas() -> anyhow::Result<()> {
    let (fx, pk) = ready().await?;
    let token = fx.token.id().to_string();

    // 1. Widening that introduces `bob.testnet`, so the token has to register it.
    let with_payee = rule(
        &token,
        100_000,
        1_000_000,
        3_600_000,
        0,
        u64::MAX,
        &["alice.testnet", "bob.testnet"],
        false,
    );
    let a = sign_rule(&fx, &pk, NODE, &with_payee).await?;
    let outcome = set_rule(&fx, &fx.admin, NODE, &with_payee, Some(a)).await?;
    assert!(outcome.is_success(), "the measured call failed: {outcome:#?}");
    let widening_with_payee = outcome.total_gas_burnt;

    // 2. Widening that introduces no payee: raise a limit on the list we already have.
    let no_new_payee = rule(
        &token,
        200_000,
        1_000_000,
        3_600_000,
        0,
        u64::MAX,
        &["alice.testnet", "bob.testnet"],
        false,
    );
    let a = sign_rule(&fx, &pk, NODE, &no_new_payee).await?;
    let outcome = set_rule(&fx, &fx.admin, NODE, &no_new_payee, Some(a)).await?;
    assert!(outcome.is_success(), "the measured call failed: {outcome:#?}");
    let widening_only = outcome.total_gas_burnt;

    // 3. The same method with no assertion to verify.
    let tighter = rule(&token, 1, 1, 86_400_000, 0, u64::MAX, &[], false);
    let tightening = set_rule(&fx, &fx.admin, NODE, &tighter, None)
        .await?
        .total_gas_burnt;

    let tgas = |g: Gas| g.as_gas() as f64 / 1e12;
    println!(
        "set_rule (widening, assertion + a new payee registered): {widening_with_payee} ({:.2} TGas)",
        tgas(widening_with_payee)
    );
    println!(
        "set_rule (widening, assertion, no new payee):             {widening_only} ({:.2} TGas)",
        tgas(widening_only)
    );
    println!(
        "set_rule (tightening, no assertion):                      {tightening} ({:.2} TGas)",
        tgas(tightening)
    );
    println!(
        "  the passkey gate costs:        {:.2} TGas",
        tgas(widening_only) - tgas(tightening)
    );
    println!(
        "  registering one payee costs:   {:.2} TGas",
        tgas(widening_with_payee) - tgas(widening_only)
    );

    assert!(
        widening_with_payee < Gas::from_tgas(100),
        "the widest set_rule path burnt {widening_with_payee}, over the 100 TGas regression \
         guard (the protocol limit is 300 TGas; this bound sits far below it so a regression \
         shows up here first)"
    );
    Ok(())
}
