//! The keys the agents hold, and what the protocol — not this contract — refuses them.
//!
//! There is deliberately no contract view that lists access keys: no NEAR host function
//! enumerates them. Key facts are read here through the worker's `view_access_keys` RPC, the
//! same call `scripts/` and the web page use.
//!
//! Every refusal below comes from the NEAR runtime before any contract code runs, which is
//! the point: an agent key's narrowness does not depend on a line of this contract being right.
//! The key is built exactly as `scripts/grant-agent-key.sh` builds it: `receiver_id` = the
//! wallet, `method_names` = `["spend"]`, a small allowance. (The sandbox tests cannot run the
//! near-cli script itself; they mirror its parameters.)

mod common;

use common::{deploy_with_token, full_access_key_count, Fixture};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, AccessKeyPermission, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::json;

/// The allowance the grant script uses by default.
const ALLOWANCE: NearToken = NearToken::from_millinear(250);

/// Freeze a fresh deployment with one agent key on the wallet, restricted like the script's.
async fn frozen_with_key() -> anyhow::Result<(Fixture, Account)> {
    let fx = deploy_with_token().await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    fx.wallet
        .batch()
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend"], Some(ALLOWANCE)),
        )
        .transact()
        .await?
        .into_result()?;
    for k in fx
        .worker
        .view_access_keys(fx.wallet.id())
        .await?
        .iter()
        .filter(|k| matches!(k.access_key.permission, AccessKeyPermission::FullAccess))
    {
        fx.wallet.batch().delete_key(k.public_key.clone()).transact().await?.into_result()?;
    }
    let agent = Account::from_secret_key(fx.wallet.id().clone(), sk, &fx.worker);
    Ok((fx, agent))
}

/// A modest, realistic gas attach. NOT `max_gas()`: 300 TGas costs 1 NEAR, more than the key's
/// allowance, so a `max_gas` call is refused with `NotEnoughAllowance` before the key's
/// method or receiver restriction is ever looked at — which would make every negative test in
/// this file pass for the wrong reason. The specific error is asserted below as well.
const GAS: Gas = Gas::from_tgas(30);

/// How a call refused at the protocol layer shows up. Depending on the check, the node
/// rejects the transaction outright (an `Err`) or it fails as a receipt; either counts, and
/// the text must name the SPECIFIC restriction that fired — not merely "an access-key error".
fn refusal(r: anyhow::Result<ExecutionFinalResult>, expect: &[&str]) -> String {
    let text = match r {
        Err(e) => format!("{e:?}"),
        Ok(res) => {
            assert!(res.is_failure(), "the agent key was allowed through: {res:#?}");
            format!("{:?}", res.into_result().unwrap_err())
        }
    };
    assert!(
        expect.iter().any(|e| text.contains(e)),
        "refused, but not by the access-key check (wanted one of {expect:?}): {text}"
    );
    text
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[tokio::test]
async fn an_agent_key_cannot_call_anything_but_spend() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let to = fx.admin.id().to_string();
    let calls = [
        ("set_rule", json!({ "node": "ops.testnet", "rule": {}, "assertion": {} })),
        ("withdraw", json!({ "to": to, "amount": "1", "assertion": {} })),
        ("add_payee", json!({ "node": "ops.testnet", "payee": to, "assertion": {} })),
        ("register_credential", json!({ "cred": {} })),
        ("set_paused", json!({ "paused": false, "assertion": null })),
        ("on_withdrawn", json!({ "to": to, "amount": "1" })),
    ];
    for (method, args) in calls {
        let r = agent
            .call(fx.wallet.id(), method)
            .args_json(args)
            .gas(GAS)
            .transact()
            .await
            .map_err(Into::into);
        let text = refusal(r, &["MethodNameMismatch"]);
        println!("agent key -> {method}: {}", one_line(&text));
    }
    Ok(())
}

#[tokio::test]
async fn an_agent_key_cannot_call_the_token_contract_directly() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    // The wallet holds the whole supply, so if this went through it would move real money.
    // NEP-141 wants 1 yoctoNEAR attached, and a function-call key cannot attach a deposit at
    // all (`DepositWithFunctionCall`, checked first); without one the receiver restriction is
    // what refuses it. Both routes are closed at the protocol.
    for (deposit, expect) in [
        (NearToken::from_yoctonear(1), "DepositWithFunctionCall"),
        (NearToken::from_yoctonear(0), "ReceiverMismatch"),
    ] {
        let r = agent
            .call(fx.token.id(), "ft_transfer")
            .args_json(json!({ "receiver_id": fx.admin.id(), "amount": "1" }))
            .deposit(deposit)
            .gas(GAS)
            .transact()
            .await
            .map_err(Into::into);
        let text = refusal(r, &[expect]);
        println!("agent key -> token.ft_transfer (deposit {deposit}): {}", one_line(&text));
    }
    let bal: String = fx
        .token
        .view("ft_balance_of")
        .args_json(json!({ "account_id": fx.admin.id() }))
        .await?
        .json()?;
    assert_eq!(bal, "0");
    Ok(())
}

/// The attacks on frozen code: change it (deploy), add a way back in (add_key), remove the
/// restriction's neighbours (delete_key), or remove the account (delete_account) — and move
/// NEAR. All need a full-access key, which no one holds after the freeze, and the agent's
/// function-call key is refused each time with `RequiresFullAccess`.
#[tokio::test]
async fn an_agent_key_cannot_add_keys_deploy_delete_or_transfer() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let wallet = fx.wallet.id();
    let other = SecretKey::from_random(KeyType::ED25519).public_key();
    let own = agent.secret_key().public_key();

    let attempts: Vec<(&str, anyhow::Result<ExecutionFinalResult>)> = vec![
        (
            "add_key(full access)",
            agent.batch(wallet).add_key(other, AccessKey::full_access()).transact().await.map_err(Into::into),
        ),
        (
            "deploy",
            agent.batch(wallet).deploy(&common::wasm()?).transact().await.map_err(Into::into),
        ),
        (
            "delete_key (its own)",
            agent.batch(wallet).delete_key(own).transact().await.map_err(Into::into),
        ),
        (
            "delete_account",
            agent.batch(wallet).delete_account(fx.admin.id()).transact().await.map_err(Into::into),
        ),
        (
            "transfer NEAR",
            agent
                .transfer_near(fx.admin.id(), NearToken::from_yoctonear(1))
                .await
                .map_err(Into::into),
        ),
    ];
    for (what, r) in attempts {
        let text = refusal(r, &["RequiresFullAccess"]);
        println!("agent key -> {what}: {}", one_line(&text));
    }
    // And the code is the code it was: the contract still answers.
    assert_eq!(full_access_key_count(&fx.worker, wallet).await?, 0);
    let admin: String = fx.wallet.view("get_admin").await?.json()?;
    assert_eq!(admin, fx.admin.id().to_string());
    Ok(())
}

/// The control for everything above: the same key, same gas, reaches `spend`. Without it the
/// refusals could just mean the key is dead. A caller with no rule is answered, not rejected.
#[tokio::test]
async fn the_same_key_can_call_spend() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let res = agent
        .call(fx.wallet.id(), "spend")
        .args_json(json!({ "token": fx.token.id(), "payee": fx.admin.id(), "amount": "1" }))
        .gas(GAS)
        .transact()
        .await?;
    assert!(res.is_success(), "the agent key could not call spend: {res:#?}");
    // Proof that `spend` actually RAN, not merely that the transaction landed: the contract's
    // own answer, a refusal with code 1 (no rule for this caller).
    let v: serde_json::Value = res.json()?;
    assert_eq!(v["status"], "refused", "unexpected spend answer: {v}");
    assert_eq!(v["code"], 1, "unexpected spend answer: {v}");
    Ok(())
}

/// The key on chain is exactly what was asked for: this is the RPC read the later tasks do.
#[tokio::test]
async fn rpc_shows_the_agent_key_is_restricted_to_spend_on_the_wallet() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let keys = fx.worker.view_access_keys(fx.wallet.id()).await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].public_key, agent.secret_key().public_key());
    match &keys[0].access_key.permission {
        AccessKeyPermission::FunctionCall(fc) => {
            assert_eq!(fc.receiver_id, fx.wallet.id().to_string());
            assert_eq!(fc.method_names, vec!["spend".to_string()]);
            assert_eq!(fc.allowance, Some(ALLOWANCE));
        }
        other => panic!("the agent key is not a function-call key: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn rpc_shows_zero_full_access_keys_after_freeze() -> anyhow::Result<()> {
    let (fx, _agent) = frozen_with_key().await?;
    assert_eq!(full_access_key_count(&fx.worker, fx.wallet.id()).await?, 0);
    Ok(())
}

/// The names of a wasm module's exports, read from its export section (id 7). Hand-parsed
/// because the only alternative is a dependency for fifteen lines.
fn wasm_exports(wasm: &[u8]) -> Vec<String> {
    fn leb(b: &[u8], at: &mut usize) -> usize {
        let (mut v, mut shift) = (0usize, 0);
        loop {
            let byte = b[*at];
            *at += 1;
            v |= ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                return v;
            }
            shift += 7;
        }
    }
    assert_eq!(&wasm[..4], b"\0asm");
    let mut at = 8;
    while at < wasm.len() {
        let id = wasm[at];
        at += 1;
        let size = leb(wasm, &mut at);
        if id == 7 {
            let mut p = at;
            let count = leb(wasm, &mut p);
            let mut names = Vec::new();
            for _ in 0..count {
                let n = leb(wasm, &mut p);
                names.push(String::from_utf8(wasm[p..p + n].to_vec()).unwrap());
                p += n;
                p += 1; // export kind
                leb(wasm, &mut p); // index
            }
            return names;
        }
        at += size;
    }
    panic!("no export section");
}

/// The contract must not grow a key-enumeration method; nothing on the host could back one.
/// Compared against the module's real export list, not a grep of its bytes.
#[tokio::test]
async fn the_contract_exports_no_key_enumeration() -> anyhow::Result<()> {
    let exports = wasm_exports(&common::wasm()?);
    println!("exports: {exports:?}");
    assert!(exports.contains(&"spend".to_string()) && exports.contains(&"withdraw".to_string()));
    assert!(exports.len() > 10, "export list looks wrong: {exports:?}");
    for e in &exports {
        assert!(!e.to_lowercase().contains("key"), "an export mentions keys: {e}");
    }
    Ok(())
}
