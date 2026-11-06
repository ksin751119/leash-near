//! The keys the agents hold, and what the protocol — not this contract — refuses them.
//!
//! There is deliberately no contract view that lists access keys: no NEAR host function
//! enumerates them. Key facts are read here through the worker's `view_access_keys` RPC, the
//! same call `scripts/` and the web page use.
//!
//! Every refusal below comes from the NEAR runtime before any contract code runs, which is
//! the point: an agent key's narrowness does not depend on a line of this contract being right.
//! The key is built exactly as `scripts/grant-agent-key.sh` builds it, and it sits where the
//! script puts it: on the AGENT's own account (`pay.ops.…`), not on the wallet. `spend` derives
//! the budget node from `predecessor_id`, so the signer has to be the agent; a key on the wallet
//! would sign as the wallet and be refused with code 1 for having no node (seen on testnet).
//! The key has `receiver_id` = the wallet, `method_names` = `["spend"]`, a small allowance, and
//! is the only key the agent account holds. (The sandbox tests cannot run the near-cli script
//! itself; they mirror its parameters.) The wallet is frozen and holds no key at all.

mod common;

use common::{
    agents, deploy_with_token, full_access_key_count, register_passkey, rule,
    set_rule_signed, Fixture, Passkey,
};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, AccessKeyPermission, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::json;

/// The allowance the grant script uses by default.
const ALLOWANCE: NearToken = NearToken::from_millinear(250);

const PAYEE: &str = "alice.testnet";

/// A deployment as the scripts leave it: the node `ops` has a rule, the wallet is frozen (no key
/// of any kind), and `pay.ops` holds one function-call key restricted like the script's and no
/// full-access key. Returns that agent signing with the restricted key.
async fn frozen_with_key() -> anyhow::Result<(Fixture, Account)> {
    let fx = deploy_with_token().await?;
    let pk = Passkey::new("admin phone");
    register_passkey(&fx, &pk).await?;
    let ag = agents(&fx).await?;
    let token = fx.token.id().to_string();
    set_rule_signed(&fx, &pk, &ag.node, &rule(&token, 1_000, 10_000, 86_400_000, 0, u64::MAX, &[PAYEE], false))
        .await?;

    // grant-agent-key.sh: the restricted key on the agent account, then the agent's full-access
    // keys deleted.
    let sk = SecretKey::from_random(KeyType::ED25519);
    ag.pay
        .batch(ag.pay.id())
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(fx.wallet.id(), &["spend"], Some(ALLOWANCE)),
        )
        .transact()
        .await?
        .into_result()?;
    for k in fx
        .worker
        .view_access_keys(ag.pay.id())
        .await?
        .iter()
        .filter(|k| matches!(k.access_key.permission, AccessKeyPermission::FullAccess))
    {
        ag.pay.batch(ag.pay.id()).delete_key(k.public_key.clone()).transact().await?.into_result()?;
    }

    // freeze.sh: no key left on the wallet.
    for k in fx.worker.view_access_keys(fx.wallet.id()).await? {
        fx.wallet.batch().delete_key(k.public_key.clone()).transact().await?.into_result()?;
    }
    let agent = Account::from_secret_key(ag.pay.id().clone(), sk, &fx.worker);
    Ok((fx, agent))
}

/// A modest, realistic gas attach. NOT `max_gas()`: 300 TGas costs 1 NEAR, more than the key's
/// allowance, so a `max_gas` call is refused with `NotEnoughAllowance` before the key's
/// method or receiver restriction is ever looked at — which would make every negative test in
/// this file pass for the wrong reason. The specific error is asserted below as well.
///
/// 60 TGas, because an allowed `spend` reserves 20 + 15 TGas for its two promises before it
/// starts, so 30 fails with "Exceeded the prepaid gas". Well under what the allowance covers.
const GAS: Gas = Gas::from_tgas(60);

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

/// The control for everything above: the same key, same gas, reaches `spend`, and the policy is
/// really evaluated for this agent. Without it the refusals could just mean the key is dead.
///
/// The answer has to be `allowed`, and the payee must have been paid. The earlier version of
/// this test put the key on the wallet and asserted a refusal with code 1 (no rule for the
/// caller): that was the wrong-key-placement bug written down as the expected result.
#[tokio::test]
async fn the_same_key_can_call_spend() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let res = agent
        .call(fx.wallet.id(), "spend")
        .args_json(json!({ "token": fx.token.id(), "payee": PAYEE, "amount": "750" }))
        .gas(GAS)
        .transact()
        .await?;
    assert!(res.is_success(), "the agent key could not call spend: {res:#?}");
    let v: serde_json::Value = res.json()?;
    assert_eq!(v, json!({ "status": "allowed" }), "unexpected spend answer: {v}");
    let bal: String = fx
        .token
        .view("ft_balance_of")
        .args_json(json!({ "account_id": PAYEE }))
        .await?
        .json()?;
    assert_eq!(bal, "750", "the payee was not paid");
    Ok(())
}

/// The same key, one rule broken: the chain refuses for a policy reason (the allow-list, code 4),
/// not because the caller has no node. Together with the test above this shows the key reaches
/// the policy for *its own* node.
#[tokio::test]
async fn a_policy_refusal_names_the_agents_node() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let res = agent
        .call(fx.wallet.id(), "spend")
        .args_json(json!({ "token": fx.token.id(), "payee": "mallory.testnet", "amount": "1" }))
        .gas(GAS)
        .transact()
        .await?;
    assert!(res.is_success(), "{res:#?}");
    let v: serde_json::Value = res.json()?;
    assert_eq!(v["status"], "refused", "unexpected spend answer: {v}");
    assert_eq!(v["code"], 4, "unexpected spend answer: {v}");
    Ok(())
}

/// The key on chain is exactly what was asked for, on the agent's account: this is the RPC read
/// the later tasks do. It is the only key the agent account holds.
#[tokio::test]
async fn rpc_shows_the_agent_key_is_restricted_to_spend_on_the_wallet() -> anyhow::Result<()> {
    let (fx, agent) = frozen_with_key().await?;
    let keys = fx.worker.view_access_keys(agent.id()).await?;
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

/// The headline: after the freeze the wallet holds no key of any kind, so nobody can sign as it.
#[tokio::test]
async fn rpc_shows_the_wallet_has_no_keys_after_freeze() -> anyhow::Result<()> {
    let (fx, _agent) = frozen_with_key().await?;
    assert_eq!(full_access_key_count(&fx.worker, fx.wallet.id()).await?, 0);
    assert_eq!(fx.worker.view_access_keys(fx.wallet.id()).await?.len(), 0);
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
