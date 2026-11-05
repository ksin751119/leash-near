mod common;
use common::{deploy, deploy_and_freeze, deploy_and_freeze_with_agent_key, full_access_key_count, wasm};

#[tokio::test]
async fn deploying_new_code_fails_after_freeze() -> anyhow::Result<()> {
    let (worker, wallet) = deploy_and_freeze().await?;
    // wallet has zero full-access keys
    assert_eq!(full_access_key_count(&worker, wallet.id()).await?, 0);
    // Redeploying from the account itself must not succeed. With no key left the local
    // signer matches nothing on chain, so the RPC may reject the transaction outright
    // (Err) or return a failed receipt. An Err only counts if it names the access-key
    // problem: near-workspaces maps every RPC failure to the same BroadcastTxFailure,
    // so an unrelated outage must not make this test pass.
    match wallet.batch().deploy(&wasm()?).transact().await {
        Err(e) => {
            let text = format!("{e:?}");
            eprintln!("redeploy rejected: {text}");
            assert!(
                text.contains("AccessKeyNotFound") || text.contains("InvalidAccessKeyError"),
                "rejected for the wrong reason: {text}"
            );
        }
        Ok(res) => {
            eprintln!("redeploy returned a failed outcome");
            assert!(res.is_failure(), "redeploy unexpectedly succeeded");
        }
    }
    Ok(())
}

/// Control: the same redeploy works while the full-access key still exists, so the
/// test above fails because of the freeze and not because of the redeploy itself.
#[tokio::test]
async fn deploying_new_code_works_before_freeze() -> anyhow::Result<()> {
    let (worker, wallet) = deploy().await?;
    assert_eq!(full_access_key_count(&worker, wallet.id()).await?, 1);
    wallet.batch().deploy(&wasm()?).transact().await?.into_result()?;
    Ok(())
}

/// The agent case: a key that exists on the account (function-call, `spend` only) still
/// cannot deploy. The transaction reaches the chain and is rejected on the merits.
#[tokio::test]
async fn function_call_key_cannot_deploy_after_freeze() -> anyhow::Result<()> {
    let (worker, wallet, agent) = deploy_and_freeze_with_agent_key().await?;
    assert_eq!(full_access_key_count(&worker, wallet.id()).await?, 0);
    assert_eq!(worker.view_access_keys(wallet.id()).await?.len(), 1);
    match agent.batch(wallet.id()).deploy(&wasm()?).transact().await {
        Err(e) => {
            let text = format!("{e:?}");
            eprintln!("agent redeploy rejected: {text}");
            assert!(
                text.contains("RequiresFullAccess") || text.contains("InvalidAccessKeyError"),
                "rejected for the wrong reason: {text}"
            );
        }
        Ok(res) => {
            eprintln!("agent redeploy returned a failed outcome");
            assert!(res.is_failure(), "agent key redeployed the contract");
        }
    }
    Ok(())
}
