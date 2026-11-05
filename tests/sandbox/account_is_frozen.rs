mod common;
use common::{deploy, deploy_and_freeze, full_access_key_count, wasm};

#[tokio::test]
async fn deploying_new_code_fails_after_freeze() -> anyhow::Result<()> {
    let (worker, wallet) = deploy_and_freeze().await?;
    // wallet has zero full-access keys
    assert_eq!(full_access_key_count(&worker, wallet.id()).await?, 0);
    // Redeploying from the account itself must not succeed. With no key left the local
    // signer matches nothing on chain, so the RPC may reject the transaction outright
    // (Err) or return a failed receipt; either one proves the code is frozen.
    let attempt = wallet.batch().deploy(&wasm()?).transact().await;
    match attempt {
        Err(e) => eprintln!("redeploy rejected before execution: {e}"),
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
