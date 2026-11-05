//! Shared helpers for the sandbox tests. Contracts are built from source, so no test
//! depends on a prebuilt wasm download.
#![allow(dead_code)]

use near_workspaces::network::Sandbox;
use near_workspaces::types::{AccessKey, AccessKeyPermission, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use std::path::PathBuf;
use std::process::Command;

/// The workspace root, one level above this crate's manifest.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Build a workspace member to wasm32 (release) and return its bytes.
pub fn build_wasm(package: &str) -> anyhow::Result<Vec<u8>> {
    let root = repo_root();
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(&root)
        .args(["build", "--release", "--target", "wasm32-unknown-unknown", "-p", package])
        .status()?;
    anyhow::ensure!(status.success(), "building {package} to wasm failed");
    let file = package.replace('-', "_");
    let path = root.join(format!("target/wasm32-unknown-unknown/release/{file}.wasm"));
    Ok(std::fs::read(path)?)
}

pub fn wasm() -> anyhow::Result<Vec<u8>> {
    build_wasm("leash-contract")
}

/// Number of full-access keys on the account, read from the sandbox worker's RPC.
pub async fn full_access_key_count(
    worker: &Worker<Sandbox>,
    id: &AccountId,
) -> anyhow::Result<usize> {
    let keys = worker.view_access_keys(id).await?;
    Ok(keys
        .iter()
        .filter(|k| matches!(k.access_key.permission, AccessKeyPermission::FullAccess))
        .count())
}

/// Deploy the Leash contract to a fresh account and initialise it. The account still
/// has its full-access key.
pub async fn deploy() -> anyhow::Result<(Worker<Sandbox>, Contract)> {
    let worker = near_workspaces::sandbox().await?;
    let admin = worker.dev_create_account().await?;
    let wallet = worker.dev_deploy(&wasm()?).await?;
    let token: AccountId = format!("usdc.{}", worker.root_account()?.id()).parse()?;

    wallet
        .call("new")
        .args_json(serde_json::json!({ "admin": admin.id(), "token": token }))
        .transact()
        .await?
        .into_result()?;
    Ok((worker, wallet))
}

/// `deploy`, then delete every full-access key on the wallet account.
pub async fn deploy_and_freeze() -> anyhow::Result<(Worker<Sandbox>, Contract)> {
    let (worker, wallet) = deploy().await?;
    let keys = worker.view_access_keys(wallet.id()).await?;
    for k in keys
        .iter()
        .filter(|k| matches!(k.access_key.permission, AccessKeyPermission::FullAccess))
    {
        wallet
            .batch()
            .delete_key(k.public_key.clone())
            .transact()
            .await?
            .into_result()?;
    }
    Ok((worker, wallet))
}

/// Like `deploy_and_freeze`, but first adds a function-call key for `spend` (the agent
/// key) and returns an `Account` signing with it. The key still exists after the freeze.
pub async fn deploy_and_freeze_with_agent_key(
) -> anyhow::Result<(Worker<Sandbox>, Contract, Account)> {
    let (worker, wallet) = deploy().await?;
    let agent_sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    wallet
        .batch()
        .add_key(
            agent_sk.public_key(),
            AccessKey::function_call_access(wallet.id(), &["spend"], None),
        )
        .transact()
        .await?
        .into_result()?;
    for k in worker
        .view_access_keys(wallet.id())
        .await?
        .iter()
        .filter(|k| matches!(k.access_key.permission, AccessKeyPermission::FullAccess))
    {
        wallet
            .batch()
            .delete_key(k.public_key.clone())
            .transact()
            .await?
            .into_result()?;
    }
    let agent = Account::from_secret_key(wallet.id().clone(), agent_sk, &worker);
    Ok((worker, wallet, agent))
}
