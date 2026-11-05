mod common;
use common::build_wasm;
use near_workspaces::types::NearToken;
use serde_json::json;

#[tokio::test]
async fn transfer_needs_a_registered_receiver() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let token = worker.dev_deploy(&build_wasm("test-token")?).await?;
    let owner = worker.dev_create_account().await?;
    let receiver = worker.dev_create_account().await?;

    token
        .call("new")
        .args_json(json!({ "owner_id": owner.id(), "total_supply": "1000000000", "decimals": 6 }))
        .transact()
        .await?
        .into_result()?;

    let transfer = |amount: &str| {
        owner
            .call(token.id(), "ft_transfer")
            .args_json(json!({ "receiver_id": receiver.id(), "amount": amount, "memo": null }))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
    };

    // receiver has no storage deposit: the transfer fails and nothing moves
    assert!(transfer("250").await?.is_failure());
    let bal: String = token.view("ft_balance_of").args_json(json!({ "account_id": receiver.id() })).await?.json()?;
    assert_eq!(bal, "0");

    receiver
        .call(token.id(), "storage_deposit")
        .args_json(json!({ "account_id": receiver.id() }))
        .deposit(NearToken::from_millinear(10))
        .transact()
        .await?
        .into_result()?;

    transfer("250").await?.into_result()?;
    let bal: String = token.view("ft_balance_of").args_json(json!({ "account_id": receiver.id() })).await?.json()?;
    assert_eq!(bal, "250");
    let owner_bal: String = token.view("ft_balance_of").args_json(json!({ "account_id": owner.id() })).await?.json()?;
    assert_eq!(owner_bal, "999999750");
    let supply: String = token.view("ft_total_supply").await?.json()?;
    assert_eq!(supply, "1000000000");
    Ok(())
}
