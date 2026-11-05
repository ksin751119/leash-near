//! The risk gate for the whole design: P-256 is not a NEAR host function, so a WebAuthn
//! assertion is verified by curve arithmetic running inside the wasm. If that does not fit in
//! a transaction's gas, loosening a rule cannot be gated on a passkey and the design falls
//! back to a 24-hour timelock.
//!
//! `set_rule` does not exist until Task 5, so the gate measures `probe_verify`: a view method
//! that runs exactly the verification and nothing else. Task 5 measures the whole `set_rule`
//! path, and that is the figure the README quotes.

mod common;
use common::deploy;
use near_workspaces::types::Gas;

const VALID: &str = include_str!("../fixtures/assertion_valid.json");
const UV_CLEAR: &str = include_str!("../fixtures/assertion_uv_clear.json");
const WRONG_CHALLENGE: &str = include_str!("../fixtures/assertion_wrong_challenge.json");

/// `probe_verify`'s arguments, straight out of a fixture file. Every byte field in the
/// fixture is already standard base64, which is what `Base64VecU8` reads, so these are
/// copied across untouched — the test does not re-encode anything and so cannot paper over
/// an encoding mistake.
fn probe_args(fixture: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(fixture).expect("fixture is valid JSON");
    serde_json::json!({
        "pubkey_sec1": v["pubkey_sec1"],
        "challenge": v["challenge"],
        "authenticator_data": v["authenticator_data"],
        "client_data_json": v["client_data_json"],
        "signature_der": v["signature_der"],
    })
}

#[tokio::test]
async fn verifying_a_real_assertion_fits_in_gas() -> anyhow::Result<()> {
    let (_worker, wallet) = deploy().await?;

    let outcome = wallet
        .call("probe_verify")
        .args_json(probe_args(VALID))
        .max_gas()
        .transact()
        .await?;

    assert!(outcome.is_success(), "probe_verify failed: {outcome:#?}");
    // `json` consumes the outcome, so read the gas first.
    let burnt = outcome.total_gas_burnt;
    // Without this the test could pass while measuring the cost of an early `false` return,
    // which is not the cost the gate is about.
    assert!(
        outcome.json::<bool>()?,
        "probe_verify returned false, so the gas figure below is not the cost of a \
         successful verification"
    );

    // A trivial method on the same contract, for scale: every function call pays for the
    // transaction and for loading the contract's code before it executes a single
    // instruction. Printing it makes the figure above readable — the difference is what the
    // curve arithmetic actually costs, and that is the part Task 5 has to budget around.
    let baseline = wallet
        .call("is_paused")
        .max_gas()
        .transact()
        .await?
        .total_gas_burnt;

    println!(
        "WebAuthn P-256 verification on chain: {burnt} burnt ({} gas, {:.2} TGas)",
        burnt.as_gas(),
        burnt.as_gas() as f64 / 1e12
    );
    println!(
        "  of which fixed overhead (a no-op call on the same contract): {baseline} ({} gas)",
        baseline.as_gas()
    );
    println!(
        "  verification itself: {:.2} TGas",
        (burnt.as_gas().saturating_sub(baseline.as_gas())) as f64 / 1e12
    );

    assert!(
        burnt < Gas::from_tgas(300),
        "verification burnt {burnt}, which does not fit in a transaction"
    );
    Ok(())
}

/// The same path, on chain, for the two assertions that must not pass. Without this the gate
/// would prove only that the contract can say yes.
#[tokio::test]
async fn probe_rejects_assertions_that_must_not_pass() -> anyhow::Result<()> {
    let (_worker, wallet) = deploy().await?;

    for (name, fixture) in [("uv bit clear", UV_CLEAR), ("wrong challenge", WRONG_CHALLENGE)] {
        let outcome = wallet
            .call("probe_verify")
            .args_json(probe_args(fixture))
            .max_gas()
            .transact()
            .await?;
        assert!(outcome.is_success(), "probe_verify panicked on {name}: {outcome:#?}");
        let burnt = outcome.total_gas_burnt;
        assert!(
            !outcome.json::<bool>()?,
            "the contract accepted an assertion with {name}"
        );
        println!("rejected ({name}): {burnt} burnt");
    }
    Ok(())
}
