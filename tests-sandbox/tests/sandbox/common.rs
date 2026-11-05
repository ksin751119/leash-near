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

// ---------------------------------------------------------------------------------------
// A full deployment: the wallet contract, its admin, and a NEP-141 to pay out of.
// ---------------------------------------------------------------------------------------

/// Everything the rule tests need. `admin` is the account `set_rule` and friends accept
/// calls from; `wallet` holds the contract; `token` is the NEP-141 named in the rules.
pub struct Fixture {
    pub worker: Worker<Sandbox>,
    pub wallet: Contract,
    pub admin: Account,
    pub token: Contract,
}

/// Deploy the test token and the wallet contract, wiring the wallet's admin and token.
///
/// The token's whole supply goes to the wallet account, which also registers it for
/// storage, so Task 6's transfers have somewhere to come from.
pub async fn deploy_with_token() -> anyhow::Result<Fixture> {
    let worker = near_workspaces::sandbox().await?;
    let admin = worker.dev_create_account().await?;
    let token = worker.dev_deploy(&build_wasm("test-token")?).await?;
    let wallet = worker.dev_deploy(&wasm()?).await?;

    token
        .call("new")
        .args_json(serde_json::json!({
            "owner_id": wallet.id(), "total_supply": "1000000000000", "decimals": 6
        }))
        .transact()
        .await?
        .into_result()?;
    wallet
        .call("new")
        .args_json(serde_json::json!({ "admin": admin.id(), "token": token.id() }))
        .transact()
        .await?
        .into_result()?;

    Ok(Fixture { worker, wallet, admin, token })
}

// ---------------------------------------------------------------------------------------
// A software passkey
// ---------------------------------------------------------------------------------------

use near_sdk::base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// The relying party these tests pretend to be. The contract checks neither the rpIdHash
/// nor the origin (see `contract/src/webauthn.rs`), so the only thing that matters here is
/// that the bytes are stable: they are part of what gets signed.
const RP_ID: &str = "leash.local";
const ORIGIN: &str = "https://leash.local";

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;

/// A P-256 key standing in for a passkey, with the credential id the contract stores it
/// under. Deterministic: the private key is SHA-256 of a label, and signing is RFC 6979,
/// so a test run produces the same bytes every time and a failure is reproducible.
pub struct Passkey {
    signing: SigningKey,
    pub credential_id: Vec<u8>,
}

/// One `navigator.credentials.get()` result, in the JSON shape `Assertion` deserialises.
pub type AssertionJson = serde_json::Value;

impl Passkey {
    pub fn new(label: &str) -> Self {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        let signing = SigningKey::from_bytes(&seed.into()).expect("label gives a usable key");
        let credential_id = Sha256::digest(format!("{label} credential id").as_bytes())[..16].to_vec();
        Self { signing, credential_id }
    }

    /// SEC1 uncompressed, `0x04 ‖ X ‖ Y`.
    pub fn pubkey_sec1(&self) -> Vec<u8> {
        self.signing.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    /// The argument `register_credential` takes.
    pub fn registration(&self) -> serde_json::Value {
        serde_json::json!({ "cred": {
            "id": STANDARD.encode(&self.credential_id),
            "pubkey_sec1": STANDARD.encode(self.pubkey_sec1()),
        }})
    }

    /// Sign `challenge` with the UV bit set, as a device does after a biometric unlock.
    pub fn assert_over(&self, challenge: &[u8; 32]) -> AssertionJson {
        self.assert_over_with_flags(challenge, FLAG_UP | FLAG_UV)
    }

    pub fn assert_over_with_flags(&self, challenge: &[u8; 32], flags: u8) -> AssertionJson {
        // 32-byte rpIdHash ‖ 1 flag byte ‖ 4-byte big-endian signature counter. Synced
        // passkeys leave the counter at zero and the contract does not read it.
        let mut auth = Vec::with_capacity(37);
        auth.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        auth.push(flags);
        auth.extend_from_slice(&0u32.to_be_bytes());

        // Built by hand, not with serde: these exact bytes are what gets signed, so the
        // key order and the absence of whitespace are part of the message.
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        );

        let mut signed = Vec::with_capacity(auth.len() + 32);
        signed.extend_from_slice(&auth);
        signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let sig: Signature = self
            .signing
            .sign_prehash(&Sha256::digest(&signed))
            .expect("signing a 32-byte prehash cannot fail");

        serde_json::json!({
            "credential_id": STANDARD.encode(&self.credential_id),
            "authenticator_data": STANDARD.encode(&auth),
            "client_data_json": client_data_json,
            "signature_der": STANDARD.encode(sig.to_der().as_bytes()),
        })
    }
}

// ---------------------------------------------------------------------------------------
// The challenge, reproduced from the documented byte layout
// ---------------------------------------------------------------------------------------

/// The action tag every rule change is signed under. Mirrors `ACTION_SET_RULE` in
/// `contract/src/challenge.rs`.
pub const ACTION_SET_RULE: &str = "leash:set_rule:v1";

/// `sha256(len(action) ‖ action ‖ len(payload) ‖ payload ‖ nonce ‖ len(contract) ‖ contract)`,
/// written out here independently of the contract. Lengths are `u32` little-endian, the
/// nonce is `u64` little-endian. See the module doc comment in `contract/src/challenge.rs`
/// for the authoritative description; `challenge_for` on the contract is checked against
/// this function by `challenge_for_matches_the_documented_layout`.
pub fn gate_challenge(action: &str, payload: &[u8], nonce: u64, contract: &str) -> [u8; 32] {
    let mut m = Vec::new();
    m.extend_from_slice(&(action.len() as u32).to_le_bytes());
    m.extend_from_slice(action.as_bytes());
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(payload);
    m.extend_from_slice(&nonce.to_le_bytes());
    m.extend_from_slice(&(contract.len() as u32).to_le_bytes());
    m.extend_from_slice(contract.as_bytes());
    Sha256::digest(&m).into()
}

/// The payload a rule change commits to: the node, then the normalised rule's Borsh bytes.
pub fn set_rule_payload(node: &str, rule: &leash_contract::rule::Rule) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(node.len() as u32).to_le_bytes());
    p.extend_from_slice(node.as_bytes());
    p.extend_from_slice(&near_sdk::borsh::to_vec(rule).expect("a Rule always serialises"));
    p
}

/// Why a call failed, as the chain reported it.
///
/// Readable only because `.cargo/config.toml` passes `--cfg near`; without it every
/// `require!` in the contract arrives as a bare `unreachable` trap with the message gone.
/// Asserting on these strings is what makes a negative test prove the gate rejected the
/// call, rather than prove that something — anything — went wrong.
pub fn why(res: near_workspaces::result::ExecutionFinalResult) -> String {
    format!("{:?}", res.into_result().expect_err("the call was expected to fail"))
}
