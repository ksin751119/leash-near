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

/// The host function `env::panic_str` calls when the wasm is built with `--cfg near`. Its
/// presence in the import section is how a build proves it carries the flag; see
/// `.cargo/config.toml` and `scripts/build-contract.sh`.
pub const HOST_PANIC_IMPORT: &[u8] = b"panic_utf8";

/// Build a workspace member to wasm32 (release) and return its bytes.
///
/// Sets `--cfg near` itself rather than relying on `.cargo/config.toml`, because cargo
/// ignores config `rustflags` entirely whenever the `RUSTFLAGS` environment variable is set,
/// even to the empty string — and a wasm built without the flag silently discards every panic
/// message, which would turn a dozen assertions in `rules.rs` about *why* a call was refused
/// into assertions that something, anything, went wrong.
pub fn build_wasm(package: &str) -> anyhow::Result<Vec<u8>> {
    let root = repo_root();
    let rustflags = match std::env::var("RUSTFLAGS") {
        Ok(existing) => format!("{existing} --cfg near"),
        Err(_) => "--cfg near".to_string(),
    };
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(&root)
        .env("RUSTFLAGS", rustflags)
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

/// The action tags, mirroring `contract/src/challenge.rs`. Written out here rather than
/// imported so that renaming one in the contract shows up as a test failure.
///
/// `set_rule` and `add_payee` sign over the same payload under different tags, because
/// `set_rule` resets the spend ledger and `add_payee` does not.
pub const ACTION_SET_RULE: &str = "leash:set_rule:v1";
pub const ACTION_ADD_PAYEE: &str = "leash:add_payee:v1";
pub const ACTION_UNPAUSE: &str = "leash:unpause:v1";

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

// ---------------------------------------------------------------------------------------
// Setting a rule, and the agent accounts that spend against it
// ---------------------------------------------------------------------------------------
//
// `rules.rs` (Task 5) carries its own older copies of the three signing helpers below. These
// are the shared ones: anything written after Task 6 uses them from here, so that the way a
// test configures a node lives in one place rather than growing a copy per file.

use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::NearToken;
use serde_json::json;

/// A rule's JSON, as the contract's own serializer writes it. Going through the contract's
/// `Rule` type rather than a hand-built object means a test cannot submit a field the
/// contract does not have, or miss one it does.
pub fn rule_json(r: &leash_contract::rule::Rule) -> serde_json::Value {
    serde_json::from_str(&near_sdk::serde_json::to_string(r).expect("Rule serialises"))
        .expect("serde_json agrees with near_sdk's")
}

/// `Rule::try_new` with `&str` payees. Panics on an invalid rule: a test that writes one has
/// a typo, and it should name itself rather than arrive as a failed contract call later.
#[allow(clippy::too_many_arguments)]
pub fn rule(
    token: &str,
    per_tx_limit: u128,
    period_limit: u128,
    period_ms: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    payees: &[&str],
    paused: bool,
) -> leash_contract::rule::Rule {
    leash_contract::rule::Rule::try_new(
        token.parse().expect("valid token id"),
        per_tx_limit,
        period_limit,
        period_ms,
        window_start_ms,
        window_end_ms,
        payees.iter().map(|p| p.parse().expect("valid payee id")).collect(),
        paused,
    )
    .expect("the test wrote an invalid rule")
}

/// Register `pk` as a credential that may authorise loosenings. ADMIN only, so it goes
/// through the fixture's admin account.
pub async fn register_passkey(fx: &Fixture, pk: &Passkey) -> anyhow::Result<()> {
    fx.admin
        .call(fx.wallet.id(), "register_credential")
        .args_json(pk.registration())
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

/// The nonce the credential's next challenge must carry.
pub async fn nonce_of(fx: &Fixture, pk: &Passkey) -> anyhow::Result<u64> {
    let n: Option<u64> = fx
        .wallet
        .view("credential_nonce")
        .args_json(json!({ "credential_id": STANDARD.encode(&pk.credential_id) }))
        .await?
        .json()?;
    n.ok_or_else(|| anyhow::anyhow!("credential is not registered"))
}

/// Sign `rule` for `node` as a `set_rule`, at the credential's current nonce.
pub async fn sign_rule(
    fx: &Fixture,
    pk: &Passkey,
    node: &str,
    r: &leash_contract::rule::Rule,
) -> anyhow::Result<AssertionJson> {
    let nonce = nonce_of(fx, pk).await?;
    Ok(pk.assert_over(&gate_challenge(
        ACTION_SET_RULE,
        &set_rule_payload(node, r),
        nonce,
        fx.wallet.id().as_str(),
    )))
}

/// `set_rule` as ADMIN, with a freshly signed assertion, asserting that it landed.
///
/// Every rule these tests set is a loosening — the first rule for a node always is — so
/// every one of them needs a signature. That is the gate working, not a detour around it.
pub async fn set_rule_signed(
    fx: &Fixture,
    pk: &Passkey,
    node: &str,
    r: &leash_contract::rule::Rule,
) -> anyhow::Result<()> {
    let assertion = sign_rule(fx, pk, node, r).await?;
    let res = fx
        .admin
        .call(fx.wallet.id(), "set_rule")
        .args_json(json!({ "node": node, "rule": rule_json(r), "assertion": assertion }))
        .max_gas()
        .transact()
        .await?;
    anyhow::ensure!(res.is_success(), "a signed set_rule failed: {res:#?}");
    Ok(())
}

/// Pause or unpause the whole account. Pausing needs no assertion; unpausing does, which is
/// why this only pauses.
pub async fn pause_account(fx: &Fixture) -> anyhow::Result<()> {
    fx.admin
        .call(fx.wallet.id(), "set_paused")
        .args_json(json!({ "paused": true, "assertion": null }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

/// Create `<name>.<parent>` with a full-access key and `near` NEAR to pay for gas.
///
/// The balance has to cover what this account will itself spend on creating children: `ops`
/// pays for both agent accounts out of its own balance, so it needs more than they do.
pub async fn subaccount(parent: &Account, name: &str, near: u128) -> anyhow::Result<Account> {
    Ok(parent
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .transact()
        .await?
        .into_result()?)
}

/// The two agents and the node they share, created under the sandbox root.
///
/// The names are the point: `pay.ops.…` and `subs.ops.…` both derive to `ops.…`, so one rule
/// governs both processes and the budget is drawn down by two callers with no channel between
/// them. That is the shared-budget claim, and it is enforced by the protocol's naming rule
/// rather than by any registry in this contract.
pub struct Agents {
    pub node: String,
    pub pay: Account,
    pub subs: Account,
}

/// `ops.<root>` with two agent accounts under it. The node account itself exists only to be a
/// name and a parent — the contract never looks it up and it never signs anything.
pub async fn agents(fx: &Fixture) -> anyhow::Result<Agents> {
    let root = fx.worker.root_account()?;
    let ops = subaccount(&root, "ops", 30).await?;
    let pay = subaccount(&ops, "pay", 10).await?;
    let subs = subaccount(&ops, "subs", 10).await?;
    Ok(Agents { node: ops.id().to_string(), pay, subs })
}

/// `agent` signing with a function-call key on **its own** account, restricted to calling
/// `spend` on the wallet and nothing else.
///
/// This is the key an agent process actually holds, and using it in a test proves two things
/// a full-access key would not: that `spend` is reachable from a restricted key at all, and
/// that it works with **no deposit attached** — a function-call key cannot attach one, which
/// is why the contract pays NEP-141's one yoctoNEAR itself.
pub async fn restricted_key(fx: &Fixture, agent: &Account) -> anyhow::Result<Account> {
    let sk = SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    agent
        // `Account::batch` wants the receiver; the key being added lives on `agent` itself and
        // is restricted to calling the wallet, which is the two halves of this line.
        .batch(agent.id())
        .add_key(sk.public_key(), AccessKey::function_call_access(fx.wallet.id(), &["spend"], None))
        .transact()
        .await?
        .into_result()?;
    Ok(Account::from_secret_key(agent.id().clone(), sk, &fx.worker))
}

/// Call `spend` as `caller`. Returns the raw result, because most of these tests care that
/// the transaction *succeeded* while the payment did not.
pub async fn spend(
    fx: &Fixture,
    caller: &Account,
    token: &str,
    payee: &str,
    amount: u128,
) -> anyhow::Result<ExecutionFinalResult> {
    Ok(caller
        .call(fx.wallet.id(), "spend")
        .args_json(json!({ "token": token, "payee": payee, "amount": amount.to_string() }))
        .max_gas()
        .transact()
        .await?)
}

/// The NEP-141 balance of one account on the fixture's token.
pub async fn balance_of(fx: &Fixture, account: &str) -> anyhow::Result<u128> {
    let b: String = fx
        .token
        .view("ft_balance_of")
        .args_json(json!({ "account_id": account }))
        .await?
        .json()?;
    Ok(b.parse()?)
}

/// `spent_in_period` for a node, as a number.
pub async fn spent_in_period(fx: &Fixture, node: &str) -> anyhow::Result<u128> {
    let s: String = fx
        .wallet
        .view("spent_in_period")
        .args_json(json!({ "node": node }))
        .await?
        .json()?;
    Ok(s.parse()?)
}

/// The decision ring, newest first, as raw JSON — the shape the demo page receives.
pub async fn recent_decisions(fx: &Fixture) -> anyhow::Result<Vec<serde_json::Value>> {
    Ok(fx.wallet.view("recent_decisions").await?.json()?)
}

/// The outcome of the newest decision, parsed back into the contract's own enum through the
/// wire shape a client sees.
pub async fn newest_outcome(fx: &Fixture) -> anyhow::Result<leash_contract::decision::Outcome> {
    let all = recent_decisions(fx).await?;
    let newest = all.first().ok_or_else(|| anyhow::anyhow!("no decisions recorded"))?;
    // Through a string, so this compiles whether or not cargo unified the test's `serde_json`
    // with `near_sdk`'s. Deserialising rather than reading the fields is the point: it checks
    // that the shape a client receives really does parse back into the contract's own enum.
    let s = serde_json::to_string(&newest["outcome"])?;
    Ok(near_sdk::serde_json::from_str(&s)?)
}
