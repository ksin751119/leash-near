mod node;
mod rule;
mod webauthn;

use crate::webauthn::{verify_assertion, Credential};
use near_sdk::json_types::Base64VecU8;
use near_sdk::{near, AccountId, PanicOnDefault};

/// The wallet account's contract. The account that hosts it has its full-access keys
/// deleted after deploy, so this code is fixed for good. For that reason the contract
/// deliberately has no method that deploys code or adds a key
/// (no `Promise::deploy_contract`, no `add_key`): tests-sandbox/tests/sandbox/account_is_frozen.rs pins it.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct LeashAccount {
    admin: AccountId,
    token: AccountId,
    paused: bool,
}

#[near]
impl LeashAccount {
    #[init]
    pub fn new(admin: AccountId, token: AccountId) -> Self {
        Self {
            admin,
            token,
            paused: false,
        }
    }

    pub fn get_admin(&self) -> AccountId {
        self.admin.clone()
    }

    pub fn get_token(&self) -> AccountId {
        self.token.clone()
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Verify a WebAuthn assertion and report whether it passed. Changes no state, consumes
    /// no nonce, checks no caller.
    ///
    /// It exists to measure what P-256 verification costs inside the contract, and it stays
    /// after the gated methods land as the project's gas-measurement surface: it is the one
    /// place where the cost of the curve arithmetic can be read without the rest of a
    /// transaction's cost mixed in.
    ///
    /// A `true` means the holder of this public key signed this exact challenge and the
    /// authenticator asserted user verification. It does **not** mean the key is
    /// hardware-backed: this probe takes a public key as an argument, so anyone can pass one
    /// they minted in a script and get a `true` with no device and no human involved. That is
    /// not a weakness in the verification — it is where the trust boundary actually sits. See
    /// the `webauthn` module header.
    ///
    /// Anything malformed returns `false` rather than panicking.
    pub fn probe_verify(
        &self,
        pubkey_sec1: Base64VecU8,
        challenge: Base64VecU8,
        authenticator_data: Base64VecU8,
        client_data_json: String,
        signature_der: Base64VecU8,
    ) -> bool {
        let Ok(challenge) = <[u8; 32]>::try_from(challenge.0.as_slice()) else {
            return false;
        };
        // The credential id is irrelevant to verification: the probe takes the public key
        // directly instead of looking a credential up in state.
        let Ok(cred) = Credential::try_new(Vec::new(), pubkey_sec1.into(), 0) else {
            return false;
        };
        verify_assertion(
            &cred,
            &challenge,
            authenticator_data.as_ref(),
            &client_data_json,
            signature_der.as_ref(),
        )
        .is_ok()
    }
}
