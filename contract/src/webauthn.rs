//! On-chain verification of a WebAuthn (passkey) assertion.
//!
//! # What this proves, exactly
//!
//! A passing verification establishes two things and no more:
//!
//! 1. the holder of a registered credential signed **this exact challenge**, and
//! 2. the authenticator asserted **user verification** — the UV bit — at the moment of
//!    signing.
//!
//! It **cannot** establish that the credential is hardware-backed rather than a software
//! P-256 key. WebAuthn attestation is absent for synced passkeys — iCloud Keychain and
//! Google Password Manager attest `none` — so nothing reaches this contract that could tell
//! a secure enclave from a key minted in a script. Nothing in this module distinguishes
//! them, and nothing here could.
//!
//! **The guarantee is therefore only as strong as the registration step: whoever registers a
//! credential vouches that it is a real authenticator.** Given a credential that genuinely is
//! one, a passing verification means a human was present at that device and unlocked it with
//! a biometric or the device PIN — and even then not a *unique* human, because anyone
//! enrolled on that device satisfies it exactly as well as the owner does.
//!
//! Those caveats travel together. "A human was present at a registered device" is not a claim
//! this code supports on its own, and must never be written without the registration caveat
//! beside it. "A unique human" is never true here at all.
//!
//! Why it runs on chain: tightening a spending rule is free and immediate, loosening one
//! requires a signature from a registered credential. The contract itself checks that
//! signature, so there is no server, no oracle and no bridge in the trust path — the trust
//! that remains sits entirely at registration.
//!
//! What this module deliberately does not check:
//! - **`origin`** and the rpIdHash in `authenticatorData[0..32]`. An authenticator will only
//!   ever sign with a credential under the relying party that credential was created for, and
//!   the public key we verify against is stored per credential, so the relying party is
//!   already pinned by the key itself. Checking `origin` on chain would buy nothing and would
//!   hard-code a domain into frozen contract code.
//! - **the signature counter** in `authenticatorData[33..37]`. Platform authenticators that
//!   sync passkeys across devices (iCloud Keychain, Google Password Manager) leave it at
//!   zero, so a monotonicity check would reject the common case. Replay is stopped by the
//!   challenge, which binds an assertion to one rule and one nonce.

use near_sdk::base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use near_sdk::json_types::Base64VecU8;
use near_sdk::near;
use near_sdk::serde::Deserialize;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// `authenticatorData` is at minimum 32 bytes of rpIdHash, one flag byte and a 4-byte
/// signature counter. An assertion carries no attested credential data, so 37 bytes is the
/// normal length as well as the minimum.
const AUTH_DATA_MIN_LEN: usize = 37;

/// Offset of the flag byte. Reading it needs `AUTH_DATA_MIN_LEN` checked first.
const FLAGS_OFFSET: usize = 32;

/// "User verified": a biometric or the device PIN was checked. Not to be confused with
/// `0x01` (UP, user present — a mere touch) or `0x40` (AT, attested credential data follows).
const FLAG_UV: u8 = 0x04;

/// Why an assertion was not accepted. Every variant is a rejection, never a panic: a caller
/// submitting rubbish should get a clean failure, not an exhausted-gas receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The UV bit in `authenticatorData[32]` is clear. The device was touched but nobody
    /// proved they could unlock it.
    UserNotVerified,
    /// The challenge inside `clientDataJSON` is not the one expected — a signature for some
    /// other rule, or for the same rule at a different nonce.
    ChallengeMismatch,
    /// `clientDataJSON`'s `type` is not `webauthn.get`, so these bytes come from a
    /// registration ceremony or something else entirely, not from an assertion.
    BadType,
    /// The signature parsed but does not verify under this credential's public key.
    BadSignature,
    /// Structurally broken input: short `authenticatorData`, `clientDataJSON` that is not
    /// JSON or has no `challenge`, a challenge that is not base64url, a signature that is not
    /// DER, or a public key that is not a SEC1 point.
    Malformed,
}

/// Byte fields as standard base64 in JSON, which is what `Base64VecU8` uses on the wire and
/// what a browser can produce from an `ArrayBuffer` in two lines.
///
/// Serialising only: `Credential` deserialises through `CredentialInput`, which uses
/// `Base64VecU8` directly.
mod b64_bytes {
    use near_sdk::json_types::Base64VecU8;
    use near_sdk::serde::{Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        Base64VecU8::from(v.to_vec()).serialize(s)
    }
}

/// The wire form of a credential, as `register_credential` takes it. Deserialising goes
/// through `Credential::try_new`, so a credential that arrives as JSON has had its public
/// key parsed before it reaches state.
///
/// `nonce` is optional and defaults to 0. Supplying one is allowed (an operator restoring a
/// credential after a migration needs it) and is safe only because re-registering an id is
/// refused outright — see `register_credential`. A reset nonce would re-arm every assertion
/// ever signed under that credential.
///
/// A supplied nonce is capped so the credential cannot be registered already exhausted: see
/// [`MAX_INITIAL_NONCE`].
#[near(serializers = [json])]
pub struct CredentialInput {
    pub id: Base64VecU8,
    pub pubkey_sec1: Base64VecU8,
    pub nonce: Option<u64>,
}

/// Highest nonce a credential may be *registered* with, leaving [`MIN_REMAINING_NONCES`]
/// signatures of headroom.
///
/// Without a cap, registering at `u64::MAX` would produce a credential that panics
/// ("credential nonce exhausted") the first time it is used — on an account whose code cannot
/// be redeployed, with a credential id that can never be registered again. ADMIN-only and a
/// typo away, so it is cheaper to refuse it at the door.
pub const MIN_REMAINING_NONCES: u64 = 1_000_000;
pub const MAX_INITIAL_NONCE: u64 = u64::MAX - MIN_REMAINING_NONCES;

impl TryFrom<CredentialInput> for Credential {
    type Error = String;
    fn try_from(i: CredentialInput) -> Result<Self, String> {
        let nonce = i.nonce.unwrap_or(0);
        if nonce > MAX_INITIAL_NONCE {
            return Err(format!(
                "nonce {nonce} leaves fewer than {MIN_REMAINING_NONCES} uses; \
                 register at most {MAX_INITIAL_NONCE}"
            ));
        }
        Credential::try_new(i.id.into(), i.pubkey_sec1.into(), nonce)
            .map_err(|e| format!("credential rejected: {e:?}"))
    }
}

/// A registered passkey. `nonce` is the credential's own replay counter: it goes into the
/// challenge the device signs, so an assertion can be spent exactly once.
///
/// Fields are private and `try_new` is the only way in, so a `Credential` that exists is one
/// whose public key parses. Rejecting a bad key at registration rather than at use matters
/// here: the whole point of the credential is to be available in an emergency.
///
/// `revoked` is why a removed credential stays in state instead of being deleted. Deleting
/// the entry would free the id for re-registration, and a re-registered id starts at nonce 0
/// — which re-arms every assertion ever signed under it. A tombstone keeps the spent nonce
/// forever, so the id is permanently unusable while the *slot* it occupied is free for a new
/// credential. See `State::revoke_credential` and `register_credential`.
#[near(serializers = [borsh, json])]
#[serde(try_from = "CredentialInput")]
#[derive(Clone, PartialEq, Debug)]
pub struct Credential {
    #[serde(serialize_with = "b64_bytes::serialize")]
    id: Vec<u8>,
    #[serde(serialize_with = "b64_bytes::serialize")]
    pubkey_sec1: Vec<u8>,
    nonce: u64,
    revoked: bool,
}

impl Credential {
    /// `pubkey_sec1` is a SEC1-encoded P-256 point, either uncompressed (65 bytes,
    /// `0x04 ‖ X ‖ Y`) or compressed (33 bytes, `0x02`/`0x03` ‖ X). Both are accepted.
    pub fn try_new(id: Vec<u8>, pubkey_sec1: Vec<u8>, nonce: u64) -> Result<Self, VerifyError> {
        VerifyingKey::from_sec1_bytes(&pubkey_sec1).map_err(|_| VerifyError::Malformed)?;
        Ok(Self {
            id,
            pubkey_sec1,
            nonce,
            revoked: false,
        })
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn pubkey_sec1(&self) -> &[u8] {
        &self.pubkey_sec1
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Whether this credential has been revoked. A revoked credential authorises nothing;
    /// the entry survives only to keep its id and spent nonce out of circulation.
    pub fn revoked(&self) -> bool {
        self.revoked
    }

    /// Mark this credential revoked. Irreversible on purpose: un-revoking would put an id
    /// whose nonce is known back into service.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Spend this credential's current nonce. Called only after an assertion has verified,
    /// so a rejected assertion never burns one.
    ///
    /// Strictly increasing and never reset: that is the whole replay guard. Note that it is
    /// keyed on the nonce and not on the signature bytes — ECDSA signatures are malleable
    /// (negate `s` and the signature still verifies), so a dedupe keyed on the signature
    /// could be walked straight around.
    pub fn spend_nonce(&mut self) {
        self.nonce = self
            .nonce
            .checked_add(1)
            .unwrap_or_else(|| near_sdk::env::panic_str("credential nonce exhausted"));
    }
}

/// The wire form of an assertion: what the browser's `navigator.credentials.get()` produced,
/// as every gated method takes it. The byte fields are base64 in JSON, which is what a
/// browser naturally sends.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct Assertion {
    pub credential_id: Base64VecU8,
    pub authenticator_data: Base64VecU8,
    pub client_data_json: String,
    pub signature_der: Base64VecU8,
}

/// The fields of `clientDataJSON` this contract reads. Unknown fields (`origin`,
/// `crossOrigin`, `topOrigin`) are ignored on purpose — browsers add to this object over
/// time and frozen contract code cannot be updated to keep up.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
}

/// Compare two byte strings without an early exit.
///
/// On a public blockchain this is close to ceremony: the transaction, the challenge and the
/// contract code are all public, and execution is deterministic, so there is no timing signal
/// worth harvesting. It costs a handful of gas and removes the question, so it is done anyway.
/// The length is allowed to leak; a challenge is always 32 bytes.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verify a WebAuthn assertion against a registered credential and an expected challenge.
///
/// `expected_challenge` is opaque here. Task 5 computes it from the rule and the credential's
/// nonce; this function only cares that the bytes the device signed are those bytes.
///
/// Checks run cheapest first, so a malformed or unverified submission does not pay for the
/// curve arithmetic. The signature check is last, which means the error returned for an
/// assertion with several problems names the first one found — that is a diagnostic detail,
/// not a security property: nothing is accepted unless every check passes.
pub fn verify_assertion(
    cred: &Credential,
    expected_challenge: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &str,
    sig_der: &[u8],
) -> Result<(), VerifyError> {
    if authenticator_data.len() < AUTH_DATA_MIN_LEN {
        return Err(VerifyError::Malformed);
    }
    if authenticator_data[FLAGS_OFFSET] & FLAG_UV == 0 {
        return Err(VerifyError::UserNotVerified);
    }

    let client: ClientData =
        near_sdk::serde_json::from_str(client_data_json).map_err(|_| VerifyError::Malformed)?;
    if client.ceremony_type != "webauthn.get" {
        return Err(VerifyError::BadType);
    }
    // WebAuthn's base64url is unpadded. A browser will never send padding here and a decoder
    // configured for the padded alphabet rejects what the browser does send.
    let challenge = URL_SAFE_NO_PAD
        .decode(client.challenge.as_bytes())
        .map_err(|_| VerifyError::Malformed)?;
    if !bytes_eq(&challenge, expected_challenge) {
        return Err(VerifyError::ChallengeMismatch);
    }

    // `from_sec1_bytes` cannot fail for a credential built through `try_new`. It is still
    // handled rather than unwrapped, because a credential can also arrive by Borsh from
    // contract state, and state outlives the code that wrote it.
    let key = VerifyingKey::from_sec1_bytes(&cred.pubkey_sec1).map_err(|_| VerifyError::Malformed)?;
    let sig = Signature::from_der(sig_der).map_err(|_| VerifyError::Malformed)?;

    // What the authenticator signed: authenticatorData ‖ SHA-256(clientDataJSON). Note that
    // it is the *raw* clientDataJSON bytes that are hashed, not a re-serialisation of the
    // parsed object — key order and whitespace are part of the signed message.
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));

    key.verify_prehash(&Sha256::digest(&signed), &sig)
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
    use near_sdk::serde_json::Value;

    const VALID: &str = include_str!("../../tests-sandbox/tests/fixtures/assertion_valid.json");
    const UV_CLEAR: &str = include_str!("../../tests-sandbox/tests/fixtures/assertion_uv_clear.json");
    const WRONG_CHALLENGE: &str =
        include_str!("../../tests-sandbox/tests/fixtures/assertion_wrong_challenge.json");

    /// One fixture, decoded. Every byte field in the file is standard base64 (what near-sdk's
    /// `Base64VecU8` uses on the wire), except `client_data_json`, which is the literal JSON
    /// string the authenticator signed over.
    ///
    /// The six fields below are the whole required schema, and they are exactly the fields
    /// `tools/capture-assertion.html` emits from a real device. Everything under `meta` is
    /// documentation and is optional, so a capture can be dropped in here as-is — the one
    /// thing Task 10's preflight depends on, done under time pressure on recording day.
    struct Fixture {
        credential_id: Vec<u8>,
        pubkey_sec1: Vec<u8>,
        challenge: [u8; 32],
        authenticator_data: Vec<u8>,
        client_data_json: String,
        signature_der: Vec<u8>,
    }

    impl Fixture {
        fn cred(&self) -> Credential {
            Credential::try_new(self.credential_id.clone(), self.pubkey_sec1.clone(), 0)
                .expect("fixture public key should parse")
        }

        /// `verify_assertion` with the fixture's own bytes.
        fn verify(&self) -> Result<(), VerifyError> {
            verify_assertion(
                &self.cred(),
                &self.challenge,
                &self.authenticator_data,
                &self.client_data_json,
                &self.signature_der,
            )
        }
    }

    /// Decode a fixture, failing with a message that names the file and the field.
    ///
    /// Required fields are required loudly; anything under `meta` is never read. A fixture
    /// that is missing a required field is a broken fixture and the test run should say which
    /// one, rather than reporting `called Option::unwrap() on a None value` from inside a
    /// closure and leaving whoever is capturing from a phone to guess.
    fn load_named(name: &str, text: &str) -> Fixture {
        let v: Value = near_sdk::serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("fixture {name} is not valid JSON: {e}"));
        let text_field = |key: &str| -> &str {
            v.get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("fixture {name} has no string field `{key}`"))
        };
        let bytes = |key: &str| -> Vec<u8> {
            STANDARD
                .decode(text_field(key))
                .unwrap_or_else(|e| panic!("fixture {name} field `{key}` is not base64: {e}"))
        };
        let raw_challenge = bytes("challenge");
        let challenge: [u8; 32] = raw_challenge.clone().try_into().unwrap_or_else(|_| {
            panic!(
                "fixture {name} field `challenge` is {} bytes, expected 32",
                raw_challenge.len()
            )
        });
        Fixture {
            credential_id: bytes("credential_id"),
            pubkey_sec1: bytes("pubkey_sec1"),
            challenge,
            authenticator_data: bytes("authenticator_data"),
            client_data_json: text_field("client_data_json").to_string(),
            signature_der: bytes("signature_der"),
        }
    }

    fn valid() -> Fixture {
        load_named("assertion_valid.json", VALID)
    }

    fn uv_clear() -> Fixture {
        load_named("assertion_uv_clear.json", UV_CLEAR)
    }

    fn wrong_challenge() -> Fixture {
        load_named("assertion_wrong_challenge.json", WRONG_CHALLENGE)
    }

    // --- the four cases the brief names ------------------------------------------------

    #[test]
    fn accepts_a_real_assertion() {
        assert!(valid().verify().is_ok());
    }

    #[test]
    fn rejects_when_uv_bit_clear() {
        assert_eq!(uv_clear().verify(), Err(VerifyError::UserNotVerified));
    }

    #[test]
    fn rejects_challenge_for_another_rule() {
        assert_eq!(
            wrong_challenge().verify(),
            Err(VerifyError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let f = valid();
        // Flip the lowest bit of `s`. The DER stays structurally valid and `s` stays well
        // inside the group order, so this reaches the curve maths and fails there rather
        // than failing to parse.
        let mut sig = f.signature_der.clone();
        *sig.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                &f.client_data_json,
                &sig
            ),
            Err(VerifyError::BadSignature)
        );
    }

    // --- the remaining VerifyError variants and the malformed inputs -------------------

    #[test]
    fn rejects_a_type_that_is_not_webauthn_get() {
        let f = valid();
        // A registration ceremony's clientDataJSON replayed as an assertion.
        let client = f.client_data_json.replace("webauthn.get", "webauthn.create");
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                &client,
                &f.signature_der
            ),
            Err(VerifyError::BadType)
        );
    }

    #[test]
    fn rejects_authenticator_data_shorter_than_37_bytes() {
        let f = valid();
        // 36 bytes: rpIdHash and nothing else worth reading. Indexing byte 32 for the UV
        // flag on this would panic, which is why the length check comes first.
        let short = f.authenticator_data[..36].to_vec();
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &short,
                &f.client_data_json,
                &f.signature_der
            ),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_client_data_that_is_not_json() {
        let f = valid();
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                "not json at all",
                &f.signature_der
            ),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_a_challenge_that_is_not_base64url() {
        let f = valid();
        // `!` is in neither base64 alphabet.
        let client = near_sdk::serde_json::json!({
            "type": "webauthn.get",
            "challenge": "!!!!",
            "origin": "https://leash.local",
        })
        .to_string();
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                &client,
                &f.signature_der
            ),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_client_data_with_no_challenge_field() {
        let f = valid();
        let client = near_sdk::serde_json::json!({
            "type": "webauthn.get",
            "origin": "https://leash.local",
        })
        .to_string();
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                &client,
                &f.signature_der
            ),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_a_signature_that_is_not_der() {
        let f = valid();
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &f.authenticator_data,
                &f.client_data_json,
                b"\x30\x00"
            ),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn a_registration_nonce_must_leave_headroom() {
        use near_sdk::json_types::Base64VecU8;
        let f = valid();
        let input = |nonce: u64| CredentialInput {
            id: Base64VecU8::from(f.credential_id.clone()),
            pubkey_sec1: Base64VecU8::from(f.pubkey_sec1.clone()),
            nonce: Some(nonce),
        };
        assert!(Credential::try_from(input(u64::MAX)).is_err());
        assert!(Credential::try_from(input(MAX_INITIAL_NONCE + 1)).is_err());
        assert!(Credential::try_from(input(MAX_INITIAL_NONCE)).is_ok());
        assert!(Credential::try_from(input(0)).is_ok());
    }

    #[test]
    fn a_fresh_credential_is_not_revoked_and_revocation_sticks() {
        let f = valid();
        let mut c = f.cred();
        assert!(!c.revoked());
        c.revoke();
        assert!(c.revoked());
        // No un-revoke exists: putting an id whose nonce is known back into service is the
        // one thing a tombstone is there to prevent.
    }

    #[test]
    fn rejects_a_public_key_that_does_not_parse() {
        // Caught at registration, not at verification: a credential that could never verify
        // anything must not reach storage.
        assert!(Credential::try_new(vec![1, 2, 3], vec![0x04; 65], 0).is_err());
        assert!(Credential::try_new(vec![1, 2, 3], vec![], 0).is_err());
    }

    /// The UV bit is `0x04`. `0x40` is AT (attested credential data) and `0x01` is UP (user
    /// present); neither means a biometric or PIN was checked. A `& 0x40` typo here would
    /// accept a touch as if it were a Face ID unlock, so pin it.
    #[test]
    fn the_at_bit_does_not_count_as_user_verification() {
        let f = valid();
        let mut auth = f.authenticator_data.clone();
        auth[32] = 0x41; // UP | AT, UV clear
        assert_eq!(
            verify_assertion(
                &f.cred(),
                &f.challenge,
                &auth,
                &f.client_data_json,
                &f.signature_der
            ),
            Err(VerifyError::UserNotVerified)
        );
    }

    /// A compressed SEC1 key is 33 bytes instead of 65 and verifies the same signature, so
    /// a credential can be stored in half the space.
    ///
    /// The compressed form is derived here from the fixture's own uncompressed key rather
    /// than read out of the fixture file. That keeps the required fixture schema down to the
    /// six fields a real capture carries, and it makes the test stronger: it proves the
    /// contract accepts the compressed encoding of the very key under test, with no help from
    /// whatever produced the fixture.
    #[test]
    fn accepts_a_compressed_public_key() {
        let f = valid();
        let compressed = VerifyingKey::from_sec1_bytes(&f.pubkey_sec1)
            .expect("fixture public key should parse")
            .to_encoded_point(true);
        let cred = Credential::try_new(
            f.credential_id.clone(),
            compressed.as_bytes().to_vec(),
            0,
        )
        .expect("a compressed SEC1 key should parse");
        assert_eq!(cred.pubkey_sec1().len(), 33);
        assert_eq!(f.pubkey_sec1.len(), 65, "the fixture carries the uncompressed form");
        assert!(verify_assertion(
            &cred,
            &f.challenge,
            &f.authenticator_data,
            &f.client_data_json,
            &f.signature_der
        )
        .is_ok());
    }
}
