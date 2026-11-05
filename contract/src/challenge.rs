//! The bytes a passkey signs to authorise a loosening.
//!
//! # Why the challenge is not just the rule
//!
//! The design doc originally said `sha256(borsh(rule) ‖ nonce)`. That is not enough. A
//! challenge over the rule and a nonce alone would make one signature reusable in two places
//! it was never meant for:
//!
//! - **Across nodes.** Two nodes carrying identical rules would produce identical challenge
//!   bytes, so an assertion signed to widen the engineering budget would also widen the
//!   operations budget.
//! - **Across deployments.** The same contract deployed twice — testnet and mainnet, or a
//!   redeploy under a new account — would accept each other's signatures.
//!
//! So the challenge binds four things: the **action**, the **payload** (which carries the
//! node and the rule), the credential's **nonce**, and the **contract's own account id**.
//!
//! # Byte layout
//!
//! ```text
//! challenge = SHA-256(
//!       u32le(action.len())      //  4 bytes
//!     ‖ action                   //  action.len() bytes, ASCII
//!     ‖ u32le(payload.len())     //  4 bytes
//!     ‖ payload                  //  payload.len() bytes
//!     ‖ u64le(nonce)             //  8 bytes
//!     ‖ u32le(contract_id.len()) //  4 bytes
//!     ‖ contract_id              //  contract_id.len() bytes, UTF-8
//! )
//! ```
//!
//! Every variable-length part is length-prefixed, so the concatenation is injective: no two
//! different inputs can produce the same byte string. (Dropping the lengths would not be
//! safe — `"ab" ‖ "c"` and `"a" ‖ "bc"` are the same bytes.)
//!
//! For a rule change, `action` is [`ACTION_SET_RULE`] and `payload` is:
//!
//! ```text
//! payload = u32le(node.len()) ‖ node ‖ borsh(rule)
//! ```
//!
//! where `borsh(rule)` is the Borsh encoding of the **normalised** [`Rule`] — the value the
//! contract parsed from JSON through `Rule::try_new` and re-serialised itself, never bytes
//! the caller supplied. That matters: `Rule`'s derived `BorshDeserialize` does not re-sort
//! or dedupe `payees`, so two different byte strings can describe the same rule. Hashing
//! only what the contract produced removes the question.
//!
//! The `u32le(len) ‖ utf8` shape used for `node` and `contract_id` is exactly how Borsh
//! encodes an `AccountId`, so an implementation that has a Borsh library can use it directly.
//!
//! `Rule`'s own Borsh encoding, field by field, for a client that must build it by hand:
//!
//! ```text
//! token:           u32le(len) ‖ utf8
//! per_tx_limit:    16 bytes, little-endian u128
//! period_limit:    16 bytes, little-endian u128
//! period_ms:        8 bytes, little-endian u64
//! window_start_ms:  8 bytes, little-endian u64
//! window_end_ms:    8 bytes, little-endian u64
//! payees:           4 bytes, little-endian u32 count, then each as u32le(len) ‖ utf8,
//!                   SORTED BYTEWISE AND DEDUPED
//! paused:           1 byte, 0 or 1
//! ```
//!
//! # For the demo page
//!
//! Do not reimplement any of the above unless you want to. `challenge_for(node, rule,
//! credential_id)` is a view method that returns these exact 32 bytes, base64-encoded, with
//! the nonce read from state. `tools/capture-assertion.html` and the demo page both call it,
//! and `challenge_for_matches_the_documented_layout` in the sandbox tests checks it against
//! an independent implementation of this layout, so the two cannot drift apart silently.
//!
//! # One action for both gated methods
//!
//! `add_payee` signs under [`ACTION_SET_RULE`] as well, over the rule that results from
//! adding the payee. So an assertion signed for `set_rule(node, R)` would also authorise an
//! `add_payee` that produces exactly `R`, and vice versa. That is deliberate: the two reach
//! the same state, and the nonce is consumed either way, so there is nothing to gain. One
//! layout is one thing for the client to get right.

use crate::rule::Rule;
use near_sdk::AccountId;
use sha2::{Digest, Sha256};

/// The action tag for a rule change. Versioned, so a future layout change cannot be
/// mistaken for this one by a client that was not updated.
pub const ACTION_SET_RULE: &str = "leash:set_rule:v1";

/// `u32le(len) ‖ bytes`.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    // A rule's Borsh encoding and an account id are both far below 4 GiB, so the cast
    // cannot truncate. `expect` rather than `as` would be noise; the bound is structural.
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The payload a rule change commits to: the node, then the normalised rule's Borsh bytes.
///
/// `rule` must be a value the contract itself normalised (via `Rule::try_new` or JSON
/// deserialisation, which routes through it). This function cannot check that — which is why
/// nothing in the contract passes it caller-supplied bytes.
pub fn set_rule_payload(node: &AccountId, rule: &Rule) -> Vec<u8> {
    let rule_bytes = near_sdk::borsh::to_vec(rule).expect("a Rule always Borsh-serialises");
    let mut payload = Vec::with_capacity(4 + node.len() + rule_bytes.len());
    push_len_prefixed(&mut payload, node.as_bytes());
    // Not length-prefixed: Borsh is self-delimiting and this is the last field, so the
    // concatenation stays injective without one.
    payload.extend_from_slice(&rule_bytes);
    payload
}

/// The 32 bytes a registered credential must sign. See the module doc comment for the layout.
pub fn gate_challenge(
    action: &str,
    payload: &[u8],
    nonce: u64,
    contract_id: &AccountId,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(20 + action.len() + payload.len() + contract_id.len());
    push_len_prefixed(&mut m, action.as_bytes());
    push_len_prefixed(&mut m, payload);
    m.extend_from_slice(&nonce.to_le_bytes());
    push_len_prefixed(&mut m, contract_id.as_bytes());
    Sha256::digest(&m).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn rule(token: &str, per_tx: u128, payees: &[&str]) -> Rule {
        Rule::try_new(
            acct(token),
            per_tx,
            10_000,
            86_400_000,
            0,
            u64::MAX,
            payees.iter().map(|p| acct(p)).collect(),
            false,
        )
        .unwrap()
    }

    fn challenge(node: &str, r: &Rule, nonce: u64, contract: &str) -> [u8; 32] {
        gate_challenge(
            ACTION_SET_RULE,
            &set_rule_payload(&acct(node), r),
            nonce,
            &acct(contract),
        )
    }

    const C: &str = "leash.testnet";

    /// The reason the spec's `sha256(borsh(rule) ‖ nonce)` was not enough: two nodes can
    /// carry byte-identical rules, and one admin signature must not widen both.
    #[test]
    fn two_nodes_with_the_same_rule_get_different_challenges() {
        let r = rule("usdc.testnet", 1_000, &["alice.testnet"]);
        assert_ne!(
            challenge("ops.leash.testnet", &r, 0, C),
            challenge("eng.leash.testnet", &r, 0, C)
        );
    }

    /// A signature from the testnet deployment must not widen the mainnet one.
    #[test]
    fn two_deployments_get_different_challenges() {
        let r = rule("usdc.testnet", 1_000, &["alice.testnet"]);
        assert_ne!(
            challenge("ops.leash.testnet", &r, 0, "leash.testnet"),
            challenge("ops.leash.testnet", &r, 0, "leash.near")
        );
    }

    /// The replay guard: the same rule at the next nonce is a different challenge.
    #[test]
    fn the_nonce_changes_the_challenge() {
        let r = rule("usdc.testnet", 1_000, &["alice.testnet"]);
        assert_ne!(
            challenge("ops.leash.testnet", &r, 0, C),
            challenge("ops.leash.testnet", &r, 1, C)
        );
    }

    #[test]
    fn a_different_rule_gets_a_different_challenge() {
        let a = rule("usdc.testnet", 1_000, &["alice.testnet"]);
        let b = rule("usdc.testnet", 1_001, &["alice.testnet"]);
        assert_ne!(challenge("ops.leash.testnet", &a, 0, C), challenge("ops.leash.testnet", &b, 0, C));
    }

    /// Normalisation happens before hashing, so payee order and duplicates cannot produce
    /// two challenges for one rule — which is what makes "re-apply the same rule" free
    /// rather than a coin flip.
    #[test]
    fn payee_order_and_duplicates_do_not_change_the_challenge() {
        let a = rule("usdc.testnet", 1_000, &["b.testnet", "a.testnet"]);
        let b = rule("usdc.testnet", 1_000, &["a.testnet", "b.testnet", "a.testnet"]);
        assert_eq!(challenge("ops.leash.testnet", &a, 0, C), challenge("ops.leash.testnet", &b, 0, C));
    }

    /// Length prefixes exist so no two different inputs can share a byte string. Without the
    /// prefix on the action, a node id could absorb the tail of the action tag.
    #[test]
    fn the_layout_is_injective_across_the_action_boundary() {
        let r = rule("usdc.testnet", 1_000, &[]);
        let p = set_rule_payload(&acct("ops.leash.testnet"), &r);
        assert_ne!(
            gate_challenge("leash:set_rule:v", &p, 0, &acct(C)),
            gate_challenge("leash:set_rule:v1", &p, 0, &acct(C))
        );
    }

    /// Pins the layout against an independent, hand-written encoding. If someone reorders
    /// the fields in `gate_challenge`, this fails — the sandbox test
    /// `challenge_for_matches_the_documented_layout` is the same check through the deployed
    /// contract.
    #[test]
    fn the_layout_matches_the_doc_comment() {
        let node = acct("ops.leash.testnet");
        let contract = acct(C);
        let r = rule("usdc.testnet", 1_000, &["alice.testnet"]);
        let nonce = 7u64;

        let mut payload = Vec::new();
        payload.extend_from_slice(&(node.as_str().len() as u32).to_le_bytes());
        payload.extend_from_slice(node.as_bytes());
        payload.extend_from_slice(&near_sdk::borsh::to_vec(&r).unwrap());

        let mut m = Vec::new();
        m.extend_from_slice(&(ACTION_SET_RULE.len() as u32).to_le_bytes());
        m.extend_from_slice(ACTION_SET_RULE.as_bytes());
        m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        m.extend_from_slice(&payload);
        m.extend_from_slice(&nonce.to_le_bytes());
        m.extend_from_slice(&(contract.as_str().len() as u32).to_le_bytes());
        m.extend_from_slice(contract.as_bytes());
        let expected: [u8; 32] = Sha256::digest(&m).into();

        assert_eq!(gate_challenge(ACTION_SET_RULE, &payload, nonce, &contract), expected);
    }

    /// And the documented `Rule` field order, so a client building the Borsh by hand has
    /// something to fail against.
    #[test]
    fn the_rule_borsh_layout_matches_the_doc_comment() {
        let r = rule("usdc.testnet", 1_000, &["b.testnet", "a.testnet"]);
        let mut want = Vec::new();
        want.extend_from_slice(&12u32.to_le_bytes()); // "usdc.testnet"
        want.extend_from_slice(b"usdc.testnet");
        want.extend_from_slice(&1_000u128.to_le_bytes());
        want.extend_from_slice(&10_000u128.to_le_bytes());
        want.extend_from_slice(&86_400_000u64.to_le_bytes());
        want.extend_from_slice(&0u64.to_le_bytes());
        want.extend_from_slice(&u64::MAX.to_le_bytes());
        want.extend_from_slice(&2u32.to_le_bytes()); // payee count, sorted
        want.extend_from_slice(&9u32.to_le_bytes());
        want.extend_from_slice(b"a.testnet");
        want.extend_from_slice(&9u32.to_le_bytes());
        want.extend_from_slice(b"b.testnet");
        want.push(0); // paused
        assert_eq!(near_sdk::borsh::to_vec(&r).unwrap(), want);
    }
}
