//! The seven checks, as a table.
//!
//! `spend` itself lives in the audited `#[near] impl` block in `lib.rs`, because that block is
//! the contract's exported surface and the one place every state-writing method is listed
//! against its guard. What lives here is the part that decides: a pure function from a rule
//! and one attempt to either "allowed" or a refusal code, with no `env`, no state and no
//! promises in it, so every one of the seven answers can be pinned by a unit test that needs
//! no sandbox.
//!
//! # Why a table rather than a chain of `if`s
//!
//! The same reason `rule::COMPARATORS` is a table: the order of the checks is part of the
//! product. An attempt that breaks three rules at once is refused with the *lowest* code, so
//! the reason the demo shows for a given attempt is fixed rather than incidental. Written as
//! a list, the order is data that a test can read; written as control flow, it is a property
//! of how someone happened to nest the branches.

use crate::decision::code;
use crate::rule::Rule;
use near_sdk::AccountId;

/// One payment attempt, as the checks see it. Gathered by `spend` before any check runs, so
/// nothing in this module reads the clock, the caller or storage.
pub struct Attempt<'a> {
    /// The token the caller named. Required in the call precisely so that check 3 exists: a
    /// contract that assumed its own `token` could never refuse the wrong one.
    pub token: &'a AccountId,
    pub payee: &'a AccountId,
    pub amount: u128,
    /// What the node has already spent in the window containing `now_ms`, with any window
    /// roll already applied. See `State::spent_in_period`.
    pub spent: u128,
    pub now_ms: u64,
    /// The account-wide pause. Refusal code 2 is this **or** the node's own `paused` flag.
    pub account_paused: bool,
}

/// One check: the code it refuses with, and the question it asks.
struct Check {
    code: u8,
    /// True when this check refuses the attempt.
    refuses: fn(&Rule, &Attempt) -> bool,
}

/// Checks 2 to 7, in the spec's order. Code 1 is not here: it fires when there is no rule at
/// all, and every check in this table needs one to read.
const CHECKS: [Check; 6] = [
    // Account-wide or node-level. Either one is a brake, and a brake that only half works is
    // not a brake.
    Check { code: code::PAUSED, refuses: |r, a| a.account_paused || r.paused() },
    Check { code: code::WRONG_TOKEN, refuses: |r, a| a.token != r.token() },
    // An empty allow-list means pay nobody, never "pay anybody" — `contains` on an empty
    // slice is false, which is the whole of it.
    Check { code: code::PAYEE_NOT_ALLOWED, refuses: |r, a| !r.payees().contains(a.payee) },
    // `>`, not `>=`: a payment of exactly the limit is allowed. A zero limit therefore allows
    // nothing, which is the documented meaning of zero.
    Check { code: code::OVER_PER_TX_LIMIT, refuses: |r, a| a.amount > r.per_tx_limit() },
    // Overflow counts as over the limit. `checked_add` rather than `saturating_add` because
    // saturation here would compare `u128::MAX > period_limit`, which is the right answer for
    // every limit except `u128::MAX` itself — a rule that could then be spent twice over.
    Check {
        code: code::OVER_PERIOD_LIMIT,
        refuses: |r, a| match a.spent.checked_add(a.amount) {
            Some(total) => total > r.period_limit(),
            None => true,
        },
    },
    // Inclusive at both ends, so the "no restriction" sentinel `0 ..= u64::MAX` really does
    // restrict nothing.
    Check {
        code: code::OUTSIDE_WINDOW,
        refuses: |r, a| a.now_ms < r.window_start_ms() || a.now_ms > r.window_end_ms(),
    },
];

/// Run the checks against `rule` in the spec's order. `Ok(())` means the payment is allowed;
/// `Err(code)` is the first check that refused it.
///
/// `rule` is `None` both when the caller's id does not derive to a node and when the derived
/// node has no rule stored. The two are one refusal — code 1 — on purpose: from the chain's
/// side they are the same fact, that this caller has no budget.
pub fn evaluate(rule: Option<&Rule>, attempt: &Attempt) -> Result<(), u8> {
    let Some(rule) = rule else {
        return Err(code::NO_RULE);
    };
    match CHECKS.iter().find(|c| (c.refuses)(rule, attempt)) {
        Some(c) => Err(c.code),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::REFUSALS;

    fn acct(s: &str) -> AccountId {
        s.parse().expect("valid account id")
    }

    const DAY: u64 = 86_400_000;
    const NOW: u64 = 1_700_000_000_000;

    /// A rule that allows the attempt built by [`ok`]: one payee, 1_000 a transfer, 10_000 a
    /// day, no window restriction, not paused.
    fn rule() -> Rule {
        Rule::try_new(
            acct("usdc.testnet"),
            1_000,
            10_000,
            DAY,
            0,
            u64::MAX,
            vec![acct("alice.testnet")],
            false,
        )
        .expect("a valid rule")
    }

    /// An attempt the rule above allows. Each test breaks exactly one thing about it.
    fn ok<'a>(token: &'a AccountId, payee: &'a AccountId) -> Attempt<'a> {
        Attempt { token, payee, amount: 100, spent: 0, now_ms: NOW, account_paused: false }
    }

    #[test]
    fn an_attempt_within_the_rule_is_allowed() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        assert_eq!(evaluate(Some(&rule()), &ok(&t, &p)), Ok(()));
    }

    #[test]
    fn no_rule_is_code_one() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        assert_eq!(evaluate(None, &ok(&t, &p)), Err(1));
    }

    #[test]
    fn a_paused_account_is_code_two() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let mut a = ok(&t, &p);
        a.account_paused = true;
        assert_eq!(evaluate(Some(&rule()), &a), Err(2));
    }

    /// The other half of code 2: the account is running, this node is not.
    #[test]
    fn a_paused_node_is_also_code_two() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let mut r = rule();
        r = Rule::try_new(
            r.token().clone(),
            r.per_tx_limit(),
            r.period_limit(),
            r.period_ms(),
            r.window_start_ms(),
            r.window_end_ms(),
            r.payees().to_vec(),
            true,
        )
        .unwrap();
        assert_eq!(evaluate(Some(&r), &ok(&t, &p)), Err(2));
    }

    #[test]
    fn another_token_is_code_three() {
        let (t, p) = (acct("dai.testnet"), acct("alice.testnet"));
        assert_eq!(evaluate(Some(&rule()), &ok(&t, &p)), Err(3));
    }

    #[test]
    fn a_payee_not_on_the_list_is_code_four() {
        let (t, p) = (acct("usdc.testnet"), acct("mallory.testnet"));
        assert_eq!(evaluate(Some(&rule()), &ok(&t, &p)), Err(4));
    }

    #[test]
    fn an_empty_payee_list_pays_nobody() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let r = Rule::try_new(acct("usdc.testnet"), 1_000, 10_000, DAY, 0, u64::MAX, vec![], false)
            .unwrap();
        assert_eq!(evaluate(Some(&r), &ok(&t, &p)), Err(4));
    }

    #[test]
    fn over_the_per_tx_limit_is_code_five() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let mut a = ok(&t, &p);
        a.amount = 1_001;
        assert_eq!(evaluate(Some(&rule()), &a), Err(5));
        // Exactly the limit is allowed.
        a.amount = 1_000;
        assert_eq!(evaluate(Some(&rule()), &a), Ok(()));
    }

    #[test]
    fn a_zero_per_tx_limit_allows_nothing() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let r =
            Rule::try_new(acct("usdc.testnet"), 0, 10_000, DAY, 0, u64::MAX, vec![p.clone()], false)
                .unwrap();
        let mut a = ok(&t, &p);
        a.amount = 1;
        assert_eq!(evaluate(Some(&r), &a), Err(5));
    }

    #[test]
    fn over_the_period_limit_is_code_six() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let mut a = ok(&t, &p);
        // Under the per-tx limit, but the window has no room left for it.
        a.spent = 9_950;
        a.amount = 100;
        assert_eq!(evaluate(Some(&rule()), &a), Err(6));
        // Exactly filling the period is allowed.
        a.amount = 50;
        assert_eq!(evaluate(Some(&rule()), &a), Ok(()));
    }

    /// `spent + amount` overflowing must read as over the limit, not wrap into room.
    #[test]
    fn an_overflowing_total_is_code_six() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let r = Rule::try_new(
            acct("usdc.testnet"),
            u128::MAX,
            u128::MAX,
            DAY,
            0,
            u64::MAX,
            vec![p.clone()],
            false,
        )
        .unwrap();
        let mut a = ok(&t, &p);
        a.spent = 1;
        a.amount = u128::MAX;
        assert_eq!(evaluate(Some(&r), &a), Err(6));
    }

    #[test]
    fn before_the_window_is_code_seven() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let r = Rule::try_new(
            acct("usdc.testnet"),
            1_000,
            10_000,
            DAY,
            NOW + 1,
            u64::MAX,
            vec![p.clone()],
            false,
        )
        .unwrap();
        assert_eq!(evaluate(Some(&r), &ok(&t, &p)), Err(7));
    }

    #[test]
    fn after_the_window_is_code_seven() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        let r =
            Rule::try_new(acct("usdc.testnet"), 1_000, 10_000, DAY, 0, NOW - 1, vec![p.clone()], false)
                .unwrap();
        assert_eq!(evaluate(Some(&r), &ok(&t, &p)), Err(7));
    }

    /// Both ends of the window are inclusive, which is what makes `0 ..= u64::MAX` mean "no
    /// restriction" rather than "almost none".
    #[test]
    fn the_window_includes_both_of_its_ends() {
        let (t, p) = (acct("usdc.testnet"), acct("alice.testnet"));
        for (start, end) in [(NOW, u64::MAX), (0, NOW), (NOW, NOW)] {
            let r = Rule::try_new(
                acct("usdc.testnet"),
                1_000,
                10_000,
                DAY,
                start,
                end,
                vec![p.clone()],
                false,
            )
            .unwrap();
            assert_eq!(evaluate(Some(&r), &ok(&t, &p)), Ok(()), "window {start}..={end}");
        }
    }

    /// The order of the table is part of the product: an attempt that breaks everything is
    /// refused with the lowest code, every time, so a demo recording is reproducible.
    #[test]
    fn the_first_failing_check_wins() {
        let (t, p) = (acct("dai.testnet"), acct("mallory.testnet"));
        let r = Rule::try_new(acct("usdc.testnet"), 0, 0, DAY, NOW + 1, u64::MAX, vec![], true)
            .unwrap();
        let mut a = ok(&t, &p);
        a.amount = u128::MAX;
        a.spent = 1;
        a.account_paused = true;
        // Paused is code 2, and everything from 3 to 7 is also broken.
        assert_eq!(evaluate(Some(&r), &a), Err(2));

        // With no rule at all, code 1 outranks even that.
        assert_eq!(evaluate(None, &a), Err(1));
    }

    /// Every code this module can return has a reason in `decision::REFUSALS`, and every row
    /// there is reachable from here. A code with no sentence, or a sentence with no code,
    /// means the UI would show something this contract cannot produce.
    #[test]
    fn the_table_and_the_reasons_agree() {
        let mut from_checks: Vec<u8> = CHECKS.iter().map(|c| c.code).collect();
        from_checks.push(code::NO_RULE);
        from_checks.sort_unstable();
        let from_reasons: Vec<u8> = REFUSALS.iter().map(|r| r.code).collect();
        assert_eq!(from_checks, from_reasons);
    }

    /// The checks run in the order the reason table lists them, so "the first failing check
    /// wins" and "the lowest code wins" are the same sentence.
    #[test]
    fn the_checks_are_in_the_reason_tables_order() {
        let checks: Vec<u8> = CHECKS.iter().map(|c| c.code).collect();
        let reasons: Vec<u8> = REFUSALS.iter().skip(1).map(|r| r.code).collect();
        assert_eq!(checks, reasons);
    }
}
