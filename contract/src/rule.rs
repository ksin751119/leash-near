use near_sdk::{near, AccountId};

mod u128_dec {
    use near_sdk::serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(near_sdk::serde::de::Error::custom)
    }
}

/// The wire form of a rule. Deserialising goes through `Rule::new`, so a rule that arrives
/// as JSON is always canonical.
#[near(serializers = [json])]
struct RuleInput {
    token: AccountId,
    #[serde(with = "u128_dec")]
    per_tx_limit: u128,
    #[serde(with = "u128_dec")]
    period_limit: u128,
    period_ms: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    payees: Vec<AccountId>,
    paused: bool,
}

impl From<RuleInput> for Rule {
    fn from(i: RuleInput) -> Self {
        Rule::new(i.token, i.per_tx_limit, i.period_limit, i.period_ms, i.window_start_ms, i.window_end_ms, i.payees, i.paused)
    }
}

/// A node's spending rule. No `epoch`: that lives in the stored record, so the bytes a
/// passkey signs are exactly the bytes the caller submitted.
///
/// Canonical form: `payees` is sorted and has no duplicates. Fields are private so the only
/// ways to get a `Rule` are `new` and JSON deserialisation, and both normalise.
#[near(serializers = [borsh, json])]
#[serde(from = "RuleInput")]
#[derive(Clone, PartialEq, Debug)]
pub struct Rule {
    token: AccountId,
    #[serde(with = "u128_dec")]
    per_tx_limit: u128,
    #[serde(with = "u128_dec")]
    period_limit: u128,
    period_ms: u64,
    window_start_ms: u64,
    window_end_ms: u64,
    payees: Vec<AccountId>,
    paused: bool,
}

impl Rule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: AccountId,
        per_tx_limit: u128,
        period_limit: u128,
        period_ms: u64,
        window_start_ms: u64,
        window_end_ms: u64,
        mut payees: Vec<AccountId>,
        paused: bool,
    ) -> Self {
        payees.sort();
        payees.dedup();
        Self { token, per_tx_limit, period_limit, period_ms, window_start_ms, window_end_ms, payees, paused }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    Tightening,
    Widening,
}

/// One field's answer to "does the proposed value loosen this field?".
struct Comparator {
    field: &'static str,
    loosens: fn(&Rule, &Rule) -> bool,
}

/// Every field of `Rule` must have exactly one entry here. `covered_fields` destructures
/// `Rule` without `..`, so adding a field fails to compile until that function is updated,
/// and the `every_field_has_a_comparator` test fails until the table matches the field list.
const COMPARATORS: [Comparator; 8] = [
    Comparator { field: "token", loosens: |c, p| p.token != c.token },
    Comparator { field: "per_tx_limit", loosens: |c, p| p.per_tx_limit > c.per_tx_limit },
    Comparator { field: "period_limit", loosens: |c, p| p.period_limit > c.period_limit },
    // A shorter period resets the limit more often, so more money per unit time.
    Comparator { field: "period_ms", loosens: |c, p| p.period_ms < c.period_ms },
    Comparator { field: "window_start_ms", loosens: |c, p| p.window_start_ms < c.window_start_ms },
    Comparator { field: "window_end_ms", loosens: |c, p| p.window_end_ms > c.window_end_ms },
    Comparator { field: "payees", loosens: |c, p| p.payees.iter().any(|x| !c.payees.contains(x)) },
    Comparator { field: "paused", loosens: |c, p| c.paused && !p.paused },
];

#[allow(dead_code)]
fn covered_fields(r: &Rule) {
    let Rule { token: _, per_tx_limit: _, period_limit: _, period_ms: _, window_start_ms: _, window_end_ms: _, payees: _, paused: _ } = r;
}

/// `Widening` if any field loosens. Anything else (including no change) is `Tightening`,
/// which ADMIN may apply alone.
pub fn classify(current: &Rule, proposed: &Rule) -> Change {
    if COMPARATORS.iter().any(|c| (c.loosens)(current, proposed)) {
        Change::Widening
    } else {
        Change::Tightening
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(s: &str) -> AccountId { s.parse().unwrap() }

    fn base() -> Rule {
        Rule::new(acct("usdc.testnet"), 100, 1_000, 86_400_000, 1_000, 9_000, vec![acct("a.testnet"), acct("b.testnet")], false)
    }

    impl Rule {
        fn with_token(mut self, t: &str) -> Self { self.token = acct(t); self }
        fn with_per_tx(mut self, v: u128) -> Self { self.per_tx_limit = v; self }
        fn with_period_limit(mut self, v: u128) -> Self { self.period_limit = v; self }
        fn with_period_ms(mut self, v: u64) -> Self { self.period_ms = v; self }
        fn with_window(mut self, s: u64, e: u64) -> Self { self.window_start_ms = s; self.window_end_ms = e; self }
        fn with_payees(mut self, p: &[&str]) -> Self { self.payees = p.iter().map(|s| acct(s)).collect(); self.payees.sort(); self }
        fn with_paused(mut self, p: bool) -> Self { self.paused = p; self }
    }

    #[test] fn identical_rule_is_tightening() {
        assert_eq!(classify(&base(), &base()), Change::Tightening);
    }
    #[test] fn higher_per_tx_limit_is_widening() {
        assert_eq!(classify(&base(), &base().with_per_tx(101)), Change::Widening);
    }
    #[test] fn lower_per_tx_limit_is_tightening() {
        assert_eq!(classify(&base(), &base().with_per_tx(99)), Change::Tightening);
    }
    #[test] fn higher_period_limit_is_widening() {
        assert_eq!(classify(&base(), &base().with_period_limit(1_001)), Change::Widening);
    }
    #[test] fn lower_period_limit_is_tightening() {
        assert_eq!(classify(&base(), &base().with_period_limit(999)), Change::Tightening);
    }
    #[test] fn shorter_period_is_widening() {
        assert_eq!(classify(&base(), &base().with_period_ms(86_399_999)), Change::Widening);
    }
    #[test] fn longer_period_is_tightening() {
        assert_eq!(classify(&base(), &base().with_period_ms(86_400_001)), Change::Tightening);
    }
    #[test] fn earlier_window_start_is_widening() {
        assert_eq!(classify(&base(), &base().with_window(999, 9_000)), Change::Widening);
    }
    #[test] fn later_window_end_is_widening() {
        assert_eq!(classify(&base(), &base().with_window(1_000, 9_001)), Change::Widening);
    }
    #[test] fn narrower_window_is_tightening() {
        assert_eq!(classify(&base(), &base().with_window(1_001, 8_999)), Change::Tightening);
    }
    #[test] fn adding_a_payee_is_widening() {
        assert_eq!(classify(&base(), &base().with_payees(&["a.testnet", "b.testnet", "c.testnet"])), Change::Widening);
    }
    #[test] fn swapping_a_payee_is_widening() {
        assert_eq!(classify(&base(), &base().with_payees(&["a.testnet", "c.testnet"])), Change::Widening);
    }
    #[test] fn removing_a_payee_is_tightening() {
        assert_eq!(classify(&base(), &base().with_payees(&["a.testnet"])), Change::Tightening);
    }
    #[test] fn changing_token_is_widening() {
        assert_eq!(classify(&base(), &base().with_token("other.testnet")), Change::Widening);
    }
    #[test] fn unpausing_is_widening() {
        assert_eq!(classify(&base().with_paused(true), &base().with_paused(false)), Change::Widening);
    }
    #[test] fn pausing_is_tightening() {
        assert_eq!(classify(&base().with_paused(false), &base().with_paused(true)), Change::Tightening);
    }
    #[test] fn mixed_change_is_widening() {
        // per_tx_limit down, period_limit up
        assert_eq!(classify(&base(), &base().with_per_tx(50).with_period_limit(10_000)), Change::Widening);
    }

    #[test] fn payee_order_does_not_change_equality_or_bytes() {
        let a = Rule::new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("b.testnet"), acct("a.testnet")], false);
        let b = Rule::new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("b.testnet")], false);
        assert_eq!(a, b);
        assert_eq!(near_sdk::borsh::to_vec(&a).unwrap(), near_sdk::borsh::to_vec(&b).unwrap());
    }
    #[test] fn duplicate_payees_collapse() {
        let a = Rule::new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("a.testnet")], false);
        let b = Rule::new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet")], false);
        assert_eq!(near_sdk::borsh::to_vec(&a).unwrap(), near_sdk::borsh::to_vec(&b).unwrap());
    }
    #[test] fn json_input_is_normalised_too() {
        let json = r#"{"token":"usdc.testnet","per_tx_limit":"1","period_limit":"2","period_ms":3,
            "window_start_ms":4,"window_end_ms":5,"payees":["b.testnet","a.testnet","a.testnet"],"paused":false}"#;
        let r: Rule = near_sdk::serde_json::from_str(json).unwrap();
        assert_eq!(r, Rule::new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("b.testnet")], false));
    }
    #[test] fn every_field_has_a_comparator() {
        let v = near_sdk::serde_json::to_value(base()).unwrap();
        let mut json_fields: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut table: Vec<&str> = COMPARATORS.iter().map(|c| c.field).collect();
        json_fields.sort();
        table.sort();
        assert_eq!(json_fields, table);
    }
}
