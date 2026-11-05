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

impl TryFrom<RuleInput> for Rule {
    type Error = String;
    fn try_from(i: RuleInput) -> Result<Self, String> {
        Rule::try_new(i.token, i.per_tx_limit, i.period_limit, i.period_ms, i.window_start_ms, i.window_end_ms, i.payees, i.paused)
    }
}

/// A node's spending rule. No `epoch`: that lives in the stored record, so the bytes a
/// passkey signs are exactly the bytes the caller submitted.
///
/// Canonical form: `payees` is sorted and has no duplicates. Fields are private so the only
/// ways to get a `Rule` are `try_new` and JSON deserialisation, and both normalise and validate.
///
/// Meanings pinned by the project (each has a test; all fail closed):
/// - `window_start_ms > window_end_ms` is invalid and rejected. "No window restriction" is the
///   explicit sentinel `window_start_ms = 0, window_end_ms = u64::MAX`.
/// - `period_ms == 0` is invalid and rejected (the period bucket is `now_ms / period_ms`).
/// - An empty `payees` list means pay nobody, never "any payee".
/// - `per_tx_limit == 0` and `period_limit == 0` mean zero allowed, never "unlimited".
#[near(serializers = [borsh, json])]
#[serde(try_from = "RuleInput")]
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
    pub fn try_new(
        token: AccountId,
        per_tx_limit: u128,
        period_limit: u128,
        period_ms: u64,
        window_start_ms: u64,
        window_end_ms: u64,
        mut payees: Vec<AccountId>,
        paused: bool,
    ) -> Result<Self, String> {
        if period_ms == 0 {
            return Err("period_ms must be greater than zero".into());
        }
        if window_start_ms > window_end_ms {
            return Err("window_start_ms must not be after window_end_ms".into());
        }
        payees.sort();
        payees.dedup();
        Ok(Self { token, per_tx_limit, period_limit, period_ms, window_start_ms, window_end_ms, payees, paused })
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
        Rule::try_new(acct("usdc.testnet"), 100, 1_000, 86_400_000, 1_000, 9_000, vec![acct("a.testnet"), acct("b.testnet")], false).unwrap()
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
    #[test] fn mixed_change_is_widening() {
        // per_tx_limit down, period_limit up
        assert_eq!(classify(&base(), &base().with_per_tx(50).with_period_limit(10_000)), Change::Widening);
    }

    #[test] fn payee_order_does_not_change_equality_or_bytes() {
        let a = Rule::try_new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("b.testnet"), acct("a.testnet")], false).unwrap();
        let b = Rule::try_new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("b.testnet")], false).unwrap();
        assert_eq!(a, b);
        assert_eq!(near_sdk::borsh::to_vec(&a).unwrap(), near_sdk::borsh::to_vec(&b).unwrap());
    }
    #[test] fn duplicate_payees_collapse() {
        let a = Rule::try_new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("a.testnet")], false).unwrap();
        let b = Rule::try_new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet")], false).unwrap();
        assert_eq!(near_sdk::borsh::to_vec(&a).unwrap(), near_sdk::borsh::to_vec(&b).unwrap());
    }
    #[test] fn json_input_is_normalised_too() {
        let json = r#"{"token":"usdc.testnet","per_tx_limit":"1","period_limit":"2","period_ms":3,
            "window_start_ms":4,"window_end_ms":5,"payees":["b.testnet","a.testnet","a.testnet"],"paused":false}"#;
        let r: Rule = near_sdk::serde_json::from_str(json).unwrap();
        assert_eq!(r, Rule::try_new(acct("usdc.testnet"), 1, 2, 3, 4, 5, vec![acct("a.testnet"), acct("b.testnet")], false).unwrap());
    }
    #[test] fn every_field_has_a_comparator() {
        let v = near_sdk::serde_json::to_value(base()).unwrap();
        let mut json_fields: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut table: Vec<&str> = COMPARATORS.iter().map(|c| c.field).collect();
        json_fields.sort();
        table.sort();
        assert_eq!(json_fields, table);
    }

    #[test] fn removing_a_payee_is_tightening() {
        assert_eq!(classify(&base(), &base().with_payees(&["a.testnet"])), Change::Tightening);
    }
    #[test] fn shorter_period_is_widening() {
        assert_eq!(classify(&base(), &base().with_period_ms(86_399_999)), Change::Widening);
    }

    // Pinned meanings (see the doc comment on `Rule`).
    #[test] fn empty_payees_means_pay_nobody() {
        // Emptying the list tightens; filling an empty list widens. An empty list is never "any payee".
        assert_eq!(classify(&base(), &base().with_payees(&[])), Change::Tightening);
        assert_eq!(classify(&base().with_payees(&[]), &base()), Change::Widening);
    }
    #[test] fn zero_limits_mean_zero_allowed_not_unlimited() {
        assert_eq!(classify(&base(), &base().with_per_tx(0).with_period_limit(0)), Change::Tightening);
        assert_eq!(classify(&base().with_per_tx(0), &base()), Change::Widening);
        assert_eq!(classify(&base().with_period_limit(0), &base()), Change::Widening);
    }

    fn try_with(period_ms: u64, start: u64, end: u64) -> Result<Rule, String> {
        Rule::try_new(acct("usdc.testnet"), 1, 2, period_ms, start, end, vec![], false)
    }
    #[test] fn zero_period_is_rejected() {
        assert!(try_with(0, 0, 10).is_err());
    }
    #[test] fn inverted_window_is_rejected() {
        assert!(try_with(1, 9_500, 500).is_err());
        assert!(try_with(1, 1, 0).is_err());
    }
    #[test] fn degenerate_but_ordered_windows_are_accepted() {
        assert!(try_with(1, 5, 5).is_ok());
        assert!(try_with(1, 0, u64::MAX).is_ok()); // the "no restriction" sentinel
    }
    #[test] fn json_cannot_build_an_invalid_rule() {
        let mk = |period: u64, start: u64, end: u64| format!(
            r#"{{"token":"usdc.testnet","per_tx_limit":"1","period_limit":"2","period_ms":{period},
            "window_start_ms":{start},"window_end_ms":{end},"payees":[],"paused":false}}"#);
        assert!(near_sdk::serde_json::from_str::<Rule>(&mk(0, 0, 10)).is_err());
        assert!(near_sdk::serde_json::from_str::<Rule>(&mk(1, 9_500, 500)).is_err());
        assert!(near_sdk::serde_json::from_str::<Rule>(&mk(1, 0, 10)).is_ok());
    }

    // Exhaustive guard: every comparator must react to its own field and to no other.
    // Returns (current, proposed) where only `field` loosens, or None if the field has no
    // tightened direction.
    fn loosened(field: &str) -> (Rule, Rule) {
        let b = base();
        match field {
            "token" => (b.clone(), b.with_token("other.testnet")),
            "per_tx_limit" => (b.clone(), b.with_per_tx(101)),
            "period_limit" => (b.clone(), b.with_period_limit(1_001)),
            "period_ms" => (b.clone(), b.with_period_ms(86_399_999)),
            "window_start_ms" => (b.clone(), b.with_window(999, 9_000)),
            "window_end_ms" => (b.clone(), b.with_window(1_000, 9_001)),
            "payees" => (b.clone(), b.with_payees(&["a.testnet", "b.testnet", "c.testnet"])),
            "paused" => (b.clone().with_paused(true), b),
            other => panic!("no loosening case for field {other}: add one"),
        }
    }
    fn tightened(field: &str) -> Option<(Rule, Rule)> {
        let b = base();
        Some(match field {
            "token" => return None, // any token change is a loosening
            "per_tx_limit" => (b.clone(), b.with_per_tx(99)),
            "period_limit" => (b.clone(), b.with_period_limit(999)),
            "period_ms" => (b.clone(), b.with_period_ms(86_400_001)),
            "window_start_ms" => (b.clone(), b.with_window(1_001, 9_000)),
            "window_end_ms" => (b.clone(), b.with_window(1_000, 8_999)),
            "payees" => (b.clone(), b.with_payees(&["a.testnet"])),
            "paused" => (b.clone(), b.with_paused(true)),
            other => panic!("no tightening case for field {other}: add one"),
        })
    }
    fn fired(table: &[Comparator], c: &Rule, p: &Rule) -> Vec<&'static str> {
        table.iter().filter(|x| (x.loosens)(c, p)).map(|x| x.field).collect()
    }
    fn check_table(table: &[Comparator]) -> Result<(), String> {
        for entry in table {
            let (c, p) = loosened(entry.field);
            let got = fired(table, &c, &p);
            if got != vec![entry.field] {
                return Err(format!("loosening only {} fired {:?}", entry.field, got));
            }
            if let Some((c, p)) = tightened(entry.field) {
                let got = fired(table, &c, &p);
                if !got.is_empty() {
                    return Err(format!("tightening {} fired {:?}", entry.field, got));
                }
            }
        }
        Ok(())
    }
    #[test] fn each_comparator_fires_for_its_own_field_only() {
        check_table(&COMPARATORS).unwrap();
    }
    #[test] fn guard_catches_a_flipped_comparator() {
        let flipped = Comparator { field: "per_tx_limit", loosens: |c, p| p.per_tx_limit < c.per_tx_limit };
        let table: Vec<Comparator> = COMPARATORS.iter()
            .map(|c| if c.field == "per_tx_limit" { Comparator { field: flipped.field, loosens: flipped.loosens } } else { Comparator { field: c.field, loosens: c.loosens } })
            .collect();
        assert!(check_table(&table).is_err());
    }
    #[test] fn guard_catches_a_comparator_that_never_fires() {
        let table: Vec<Comparator> = COMPARATORS.iter()
            .map(|c| if c.field == "paused" { Comparator { field: "paused", loosens: |_, _| false } } else { Comparator { field: c.field, loosens: c.loosens } })
            .collect();
        assert!(check_table(&table).is_err());
    }
    #[test] fn u128_max_boundary() {
        let hi = base().with_per_tx(u128::MAX).with_period_limit(u128::MAX);
        let lo = base().with_per_tx(u128::MAX - 1).with_period_limit(u128::MAX - 1);
        assert_eq!(classify(&lo, &hi), Change::Widening);
        assert_eq!(classify(&hi, &lo), Change::Tightening);
        assert_eq!(classify(&hi, &hi), Change::Tightening);
    }
}
