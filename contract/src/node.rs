use near_sdk::AccountId;

/// The budget node an agent belongs to: everything after the first `.` in its id.
/// `None` when the id has no separator or the remainder is not a valid account id.
pub fn node_of(agent: &AccountId) -> Option<AccountId> {
    let (_, node) = agent.as_str().split_once('.')?;
    node.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn derives_parent() {
        assert_eq!(node_of(&"pay.ops.leash.testnet".parse().unwrap()).unwrap(), "ops.leash.testnet".parse::<AccountId>().unwrap());
    }
    #[test] fn two_agents_share_one_node() {
        assert_eq!(node_of(&"pay.ops.leash.testnet".parse().unwrap()), node_of(&"subs.ops.leash.testnet".parse().unwrap()));
    }
    #[test] fn refuses_id_without_separator() {
        assert!(node_of(&"alice".parse().unwrap()).is_none());
    }
    #[test] fn refuses_remainder_that_is_not_an_account() {
        assert!(node_of(&"alice.b".parse().unwrap()).is_none());
    }
}
