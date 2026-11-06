//! Minimal NEP-141 token for sandbox tests: transfers, balances, storage registration.
//! Not the full standard (no ft_transfer_call). `ft_metadata` (NEP-148) answers decimals and symbol,
//! which is what scripts/preflight.sh and any wallet UI ask a token for.
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, NearToken, PanicOnDefault, Promise,
};

/// Storage deposit a new account must attach to register (0.00125 NEAR, the usual NEP-141 amount).
const STORAGE_MIN: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TestToken {
    balances: LookupMap<AccountId, u128>,
    total_supply: u128,
    decimals: u8,
}

#[near(serializers = [json])]
pub struct StorageBalance {
    pub total: U128,
    pub available: U128,
}

#[near(serializers = [json])]
pub struct FungibleTokenMetadata {
    spec: String,
    name: String,
    symbol: String,
    icon: Option<String>,
    reference: Option<String>,
    reference_hash: Option<String>,
    decimals: u8,
}

#[near]
impl TestToken {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128, decimals: u8) -> Self {
        let mut balances = LookupMap::new(b"b");
        balances.insert(owner_id, total_supply.0);
        Self {
            balances,
            total_supply: total_supply.0,
            decimals,
        }
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let sender = env::predecessor_account_id();
        require!(amount.0 > 0, "amount must be positive");
        require!(sender != receiver_id, "sender and receiver must differ");
        require!(
            self.balances.contains_key(&receiver_id),
            "receiver is not registered, call storage_deposit first"
        );
        let from = *self.balances.get(&sender).unwrap_or(&0);
        require!(from >= amount.0, "not enough balance");
        let to = *self.balances.get(&receiver_id).unwrap();
        self.balances.insert(sender, from - amount.0);
        self.balances.insert(receiver_id, to + amount.0);
        if let Some(memo) = memo {
            env::log_str(&format!("memo: {memo}"));
        }
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(*self.balances.get(&account_id).unwrap_or(&0))
    }

    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_supply)
    }

    pub fn ft_decimals(&self) -> u8 {
        self.decimals
    }

    pub fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: "ft-1.0.0".to_string(),
            name: "Leash test USDC".to_string(),
            symbol: "USDC".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: self.decimals,
        }
    }

    /// Registers `account_id` (default: the caller). Refunds anything above the minimum.
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> StorageBalance {
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        let attached = env::attached_deposit();
        if self.balances.contains_key(&account_id) {
            // already registered, give the whole deposit back
            if !attached.is_zero() {
                let _ = Promise::new(env::predecessor_account_id()).transfer(attached);
            }
        } else {
            require!(attached >= STORAGE_MIN, "attach at least 0.00125 NEAR");
            self.balances.insert(account_id, 0);
            let excess = attached.saturating_sub(STORAGE_MIN);
            if !excess.is_zero() {
                let _ = Promise::new(env::predecessor_account_id()).transfer(excess);
            }
        }
        StorageBalance {
            total: U128(STORAGE_MIN.as_yoctonear()),
            available: U128(0),
        }
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.balances.contains_key(&account_id).then(|| StorageBalance {
            total: U128(STORAGE_MIN.as_yoctonear()),
            available: U128(0),
        })
    }
}
