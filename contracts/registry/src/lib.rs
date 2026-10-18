//! SplitVault Registry — on-chain index of all deployed split contract instances.
//!
//! Maintains a searchable map from creator address to their list of deployed
//! split contract addresses so frontends can discover active invoices.

#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

fn registry_admin_key() -> Symbol {
    symbol_short!("reg_adm")
}

/// Per-creator list of registered contract addresses — persistent storage.
fn creator_contracts_key(creator: &Address) -> (Symbol, Address) {
    (symbol_short!("cr_ctrs"), creator.clone())
}

/// Per-(creator, contract) flag to detect duplicate registrations — persistent.
fn registration_key(creator: &Address, contract: &Address) -> (Symbol, Address, Address) {
    (symbol_short!("reg_chk"), creator.clone(), contract.clone())
}

/// Maximum contracts per creator to bound storage growth and prevent DoS.
const MAX_CONTRACTS_PER_CREATOR: u32 = 5_000;

// ---------------------------------------------------------------------------
// Storage rent / TTL constants
// ---------------------------------------------------------------------------

/// Minimum TTL threshold before an extension is triggered (~60 days at 5 s/ledger).
const REGISTRY_MIN_TTL: u32 = 518_400;

/// Maximum TTL to extend to (~1 year at 5 s/ledger).
const REGISTRY_MAX_TTL: u32 = 6_307_200;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when a contract is registered for a creator.
///
/// Topics: (registry, registered, creator)
/// Data: contract_address
pub fn contract_registered(env: &Env, creator: &Address, contract: &Address) {
    env.events().publish(
        (
            symbol_short!("registry"),
            symbol_short!("register"),
            creator.clone(),
        ),
        contract.clone(),
    );
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    /// Initialise the registry by recording its admin.
    /// Can only be called once.
    pub fn initialize(env: Env, admin: Address) {
        assert!(
            !env.storage().instance().has(&registry_admin_key()),
            "already initialized"
        );
        env.storage().instance().set(&registry_admin_key(), &admin);
    }

    /// Register a deployed contract address under a creator.
    ///
    /// Appends `contract` to the creator's list. Rejects duplicate
    /// registrations for the same (creator, contract) pair.
    ///
    /// # Panics
    /// * `"registry limit exceeded"` — the creator already has
    ///   [`MAX_CONTRACTS_PER_CREATOR`] registered contracts.
    /// * `"already registered"` — this contract address is already
    ///   in the creator's list.
    pub fn register(env: Env, creator: Address, contract: Address) {
        creator.require_auth();

        let contracts_key = creator_contracts_key(&creator);
        let registration_check_key = registration_key(&creator, &contract);

        // Reject duplicates.
        assert!(
            !env.storage().persistent().has(&registration_check_key),
            "already registered"
        );

        // Enforce per-creator limit.
        let mut contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&contracts_key)
            .unwrap_or_else(|| Vec::new(&env));
        assert!(
            contracts.len() < MAX_CONTRACTS_PER_CREATOR as u32,
            "registry limit exceeded"
        );

        // Append and persist, then bump TTL so the creator list survives
        // even when the creator is only active once a year (#48).
        contracts.push_back(contract.clone());
        env.storage()
            .persistent()
            .set(&contracts_key, &contracts);
        env.storage()
            .persistent()
            .extend_ttl(&contracts_key, REGISTRY_MIN_TTL, REGISTRY_MAX_TTL);

        // Mark as registered and bump TTL on the flag entry too (#48).
        env.storage()
            .persistent()
            .set(&registration_check_key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&registration_check_key, REGISTRY_MIN_TTL, REGISTRY_MAX_TTL);

        // Emit event.
        contract_registered(&env, &creator, &contract);
    }

    /// Return all registered contract addresses for a creator.
    pub fn get_contracts(env: Env, creator: Address) -> Vec<Address> {
        let key = creator_contracts_key(&creator);
        let contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        // Bump TTL on every read so active registries never expire (#48).
        if env.storage().persistent().has(&key) {
            env.storage()
                .persistent()
                .extend_ttl(&key, REGISTRY_MIN_TTL, REGISTRY_MAX_TTL);
        }
        contracts
    }

    /// Return a paginated slice of a creator's registered contract addresses.
    ///
    /// Returns up to `limit` addresses starting at index `start`. Out-of-range
    /// `start` or `limit == 0` yields an empty vector. This bounds the compute
    /// and memory consumed by a single view call for prolific creators (#77).
    pub fn get_contracts_page(
        env: Env,
        creator: Address,
        start: u32,
        limit: u32,
    ) -> Vec<Address> {
        let key = creator_contracts_key(&creator);
        let contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        // Bump TTL on every read so active registries never expire (#48).
        if env.storage().persistent().has(&key) {
            env.storage()
                .persistent()
                .extend_ttl(&key, REGISTRY_MIN_TTL, REGISTRY_MAX_TTL);
        }

        let mut page: Vec<Address> = Vec::new(&env);
        let total = contracts.len();
        if limit == 0 || start >= total {
            return page;
        }

        // Clamp the end index to the vector length, guarding against overflow.
        let end = match start.checked_add(limit) {
            Some(sum) => {
                if sum < total {
                    sum
                } else {
                    total
                }
            }
            None => total,
        };

        let mut i = start;
        while i < end {
            page.push_back(contracts.get_unchecked(i));
            i += 1;
        }
        page
    }

    /// Return the number of registered contracts for a creator.
    pub fn get_contract_count(env: Env, creator: Address) -> u32 {
        let contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&creator_contracts_key(&creator))
            .unwrap_or_else(|| Vec::new(&env));
        contracts.len()
    }

    /// Check whether a specific (creator, contract) pair is already registered.
    pub fn is_registered(env: Env, creator: Address, contract: Address) -> bool {
        env.storage()
            .persistent()
            .has(&registration_key(&creator, &contract))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::{storage::Persistent as _, Address as _, Events as _},
        Address, Env, Symbol, TryFromVal, Val, Vec,
    };

    #[test]
    fn test_register_and_get_contracts() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let registry_id = env.register(Registry, ());
        let registry_client = RegistryClient::new(&env, &registry_id);
        registry_client.initialize(&admin);

        let creator = Address::generate(&env);
        let contract_addr = Address::generate(&env);

        registry_client.register(&creator, &contract_addr);

        let contracts = registry_client.get_contracts(&creator);
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts.get_unchecked(0), contract_addr);
        assert_eq!(registry_client.get_contract_count(&creator), 1);
    }

    #[test]
    fn test_multiple_creators() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let registry_id = env.register(Registry, ());
        let registry_client = RegistryClient::new(&env, &registry_id);
        registry_client.initialize(&admin);

        let c1 = Address::generate(&env);
        let c2 = Address::generate(&env);
        let addr1 = Address::generate(&env);
        let addr2 = Address::generate(&env);
        let addr3 = Address::generate(&env);

        registry_client.register(&c1, &addr1);
        registry_client.register(&c1, &addr2);
        registry_client.register(&c2, &addr3);

        let c1_contracts = registry_client.get_contracts(&c1);
        assert_eq!(c1_contracts.len(), 2);
        assert_eq!(c1_contracts.get_unchecked(0), addr1);
        assert_eq!(c1_contracts.get_unchecked(1), addr2);

        let c2_contrac

/* … truncated 6579 chars — edit only what you need near the top … */
