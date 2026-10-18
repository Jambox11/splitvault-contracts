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

/// Global pause flag — instance storage.
fn registry_paused_key() -> Symbol {
    symbol_short!("reg_pause")
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

/// Emitted when an admin deregisters a contract from a creator.
///
/// Topics: (registry, deregister, creator)
/// Data: contract_address
pub fn contract_deregistered(env: &Env, creator: &Address, contract: &Address) {
    env.events().publish(
        (
            symbol_short!("registry"),
            symbol_short!("deregist"),
            creator.clone(),
        ),
        contract.clone(),
    );
}

/// Emitted when admin privileges are transferred.
///
/// Topics: (registry, set_admin)
/// Data: new_admin
pub fn admin_changed(env: &Env, new_admin: &Address) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("set_admin")),
        new_admin.clone(),
    );
}

/// Emitted when the registry is paused or unpaused.
///
/// Topics: (registry, paused)
/// Data: paused flag
pub fn pause_changed(env: &Env, paused: bool) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("paused")),
        paused,
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

    /// Return the current registry admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&registry_admin_key())
            .expect("not initialized")
    }

    /// Transfer admin privileges to `new_admin`. Requires current admin auth.
    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&registry_admin_key())
            .expect("not initialized");
        admin.require_auth();
        env.storage().instance().set(&registry_admin_key(), &new_admin);
        admin_changed(&env, &new_admin);
    }

    /// Pause or unpause registrations. Requires admin auth.
    ///
    /// While paused, [`Registry::register`] is rejected; admin management
    /// functions remain available.
    pub fn pause(env: Env, paused: bool) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&registry_admin_key())
            .expect("not initialized");
        admin.require_auth();
        env.storage().instance().set(&registry_paused_key(), &paused);
        pause_changed(&env, paused);
    }

    /// Return whether registrations are currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&registry_paused_key())
            .unwrap_or(false)
    }

    /// Remove a contract from a creator's registry. Requires admin auth.
    ///
    /// Used to purge spam or invalid entries. No-op if not registered.
    pub fn deregister_contract(env: Env, creator: Address, contract: Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&registry_admin_key())
            .expect("not initialized");
        admin.require_auth();

        let contracts_key = creator_contracts_key(&creator);
        let registration_check_key = registration_key(&creator, &contract);

        if !env.storage().persistent().has(&registration_check_key) {
            return;
        }

        let contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&contracts_key)
            .unwrap_or_else(|| Vec::new(&env));

        let mut remaining: Vec<Address> = Vec::new(&env);
        let mut i = 0;
        while i < contracts.len() {
            let entry = contracts.get_unchecked(i);
            if entry != contract {
                remaining.push_back(entry);
            }
            i += 1;
        }

        env.storage().persistent().set(&contracts_key, &remaining);
        env.storage()
            .persistent()
            .extend_ttl(&contracts_key, REGISTRY_MIN_TTL, REGISTRY_MAX_TTL);

        env.storage()
            .persistent()
            .remove(&registration_check_key);

        contract_deregistered(&env, &creator, &contract);
    }

    /// Register a deployed contract address under a creator.
    ///
    /// Appends `contract` to the creator's list. Rejects duplicate
    /// registrations for the same (creator, contract) pair.
    ///
    /// # Panics
    /// * `"registry paused"` — the registry is currently paused.
    /// * `"registry limit exceeded"` — the creator already has
    ///   [`MAX_CONTRACTS_PER_CREATOR`] registered contracts.
    /// * `"already registered"` — this contract address is already
    ///   in the creator's list.
    pub fn register(env: Env, creator: Address, contract: Address) {
        creator.require_auth();

        let paused: bool = env
            .storage()
            .instance()
            .get(&registry_paused_key())
            .unwrap_or(false);
        assert!(!paused, "registry paused");

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
        let env 

/* … truncated 1675 chars — edit only what you need near the top … */
