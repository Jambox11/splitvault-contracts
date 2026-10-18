use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

fn setup() -> (Env, RegistryContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn test_register_and_get_contracts() {
    let (env, client, _admin) = setup();
    let creator = Address::generate(&env);
    let contract = Address::generate(&env);

    client.register(&creator, &contract);

    let contracts = client.get_contracts(&creator);
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts.get(0).unwrap(), contract);
}

#[test]
fn test_deregister_removes_contract() {
    let (env, client, _admin) = setup();
    let creator = Address::generate(&env);
    let contract_a = Address::generate(&env);
    let contract_b = Address::generate(&env);

    client.register(&creator, &contract_a);
    client.register(&creator, &contract_b);

    client.deregister(&creator, &contract_a);

    let contracts = client.get_contracts(&creator);
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts.get(0).unwrap(), contract_b);
}

#[test]
fn test_deregister_clears_registration_check() {
    let (env, client, _admin) = setup();
    let creator = Address::generate(&env);
    let contract = Address::generate(&env);

    client.register(&creator, &contract);
    assert!(client.is_registered(&contract));

    client.deregister(&creator, &contract);
    assert!(!client.is_registered(&contract));
}

#[test]
fn test_deregister_unknown_contract_is_noop() {
    let (env, client, _admin) = setup();
    let creator = Address::generate(&env);
    let contract = Address::generate(&env);

    client.deregister(&creator, &contract);

    let contracts = client.get_contracts(&creator);
    assert_eq!(contracts.len(), 0);
}
