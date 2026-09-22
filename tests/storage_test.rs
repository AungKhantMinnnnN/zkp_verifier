use zkp_verifier::storage::UserRegistry;
use zkp_verifier::zkp_core_engine::UserSecretKey;

#[test]
fn test_sqlite_user_registration_and_lookup() {
    let registry = UserRegistry::in_memory().expect("Failed to create in-memory SQLite registry");

    let alice_sk = UserSecretKey::generate();
    let alice_pk = alice_sk.public_key();

    // User should not exist initially
    assert!(!registry.is_registered("alice").unwrap());
    assert!(registry.get_public_key("alice").unwrap().is_none());

    // Register user
    registry.register("alice", &alice_pk).expect("Registration failed");
    assert!(registry.is_registered("alice").unwrap());

    // Fetch and verify public key
    let retrieved_pk = registry.get_public_key("alice").unwrap().expect("User should exist");
    assert_eq!(alice_pk, retrieved_pk);

    // Verify count and list
    assert_eq!(registry.count().unwrap(), 1);
    let users = registry.list_users().unwrap();
    assert_eq!(users, vec!["alice".to_string()]);
}

#[test]
fn test_sqlite_user_key_update() {
    let registry = UserRegistry::in_memory().unwrap();

    let sk1 = UserSecretKey::generate();
    let pk1 = sk1.public_key();
    registry.register("bob", &pk1).unwrap();
    assert_eq!(registry.get_public_key("bob").unwrap().unwrap(), pk1);

    // Key rotation / update
    let sk2 = UserSecretKey::generate();
    let pk2 = sk2.public_key();
    registry.register("bob", &pk2).unwrap();
    assert_eq!(registry.get_public_key("bob").unwrap().unwrap(), pk2);
    assert_eq!(registry.count().unwrap(), 1);
}

#[test]
fn test_sqlite_user_removal() {
    let registry = UserRegistry::in_memory().unwrap();

    let sk = UserSecretKey::generate();
    registry.register("charlie", &sk.public_key()).unwrap();
    assert!(registry.is_registered("charlie").unwrap());

    let removed = registry.remove("charlie").unwrap();
    assert!(removed);
    assert!(!registry.is_registered("charlie").unwrap());
    assert_eq!(registry.count().unwrap(), 0);
}
