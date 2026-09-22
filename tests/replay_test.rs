use zkp_verifier::replay::{ReplayError, ReplayProtector};
use zkp_verifier::zkp_core_engine::{UserSecretKey, ZkpEngine};

#[test]
fn test_replay_protector_fresh_proof_passes() {
    let protector = ReplayProtector::new(60);
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();

    let proof = ZkpEngine::generate_proof(&sk, &pk);
    let result = protector.check_and_record("alice", &proof);
    assert!(result.is_ok());
    assert_eq!(protector.active_nonces_count(), 1);
}

#[test]
fn test_replay_protector_detects_duplicate_nonce() {
    let protector = ReplayProtector::new(60);
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();

    let proof = ZkpEngine::generate_proof(&sk, &pk);
    
    // 1st submission passes
    assert!(protector.check_and_record("alice", &proof).is_ok());

    // 2nd submission with identical nonce fails
    let result = protector.check_and_record("alice", &proof);
    assert_eq!(result, Err(ReplayError::ReplayDetected));
}

#[test]
fn test_replay_protector_rejects_expired_proof() {
    let protector = ReplayProtector::new(60);
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();

    // Proof generated 120 seconds in the past
    let old_timestamp = chrono::Utc::now().timestamp() - 120;
    let old_proof = ZkpEngine::generate_proof_with_time(&sk, &pk, old_timestamp);

    let result = protector.check_and_record("bob", &old_proof);
    assert!(matches!(result, Err(ReplayError::ProofExpired { .. })));
}

#[test]
fn test_replay_protector_rejects_future_skew_proof() {
    let protector = ReplayProtector::new(60);
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();

    // Proof with future timestamp (+120 seconds)
    let future_timestamp = chrono::Utc::now().timestamp() + 120;
    let future_proof = ZkpEngine::generate_proof_with_time(&sk, &pk, future_timestamp);

    let result = protector.check_and_record("charlie", &future_proof);
    assert!(matches!(result, Err(ReplayError::ClockSkewFuture { .. })));
}
