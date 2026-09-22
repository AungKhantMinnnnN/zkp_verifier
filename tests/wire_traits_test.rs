use zkp_verifier::protocol::{AuthRequest, AuthResponse, KafkaAuthRequest, KafkaAuthResponse};
use zkp_verifier::zkp_core_engine::{Proof, UserSecretKey, ZkpEngine};

#[test]
fn test_proof_wire_from_and_try_from() {
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();
    let original_proof = ZkpEngine::generate_proof(&sk, &pk);

    // From trait
    let wire_bytes: Vec<u8> = Vec::from(&original_proof);
    assert!(!wire_bytes.is_empty());

    // TryFrom &[u8]
    let decoded_proof = Proof::try_from(wire_bytes.as_slice()).expect("Should decode slice");
    assert_eq!(original_proof, decoded_proof);

    // TryFrom Vec<u8>
    let decoded_proof_vec = Proof::try_from(wire_bytes.clone()).expect("Should decode Vec");
    assert_eq!(original_proof, decoded_proof_vec);

    // Corrupted bytes
    assert!(Proof::try_from(&wire_bytes[..5]).is_err());
}

#[test]
fn test_auth_request_wire_traits() {
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();
    let proof = ZkpEngine::generate_proof(&sk, &pk);

    let original_req = AuthRequest {
        user_id: "alice_fintech".to_string(),
        public_key: pk.to_bytes(),
        proof,
    };

    // From trait
    let wire_bytes: Vec<u8> = Vec::from(&original_req);
    assert!(!wire_bytes.is_empty());

    // TryFrom &[u8]
    let decoded_req = AuthRequest::try_from(wire_bytes.as_slice()).expect("Should decode slice");
    assert_eq!(original_req, decoded_req);

    // TryFrom Vec<u8>
    let decoded_req_vec = AuthRequest::try_from(wire_bytes).expect("Should decode Vec");
    assert_eq!(original_req, decoded_req_vec);
}

#[test]
fn test_auth_response_wire_traits() {
    let original_res = AuthResponse {
        user_id: "alice_fintech".to_string(),
        success: true,
        message: "Identity verified successfully".to_string(),
    };

    let wire_bytes: Vec<u8> = Vec::from(&original_res);
    let decoded_res = AuthResponse::try_from(wire_bytes.as_slice()).expect("Should decode");
    assert_eq!(original_res, decoded_res);
}

#[test]
fn test_kafka_events_serialization() {
    let sk = UserSecretKey::generate();
    let pk = sk.public_key();
    let proof = ZkpEngine::generate_proof(&sk, &pk);

    let kafka_req = KafkaAuthRequest::new("charlie_kafka", pk.to_bytes(), proof);
    let json_bytes = kafka_req.to_json_bytes().expect("JSON serialization failed");
    let recovered_req = KafkaAuthRequest::from_json_bytes(&json_bytes).expect("JSON deserialization failed");

    assert_eq!(kafka_req.request_id, recovered_req.request_id);
    assert_eq!(kafka_req.user_id, recovered_req.user_id);
    assert_eq!(kafka_req.proof, recovered_req.proof);

    let kafka_resp = KafkaAuthResponse::new(&kafka_req.request_id, "charlie_kafka", true, "Verified");
    let resp_json = kafka_resp.to_json_bytes().expect("JSON resp serialization failed");
    let recovered_resp = KafkaAuthResponse::from_json_bytes(&resp_json).expect("JSON resp deserialization failed");

    assert_eq!(kafka_resp.request_id, recovered_resp.request_id);
    assert_eq!(kafka_resp.success, recovered_resp.success);
}
