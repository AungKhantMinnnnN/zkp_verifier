use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use zkp_verifier::codec::ZkpMessageCodec;
use zkp_verifier::protocol::{AuthRequest, AuthResponse};
use zkp_verifier::zkp_core_engine::{UserSecretKey, ZkpEngine};

#[test]
fn test_codec_encode_decode_roundtrip() {
    let mut codec = ZkpMessageCodec::<AuthRequest, AuthResponse>::new();
    let mut buffer = BytesMut::new();

    let sk = UserSecretKey::generate();
    let pk = sk.public_key();
    let proof = ZkpEngine::generate_proof(&sk, &pk);

    let original_req = AuthRequest {
        user_id: "alice".into(),
        public_key: pk.to_bytes(),
        proof,
    };

    // Encode
    codec.encode(original_req.clone(), &mut buffer).expect("Encoding should succeed");
    assert!(buffer.len() > 4); // Must have at least the 4-byte header

    // Decode with inverted codec (ItemIn = AuthRequest)
    let mut decode_codec = ZkpMessageCodec::<AuthResponse, AuthRequest>::new();
    let decoded_req: AuthRequest = decode_codec.decode(&mut buffer)
        .expect("Decoding should succeed")
        .expect("Should return a complete item");

    assert_eq!(original_req, decoded_req);
    assert!(buffer.is_empty(), "Buffer should be fully consumed");
}

#[test]
fn test_codec_handles_partial_data() {
    let mut codec = ZkpMessageCodec::<AuthResponse, AuthResponse>::new();
    let mut buffer = BytesMut::new();

    let resp = AuthResponse {
        user_id: "bob".into(),
        success: true,
        message: "Welcome back".into(),
    };

    codec.encode(resp.clone(), &mut buffer).unwrap();
    let full_len = buffer.len();

    // Simulate arriving in two fragments
    let fragment1 = buffer.split_to(full_len / 2);
    let fragment2 = buffer;

    let mut feeder_buffer = BytesMut::new();
    feeder_buffer.extend_from_slice(&fragment1);

    // Decoding partial data should return Ok(None) and not panic
    let result = codec.decode(&mut feeder_buffer).unwrap();
    assert!(result.is_none());

    // Deliver second fragment
    feeder_buffer.extend_from_slice(&fragment2);
    let decoded = codec.decode(&mut feeder_buffer).unwrap();
    assert!(decoded.is_some());
    assert_eq!(resp, decoded.unwrap());
}

#[test]
fn test_codec_max_frame_size_defense() {
    // Codec with tiny 20-byte max size limit
    let mut tiny_codec = ZkpMessageCodec::<AuthResponse, AuthResponse>::with_max_frame_size(20);
    let mut buffer = BytesMut::new();

    let oversized_resp = AuthResponse {
        user_id: "long_name_that_exceeds_frame_limit_defense".into(),
        success: true,
        message: "This payload is intentionally way too large".into(),
    };

    let err = tiny_codec.encode(oversized_resp, &mut buffer);
    assert!(err.is_err(), "Should reject payloads exceeding max_frame_size");
}
