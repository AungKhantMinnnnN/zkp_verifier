pub mod verifier;
pub mod prover;

pub const DEFAULT_KAFKA_BROKER: &str = "127.0.0.1:9092";
pub const REQUEST_TOPIC: &str = "zkp-identity-requests";
pub const RESPONSE_TOPIC: &str = "zkp-identity-responses";
