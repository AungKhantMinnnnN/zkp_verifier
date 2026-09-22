use serde::{Deserialize, Serialize};
use crate::zkp_core_engine::{Proof, ZkpError};

/// TCP Authentication request sent by the user/prover to the bank verifier
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub user_id: String,
    pub public_key: Vec<u8>, // Compressed SEC1 point (33 bytes)
    pub proof: Proof,
}

/// TCP Authentication response sent by the bank verifier to the user/prover
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub user_id: String,
    pub success: bool,
    pub message: String,
}

// Wire transfer conversions using bincode for AuthRequest
impl TryFrom<&[u8]> for AuthRequest {
    type Error = ZkpError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Failed to deserialize AuthRequest: {e}")))
    }
}

impl TryFrom<Vec<u8>> for AuthRequest {
    type Error = ZkpError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl From<&AuthRequest> for Vec<u8> {
    fn from(req: &AuthRequest) -> Self {
        bincode::serialize(req).expect("AuthRequest bincode serialization should never fail")
    }
}

impl From<AuthRequest> for Vec<u8> {
    fn from(req: AuthRequest) -> Self {
        Vec::from(&req)
    }
}

// Wire transfer conversions using bincode for AuthResponse
impl TryFrom<&[u8]> for AuthResponse {
    type Error = ZkpError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Failed to deserialize AuthResponse: {e}")))
    }
}

impl TryFrom<Vec<u8>> for AuthResponse {
    type Error = ZkpError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl From<&AuthResponse> for Vec<u8> {
    fn from(res: &AuthResponse) -> Self {
        bincode::serialize(res).expect("AuthResponse bincode serialization should never fail")
    }
}

impl From<AuthResponse> for Vec<u8> {
    fn from(res: AuthResponse) -> Self {
        Vec::from(&res)
    }
}

/// Kafka event: Verification request published to Kafka topic
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KafkaAuthRequest {
    pub request_id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub proof: Proof,
    pub timestamp: i64,
}

impl KafkaAuthRequest {
    pub fn new(user_id: impl Into<String>, public_key: Vec<u8>, proof: Proof) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            public_key,
            proof,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ZkpError> {
        serde_json::to_vec(self)
            .map_err(|e| ZkpError::SerializationError(format!("JSON serialization error: {e}")))
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ZkpError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("JSON deserialization error: {e}")))
    }

    pub fn to_bincode_bytes(&self) -> Result<Vec<u8>, ZkpError> {
        bincode::serialize(self)
            .map_err(|e| ZkpError::SerializationError(format!("Bincode serialization error: {e}")))
    }

    pub fn from_bincode_bytes(bytes: &[u8]) -> Result<Self, ZkpError> {
        bincode::deserialize(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Bincode deserialization error: {e}")))
    }
}

/// Kafka event: Verification result published to Kafka topic
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KafkaAuthResponse {
    pub request_id: String,
    pub user_id: String,
    pub success: bool,
    pub message: String,
    pub timestamp: i64,
}

impl KafkaAuthResponse {
    pub fn new(
        request_id: impl Into<String>,
        user_id: impl Into<String>,
        success: bool,
        message: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            user_id: user_id.into(),
            success,
            message: message.into(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ZkpError> {
        serde_json::to_vec(self)
            .map_err(|e| ZkpError::SerializationError(format!("JSON serialization error: {e}")))
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ZkpError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("JSON deserialization error: {e}")))
    }
}
