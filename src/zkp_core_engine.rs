use k256::elliptic_curve::sec1::FromEncodedPoint;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkpError {
    #[error("Mathematical inconsistency during proof generation.")]
    MathError,
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Verification failed: Invalid proof.")]
    InvalidProof,
    #[error("Network/IO error: {0}")]
    IoError(#[from] std::io::Error),
}

use k256::{EncodedPoint, ProjectivePoint, Scalar, Secp256k1};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::FieldBytes;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use ff::{Field, PrimeField};

use rand_core::{OsRng, RngCore};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub r_point: Vec<u8>,  // Serialized R (33 bytes compressed point)
    pub s_scalar: Vec<u8>, // Serialized S (32 bytes scalar)
    pub timestamp: i64,    // Unix timestamp in seconds for freshness check
    pub nonce: [u8; 16],   // 128-bit random nonce for replay attack prevention
}

impl TryFrom<&[u8]> for Proof {
    type Error = ZkpError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Failed to deserialize Proof: {e}")))
    }
}

impl TryFrom<Vec<u8>> for Proof {
    type Error = ZkpError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl From<&Proof> for Vec<u8> {
    fn from(proof: &Proof) -> Self {
        bincode::serialize(proof).expect("Proof bincode serialization should never fail")
    }
}

impl From<Proof> for Vec<u8> {
    fn from(proof: Proof) -> Self {
        Vec::from(&proof)
    }
}

use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct ZkpEngine;

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct UserSecretKey(pub Scalar);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPublicKey(pub ProjectivePoint);

impl UserSecretKey {
    /// Generates a random secret key using OS randomness
    pub fn generate() -> Self {
        Self(Scalar::random(&mut rand_core::OsRng))
    }

    /// Derives the public key g^sk
    pub fn public_key(&self) -> UserPublicKey {
        UserPublicKey(ProjectivePoint::GENERATOR * self.0)
    }

    /// Kept for backwards compatibility
    #[allow(non_snake_case)]
    pub fn publicKey(&self) -> UserPublicKey {
        self.public_key()
    }

    /// Serialize to 32-byte secret scalar bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Deserialize from 32-byte secret scalar bytes
    #[allow(deprecated)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkpError> {
        if bytes.len() != 32 {
            return Err(ZkpError::SerializationError("Secret key must be exactly 32 bytes".into()));
        }
        let s_bytes = FieldBytes::<Secp256k1>::from_slice(bytes);
        let scalar = Scalar::from_repr(*s_bytes);
        if bool::from(scalar.is_none()) {
            return Err(ZkpError::SerializationError("Invalid scalar bytes for Secp256k1".into()));
        }
        Ok(Self(scalar.unwrap()))
    }
}

impl UserPublicKey {
    /// Serialize compressed SEC1 public key point (33 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Deserialize compressed SEC1 public key point
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkpError> {
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Invalid public key bytes: {e}")))?;
        let point = Option::from(ProjectivePoint::from_encoded_point(&encoded))
            .ok_or_else(|| ZkpError::SerializationError("Point not on Secp256k1 curve".into()))?;
        Ok(Self(point))
    }
}

impl ZkpEngine {
    /// Generates proof bound to current UTC timestamp and random nonce (Fiat-Shamir with replay defense)
    pub fn generate_proof(secret: &UserSecretKey, public_key: &UserPublicKey) -> Proof {
        Self::generate_proof_with_time(secret, public_key, chrono::Utc::now().timestamp())
    }

    /// Generates proof with an explicit timestamp (useful for testing clock drift & expiry)
    pub fn generate_proof_with_time(
        secret: &UserSecretKey,
        public_key: &UserPublicKey,
        timestamp: i64,
    ) -> Proof {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let k = Scalar::random(&mut rand_core::OsRng);
        let r_point = ProjectivePoint::GENERATOR * k;

        let e = Self::compute_challenge(&r_point, &public_key.0, timestamp, &nonce);
        let s = k + (e * secret.0);

        Proof {
            r_point: r_point.to_bytes().to_vec(),
            s_scalar: s.to_bytes().to_vec(),
            timestamp,
            nonce,
        }
    }

    /// Validates if proof's timestamp is within allowed clock drift
    pub fn is_fresh(proof: &Proof, max_drift_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        (now - proof.timestamp).abs() <= max_drift_secs
    }

    #[allow(deprecated)]
    pub fn verify(public_key: &ProjectivePoint, proof: &Proof) -> Result<bool, ZkpError> {
        // Convert bytes back to ProjectivePoints/Scalars
        let r_encoded = EncodedPoint::from_bytes(&proof.r_point)
            .map_err(|_| ZkpError::SerializationError("Invalid R point length/format".into()))?;

        let r_point = Option::from(ProjectivePoint::from_encoded_point(&r_encoded));

        let s_bytes = FieldBytes::<Secp256k1>::from_slice(&proof.s_scalar);
        let s_scalar = Scalar::from_repr(*s_bytes);

        if r_point.is_none().into() || s_scalar.is_none().into() {
            return Err(ZkpError::SerializationError("Invalid point encoding".into()));
        }

        let r_point = r_point.unwrap();
        let s_scalar = s_scalar.unwrap();

        // Verification: g^s == R + y^e (with timestamp and nonce bound in challenge e)
        let e = Self::compute_challenge(&r_point, public_key, proof.timestamp, &proof.nonce);
        let lhs = ProjectivePoint::GENERATOR * s_scalar;
        let rhs = r_point + (public_key * &e);

        Ok(lhs == rhs)
    }

    #[allow(deprecated)]
    fn compute_challenge(
        r: &ProjectivePoint,
        y: &ProjectivePoint,
        timestamp: i64,
        nonce: &[u8; 16],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(r.to_bytes());
        hasher.update(y.to_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(nonce);

        let hash_result = hasher.finalize();

        let bytes = FieldBytes::<Secp256k1>::from_slice(&hash_result);
        Scalar::from_repr(*bytes).expect("Hash to Scalar failed.")
    }
}


// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_verification_success() {
        // Use the helper we built: generate the secret and derive the public key
        let alice_sk = UserSecretKey::generate();
        let alice_pk = alice_sk.publicKey();

        // Pass the wrapped types
        let proof = ZkpEngine::generate_proof(&alice_sk, &alice_pk);
        let result = ZkpEngine::verify(&alice_pk.0, &proof).unwrap();

        assert!(result, "Valid proof should be verified.");
    }

    #[test]
    fn test_proof_verification_failure() {
        let alice_sk = UserSecretKey::generate();
        let alice_pk = alice_sk.publicKey();

        let mut proof = ZkpEngine::generate_proof(&alice_sk, &alice_pk);
        
        // Maliciously alter the byte vector inside the proof
        if let Some(last) = proof.s_scalar.last_mut() {
            *last = last.wrapping_add(1);
        }

        let result = ZkpEngine::verify(&alice_pk.0, &proof).unwrap();
        assert!(!result, "Altered proof should fail verification.");
    }

    #[test]
    fn test_proof_wire_transfer_traits() {
        let alice_sk = UserSecretKey::generate();
        let alice_pk = alice_sk.public_key();
        let original_proof = ZkpEngine::generate_proof(&alice_sk, &alice_pk);

        // Test From trait (Proof -> Vec<u8>)
        let wire_bytes: Vec<u8> = Vec::from(&original_proof);
        assert!(!wire_bytes.is_empty());

        // Test TryFrom trait (&[u8] -> Proof)
        let recovered_proof = Proof::try_from(wire_bytes.as_slice()).expect("Deserialization should succeed");
        assert_eq!(original_proof, recovered_proof);

        // Verification of recovered proof must pass
        let valid = ZkpEngine::verify(&alice_pk.0, &recovered_proof).unwrap();
        assert!(valid);

        // Invalid wire bytes should return error
        let corrupted_bytes = vec![0u8; 10];
        let err_result = Proof::try_from(corrupted_bytes.as_slice());
        assert!(err_result.is_err());
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let sk = UserSecretKey::generate();
        let pk = sk.public_key();

        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 33); // 33-byte compressed Secp256k1 point

        let recovered_pk = UserPublicKey::from_bytes(&bytes).expect("Should recover public key");
        assert_eq!(pk, recovered_pk);
    }

    #[test]
    fn test_secret_key_zeroization() {
        let mut sk = UserSecretKey::generate();
        assert_ne!(sk.0, Scalar::ZERO);
        sk.zeroize();
        assert_eq!(sk.0, Scalar::ZERO);
    }

    #[test]
    fn test_replay_timestamp_tampering_fails() {
        let sk = UserSecretKey::generate();
        let pk = sk.public_key();

        let mut proof = ZkpEngine::generate_proof(&sk, &pk);
        
        // Attacker attempts to change the timestamp to make an old proof look fresh
        proof.timestamp += 100;

        // Challenge hash will not match the proof, verification must fail
        let result = ZkpEngine::verify(&pk.0, &proof).unwrap();
        assert!(!result, "Altering timestamp in proof must cause verification failure");
    }

    #[test]
    fn test_replay_nonce_tampering_fails() {
        let sk = UserSecretKey::generate();
        let pk = sk.public_key();

        let mut proof = ZkpEngine::generate_proof(&sk, &pk);
        
        // Attacker alters nonce
        proof.nonce[0] = proof.nonce[0].wrapping_add(1);

        // Verification must fail
        let result = ZkpEngine::verify(&pk.0, &proof).unwrap();
        assert!(!result, "Altering nonce in proof must cause verification failure");
    }
}