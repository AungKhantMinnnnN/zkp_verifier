use k256::elliptic_curve::sec1::FromEncodedPoint;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkpError {
    #[error("Mathematical inconsistency during proof generation.")]
    MathError,
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Verification failed: Invalid proof.")]
    InvalidProof
}

use k256::{Scalar, ProjectivePoint, Secp256k1, EncodedPoint};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::{FieldBytes};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use ff::{Field, PrimeField};
use rand_core::OsRng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof {
    pub r_point: Vec<u8>, // Serialized R
    pub s_scalar: Vec<u8> // Serialized S
}

pub struct ZkpEngine;
pub struct UserSecretKey(pub Scalar);
pub struct UserPublicKey(pub ProjectivePoint);

impl UserSecretKey {
    // Generates a random secret key
    pub fn generate() -> Self{
        Self(Scalar::random(&mut rand_core::OsRng))
    }

    pub fn publicKey(&self) -> UserPublicKey {
        UserPublicKey(ProjectivePoint::GENERATOR * self.0)
    }
}

impl ZkpEngine {
    pub fn generate_proof(secret: &UserSecretKey, public_key: &UserPublicKey) -> Proof {
        let k = Scalar::random(&mut rand_core::OsRng);
        let r_point = ProjectivePoint::GENERATOR * k;

        let e = Self::compute_challenge(&r_point, &public_key.0);
        let s = k + (e * secret.0);

        Proof{
            r_point: r_point.to_bytes().to_vec(),
            s_scalar: s.to_bytes().to_vec()
        }
    }

    pub fn verify(public_key: &ProjectivePoint, proof: Proof) -> Result<bool,ZkpError> {
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

        // Verification: g^s == R + y^e
        let e = Self::compute_challenge(&r_point, public_key);
        let lhs = ProjectivePoint::GENERATOR * s_scalar;
        let rhs = r_point + (public_key * &e);

        Ok(lhs == rhs)
    }

    fn compute_challenge(r: &ProjectivePoint, y: &ProjectivePoint) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(r.to_bytes());
        hasher.update(y.to_bytes());

        let hash_result = hasher.finalize();

        // Explicitly tell the compiler we are using the 32-byte array for Secp256k1
        let bytes = FieldBytes::<Secp256k1>::from_slice(&hash_result);

        // from_repr returns a 'CtOption'
        // use .unwrap() or .expect() to get the Scalar
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
        let result = ZkpEngine::verify(&alice_pk.0, proof).unwrap();

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

        let result = ZkpEngine::verify(&alice_pk.0, proof).unwrap();
        assert!(!result, "Altered proof should fail verification.");
    }
}