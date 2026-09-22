use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use crate::zkp_core_engine::Proof;

pub const DEFAULT_MAX_DRIFT_SECS: i64 = 60;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ReplayError {
    #[error("Proof expired: age {age_secs}s exceeds maximum allowed drift of {max_allowed}s")]
    ProofExpired { age_secs: i64, max_allowed: i64 },
    #[error("Future timestamp detected: clock skew of {drift_secs}s exceeds maximum allowed")]
    ClockSkewFuture { drift_secs: i64 },
    #[error("Replay attack detected: Nonce has already been used for this user")]
    ReplayDetected,
}

/// Thread-safe in-memory replay attack protector with automatic nonce expiration
pub struct ReplayProtector {
    max_drift_secs: i64,
    // Maps (user_id, nonce) -> timestamp
    seen_nonces: Mutex<HashMap<(String, [u8; 16]), i64>>,
}

impl Default for ReplayProtector {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DRIFT_SECS)
    }
}

impl ReplayProtector {
    pub fn new(max_drift_secs: i64) -> Self {
        Self {
            max_drift_secs,
            seen_nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Validates proof freshness and ensures nonce has not been previously observed
    pub fn check_and_record(&self, user_id: &str, proof: &Proof) -> Result<(), ReplayError> {
        let now = chrono::Utc::now().timestamp();
        let diff = now - proof.timestamp;

        // Reject if proof was generated in the future beyond allowed drift
        if diff < -self.max_drift_secs {
            return Err(ReplayError::ClockSkewFuture {
                drift_secs: -diff,
            });
        }

        // Reject if proof is older than allowed drift
        if diff > self.max_drift_secs {
            return Err(ReplayError::ProofExpired {
                age_secs: diff,
                max_allowed: self.max_drift_secs,
            });
        }

        let mut nonces = self.seen_nonces.lock().unwrap();

        // Prune nonces older than the validity window
        let cutoff = now - self.max_drift_secs;
        nonces.retain(|_, &mut ts| ts >= cutoff);

        let key = (user_id.to_string(), proof.nonce);
        if nonces.contains_key(&key) {
            return Err(ReplayError::ReplayDetected);
        }

        nonces.insert(key, proof.timestamp);
        Ok(())
    }

    /// Count active nonces currently tracked in the cache
    pub fn active_nonces_count(&self) -> usize {
        let nonces = self.seen_nonces.lock().unwrap();
        nonces.len()
    }
}
