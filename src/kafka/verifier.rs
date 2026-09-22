use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use rskafka::client::{
    partition::{Compression, OffsetAt, PartitionClient, UnknownTopicHandling},
    ClientBuilder,
};
use rskafka::record::Record;
use tokio::sync::watch;

use crate::protocol::{KafkaAuthRequest, KafkaAuthResponse};
use crate::replay::ReplayProtector;
use crate::storage::UserRegistry;
use crate::zkp_core_engine::ZkpEngine;

pub struct KafkaVerifierWorker {
    req_client: Arc<PartitionClient>,
    res_client: Arc<PartitionClient>,
    registry: Arc<UserRegistry>,
    replay_protector: Arc<ReplayProtector>,
}

impl KafkaVerifierWorker {
    /// Create a new Kafka verifier worker for the given topics and partition
    pub async fn new(
        broker: &str,
        req_topic: &str,
        res_topic: &str,
        partition: i32,
    ) -> Result<Self, anyhow::Error> {
        let client = ClientBuilder::new(vec![broker.to_string()])
            .build()
            .await?;

        let req_client = Arc::new(
            client
                .partition_client(req_topic, partition, UnknownTopicHandling::Retry)
                .await?,
        );
        let res_client = Arc::new(
            client
                .partition_client(res_topic, partition, UnknownTopicHandling::Retry)
                .await?,
        );

        let registry = Arc::new(UserRegistry::in_memory().expect("Failed to init in-memory registry"));
        let replay_protector = Arc::new(ReplayProtector::default());

        Ok(Self {
            req_client,
            res_client,
            registry,
            replay_protector,
        })
    }

    /// Attach a custom persistent or pre-populated UserRegistry
    pub fn with_registry(mut self, registry: UserRegistry) -> Self {
        self.registry = Arc::new(registry);
        self
    }

    /// Attach a custom ReplayProtector
    pub fn with_replay_protector(mut self, protector: ReplayProtector) -> Self {
        self.replay_protector = Arc::new(protector);
        self
    }

    pub fn registry(&self) -> Arc<UserRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn replay_protector(&self) -> Arc<ReplayProtector> {
        Arc::clone(&self.replay_protector)
    }

    /// Run continuous consumption and verification loop
    pub async fn run(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), anyhow::Error> {
        let mut offset = match self.req_client.get_offset(OffsetAt::Latest).await {
            Ok(off) => off,
            Err(_) => 0,
        };

        println!(
            "[Kafka Verifier] Worker listening on topic '{}' partition {} from offset {}",
            self.req_client.topic(),
            self.req_client.partition(),
            offset
        );

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        println!("[Kafka Verifier] Shutdown signal received. Exiting.");
                        break;
                    }
                }
                fetch_res = self.req_client.fetch_records(offset, 1..1_048_576, 1_000) => {
                    match fetch_res {
                        Ok((records, high_watermark)) => {
                            for record_and_offset in records {
                                offset = record_and_offset.offset + 1;
                                if let Err(e) = self.process_record(record_and_offset.record).await {
                                    eprintln!("[Kafka Verifier] Error processing record: {:?}", e);
                                }
                            }
                            if offset >= high_watermark {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                        Err(e) => {
                            eprintln!("[Kafka Verifier] Fetch error: {:?}. Retrying in 1s...", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single Kafka verification request record
    pub async fn process_record(&self, record: Record) -> Result<(), anyhow::Error> {
        let value = match record.value {
            Some(v) => v,
            None => return Ok(()),
        };

        let req = match KafkaAuthRequest::from_json_bytes(&value) {
            Ok(r) => r,
            Err(_) => KafkaAuthRequest::from_bincode_bytes(&value)?,
        };

        println!(
            "[Kafka Verifier] Processing verification for request_id='{}', user_id='{}'",
            req.request_id, req.user_id
        );

        // 1. Persistent Storage Check: Check if user is registered and matches stored key
        let (success, message) = match self.registry.get_public_key(&req.user_id) {
            Ok(Some(registered_pk)) => {
                if req.public_key != registered_pk.to_bytes() {
                    (false, "Authentication failed: Public key does not match bank records".to_string())
                } else {
                    // 2. Replay Attack & Freshness Validation
                    match self.replay_protector.check_and_record(&req.user_id, &req.proof) {
                        Err(replay_err) => (false, format!("Security rejection: {replay_err}")),
                        Ok(()) => {
                            // 3. Cryptographic Schnorr ZKP Check
                            match ZkpEngine::verify(&registered_pk.0, &req.proof) {
                                Ok(true) => (true, format!("ZKP Identity verified successfully for '{}'", req.user_id)),
                                Ok(false) => (false, "Verification failed: Mathematical check failed".to_string()),
                                Err(e) => (false, format!("Cryptographic math error: {e}")),
                            }
                        }
                    }
                }
            }
            Ok(None) => (
                false,
                format!("Authentication failed: User '{}' is not registered with bank", req.user_id),
            ),
            Err(e) => (false, format!("Database storage error: {e}")),
        };

        let response = KafkaAuthResponse::new(
            &req.request_id,
            &req.user_id,
            success,
            message,
        );

        let resp_bytes = response.to_json_bytes()?;
        let resp_record = Record {
            key: Some(req.user_id.into_bytes()),
            value: Some(resp_bytes),
            headers: BTreeMap::new(),
            timestamp: Utc::now(),
        };

        self.res_client
            .produce(vec![resp_record], Compression::NoCompression)
            .await?;

        println!(
            "[Kafka Verifier] Published result for request_id='{}': success={}",
            req.request_id, success
        );

        Ok(())
    }
}
