use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::Utc;
use rskafka::client::{
    partition::{Compression, OffsetAt, PartitionClient, UnknownTopicHandling},
    ClientBuilder,
};
use rskafka::record::Record;

use crate::protocol::{KafkaAuthRequest, KafkaAuthResponse};
use crate::zkp_core_engine::{UserSecretKey, ZkpEngine};

pub struct KafkaProverClient {
    req_client: Arc<PartitionClient>,
    res_client: Arc<PartitionClient>,
}

impl KafkaProverClient {
    /// Create a new Kafka Prover client connected to the specified broker and topics
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

        Ok(Self {
            req_client,
            res_client,
        })
    }

    /// Submit a Zero-Knowledge Proof authentication request to Kafka
    pub async fn submit_verification(
        &self,
        user_id: &str,
        secret_key: &UserSecretKey,
        tamper: bool,
    ) -> Result<KafkaAuthRequest, anyhow::Error> {
        let public_key = secret_key.public_key();
        let mut proof = ZkpEngine::generate_proof(secret_key, &public_key);

        if tamper {
            if let Some(last_byte) = proof.s_scalar.last_mut() {
                *last_byte = last_byte.wrapping_add(1);
            }
        }

        let request = KafkaAuthRequest::new(user_id, public_key.to_bytes(), proof);
        let payload = request.to_json_bytes()?;

        let record = Record {
            key: Some(user_id.as_bytes().to_vec()),
            value: Some(payload),
            headers: BTreeMap::new(),
            timestamp: Utc::now(),
        };

        self.req_client
            .produce(vec![record], Compression::NoCompression)
            .await?;

        println!(
            "[Kafka Prover] Published proof request: request_id='{}', user_id='{}'",
            request.request_id, user_id
        );

        Ok(request)
    }

    /// Poll the response topic for the matching request_id until timeout
    pub async fn wait_for_response(
        &self,
        request_id: &str,
        timeout: Duration,
    ) -> Result<Option<KafkaAuthResponse>, anyhow::Error> {
        let deadline = Instant::now() + timeout;
        let mut offset = match self.res_client.get_offset(OffsetAt::Earliest).await {
            Ok(off) => off,
            Err(_) => 0,
        };

        while Instant::now() < deadline {
            let fetch_res = self.res_client.fetch_records(offset, 1..1_048_576, 500).await;
            match fetch_res {
                Ok((records, _high_watermark)) => {
                    for record_and_offset in records {
                        offset = record_and_offset.offset + 1;
                        if let Some(val) = record_and_offset.record.value {
                            if let Ok(resp) = KafkaAuthResponse::from_json_bytes(&val) {
                                if resp.request_id == request_id {
                                    return Ok(Some(resp));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[Kafka Prover] Error polling response topic: {:?}", e);
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(None)
    }
}
