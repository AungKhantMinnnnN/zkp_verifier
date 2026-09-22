use std::env;
use std::fs;
use std::time::Duration;
use zkp_verifier::kafka::{prover::KafkaProverClient, DEFAULT_KAFKA_BROKER, REQUEST_TOPIC, RESPONSE_TOPIC};
use zkp_verifier::storage::UserRegistry;
use zkp_verifier::zkp_core_engine::UserSecretKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut broker = DEFAULT_KAFKA_BROKER.to_string();
    let mut user_id = "bob_kafka_user".to_string();
    let mut partition = 0;
    let mut tamper = false;
    let mut replay = false;
    let mut unregistered = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--broker" => {
                if i + 1 < args.len() {
                    broker = args[i + 1].clone();
                    i += 1;
                }
            }
            "--user" => {
                if i + 1 < args.len() {
                    user_id = args[i + 1].clone();
                    i += 1;
                }
            }
            "--partition" => {
                if i + 1 < args.len() {
                    partition = args[i + 1].parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--tamper" => {
                tamper = true;
            }
            "--replay" => {
                replay = true;
            }
            "--unregistered" => {
                unregistered = true;
            }
            "--help" | "-h" => {
                println!("Usage: kafka_prover [OPTIONS]");
                println!("Options:");
                println!("  --broker <HOST:PORT> Kafka broker address (default: {})", DEFAULT_KAFKA_BROKER);
                println!("  --user <NAME>        User identity (default: bob_kafka_user)");
                println!("  --partition <NUM>    Topic partition to publish to (default: 0)");
                println!("  --tamper             Corrupt the proof scalar to simulate attack");
                println!("  --replay             Re-publish the exact same proof to test replay defense");
                println!("  --unregistered       Use an unregistered user ID");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    if unregistered {
        user_id = format!("unregistered_{}", uuid::Uuid::new_v4());
    }

    println!("==================================================");
    println!(" 👤 Kafka ZKP Prover (Phase 3 Hardened Security) ");
    println!("==================================================");
    println!("Broker:            {}", broker);
    println!("User ID:           {}", user_id);
    println!("Tamper simulation: {}", tamper);
    println!("Replay simulation: {}", replay);

    let prover = match KafkaProverClient::new(&broker, REQUEST_TOPIC, RESPONSE_TOPIC, partition).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\n❌ Failed to connect to Kafka at {}: {:?}", broker, e);
            eprintln!("Tip: Ensure Kafka broker is running (e.g. via `docker compose up -d`).");
            return Err(e.into());
        }
    };

    let key_file = format!("{}.key", user_id);
    let secret_key = if fs::metadata(&key_file).is_ok() {
        println!("\n[1/3] Loading existing private key from '{}'...", key_file);
        let hex = fs::read_to_string(&key_file)?;
        let bytes = hex_decode(hex.trim())?;
        UserSecretKey::from_bytes(&bytes)?
    } else {
        println!("\n[1/3] Generating new keypair for '{}'...", user_id);
        let sk = UserSecretKey::generate();
        let pk = sk.public_key();
        
        if !unregistered {
            if let Ok(registry) = UserRegistry::open("zkp_bank.db") {
                let _ = registry.register(&user_id, &pk);
                println!("      Auto-enrolled '{}' into 'zkp_bank.db'", user_id);
            }
        }
        let _ = fs::write(&key_file, hex_string(&sk.0.to_bytes()));
        sk
    };

    let public_key = secret_key.public_key();
    let pk_bytes = public_key.to_bytes();
    println!("      Public Key: {}", hex_string(&pk_bytes));

    println!("\n[2/3] Publishing ZKP Request to Kafka topic '{}'...", REQUEST_TOPIC);
    let start = std::time::Instant::now();
    let req = prover.submit_verification(&user_id, &secret_key, tamper).await?;
    println!("      Published request_id='{}'", req.request_id);

    println!("\n[3/3] Awaiting correlated response from topic '{}'...", RESPONSE_TOPIC);
    match prover.wait_for_response(&req.request_id, Duration::from_secs(10)).await? {
        Some(resp) => {
            let elapsed = start.elapsed();
            println!("\n--- Kafka Verification Event Received ({:?}) ---", elapsed);
            println!("Request ID: {}", resp.request_id);
            println!("Status:     {}", if resp.success { "✅ VERIFIED" } else { "❌ REJECTED" });
            println!("User:       {}", resp.user_id);
            println!("Message:    {}", resp.message);
            println!("--------------------------------------------------");
        }
        None => {
            println!("\n⚠️ Timed out waiting for response event for request_id='{}'.", req.request_id);
            println!("Ensure the `kafka_verifier` worker is running.");
        }
    }

    // Optional replay test
    if replay {
        println!("\n🚨 REPLAY ATTACK SIMULATION:");
        println!("Re-publishing identical request to Kafka to test verifier replay protection...");
        let payload = req.to_json_bytes()?;
        let record = rskafka::record::Record {
            key: Some(user_id.as_bytes().to_vec()),
            value: Some(payload),
            headers: std::collections::BTreeMap::new(),
            timestamp: chrono::Utc::now(),
        };

        // Submit duplicate
        let client = rskafka::client::ClientBuilder::new(vec![broker.clone()]).build().await?;
        let req_client = client.partition_client(REQUEST_TOPIC, partition, rskafka::client::partition::UnknownTopicHandling::Retry).await?;
        req_client.produce(vec![record], rskafka::client::partition::Compression::NoCompression).await?;
        println!("      Replayed request_id='{}'", req.request_id);

        match prover.wait_for_response(&req.request_id, Duration::from_secs(5)).await? {
            Some(replay_resp) => {
                println!("\n--- Kafka Response to Replay Attack ---");
                println!("Status:  {}", if replay_resp.success { "⚠️ VULNERABLE" } else { "🛡️ BLOCKED (Rejected)" });
                println!("Message: {}", replay_resp.message);
                println!("--------------------------------------------------");
            }
            None => {
                println!("No duplicate response received (worker discarded duplicate).");
            }
        }
    }

    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}
