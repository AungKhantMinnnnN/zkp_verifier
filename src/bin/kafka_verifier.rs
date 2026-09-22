use std::env;
use tokio::sync::watch;
use zkp_verifier::kafka::{verifier::KafkaVerifierWorker, DEFAULT_KAFKA_BROKER, REQUEST_TOPIC, RESPONSE_TOPIC};
use zkp_verifier::storage::UserRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut broker = DEFAULT_KAFKA_BROKER.to_string();
    let mut partition = 0;
    let mut db_path = "zkp_bank.db".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--broker" => {
                if i + 1 < args.len() {
                    broker = args[i + 1].clone();
                    i += 1;
                }
            }
            "--partition" => {
                if i + 1 < args.len() {
                    partition = args[i + 1].parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--db" => {
                if i + 1 < args.len() {
                    db_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("Usage: kafka_verifier [OPTIONS]");
                println!("Options:");
                println!("  --broker <HOST:PORT> Kafka broker address (default: {})", DEFAULT_KAFKA_BROKER);
                println!("  --partition <NUM>    Topic partition to consume (default: 0)");
                println!("  --db <PATH>          SQLite database path (default: zkp_bank.db)");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    println!("==================================================");
    println!(" 🏦 Kafka ZKP Verifier Daemon (Phase 3 Hardened) ");
    println!("==================================================");
    println!("Broker:          {}", broker);
    println!("Request Topic:   {}", REQUEST_TOPIC);
    println!("Response Topic:  {}", RESPONSE_TOPIC);
    println!("Partition:       {}", partition);
    println!("SQLite Registry: {}", db_path);

    let registry = UserRegistry::open(&db_path)?;
    println!("Registered Users: {}", registry.count()?);

    let worker = match KafkaVerifierWorker::new(&broker, REQUEST_TOPIC, RESPONSE_TOPIC, partition).await {
        Ok(w) => w.with_registry(registry),
        Err(e) => {
            eprintln!("\n❌ Failed to connect to Kafka at {}: {:?}", broker, e);
            eprintln!("Tip: Ensure Kafka broker is running (e.g. via `docker compose up -d`).");
            return Err(e.into());
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n[Kafka Verifier] Received Ctrl+C. Shutting down...");
        let _ = shutdown_tx.send(true);
    });

    println!("\n[Kafka Verifier] Starting consumer loop...");
    worker.run(shutdown_rx).await?;
    println!("[Kafka Verifier] Finished cleanly.");

    Ok(())
}
