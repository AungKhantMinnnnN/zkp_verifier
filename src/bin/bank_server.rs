use std::env;
use tokio::sync::watch;
use zkp_verifier::storage::UserRegistry;
use zkp_verifier::tcp::BankServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut addr = "127.0.0.1:8080".to_string();
    let mut db_path = "zkp_bank.db".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                if i + 1 < args.len() {
                    addr = args[i + 1].clone();
                    i += 1;
                }
            }
            "--db" => {
                if i + 1 < args.len() {
                    db_path = args[i + 1].clone();
                    i += 1;
                }
            }
            _ => {
                if !args[i].starts_with('-') {
                    addr = args[i].clone();
                }
            }
        }
        i += 1;
    }

    println!("=======================================================");
    println!(" 🏦 Bank Verifier Server (Phase 3 Hardened Security)   ");
    println!("=======================================================");
    println!("Listening Address:  {}", addr);
    println!("SQLite Registry:    {}", db_path);

    let registry = UserRegistry::open(&db_path)?;
    let user_count = registry.count()?;
    println!("Registered Users:   {}", user_count);
    if user_count == 0 {
        println!("ℹ️  No registered users found. Users can enroll via:");
        println!("   cargo run --bin enroll_user -- --user <NAME>");
    }

    let server = BankServer::bind(&addr).await?.with_registry(registry);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n[Bank Verifier] Received Ctrl+C. Initiating graceful shutdown...");
        let _ = shutdown_tx.send(true);
    });

    server.run(shutdown_rx).await?;
    println!("[Bank Verifier] Server terminated gracefully.");
    Ok(())
}
