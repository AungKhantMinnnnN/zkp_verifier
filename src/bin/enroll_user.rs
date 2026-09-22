use std::env;
use std::fs;
use zkp_verifier::storage::UserRegistry;
use zkp_verifier::zkp_core_engine::UserSecretKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut db_path = "zkp_bank.db".to_string();
    let mut user_id: Option<String> = None;
    let mut list = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                if i + 1 < args.len() {
                    db_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--user" => {
                if i + 1 < args.len() {
                    user_id = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--list" => {
                list = true;
            }
            "--help" | "-h" => {
                println!("Usage: enroll_user [OPTIONS]");
                println!("Options:");
                println!("  --user <NAME>    User identity to enroll");
                println!("  --db <PATH>      SQLite database path (default: zkp_bank.db)");
                println!("  --list           List all currently enrolled users");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let registry = UserRegistry::open(&db_path)?;

    println!("=======================================================");
    println!(" 🏦 Bank Identity Enrollment & Storage (SQLite)       ");
    println!("=======================================================");
    println!("Database: {}", db_path);

    if list {
        let users = registry.list_users()?;
        println!("\nRegistered Users ({}) :", users.len());
        for u in users {
            let pk = registry.get_public_key(&u)?.unwrap();
            println!("  • {} -> PK: {}", u, hex_string(&pk.to_bytes()));
        }
        return Ok(());
    }

    let user_name = user_id.unwrap_or_else(|| "alice_fintech".to_string());

    println!("\n[1/3] Generating Secp256k1 keypair for '{}'...", user_name);
    let secret_key = UserSecretKey::generate();
    let public_key = secret_key.public_key();
    let pk_bytes = public_key.to_bytes();
    let sk_bytes = secret_key.0.to_bytes();

    let key_file = format!("{}.key", user_name);
    fs::write(&key_file, hex_string(&sk_bytes))?;
    println!("      Private key saved to: {}", key_file);
    println!("      Public Key (hex):    {}", hex_string(&pk_bytes));

    println!("\n[2/3] Enrolling public key into bank database...");
    registry.register(&user_name, &public_key)?;

    println!("\n[3/3] Verification: Checking user existence in registry...");
    assert!(registry.is_registered(&user_name)?);
    println!("      User '{}' successfully enrolled in SQLite!", user_name);
    println!("=======================================================");

    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
