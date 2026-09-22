use std::env;
use std::fs;
use zkp_verifier::protocol::AuthRequest;
use zkp_verifier::storage::UserRegistry;
use zkp_verifier::tcp::UserProverClient;
use zkp_verifier::zkp_core_engine::{UserSecretKey, ZkpEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut addr = "127.0.0.1:8080".to_string();
    let mut user_id = "alice_fintech".to_string();
    let mut tamper = false;
    let mut replay = false;
    let mut unregistered = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                if i + 1 < args.len() {
                    addr = args[i + 1].clone();
                    i += 1;
                }
            }
            "--user" => {
                if i + 1 < args.len() {
                    user_id = args[i + 1].clone();
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
                println!("Usage: user_client [OPTIONS]");
                println!("Options:");
                println!("  --addr <ADDR>       Bank server address (default: 127.0.0.1:8080)");
                println!("  --user <NAME>       User identity (default: alice_fintech)");
                println!("  --tamper            Corrupt the proof scalar to simulate attack");
                println!("  --replay            Send the exact same proof twice to test replay defense");
                println!("  --unregistered      Use an unregistered username to test registry rejection");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    if unregistered {
        user_id = format!("unknown_user_{}", uuid::Uuid::new_v4());
    }

    println!("=======================================================");
    println!(" 👤 User Prover Client (Phase 3 Hardened Security)     ");
    println!("=======================================================");
    println!("Connecting to Bank at: {}", addr);
    println!("User identity:         {}", user_id);
    println!("Tamper simulation:     {}", tamper);
    println!("Replay simulation:     {}", replay);

    // 1. Key Management: Check if user already has a saved key or auto-enroll into database
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
        
        // Auto-enroll in local bank database if not testing unregistered user
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
    println!("      Public Key (hex): {}", hex_string(&pk_bytes));

    // 2. Connect to the Bank Verifier
    println!("\n[2/3] Connecting to TCP server...");
    let mut client = UserProverClient::connect(&addr).await?;
    println!("      Connected successfully!");

    // 3. Generate ZKP Proof and authenticate
    println!("\n[3/3] Generating Schnorr Non-Interactive Proof (with timestamp & nonce)...");
    let mut proof = ZkpEngine::generate_proof(&secret_key, &public_key);

    if tamper {
        if let Some(last_byte) = proof.s_scalar.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }
    }

    let request = AuthRequest {
        user_id: user_id.clone(),
        public_key: pk_bytes.clone(),
        proof: proof.clone(),
    };

    let start = std::time::Instant::now();
    let response = client.send_raw_request(request.clone()).await?;
    let elapsed = start.elapsed();

    println!("\n--- Bank Response ({:?}) ---", elapsed);
    println!("Status:  {}", if response.success { "✅ VERIFIED" } else { "❌ REJECTED" });
    println!("User:    {}", response.user_id);
    println!("Message: {}", response.message);
    println!("-------------------------------------------------------");

    // 4. Test Replay Attack Defense if requested
    if replay {
        println!("\n🚨 REPLAY ATTACK SIMULATION:");
        println!("Transmitting the exact same intercepted proof packet a second time...");
        let start_replay = std::time::Instant::now();
        let replay_response = client.send_raw_request(request).await?;
        let elapsed_replay = start_replay.elapsed();

        println!("\n--- Bank Response to Replay Attack ({:?}) ---", elapsed_replay);
        println!("Status:  {}", if replay_response.success { "⚠️ VULNERABLE (Verified)" } else { "🛡️ BLOCKED (Rejected)" });
        println!("Message: {}", replay_response.message);
        println!("-------------------------------------------------------");
    }

    // SecretKey automatically zeroized from RAM on drop!
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
