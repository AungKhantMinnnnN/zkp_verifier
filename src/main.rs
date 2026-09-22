fn main() {
    println!("===========================================================");
    println!("       ZKP-Fintech: Private Identity Verifier              ");
    println!("===========================================================");
    println!("Available Binaries:");
    println!("  • Bank TCP Server:    cargo run --bin bank_server");
    println!("  • User TCP Client:    cargo run --bin user_client [-- --tamper]");
    println!("  • Kafka Verifier:     cargo run --bin kafka_verifier");
    println!("  • Kafka Prover:       cargo run --bin kafka_prover [-- --tamper]");
    println!();
    println!("Run tests:");
    println!("  cargo test");
    println!("===========================================================");
}