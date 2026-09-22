# ZKP-Fintech: Private Identity Verifier

A high-performance, asynchronous Rust project implementing Zero-Knowledge Proofs (ZKP) to verify user identity without sensitive data exchange. Built for the intersection of Fintech and Cybersecurity.

---

## 🛠 Tech Stack

| Component         | Technology            | Why?                                                                 |
|:------------------|:----------------------|:---------------------------------------------------------------------|
| **Language** | **Rust** | Memory safety, zero-cost abstractions, and fearless concurrency.      |
| **Cryptography** | `k256` (Secp256k1)    | Industry standard for Bitcoin/Ethereum; high-performance ECC.        |
| **Math Traits** | `ff` & `PrimeField`   | Robust finite-field arithmetic and trait-based abstractions.         |
| **Async Runtime** | **Tokio** | Non-blocking I/O for handling high-frequency financial connections.  |
| **Streaming / Bus**| `rskafka`             | 100% pure-Rust async Kafka client for distributed verification pipelines. |
| **Framing**       | `tokio-util` (Codec)  | Length-delimited framing to prevent packet fragmentation over TCP.    |
| **Serialization** | `Serde` & `Bincode`   | Efficient, type-safe binary serialization for network packets.       |
| **Error Handling**| `thiserror` & `anyhow`| Differentiates between math errors, codec errors, and network failures.|

---

## 🗺 Project Roadmap

### Phase 1: Cryptographic Core (Completed)
- [x] Implement Schnorr Identification Protocol (Non-interactive via Fiat-Shamir).
- [x] Define Newtype wrappers for `UserSecretKey` and `UserPublicKey` for type safety.
- [x] Unit testing for "Happy Path" and "Malicious Alteration" (tamper detection).
- [x] Fixed byte-alignment issues (33-byte points vs 32-byte scalars).

### Phase 2: Asynchronous Networking & Kafka (Completed)
- [x] Build a Tokio TCP Server (The "Bank" Verifier) in [`src/bin/bank_server.rs`](src/bin/bank_server.rs).
- [x] Build a CLI Client (The "User" Prover) in [`src/bin/user_client.rs`](src/bin/user_client.rs).
- [x] Implement a Length-Delimited Codec for framing ZKP messages over TCP in [`src/codec.rs`](src/codec.rs).
- [x] Implement the `From` and `TryFrom` traits for binary wire-transfer of proofs and messages in [`src/protocol.rs`](src/protocol.rs).
- [x] Integrate Apache Kafka using `rskafka` for asynchronous, distributed fintech verification pipelines:
  - [`src/bin/kafka_verifier.rs`](src/bin/kafka_verifier.rs) (Event-driven verification worker)
  - [`src/bin/kafka_prover.rs`](src/bin/kafka_prover.rs) (Event-driven verification requester)
  - [`docker-compose.yml`](docker-compose.yml) (KRaft Apache Kafka container)

### Phase 3: Fintech Features & Security (Completed)
- [x] Persistent storage for User Public Keys (SQLite) in [`src/storage.rs`](src/storage.rs) and CLI enrollment in [`src/bin/enroll_user.rs`](src/bin/enroll_user.rs).
- [x] Replay attack protection using Unix Timestamps and Nonces in the Fiat-Shamir Challenge hash in [`src/zkp_core_engine.rs`](src/zkp_core_engine.rs) and [`src/replay.rs`](src/replay.rs).
- [x] Secure memory handling using the `zeroize` and `zeroize_on_drop` traits for private keys in [`src/zkp_core_engine.rs`](src/zkp_core_engine.rs).

---

## 📖 Documentation

### `zkp_core_engine` Module
The heart of the project. It handles the elliptic curve math required for the Schnorr Proof.

#### Key Structures
* **`UserSecretKey(Scalar)`**: Wraps a private 256-bit integer.
* **`UserPublicKey(ProjectivePoint)`**: Wraps an (x,y) coordinate on the Secp256k1 curve.
* **`Proof`**: The data package sent over the network:
    * `r_point`: The 33-byte compressed commitment ($R$).
    * `s_scalar`: The 32-byte response scalar ($s$).

#### Core Functions
1. **`generate_proof(&sk, &pk)`**: 
   - Picks a random nonce $k$.
   - Computes commitment $R = g^k$.
   - Hashes $R$ and $pk$ to produce a challenge $e$.
   - Computes $s = k + e \cdot sk$.
2. **`verify(&pk, proof)`**: 
   - Reconstructs challenge $e$ using provided $R$ and known $pk$.
   - Validates equation: $g^s == R + (pk \cdot e)$.

---

## 🚀 Running the Project

### 1. Run Unit and Integration Tests
```bash
cargo test
```

---

### 2. Tokio TCP Client/Server (Phase 2)

#### Start the Bank Verifier Server:
```bash
cargo run --bin bank_server
# Listens on 127.0.0.1:8080 by default (or provide custom address: cargo run --bin bank_server -- 127.0.0.1:9000)
```

#### Run the User Prover Client (Happy Path):
```bash
cargo run --bin user_client -- --user alice
```

#### Simulate a Tampered Proof / Fraudulent Prover:
```bash
cargo run --bin user_client -- --user mallory --tamper
```

#### Test Replay Attack Protection (Intercepted duplicate proof):
```bash
cargo run --bin user_client -- --user alice --replay
```

#### Test Unregistered User Rejection:
```bash
cargo run --bin user_client -- --unregistered
```

#### User Enrollment & SQLite Key Management:
```bash
# Enroll a new user in the bank SQLite database (generates and saves <user>.key)
cargo run --bin enroll_user -- --user charlie

# List all registered users in the database
cargo run --bin enroll_user -- --list
```

---

### 3. Kafka Event-Driven Pipeline (`rskafka`)

#### Start Local Kafka (KRaft mode):
```bash
docker compose up -d
```

#### Start the Kafka Verifier Daemon:
```bash
cargo run --bin kafka_verifier
```

#### Run the Kafka Prover (Publishes proof and awaits response):
```bash
# Legitimate user
cargo run --bin kafka_prover -- --user bob_kafka_user

# Attacker / Tampered proof simulation
cargo run --bin kafka_prover -- --user fraudulent_user --tamper

# Replay attack simulation over Kafka
cargo run --bin kafka_prover -- --user bob_kafka_user --replay
```
