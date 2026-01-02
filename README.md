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
| **Serialization** | `Serde` & `Bincode`   | Efficient, type-safe binary serialization for network packets.       |
| **Error Handling**| `thiserror` & `anyhow`| Differentiates between math errors and network failures.             |

---

## 🗺 Project Roadmap

### Phase 1: Cryptographic Core (Completed)
- [x] Implement Schnorr Identification Protocol (Non-interactive via Fiat-Shamir).
- [x] Define Newtype wrappers for `UserSecretKey` and `UserPublicKey` for type safety.
- [x] Unit testing for "Happy Path" and "Malicious Alteration" (tamper detection).
- [x] Fixed byte-alignment issues (33-byte points vs 32-byte scalars).

### Phase 2: Asynchronous Networking (Week 2)
- [ ] Build a Tokio TCP Server (The "Bank" Verifier).
- [ ] Build a CLI Client (The "User" Prover).
- [ ] Implement a Length-Delimited Codec for framing ZKP messages over TCP.
- [ ] Implement the `From` and `TryFrom` traits for binary wire-transfer of proofs.

### Phase 3: Fintech Features & Security (Week 3)
- [ ] Persistent storage for User Public Keys (SQLite/RocksDB).
- [ ] Replay attack protection using Unix Timestamps in the Challenge hash.
- [ ] Secure memory handling using the `zeroize` crate for secrets.

---

## 📖 Documentation

### `zkp_core_engine` Module
The heart of the project. It handles the elliptic curve math required for the Schnorr Proof.

#### Key Structures
* **UserSecretKey(Scalar)**: Wraps a private 256-bit integer.
* **UserPublicKey(ProjectivePoint)**: Wraps an (x,y) coordinate on the Secp256k1 curve.
* **SchnorrProof**: The data package sent over the network:
    * `r_point`: The 33-byte compressed commitment (R).
    * `s_scalar`: The 32-byte response scalar (s).

#### Core Functions
1. **generate_proof(&sk, &pk)**: 
   - Picks a random nonce `k`.
   - Computes commitment `R = g^k`.
   - Hashes `R` and `pk` to produce a challenge `e`.
   - Computes `s = k + e * sk`.
2. **verify(&pk, proof)**: 
   - Reconstructs the challenge `e` using the provided `R` and the known `pk`.
   - Validates the equation: `g^s == R + (pk * e)`.

---

## 🚀 Running the Project

### Prerequisites
* Rust & Cargo (Stable)

### 1. Run Unit Tests
Ensure the math logic and type conversions are sound:
```bash
cargo test
