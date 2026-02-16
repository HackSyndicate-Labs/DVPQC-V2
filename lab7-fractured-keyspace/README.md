# DLT-01: Fractured Keyspace

## 🌌 Mission Briefing
**Role:** Dimensional Stabilizer
**Location:** Sector 9 (Parallel)

"The bunker has suffered a dimensional fracture. We are seeing duplicates of our cryptographic operations in parallel realities. The same 'randomness' is being used twice."

Dilithium-2 (ML-DSA) is a fiat-shamir signature scheme dependent on unique, non-repeating nonces for every signature. If the randomness repeats for different messages using the same secret key, the security collapses.

## 🛠️ Technology Stack
*   **Algorithm**: Dilithium-2 (ML-DSA)
*   **Implementation**: Rust
*   **Library**: `liboqs` bindings

## 🔬 Analysis Objectives
Usually, Dilithium is deterministic (deriving 'r' from the message and secret key) to avoid this exact problem. However, this implementation attempts to add "extra entropy" manually but fails to update the state correctly.

**Your Objective:**
1.  Analyze the `sign()` function in `src/main.rs`.
2.  Identify how the "nonce" or "y-vector" is generated.
3.  Find two signatures that share the same randomness but sign different messages.
4.  Use these "Fractured" signatures to recover the secret signing key.

## ⚠️ Classification
*   **Difficulty**: Medium ⚡
*   **Category**: Cryptographic Logic / Nonce Reuse
*   **Impact**: Secret Key Recovery

> "Two realities, one seed. A fatal collision."
