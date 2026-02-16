# KYB-01: Frozen Lattice

## 🌌 Mission Briefing
**Role:** Cryo-Security Engineer
**Location:** Sector 7, Ice Planet Hoth (Simulation)

"The Lattice Reactor has frozen over. While operational, it's emitting precise temporal patterns that shouldn't exist. The enemy is listening to the ticking."

Our Kyber-512 implementation (based on `reference_implementation`) is intended to run in constant time. However, deep scans suggest that the decryption process varies in duration depending on the secret key structure.

## 🛠️ Technology Stack
*   **Algorithm**: Kyber-512 (ML-KEM)
*   **Implementation**: C (Reference Style)
*   **Standard**: PQClean

## 🔬 Analysis Objectives
Kyber is a lattice-based KEM. To prevent side-channel attacks, every operation involving secret data (polynomial addition, multiplication, modular reduction) must take the exact same number of CPU cycles.

**Your Objective:**
1.  Isolate the `indcpa_dec` and `verify` functions.
2.  Use a timing harness (or static analysis) to confirm if conditional branches depend on secret data.
3.  "Thaw" the code: Remove the timing dependencies to secure the reactor.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Side-Channel / Timing Attack
*   **Impact**: Key Recovery (Remote)

> "Time is a flat circle, unless you leak it."
