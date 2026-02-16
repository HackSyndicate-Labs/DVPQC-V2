# KYB-03: Entropy Collapse

## 🌌 Mission Briefing
**Role:** Chaos Engineer
**Location:** The Void Station

"The random number generator isn't random. The universe seems to be repeating itself. We are seeing duplicate keys generated in different sectors."

A secure KEM like Kyber relies entirely on the quality of its random seed for generating the public/secret keypair. Our C++ implementation of the RNG seems... predictable.

## 🛠️ Technology Stack
*   **Algorithm**: Kyber
*   **Implementation**: C++
*   **Library**: PQClean

## 🔬 Analysis Objectives
Cryptographic keys must be generated from high-entropy sources (`/dev/urandom`, hardware RNG).
Common failures include seeding with `time(NULL)`, using a small seed space, or reusing seeds.

**Your Objective:**
1.  Audit the `randombytes()` implementation or how it is called during Key Generation.
2.  Determine the source of entropy. Is it truly random?
3.  Predict the next "random" key or recover a previous one by bruteforcing the weak seed.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Weak Randomness / RNG
*   **Impact**: Total Compromise

> "Chaos is order, if you know the seed."
