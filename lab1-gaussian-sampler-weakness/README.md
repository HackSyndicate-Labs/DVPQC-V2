# QUA-01: Event Horizon

## 🌌 Mission Briefing
**Role:** Quantum Analyst
**Location:** Station Alpha, Sagittarius A* Orbit

"We are trapped near the event horizon of a supermassive black hole. The gravitational forces are interfering with our Gaussian Samplers. The distributions are... unstable."

Your job is to diagnose the **Falcon-512 Signature Module**. It generates signatures, but the Command Center reports that the signatures are exhibiting strange statistical anomalies. If we don't fix the sampler, the secure channel home will collapse.

## 🛠️ Technology Stack
*   **Algorithm**: Falcon-512 (NIST PQC Standard)
*   **Standard Library**: `PQClean` (Reference Implementation)
*   **Language**: C++

## 🔬 Analysis Objectives
The module uses a Gaussian Sampler to generate the trapdoor perturbations required for Falcon signatures.
Ideally, this sampler should be statistically indistinguishable from a true discrete Gaussian distribution.

**Your Objective:**
1.  Review the `sampler.cpp` implementation.
2.  Determine why the output deviates from the expected distribution.
3.  Identify the implementation flaw that allows an attacker to recover the secret key from the signature set.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Cryptographic Implementation / Side-Channel
*   **Impact**: Key Recovery

> "The horizon is silent, but the math screams."
