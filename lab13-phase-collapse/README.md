# MIX-02: Phase Collapse

## 🌌 Mission Briefing
**Role:** Phase Architect
**Location:** The Divergence Point

"The lab has entered a Phase Collapse. The KEM works, the Signatures allow access, but the Client and Server effectively exist in different realities. They cannot talk."

The Key Derivation Function (KDF) is the bridge between the raw shared secret and the usable session keys. It must be deterministic and identical on both sides.

## 🛠️ Technology Stack
*   **Algorithm**: Hybrid (Falcon + Kyber)
*   **Implementation**: C (Static Analysis)
*   **Library**: liboqs / PQClean

## 🔬 Analysis Objectives
In C, memory management is manual. Structs carry more than just data—they carry padding and alignment bytes.
If a KDF mistakenly incorporates uninitialized memory (padding) into the key generation, the keys will diverge based on stack artifacts.

**Your Objective:**
1.  Audit the `src/kdf.c` source code.
2.  Identify where `uninitialized memory` is being read.
3.  Explain why `Hash(Secret || Context_Server)` != `Hash(Secret || Context_Client)`.
4.  Propose a fix to stabilize the phase.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Memory Safety / Uninitialized Read
*   **Impact**: Denial of Service / Key Divergence

> "The dust on the stack is enough to collapse the universe."
