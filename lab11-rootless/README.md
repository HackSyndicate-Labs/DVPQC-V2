# SPH-02: Rootless

## 🌌 Mission Briefing
**Role:** Root Administrator
**Location:** Core Server, Sector 0

"The Mother Tree has lost its connection. Applications are accepting signatures from trees with unknown roots. Reality is fragmenting into unverified branches."

A SPHINCS+ signature contains the public key (Root Hash) implicitly or explicitly. The verifier MUST check that the signature's computed root matches the trusted public key.

## 🛠️ Technology Stack
*   **Algorithm**: SPHINCS+
*   **Implementation**: C++
*   **Library**: `liboqs` wrapper

## 🔬 Analysis Objectives
Verification involves recomputing the root of the Merkle Tree from the signature and the message.
The final step—comparing `ComputedRoot` vs `TrustedRoot`—is the most critical line of code.

**Your Objective:**
1.  Audit the `Verifier::verify()` method in `src/verifier.cpp`.
2.  Investigate how the "Root Hash" is compared. Is it a full comparison? A partial check?
3.  Forge a signature by finding a collision or exploiting a weak comparison to mimic a valid root.

## ⚠️ Classification
*   **Difficulty**: Medium ⚡
*   **Category**: Improper Verification
*   **Impact**: Signature Forgery

> "A tree without a root is just firewood."
