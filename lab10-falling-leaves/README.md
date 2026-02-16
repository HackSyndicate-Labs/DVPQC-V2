# SPH-01: Falling Leaves

## 🌌 Mission Briefing
**Role:** Arbo-Cryptographer
**Location:** The Great Canopy (Virtual)

"The Quantum Mega-Tree is shedding. Leaves that should be securely attached to the Merkle structure are falling into unauthorized hands. We are seeing path exposures."

SPHINCS+ is a stateless hash-based signature scheme. It relies on massive Merkle Trees. The security depends on the secrecy of the authentication paths and the one-time signature (WOTS+) leaves.

## 🛠️ Technology Stack
*   **Algorithm**: SPHINCS+
*   **Implementation**: C
*   **Library**: PQClean

## 🔬 Analysis Objectives
The tree traversal algorithm determines which nodes need to be computed to generate an authentication path.
If this logic is flawed, it might reuse WOTS+ keys or reveal neighboring nodes that should remain secret.

**Your Objective:**
1.  Study the `tree.c` implementation.
2.  Trace the `compute_auth_path()` function.
3.  Identify the index miscalculation that exposes privileged tree nodes.
4.  Recover a valid path for a forged message.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Logic Error / Tree Traversal
*   **Impact**: Component Forgery

> "When the leaves fall, the root is exposed."
