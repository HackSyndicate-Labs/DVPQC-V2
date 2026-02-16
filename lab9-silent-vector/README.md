# DLT-03: Silent Vector

## 🌌 Mission Briefing
**Role:** Signal Interceptor
**Location:** Listening Post 4

"There is a signal cutting through the noise. It's silent to most, but our sensors picked up a trace. The vectors are leaking."

During the signing process of Dilithium, an intermediate vector `w` is calculated. It is supposed to be kept secret until it is compressed and hinted. However, a debug channel or side-channel seems to be leaking partial information about `w` before the rejection sampling step.

## 🛠️ Technology Stack
*   **Algorithm**: Dilithium
*   **Implementation**: Python (`liboqs`)
*   **Vulnerability Class**: Information Leakage

## 🔬 Analysis Objectives
The security of Dilithium relies on the "Learning With Errors" (LWE) hardness, specifically `A*s + e`.
If parts of the error or intermediate vectors are known, the lattice problem becomes significantly easier to solve.

**Your Objective:**
1.  Analyze the `signer.py` script.
2.  Locate the unintended output/log that reveals parts of the internal state.
3.  Use this "Silent" leakage to reduce the search space for the secret key.

## ⚠️ Classification
*   **Difficulty**: Low 🟢
*   **Category**: Information Leakage
*   **Impact**: Key Recovery / Security Reduction

> "Silence is loud if you know what to listen for."
