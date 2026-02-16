# QUA-02: Quantum Drift

## 🌌 Mission Briefing
**Role:** Precision Engineer
**Location:** High-Energy Physics Lab, Deep Space

"The universal constants are drifting. Our floating-point units are no longer reliable for high-precision quantum cryptography."

The Falcon signature scheme relies on precise calculations over `FFT` domains. We implemented a custom version using standard `double` precision floating-point arithmetic. However, adversaries are seemingly able to predict our secret polynomials.

## 🛠️ Technology Stack
*   **Algorithm**: Falcon (Fast Fourier Transform based)
*   **Implementation**: Custom / `liboqs` based
*   **Language**: C++

## 🔬 Analysis Objectives
Falcon is unique among PQC algorithms because it heavily utilizes floating-point arithmetic.
For security, these operations must be constant-time and free of data-dependent rounding errors.

**Your Objective:**
1.  Audit the floating-point operations in the signature generation path.
2.  Investigate if the lack of constant-time guarantees or specific rounding behaviors leaks information about the secret key.
3.  Demonstrate how the "Drift" (precision loss/leakage) compromises the system.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Side-Channel / Floating-Point Leakage
*   **Impact**: Full Key Recovery

> "In the quantum realm, close enough is not enough."
