# KYB-02: Crystal Echo

## 🌌 Mission Briefing
**Role:** Signal Analyst
**Location:** Crystal Caverns, Sub-Terra

"We are hearing echoes from inside the module. When we send malformed crystals (ciphertexts) into the chamber, the device responds... differently."

The cryptographic module implements Kyber (CCA-secure KEM). It is supposed to handle invalid ciphertexts silently by returning a pseudorandom shared secret. However, reports verify that sending specific invalid ciphertexts allows an attacker to deduce the internal state.

## 🛠️ Technology Stack
*   **Algorithm**: Kyber (ML-KEM)
*   **Implementation**: Python (`liboqs` wrapper)
*   **Vulnerability Class**: Oracle Attack

## 🔬 Analysis Objectives
The Fujisaki-Okamoto (FO) transform is what makes Kyber CCA-secure. It re-encrypts the decrypted message and checks if it matches the received ciphertext.
If this check is skipped, implemented incorrectly, or leaks the result, the scheme degrades to CPA-secure only.

**Your Objective:**
1.  Examine the `decapsulate()` function in the Python wrapper.
2.  Identify the flaw in the Re-Encryption check (FO Transform).
3.  Exploit the "Echo": Use the failure behavior to decrypt a captured session key.

## ⚠️ Classification
*   **Difficulty**: Low 🟢
*   **Category**: Cryptographic Logic / Oracle Attack
*   **Impact**: Session Hijacking / Decryption

> "The crystals sing to those who listen."
