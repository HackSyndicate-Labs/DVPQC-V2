# Damn Vulnerable Post-Quantum Cryptography Labs (DVPQC-V2)

![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-blue)
![Focus](https://img.shields.io/badge/Focus-Offensive%20Security-red)
![Maintainer](https://img.shields.io/badge/Maintainer-Mauro%20Carrillo-blue)

## Overview

**Damn Vulnerable PQC Labs V2** is a comprehensive suite of security laboratories designed to demonstrate, analyze, and exploit implementation flaws in Post-Quantum Cryptography (PQC) systems. This project is not a critique of the mathematical robustness of algorithms like Kyber, Dilithium, Falcon, or SPHINCS+, but rather an educational platform that highlights how implementation errors—such as side-channel leaks, improper validation, bad randomness, or memory corruption—can compromise even the most secure cryptographic primitives.

This repository is curated by **HackSyndicate** and led by **Mauro Carrillo** to provide realistic, rigorous scenarios for security auditors and cryptographers. The labs are based on real-world findings and theoretical attack vectors, adapted for an academic and offensive security training environment.

## Purpose and Scope

The primary objective of this project is to train security professionals in the art of **PQC Auditing**. As the world transitions to quantum-resistant standards, the attack surface shifts from mathematical cryptanalysis to implementation security.

*   **Academic Use Only**: These labs are intended for study, research, and training purposes.
*   **Offensive Focus**: The methodology is offensive-first. Understanding how to break these implementations is the prerequisite for learning how to secure them.
*   **Vulnerability Context**: The vulnerabilities presented here reside in the *implementation layer* (C, C++, Go, Python, Rust code), not in the NIST-standardized algorithms themselves.

## Project Statistics

| Metric | Count |
| :--- | :--- |
| **Total Laboratories** | 13 |
| **Vulnerabilities Covered** | 20+ |
| **PQC Algorithms** | 7 (Falcon, Kyber, Dilithium, SPHINCS+, X25519, etc.) |
| **Languages** | C, C++, Go, Rust, Python |

## Laboratory Inventory

The following table lists the currently available laboratories, categorized by algorithm and difficulty.

| ID | Name | Vulnerability | Algorithm | Library | Language | Difficulty |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **QUA-01** | Event Horizon | Gaussian Sampler Weakness | Falcon-512 | PQClean | C++ | Hardcore |
| **QUA-02** | Quantum Drift | Floating-Point Leakage | Falcon | liboqs | C++ | Hardcore |
| **QUA-03** | Zero Trace | Improper Signature Verification | Falcon | liboqs | Go | Medium |
| **KYB-01** | Frozen Lattice | Side-Channel Timing Leak | Kyber-512 | PQClean | C | Hardcore |
| **KYB-02** | Crystal Echo | Incorrect IND-CCA Transform | Kyber | liboqs | Python | Low |
| **KYB-03** | Entropy Collapse | Insufficient RNG | Kyber | PQClean | C++ | Hardcore |
| **DLT-01** | Fractured Keyspace | Key Reuse (ML-DSA) | Dilithium-2 | liboqs | Rust | Medium |
| **DLT-02** | Temporal Fork | Fault Injection | Dilithium-3 | PQClean | C | Hardcore |
| **DLT-03** | Silent Vector | W-Vector Leakage | Dilithium | liboqs | Python | Low |
| **SPH-01** | Falling Leaves | Tree Traversal Weakness | SPHINCS+ | PQClean | C | Hardcore |
| **SPH-02** | Rootless | Bad Root Verification | SPHINCS+ | liboqs | C++ | Medium |
| **MIX-01** | Quantum Mirage | Hybrid KEM Mis-Binding | Kyber + X25519 | liboqs (Circl) | Go | Medium |
| **MIX-02** | Phase Collapse | Incorrect Key Derivation | Falcon + Kyber | PQClean (liboqs) | C | Hardcore |

## Credits

**HackSyndicate**
*   **Project Lead & Architect**: Mauro Carrillo

This project is the result of extensive research into the failure modes of next-generation cryptography. Special thanks to the open-source community for tools like `liboqs`, `PQClean`, and `Circl`, which serve as the foundation for these demonstrations.

## Disclaimer

**Damn Vulnerable PQC Labs** is intended for **educational and research purposes only**. The code in this repository contains intentional vulnerabilities and should **NEVER** be used in a production environment. The authors are not responsible for any misuse of the information or code provided herein.

## Usage

Each laboratory is self-contained in its own directory. To get started:

1.  Navigate to a lab directory (e.g., `cd lab1-gaussian-sampler-weakness`).
2.  Read the `README.md` within the lab folder for specific vulnerability details and instructions.
3.  Follow the build and run instructions provided in the lab's documentation.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
