# DLT-02: Temporal Fork

## 🌌 Mission Briefing
**Role:** Chrono-Debugger
**Location:** Timeline Beta (Unstable)

"A temporal fork is causing our processors to skip instructions. The verification logic sometimes... just doesn't happen."

Validating a Dilithium-3 signature involves complex polynomial arithmetic and bounds checks. The hardware running this verification is under stress from the anomaly, causing occasional "glitches" where instructions are skipped.

## 🛠️ Technology Stack
*   **Algorithm**: Dilithium-3
*   **Implementation**: C (Embedded style)
*   **Technique**: Fault Injection Simulation

## 🔬 Analysis Objectives
Fault Injection Attacks (FIA) exploit hardware glitches to bypass security checks.
In this lab, we simulate these glitches in software.

**Your Objective:**
1.  Review the `verify.c` code logic.
2.  Identify critical branches (e.g., `if (check_norm(...) != 0) return INVALID;`).
3.  Simulate a "glitch" (instruction skip) that bypasses this check.
4.  Forge a signature that is mathematically garbage but accepted by the "glitched" verifier.

## ⚠️ Classification
*   **Difficulty**: Hardcore 💀
*   **Category**: Fault Injection / Glitching
*   **Impact**: Signature Forgery

> "The universe didn't verify that. Why should we?"
