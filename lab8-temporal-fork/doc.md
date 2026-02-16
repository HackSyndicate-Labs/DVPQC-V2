# Fault Injection & Side-Channel Analysis (SCA)

## Overview
Post-Quantum Cryptography algorithms like Dilithium are mathematically secure against quantum computers. However, the **physical implementation** of these algorithms can be vulnerable to attacks that exploit the hardware's behavior.

## The Attack Vector: Power Glitching
Digital circuits rely on a stable voltage supply to differentiate between logic `0` and `1`.
- **Voltage Drop (Sag):** If the voltage drops below a threshold, a transistor might fail to switch state in time for the clock cycle.
- **Instruction Skip:** This can cause the CPU to misinterpret an instruction, often treating a complex conditional check (like signature verification) as a simple `NOP` (No Operation) or taking the wrong branch.

## Mechanism in Lab 8
This lab simulates a **Software-Defined Radio / Embedded Controller**.
1.  **Hamming Weight Leakage:** The power consumption of the device is directly proportional to the number of bits flipped during data processing.
2.  **Input Dependency:** By crafting a specific input pattern (e.g., a block of high-density 1s), an attacker can force the simulated voltage regulator to undershoot or overshoot.
3.  **Temporal Precision:** The glitch must occur **exactly** when the critical verification instruction is executing.

## Real-World Mitigation
- **Constant-Time Execution:** Algorithms should not branch based on secret data.
- **Random Delays:** Inserting random `NOP`s to desynchronize attackers.
- **Hardware Hardening:** Brown-out detectors (BOD) that reset the chip if voltage fluctuates.

## 4. Post-Mortem
The system failed due to a physical fault injection attack.
