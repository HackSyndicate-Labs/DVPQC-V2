# MIX-01: Quantum Mirage

## 🌌 Mission Briefing
**Role:** Protocol Diplomat
**Location:** The Inter-Realm Border

"We are seeing a Mirage. Communications that claim to be Quantum-Resistant are actually holograms. The connection is secure in one world, but completely open in the other."

Hybrid Key Exchange combines a Classical Algorithm (X25519) with a Post-Quantum Algorithm (Kyber) to provide defense-in-depth. Both keys must be bound together to derive the final session secret.

## 🛠️ Technology Stack
*   **Algorithm**: Hybrid (Kyber-512 + X25519)
*   **Implementation**: Go
*   **Library**: Cloudflare Circl (`github.com/cloudflare/circl`)

## 🔬 Analysis Objectives
A "Mis-Binding" or "Downgrade" attack occurs when an attacker can strip the Quantum component from the handshake without the endpoints noticing.
This usually happens if the session key derivation is not strictly dependent on the negotiation transcript.

**Your Objective:**
1.  Analyze the `handshake.go` protocol flow.
2.  Determine how the Session Key is calculated. Is the Kyber key *mandatory*?
3.  Execute a Man-in-the-Middle (MITM) attack to strip the Kyber public key.
4.  Force the client and server to agree on a Classical-only key (Downgrade).

## ⚠️ Classification
*   **Difficulty**: Medium ⚡
*   **Category**: Downgrade Attack / Binding Protocol
*   **Impact**: Loss of Forward Secrecy (Harvest Now, Decrypt Later)

> "It looks like security, but it's just a reflection."
