# Crystal Echo - Architecture Documentation

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Crystal Lattice Security Systems                  │
│                      Echo Chamber Module v2.1                        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         Protocol Layer                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    ProtocolHandler                           │   │
│  │  - Message parsing/serialization                            │   │
│  │  - Session management                                        │   │
│  │  - Request routing                                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Application Layer                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      EchoChamber                             │   │
│  │  - Session lifecycle                                         │   │
│  │  - Key exchange orchestration                                │   │
│  │  - Statistics & monitoring                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                    │                                 │
│                    ┌───────────────┴───────────────┐                │
│                    ▼                               ▼                │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐  │
│  │         KeyStore            │  │        FOTransform          │  │
│  │  - Key storage              │  │  - FO transformation        │  │
│  │  - Key rotation             │  │  - Re-encryption logic      │  │
│  │  - Expiration               │  │  - ⚠️ VULNERABLE ⚠️         │  │
│  └─────────────────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Cryptographic Layer                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      CrystalKEM                              │   │
│  │  - liboqs wrapper                                            │   │
│  │  - Kyber768 operations                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                    │                                 │
│                                    ▼                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                       liboqs                                 │   │
│  │  - Reference Kyber implementation                            │   │
│  │  - NIST-compliant                                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### 1. CrystalKEM (`crystal_kem.py`)

The lowest-level cryptographic wrapper around liboqs Kyber.

**Responsibilities:**
- Keypair generation
- Raw encapsulation
- Raw decapsulation (without FO transform)
- Hash utilities

**Security Notes:**
- This component is secure - it's a thin wrapper around liboqs
- The vulnerability is NOT in this layer

### 2. FOTransform (`fo_transform.py`)

The Fujisaki-Okamoto transformation layer. **THIS IS WHERE THE VULNERABILITY LIVES.**

**Responsibilities:**
- Convert CPA-secure Kyber to CCA-secure KEM
- Re-encryption verification
- Implicit rejection handling

**Vulnerabilities:**
- `_should_skip_reencryption()`: Bypasses re-encryption for high-entropy inputs
- `_compare_ciphertexts()`: Not constant-time
- `_compute_shared_secret()`: Leaks validity through error handling

### 3. KeyStore (`key_store.py`)

Persistent storage for Kyber keypairs.

**Responsibilities:**
- Store/retrieve keypairs by ID
- Handle key expiration
- Eviction policy

**Security Notes:**
- Generally secure
- Keys are stored in memory (would need secure storage in production)

### 4. EchoChamber (`echo_chamber.py`)

Main orchestration layer for key exchanges.

**Responsibilities:**
- Session management
- Coordinate encapsulation/decapsulation
- Statistics collection

**Vulnerabilities:**
- Exposes too much internal state
- `validate_ciphertext()` acts as an oracle
- `compare_with_reference()` is a differential oracle

### 5. ProtocolHandler (`protocol_handler.py`)

Network protocol implementation.

**Responsibilities:**
- Message serialization
- Request routing
- Error responses

**Vulnerabilities:**
- Error codes leak information
- Different responses for different error types

## Data Flow

### Normal Key Exchange

```
Client                              Server
   │                                   │
   │──── KEYGEN Request ──────────────>│
   │                                   │ generate_keys()
   │<─── Public Key ───────────────────│
   │                                   │
   │ encapsulate(pk)                   │
   │──── Ciphertext ──────────────────>│
   │                                   │ decapsulate(ct)
   │                                   │  └── FOTransform.decapsulate()
   │                                   │       └── ⚠️ May bypass checks ⚠️
   │<─── Success ──────────────────────│
   │                                   │
[Shared Secret]                  [Shared Secret]
```

### Vulnerable Path (Entropy Bypass)

```
Attacker                            Server
   │                                   │
   │ Create high-entropy CT            │
   │ (>200 unique bytes)               │
   │                                   │
   │──── Malformed CT ────────────────>│
   │                                   │ FOTransform.decapsulate()
   │                                   │  ├── _validate_ciphertext_length() ✓
   │                                   │  ├── _should_skip_reencryption()
   │                                   │  │    └── entropy > 0.7? YES!
   │                                   │  │    └── SKIP RE-ENCRYPTION ⚠️
   │                                   │  └── Return "valid" result
   │<─── Success ──────────────────────│
   │                                   │
[Attacker knows]               [Wrong Shared Secret]
[result was "valid"]           [But thinks it's valid]
```

## Security Analysis

### Attack Surface

1. **Ciphertext Input**: Primary attack vector
2. **Timing Oracle**: Observable through network latency
3. **Error Oracle**: Different error codes/behaviors
4. **State Exposure**: Debug/monitoring interfaces

### Threat Model

- **Attacker capability**: Can submit arbitrary ciphertexts
- **Attacker goal**: Break IND-CCA security, recover key material
- **Attack type**: Chosen-ciphertext attack with oracle access

### Vulnerability Impact

| Vulnerability | Impact | Exploitability |
|--------------|--------|----------------|
| Entropy Bypass | Critical | Easy |
| Timing Leak | High | Medium |
| Error Oracle | High | Easy |
| State Exposure | Medium | Easy |

## Mitigation Recommendations

1. **Never skip re-encryption** - Always verify CT validity
2. **Use constant-time comparison** - `hmac.compare_digest()`
3. **Implement proper implicit rejection** - Indistinguishable errors
4. **Remove debug interfaces** - No state/timing exposure
5. **Validate all inputs** - Comprehensive CT validation
