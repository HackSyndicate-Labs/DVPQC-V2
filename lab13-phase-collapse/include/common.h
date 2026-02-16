#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Open Quantum Safe Library Headers
#include <oqs/oqs.h>

// Cryptographic Constants
// Mapped to specific OQS algorithms for this implementation:
#define KYBER_ALG_NAME OQS_KEM_alg_kyber_512
#define FALCON_ALG_NAME OQS_SIG_alg_falcon_512
#define SESSION_KEY_BYTES 32

// Protocol Constants
#define PROTOCOL_VERSION 0x02

// Context Structure for Key Derivation
// WARN: Be careful with alignment and padding in this struct!
typedef struct {
    uint32_t timestamp; // 4 bytes
    uint8_t  role;      // 1 byte (0=Server, 1=Client)
    // ... Implicit Padding (3 bytes) on 32/64-bit systems ...
    uint32_t version;   // 4 bytes
} KDFContext;

// Function Prototypes

// KEM (Kyber via LibOQS)
void kem_keygen(uint8_t **pk, uint8_t **sk);
void kem_encapsulate(const uint8_t *pk, uint8_t **ct, uint8_t **ss);
void kem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t **ss);
void kem_free(uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss);

// Signature (Falcon via LibOQS)
void sign_message(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len, const uint8_t *sk);
int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk);

// KDF
void derive_session_key(const uint8_t *shared_secret, KDFContext ctx, uint8_t *out_key);

// Utils
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif // COMMON_H
