#include "../include/common.h"

// Kyber-512 Implementation using LibOQS
// Wraps OQS_KEM family functions for key encapsulation.

void kem_keygen(uint8_t **pk, uint8_t **sk) {
    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (kem == NULL) {
        fprintf(stderr, "Error: OQS_KEM_new failed\n");
        exit(1);
    }

    *pk = malloc(kem->length_public_key);
    *sk = malloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, *pk, *sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: OQS_KEM_keypair failed\n");
        free(*pk); free(*sk);
        exit(1);
    }
    
    // Cleanup container, keep keys
    OQS_KEM_free(kem);
}

void kem_encapsulate(const uint8_t *pk, uint8_t **ct, uint8_t **ss) {
    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (kem == NULL) exit(1);

    *ct = malloc(kem->length_ciphertext);
    *ss = malloc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, *ct, *ss, pk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: OQS_KEM_encaps failed\n");
        exit(1);
    }

    OQS_KEM_free(kem);
}

void kem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t **ss) {
    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (kem == NULL) exit(1);

    *ss = malloc(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, *ss, ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: OQS_KEM_decaps failed\n");
        exit(1);
    }

    OQS_KEM_free(kem);
}

void kem_free(uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss) {
    if (pk) free(pk);
    if (sk) free(sk);
    if (ct) free(ct);
    if (ss) free(ss);
}
