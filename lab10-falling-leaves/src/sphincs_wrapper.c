/**
 * SPHINCS+ Wrapper — Clean PQClean Interface
 * ============================================
 * Thin wrapper around PQClean SPHINCS+-SHA2-128f-simple.
 * This module contains NO vulnerabilities.
 */

#include <string.h>
#include "lab10.h"
#include "api.h"

int spx_keygen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

int spx_sign(uint8_t *sig, size_t *siglen,
             const uint8_t *msg, size_t msglen,
             const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(
        sig, siglen, msg, msglen, sk);
}

int spx_verify(const uint8_t *sig, size_t siglen,
               const uint8_t *msg, size_t msglen,
               const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
        sig, siglen, msg, msglen, pk);
}
