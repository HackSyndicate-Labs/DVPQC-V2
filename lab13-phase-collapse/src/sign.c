#include "../include/common.h"

// Falcon-512 Implementation using LibOQS

void sign_message(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len, const uint8_t *sk) {
    OQS_SIG *sig_alg = OQS_SIG_new(FALCON_ALG_NAME);
    if (sig_alg == NULL) {
        fprintf(stderr, "Error: OQS_SIG_new failed\n");
        exit(1);
    }

    *sig = malloc(sig_alg->length_signature);
    *sig_len = sig_alg->length_signature;

    if (OQS_SIG_sign(sig_alg, *sig, sig_len, msg, msg_len, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: OQS_SIG_sign failed\n");
        exit(1);
    }

    OQS_SIG_free(sig_alg);
}

int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    OQS_SIG *sig_alg = OQS_SIG_new(FALCON_ALG_NAME);
    if (sig_alg == NULL) exit(1);

    int result = OQS_SIG_verify(sig_alg, msg, msg_len, sig, sig_len, pk);
    
    OQS_SIG_free(sig_alg);
    
    return (result == OQS_SUCCESS) ? 1 : 0;
}
