#include "../include/common.h"

// Vulnerable KDF Implementation
// This function derives a session key by mixing the Shared Secret with the KDF Context.

void derive_session_key(const uint8_t *shared_secret, KDFContext ctx, uint8_t *out_key) {
    // We want to mix the Shared Secret AND the Context (Timestamp, Role, Version)
    // into the final key.
    
    // We read the raw bytes of the struct 'ctx' to mix into the key.
    
    // Simulating a Hash Function (e.g. SHAKE256)
    // Here we just XOR/Add bytes for demonstration.
    
    const uint8_t *ctx_bytes = (const uint8_t *)&ctx;
    
    for (int i = 0; i < SESSION_KEY_BYTES; i++) {
        // Start with the shared secret byte
        uint8_t k = shared_secret[i];
        
        // Mix in the context bytes cyclically
        // We read sizeof(KDFContext) bytes. This INCLUDES the padding!
        for (int j = 0; j < sizeof(KDFContext); j++) {
            k ^= ctx_bytes[j] + (i * j);
        }
        
        out_key[i] = k;
    }
    
    printf("[DEBUG] Deriving Key... Context Size: %zu bytes\n", sizeof(KDFContext));
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for(size_t i=0; i<len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
