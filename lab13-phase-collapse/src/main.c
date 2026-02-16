#include "../include/common.h"

// Simulation of "Phase Collapse"
// We simulate a Client and a Server executing the protocol.
// Even though they agree on the Kyber Shared Secret, they will derive DIFFERENT Session Keys.

void simulate_server(const uint8_t *shared_secret) {
    printf("\n--- SERVER SIDE ---\n");
    
    // 1. Initialize Context
    // BAD PRACTICE: Field-by-field initialization leaves padding uninitialized!
    KDFContext ctx;
    ctx.timestamp = 0x12345678;
    ctx.role = 0; // Server
    ctx.version = PROTOCOL_VERSION;
    
    // Note: We did NOT do memset(&ctx, 0, sizeof(ctx));
    // So the 3 bytes of padding after 'role' are UNINITIALIZED.
    
    uint8_t session_key[SESSION_KEY_BYTES];
    derive_session_key(shared_secret, ctx, session_key);
    
    print_hex("Server Derived Key", session_key, SESSION_KEY_BYTES);
}

void simulate_client(const uint8_t *shared_secret) {
    printf("\n--- CLIENT SIDE ---\n");
    
    // To ensure "different" garbage on the stack, we put some dummy variables here
    // or call a function to dirty the stack.
    volatile uint8_t garbage[100];
    memset((void*)garbage, 0xCC, sizeof(garbage)); 
    
    // 1. Initialize Context
    // The "Client" agreed on these values via the handshake transcript...
    KDFContext ctx;
    ctx.timestamp = 0x12345678; // Same timestamp
    ctx.role = 0; // Role copied from session agreement
    ctx.version = PROTOCOL_VERSION;
    
    // Again, field-by-field. The padding bytes here (on Client stack) will be DIFFERENT
    // from the padding bytes on the Server stack.
    
    uint8_t session_key[SESSION_KEY_BYTES];
    derive_session_key(shared_secret, ctx, session_key);
    
    print_hex("Client Derived Key", session_key, SESSION_KEY_BYTES);
}

int main() {
    printf("Lab 13: Phase Collapse (Audit Mode)\n");
    printf("Demonstrating Non-Deterministic Key Derivation due to Uninitialized Padding\n");
    // 1. Simulate Kyber Key Exchange
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *ct = NULL;
    uint8_t *ss_server = NULL;
    uint8_t *ss_decapped = NULL;
    
    printf("\n[+] Generating Kyber-512 Keypair...\n");
    kem_keygen(&pk, &sk);
    
    printf("[+] Encapsulating (Server generates shared secret)...\n");
    kem_encapsulate(pk, &ct, &ss_server);
    
    printf("[+] Decapsulating (Client recovers shared secret)...\n");
    kem_decapsulate(ct, sk, &ss_decapped);
    
    if (memcmp(ss_server, ss_decapped, 32) == 0) {
        printf("[+] Kyber Shared Secrets Match!\n");
    } else {
        printf("[-] Fatal: Shared Secrets do not match!\n");
        return 1;
    }
    
    // 2. Derive Session Keys (The Flaw)
    // We pass the SAME shared secret to both simulations.
    simulate_server(ss_server);
    simulate_client(ss_server); // Should be ss_decapped, but they are equal.
    
    printf("\n[!] Analyze the outputs above. Do the keys match?\n");
    printf("[!] Hint: Look at the KDF Context Input hex dump.\n");
    
    // Cleanup
    kem_free(pk, sk, ct, ss_server);
    free(ss_decapped);
    
    return 0;
}
