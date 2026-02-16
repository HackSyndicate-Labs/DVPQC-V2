#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "hal/glitch_controller.h" 

// Forward declaration if not in header
int security_handler(const uint8_t *stream, size_t stream_len);
#define BOOT_OK 0x01

void print_hex(const uint8_t *data, size_t len) {
    for(size_t i=0; i<len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main() {
    printf("==========================================\n");
    printf("   SECURE BOOTLOADER v2.0 (HARDENED)      \n");
    printf("==========================================\n");
    printf("[BOOT] Initializing Hardware Abstraction...\n");
    
    printf("[BOOT] Waiting for Signed Firmware Image...\n");
    printf("[INPUT] Enter Stream (Hex): > ");

    char input_hex[7000];
    if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) return 1;

    // Parse Hex
    uint8_t buffer[3325];
    size_t len = 0;
    char *pos = input_hex;
    while (*pos && len < sizeof(buffer)) {
        unsigned int val;
        if (sscanf(pos, "%2x", &val) == 1) {
            buffer[len++] = (uint8_t)val;
            pos += 2;
        } else {
            break; 
        }
    }

    if (len < (32 + 3293)) {
        printf("[ERROR] Image Corrupted / Truncated.\n");
        return 1;
    }

    printf("[BOOT] Verifying Signature (Dilithium-3 Hardware Accel)...\n");
    
    int result = security_handler(buffer, len);
    
    if (result == BOOT_OK) {
        printf("\n[SUCCESS] BOOT SEQUENCE INITIATED.\n");
    } else {
        printf("\n[FAILURE] SECURITY VIOLATION DETECTED. SYSTEM HALTED.\n");
    }

    return 0;
}
