#include <stdio.h>
#include <string.h>
#include "hal/glitch_controller.h"

// Forward declaration
void ntt_transform_block(SoC_State *soc, uint32_t *poly_coeffs);

// Dilithium Constants
#define SIG_SIZE 3293
#define MSG_SIZE 32

#include <intrin.h>

// Helper for portability
static inline uint32_t manual_popcount(uint32_t x) {
    uint32_t c = 0;
    while(x) { c += (x & 1); x >>= 1; }
    return c;
}

// Firmware Error Codes
#define BOOT_OK 0x01
#define AUTH_FAIL 0xFF
#define HARDWARE_ERR 0xEE

int security_handler(const uint8_t *stream, size_t stream_len) {
    SoC_State soc;
    hal_init(&soc);
    
    if (stream_len < (SIG_SIZE + MSG_SIZE)) return HARDWARE_ERR;
    const uint8_t *msg = stream;
    const uint8_t *sig = stream + MSG_SIZE;
    
    // 1. Load Data into "SRAM" (Simulated)
    // This phase consumes power based on the data patterns.
    // Smart attackers will use this to "prime" the regulator via dI/dt.
    uint32_t scratchpad[256];
    
    // Copy signature pattern into scratchpad for processing
    // We map bytes to uint32s.
    for(int i=0; i<256; i++) {

        uint32_t val = 0;
        val |= sig[i*4];
        val |= (sig[i*4+1] << 8);
        val |= (sig[i*4+2] << 16);
        val |= (sig[i*4+3] << 24);
        scratchpad[i] = val;
        
        uint32_t hw = manual_popcount(val);
        hal_tick(&soc, 1, hw); // 1 Cycle per word load
    }
    
    // 2. Perform Crypto Check (NTT Transform)
    // This is the High-Intensity Operation.
    ntt_transform_block(&soc, scratchpad);
    
    // 3. Final Verification Check
    // We check if the result "converged" to 0 (which means Sig == PrivateKey operation)
    // In our Mock: If ntt_transform_block was Glitched, it wrote 0s to scratchpad[0].
    
    // Real Admin Key Check (Mocked):
    // Normall we check if scratchpad matches the PK arithmetic. 
    // Here we check if scratchpad[0] is 0 AND scratchpad[1] is 0 (Simulating a successful "difference check")
    
    if (scratchpad[0] == 0 && scratchpad[1] == 0) {
        return BOOT_OK; // Access Granted
    }
    
    return AUTH_FAIL;
}
