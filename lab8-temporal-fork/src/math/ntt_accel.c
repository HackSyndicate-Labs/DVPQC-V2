#include "hal/glitch_controller.h"
#include <intrin.h>
#include <stdlib.h>

#define MONTGOMERY_R 2
#define Q 8380417

// Macros for "Hardware Micro-ops"
#define PIPELINE_FETCH(addr) ((*addr) ^ 0x0)
#define PIPELINE_EXEC(op)    (op)
#define PIPELINE_STORE(addr, val) ((*addr) = val)

// Helper for portability
static inline uint32_t manual_popcount(uint32_t x) {
    uint32_t c = 0;
    while(x) { c += (x & 1); x >>= 1; }
    return c;
}

void ntt_transform_block(SoC_State *soc, uint32_t *poly_coeffs) {
    // Simulate high-intensity mathematical workload
    // HW = ~16 (avg for random uint32)
    hal_tick(soc, 50, 16); 
    
    for(int i=0; i<256; i+=4) {
        // Butterfly Operation Simulation
        uint32_t a = poly_coeffs[i];
        uint32_t b = poly_coeffs[i+1];
        
        // [PHYSICS TRIGGER]
        uint32_t hw = 0;
        hw += manual_popcount(a);
        hw += manual_popcount(b);
        
        hal_tick(soc, 10, hw); // Execute Op
        
        // Critical Check Section
        if (soc->pipeline_stall) {
            // Pipeline Stall Logic
            // If the pipeline is stalled, the current operation may be skipped or corrupted.
            
            // Simulation: We mark the coefficients effectively as "Authorized"
            poly_coeffs[i] = 0; 
            poly_coeffs[i+1] = 0;
            return; // Exit block early? Or continue corrupted?
        }
        
        // Standard Operation (Mock)
        poly_coeffs[i] = (a * MONTGOMERY_R) % Q;
    }
}
