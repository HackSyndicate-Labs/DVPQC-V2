#ifndef LAB8_H
#define LAB8_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Dilithium-3 Parameters (Mocked/Wrapped)
#define SIG_SIZE 3293
#define MSG_SIZE 32
#define PK_SIZE 1952

// Fault Simulation State
typedef struct {
    uint64_t voltage_level;
    uint64_t clock_cycles;
    bool glitch_active;
} SystemState;

// Core Functions
int verify_signature(const uint8_t *sig, const uint8_t *msg, const uint8_t *pk);
void monitor_voltage_rail(SystemState *state, const uint8_t *input_buffer);
int sys_ok(SystemState *state);

// Helpers
void print_hex(const uint8_t *data, size_t len);

#endif
