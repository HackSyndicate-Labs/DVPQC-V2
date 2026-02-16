#ifndef GLITCH_CONTROLLER_H
#define GLITCH_CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>

// Simulated Hardware Constraints
#define THERMAL_LIMIT     8500  // 85.00 C
#define VOLTAGE_RAIL_MV   1200  // 1.2V Core
#define CLOCK_FREQ_HZ     100000000

// Register Map (Simulated)
typedef struct {
    uint32_t STATUS;     // 0x00
    uint32_t CTRL;       // 0x04
    uint32_t POWER_DRAW; // 0x08
    uint32_t TEMP_SENS;  // 0x0C
    uint32_t GLITCH_DET; // 0x10
} HW_Registers;

// Global Hardware State (Singleton)
typedef struct {
    HW_Registers regs;
    uint32_t cycles_elapsed;
    float core_voltage;
    float die_temp;
    bool pipeline_stall;
} SoC_State;

// Core APIs
void hal_init(SoC_State *soc);
void hal_tick(SoC_State *soc, uint32_t instruction_cost, uint32_t data_hamming_weight);
bool hal_is_stable(SoC_State *soc);

// Math Accelerators
void ntt_transform_block(SoC_State *soc, uint32_t *poly_coeffs);

#endif
