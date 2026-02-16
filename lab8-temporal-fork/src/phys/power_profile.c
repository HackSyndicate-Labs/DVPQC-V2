#include "hal/glitch_controller.h"
#include <math.h>
#include <stdio.h>

// Thermal Constants
#define AMBIENT_TEMP 25.0f
#define HEAT_COEFF   0.005f
#define COOL_COEFF   0.002f

void hal_init(SoC_State *soc) {
    soc->regs.STATUS = 1; // IDLE
    soc->regs.POWER_DRAW = 0;
    soc->core_voltage = 1.2f;
    soc->die_temp = AMBIENT_TEMP;
    soc->pipeline_stall = false;
    soc->cycles_elapsed = 0;
}

// The heart of the simulation: Physics Engine
void hal_tick(SoC_State *soc, uint32_t instruction_cost, uint32_t data_hamming_weight) {
    soc->cycles_elapsed += instruction_cost;
    
    // Power Model: Base + Dynamic (Hamming Weight)
    // Instantaneous Current Calculation
    float current_draw = (float)instruction_cost * 0.1f + (float)data_hamming_weight * 0.05f;
    
    // Thermal Model (Integrator)
    soc->die_temp += (current_draw * HEAT_COEFF);
    soc->die_temp -= ((soc->die_temp - AMBIENT_TEMP) * COOL_COEFF);
    
    // Voltage Model (IR Drop)
    // V_core = V_rail - (I * R_eff)
    
    static float prev_current = 0.0f;
    float di_dt = current_draw - prev_current;
    
    // Regulator Response Lag
    soc->core_voltage = 1.2f - (di_dt * 0.15f);
    
    // The "Glitch Window" Logic
    
    if (soc->core_voltage > 1.45f) {
        soc->pipeline_stall = true; // [GLITCH] Instruction Skip!
        soc->regs.GLITCH_DET = 0xCA171CA4;
    } else if (soc->core_voltage < 0.9f) {

        soc->regs.STATUS = 0xDEAD; // Brownout
    } else {
        soc->pipeline_stall = false;
    }
    
    prev_current = current_draw;
}

bool hal_is_stable(SoC_State *soc) {
    // Returns true if voltage is within nominal operation window
    return (soc->core_voltage > 1.0f && soc->core_voltage < 1.4f);
}
