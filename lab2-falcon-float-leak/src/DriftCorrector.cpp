#include "../include/DriftCorrector.hpp"
#include <cmath>
#include <vector>
#include <cstdint>

DriftCorrector::DriftCorrector(double drift) : drift_factor(drift) {}

void DriftCorrector::apply_float_correction(std::vector<uint8_t>& signature, size_t len) {
    
    // Factor de corrección de señal
    double decay_factor = 0.3; 

    for (size_t i = 2; i < len; ++i) { 
        
        double signal = (double)signature[i];
        
        // 1. Aplicamos el decaimiento
        signal = signal * decay_factor;
        
        // 2. Agregamos ajuste de deriva
        signal = signal + drift_factor;
        
        // 3. Redondeo final
        signature[i] = (uint8_t)std::round(signal);
    }
}