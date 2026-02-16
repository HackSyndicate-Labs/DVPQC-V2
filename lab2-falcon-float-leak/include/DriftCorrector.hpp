#ifndef DRIFT_CORRECTOR_HPP
#define DRIFT_CORRECTOR_HPP

#include <vector>
#include <cstddef> // Para size_t
#include <cstdint> // Para uint8_t

class DriftCorrector {
private:
    double drift_factor;

public:
    // Constructor que recibe el factor de deriva
    DriftCorrector(double drift);

    // La función que aplica la corrección de punto flotante (y rompe la firma)
    void apply_float_correction(std::vector<uint8_t>& signature, size_t len);
};

#endif