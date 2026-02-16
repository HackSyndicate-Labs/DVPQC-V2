#pragma once
#include <vector>
#include <random>
#include <cstdint>

/*
 * GaussianSampler
 *
 * Implementación deliberadamente imperfecta del muestreador Gaussiano.
 * El bug está en la inicialización del RNG y en el truncamiento de colas,
 * lo que produce ruido sesgado y reproducible en un rango limitado.
 */
class GaussianSampler {
public:
    GaussianSampler();

    // Genera n valores pequeños (enteros) usados como "noise"
    std::vector<int> sampleNoise(size_t n);

    // Getter de semilla para debugging/instructor (devuelve 0 si no se desea exponer)
    uint32_t getSeedForDebug() const;

private:
    std::mt19937 rng;
    std::normal_distribution<double> gaussian;
    uint32_t seed_used;
};
