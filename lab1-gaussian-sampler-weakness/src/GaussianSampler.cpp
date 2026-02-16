#include "GaussianSampler.hpp"
#include <vector>
#include <random>
#include <cstdint>
#include <cmath>
#include <ctime>      // ← para time()
#include <unistd.h>   // ← para getpid()

/*
 * Implementación del sampler Gaussiano
 */

GaussianSampler::GaussianSampler() {
    // Inicialización del seed
    seed_used = static_cast<uint32_t>(time(nullptr)) ^ static_cast<uint32_t>(getpid());
    rng.seed(seed_used);

    // Configuración de distribución normal
    gaussian = std::normal_distribution<double>(0.0, 1.50);
}

std::vector<int> GaussianSampler::sampleNoise(size_t n) {
    std::vector<int> out;
    out.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        double x = gaussian(rng);

        // Limitación de valores extremos
        if (x > 2.0) x = 2.0;
        if (x < -2.0) x = -2.0;

        int v = static_cast<int>(std::round(x));
        out.push_back(v);
    }
    return out;
}

uint32_t GaussianSampler::getSeedForDebug() const {
    // Retorna la semilla utilizada
    return seed_used;
}
