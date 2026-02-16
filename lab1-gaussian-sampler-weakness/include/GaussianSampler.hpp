#pragma once
#include <vector>
#include <random>
#include <cstdint>


class GaussianSampler {
public:
    GaussianSampler();

    std::vector<int> sampleNoise(size_t n);

    uint32_t getSeedForDebug() const;

private:
    std::mt19937 rng;
    std::normal_distribution<double> gaussian;
    uint32_t seed_used;
};
