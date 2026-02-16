#pragma once

#include <sys/types.h>
#include <vector>
#include <string>
#include <cstdint>
#include "GaussianSampler.hpp"

// IMPORTANTE:
// Incluimos el API real usando la ruta correcta dentro del proyecto.
extern "C" {
#include "../../external/pqclean/crypto_sign/falcon-512/clean/api.h"
}

class FalconEngine {
public:
    FalconEngine();
    ~FalconEngine();

    std::vector<uint8_t> signReal(const std::string &msg);
    // bool verifyReal(const std::string &msg); 
    bool verifyReal(const std::string &msg, const std::vector<uint8_t>& sig);

    std::vector<int> signInternal(const std::string &msg);

    const std::vector<uint8_t>& getPublicKey() const { return publicKey; }
    const std::vector<int>& getSecretInt() const { return secretInt; }

    uint32_t getSamplerSeed() const;

private:
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
    std::vector<int> secretInt;

    GaussianSampler sampler;

    void generateKeypair();
    void deriveSecretInt();
};

