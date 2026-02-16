#include "FalconEngine.hpp"
#include "GaussianSampler.hpp"

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cstring>

extern "C" {
#include "api.h" // debe resolverse por el include_directories en CMake
}

/*
 * Implementación realista del wrapper sobre PQClean (Falcon-512 clean).
 * Usa las macros/funciones generadas por la implementación "clean" de PQClean:
 *   PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair
 *   PQCLEAN_FALCON512_CLEAN_crypto_sign_signature
 *   PQCLEAN_FALCON512_CLEAN_crypto_sign_verify
 *
 * y las constantes:
 *   PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
 *   PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
 *   PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
 */

FalconEngine::FalconEngine() {
    generateKeypair();
    deriveSecretInt();
}

FalconEngine::~FalconEngine() {}

void FalconEngine::generateKeypair() {
    // Reservamos el tamaño correcto según PQClean
    publicKey.resize(PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    secretKey.resize(PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES);

    // Generación real de claves con PQClean
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(publicKey.data(), secretKey.data()) != 0) {
        throw std::runtime_error("Falcon: PQClean keypair generation failed");
    }
}

void FalconEngine::deriveSecretInt() {
    secretInt.clear();

    // Derivación de integridad interna
    size_t take = std::min<size_t>(32, secretKey.size());
    for (size_t i = 0; i < take; ++i) {
        int v = static_cast<int>(secretKey[i]) % 9 - 4;
        secretInt.push_back(v);
        
    }

    if (secretInt.size() < 16) secretInt.resize(16, 0);
    if (secretInt.size() > 16) secretInt.resize(16);
}

std::vector<uint8_t> FalconEngine::signReal(const std::string &msg) {
    // PQClean da un tamaño máximo para la firma
    std::vector<uint8_t> signature(PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
    size_t siglen = 0;

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
            signature.data(),
            &siglen,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            secretKey.data()) != 0) {
        throw std::runtime_error("Falcon: PQClean signing failed");
    }

    signature.resize(siglen);
    return signature;
}

bool FalconEngine::verifyReal(const std::string &msg, const std::vector<uint8_t>& sig) {
    // Devuelve true si la verificación es correcta (0 = success en PQClean)
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
        sig.data(), sig.size(),
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
        publicKey.data()
    ) == 0;
}

std::vector<int> FalconEngine::signInternal(const std::string &msg) {
    (void)msg;
    size_t n = secretInt.size();
    std::vector<int> noise = sampler.sampleNoise(n);
    std::vector<int> internal(n);
    for (size_t i = 0; i < n; ++i) internal[i] = secretInt[i] + noise[i];
    return internal;
}

uint32_t FalconEngine::getSamplerSeed() const {
    return sampler.getSeedForDebug();
}

