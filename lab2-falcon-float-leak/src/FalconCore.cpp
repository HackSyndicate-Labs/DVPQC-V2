#include "../include/FalconCore.hpp"
#include "../include/UniversalConstants.hpp"
#include <iostream>
#include <cstring>
#include <vector>

// IMPORTANTE: Importamos las funciones de C de PQClean
extern "C" {
    #include "api.h" // El header oficial de Falcon-512 en pqclean
}

FalconCore::FalconCore() : corrector(0.0015) {
    // Usamos las constantes reales de la librería
    size_t pk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;

    public_key.resize(pk_len);
    secret_key.resize(sk_len);

    // LLAMADA REAL A LA LIBRERÍA: Generación de claves
    // Esto usa la implementación "clean" de Falcon
    std::cout << "[FalconCore] Calling PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair..." << std::endl;
    int res = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(public_key.data(), secret_key.data());
    
    if (res != 0) {
        std::cerr << "[FATAL] Falcon KeyGen failed inside liboqs/pqclean!" << std::endl;
        exit(1);
    }
}

std::vector<uint8_t> FalconCore::sign_data(const std::string& message) {
    // Preparar buffers para la firma real
    size_t sig_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
    std::vector<uint8_t> signature(sig_len + message.size());
    size_t actual_sig_len;

    // LLAMADA REAL A LA LIBRERÍA: Firmar el mensaje
    int res = PQCLEAN_FALCON512_CLEAN_crypto_sign(
        signature.data(), &actual_sig_len,
        (const uint8_t*)message.c_str(), message.size(),
        secret_key.data()
    );

    // Verificación de estabilidad del sistema
    if (!UniversalConstants::is_stable()) {
        // Aplicar corrección de deriva si el sistema no es estable
        corrector.apply_float_correction(signature, actual_sig_len);
    }

    // Redimensionamos al tamaño real de la firma generada
    signature.resize(actual_sig_len);
    return signature;
}