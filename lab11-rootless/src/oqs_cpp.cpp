#include "liboqs_shim.h"
#include <iostream>
#include <vector>
#include <cstring>

// Include PQClean C APIS
extern "C" {
    #include "../src/pqclean/api.h"
}

namespace oqs {

Signature::Signature(const std::string& alg_name) : alg_name_(alg_name) {
    if (alg_name != "SPHINCS+-SHA2-128f-simple") {
        throw std::runtime_error("Algorithm not supported in this lab environment");
    }
}

Signature::~Signature() {
    // secure cleanup if needed
}

std::vector<uint8_t> Signature::generate_keypair() {
    std::vector<uint8_t> pk(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);

    if (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) != 0) {
        throw std::runtime_error("Key generation failed");
    }

    public_key_ = pk;
    secret_key_ = sk;
    return pk;
}

std::vector<uint8_t> Signature::export_public_key() const {
    return public_key_;
}

std::vector<uint8_t> Signature::export_secret_key() const {
    return secret_key_;
}

void Signature::import_public_key(const std::vector<uint8_t>& pk) {
    if (pk.size() != PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        throw std::runtime_error("Invalid public key size");
    }
    public_key_ = pk;
}

void Signature::import_secret_key(const std::vector<uint8_t>& sk) {
    if (sk.size() != PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES) {
        throw std::runtime_error("Invalid secret key size");
    }
    secret_key_ = sk;
}

std::vector<uint8_t> Signature::sign(const std::vector<uint8_t>& message) const {
    if (secret_key_.empty()) {
        throw std::runtime_error("Secret key not set");
    }

    std::vector<uint8_t> sig(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES);
    size_t siglen = 0;

    if (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig.data(), &siglen,
                              message.data(), message.size(),
                              secret_key_.data()) != 0) {
        throw std::runtime_error("Signing failed");
    }

    sig.resize(siglen);
    return sig;
}

bool Signature::verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key) const {
    if (public_key.size() != PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return false;
    }

    // crypto_sign_verify returns 0 on success
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(signature.data(), signature.size(),
                              message.data(), message.size(),
                              public_key.data()) == 0;
}

size_t Signature::get_verification_depth() const {
    // Hint to the user about the vulnerability level
    return 2; // "Rootless" optimization depth (bytes)
}

} // namespace oqs
