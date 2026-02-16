#include "../../include/KyberManager.h"
extern "C" {
#include "../../../external/pqclean/crypto_kem/ml-kem-768/clean/api.h"
}
#include <iostream>
#include <cstring>

namespace Crypto {

KyberManager::KyberManager() {}
KyberManager::~KyberManager() {}

bool KyberManager::generateKeys(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    pk.resize(PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk.resize(PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);

    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk.data(), sk.data()) != 0) {
        return false;
    }
    return true;
}

bool KyberManager::encapsulate(const std::vector<uint8_t>& pk, 
                               std::vector<uint8_t>& ct, 
                               std::vector<uint8_t>& ss) {
    if (pk.size() != PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES) return false;

    ct.resize(PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ss.resize(PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES);

    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct.data(), ss.data(), pk.data()) != 0) {
        return false;
    }
    return true;
}

bool KyberManager::decapsulate(const std::vector<uint8_t>& ct, 
                               const std::vector<uint8_t>& sk, 
                               std::vector<uint8_t>& ss) {
    if (ct.size() != PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) return false;
    if (sk.size() != PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES) return false;

    ss.resize(PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES);

    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss.data(), ct.data(), sk.data()) != 0) {
        return false;
    }
    return true;
}

size_t KyberManager::getPublicKeySize() { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES; }
size_t KyberManager::getSecretKeySize() { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES; }
size_t KyberManager::getCiphertextSize() { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES; }
size_t KyberManager::getSharedSecretSize() { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES; }

} // namespace Crypto
