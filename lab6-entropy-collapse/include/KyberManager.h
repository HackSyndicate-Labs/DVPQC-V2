#ifndef KYBER_MANAGER_H
#define KYBER_MANAGER_H

#include <vector>
#include <string>
#include <cstdint>

namespace Crypto {

class KyberManager {
public:
    KyberManager();
    ~KyberManager();

    // Key Generation
    bool generateKeys(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

    // Encapsulation (Alice)
    bool encapsulate(const std::vector<uint8_t>& pk, 
                     std::vector<uint8_t>& ct, 
                     std::vector<uint8_t>& ss);

    // Decapsulation (Bob)
    bool decapsulate(const std::vector<uint8_t>& ct, 
                     const std::vector<uint8_t>& sk, 
                     std::vector<uint8_t>& ss);

    static size_t getPublicKeySize();
    static size_t getSecretKeySize();
    static size_t getCiphertextSize();
    static size_t getSharedSecretSize();
};

} // namespace Crypto

#endif // KYBER_MANAGER_H
