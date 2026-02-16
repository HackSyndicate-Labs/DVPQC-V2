/**
 * liboqs C++ Shim
 * ================
 * A drop-in replacement for the `liboqs` C++ wrapper,
 * backed by our local (modified) PQClean implementation
 * to simulate the "Rootless" environment.
 */

#ifndef OQS_CPP_H
#define OQS_CPP_H

#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>

namespace oqs {

class Signature {
public:
    Signature(const std::string& alg_name);
    ~Signature();

    // Key management
    std::vector<uint8_t> generate_keypair();
    std::vector<uint8_t> export_public_key() const;
    std::vector<uint8_t> export_secret_key() const;

    void import_public_key(const std::vector<uint8_t>& pk);
    void import_secret_key(const std::vector<uint8_t>& sk);

    // Signing
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const;

    // Verification
    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) const;

    // Properties
    size_t get_verification_depth() const; // Custom API for lab hint

private:
    std::vector<uint8_t> secret_key_;
    std::vector<uint8_t> public_key_;
    std::string alg_name_;
};

} // namespace oqs

#endif // OQS_CPP_H
