#ifndef TRANSCEIVER_H
#define TRANSCEIVER_H

#include <string>
#include <vector>
#include "KyberManager.h"

namespace Radio {

class Transceiver {
public:
    Transceiver();
    
    // Initialize the radio with a new identity/keypair
    void initialize();

    // Send a secure message (simulated)
    void sendMessage(const std::string& msg);

    // Receive a simulated message
    void receiveMessage(const std::vector<uint8_t>& ct);

    // Get current public key for display
    std::vector<uint8_t> getPublicKey() const;

private:
    Crypto::KyberManager kem;
    std::vector<uint8_t> my_pk;
    std::vector<uint8_t> my_sk;
    bool initialized;
};

} // namespace Radio

#endif // TRANSCEIVER_H
