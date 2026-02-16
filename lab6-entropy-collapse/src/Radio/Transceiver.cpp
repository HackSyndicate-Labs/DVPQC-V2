#include "../../include/Transceiver.h"
#include <iostream>
#include <iomanip>

namespace Radio {

Transceiver::Transceiver() : initialized(false) {}

void Transceiver::initialize() {
    std::cout << "[RADIO] Initializing Secure Quantum Link..." << std::endl;
    // Keys are generated here, using the (flawed) EntropyPool via randombytes override
    if (kem.generateKeys(my_pk, my_sk)) {
        initialized = true;
        std::cout << "[RADIO] Link Established. Identity Secured." << std::endl;
    } else {
        std::cerr << "[RADIO] CRITICAL FAILURE: Key Generation Failed." << std::endl;
    }
}

void Transceiver::sendMessage(const std::string& msg) {
    if (!initialized) return;
    std::cout << "[RADIO] Encrypting transmission: \"" << msg << "\"" << std::endl;
    // In a real scenario, we'd use the shared secret to encrypt the message (AES/ChaCha)
    // For this lab, we just demonstrate the KEM exchange part as that's the vulnerability focus
    std::cout << "[RADIO] Burst transmission sent." << std::endl;
}

void Transceiver::receiveMessage(const std::vector<uint8_t>& ct) {
    if (!initialized) return;
    std::vector<uint8_t> ss;
    if (kem.decapsulate(ct, my_sk, ss)) {
        std::cout << "[RADIO] Transmission Received. Decapsulation Successful." << std::endl;
        std::cout << "        Shared Secret Segment: ";
        for(size_t i=0; i<8; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ss[i];
        std::cout << "..." << std::dec << std::endl;
    } else {
        std::cerr << "[RADIO] Decapsulation Failed. Signal Corrupted." << std::endl;
    }
}

std::vector<uint8_t> Transceiver::getPublicKey() const {
    return my_pk;
}

} // namespace Radio
