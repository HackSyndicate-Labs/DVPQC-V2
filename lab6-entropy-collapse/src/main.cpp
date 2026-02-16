#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include "../include/Transceiver.h"

void print_banner() {
    std::cout << "========================================================================" << std::endl;
    std::cout << "   SECURE COMMAND LINK - QUANTUM ENCRYPTED PROTOCOL (QEP-768)" << std::endl;
    std::cout << "   STATUS: ONLINE" << std::endl;
    std::cout << "   ENTROPY: POOL STABLE (SYNCED)" << std::endl;
    std::cout << "========================================================================" << std::endl << std::endl;
}

void hex_dump(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (size_t i = 0; i < data.size() && i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

int main() {
    print_banner();

    // Initialize the Secure Transceiver
    Radio::Transceiver radio;
    
    std::cout << "[SYSTEM] Initializing Hardware..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    radio.initialize();
    
    std::vector<uint8_t> pk = radio.getPublicKey();
    hex_dump("[INFO] DEVICE PUBLIC KEY", pk);

    std::cout << "\n[SYSTEM] Listening for encrypted traffic..." << std::endl;
    
    // Simulate some background traffic
    for (int i = 0; i < 3; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        radio.sendMessage("HEARTBEAT_KEEPALIVE_SEQ_" + std::to_string(i));
    }

    std::cout << "\n[ALERT] INTERCEPT WARNING: Unidentified signal detected on frequency." << std::endl;
    std::cout << "[SYSTEM] Encryption integrity verification required." << std::endl;
    std::cout << "[SYSTEM] If you can predict the next Private Key, the system is compromised." << std::endl;

    return 0;
}
