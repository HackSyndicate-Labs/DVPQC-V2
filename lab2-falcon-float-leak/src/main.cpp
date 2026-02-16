#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <chrono>
#include "../include/FalconCore.hpp"
#include "../include/UniversalConstants.hpp"

// Función auxiliar para imprimir bytes en Hex
void print_hex(const std::vector<uint8_t>& data, size_t limit) {
    for (size_t i = 0; i < limit && i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > limit) std::cout << "...";
    std::cout << std::dec; // Volver a decimal
}

int main() {
    std::cout << "\n==================================================" << std::endl;
    std::cout << "   QUA-02 SYSTEM BOOT :: QUANTUM LABS v2.0" << std::endl;
    std::cout << "==================================================" << std::endl;
    

    std::cout << "[*] Initializing Falcon-512 Cryptographic Engine..." << std::endl;
    
    // Instanciamos el Core (Esto llama a pqclean para generar llaves reales)
    FalconCore engine;
    
    std::cout << "[*] Keys Generated. Public Key Preview: ";
    print_hex(engine.get_public_key(), 16);
    std::cout << std::endl << std::endl;

    std::cout << "--- BEGIN TELEMETRY STREAM ---" << std::endl;
    std::cout << "ID | MESSAGE (ASCII)      | SIGNATURE SNIPPET" << std::endl;
    std::cout << "---|----------------------|---------------------------------" << std::endl;

    // Generamos 10 firmas para que el usuario tenga data
    for (int i = 0; i < 10; ++i) {
        std::string msg = "SENSOR_READING_" + std::to_string(i * 123);
        
        // Firma del mensaje
        std::vector<uint8_t> sig = engine.sign_data(msg);

        std::cout << std::setw(2) << i << " | " 
                  << std::setw(20) << std::left << msg << " | ";
        
        print_hex(sig, 60); 
        
        std::cout << std::endl;
        
        // Simular tiempo de proceso
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return 0;
}