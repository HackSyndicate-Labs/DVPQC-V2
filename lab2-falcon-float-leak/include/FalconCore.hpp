#ifndef FALCON_CORE_HPP
#define FALCON_CORE_HPP

#include <vector>
#include <string>
#include <cstdint>
#include "DriftCorrector.hpp"

class FalconCore {
private:
    // Almacenamiento de llaves (formato raw bytes de Falcon)
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    
    // El módulo defectuoso
    DriftCorrector corrector;

public:
    FalconCore(); // El constructor genera las llaves reales

    // Firma un mensaje de texto y retorna la firma (posiblemente corrupta)
    std::vector<uint8_t> sign_data(const std::string& message);
    
    // Getter para la llave pública (por si el usuario la necesita para verificar)
    std::vector<uint8_t> get_public_key() const { return public_key; }
};

#endif