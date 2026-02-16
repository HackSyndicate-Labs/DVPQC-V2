#ifndef UNIVERSAL_CONSTANTS_HPP
#define UNIVERSAL_CONSTANTS_HPP

class UniversalConstants {
public:
    // Retorna true si el universo es estable (False en este lab para activar el bug)
    static bool is_stable();
    
    // Retorna el nivel de entropía actual
    static double get_instability_factor();
};

#endif