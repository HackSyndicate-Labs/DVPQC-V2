#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // para usleep
#include <time.h>
#include "cryo_shield.h"

/*
 * ============================================================================
 * CRYO SHIELD SYSTEM v4.2
 * ============================================================================
 */

// Estado interno del generador de entropía (LCG)
static uint64_t thermal_entropy_state;

// Almacena el último valor de "ruido" aplicado para reportarlo como temperatura
static uint32_t last_applied_cooling_val = 0;

void cryo_system_init(void) {
    // Inicialización de semilla basada en tiempo
    // En un entorno real, esto sería un TRNG de hardware.
    srand(time(NULL));
    thermal_entropy_state = rand();
    
    // "Warm up" del generador
    thermal_entropy_state = (thermal_entropy_state * 6364136223846793005ULL + 1);
}

// Generador Pseudo-Aleatorio Lineal simple
static uint32_t get_next_entropy_chunk() {
    thermal_entropy_state = (thermal_entropy_state * 6364136223846793005ULL + 1442695040888963407ULL);
    // Usamos los bits altos para mejor distribución
    return (uint32_t)(thermal_entropy_state >> 32);
}

void engage_thermal_jitter(void) {
    /*
     * CALIBRACIÓN TÉRMICA
     * Generamos un retardo aleatorio entre 0 y 5000 microsegundos.
     * Esto es suficiente para ocultar las diferencias de nanosegundos
     * del memcmp inseguro en el núcleo.
     */
    
    uint32_t noise = get_next_entropy_chunk();
    
    // Máscara 0x1FFF = 8191 (aprox 8ms max delay)
    // Esto es el valor crudo de "frio" inyectado
    uint32_t cooling_uS = noise & 0x1FFF; 

    // Guardamos este valor para calcular la temperatura resultante después
    last_applied_cooling_val = cooling_uS;

    // Aplicamos el freno físico (Sleep)
    if (cooling_uS > 0) {
        usleep(cooling_uS);
    }
}

uint32_t get_reactor_temperature(void) {
    /*
     * LECTURA DE SENSORES
     * La temperatura del reactor es inversamente proporcional al enfriamiento aplicado.
     */
    
    const uint32_t BASE_TEMP_MK = 3000;
    
    // Cálculo de temperatura basado en enfriamiento
    
    return BASE_TEMP_MK + (last_applied_cooling_val * 2);
}