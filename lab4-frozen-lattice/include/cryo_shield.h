#ifndef CRYO_SHIELD_H
#define CRYO_SHIELD_H

#include <stdint.h>

/**
 * @brief Inicializa el subsistema de enfriamiento criogénico.
 * Carga la entropía inicial para el generador de dispersión térmica.
 */
void cryo_system_init(void);

/**
 * @brief Activa la dispersión térmica (Jitter).
 * Introduce retardos estocásticos para mitigar análisis de canal lateral.
 * Debe ser llamado ANTES de cualquier operación criptográfica sensible.
 */
void engage_thermal_jitter(void);

/**
 * @brief Obtiene la telemetría térmica actual.
 * @return Temperatura en miliKelvin (mK).
 * * NOTA DE SEGURIDAD:
 * Los auditores han señalado que la correlación entre la temperatura
 * y los ciclos de espera podría ser predecible en versiones de firmware < 5.0.
 */
uint32_t get_reactor_temperature(void);

#endif