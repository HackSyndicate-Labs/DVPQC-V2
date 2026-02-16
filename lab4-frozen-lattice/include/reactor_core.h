#ifndef REACTOR_CORE_H
#define REACTOR_CORE_H

#include <stdint.h>

// Definiciones estándar para Kyber-512 (ML-KEM-512)
// Usamos el prefijo LAB_ para evitar conflictos con los headers internos de la librería
#define LAB_KYBER_SYMBYTES 32
#define LAB_KYBER_CIPHERTEXTBYTES 768
#define LAB_KYBER_SECRETKEYBYTES 1632
#define LAB_KYBER_PUBLICKEYBYTES 800

/**
 * @brief Núcleo de desencapsulación de alto rendimiento.
 * @param ss Salida: Clave compartida (Shared Secret) - 32 bytes
 * @param ct Entrada: Texto cifrado (Ciphertext) - 768 bytes
 * @param sk Entrada: Clave secreta (Secret Key) - 1632 bytes
 * @return 0 si éxito, -1 si fallo de integridad (reject)
 */
int reactor_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif