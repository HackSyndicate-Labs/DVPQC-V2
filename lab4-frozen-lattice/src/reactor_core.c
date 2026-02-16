#include "reactor_core.h"
#include <string.h> 
#include <stdio.h>

// Incluimos headers de PQClean
#include "indcpa.h"
#include "fips202.h" 
#include "api.h" 

// --- MACROS Y DEFINICIONES ---

// Prefijo correcto para ML-KEM (Kyber) en tu versión de PQClean
#define PQ_PREFIX(func) PQCLEAN_MLKEM512_CLEAN_##func

// Mapeamos las funciones internas
#define INDCPA_DEC PQ_PREFIX(indcpa_dec)
#define INDCPA_ENC PQ_PREFIX(indcpa_enc)

// --- CORRECCIÓN DEL ERROR ---
// La librería no exporta INDCPA_SECRETKEYBYTES con el prefijo público.
// Lo definimos manualmente según el estándar ML-KEM-512:
// k=2, polybytes=384 -> 2 * 384 = 768 bytes.
#define LAB_INDCPA_SECRETKEYBYTES 768

int reactor_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    size_t i;
    int fail = 0;
    
    // Buffers internos
    uint8_t buf[2 * LAB_KYBER_SYMBYTES];
    uint8_t kr[2 * LAB_KYBER_SYMBYTES]; 
    uint8_t cmp[LAB_KYBER_CIPHERTEXTBYTES]; 
    
    // Puntero a la llave pública dentro de la estructura de la llave secreta.
    // En Kyber, la SK almacena la PK justo después de la parte secreta (INDCPA).
    const uint8_t *pk = sk + LAB_INDCPA_SECRETKEYBYTES;

    // -------------------------------------------------------------------------
    // PASO 1: Desencriptado IND-CPA 
    // -------------------------------------------------------------------------
    // Recuperamos el mensaje original m'
    INDCPA_DEC(buf, ct, sk);

    // -------------------------------------------------------------------------
    // PASO 2: Re-hashing (Multitarget countermeasure)
    // -------------------------------------------------------------------------
    // Copiamos el hash de la llave pública (H(pk)) que está al final de la SK
    // La estructura de SK es: INDCPA_SK (768) || PK (800) || H(PK) (32) || z (32)
    // Total = 1632 bytes.
    // Queremos acceder a los últimos 64 bytes donde vive H(pk) y z.
    
    for(i = 0; i < LAB_KYBER_SYMBYTES; i++) {
        buf[LAB_KYBER_SYMBYTES + i] = sk[LAB_KYBER_SECRETKEYBYTES - 2 * LAB_KYBER_SYMBYTES + i];
    }
    
    // Hash(m' || h(pk)) -> K' || r'
    sha3_512(kr, buf, 2 * LAB_KYBER_SYMBYTES);

    // -------------------------------------------------------------------------
    // PASO 3: Re-Encryption (Fujisaki-Okamoto Check)
    // -------------------------------------------------------------------------
    // Re-encriptamos m' usando la aleatoriedad r' derivada para ver si coincide con el ciphertext original
    INDCPA_ENC(cmp, buf, pk, kr + LAB_KYBER_SYMBYTES);

    // -------------------------------------------------------------------------
    // PASO 4: Verificación de Integridad
    // -------------------------------------------------------------------------
    
    for(i = 0; i < LAB_KYBER_CIPHERTEXTBYTES; i++) {
        if(ct[i] != cmp[i]) {
            fail = 1;
            break;
        }
    }

    // -------------------------------------------------------------------------
    // PASO 5: Derivación de la Llave Compartida
    // -------------------------------------------------------------------------
    if(fail) {
        return -1; // Fallo reportado (El main controlará qué devolver al usuario)
    }

    // KDF Final
    sha3_256(ss, kr, LAB_KYBER_SYMBYTES);
    
    return 0; 
}