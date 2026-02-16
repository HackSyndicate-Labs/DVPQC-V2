#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"        // API de PQClean (ML-KEM-512)
#include "randombytes.h"

// Usamos las macros de la librería externa
#define KEM_SECRETKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define KEM_PUBLICKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define KEM_CIPHERTEXTBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define KEM_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES

void write_file(const char *filename, const uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Error abriendo archivo para escritura");
        exit(1);
    }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("[+] Generado: %s (%zu bytes)\n", filename, len);
}

int main() {
    uint8_t pk[KEM_PUBLICKEYBYTES];
    uint8_t sk[KEM_SECRETKEYBYTES];
    uint8_t ct[KEM_CIPHERTEXTBYTES];
    uint8_t ss[KEM_BYTES]; // Shared Secret original (para validar)

    printf("[*] Iniciando Generador de Combustible ML-KEM-512...\n");

    // 1. Generar Keypair (PK, SK)
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "[!] Error generando llaves.\n");
        return 1;
    }

    // 2. Encapsular (Generar Ciphertext y Shared Secret)
    // Usamos la PK que acabamos de crear para generar un reto válido
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk) != 0) {
        fprintf(stderr, "[!] Error encapsulando.\n");
        return 1;
    }

    // 3. Guardar artefactos
    write_file("sk.bin", sk, KEM_SECRETKEYBYTES);
    write_file("ct.bin", ct, KEM_CIPHERTEXTBYTES);
    write_file("ss_gold.bin", ss, KEM_BYTES); // Para comparar si el reactor funciona bien
    
    // Opcional: Guardar PK si quisieras atacar desde fuera completamente
    write_file("pk.bin", pk, KEM_PUBLICKEYBYTES); 

    printf("[*] Listo. Ejecuta el reactor con: ./frozen_lattice_reactor sk.bin ct.bin\n");
    return 0;
}