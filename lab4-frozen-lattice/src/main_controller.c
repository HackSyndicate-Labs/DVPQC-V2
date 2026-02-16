#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h> 

#include "reactor_core.h"
#include "cryo_shield.h"
#include "telemetry.h"

#define BILLION  1000000000L

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <secret_key_file> <ciphertext_file>\n", argv[0]);
        return 1;
    }

    const char *sk_file = argv[1];
    const char *ct_file = argv[2];

    // Buffers usando las definiciones LAB_
    uint8_t sk[LAB_KYBER_SECRETKEYBYTES];
    uint8_t ct[LAB_KYBER_CIPHERTEXTBYTES];
    uint8_t ss[LAB_KYBER_SYMBYTES]; 

    // 1. Cargar Combustible
    if (!read_file_bytes(sk_file, sk, LAB_KYBER_SECRETKEYBYTES)) return 1;
    if (!read_file_bytes(ct_file, ct, LAB_KYBER_CIPHERTEXTBYTES)) return 1;

    // 2. Inicializar Subsistemas
    cryo_system_init();
    
    struct timespec start, end;
    uint64_t diff_ns;

    // 3. Activar Escudo Térmico
    engage_thermal_jitter();

    clock_gettime(CLOCK_MONOTONIC, &start);

    // 4. Ejecutar Reactor
    int result = reactor_decapsulate(ss, ct, sk);

    clock_gettime(CLOCK_MONOTONIC, &end);

    diff_ns = (end.tv_sec - start.tv_sec) * BILLION + (end.tv_nsec - start.tv_nsec);

    // 5. Preparar Telemetría
    ReactorTelemetry telemetry;
    telemetry.integrity_status = (result == 0) ? 1 : 0;
    telemetry.reactor_temp_mk = get_reactor_temperature();
    telemetry.cycles_consumed = diff_ns; 

    if (result == 0) {
        snprintf(telemetry.message, 64, "KEY_ESTABLISHED_STABLE");
    } else {
        snprintf(telemetry.message, 64, "INTEGRITY_VIOLATION_DETECTED");
    }

    print_telemetry(&telemetry);

    return (result == 0) ? 0 : 1;
}