#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>

typedef struct {
    uint32_t reactor_temp_mk;  // Temperatura en mK
    uint64_t cycles_consumed;  // Ciclos de CPU (simulado)
    uint8_t  integrity_status; // 1 = OK, 0 = FAIL
    char     message[64];      // Mensaje de estado
} ReactorTelemetry;

// Imprime el estado del reactor en formato JSON-like para facilitar el parsing
void print_telemetry(ReactorTelemetry *t);

// Lee un archivo binario desde disco (Utilidad)
int read_file_bytes(const char* filename, uint8_t* buffer, size_t expected_len);

#endif