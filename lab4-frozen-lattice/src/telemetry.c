#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "telemetry.h"

// --- UTILIDADES DE SISTEMA ---

int read_file_bytes(const char* filename, uint8_t* buffer, size_t expected_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[!] Error: No se pudo abrir el archivo %s\n", filename);
        return 0;
    }

    // Obtenemos tamaño del archivo
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize != (long)expected_len) {
        fprintf(stderr, "[!] Error: Tamaño de archivo incorrecto en %s. Esperado: %zu, Leído: %ld\n", 
                filename, expected_len, fsize);
        fclose(f);
        return 0;
    }

    size_t read_bytes = fread(buffer, 1, expected_len, f);
    fclose(f);

    return (read_bytes == expected_len);
}

// --- SISTEMA DE REPORTE (PARSING TARGET) ---

void print_telemetry(ReactorTelemetry *t) {
    /* * Formato JSON-like simplificado.
     */
    printf("{\n");
    printf("  \"status\": \"%s\",\n", t->integrity_status ? "STABLE" : "CRITICAL_FAILURE");
    printf("  \"telemetry\": {\n");
    printf("    \"temp_mk\": %d,\n", t->reactor_temp_mk);
    printf("    \"cpu_cycles\": %lu\n", t->cycles_consumed);
    printf("  },\n");
    printf("  \"msg\": \"%s\"\n", t->message);
    printf("}\n");
    
    // Forzamos flush para que Python lo lea inmediatamente a través de pipes
    fflush(stdout); 
}