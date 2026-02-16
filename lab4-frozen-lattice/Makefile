# ==============================================================================
#  KYB-01 "FROZEN LATTICE" - REACTOR BUILD SYSTEM
#  Integración: Lab Code + PQClean External Libraries (ML-KEM Standard)
# ==============================================================================

CC = gcc
# Usamos -O0 para desactivar optimizaciones y garantizar que el bucle de 
# retardo/verificación no sea eliminado por el compilador.
CFLAGS = -O0 -Wall -Wextra -Wno-unused-parameter -I./include -I$(KYBER_PATH) -I$(COMMON_PATH)

# --- RUTAS DE INTEGRACIÓN ---
# Ajustado para ML-KEM-512 (Antiguo Kyber-512)
PQDIR = ../external/pqclean
KYBER_PATH = $(PQDIR)/crypto_kem/ml-kem-512/clean
COMMON_PATH = $(PQDIR)/common

# --- FUENTES DEL LABORATORIO ---
LAB_SRCS = src/main_controller.c \
           src/reactor_core.c \
           src/cryo_shield.c \
           src/telemetry.c

KEYGEN_SRCS = src/keygen.c
FORGE_SRCS = src/payload_forge.c

# --- FUENTES DE ML-KEM (PQCLEAN) ---
# Incluimos las primitivas matemáticas necesarias
# [FIX] symmetric-shake.c: Necesario para las funciones hash (SHAKE)
# [FIX] kem.c: Necesario para las funciones de alto nivel usadas por keygen
KYBER_SRCS = $(KYBER_PATH)/indcpa.c \
             $(KYBER_PATH)/poly.c \
             $(KYBER_PATH)/polyvec.c \
             $(KYBER_PATH)/ntt.c \
             $(KYBER_PATH)/cbd.c \
             $(KYBER_PATH)/reduce.c \
             $(KYBER_PATH)/verify.c \
             $(KYBER_PATH)/symmetric-shake.c \
             $(KYBER_PATH)/kem.c

# --- FUENTES COMUNES ---
COMMON_SRCS = $(COMMON_PATH)/fips202.c \
              $(COMMON_PATH)/sha2.c \
              $(COMMON_PATH)/randombytes.c

# --- OBJETIVOS ---
TARGET_REACTOR = frozen_lattice_reactor
TARGET_KEYGEN = keygen
TARGET_FORGE = payload_forge

all: info $(TARGET_REACTOR) $(TARGET_KEYGEN) $(TARGET_FORGE)

info:
	@echo "[*] Compilando Entorno ML-KEM-512..."
	@echo "[*] Librerías detectadas en: $(KYBER_PATH)"

# Compilación del Reactor (Vulnerable)
$(TARGET_REACTOR): $(LAB_SRCS)
	@echo "[*] Construyendo Reactor..."
	$(CC) $(CFLAGS) $(LAB_SRCS) $(KYBER_SRCS) $(COMMON_SRCS) -o $(TARGET_REACTOR)

# Compilación del Generador de Llaves (Utility)
$(TARGET_KEYGEN): $(KEYGEN_SRCS)
	@echo "[*] Construyendo Keygen Tool..."
	$(CC) $(CFLAGS) $(KEYGEN_SRCS) $(KYBER_SRCS) $(COMMON_SRCS) -o $(TARGET_KEYGEN)

# Compilación del Forjador de Payloads (Exploit Tool)
$(TARGET_FORGE): $(FORGE_SRCS)
	@echo "[*] Construyendo Herramienta de Forjado Matemático..."
	$(CC) $(CFLAGS) $(FORGE_SRCS) $(KYBER_SRCS) $(COMMON_SRCS) -o $(TARGET_FORGE)

clean:
	rm -f $(TARGET_REACTOR) $(TARGET_KEYGEN) $(TARGET_FORGE) *.bin
	@echo "[!] Limpieza completada."

.PHONY: all clean info