cmake_minimum_required(VERSION 3.10)

# Nombre del proyecto
project(lab2_falcon_drift)

# Estándar C++
set(CMAKE_CXX_STANDARD 17)

# --- INTEGRACIÓN CON PQCLEAN (EXTERNAL) ---

# 1. Definir ruta a pqclean (subiendo un nivel desde lab2/ y entrando a external)
set(PQCLEAN_DIR "${CMAKE_SOURCE_DIR}/../external/pqclean")

# 2. Verificar que existe (opcional pero útil para debug)
if(NOT EXISTS "${PQCLEAN_DIR}")
    message(FATAL_ERROR "No se encuentra pqclean en: ${PQCLEAN_DIR}")
endif()

# 3. Incluir headers
include_directories(
    include                                         # Headers locales (FalconCore.hpp, etc)
    ${PQCLEAN_DIR}/common                           # Headers comunes de pqclean (sha2, etc)
    ${PQCLEAN_DIR}/crypto_sign/falcon-512/clean     # Headers específicos de Falcon-512
)

# 4. Buscar todos los fuentes .c de Falcon y Common
file(GLOB PQCLEAN_SOURCES 
    "${PQCLEAN_DIR}/crypto_sign/falcon-512/clean/*.c"
    "${PQCLEAN_DIR}/common/*.c"
)

# --- COMPILACIÓN DEL RETO ---

# 5. Crear el ejecutable uniendo tus fuentes C++ con los fuentes C de la librería
add_executable(quantum_drift 
    src/main.cpp
    src/FalconCore.cpp
    src/DriftCorrector.cpp
    src/UniversalConstants.cpp
    ${PQCLEAN_SOURCES}
)

# 6. Mensaje de éxito
message(STATUS "Configurado Lab 2: Falcon Float Leak con librería externa.")