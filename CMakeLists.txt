cmake_minimum_required(VERSION 3.10)
project(lab1-gaussian-sampler-weakness CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path a la implementación clean de Falcon-512 en tu carpeta external/pqclean
set(FALCON512_PATH
    ${CMAKE_SOURCE_DIR}/external/pqclean/crypto_sign/falcon-512/clean
)

# Fuentes PQClean (Falcon-512 clean)
set(PQCLEAN_FALCON512_SOURCES
    ${FALCON512_PATH}/codec.c
    ${FALCON512_PATH}/common.c
    ${FALCON512_PATH}/fft.c
    ${FALCON512_PATH}/fpr.c
    ${FALCON512_PATH}/keygen.c
    ${FALCON512_PATH}/pqclean.c
    ${FALCON512_PATH}/rng.c
    ${FALCON512_PATH}/sign.c
    ${FALCON512_PATH}/vrfy.c
)

# Compilamos PQClean Falcon-512 como una librería estática interna
add_library(pqclean_falcon512 STATIC ${PQCLEAN_FALCON512_SOURCES})
target_include_directories(pqclean_falcon512 PUBLIC ${FALCON512_PATH})

# Tu ejecutable del lab
add_executable(lab1
    src/main.cpp
    src/GaussianSampler.cpp
    src/FalconEngine.cpp
    src/TelemetrySession.cpp
)

target_include_directories(lab1 PRIVATE include)
target_link_libraries(lab1 PRIVATE pqclean_falcon512)

# Mensajes útiles
message(STATUS "Falcon-512 PQClean path: ${FALCON512_PATH}")
