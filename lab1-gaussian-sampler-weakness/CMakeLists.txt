cmake_minimum_required(VERSION 3.16)
project(lab1_gaussian_sampler)

set(CMAKE_CXX_STANDARD 17)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean
    ${PROJECT_SOURCE_DIR}/../external/pqclean/common
)

# PQClean fuentes FALCON-512 (clean)
set(PQCLEAN_FALCON_SRC
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/codec.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/common.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/fft.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/fpr.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/keygen.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/pqclean.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/rng.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/sign.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/crypto_sign/falcon-512/clean/vrfy.c
)

# Dependencias comunes PQClean (Keccak/SHAKE)
set(PQCLEAN_COMMON_SRC
    ${PROJECT_SOURCE_DIR}/../external/pqclean/common/fips202.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/common/sha2.c
    ${PROJECT_SOURCE_DIR}/../external/pqclean/common/randombytes.c
)

# LAB sources
set(SOURCES
    src/main.cpp
    src/GaussianSampler.cpp
    src/FalconEngine.cpp
    src/TelemetrySession.cpp
    ${PQCLEAN_FALCON_SRC}
    ${PQCLEAN_COMMON_SRC}
)

add_executable(lab1-gaussian-sampler-weakness ${SOURCES})


