cmake_minimum_required(VERSION 3.10)
project(lab6-entropy-collapse C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

# Paths
set(PQCLEAN_ROOT "${CMAKE_SOURCE_DIR}/../external/pqclean")
set(PQCLEAN_COMMON "${PQCLEAN_ROOT}/common")
set(PQCLEAN_KEM "${PQCLEAN_ROOT}/crypto_kem/ml-kem-768/clean")

# Sources from PQClean Common
set(COMMON_SOURCES
    ${PQCLEAN_COMMON}/fips202.c
    ${PQCLEAN_COMMON}/sha2.c
    ${PQCLEAN_COMMON}/sp800-185.c
    ${PQCLEAN_COMMON}/nistseedexpander.c
    ${PQCLEAN_COMMON}/aes.c
    # randombytes.c is EXCLUDED because we override it in Utils/EntropyPool.cpp
)

# Sources from ML-KEM-768 Clean
file(GLOB KEM_SOURCES "${PQCLEAN_KEM}/*.c")

# Lab Sources
set(LAB_SOURCES
    src/main.cpp
    src/Utils/EntropyPool.cpp
    src/Crypto/KyberManager.cpp
    src/Radio/Transceiver.cpp
)

# Include directories
include_directories(
    include
    ${PQCLEAN_COMMON}
    ${PQCLEAN_KEM}
)

# Lab executable
add_executable(lab6
    ${LAB_SOURCES}
    ${COMMON_SOURCES}
    ${KEM_SOURCES}
)

# Link directories/libraries
if(UNIX)
    target_link_libraries(lab6 m)
endif()
