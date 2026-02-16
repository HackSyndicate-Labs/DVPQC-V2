cmake_minimum_required(VERSION 3.10)
project(lab8-temporal-fork C)

set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(src/hal)

# Source files
set(SOURCES
    src/main.c
    src/core/security_controller.c
    src/phys/power_profile.c
    src/math/ntt_accel.c
)

set(FUZZ_SOURCES
    fuzz/fuzz_harness.c
    src/core/security_controller.c
    src/phys/power_profile.c
    src/math/ntt_accel.c
)

# Executables
add_executable(lab8 ${SOURCES})
add_executable(lab8_fuzz ${FUZZ_SOURCES})

# Hardware Abstraction Layer
target_include_directories(lab8 PRIVATE src/hal)
target_include_directories(lab8_fuzz PRIVATE src/hal)
