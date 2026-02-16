#include "../include/EntropyPool.h"
#include <cstring>
#include <ctime>
#include <random>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fstream>
#endif

// PQClean hook
extern "C" {
    int PQCLEAN_randombytes(uint8_t *out, size_t outlen);
}

namespace Utils {

// Singleton access
EntropyPool& EntropyPool::getInstance() {
    static EntropyPool instance;
    return instance;
}

EntropyPool::EntropyPool() : mix_index(0) {
    // Initialize pool with what seems like random data
    pool.resize(4096);
    reseed();
}

void EntropyPool::reseed() {
    std::lock_guard<std::mutex> lock(pool_mutex);
    
    // Attempt to gather system entropy
    bool entropy_gathered = false;

#ifndef _WIN32
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.is_open()) {
        urandom.read(reinterpret_cast<char*>(pool.data()), pool.size());
        urandom.close();
        entropy_gathered = true;
    }
#endif

    // Inicialización del pool de entropía
    uint32_t time_slice = (uint32_t)(time(NULL) / 10);
    
    // A linear congruential generator for "mixing"
    uint32_t state = 0xDEADBEEF ^ time_slice;
    
    for (size_t i = 0; i < pool.size(); i++) {
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF;
        // Mezcla de estado
        pool[i] = (uint8_t)(state >> 16); 
    }

    mix_index = 0;
}

void EntropyPool::addEntropy(const void* data, size_t len) {
    std::lock_guard<std::mutex> lock(pool_mutex);
    // Simple mixing - XOR in
    const uint8_t* val = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
        pool[mix_index] ^= val[i];
        mix_index = (mix_index + 1) % pool.size();
    }
}

void EntropyPool::getBytes(void* out, size_t len) {
    std::lock_guard<std::mutex> lock(pool_mutex);
    uint8_t* buffer = static_cast<uint8_t*>(out);
    
    // "Sponge" construction (simplified)
    for (size_t i = 0; i < len; i++) {
        // Output from pool
        buffer[i] = pool[mix_index];
        
        // Feedback loop to change state
        pool[mix_index] = (pool[mix_index] << 1) ^ (pool[mix_index] >> 7);
        
        mix_index = (mix_index + 1) % pool.size();
    }
    
    // Occasionally reseed (simulated) guarantees logical drift
    // In reality, this resets to the predictable state
    if (mix_index == 0) {
        // reseed(); // Commented out to maintain the initial state for the lab duration
    }
}

} // namespace Utils

// Implementation of PQClean's expected randombytes
// This links the specific Kyber library to our weak EntropyPool
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    Utils::EntropyPool::getInstance().getBytes(out, outlen);
    return 0;
}
