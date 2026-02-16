#ifndef ENTROPY_POOL_H
#define ENTROPY_POOL_H

#include <vector>
#include <cstdint>
#include <mutex>

namespace Utils {

class EntropyPool {
public:
    static EntropyPool& getInstance();

    // Mixing new entropy into the pool
    void addEntropy(const void* data, size_t len);
    
    // Retrieve random bytes
    void getBytes(void* out, size_t len);

private:
    EntropyPool();
    ~EntropyPool() = default;

    // Internal state
    std::vector<uint8_t> pool;
    uint32_t mix_index;
    std::mutex pool_mutex;

    void reseed();
};

} // namespace Utils

#endif // ENTROPY_POOL_H
