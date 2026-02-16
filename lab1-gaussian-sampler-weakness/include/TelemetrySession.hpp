#pragma once

#include <string>
#include <vector>
#include <cstdint>

class TelemetrySession {
public:
    explicit TelemetrySession(const std::string &out_path);

    void recordInternal(const std::vector<int> &internal_sig,
                        uint32_t seed_snapshot);

    void dump() const;

private:
    std::string path;
    std::vector<std::vector<int>> captured;
    std::vector<uint32_t> seeds;
};

