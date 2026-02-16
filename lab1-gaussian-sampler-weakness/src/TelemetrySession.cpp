#include "TelemetrySession.hpp"   // ← NECESARIO
#include <fstream>
#include <iostream>
#include <ctime>

TelemetrySession::TelemetrySession(const std::string &out_path)
    : path(out_path) {}

void TelemetrySession::recordInternal(const std::vector<int> &internal_sig,
                                      uint32_t seed_snapshot) {
    captured.push_back(internal_sig);
    seeds.push_back(seed_snapshot);
}

void TelemetrySession::dump() const {
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) {
        std::cerr << "Telemetry: cannot open " << path << "\n";
        return;
    }

    for (size_t i = 0; i < captured.size(); ++i) {
        std::time_t ts = std::time(nullptr);
        f << ts << "|" << seeds[i] << "|";
        for (size_t j = 0; j < captured[i].size(); ++j) {
            if (j) f << ",";
            f << captured[i][j];
        }
        f << "\n";
    }
    f.close();

    std::cout << "[Telemetry] saved to " << path << "\n";
    for (size_t i = 0; i < captured.size(); ++i) {
        std::cout << " entry " << i << " seed=" << seeds[i] << " { ";
        for (int v : captured[i]) std::cout << v << " ";
        std::cout << "}\n";
    }
}

