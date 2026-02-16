#include "FalconEngine.hpp"
#include "TelemetrySession.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <thread>   
#include <chrono>  


int main() {
    std::cout << "=== DAMVULN PQC LAB - Lab1: Gaussian Sampler Weakness ===\n";
    std::cout << "Generando keypair real (Falcon-512) y recolectando telemetría...\n";

    FalconEngine engine;
    TelemetrySession telemetry("telemetry.log");

    const std::string message = "telemetry-pqc-packet";

    // Generamos varias entradas (firmas internas + firmas reales) para el análisis
    for (int i = 0; i < 8; ++i) {
        auto internal = engine.signInternal(message);

        // Snapshot del seed para telemetría (oculto por defecto)
        uint32_t seed_snapshot = 0;

        telemetry.recordInternal(internal, seed_snapshot);

        // Generamos también una firma real (no almacenada) para simular actividad normal
        auto real_sig = engine.signReal(message);

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    telemetry.dump();
    std::cout << "Lab finished. telemetry.log generated.\n";
    return 0;
}
