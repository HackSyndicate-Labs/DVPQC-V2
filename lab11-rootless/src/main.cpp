/**
 * SPH-02 "Rootless" — Service Application
 * ========================================
 * The "Mother Tree" authentication service.
 * Verifies SPHINCS+ signatures using a high-performance (but flawed)
 * root verification strategy.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include "liboqs_shim.h"
#include "../include/lab11.h"

// ANSI color codes for lore
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"

static void print_banner() {
    std::cout << CYAN << R"(
   .       .
    \     /
   . \   / .     THE MOTHER TREE
    \ \ / /      Status: ROOT_LOST
     \ | /       Mode:   CACHED_VERIFICATION
      \|/
       |
)" << RESET << std::endl;
}

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
}

static void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not write file: " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < data.size() && i < 16; ++i) { // Show first 16 bytes
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    if (data.size() > 16) ss << "...";
    return ss.str();
}

void do_keygen() {
    oqs::Signature sig("SPHINCS+-SHA2-128f-simple");
    std::cout << "[*] Generating SPHINCS+ keypair (this may take a moment)...\n";
    auto pk = sig.generate_keypair();
    auto sk = sig.export_secret_key();

    write_file("sphincs.pk", pk);
    write_file("sphincs.sk", sk);

    std::cout << "[+] Keys generated:\n";
    std::cout << "    PK: " << to_hex(pk) << "\n";
    std::cout << "    SK: " << to_hex(sk) << "\n";
    std::cout << "[*] Saved to sphincs.pk / sphincs.sk\n";
}

void do_sign(const std::string& msg_str) {
    oqs::Signature sig("SPHINCS+-SHA2-128f-simple");
    
    // Load SK
    try {
        auto sk = read_file("sphincs.sk");
        sig.import_secret_key(sk);

        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
        auto signature = sig.sign(message);

        std::string sig_path = "sig.bin";
        write_file(sig_path, signature);
        std::cout << "[+] Signature generated: " << sig_path << " (" << signature.size() << " bytes)\n";
    } catch (const std::exception& e) {
        std::cerr << RED << "[-] Error: " << e.what() << RESET << "\n";
    }
}

// Fixed version of verify that doesn't rely on shim loading keys (it passes keys to verify)
int do_verify(const std::string& msg_str, const std::string& sig_path, const std::string& pk_path) {
    try {
        oqs::Signature sig("SPHINCS+-SHA2-128f-simple");
        
        auto pk = read_file(pk_path);
        auto signature = read_file(sig_path);
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        std::cout << "[*] Verifying signature against " << pk_path << "\n";
        std::cout << "    Message: \"" << msg_str << "\"\n";
        std::cout << "    Root Check Optimization: " << sig.get_verification_depth() << " bytes\n";
        
        bool valid = sig.verify(message, signature, pk);

        if (valid) {
            std::cout << GREEN << "[+] ACCESS GRANTED. ROOT CONFIRMED." << RESET << "\n";
            std::cout << "    The signature is valid under the current root policy.\n";
            return 0;
        } else {
            std::cout << RED << "[-] ACCESS DENIED. ROOT MISMATCH." << RESET << "\n";
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << RED << "[-] Error: " << e.what() << RESET << "\n";
    }
}

void fast_collider() {
    // Hidden tool for students to find collision
    std::cout << "[*] Starting root collider...\n";
    // We can implement a C++ collider inside the binary for speed?
    // No, that makes it too easy if they just run `--collider`.
    // Let's not implement it, forcing them to write code.
    std::cout << "[-] Collider module corrupted. Please implement external bypass.\n";
}

int main(int argc, char** argv) {
    print_banner();

    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  lab11 --keygen\n";
        std::cout << "  lab11 --sign <msg>        (Requires sphincs.sk)\n";
        std::cout << "  lab11 --verify <msg> <sig_file> <pk_file>\n";
        std::cout << "  lab11 --info\n";
        return 1;
    }

    std::string mode = argv[1];

    try {
        if (mode == "--keygen") {
            do_keygen();
        } else if (mode == "--sign") {
            if (argc < 3) {
                std::cerr << "[-] Usage: lab11 --sign <msg>\n";
                return 1;
            }
            do_sign(argv[2]);
        } else if (mode == "--verify") {
            if (argc < 5) {
                std::cerr << "[-] Usage: lab11 --verify <msg> <sig> <pk>\n";
                return 1;
            }
            return do_verify(argv[2], argv[3], argv[4]);
        } else if (mode == "--info") {
             oqs::Signature sig("SPHINCS+-SHA2-128f-simple");
             std::cout << "Algorithm:   SPHINCS+-SHA2-128f-simple\n";
             std::cout << "Root Policy: Partial Check (" << sig.get_verification_depth() << " bytes)\n";
             std::cout << "Status:      Vulnerable to collision attacks\n";
        } else {
            std::cerr << "[-] Unknown command\n";
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "[-] Critical Error: " << e.what() << RESET << "\n";
        return 1;
    }

    return 0;
}
