#include "rsatool/benchmark.hpp"

#include "rsatool/rsa_oaep.hpp"

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace rsatool {

namespace {

template <typename Fn>
double measure_ms(Fn&& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::vector<uint8_t> fixed_message(size_t n) {
    std::vector<uint8_t> m(n);
    for (size_t i = 0; i < n; ++i) {
        m[i] = static_cast<uint8_t>(i & 0xff);
    }
    return m;
}

} // namespace

void run_rsa_benchmark_csv(int bits, const std::string& out_csv) {
    if (bits != 3072 && bits != 4096) {
        throw std::runtime_error("bench supports --bits 3072|4096");
    }

    CryptoPP::AutoSeededRandomPool rng;

    std::ofstream out(out_csv);
    if (!out) {
        throw std::runtime_error("cannot open benchmark CSV for writing: " + out_csv);
    }

    out << "bits,operation,iterations,total_ms,avg_ms,ops_per_sec\n";

    std::cout << "[INFO] RSA benchmark bits: " << bits << "\n";
    std::cout << "[INFO] Output CSV: " << out_csv << "\n";

    CryptoPP::RSA::PrivateKey priv;
    double keygen_ms = measure_ms([&]() {
        priv.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(bits));
    });

    CryptoPP::RSA::PublicKey pub(priv);

    out << bits << ",keygen,1,"
        << std::fixed << std::setprecision(6)
        << keygen_ms << ","
        << keygen_ms << ","
        << (1000.0 / keygen_ms) << "\n";

    std::cout << "[OK] keygen avg_ms=" << keygen_ms << "\n";

    const size_t max_plain = rsa_oaep_sha256_max_plaintext_size_bytes(pub);
    const std::vector<uint8_t> msg = fixed_message(max_plain > 64 ? 64 : max_plain);

    std::vector<uint8_t> ct;

    const size_t enc_iters = 200;
    double enc_total = measure_ms([&]() {
        for (size_t i = 0; i < enc_iters; ++i) {
            ct = rsa_oaep_sha256_encrypt(pub, msg, "");
        }
    });

    out << bits << ",encrypt," << enc_iters << ","
        << enc_total << ","
        << (enc_total / static_cast<double>(enc_iters)) << ","
        << (1000.0 * static_cast<double>(enc_iters) / enc_total) << "\n";

    std::cout << "[OK] encrypt avg_ms="
              << (enc_total / static_cast<double>(enc_iters))
              << "\n";

    const size_t dec_iters = 50;
    double dec_total = measure_ms([&]() {
        for (size_t i = 0; i < dec_iters; ++i) {
            volatile auto recovered = rsa_oaep_sha256_decrypt(priv, ct, "");
            (void)recovered;
        }
    });

    out << bits << ",decrypt," << dec_iters << ","
        << dec_total << ","
        << (dec_total / static_cast<double>(dec_iters)) << ","
        << (1000.0 * static_cast<double>(dec_iters) / dec_total) << "\n";

    std::cout << "[OK] decrypt avg_ms="
              << (dec_total / static_cast<double>(dec_iters))
              << "\n";

    std::cout << "[OK] RSA benchmark completed\n";
}

} // namespace rsatool
