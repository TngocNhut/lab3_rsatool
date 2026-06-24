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

#include "rsatool/file_utils.hpp"
#include "rsatool/hybrid.hpp"
#include "rsatool/rsa_keys.hpp"

#include <filesystem>

namespace rsatool {

void run_hybrid_benchmark_csv(
    const std::string& public_key_pem,
    const std::string& private_key_pem,
    const std::string& out_csv
) {
    const CryptoPP::RSA::PublicKey pub = load_public_key_pem(public_key_pem);
    const CryptoPP::RSA::PrivateKey priv = load_private_key_pem(private_key_pem);

    const std::vector<size_t> sizes = {
        1024,
        1024 * 1024,
        100 * 1024 * 1024
    };

    std::ofstream out(out_csv);
    if (!out) {
        throw std::runtime_error("cannot open hybrid benchmark CSV for writing: " + out_csv);
    }

    out << "mode,size_bytes,iterations,total_encrypt_ms,avg_encrypt_ms,total_decrypt_ms,avg_decrypt_ms,throughput_encrypt_mib_s,throughput_decrypt_mib_s\n";

    const std::filesystem::path tmp_dir = std::filesystem::path(out_csv).parent_path() / "tmp_hybrid_bench";
    std::filesystem::create_directories(tmp_dir);

    std::cout << "[INFO] Hybrid benchmark output CSV: " << out_csv << "\n";

    for (size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        for (size_t i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<uint8_t>(i & 0xff);
        }

        size_t iterations = 50;
        if (size >= 1024 * 1024) {
            iterations = 10;
        }
        if (size >= 100 * 1024 * 1024) {
            iterations = 1;
        }

        const std::filesystem::path envelope_path =
            tmp_dir / ("hybrid_" + std::to_string(size) + ".json");

        // Warm-up
        hybrid_encrypt_file(pub, plaintext, envelope_path.string());
        volatile auto warm_plain = hybrid_decrypt_file(priv, envelope_path.string());
        (void)warm_plain;

        const auto enc_start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < iterations; ++i) {
            hybrid_encrypt_file(pub, plaintext, envelope_path.string());
        }
        const auto enc_end = std::chrono::steady_clock::now();

        const double enc_total_ms =
            std::chrono::duration<double, std::milli>(enc_end - enc_start).count();

        const auto dec_start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < iterations; ++i) {
            volatile auto recovered = hybrid_decrypt_file(priv, envelope_path.string());
            (void)recovered;
        }
        const auto dec_end = std::chrono::steady_clock::now();

        const double dec_total_ms =
            std::chrono::duration<double, std::milli>(dec_end - dec_start).count();

        const double enc_avg_ms = enc_total_ms / static_cast<double>(iterations);
        const double dec_avg_ms = dec_total_ms / static_cast<double>(iterations);

        const double total_mib =
            (static_cast<double>(size) * static_cast<double>(iterations)) /
            (1024.0 * 1024.0);

        const double enc_throughput =
            total_mib / (enc_total_ms / 1000.0);

        const double dec_throughput =
            total_mib / (dec_total_ms / 1000.0);

        out << "hybrid,"
            << size << ","
            << iterations << ","
            << std::fixed << std::setprecision(6)
            << enc_total_ms << ","
            << enc_avg_ms << ","
            << dec_total_ms << ","
            << dec_avg_ms << ","
            << enc_throughput << ","
            << dec_throughput << "\n";

        std::cout << "[OK] size=" << size
                  << " bytes, iterations=" << iterations
                  << ", enc_avg_ms=" << enc_avg_ms
                  << ", dec_avg_ms=" << dec_avg_ms
                  << ", enc_MiB_s=" << enc_throughput
                  << ", dec_MiB_s=" << dec_throughput
                  << "\n";
    }

    std::cout << "[OK] Hybrid benchmark completed\n";
}

} // namespace rsatool
