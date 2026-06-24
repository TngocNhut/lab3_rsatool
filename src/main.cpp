#include "rsatool/rsa_keys.hpp"

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

#include <exception>
#include <iostream>
#include <string>

namespace {

void print_help() {
    std::cout
        << "rsatool - Lab 3 RSA-OAEP and Hybrid Encryption Tool\n\n"
        << "Usage:\n"
        << "  rsatool --help\n"
        << "  rsatool version\n"
        << "  rsatool selftest\n"
        << "  rsatool keygen --bits 3072|4096 --pub pub.pem --priv priv.pem\n"
        << "  rsatool keyinfo --pub pub.pem\n"
        << "  rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label text]\n"
        << "  rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin [--label text]\n"
        << "  rsatool bench --bits 3072|4096 --out benchmark.csv\n\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }
    return {};
}

int run_selftest() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 3072);

    CryptoPP::RSA::PublicKey pub(priv);

    if (!priv.Validate(rng, 3)) {
        std::cerr << "ERROR: generated RSA private key failed validation\n";
        return 1;
    }

    if (!pub.Validate(rng, 3)) {
        std::cerr << "ERROR: generated RSA public key failed validation\n";
        return 1;
    }

    CryptoPP::SHA256 hash;

    std::cout << "[OK] Crypto++ AutoSeededRandomPool works\n";
    std::cout << "[OK] Generated RSA-3072 test key pair\n";
    std::cout << "[OK] RSA private/public key validation passed\n";
    std::cout << "[OK] SHA-256 digest size: " << hash.DigestSize() << " bytes\n";

    return 0;
}

int run_keygen(int argc, char* argv[]) {
    const std::string bits_str = get_arg(argc, argv, "--bits");
    const std::string pub_path = get_arg(argc, argv, "--pub");
    const std::string priv_path = get_arg(argc, argv, "--priv");

    if (bits_str.empty() || pub_path.empty() || priv_path.empty()) {
        std::cerr << "ERROR: keygen requires --bits 3072|4096 --pub pub.pem --priv priv.pem\n";
        return 1;
    }

    int bits = 0;
    try {
        bits = std::stoi(bits_str);
    } catch (...) {
        std::cerr << "ERROR: invalid --bits value\n";
        return 1;
    }

    const rsatool::RsaKeyPairPaths paths =
        rsatool::generate_rsa_keypair_files(bits, pub_path, priv_path);

    std::cout << "[OK] Generated RSA-" << bits << " key pair\n";
    std::cout << "[OK] Public PEM: " << paths.public_pem << "\n";
    std::cout << "[OK] Private PEM: " << paths.private_pem << "\n";
    std::cout << "[OK] Public DER: " << paths.public_der << "\n";
    std::cout << "[OK] Private DER: " << paths.private_der << "\n";
    std::cout << "[OK] Metadata JSON: " << paths.metadata_json << "\n";
    std::cout << "[INFO] OAEP hash: SHA-256\n";
    std::cout << "[INFO] MGF: MGF1-SHA256\n";

    return 0;
}

int run_keyinfo(int argc, char* argv[]) {
    const std::string pub_path = get_arg(argc, argv, "--pub");

    if (pub_path.empty()) {
        std::cerr << "ERROR: keyinfo requires --pub pub.pem\n";
        return 1;
    }

    const int bits = rsatool::rsa_modulus_bits_from_public_pem(pub_path);

    if (bits < 3072) {
        std::cerr << "ERROR: RSA key too small: " << bits << " bits. Minimum is 3072 bits.\n";
        return 1;
    }

    std::cout << "[OK] Public key: " << pub_path << "\n";
    std::cout << "[OK] RSA modulus size: " << bits << " bits\n";
    std::cout << "[OK] Minimum requirement satisfied: RSA >= 3072 bits\n";
    std::cout << "[INFO] Intended padding: OAEP\n";
    std::cout << "[INFO] Intended hash: SHA-256\n";

    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1) {
            print_help();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "-h") {
            print_help();
            return 0;
        }

        if (command == "version") {
            std::cout << "rsatool 1.0.0\n";
            std::cout << "RSA-OAEP-SHA256 / AES-256-GCM hybrid encryption\n";
            return 0;
        }

        if (command == "selftest") {
            return run_selftest();
        }

        if (command == "keygen") {
            return run_keygen(argc, argv);
        }

        if (command == "keyinfo") {
            return run_keyinfo(argc, argv);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: rsatool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
