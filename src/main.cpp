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

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: rsatool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
