#pragma once

#include <cryptopp/rsa.h>

#include <string>
#include <vector>

namespace rsatool {

struct RsaKeyPairPaths {
    std::string public_pem;
    std::string private_pem;
    std::string public_der;
    std::string private_der;
    std::string metadata_json;
};

RsaKeyPairPaths generate_rsa_keypair_files(
    int bits,
    const std::string& public_pem_path,
    const std::string& private_pem_path
);

CryptoPP::RSA::PublicKey load_public_key_pem(const std::string& path);
CryptoPP::RSA::PrivateKey load_private_key_pem(const std::string& path);

int rsa_modulus_bits_from_public_pem(const std::string& path);

} // namespace rsatool
