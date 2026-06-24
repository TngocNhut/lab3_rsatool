#pragma once

#include <cryptopp/rsa.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rsatool {

size_t rsa_oaep_sha256_max_plaintext_size_bytes(
    const CryptoPP::RSA::PublicKey& public_key
);

std::vector<uint8_t> rsa_oaep_sha256_encrypt(
    const CryptoPP::RSA::PublicKey& public_key,
    const std::vector<uint8_t>& plaintext,
    const std::string& label
);

std::vector<uint8_t> rsa_oaep_sha256_decrypt(
    const CryptoPP::RSA::PrivateKey& private_key,
    const std::vector<uint8_t>& ciphertext,
    const std::string& label
);

} // namespace rsatool
