#pragma once

#include <cryptopp/rsa.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rsatool {

void hybrid_encrypt_file(
    const CryptoPP::RSA::PublicKey& public_key,
    const std::vector<uint8_t>& plaintext,
    const std::string& out_path
);

std::vector<uint8_t> hybrid_decrypt_file(
    const CryptoPP::RSA::PrivateKey& private_key,
    const std::string& in_path
);

bool is_hybrid_envelope_file(const std::string& in_path);

} // namespace rsatool
