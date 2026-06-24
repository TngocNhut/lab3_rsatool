#include "rsatool/rsa_oaep.hpp"

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

#include <stdexcept>
#include <string>

namespace rsatool {

size_t rsa_oaep_sha256_max_plaintext_size_bytes(
    const CryptoPP::RSA::PublicKey& public_key
) {
    CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor encryptor(public_key);
    return encryptor.FixedMaxPlaintextLength();
}

std::vector<uint8_t> rsa_oaep_sha256_encrypt(
    const CryptoPP::RSA::PublicKey& public_key,
    const std::vector<uint8_t>& plaintext,
    const std::string& label
) {
    if (!label.empty()) {
        throw std::runtime_error(
            "OAEP label is not enabled in this build checkpoint; use empty label for now"
        );
    }

    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor encryptor(public_key);

    const size_t max_len = encryptor.FixedMaxPlaintextLength();
    if (plaintext.size() > max_len) {
        throw std::runtime_error(
            "plaintext too large for direct RSA-OAEP-SHA256; hybrid mode is required"
        );
    }

    std::string plain_str(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
    );

    std::string cipher_str;

    CryptoPP::StringSource ss(
        plain_str,
        true,
        new CryptoPP::PK_EncryptorFilter(
            rng,
            encryptor,
            new CryptoPP::StringSink(cipher_str)
        )
    );

    return std::vector<uint8_t>(cipher_str.begin(), cipher_str.end());
}

std::vector<uint8_t> rsa_oaep_sha256_decrypt(
    const CryptoPP::RSA::PrivateKey& private_key,
    const std::vector<uint8_t>& ciphertext,
    const std::string& label
) {
    if (!label.empty()) {
        throw std::runtime_error(
            "OAEP label is not enabled in this build checkpoint; use empty label for now"
        );
    }

    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor decryptor(private_key);

    std::string cipher_str(
        reinterpret_cast<const char*>(ciphertext.data()),
        ciphertext.size()
    );

    std::string recovered;

    try {
        CryptoPP::StringSource ss(
            cipher_str,
            true,
            new CryptoPP::PK_DecryptorFilter(
                rng,
                decryptor,
                new CryptoPP::StringSink(recovered)
            )
        );
    } catch (const CryptoPP::Exception&) {
        throw std::runtime_error("RSA-OAEP decryption failed");
    }

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

} // namespace rsatool
