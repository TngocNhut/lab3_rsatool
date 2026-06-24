#include "rsatool/hybrid.hpp"

#include "rsatool/encoding.hpp"
#include "rsatool/file_utils.hpp"
#include "rsatool/rsa_oaep.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace rsatool {

namespace {

constexpr size_t AES256_KEY_SIZE = 32;
constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;

struct GcmEncryptResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
};

GcmEncryptResult aes256_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                                    const std::vector<uint8_t>& aes_key) {
    if (aes_key.size() != AES256_KEY_SIZE) {
        throw std::runtime_error("invalid AES-256 key length");
    }

    CryptoPP::AutoSeededRandomPool rng;

    GcmEncryptResult result;
    result.iv.resize(GCM_IV_SIZE);
    rng.GenerateBlock(result.iv.data(), result.iv.size());

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(aes_key.data(), aes_key.size(), result.iv.data(), result.iv.size());

    std::string input(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
    );

    std::string output;

    CryptoPP::AuthenticatedEncryptionFilter filter(
        enc,
        new CryptoPP::StringSink(output),
        false,
        GCM_TAG_SIZE
    );

    filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
        reinterpret_cast<const CryptoPP::byte*>(input.data()),
        input.size()
    );
    filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    if (output.size() < GCM_TAG_SIZE) {
        throw std::runtime_error("AES-GCM output too short");
    }

    const size_t ct_size = output.size() - GCM_TAG_SIZE;

    result.ciphertext.assign(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(ct_size));
    result.tag.assign(output.begin() + static_cast<std::ptrdiff_t>(ct_size), output.end());

    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& aes_key,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& tag) {
    if (aes_key.size() != AES256_KEY_SIZE) {
        throw std::runtime_error("invalid AES-256 key length");
    }

    if (iv.size() != GCM_IV_SIZE) {
        throw std::runtime_error("invalid AES-GCM IV length");
    }

    if (tag.size() != GCM_TAG_SIZE) {
        throw std::runtime_error("invalid AES-GCM tag length");
    }

    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(aes_key.data(), aes_key.size(), iv.data(), iv.size());

    std::string combined;
    combined.reserve(ciphertext.size() + tag.size());
    combined.assign(ciphertext.begin(), ciphertext.end());
    combined.append(tag.begin(), tag.end());

    std::string recovered;

    try {
        CryptoPP::AuthenticatedDecryptionFilter filter(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            GCM_TAG_SIZE
        );

        filter.ChannelPut(
            CryptoPP::DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(combined.data()),
            combined.size()
        );
        filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    } catch (const CryptoPP::Exception&) {
        throw std::runtime_error("AES-GCM authentication failed");
    }

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

} // namespace

void hybrid_encrypt_file(
    const CryptoPP::RSA::PublicKey& public_key,
    const std::vector<uint8_t>& plaintext,
    const std::string& out_path
) {
    CryptoPP::AutoSeededRandomPool rng;

    std::vector<uint8_t> aes_key(AES256_KEY_SIZE);
    rng.GenerateBlock(aes_key.data(), aes_key.size());

    const GcmEncryptResult gcm = aes256_gcm_encrypt(plaintext, aes_key);

    const std::vector<uint8_t> wrapped_key =
        rsa_oaep_sha256_encrypt(public_key, aes_key, "");

    nlohmann::json envelope;
    envelope["mode"] = "RSA-OAEP-AES-256-GCM";
    envelope["rsa_padding"] = "OAEP";
    envelope["rsa_hash"] = "SHA-256";
    envelope["rsa_mgf"] = "MGF1-SHA256";
    envelope["aes"] = "AES-256-GCM";
    envelope["iv_len"] = GCM_IV_SIZE;
    envelope["tag_len"] = GCM_TAG_SIZE;
    envelope["wrapped_key"] = base64_encode(wrapped_key);
    envelope["iv"] = base64_encode(gcm.iv);
    envelope["tag"] = base64_encode(gcm.tag);
    envelope["ciphertext"] = base64_encode(gcm.ciphertext);

    write_text_file(out_path, envelope.dump(4) + "\n");
}

std::vector<uint8_t> hybrid_decrypt_file(
    const CryptoPP::RSA::PrivateKey& private_key,
    const std::string& in_path
) {
    const std::vector<uint8_t> file_bytes = read_binary_file(in_path);
    const std::string text(file_bytes.begin(), file_bytes.end());

    nlohmann::json envelope;

    try {
        envelope = nlohmann::json::parse(text);
    } catch (...) {
        throw std::runtime_error("invalid hybrid envelope JSON");
    }

    if (!envelope.contains("mode") || envelope["mode"] != "RSA-OAEP-AES-256-GCM") {
        throw std::runtime_error("unsupported or invalid hybrid envelope mode");
    }

    const std::vector<uint8_t> wrapped_key = base64_decode(envelope.at("wrapped_key").get<std::string>());
    const std::vector<uint8_t> iv = base64_decode(envelope.at("iv").get<std::string>());
    const std::vector<uint8_t> tag = base64_decode(envelope.at("tag").get<std::string>());
    const std::vector<uint8_t> ciphertext = base64_decode(envelope.at("ciphertext").get<std::string>());

    const std::vector<uint8_t> aes_key =
        rsa_oaep_sha256_decrypt(private_key, wrapped_key, "");

    return aes256_gcm_decrypt(ciphertext, aes_key, iv, tag);
}

bool is_hybrid_envelope_file(const std::string& in_path) {
    try {
        const std::vector<uint8_t> file_bytes = read_binary_file(in_path);
        const std::string text(file_bytes.begin(), file_bytes.end());
        const nlohmann::json j = nlohmann::json::parse(text);
        return j.contains("mode") && j["mode"] == "RSA-OAEP-AES-256-GCM";
    } catch (...) {
        return false;
    }
}


bool looks_like_json_envelope_file(const std::string& in_path) {
    try {
        const std::vector<uint8_t> file_bytes = read_binary_file(in_path);
        const std::string text(file_bytes.begin(), file_bytes.end());
        const nlohmann::json j = nlohmann::json::parse(text);

        return j.is_object() && (
            j.contains("mode") ||
            j.contains("wrapped_key") ||
            j.contains("ciphertext") ||
            j.contains("tag") ||
            j.contains("iv")
        );
    } catch (...) {
        return false;
    }
}

} // namespace rsatool
