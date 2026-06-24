#include "rsatool/rsa_keys.hpp"

#include "rsatool/encoding.hpp"
#include "rsatool/file_utils.hpp"

#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>

#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace rsatool {

namespace {

std::string utc_now_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

template <typename KeyT>
std::vector<uint8_t> save_key_to_der_bytes(const KeyT& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    std::vector<uint8_t> der(static_cast<size_t>(queue.CurrentSize()));
    if (!der.empty()) {
        queue.Get(der.data(), der.size());
    }

    return der;
}

template <typename KeyT>
void load_key_from_der_bytes(KeyT& key, const std::vector<uint8_t>& der) {
    CryptoPP::ByteQueue queue;
    queue.Put(der.data(), der.size());
    queue.MessageEnd();
    key.Load(queue);
}

std::string replace_extension_or_append(const std::string& path, const std::string& suffix) {
    std::filesystem::path p(path);
    p.replace_extension(suffix);
    return p.string();
}

} // namespace

RsaKeyPairPaths generate_rsa_keypair_files(
    int bits,
    const std::string& public_pem_path,
    const std::string& private_pem_path
) {
    if (bits != 3072 && bits != 4096) {
        throw std::runtime_error("RSA modulus size must be 3072 or 4096 bits");
    }

    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey private_key;
    private_key.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(bits));

    CryptoPP::RSA::PublicKey public_key(private_key);

    if (!private_key.Validate(rng, 3)) {
        throw std::runtime_error("generated RSA private key failed validation");
    }

    if (!public_key.Validate(rng, 3)) {
        throw std::runtime_error("generated RSA public key failed validation");
    }

    const std::vector<uint8_t> pub_der = save_key_to_der_bytes(public_key);
    const std::vector<uint8_t> priv_der = save_key_to_der_bytes(private_key);

    const std::string public_der_path = replace_extension_or_append(public_pem_path, ".der");
    const std::string private_der_path = replace_extension_or_append(private_pem_path, ".der");
    const std::string metadata_path = replace_extension_or_append(private_pem_path, ".metadata.json");

    write_binary_file(public_der_path, pub_der);
    write_binary_file(private_der_path, priv_der);

    write_text_file(public_pem_path, pem_wrap("RSA PUBLIC KEY", pub_der));
    write_text_file(private_pem_path, pem_wrap("RSA PRIVATE KEY", priv_der));

    nlohmann::json meta;
    meta["creation_time"] = utc_now_iso8601();
    meta["modulus_bits"] = bits;
    meta["hash"] = "SHA-256";
    meta["padding"] = "OAEP";
    meta["mgf"] = "MGF1-SHA256";
    meta["public_key_pem"] = public_pem_path;
    meta["private_key_pem"] = private_pem_path;
    meta["public_key_der"] = public_der_path;
    meta["private_key_der"] = private_der_path;
    meta["library"] = "Crypto++";

    write_text_file(metadata_path, meta.dump(4) + "\n");

    return {
        public_pem_path,
        private_pem_path,
        public_der_path,
        private_der_path,
        metadata_path
    };
}

CryptoPP::RSA::PublicKey load_public_key_pem(const std::string& path) {
    const std::vector<uint8_t> file_bytes = read_binary_file(path);
    const std::string pem_text(file_bytes.begin(), file_bytes.end());
    const std::vector<uint8_t> der = pem_unwrap(pem_text);

    CryptoPP::RSA::PublicKey key;
    load_key_from_der_bytes(key, der);

    CryptoPP::AutoSeededRandomPool rng;
    if (!key.Validate(rng, 3)) {
        throw std::runtime_error("RSA public key validation failed");
    }

    return key;
}

CryptoPP::RSA::PrivateKey load_private_key_pem(const std::string& path) {
    const std::vector<uint8_t> file_bytes = read_binary_file(path);
    const std::string pem_text(file_bytes.begin(), file_bytes.end());
    const std::vector<uint8_t> der = pem_unwrap(pem_text);

    CryptoPP::RSA::PrivateKey key;
    load_key_from_der_bytes(key, der);

    CryptoPP::AutoSeededRandomPool rng;
    if (!key.Validate(rng, 3)) {
        throw std::runtime_error("RSA private key validation failed");
    }

    return key;
}

int rsa_modulus_bits_from_public_pem(const std::string& path) {
    const CryptoPP::RSA::PublicKey key = load_public_key_pem(path);
    return static_cast<int>(key.GetModulus().BitCount());
}

} // namespace rsatool
