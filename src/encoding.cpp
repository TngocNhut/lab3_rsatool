#include "rsatool/encoding.hpp"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace rsatool {

std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }

    return oss.str();
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string encoded;

    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}

std::vector<uint8_t> base64_decode(const std::string& text) {
    std::string decoded;

    CryptoPP::StringSource ss(
        text,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        )
    );

    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::string pem_wrap(const std::string& label, const std::vector<uint8_t>& der) {
    const std::string b64 = base64_encode(der);

    std::ostringstream oss;
    oss << "-----BEGIN " << label << "-----\n";

    for (size_t i = 0; i < b64.size(); i += 64) {
        oss << b64.substr(i, 64) << "\n";
    }

    oss << "-----END " << label << "-----\n";
    return oss.str();
}

std::vector<uint8_t> pem_unwrap(const std::string& pem_text) {
    std::string b64;

    std::istringstream iss(pem_text);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.rfind("-----BEGIN ", 0) == 0) {
            continue;
        }
        if (line.rfind("-----END ", 0) == 0) {
            continue;
        }

        for (char ch : line) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                b64.push_back(ch);
            }
        }
    }

    if (b64.empty()) {
        throw std::runtime_error("invalid PEM: no base64 body found");
    }

    return base64_decode(b64);
}

} // namespace rsatool
