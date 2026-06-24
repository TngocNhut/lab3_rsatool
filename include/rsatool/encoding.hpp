#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rsatool {

std::string to_hex(const std::vector<uint8_t>& data);
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& text);
std::string pem_wrap(const std::string& label, const std::vector<uint8_t>& der);
std::vector<uint8_t> pem_unwrap(const std::string& pem_text);

} // namespace rsatool
