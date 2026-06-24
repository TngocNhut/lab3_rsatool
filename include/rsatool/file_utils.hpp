#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rsatool {

std::vector<uint8_t> read_binary_file(const std::string& path);
void write_binary_file(const std::string& path, const std::vector<uint8_t>& data);
void write_text_file(const std::string& path, const std::string& text);
bool file_exists(const std::string& path);

} // namespace rsatool
