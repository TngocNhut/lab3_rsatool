#pragma once

#include <string>

namespace rsatool {

void run_rsa_benchmark_csv(int bits, const std::string& out_csv);

void run_hybrid_benchmark_csv(
    const std::string& public_key_pem,
    const std::string& private_key_pem,
    const std::string& out_csv
);

} // namespace rsatool
