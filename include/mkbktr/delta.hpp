#pragma once

#include <string_view>
#include <vector>

#include <mkbktr/mktr_structs.hpp>

namespace mk {
namespace delta {

static const int64_t DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024; // 4MiB

// Given an base file and an updated file, generate a list of relocation entries
std::vector<BktrRelocationEntry>
generate_diff(const std::string_view &old_data,
              const std::string_view &new_data,
              int64_t block_size = DEFAULT_BLOCK_SIZE);

} // namespace delta
} // namespace mk
