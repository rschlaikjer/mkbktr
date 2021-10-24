#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <mkbktr/mktr_structs.hpp>

namespace mk {
namespace delta {

static const int64_t DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024; // 4MiB

// Wrapper for patch data + relocation entries
struct Delta {
  std::string patch_data;
  std::vector<BktrRelocationEntry> relocations;
};

// Given an base file and an updated file, generate a list of relocation entries
Delta generate_diff(const std::string_view &old_data,
                    const std::string_view &new_data,
                    int64_t block_size = DEFAULT_BLOCK_SIZE);

} // namespace delta
} // namespace mk
