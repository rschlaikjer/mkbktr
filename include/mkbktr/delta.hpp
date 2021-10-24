#pragma once

#include <string_view>
#include <vector>

#include <mkbktr/mktr_structs.hpp>

namespace mk {
namespace delta {

// Given an base file and an updated file, generate a list of relocation entries
std::vector<BktrRelocationEntry>
generate_diff(const std::string_view &old_data,
              const std::string_view &new_data);

} // namespace delta
} // namespace mk
