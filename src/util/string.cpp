#include <mkbktr.hpp>
#include <mkbktr/util/string.hpp>

namespace mkbktr {
namespace string {

std::string hex_to_bytes(const std::string &hex) {
  MKASSERT(hex.size() % 2 == 0);
  std::string ret;
  ret.resize(hex.size() / 2);

  auto nibble_to_int = [](char nibble) -> int {
    // Uppercase
    if (nibble >= '0' && nibble <= '9') {
      return nibble - '0';
    }
    if (nibble >= 'A' && nibble <= 'F') {
      return nibble - 'A' + 10;
    }
    if (nibble >= 'a' && nibble <= 'f') {
      return nibble - 'a' + 10;
    }
    MKASSERT(false);
    return -1;
  };

  for (std::string::size_type i = 0; i < ret.size(); i++) {
    ret[i] = nibble_to_int(hex[i * 2]) << 4 | nibble_to_int(hex[i * 2 + 1]);
  }

  return ret;
}

} // namespace string
} // namespace mkbktr
