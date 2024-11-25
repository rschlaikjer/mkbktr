#include <stdint.h>

#include <mkbktr.hpp>
#include <mkbktr/util/string.hpp>

namespace mk {
namespace string {

std::string bytes_to_hex(const std::string &bytes) {
  std::string ret;
  ret.resize(bytes.size() * 2);
  auto nibble_to_hex = [](uint8_t nibble) -> char {
    nibble &= 0xF;
    if (nibble < 10)
      return '0' + nibble;
    return 'A' + (nibble - 10);
  };

  for (std::string::size_type i = 0; i < bytes.size(); i++) {
    uint8_t byte = bytes[i];
    ret[i * 2] = nibble_to_hex(byte >> 4);
    ret[i * 2 + 1] = nibble_to_hex(byte);
  }

  return ret;
}

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
} // namespace mk
