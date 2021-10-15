#include <fstream>
#include <unordered_map>

#include <mkbktr/keys.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

namespace mk {

// std::string header_key;

std::unique_ptr<Keys> Keys::from_file(const char *path) {
  // Try and open the key file
  std::ifstream ss(path);
  if (!ss.is_open()) {
    LOG("Failed to open '%s'\n", path);
    return nullptr;
  }

  // Split into lines
  std::string line;
  std::unordered_map<std::string, std::string> keys_by_name;
  while (std::getline(ss, line, '\n')) {
    // Split line on '='
    auto pos = line.find('=');
    if (pos == std::string::npos) {
      LOG("Failed to parse key line '%s'\n", line.c_str());
      continue;
    }
    std::string key = line.substr(0, pos);
    std::string value = line.substr(pos + 1);
    string::trim(key);
    string::trim(value);
    keys_by_name[key] = string::hex_to_bytes(value);
  }

  return std::unique_ptr<Keys>(new Keys(keys_by_name));
}

} // namespace mk
