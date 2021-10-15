#pragma once

#include <memory>
#include <string>
#include <unordered_map>

namespace mk {

struct Keys {

  const uint8_t *get(const std::string &name) const {
    return reinterpret_cast<const uint8_t *>(_keys_by_name.at(name).data());
  }

  static std::unique_ptr<Keys> from_file(const char *path);

protected:
  Keys(std::unordered_map<std::string, std::string> keys)
      : _keys_by_name(keys) {}

private:
  std::unordered_map<std::string, std::string> _keys_by_name;
};

} // namespace mk
