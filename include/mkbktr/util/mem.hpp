#pragma once

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <string_view>

namespace mk {
namespace mem {

struct MappedData {
  // MMap'd file data
  MappedData(const uint8_t *data, ssize_t size) : _data(data), _size(size) {}
  ~MappedData();
  MappedData(const MappedData &other) = delete;
  MappedData &operator=(const MappedData &other) = delete;
  const uint8_t *const _data;
  const ssize_t _size;

  static std::unique_ptr<MappedData> from_file(const char *filename);
  const std::string_view view() const;
};

} // namespace mem
} // namespace mk
