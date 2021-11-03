#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <mkbktr/util/mem.hpp>

namespace mk {
namespace mem {

MappedData::~MappedData() { munmap(const_cast<uint8_t *>(_data), _size); }

std::unique_ptr<MappedData> MappedData::from_file(const char *filename) {
  int file_fd = ::open(filename, O_RDONLY);
  if (file_fd < 0) {
    return nullptr;
  }

  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(file_fd); });

  const off_t file_size = ::lseek(file_fd, 0, SEEK_END);
  if (file_size < 0) {
    return nullptr;
  }
  if (lseek(file_fd, 0, SEEK_SET) < 0) {
    return nullptr;
  }

  void *mmapped_data =
    mmap(nullptr, file_size, PROT_READ, MAP_SHARED, file_fd, 0);

  if (mmapped_data == nullptr) {
    return nullptr;
  }

  return std::make_unique<MappedData>(reinterpret_cast<uint8_t *>(mmapped_data),
                                      file_size);
}

const std::string_view MappedData::view() const {
  return std::string_view{reinterpret_cast<const char *>(_data),
                          static_cast<std::string_view::size_type>(_size)};
}

} // namespace mem
} // namespace mk
