#pragma once

#include <memory>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/mem.hpp>

namespace mk {

class MappedNca {
public:
  static std::unique_ptr<MappedNca>
  parse(std::unique_ptr<mk::mem::MappedData> backing_data, mk::Keys keys);

public:
  void print_header_info();
  void print_bktr_section(int section);
  void print_romfs_section(int section);

  // Read and decrypt data from a section that uses AES-CTR
  // May only be used for reads that are aligned on a sector boundary
  void read_aes_ctr_aligned(int section, uint64_t data_offset, uint64_t len,
                            uint8_t *out) const;

  // Read and drcrypt data from a section that uses AES-CTR
  // Does not require sector alignment, but may incur memmove
  void read_aes_ctr(int section, uint64_t data_offset, uint64_t len,
                    uint8_t *out) const;
  std::string read_aes_ctr(int section, uint64_t data_offset,
                           uint64_t len) const;

  // Read and decrypt an entire section's data
  std::string decrypt_section(int section);

  // Size of a section, in bytes
  uint64_t section_size(int section) const;

  // Pointer to the start of section data
  const uint8_t *section_data(int section);

  const uint8_t *header_plaintext() { return _xts_header_decrypted; }

  std::unordered_map<uint64_t, std::string> list_files(int section);

private:
  MappedNca(std::unique_ptr<mk::mem::MappedData> backing_data, mk::Keys keys);

public:
  // Underlying source data file
  const std::unique_ptr<mk::mem::MappedData> _backing_data;

  // Copy of decryption keys
  const mk::Keys _keys;

  // AES context for header data
  aes_ctx_t *_aes_xts_ctx = nullptr;

  // Raw decrypted data for header context
  uint8_t _xts_header_decrypted[0xC00];
  // Header pointer over the decrypted data
  const NcaHeader *const _header =
      reinterpret_cast<NcaHeader *>(_xts_header_decrypted);

  // Decrypted header keys
  uint8_t _decrypted_keys[4][0x10];

  // AES contexts created from section keys
  aes_ctx_t *_fs_entry_aes_ctxs[4];

  // FS headers are at 0x400 + sectionId * 0x200
  const NcaFsHeader *_fs_headers[4] = {
      reinterpret_cast<NcaFsHeader *>(
          &_xts_header_decrypted[0x400 + 0x200 * 0]),
      reinterpret_cast<NcaFsHeader *>(
          &_xts_header_decrypted[0x400 + 0x200 * 1]),
      reinterpret_cast<NcaFsHeader *>(
          &_xts_header_decrypted[0x400 + 0x200 * 2]),
      reinterpret_cast<NcaFsHeader *>(
          &_xts_header_decrypted[0x400 + 0x200 * 3]),
  };
};

class NcaSectionView {
public:
  static const int64_t BLOCK_SIZE_BYTES = 16 * 1024 * 1024;

public:
  NcaSectionView(const MappedNca &nca, int section);
  ~NcaSectionView();
  uint8_t operator[](int64_t offset);
  uint64_t size();
  void read(int64_t offset, int64_t len, uint8_t *out);

  // No copying
  NcaSectionView(const NcaSectionView &other) = delete;
  NcaSectionView &operator=(const NcaSectionView &other) = delete;

private:
  const MappedNca &_nca;
  const int _section;

  // Start address of current decrypted buffer data
  int64_t _current_section_base = -1;
  uint8_t *_current_section = nullptr;
};

} // namespace mk
