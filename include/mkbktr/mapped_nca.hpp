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

  // Read and decrypt data from a section that uses AES-CTR
  // May only be used for reads that are aligned on a sector boundary
  std::string read_aes_ctr_aligned(int section, uint64_t data_offset,
                                   uint64_t len);

  // Read and drcrypt data from a section that uses AES-CTR
  // Does not require sector alignment, but may incur memmove
  std::string read_aes_ctr(int section, uint64_t data_offset, uint64_t len);

private:
  MappedNca(std::unique_ptr<mk::mem::MappedData> backing_data, mk::Keys keys);

private:
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

} // namespace mk
