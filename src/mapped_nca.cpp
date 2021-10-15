#include <string.h>

#include <memory>

#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/string.hpp>

namespace mk {

static const uint32_t AES_SECTOR_SIZE = 0x200;

MappedNca::MappedNca(std::unique_ptr<mk::mem::MappedData> backing_data,
                     mk::Keys keys)
    : _backing_data(std::move(backing_data)), _keys(keys) {}

void MappedNca::print_header_info() {
  LOG("Magicnum: %c%c%c%c\n", _header->magic[0], _header->magic[1],
      _header->magic[2], _header->magic[3]);
  LOG("Distribution type: %u\n", _header->distribution_type);
  LOG("Content type: %u\n", _header->content_type);
  LOG("Key generation old: %u\n", _header->key_generation_old);
  LOG("Key area encryption area index: %u\n",
      _header->key_area_encryption_key_index);

  LOG("Content size: %lu\n", _header->content_size);
  LOG("Program ID: %lx\n", _header->program_id);
  LOG("Content index: %u\n", _header->content_index);
  LOG("SDK addon ver: %u\n", _header->sdk_addon_version);

  LOG("Key generation: %u\n", _header->key_generation);
  LOG("Header 1 sig key gen: %u\n", _header->header_1_signature_key_generation);
  LOG("Rights ID: 0x%s\n",
      mk::string::bytes_to_hex(
          std::string(reinterpret_cast<const char *>(_header->rights_id),
                      sizeof(_header->rights_id)))
          .c_str());

  for (auto &fs_entry : _header->fs_entries) {
    LOG("Fs entry start offset: %08x, end offset %08x\n", fs_entry.start_offset,
        fs_entry.end_offset);
  }

  for (auto &fs_hash : _header->fs_header_hashes) {
    LOG("Fs entry hash: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(fs_hash),
                        sizeof(fs_hash)))
            .c_str());
  }

  for (auto &encrypted_key : _header->encrypted_key_areas) {
    LOG("Encrypted key: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(encrypted_key.key),
                        sizeof(encrypted_key.key)))
            .c_str());
  }

  for (auto &decrypted_key : _decrypted_keys) {
    LOG("Decrypted key: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(decrypted_key),
                        sizeof(decrypted_key)))
            .c_str());
  }
}

void MappedNca::print_bktr_section(int section) {
  MKASSERT(section < 4);

  // Get references to filesystem header/entry data
  const NcaFsHeader *fs_header = _fs_headers[section];
  const NcaFsEntry *fs_entry = &_header->fs_entries[section];

  // The relocation header and subsection header must be contiguous
  MKASSERT(fs_header->bktr_superblock.relocation_header.offset +
               fs_header->bktr_superblock.relocation_header.size ==
           fs_header->bktr_superblock.subsection_header.offset);

  // Relocation area + subsection area must equal section size
  MKASSERT(fs_header->bktr_superblock.subsection_header.offset +
               fs_header->bktr_superblock.subsection_header.size ==
           (fs_entry->end_offset - fs_entry->start_offset) *
               fs_entry->SECTOR_SIZE);

  // Get the start offset of the section
  const uint64_t section_offset =
      fs_entry->start_offset * fs_entry->SECTOR_SIZE;

  // Decrypt the relocation header
  const uint64_t relocation_header_offset =
      fs_header->bktr_superblock.relocation_header.offset;
  const std::string decrypted_relocations =
      read_aes_ctr(section, relocation_header_offset,
                   fs_header->bktr_superblock.relocation_header.size);

  // Relocation bucket header
  const BktrHeaderEntry *relocation_header =
      reinterpret_cast<const BktrHeaderEntry *>(decrypted_relocations.data());
  LOG("Bucket count: %u, patched image size: %lu\n",
      relocation_header->bucket_count, relocation_header->patched_image_size);

  // Decrypt the buckets
  const uint64_t relocation_bucket_data_offset =
      relocation_header_offset + sizeof(BktrHeaderEntry);
  const std::string decrypted_relocation_buckets = read_aes_ctr(
      section, relocation_bucket_data_offset,
      sizeof(BktrRelocationBucket) * relocation_header->bucket_count);

  // Relocation buckets
  const BktrRelocationBucket *relocation_buckets =
      reinterpret_cast<const BktrRelocationBucket *>(
          decrypted_relocation_buckets.data());
  for (uint32_t i = 0; i < relocation_header->bucket_count; i++) {
    LOG("Bucket %4d: entry count: %d\n", i, relocation_buckets[i].entry_count);
    for (uint32_t entry = 0; entry < relocation_buckets[i].entry_count;
         entry++) {
      LOG("    entry %4d: patch addr: %016lx, src addr: %016lx, src: %s\n",
          entry, relocation_buckets[i].entries[entry].patched_address,
          relocation_buckets[i].entries[entry].source_address,
          relocation_buckets[i].entries[entry].is_patched ? "patch" : "base");
    }
  }

  // Decrypt the subsection header
  const uint64_t subsection_header_offset =
      fs_header->bktr_superblock.subsection_header.offset;
  const std::string decrypted_subsections =
      read_aes_ctr(section, subsection_header_offset,
                   fs_header->bktr_superblock.subsection_header.size);

  // Subsection bucket header
  const BktrHeaderEntry *subsection_header =
      reinterpret_cast<const BktrHeaderEntry *>(decrypted_subsections.data());
  LOG("Bucket count: %u, patched image size: %lu\n",
      subsection_header->bucket_count, subsection_header->patched_image_size);

  // Decrypt subsection buckets
  const uint64_t subsection_bucket_data_offset =
      subsection_header_offset + sizeof(BktrHeaderEntry);
  const std::string decrypted_subsection_buckets = read_aes_ctr(
      section, subsection_bucket_data_offset,
      sizeof(BktrSubsectionBucket) * subsection_header->bucket_count);

  // Subsection buckets
  const BktrSubsectionBucket *subsection_buckets =
      reinterpret_cast<const BktrSubsectionBucket *>(
          decrypted_subsection_buckets.data());
  for (uint32_t i = 0; i < subsection_header->bucket_count; i++) {
    LOG("Bucket %4d: entry count: %d\n", i, subsection_buckets[i].entry_count);
    for (uint32_t entry = 0; entry < subsection_buckets[i].entry_count;
         entry++) {
      LOG("    entry %4d: offset: %016lx, AES CTR: %08x\n", entry,
          subsection_buckets[i].entries[entry].offset,
          subsection_buckets[i].entries[entry].aes_ctr);
    }
  }
}

void init_ctr_for_section(const NcaFsHeader &fs_header, uint8_t *ctr) {
  uint32_t section_ctr[2];
  section_ctr[0] = __bswap_32(fs_header.secure_value);
  section_ctr[1] = __bswap_32(fs_header.generation);
  memcpy(ctr, section_ctr, sizeof(section_ctr));
}

static void nca_update_ctr(uint8_t *ctr, uint64_t offset) {
  offset >>= 4;
  for (unsigned j = 0; j < 0x8; j++) {
    ctr[0x10 - j - 1] = static_cast<uint8_t>(offset & 0xFF);
    offset >>= 8;
  }
}

std::string MappedNca::read_aes_ctr_aligned(int section, uint64_t data_offset,
                                            uint64_t len) {
  // Get sector start offset
  MKASSERT(section < 4);
  const uint64_t section_offset =
      _header->fs_entries[section].start_offset * NcaFsEntry::SECTOR_SIZE;

  // Assert that the read is aligned
  MKASSERT(((section_offset + data_offset) & 0xFF) == 0);

  // Initialize the CTR
  uint8_t ctr[0x10];
  init_ctr_for_section(*_fs_headers[section], ctr);
  nca_update_ctr(ctr, section_offset + data_offset);

  // Select appropriate aes ctx
  aes_ctx_t *aes_ctx = nullptr;
  if (_fs_headers[section]->encryption_type == 4) {
    aes_ctx = _fs_entry_aes_ctxs[2];
  }
  MKASSERT(aes_ctx != nullptr);

  // Decrypt
  std::string decrypted;
  decrypted.resize(len);
  aes_setiv(aes_ctx, ctr, sizeof(ctr));
  aes_decrypt(aes_ctx, reinterpret_cast<uint8_t *>(decrypted.data()),
              _backing_data->_data + section_offset + data_offset, len);

  return decrypted;
}

std::string MappedNca::read_aes_ctr(int section, uint64_t data_offset,
                                    uint64_t len) {
  return read_aes_ctr_aligned(section, data_offset, len);
}

std::unique_ptr<MappedNca>
MappedNca::parse(std::unique_ptr<mk::mem::MappedData> backing_data,
                 mk::Keys keys) {
  // Create our NCA
  auto nca =
      std::unique_ptr<MappedNca>(new MappedNca(std::move(backing_data), keys));

  // Create xts context for header
  nca->_aes_xts_ctx = new_aes_ctx(keys.get("header_key"), 32, AES_MODE_XTS);

  // Decrypt header
  uint8_t xts_header[0xC00];
  aes_xts_decrypt(nca->_aes_xts_ctx, nca->_xts_header_decrypted,
                  nca->_backing_data->_data, sizeof(nca->_xts_header_decrypted),
                  0, AES_SECTOR_SIZE);

  // Check magic
  if (strcmp(nca->_header->magic, "NCA3")) {
    LOG("Unhandled header magic\n");
    return nullptr;
  }

  // Decrypt key area
  {
    aes_ctx_t *key_aes_ctx =
        new_aes_ctx(keys.get("key_area_key_application_0a"), 16, AES_MODE_ECB);
    aes_decrypt(key_aes_ctx, (uint8_t *)nca->_decrypted_keys,
                (uint8_t *)nca->_header->encrypted_key_areas,
                sizeof(nca->_header->encrypted_key_areas));
    free_aes_ctx(key_aes_ctx);
  }

  // Create AES-CTR contexts from the section keys
  {
    for (int i = 0; i < 4; i++) {
      nca->_fs_entry_aes_ctxs[i] =
          new_aes_ctx(nca->_decrypted_keys[i], sizeof(nca->_decrypted_keys[i]),
                      AES_MODE_CTR);
    }
  }

  return nca;
}
} // namespace mk
