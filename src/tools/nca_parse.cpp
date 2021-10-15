#include <stdio.h>
#include <string.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

static void nca_update_ctr(uint8_t *ctr, uint64_t offset) {
  offset >>= 4;
  for (unsigned j = 0; j < 0x8; j++) {
    ctr[0x10 - j - 1] = static_cast<uint8_t>(offset & 0xFF);
    offset >>= 8;
  }
}

[[maybe_unused]] static void
nca_update_bktr_ctr(uint8_t *ctr, uint32_t subsection_ctr, uint64_t offset) {
  offset >>= 4;
  for (unsigned j = 0; j < 0x8; j++) {
    ctr[0x10 - j - 1] = static_cast<uint8_t>(offset & 0xFF);
    offset >>= 8;
  }
  for (unsigned j = 0; j < 4; j++) {
    ctr[0x8 - j - 1] = static_cast<uint8_t>(subsection_ctr & 0xFF);
    subsection_ctr >>= 8;
  }
}

void init_ctr_for_section(const NcaFsHeader *fs_header, uint8_t *ctr) {
  uint32_t section_ctr[2];
  section_ctr[0] = __bswap_32(fs_header->secure_value);
  section_ctr[1] = __bswap_32(fs_header->generation);
  memcpy(ctr, section_ctr, sizeof(section_ctr));
}

std::string nca_read_aes_ctr(aes_ctx_t *aes_ctx, const uint8_t *data,
                             uint64_t section_offset, uint64_t data_offset,
                             uint64_t len) {
  MKASSERT(((section_offset + data_offset) & 0xFF) == 0);

  // Decrypt
  std::string decrypted;
  decrypted.resize(len);
  aes_decrypt(aes_ctx, reinterpret_cast<uint8_t *>(decrypted.data()),
              data + section_offset + data_offset, len);

  return decrypted;
}

void print_bktr(const mkbktr::mem::MappedData &nca, aes_ctx_t *aes_ctx,
                const NcaFsEntry *fs_entry, const NcaFsHeader *fs_header) {

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

  // Regenerate ctr
  uint8_t ctr[0x10];
  init_ctr_for_section(fs_header, ctr);
  nca_update_ctr(ctr, section_offset +
                          fs_header->bktr_superblock.relocation_header.offset);
  aes_setiv(aes_ctx, ctr, 0x10);

  // Decrypt the relocations
  const std::string decrypted_relocations =
      nca_read_aes_ctr(aes_ctx, nca._data, section_offset,
                       fs_header->bktr_superblock.relocation_header.offset,
                       fs_header->bktr_superblock.relocation_header.size);

  LOG("ok");
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [nca filename]\n", argv[0]);
    return -1;
  }

  // Load file
  const char *nca_filename = argv[1];
  auto mapped_nca = mkbktr::mem::MappedData::from_file(nca_filename);
  if (mapped_nca == nullptr) {
    LOG("Failed to open '%s'\n", nca_filename);
    return -1;
  }

  // Load keys
  auto keys =
      mkbktr::Keys::from_file("/home/ross/.local/share/yuzu/keys/prod.keys");
  if (keys == nullptr) {
    return -1;
  }

  // Create xts context for header
  aes_ctx_t *xts_ctx = new_aes_ctx(keys->get("header_key"), 32, AES_MODE_XTS);

  // Decrypt header
  uint8_t xts_header[0xC00];
  aes_xts_decrypt(xts_ctx, xts_header, mapped_nca->_data, 0xC00, 0, 0x200);

  NcaHeader *header = reinterpret_cast<NcaHeader *>(xts_header);
  LOG("Magicnum: %c%c%c%c\n", header->magic[0], header->magic[1],
      header->magic[2], header->magic[3]);

  if (strcmp(header->magic, "NCA3")) {
    LOG("Unhandled header magic\n");
    return -1;
  }

  LOG("Distribution type: %u\n", header->distribution_type);
  LOG("Content type: %u\n", header->content_type);
  LOG("Key generation old: %u\n", header->key_generation_old);
  LOG("Key area encryption area index: %u\n",
      header->key_area_encryption_key_index);

  LOG("Content size: %lu\n", header->content_size);
  LOG("Program ID: %lx\n", header->program_id);
  LOG("Content index: %u\n", header->content_index);
  LOG("SDK addon ver: %u\n", header->sdk_addon_version);

  LOG("Key generation: %u\n", header->key_generation);
  LOG("Header 1 sig key gen: %u\n", header->header_1_signature_key_generation);
  LOG("Rights ID: 0x%s\n",
      mkbktr::string::bytes_to_hex(
          std::string(reinterpret_cast<const char *>(header->rights_id),
                      sizeof(header->rights_id)))
          .c_str());

  for (auto &fs_entry : header->fs_entries) {
    LOG("Fs entry start offset: %08x, end offset %08x\n", fs_entry.start_offset,
        fs_entry.end_offset);
  }

  for (auto &fs_hash : header->fs_header_hashes) {
    LOG("Fs entry hash: %s\n",
        mkbktr::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(fs_hash),
                        sizeof(fs_hash)))
            .c_str());
  }

  for (auto &encrypted_key : header->encrypted_key_areas) {
    LOG("Encrypted key: %s\n",
        mkbktr::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(encrypted_key.key),
                        sizeof(encrypted_key.key)))
            .c_str());
  }

  // Decrypt key area
  uint8_t decrypted_keys[4][0x10];
  {
    aes_ctx_t *key_aes_ctx =
        new_aes_ctx(keys->get("key_area_key_application_0a"), 16, AES_MODE_ECB);
    aes_decrypt(key_aes_ctx, (uint8_t *)decrypted_keys,
                (uint8_t *)header->encrypted_key_areas, 0x40);
    free_aes_ctx(key_aes_ctx);

    for (auto &decrypted : decrypted_keys) {
      LOG("Decrypted key: %s\n",
          mkbktr::string::bytes_to_hex(
              std::string(reinterpret_cast<const char *>(decrypted),
                          sizeof(decrypted)))
              .c_str());
    }
  }

  // BKTR key
  aes_ctx_t *bktr_aes_ctx = new_aes_ctx(decrypted_keys[2], 16, AES_MODE_CTR);

  // FS headers are at 0x400 + sectionId * 0x200
  for (int i = 0; i < 4; i++) {
    // Ignore empty sections
    auto &fs_entry = header->fs_entries[i];
    if (fs_entry.start_offset == fs_entry.end_offset) {
      continue;
    }

    long start_offset_bytes = 0x400 + (i * 0x200);
    NcaFsHeader *fs_header =
        reinterpret_cast<NcaFsHeader *>(&xts_header[start_offset_bytes]);
    LOG("%p\n", fs_header);

    if (fs_header->hash_type == 0x03) { // BKTR
      print_bktr(*mapped_nca, bktr_aes_ctx, &fs_entry, fs_header);
    }
  }

  return 0;
}
