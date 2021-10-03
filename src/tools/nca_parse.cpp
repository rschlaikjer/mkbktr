#include <stdio.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

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
  }

  return 0;
}
