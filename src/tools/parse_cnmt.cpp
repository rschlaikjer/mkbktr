#include <stdio.h>
#include <string.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [cnmt filename]\n", argv[0]);
    return -1;
  }

  // Load file
  const char *cnmt_filename = argv[1];
  auto mapped_cnmt_file = mk::mem::MappedData::from_file(cnmt_filename);
  if (mapped_cnmt_file == nullptr) {
    LOG("Failed to open '%s'\n", cnmt_filename);
    return -1;
  }

  const CnmtHeader *const header =
      reinterpret_cast<const CnmtHeader *>(mapped_cnmt_file->_data);
  LOG("title_id:                  %016lx\n", header->title_id);
  LOG("title_version:             %08lx\n", header->title_version);
  LOG("content_meta_type:         %u\n", header->content_meta_type);
  LOG("table_offset:              %u\n", header->table_offset);
  LOG("content_entry_count:       %u\n", header->content_entry_count);
  LOG("content_meta_entry_count:  %u\n", header->content_meta_entry_count);
  LOG("content_meta_attrs:        %u\n", header->content_meta_attrs);
  LOG("required_dl_sys_ver:       %u\n", header->required_download_sys_version);

  for (unsigned i = 0; i < header->content_entry_count; i++) {
    const uint64_t offset = sizeof(CnmtHeader) + header->table_offset +
                            i * sizeof(CnmtPackagedContentInfo);
    const CnmtPackagedContentInfo *const content_info =
        reinterpret_cast<const CnmtPackagedContentInfo *>(
            &mapped_cnmt_file->_data[offset]);
    LOG("ContentInfo %u:\n", i);
    LOG("    hash:          %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(content_info->hash),
                        sizeof(content_info->hash)))
            .c_str());
    LOG("    content_id:    %s\n",
        mk::string::bytes_to_hex(std::string(reinterpret_cast<const char *>(
                                                 content_info->content_id),
                                             sizeof(content_info->content_id)))
            .c_str());
    uint64_t size = 0;
    for (int j = 0; j < 6; j++) {
      size |= content_info->size[j] << (8 * j);
    }
    LOG("    size:          %u\n", size);
    LOG("    content_type:  %u\n", content_info->content_type);
  }
  struct CnmtPackagedContentInfo {
    uint8_t hash[0x20];
    uint8_t content_id[0x10];
    uint8_t size[6];
    uint8_t content_type; // 0 = meta, 1 = program, 2 = data, 3 = control, 4 =
                          // html, 5 = legal, 6 = delta
    uint8_t id_offset;
  };
  static_assert(sizeof(CnmtPackagedContentInfo) == 0x38);

  return 0;
}
