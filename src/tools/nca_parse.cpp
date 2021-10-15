#include <stdio.h>
#include <string.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

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

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [nca filename]\n", argv[0]);
    return -1;
  }

  // Load file
  const char *nca_filename = argv[1];
  auto mapped_nca_file = mk::mem::MappedData::from_file(nca_filename);
  if (mapped_nca_file == nullptr) {
    LOG("Failed to open '%s'\n", nca_filename);
    return -1;
  }

  // Load keys
  auto keys =
      mk::Keys::from_file("/home/ross/.local/share/yuzu/keys/prod.keys");
  if (keys == nullptr) {
    return -1;
  }

  // Parse into NCA
  auto nca = mk::MappedNca::parse(std::move(mapped_nca_file), *keys);
  if (nca == nullptr) {
    LOG("Failed to parse NCA\n");
    return -1;
  }

  nca->print_header_info();
  nca->print_bktr_section(1);

  return 0;
}
