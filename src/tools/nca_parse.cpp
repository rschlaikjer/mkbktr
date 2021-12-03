#include <stdio.h>
#include <string.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [nca filename] [/path/to/prod.keys]\n", argv[0]);
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
  const char *path_to_prod_keys = argv[2];
  auto keys = mk::Keys::from_file(path_to_prod_keys);
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
  nca->print_romfs_section(0);
  nca->print_bktr_section(1);

  return 0;
}
