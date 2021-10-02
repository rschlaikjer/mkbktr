#include <stdio.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
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
  aes_xts_decrypt(xts_ctx, xts_header, mapped_nca->_data, 0x400, 0, 0x200);

  return 0;
}
