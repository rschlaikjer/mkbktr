#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr,
            "Usage: %s [cnmt filename] [hash to replace] [new NCA file] "
            "[output_cnmt]\n",
            argv[0]);
    return -1;
  }

  // Load base file
  const char *cnmt_filename = argv[1];
  auto mapped_cnmt_file = mk::mem::MappedData::from_file(cnmt_filename);
  if (mapped_cnmt_file == nullptr) {
    LOG("Failed to open '%s'\n", cnmt_filename);
    return -1;
  }

  // Map the file we're using to generate the new hash/size
  const char *nca_filename = argv[3];
  auto mapped_nca_file = mk::mem::MappedData::from_file(nca_filename);
  if (mapped_nca_file == nullptr) {
    LOG("Failed to open '%s'\n", nca_filename);
    return -1;
  }

  // Generate hash over the NCA
  uint8_t new_digest[0x20];
  {
    LOG("Generate SHA256...");
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    MKASSERT(!mbedtls_md_setup(
        &ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0));
    MKASSERT(!mbedtls_md_starts(&ctx));
    mbedtls_md_update(&ctx, mapped_nca_file->_data, mapped_nca_file->_size);
    mbedtls_md_finish(&ctx, new_digest);
    mbedtls_md_free(&ctx);
    LOG("'%s': %s\n", nca_filename,
        mk::string::bytes_to_hex(
            std::string((char *)new_digest, sizeof(new_digest)))
            .c_str());
  }

  // Clone input
  std::string new_cnmt{reinterpret_cast<const char *>(mapped_cnmt_file->_data),
                       (unsigned long)mapped_cnmt_file->_size};

  // Create header over output to get the content count
  const CnmtHeader *const header =
      reinterpret_cast<const CnmtHeader *>(new_cnmt.data());

  // Iterate entries until we find one with the hash we want to replace
  const std::string hash_to_replace{argv[2]};
  bool did_replace = false;
  for (unsigned i = 0; i < header->content_entry_count; i++) {
    const uint64_t offset = sizeof(CnmtHeader) + header->table_offset +
                            i * sizeof(CnmtPackagedContentInfo);
    CnmtPackagedContentInfo *const content_info =
        reinterpret_cast<CnmtPackagedContentInfo *>(&new_cnmt.data()[offset]);

    // Stringinfy bytes of content_id
    const std::string content_id = mk::string::bytes_to_hex(
        std::string(reinterpret_cast<const char *>(content_info->content_id),
                    sizeof(content_info->content_id)));

    // If it doesn't match, pass
    if (content_id != hash_to_replace) {
      continue;
    }

    // If it does, overwrite the hash / content id
    memcpy(&content_info->hash, new_digest, sizeof(content_info->hash));
    memcpy(&content_info->content_id, new_digest,
           sizeof(content_info->content_id));
    for (int j = 0; j < 6; j++) {
      content_info->size[j] = (mapped_nca_file->_size >> (j * 8)) & 0xFF;
    }

    did_replace = true;
    break;
  }

  // If we didn't replace a section, error out
  if (!did_replace) {
    LOG("Failed to find entry with content ID '%s'\n", argv[2]);
    return -1;
  }

  // Write the updated cnmt
  const char *output_file = argv[4];
  int output_fd = ::open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (output_fd == -1) {
    fprintf(stderr, "Failed to open output '%s' - %s\n", output_file,
            strerror(errno));
    return -1;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(output_fd); });
  MKASSERT(write(output_fd, new_cnmt.data(), new_cnmt.size()) ==
           (ssize_t)new_cnmt.size());

  return 0;
}
