#include <stdio.h>
#include <string.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/delta.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>
#include <mkbktr/util/time.hpp>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s original patched output\n", argv[0]);
    return -1;
  }

  // Name args
  const char *original_nca_filename = argv[1];
  const char *new_nca_filename = argv[2];
  const char *bktr_nca_filename = argv[3];

  // Load keys
  auto keys =
      mk::Keys::from_file("/home/ross/.local/share/yuzu/keys/prod.keys");
  if (keys == nullptr) {
    return -1;
  }

  // Map the two input files
  auto mapped_nca_old = mk::mem::MappedData::from_file(original_nca_filename);
  if (mapped_nca_old == nullptr) {
    LOG("Failed to open '%s'\n", original_nca_filename);
    return -1;
  }
  auto mapped_nca_new = mk::mem::MappedData::from_file(new_nca_filename);
  if (mapped_nca_new == nullptr) {
    LOG("Failed to open '%s'\n", new_nca_filename);
    return -1;
  }

  // Parse as NCAs
  auto nca_old = mk::MappedNca::parse(std::move(mapped_nca_old), *keys);
  if (nca_old == nullptr) {
    LOG("Failed to parse NCA '%s'\n", original_nca_filename);
    return -1;
  }
  auto nca_new = mk::MappedNca::parse(std::move(mapped_nca_new), *keys);
  if (nca_new == nullptr) {
    LOG("Failed to parse NCA '%s'\n", new_nca_filename);
    return -1;
  }

  nca_old->print_header_info();
  nca_new->print_header_info();

  // Decrypt section 1 from each input NCA
  std::string old_s1;
  std::string new_s1;
  {
    mk::time::Timer t("Decrypt old NCA ROMFS");
    old_s1 = nca_old->decrypt_section(1);
  }
  {
    mk::time::Timer t("Decrypt new NCA ROMFS");
    new_s1 = nca_new->decrypt_section(1);
  }

  LOG("Old ROMFS size: %ld bytes\n", old_s1.size());
  LOG("New ROMFS size: %ld bytes\n", new_s1.size());

  // Generate deltas
  auto delta_ctx = mk::delta::generate_diff(old_s1, new_s1);

  // Print
  LOG("Total patch size %.fMiB\n",
      ((double)delta_ctx.patch_data.size()) / 1024.0 / 1024.0);
  LOG("Generated %lu relocations:\n", delta_ctx.relocations.size());

  unsigned reloc_idx = 0;
  for (auto &relocation : delta_ctx.relocations) {
    LOG("Relocation %4d: patch addr: %016lx, src addr: %016lx, src: %s\n",
        reloc_idx, relocation.patched_address, relocation.source_address,
        relocation.is_patched ? "patch" : "base");
    reloc_idx++;
  }

  return 0;
}
