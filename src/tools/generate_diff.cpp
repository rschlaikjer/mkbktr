#include <stdio.h>
#include <string.h>

#include <mkbktr/delta.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s old new\n", argv[0]);
    return -1;
  }

  // Map input files
  const char *const old_filename = argv[1];
  const char *const new_filename = argv[2];
  auto mapped_old = mk::mem::MappedData::from_file(old_filename);
  if (mapped_old == nullptr) {
    LOG("Failed to open '%s'\n", old_filename);
    return -1;
  }
  auto mapped_new = mk::mem::MappedData::from_file(new_filename);
  if (mapped_new == nullptr) {
    LOG("Failed to open '%s'\n", new_filename);
    return -1;
  }

  // Generate a list of relocations
  auto delta = mk::delta::generate_diff(mapped_old->view(), mapped_new->view());

  LOG("Total patch size %.fMiB\n",
      ((double)delta.patch_data.size()) / 1024.0 / 1024.0);
  LOG("Generated %lu relocations:\n", delta.relocations.size());
  unsigned reloc_idx = 0;
  for (auto &relocation : delta.relocations) {
    LOG("Relocation %4d: patch addr: %016lx, src addr: %016lx, src: %s\n",
        reloc_idx, relocation.patched_address, relocation.source_address,
        relocation.is_patched ? "patch" : "base");
    reloc_idx++;
  }

  return 0;
}
