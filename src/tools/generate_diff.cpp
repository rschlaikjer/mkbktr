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
  auto delta =
      mk::delta::generate_diff(mapped_old->view(), mapped_new->view(), 4);

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

  // Regenerate original
  auto get_relocation = [&](unsigned offset) -> BktrRelocationEntry & {
    for (unsigned i = 1; i < delta.relocations.size(); i++) {
      if (delta.relocations[i].patched_address > offset) {
        return delta.relocations[i - 1];
      }
    }
    return delta.relocations.back();
  };

  for (unsigned i = 0; i < mapped_new->_size; i++) {
    // What relocation are we inside
    auto &reloc = get_relocation(i);
    uint8_t byte = 0;
    if (reloc.is_patched == BktrRelocationEntry::SRC_BASE) {
      // Read byte from src file
      unsigned src_off = i - reloc.patched_address;
      byte = mapped_old->_data[reloc.source_address + src_off];
    } else {
      // Read byte from patch file
      unsigned src_off = i - reloc.patched_address;
      byte = delta.patch_data[reloc.source_address + src_off];
    }
    fprintf(stderr, "%u: reloc: %016lx, %016lx, %s: %c\n", i,
            reloc.patched_address, reloc.source_address,
            reloc.is_patched ? "PATCH" : "BASE", byte);
    printf("%c", byte);
  }

  return 0;
}
