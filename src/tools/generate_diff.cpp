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
  auto relocations =
      mk::delta::generate_diff(mapped_old->view(), mapped_new->view());

  for (auto &relocation : relocations) {
    LOG("Src: 0x%016x, Dst: %016x, %s\n", relocation.patched_address,
        relocation.source_address, relocation.is_patched ? "PATCH" : "BASE");
  }

  return 0;
}
