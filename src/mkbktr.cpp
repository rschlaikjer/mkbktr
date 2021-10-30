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
  mk::time::Timer _t_main("main()");

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
  mk::delta::Delta delta_ctx;
  {
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
    delta_ctx = mk::delta::generate_diff(old_s1, new_s1);
  }

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

  // Now we need to actually generate the output NCA.
  // Serialize the delta context as a BKTR section
  BktrHeaderEntry relocation_header;
  relocation_header.bucket_count = 1;
  relocation_header.patched_image_size = nca_new->section_size(1);
  relocation_header.bucket_patch_offsets[0] = 0x0;

  // Since we're being lazy, assert all the entries fit in a single bucket
  MKASSERT(delta_ctx.relocations.size() <=
           sizeof(BktrRelocationBucket::entries) / sizeof(BktrRelocationEntry));

  // Create bucket to contain the relocation entries
  BktrRelocationBucket relocation_bucket;
  relocation_bucket.entry_count = delta_ctx.relocations.size();
  relocation_bucket.bucket_end_offset = relocation_header.patched_image_size;
  for (unsigned i = 0; i < delta_ctx.relocations.size(); i++) {
    relocation_bucket.entries[i] = delta_ctx.relocations[i];
  }

  // Treat all of the BKTR data as a single section
  BktrHeaderEntry subsection_header;
  subsection_header.bucket_count = 1;
  subsection_header.patched_image_size = nca_new->section_size(1);
  subsection_header.bucket_patch_offsets[0] = 0x0;

  BktrSubsectionBucket subsection_bucket;
  subsection_bucket.entry_count = 1;
  subsection_bucket.bucket_end_offset = subsection_header.patched_image_size;
  // All data one section, zero tweak
  subsection_bucket.entries[0].offset = 0x0;
  subsection_bucket.entries[0].aes_ctr = 0x0;

  // Clone the delta data into the start of our BKTR section
  std::string bktr_section_data = delta_ctx.patch_data;

  // Realign to a 64-bit boundary for cleanliness
  {
    const std::string::size_type low_addr = bktr_section_data.size() & 0b111;
    if (low_addr) {
      bktr_section_data.append(8 % low_addr, '\0');
    }
  }

  // Save the new section position as the relocation header offset
  const uint64_t bktr_relocation_header_offset = bktr_section_data.size();

  // Serialize in relocations
  {
    const unsigned relocation_data_size =
        sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
    char *const relocation_write_ptr =
        &bktr_section_data.data()[bktr_section_data.size()];
    bktr_section_data.resize(bktr_section_data.size() + relocation_data_size);
    memcpy(relocation_write_ptr, &relocation_header, sizeof(relocation_header));
    memcpy(relocation_write_ptr + sizeof(relocation_header), &relocation_bucket,
           sizeof(relocation_bucket));
  }

  // Realign again
  {
    const std::string::size_type low_addr = bktr_section_data.size() & 0b111;
    if (low_addr) {
      bktr_section_data.append(8 % low_addr, '\0');
    }
  }

  // Save the new section position as the relocation header offset
  const uint64_t bktr_subsection_header_offset = bktr_section_data.size();

  // Serialize in sections
  {
    const unsigned subsection_data_size =
        sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
    char *const subsection_write_ptr =
        &bktr_section_data.data()[bktr_section_data.size()];
    bktr_section_data.resize(bktr_section_data.size() + subsection_data_size);
    memcpy(subsection_write_ptr, &subsection_header, sizeof(subsection_header));
    memcpy(subsection_write_ptr + sizeof(subsection_header), &subsection_bucket,
           sizeof(subsection_bucket));
  }

  // Create fs header for BKTR section
  NcaFsHeader bktr_fs_header;
  bktr_fs_header.version = 2;
  bktr_fs_header.fs_type = 0;
  bktr_fs_header.hash_type = 3;
  bktr_fs_header.encryption_type = 4;
  bktr_fs_header.generation = 1;
  bktr_fs_header.secure_value = 2;

  bktr_fs_header.bktr_superblock.relocation_header.offset =
      bktr_relocation_header_offset;
  bktr_fs_header.bktr_superblock.relocation_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.relocation_header.num_entries =
      delta_ctx.relocations.size();

  bktr_fs_header.bktr_superblock.subsection_header.offset =
      bktr_subsection_header_offset;
  bktr_fs_header.bktr_superblock.subsection_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.subsection_header.num_entries =
      delta_ctx.subsections.size();

  // TODO
  bktr_fs_header.bktr_superblock.ivfc_header; // Bunch of _stuff_ in here

  NcaFsEntry bktr_fs_entry;

  return 0;
}
