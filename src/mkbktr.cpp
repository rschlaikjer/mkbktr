#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/delta.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/mem.hpp>
#include <mkbktr/util/string.hpp>
#include <mkbktr/util/time.hpp>

void init_ctr_for_section(const NcaFsHeader &fs_header, uint8_t *ctr) {
  uint32_t section_ctr[2];
  section_ctr[0] = __bswap_32(fs_header.secure_value);
  section_ctr[1] = __bswap_32(fs_header.generation);
  memcpy(ctr, section_ctr, sizeof(section_ctr));
}

static void nca_update_ctr(uint8_t *ctr, uint64_t offset) {
  offset >>= 4;
  for (unsigned j = 0; j < 0x8; j++) {
    ctr[0x10 - j - 1] = static_cast<uint8_t>(offset & 0xFF);
    offset >>= 8;
  }
}

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

  // nca_old->print_header_info();
  // nca_new->print_header_info();

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

#if 0
  LOG("Generated %lu relocations:\n", delta_ctx.relocations.size());
  unsigned reloc_idx = 0;
  for (auto &relocation : delta_ctx.relocations) {
    LOG("Relocation %4d: patch addr: %016lx, src addr: %016lx, src: %s\n",
        reloc_idx, relocation.patched_address, relocation.source_address,
        relocation.is_patched ? "patch" : "base");
    reloc_idx++;
  }
#endif

  // Now we need to actually generate the output NCA.
  // Serialize the delta context as a BKTR section
  BktrHeaderEntry relocation_header;
  relocation_header.bucket_count = 1;
  relocation_header.patched_image_size = nca_new->section_size(1);
  relocation_header.bucket_patch_offsets[0] = 0x0;

  // Since we're being lazy, assert all the entries fit in a single bucket
  LOG("Bucket capacity: %lu/%lu\n", delta_ctx.relocations.size(),
      sizeof(BktrRelocationBucket::entries) / sizeof(BktrRelocationEntry));
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

  // We need to align the header data with the sector size, so pad as needed
  {
    const std::string::size_type low_addr =
        bktr_section_data.size() % NcaFsEntry::SECTOR_SIZE;
    if (low_addr) {
      LOG("Padding BKTR header info by %lu bytes\n",
          NcaFsEntry::SECTOR_SIZE - low_addr);
      bktr_section_data.append(NcaFsEntry::SECTOR_SIZE - low_addr, '\0');
    }
  }

  // Save the new section position as the relocation header offset
  const uint64_t bktr_relocation_header_offset = bktr_section_data.size();
  LOG("BKTR header offset: %016x\n", bktr_relocation_header_offset);

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
  NcaFsHeader bktr_fs_header{};
  bktr_fs_header.version = 2;
  bktr_fs_header.fs_type = 0;
  bktr_fs_header.hash_type = 3;
  bktr_fs_header.encryption_type = 4;
  bktr_fs_header.generation = 1;
  bktr_fs_header.secure_value = 2;

  // Explicitly default-init magic fields since this is a union
  bktr_fs_header.bktr_superblock = BktrSuperblock{};

  // Configure relocations
  bktr_fs_header.bktr_superblock.relocation_header.offset =
      bktr_relocation_header_offset;
  bktr_fs_header.bktr_superblock.relocation_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.relocation_header.num_entries =
      delta_ctx.relocations.size();

  // Sections
  bktr_fs_header.bktr_superblock.subsection_header.offset =
      bktr_subsection_header_offset;
  bktr_fs_header.bktr_superblock.subsection_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.subsection_header.num_entries =
      delta_ctx.relocations.size();

  // Just clone the IVFC data from the new nca?
  bktr_fs_header.bktr_superblock.ivfc_header =
      nca_new->_fs_headers[1]->bktr_superblock.ivfc_header;

  // Use the 'new' base NCA header block as a starting point
  uint8_t patch_header_plaintext[0xc00];
  memcpy(patch_header_plaintext, nca_new->header_plaintext(),
         sizeof(patch_header_plaintext));
  NcaHeader *const patch_header =
      reinterpret_cast<NcaHeader *>(patch_header_plaintext);

  // Get pointers to the header areas
  NcaFsHeader *fs_headers[4] = {
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + 0x200 * 0]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + 0x200 * 1]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + 0x200 * 2]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + 0x200 * 3]),
  };

  // Overwrite section 1 header with our custom BKTR info
  *fs_headers[1] = bktr_fs_header;

  // Recalculate FsEntry start/end offsets
  {
    uint64_t current_section_offset_bytes = 0xC00;
    for (int i = 0; i < 4; i++) {
      patch_header->fs_entries[i].start_offset =
          current_section_offset_bytes / NcaFsEntry::SECTOR_SIZE;
      if (i != 1) {
        current_section_offset_bytes += nca_new->section_size(i);
      } else {
        current_section_offset_bytes += bktr_section_data.size();
      }
      patch_header->fs_entries[i].end_offset =
          current_section_offset_bytes / NcaFsEntry::SECTOR_SIZE;
    }
  }

  // Open our output file context
  int output_fd = ::open(bktr_nca_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (output_fd == -1) {
    fprintf(stderr, "Failed to open output '%s' - %s\n", bktr_nca_filename,
            strerror(errno));
    return -1;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(output_fd); });

  // Encrypt header and emit
  uint8_t patch_header_ciphertext[sizeof(patch_header_plaintext)];
  aes_xts_encrypt(nca_new->_aes_xts_ctx, patch_header_ciphertext,
                  patch_header_plaintext, sizeof(patch_header_ciphertext), 0,
                  NcaFsEntry::SECTOR_SIZE);
  MKASSERT(::write(output_fd, patch_header_ciphertext,
                   sizeof(patch_header_plaintext)) ==
           sizeof(patch_header_plaintext));

  // For all sections _other_ than section 1, copy the data directly
  for (int i = 0; i < 4; i++) {
    // Seek to correct offset in file
    const int64_t seek_offset =
        patch_header->fs_entries[i].start_offset * NcaFsEntry::SECTOR_SIZE;
    LOG("Section %d seeking to %ld\n", i, seek_offset);
    MKASSERT(lseek(output_fd, seek_offset, SEEK_SET) != -1);

    if (i != 1) {
      // Copy raw section data, no need for decrypt/reencrypt
      const int64_t src_section_len = nca_new->section_size(i);
      const uint8_t *src_section = nca_new->section_data(i);
      MKASSERT(::write(output_fd, src_section, src_section_len) ==
               src_section_len);
    } else {
      // BKTR data section
      // TODO: encrypt

      // Create holder for encrypted bktr data
      std::string enc_bktr_section;
      enc_bktr_section.resize(bktr_section_data.size());

      // Initialize the CTR
      uint8_t ctr[0x10];
      init_ctr_for_section(*fs_headers[i], ctr);
      nca_update_ctr(ctr, seek_offset);

      // Select appropriate aes ctx
      aes_ctx_t *aes_ctx = nullptr;
      if (fs_headers[i]->encryption_type == 3 ||
          fs_headers[i]->encryption_type == 4) {
        // CTR, BKTR
        aes_ctx = nca_new->_fs_entry_aes_ctxs[2];
      }
      MKASSERT(aes_ctx != nullptr);

      // Encrypt
      aes_setiv(aes_ctx, ctr, sizeof(ctr));
      aes_encrypt(aes_ctx, reinterpret_cast<uint8_t *>(enc_bktr_section.data()),
                  reinterpret_cast<const uint8_t *>(bktr_section_data.data()),
                  enc_bktr_section.size());

      MKASSERT(::write(output_fd, enc_bktr_section.data(),
                       enc_bktr_section.size()) ==
               (long int)enc_bktr_section.size());
    }
  }

  LOG("Successfully generated '%s'\n", bktr_nca_filename);
  return 0;
}
