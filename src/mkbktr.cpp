#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <mkbktr/aes.hpp>
#include <mkbktr/delta.hpp>
#include <mkbktr/keys.hpp>
#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/mktr_structs.hpp>
#include <mkbktr/rsa.hpp>
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

void nca_update_bktr_ctr(uint8_t *ctr, uint32_t subsection_ctr,
                         uint64_t offset) {
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

static void nca_update_ctr(uint8_t *ctr, uint64_t offset) {
  offset >>= 4;
  for (unsigned j = 0; j < 0x8; j++) {
    ctr[0x10 - j - 1] = static_cast<uint8_t>(offset & 0xFF);
    offset >>= 8;
  }
}

int main(int argc, char **argv) {
  mk::time::Timer _t_main("main()");

  if (argc != 5) {
    fprintf(stderr, "Usage: %s [original nca] [patched nca] [output nca] [/path/to/prod.keys]\n", argv[0]);
    return -1;
  }

  // Name args
  const char *original_nca_filename = argv[1];
  const char *new_nca_filename = argv[2];
  const char *bktr_nca_filename = argv[3];
  const char *path_to_prod_keys = argv[4];

  // Load keys
  auto keys = mk::Keys::from_file(path_to_prod_keys);
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
      LOG("Decrypting '%s'...\n", original_nca_filename);
      mk::time::Timer t("Decrypt old NCA ROMFS");
      old_s1 = nca_old->decrypt_section(1);
    }
    {
      LOG("Decrypting '%s'...\n", new_nca_filename);
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

  auto round_to_sector = [](uint64_t size) -> uint64_t {
    uint64_t mod = size % NcaFsEntry::SECTOR_SIZE;
    if (mod == 0) {
      return size;
    }
    return size + NcaFsEntry::SECTOR_SIZE - mod;
  };

  // Clone the delta data into the start of our BKTR section
  std::string bktr_section_data = delta_ctx.patch_data;
  LOG("Raw BKTR section data: %016lx\n", bktr_section_data.size());

  // Pad to a multiple of sections
  bktr_section_data.resize(round_to_sector(bktr_section_data.size()), '\0');
  LOG("Padded BKTR section data: %016lx\n", bktr_section_data.size());

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
  subsection_header.patched_image_size = bktr_section_data.size() +
                                         sizeof(BktrHeaderEntry) +
                                         sizeof(BktrSubsectionBucket);
  subsection_header.bucket_patch_offsets[0] = 0x0;
  BktrSubsectionBucket subsection_bucket;
  subsection_bucket.entry_count = 1;
  subsection_bucket.bucket_end_offset = bktr_section_data.size();
  // All data one section, zero tweak
  subsection_bucket.entries[0].offset = 0x0;
  subsection_bucket.entries[0].aes_ctr = 0x0;

  LOG("Subsection patch size: %016x, bucket end offset: %016x\n",
      subsection_header.patched_image_size,
      subsection_bucket.bucket_end_offset);

  // Save the new section position as the relocation header offset
  const uint64_t bktr_relocation_header_offset = bktr_section_data.size();
  LOG("BKTR header offset: %016x\n", bktr_relocation_header_offset);

  // Copy relocation data into the output BKTR buffer.
  {
    const size_t relocation_data_size =
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

  // Copy subsection data into the output BKTR buffer.
  {
    const size_t subsection_data_size =
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
  bktr_fs_header.version = 0x2;
  bktr_fs_header.fs_type = 0x0;
  bktr_fs_header.hash_type = 0x3;
  bktr_fs_header.encryption_type = 0x4;
  bktr_fs_header.generation = 0x1;
  bktr_fs_header.secure_value = 0x2;

  // Explicitly default-init magic fields since this is a union
  bktr_fs_header.bktr_superblock = BktrSuperblock{};

  // Configure relocations
  bktr_fs_header.bktr_superblock.relocation_header.offset =
      bktr_relocation_header_offset;
  bktr_fs_header.bktr_superblock.relocation_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.relocation_header.num_entries =
      delta_ctx.relocations.size();

  // Configure Sections
  bktr_fs_header.bktr_superblock.subsection_header.offset =
      bktr_subsection_header_offset;
  bktr_fs_header.bktr_superblock.subsection_header.size =
      sizeof(BktrHeaderEntry) + sizeof(BktrSubsectionBucket);
  bktr_fs_header.bktr_superblock.subsection_header.num_entries = 1;

  // Clone the IVFC data from the new nca for the patch NCA
  bktr_fs_header.bktr_superblock.ivfc_header =
      nca_new->_fs_headers[1]->bktr_superblock.ivfc_header;

  // Use the 'new' base NCA header block as a starting point for result
  uint8_t patch_header_plaintext[0xc00];
  memcpy(patch_header_plaintext, nca_new->header_plaintext(),
         sizeof(patch_header_plaintext));
  NcaHeader *const patch_header =
      reinterpret_cast<NcaHeader *>(patch_header_plaintext);

  // Get pointers to the header areas
  NcaFsHeader *fs_headers[4] = {
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + (0x200 * 0)]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + (0x200 * 1)]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + (0x200 * 2)]),
      reinterpret_cast<NcaFsHeader *>(
          &patch_header_plaintext[0x400 + (0x200 * 3)]),
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
        // section 1 is the only section that needs recalculation based on BKTR size.
        current_section_offset_bytes += bktr_section_data.size();
      }
      patch_header->fs_entries[i].end_offset =
          current_section_offset_bytes / NcaFsEntry::SECTOR_SIZE;
    }
  }

  // Forcibly disable sections 2/3
  patch_header->fs_entries[2].start_offset = 0x0;
  patch_header->fs_entries[2].end_offset = 0x0;
  patch_header->fs_entries[3].start_offset = 0x0;
  patch_header->fs_entries[3].end_offset = 0x0;

  // Open our output file context
  int output_fd = ::open(bktr_nca_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (output_fd == -1) {
    fprintf(stderr, "Failed to open output '%s' - %s\n", bktr_nca_filename,
            strerror(errno));
    return -1;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(output_fd); });

  // Calculate the NPDM signature over the header
  rsa_sign(&patch_header->magic, 0x200, patch_header->header_signature_npdm,
           0x100);

  // Generate SHA256 hashes over each FsHeader
  auto generate_fs_header_sha = [](const NcaFsHeader *header, uint8_t *digest) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    MKASSERT(!mbedtls_md_setup(
        &ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0));
    MKASSERT(!mbedtls_md_starts(&ctx));
    mbedtls_md_update(&ctx, reinterpret_cast<const uint8_t *>(header),
                      sizeof(NcaFsHeader));
    mbedtls_md_finish(&ctx, digest);
    mbedtls_md_free(&ctx);
  };
  for (int i = 0; i < 4; i++) {
    generate_fs_header_sha(fs_headers[i], patch_header->fs_header_hashes[i]);
  }

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
    // Does this section exist?
    if (patch_header->fs_entries[i].start_offset == 0 &&
        patch_header->fs_entries[i].end_offset == 0) {
      // If not, no data
      continue;
    }

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

      // Create holder for encrypted bktr data
      std::string enc_bktr_section;
      enc_bktr_section.resize(bktr_section_data.size());

      // Encrypt the real BKTR data using weirdo BKTR AES-CTR
      {
        uint8_t ctr[0x10];
        init_ctr_for_section(*fs_headers[i], ctr);
        nca_update_bktr_ctr(ctr, 0x0, seek_offset);

        // Select appropriate aes context
        aes_ctx_t *aes_ctx = nullptr;
        if (fs_headers[i]->encryption_type == 3 ||
            fs_headers[i]->encryption_type == 4) {
          // CTR, BKTR
          aes_ctx = nca_new->_fs_entry_aes_ctxs[2];
        }
        MKASSERT(aes_ctx != nullptr);

        // Encrypt
        aes_setiv(aes_ctx, ctr, sizeof(ctr));
        aes_encrypt(aes_ctx,
                    reinterpret_cast<uint8_t *>(enc_bktr_section.data()),
                    reinterpret_cast<const uint8_t *>(bktr_section_data.data()),
                    bktr_relocation_header_offset);
      }

      // Encrypt the offset data using normal AES
      {
        // Initialize the CTR with the offset of the header info
        uint8_t ctr[0x10];
        init_ctr_for_section(*fs_headers[i], ctr);
        nca_update_ctr(ctr, seek_offset + bktr_relocation_header_offset);

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
        aes_encrypt(
            aes_ctx,
            reinterpret_cast<uint8_t *>(enc_bktr_section.data()) +
                bktr_relocation_header_offset,
            reinterpret_cast<const uint8_t *>(bktr_section_data.data()) +
                bktr_relocation_header_offset,
            enc_bktr_section.size() - bktr_relocation_header_offset);
      }

      MKASSERT(::write(output_fd, enc_bktr_section.data(),
                       enc_bktr_section.size()) ==
               (long int)enc_bktr_section.size());
    }
  }

  LOG("Successfully generated '%s'\n", bktr_nca_filename);
  return 0;
}
