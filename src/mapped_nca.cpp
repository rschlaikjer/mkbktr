#include <string.h>

#include <functional>
#include <memory>

#include <mkbktr/mapped_nca.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/string.hpp>

namespace mk {

static const uint32_t AES_SECTOR_SIZE = 0x200;

MappedNca::MappedNca(std::unique_ptr<mk::mem::MappedData> backing_data,
                     mk::Keys keys)
    : _backing_data(std::move(backing_data)), _keys(keys) {}

std::unordered_map<uint64_t, std::string> MappedNca::list_files(int section) {
  // Iterate the IVFC on a ROMFS block and accumulate a list of files + their
  // offsets
  MKASSERT(section < 4);

  // Read the IVFS header for the section
  HierarchicalIntegrity ivfc =
      _fs_headers[section]->bktr_superblock.ivfc_header;
  MKASSERT(!memcmp(ivfc.magic, "IVFC", 4));

  // Read romfs header
  RomfsHeader romfs_header;
  read_aes_ctr(section, ivfc.levels[5].offset, sizeof(RomfsHeader),
               reinterpret_cast<uint8_t *>(&romfs_header));

  // Read the first directory entry
  RomfsDirEntry dirent;
  read_aes_ctr(section,
               ivfc.levels[5].offset + romfs_header.dir_meta_table_offset,
               sizeof(dirent), reinterpret_cast<uint8_t *>(&dirent));

  auto read_next = [&](int64_t offset, auto *out, std::string *out_name) {
    // Read the fixed-size header
    read_aes_ctr(1, ivfc.levels[5].offset + offset, sizeof(typeof(*out)),
                 reinterpret_cast<uint8_t *>(out));

    // Allocate and copy out the name string
    if (out_name != nullptr) {
      out_name->resize(out->name_size);
      read_aes_ctr(
          1, ivfc.levels[5].offset + offset + offsetof(typeof(*out), name),
          out_name->size(), reinterpret_cast<uint8_t *>(out_name->data()));
    }
  };

  auto read_next_dir = [&](int64_t offset, RomfsDirEntry *out,
                           std::string *out_name) {
    read_next(romfs_header.dir_meta_table_offset + offset, out, out_name);
  };

  auto read_next_file = [&](int64_t offset, RomfsFileEntry *out,
                            std::string *out_name) {
    read_next(romfs_header.file_meta_table_offset + offset, out, out_name);
  };

  auto print_dir_entry = [](const RomfsDirEntry &entry) {
    LOG("    Parent:      %08x\n", entry.parent);
    LOG("    Sibling:     %08x\n", entry.sibling);
    LOG("    Child:       %08x\n", entry.child);
    LOG("    File:        %08x\n", entry.file);
    LOG("    Hash:        %08x\n", entry.hash);
    LOG("    Name Size:   %08x\n", entry.name_size);
  };

  auto print_file_entry = [](const RomfsFileEntry &entry) {
    LOG("    Parent:      %08x\n", entry.parent);
    LOG("    Sibling:     %08x\n", entry.sibling);
    LOG("    Offset:      %016x\n", entry.offset);
    LOG("    Size:        %016x\n", entry.size);
    LOG("    Hash:        %08x\n", entry.hash);
    LOG("    Name Size:   %08x\n", entry.name_size);
  };

  // Map of offset -> file name
  std::unordered_map<uint64_t, std::string> files;

  std::function<void(const RomfsFileEntry &parent)> file_iterator =
      [&](const RomfsFileEntry &prev) {
        // Iterate sibling if present
        if (prev.sibling != 0xFFFFFFFF) {
          RomfsFileEntry f_entry;
          std::string f_name;
          read_next_file(prev.sibling, &f_entry, &f_name);
          LOG("File: %s\n", f_name.c_str());
          files[f_entry.offset] = f_name;
          print_file_entry(f_entry);
          file_iterator(f_entry);
        }
      };

  std::function<void(const RomfsDirEntry &parent)> dir_iterator =
      [&](const RomfsDirEntry &parent) {
        // Iterate child if present
        if (parent.child != 0xFFFFFFFF) {
          RomfsDirEntry child_entry;
          std::string child_name;
          read_next_dir(parent.child, &child_entry, &child_name);
          LOG("Child: %s\n", child_name.c_str());
          print_dir_entry(child_entry);
          dir_iterator(child_entry);
        }

        // Iterate sibling if extant
        if (parent.sibling != 0xFFFFFFFF) {
          RomfsDirEntry sibling_entry;
          std::string sibling_name;
          read_next_dir(parent.sibling, &sibling_entry, &sibling_name);
          LOG("Sibling: %s\n", sibling_name.c_str());
          print_dir_entry(sibling_entry);
          dir_iterator(sibling_entry);
        }

        // Iterate file
        if (parent.file != 0xFFFFFFFF) {
          RomfsFileEntry f_entry;
          std::string f_name;
          read_next_file(parent.file, &f_entry, &f_name);
          LOG("File: %s\n", f_name.c_str());
          files[f_entry.offset] = f_name;
          print_file_entry(f_entry);
          file_iterator(f_entry);
        }
      };

  // Load the initial parent dirent
  RomfsDirEntry d_entry;
  read_next_dir(0, &d_entry, nullptr);

  // Traverse file tree
  dir_iterator(d_entry);

  return files;
}

void MappedNca::print_header_info() {
  LOG("Magicnum: %c%c%c%c\n", _header->magic[0], _header->magic[1],
      _header->magic[2], _header->magic[3]);
  LOG("Distribution type: %u\n", _header->distribution_type);
  LOG("Content type: %u\n", _header->content_type);
  LOG("Key generation old: %u\n", _header->key_generation_old);
  LOG("Key area encryption area index: %u\n",
      _header->key_area_encryption_key_index);

  LOG("Content size: %lu\n", _header->content_size);
  LOG("Program ID: %lx\n", _header->program_id);
  LOG("Content index: %u\n", _header->content_index);
  LOG("SDK addon ver: %u\n", _header->sdk_addon_version);

  LOG("Key generation: %u\n", _header->key_generation);
  LOG("Header 1 sig key gen: %u\n", _header->header_1_signature_key_generation);
  LOG("Rights ID: 0x%s\n",
      mk::string::bytes_to_hex(
          std::string(reinterpret_cast<const char *>(_header->rights_id),
                      sizeof(_header->rights_id)))
          .c_str());

  for (auto &fs_entry : _header->fs_entries) {
    LOG("Fs entry start offset: %08x, end offset %08x\n", fs_entry.start_offset,
        fs_entry.end_offset);
  }

  for (auto &fs_hash : _header->fs_header_hashes) {
    LOG("Fs entry hash: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(fs_hash),
                        sizeof(fs_hash)))
            .c_str());
  }

  for (auto &encrypted_key : _header->encrypted_key_areas) {
    LOG("Encrypted key: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(encrypted_key.key),
                        sizeof(encrypted_key.key)))
            .c_str());
  }

  for (auto &decrypted_key : _decrypted_keys) {
    LOG("Decrypted key: %s\n",
        mk::string::bytes_to_hex(
            std::string(reinterpret_cast<const char *>(decrypted_key),
                        sizeof(decrypted_key)))
            .c_str());
  }
}

uint64_t MappedNca::section_size(int section) const {
  MKASSERT(section < 4);

  // Get references to filesystem header/entry data
  const NcaFsEntry *fs_entry = &_header->fs_entries[section];

  // Total section size is total sector count * sector size
  return (fs_entry->end_offset - fs_entry->start_offset) *
         fs_entry->SECTOR_SIZE;
}

std::string MappedNca::decrypt_section(int section) {
  MKASSERT(section < 4);

  // Get the total size of the section
  const uint64_t section_data_size = section_size(section);

  // Decrypt all
  return read_aes_ctr(section, 0, section_data_size);
}

void MappedNca::print_romfs_section(int section) { MKASSERT(section < 4); }

void MappedNca::print_bktr_section(int section) {
  MKASSERT(section < 4);

  // Get references to filesystem header/entry data
  const NcaFsHeader *fs_header = _fs_headers[section];
  const NcaFsEntry *fs_entry = &_header->fs_entries[section];

  // The relocation header and subsection header must be contiguous
  MKASSERT(fs_header->bktr_superblock.relocation_header.offset +
               fs_header->bktr_superblock.relocation_header.size ==
           fs_header->bktr_superblock.subsection_header.offset);

  // Relocation area + subsection area must equal section size
  MKASSERT(fs_header->bktr_superblock.subsection_header.offset +
               fs_header->bktr_superblock.subsection_header.size ==
           (fs_entry->end_offset - fs_entry->start_offset) *
               fs_entry->SECTOR_SIZE);

  // Decrypt the relocation header
  const uint64_t relocation_header_offset =
      fs_header->bktr_superblock.relocation_header.offset;
  const std::string decrypted_relocations =
      read_aes_ctr(section, relocation_header_offset,
                   fs_header->bktr_superblock.relocation_header.size);

  // Relocation bucket header
  const BktrHeaderEntry *relocation_header =
      reinterpret_cast<const BktrHeaderEntry *>(decrypted_relocations.data());
  LOG("Bucket count: %u, patched image size: %lu\n",
      relocation_header->bucket_count, relocation_header->patched_image_size);

  // Decrypt the buckets
  const uint64_t relocation_bucket_data_offset =
      relocation_header_offset + sizeof(BktrHeaderEntry);
  const std::string decrypted_relocation_buckets = read_aes_ctr(
      section, relocation_bucket_data_offset,
      sizeof(BktrRelocationBucket) * relocation_header->bucket_count);

  // Relocation buckets
  const BktrRelocationBucket *relocation_buckets =
      reinterpret_cast<const BktrRelocationBucket *>(
          decrypted_relocation_buckets.data());
  for (uint32_t i = 0; i < relocation_header->bucket_count; i++) {
    LOG("Bucket %4d: entry count: %d\n", i, relocation_buckets[i].entry_count);
    for (uint32_t entry = 0; entry < relocation_buckets[i].entry_count;
         entry++) {
      LOG("    entry %4d: patch addr: %016lx, src addr: %016lx, src: %s\n",
          entry, relocation_buckets[i].entries[entry].patched_address,
          relocation_buckets[i].entries[entry].source_address,
          relocation_buckets[i].entries[entry].is_patched ? "patch" : "base");
    }
  }

  // Decrypt the subsection header
  const uint64_t subsection_header_offset =
      fs_header->bktr_superblock.subsection_header.offset;
  const std::string decrypted_subsections =
      read_aes_ctr(section, subsection_header_offset,
                   fs_header->bktr_superblock.subsection_header.size);

  // Subsection bucket header
  const BktrHeaderEntry *subsection_header =
      reinterpret_cast<const BktrHeaderEntry *>(decrypted_subsections.data());
  LOG("Bucket count: %u, patched image size: %lu\n",
      subsection_header->bucket_count, subsection_header->patched_image_size);

  // Decrypt subsection buckets
  const uint64_t subsection_bucket_data_offset =
      subsection_header_offset + sizeof(BktrHeaderEntry);
  const std::string decrypted_subsection_buckets = read_aes_ctr(
      section, subsection_bucket_data_offset,
      sizeof(BktrSubsectionBucket) * subsection_header->bucket_count);

  // Subsection buckets
  const BktrSubsectionBucket *subsection_buckets =
      reinterpret_cast<const BktrSubsectionBucket *>(
          decrypted_subsection_buckets.data());
  for (uint32_t i = 0; i < subsection_header->bucket_count; i++) {
    LOG("Bucket %4d: entry count: %d\n", i, subsection_buckets[i].entry_count);
    for (uint32_t entry = 0; entry < subsection_buckets[i].entry_count;
         entry++) {
      LOG("    entry %4d: offset: %016lx, AES CTR: %08x\n", entry,
          subsection_buckets[i].entries[entry].offset,
          subsection_buckets[i].entries[entry].aes_ctr);
    }
  }
}

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

const uint8_t *MappedNca::section_data(int section) {
  // Get sector start offset
  MKASSERT(section < 4);
  const uint64_t section_offset =
      _header->fs_entries[section].start_offset * NcaFsEntry::SECTOR_SIZE;

  return _backing_data->_data + section_offset;
}

void MappedNca::read_aes_ctr_aligned(int section, uint64_t data_offset,
                                     uint64_t len, uint8_t *out) const {
  // Get sector start offset
  MKASSERT(section < 4);
  const uint64_t section_offset =
      _header->fs_entries[section].start_offset * NcaFsEntry::SECTOR_SIZE;

  // Assert that the read is aligned
  MKASSERT(((section_offset + data_offset) & 0xFF) == 0);

  // Initialize the CTR
  uint8_t ctr[0x10];
  init_ctr_for_section(*_fs_headers[section], ctr);
  nca_update_ctr(ctr, section_offset + data_offset);

  // Select appropriate aes ctx
  aes_ctx_t *aes_ctx = nullptr;
  if (_fs_headers[section]->encryption_type == 3 ||
      _fs_headers[section]->encryption_type == 4) {
    // CTR, BKTR
    aes_ctx = _fs_entry_aes_ctxs[2];
  }
  MKASSERT(aes_ctx != nullptr);

  // Decrypt
  aes_setiv(aes_ctx, ctr, sizeof(ctr));
  aes_decrypt(aes_ctx, out, _backing_data->_data + section_offset + data_offset,
              len);
}

void MappedNca::read_aes_ctr(int section, uint64_t data_offset, uint64_t len,
                             uint8_t *out) const {
  // Is this address aligned to an AES sector boundary?
  if ((data_offset & 0xFF) == 0) {
    // If so, great, just proxy the call and be done
    read_aes_ctr_aligned(section, data_offset, len, out);
    return;
  }

  // If this _doesn't_ align to a page boundary, manually over-read the first
  // page and copy only the bit we care about into the output buffer
  uint8_t first_sector_buf[0x100];
  const uint64_t aligned_read_base = data_offset & ~(0x00000000'000000FFL);
  const uint64_t misalign_read_offset = data_offset & 0xFFL;
  const uint64_t max_misaligned_bytes_to_keep = 0x100L - misalign_read_offset;
  const uint64_t misaligned_bytes_to_keep =
      std::min(len, max_misaligned_bytes_to_keep);
  read_aes_ctr_aligned(section, aligned_read_base, 0x100, first_sector_buf);
  memcpy(out, &first_sector_buf[misalign_read_offset],
         misaligned_bytes_to_keep);

  // Now read all the subsequent blocks 'normally'
  const int64_t remaining_bytes = len - misaligned_bytes_to_keep;
  if (remaining_bytes == 0) {
    // If this block would be empty, don't even bother
    return;
  }
  const int64_t first_full_sector_offset = aligned_read_base + 0x100;
  read_aes_ctr_aligned(section, first_full_sector_offset, remaining_bytes,
                       &out[misaligned_bytes_to_keep]);
}

std::string MappedNca::read_aes_ctr(int section, uint64_t data_offset,
                                    uint64_t len) const {
  std::string ret;
  ret.resize(len);
  read_aes_ctr(section, data_offset, len,
               reinterpret_cast<uint8_t *>(ret.data()));
  return ret;
}

std::unique_ptr<MappedNca>
MappedNca::parse(std::unique_ptr<mk::mem::MappedData> backing_data,
                 mk::Keys keys) {
  // Create our NCA
  auto nca =
      std::unique_ptr<MappedNca>(new MappedNca(std::move(backing_data), keys));

  // Create xts context for header
  nca->_aes_xts_ctx = new_aes_ctx(keys.get("header_key"), 32, AES_MODE_XTS);

  // Decrypt header
  aes_xts_decrypt(nca->_aes_xts_ctx, nca->_xts_header_decrypted,
                  nca->_backing_data->_data, sizeof(nca->_xts_header_decrypted),
                  0, AES_SECTOR_SIZE);

  // Check magic
  if (strcmp(nca->_header->magic, "NCA3")) {
    LOG("Unhandled header magic\n");
    return nullptr;
  }

  auto key_for_generation = [&]() -> std::string {
    if (nca->_header->key_generation == 0)
      return "key_area_key_application_00";
    if (nca->_header->key_generation == 11)
      return "key_area_key_application_0a";

    MKASSERT(false);
    return "";
  };

  // Decrypt key area
  {
    aes_ctx_t *key_aes_ctx =
        new_aes_ctx(keys.get(key_for_generation()), 16, AES_MODE_ECB);
    aes_decrypt(key_aes_ctx, (uint8_t *)nca->_decrypted_keys,
                (uint8_t *)nca->_header->encrypted_key_areas,
                sizeof(nca->_header->encrypted_key_areas));
    free_aes_ctx(key_aes_ctx);
  }

  // Create AES-CTR contexts from the section keys
  {
    for (int i = 0; i < 4; i++) {
      nca->_fs_entry_aes_ctxs[i] =
          new_aes_ctx(nca->_decrypted_keys[i], sizeof(nca->_decrypted_keys[i]),
                      AES_MODE_CTR);
    }
  }

  return nca;
}

NcaSectionView::NcaSectionView(const MappedNca &nca, int section)
    : _nca(nca), _section(section) {
  _current_section = reinterpret_cast<uint8_t *>(malloc(BLOCK_SIZE_BYTES));
  MKASSERT(_current_section != nullptr);
}

NcaSectionView::~NcaSectionView() { free(_current_section); }

uint64_t NcaSectionView::size() { return _nca.section_size(_section); }

void NcaSectionView::read(int64_t offset, int64_t len, uint8_t *out) {
  _nca.read_aes_ctr(_section, offset, len, out);
}

uint8_t NcaSectionView::operator[](int64_t offset) {
  // Is the offset within the currently buffered section?
  // Take advantage of power of two block size
  static_assert(__builtin_popcountll(BLOCK_SIZE_BYTES) == 1);
  constexpr int64_t offset_mask = BLOCK_SIZE_BYTES - 1;
  const int64_t offset_index = offset & offset_mask;
  const int64_t offset_base = offset & ~offset_mask;

  // If it isn't, we need to decrypt from the new offset into our buffer
  if (offset_base != _current_section_base) {
    // Decrypt this page
    _nca.read_aes_ctr(_section, offset_base, BLOCK_SIZE_BYTES,
                      _current_section);
    // Update base offset
    _current_section_base = offset_base;
  }

  // At this point, we were either in a previously buffered section or have
  // freshly decrypted the section this offset falls into.
  return _current_section[offset_index];
}

} // namespace mk
