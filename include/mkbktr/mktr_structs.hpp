#pragma once

struct __attribute__((packed)) NcaFsEntry {
  uint32_t start_offset;
  uint32_t end_offset;
  uint32_t _reserved_0;
  uint32_t _reserved_1;
};

struct __attribute__((packed)) HierarchicalSha256 {
  uint8_t sha256[0x20];
  uint32_t block_size;
  const uint32_t two = 0x2;
  uint64_t hash_table_offset;
  uint64_t hash_table_size;
  uint64_t pfs0_header_offset;
  uint64_t pfs0_fs_size;
  uint8_t _reserved[0xb0];
};

struct __attribute__((packed)) BktrRelocationEntry {
  uint64_t patched_address;
  uint64_t source_address;
  // 1 = from patch, 0 = from base
  uint32_t is_patched;
};

struct __attribute__((packed)) BktrRelocationBucket {
  uint32_t _padding0;
  uint32_t entry_count;
  uint64_t bucket_end_offset;
  BktrRelocationEntry entries[0x3FF0 / sizeof(BktrRelocationEntry)];
  uint8_t _padding1[0x3FF0 % sizeof(BktrRelocationEntry)];
};

struct __attribute__((packed)) BktrSubsectionEntry {
  uint64_t offset;
  uint32_t _padding;
  uint32_t aes_ctr;
};

struct __attribute__((packed)) BktrSubsectionBucket {
  uint32_t _padding;
  uint32_t entry_count;
  uint64_t bucket_end_offset;
  BktrSubsectionEntry entries[0x3FF0 / sizeof(BktrSubsectionEntry)];
}

struct __attribute__((packed)) BktrHeaderEntry {
  uint32_t _padding;
  uint32_t bucket_count;
  uint64_t patched_image_size;
  uint64_t bucket_patch_offsets[0x3FF0 / sizeof(uint64_t))];
  // Bucket data follows, variable length
};

struct __attribute__((packed)) PatchInfo {
  uint64_t offset;
  uint64_t size;
  char magic = "BKTR";
  uint32_t _unknown0;
  uint32_t num_entries;
  uint32_t _unknown1;
};

struct __attribute__((packed)) NcaFsHeader {
  uint16_t version;
  uint8_t fs_type;
  uint8_t hash_type;
  uint8_t encryption_type;
  uint8_t _padding[3];
  HashInfo hash_info;
  PatchInfo patch_info;
  uint32_t generation;
  uint32_t secure_value;
  uint8_t sparse_info[30];
  uint8_t _reserved[0x88];
};

struct __attribute__((packed)) NcaEncryptedKeyArea {

}

struct __attribute__((packed)) NcaHeader {
  // RSA-2048 signature over the header (data from 0x200 to 0x400) using a fixed
  // key
  uint8_t header_signature[0x100];

  // RSA-2048 signature over the header (data from 0x200 to 0x400) using a key
  // from NPDM (or zeroes if not a program)
  uint8_t header_signature_npdm[0x100];

  // Magic 'NCA3'
  char magic[4];

  // (0x00 = System NCA, 0x01 = Gamecard NCA)
  uint8_t distribution_type;

  //  (0x00 = 1.0.0, 0x01 = Unused, 0x02 = 3.0.0)
  uint8_t key_generation_old;

  // (0x00 = Application, 0x01 = Ocean, 0x02 = System)
  uint8_t key_area_encryption_key_index;
  uint64_t content_size;
  uint64_t program_id;
  uint32_t content_index;
  uint32_t sdk_addon_version;

  // (0x03 = 3.0.1, 0x04 = 4.0.0, 0x05 = 5.0.0, 0x06 = 6.0.0, 0x07 = 6.2.0, 0x08
  // = 7.0.0, 0x09 = 8.1.0, 0x0A = 9.0.0, 0x0B = 9.1.0, 0x0C = 12.1.0, 0x0D
  // = 13.0.0, 0xFF = Invalid)
  uint8_t key_generation;

  uint8_t header_1_signature_key_generation;
  uint8_t _reserved[0xE];
  uint8_t rights_id[0x10];

  NcaFsEntry fs_entries[4];

  uint8_t fs_header_hashes[4][0x20];

  NcaEncryptedKeyArea encrypted_key_areas[4];
};
