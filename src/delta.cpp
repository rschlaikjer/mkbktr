#include <stdint.h>
#include <string.h>

#include <zlib.h>

#include <mbedtls/md5.h>

#include <mkbktr/delta.hpp>
#include <mkbktr/util/log.hpp>
#include <mkbktr/util/string.hpp>
#include <mkbktr/util/time.hpp>

namespace mk {
namespace delta {

struct BlockChecksum {
  // Location in old file of block
  int64_t block_offset;

  // Rolling adler32
  uint32_t weak_checksum;

  // MD5
  uint8_t strong_checksum[16];
};

class AdlerCtx {
public:
  // Initial adler is simply 1.
  static const uint32_t ADLER_INIT = 0x0000'0001;

  // Adler value is calculated modulo largest sub-16-bit prime
  static const uint32_t ADLER_MODULUS = 65521;

  AdlerCtx(int64_t block_size) : _block_size(block_size) {
    _data_ringbuffer.resize(block_size);
  }

  void reset() {
    _value = ADLER_INIT;
    _digested_block_count = 0;
  }

  void roll_n(const uint8_t *new_data, int64_t len) {
    for (int64_t i = 0; i < len; i++) {
      roll_1(new_data[i]);
    }
  }

  uint32_t digest() { return _value; }

  void roll_1(uint8_t new_byte) {
    // Split the old adler ctx
    const uint32_t old_sum = (_value >> 0) & 0xFFFF;
    const uint32_t old_sum2 = (_value >> 16) & 0xFFFF;

    // Add in the new byte
    uint32_t new_sum = old_sum + new_byte;
    uint32_t new_sum2 = old_sum2 + new_sum;

    // Simple case modulus, shouldn't hit more than twice so faster than a
    // modulo op
    while (new_sum >= ADLER_MODULUS)
      new_sum -= ADLER_MODULUS;
    while (new_sum2 >= ADLER_MODULUS)
      new_sum2 -= ADLER_MODULUS;

    // Pop the oldest data off the ringbuffer
    const unsigned pop_off = _digested_block_count % _block_size;
    const uint8_t pop_byte = _data_ringbuffer[pop_off];

    // Overwrite that offset with this new byte
    _data_ringbuffer[pop_off] = new_byte;

    // Increment the digested byte count
    _digested_block_count++;

    // If we have reached _block_size, then we want to actually start removing
    // bytes off the front.
    if (_digested_block_count > _block_size) {
      // Decrement the sum/sum2 by the values to pop
      // Note that if we would underflow, we have to underflow from
      // ADLER_MODULUS not uint16_t max
      if (new_sum >= pop_byte) {
        new_sum -= pop_byte;
      } else {
        new_sum = ADLER_MODULUS - pop_byte + new_sum;
      }

      // Same for sum2
      const uint32_t sum2_subtract =
          (ADLER_INIT + (pop_byte * (_block_size + 1))) % ADLER_MODULUS;
      if (new_sum2 >= sum2_subtract) {
        new_sum2 -= sum2_subtract;
      } else {
        new_sum2 = ADLER_MODULUS - sum2_subtract + new_sum2;
      }
    }

    // Re-pack
    _value = (new_sum2 << 16) | new_sum;
  }

private:
  // What block size are we tracking
  const int64_t _block_size;

  // Keep a cache of the last block_size bytes to make rolling easier
  std::vector<uint8_t> _data_ringbuffer;

  // How many bytes have we digested so far
  int64_t _digested_block_count = 0;

  // Current digest
  uint32_t _value = ADLER_INIT;
};

void calculate_md5(const uint8_t *data, size_t len, uint8_t out[16]) {
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, data, len);
  mbedtls_md5_finish(&ctx, out);
  mbedtls_md5_free(&ctx);
}

void test_incremental_adler(const std::string_view &data) {
  // Test that generating DEFAULT_BLOCK_SIZE adlers with zlib for each offset
  // matches generating a rolling zlib
  AdlerCtx rolling_adler(DEFAULT_BLOCK_SIZE);
  for (int64_t offset = 0; offset < (int64_t)data.size(); offset++) {
    // Roll running adler
    rolling_adler.roll_1(data[offset]);

    // Work out the block size / get a pointer to the raw bytes
    const int64_t bytes_in_block =
        offset >= DEFAULT_BLOCK_SIZE ? DEFAULT_BLOCK_SIZE : offset + 1;
    const uint8_t *const block_start =
        reinterpret_cast<const uint8_t *>(&data[offset - (bytes_in_block - 1)]);

    // Calculate zlib of the bytes in the rolling adler
    uint32_t zlib_adler =
        adler32(AdlerCtx::ADLER_INIT, block_start, bytes_in_block);

    MKASSERT(rolling_adler.digest() == zlib_adler);
  }
}

Delta generate_diff(const std::string_view &old_data,
                    const std::string_view &new_data,
                    const int64_t block_size) {
  // Sanity checks
  MKASSERT(block_size > 0);
  MKASSERT(old_data.size() > 0);
  MKASSERT(new_data.size() > 0);

  LOG("Generating diff using %ldKiB blocks\n", block_size / 1024);

  // Generate fixed-block strong/weak checksums for base file
  std::vector<BlockChecksum> old_block_checksums;
  {
    mk::time::Timer t("Generate base block checksums");

    int64_t last_status_print = mk::time::ms();
    for (int64_t old_offset = 0; old_offset < (int64_t)old_data.size();
         old_offset += block_size) {
      // Do we have enough data left to fill this block?
      const int64_t bytes_in_block = std::min(
          block_size, static_cast<int64_t>(old_data.size() - old_offset));
      const uint8_t *const block_data =
          reinterpret_cast<const uint8_t *>(&old_data[old_offset]);

      // Create a new checsum holder
      old_block_checksums.emplace_back();
      old_block_checksums.back().block_offset = old_offset;

      // Generate rolling checksum
      uint32_t zlib_adler =
          adler32(AdlerCtx::ADLER_INIT, block_data, bytes_in_block);
      old_block_checksums.back().weak_checksum = zlib_adler;

      // Generate MD5 of block
      calculate_md5(block_data, bytes_in_block,
                    old_block_checksums.back().strong_checksum);

      // Maybe print a progress msg
      if (mk::time::ms() > last_status_print + 250) {
        last_status_print = mk::time::ms();
        LOG("Generating block checksums for base file: %.1f%%\r",
            ((double)old_offset) * 100.0 / ((double)old_data.size()));
      }
    }

    // Clear line from progress indicator
    fprintf(stderr, "\n");
    LOG("Generated %lu base block hashes\n", old_block_checksums.size());
  }

  // Generate a map of weak checksum -> block checksum for quick lookup
  std::unordered_map<uint32_t, std::vector<BlockChecksum *>>
      block_checksums_by_adler;
  {
    mk::time::Timer t("Generate adler LUT");
    for (auto &block : old_block_checksums) {
      block_checksums_by_adler[block.weak_checksum].emplace_back(&block);
    }
  }

  // Now, we ned to scan the _new_ file, and calculate the rolling checksum at
  // _every_ byte offset, and test if any of them match one of the blocks in
  // the old file
  std::vector<BktrRelocationEntry> relocations;
  std::string patch_data;
  {
    mk::time::Timer t("Compare rolling adler");
    const int64_t start = mk::time::ms();

    // For fast case (data is same), track our relative offsets in both files
    int64_t old_file_cursor = 0;
    int64_t new_file_cursor = 0;

    // Track the adler context of the new file for when we need to match back in
    AdlerCtx rolling_adler(block_size);

    // Loop, alternating between match case and patch case, until we have
    // completely consumed both files
    while (true) {
      // Entry to accumulate into
      // It is assumed that upon loop entry, we are at a pair of locations where
      // data matches between files, or the start offset
      BktrRelocationEntry cur_entry;
      cur_entry.patched_address = new_file_cursor;
      cur_entry.source_address = old_file_cursor;
      cur_entry.is_patched = BktrRelocationEntry::SRC_BASE;

      // Consume current byte of input file into adler ctx
      rolling_adler.roll_1(new_data[new_file_cursor]);

      // Seek forward until old/new files diverge
      LOG("Begin linear seek starting at  %016x new, %016x old\n",
          new_file_cursor, old_file_cursor);
      while (new_data[new_file_cursor] == old_data[old_file_cursor] &&
             new_file_cursor < (int64_t)new_data.size() &&
             old_file_cursor < (int64_t)old_data.size()) {
        new_file_cursor++;
        old_file_cursor++;
      }

      LOG("Files diverge - %016x new, %016x old\n", new_file_cursor,
          old_file_cursor);

      // Did we stop because we hit EOF on one of the inputs?
      const bool eof_old = old_file_cursor >= (int64_t)old_data.size();
      const bool eof_new = new_file_cursor >= (int64_t)new_data.size();
      if (eof_old && eof_new) {
        // Done with both files. Emit any pending seek relocation and break.
        if (old_file_cursor > (int64_t)cur_entry.source_address) {
          relocations.emplace_back(cur_entry);
        }
        break;
      } else if (eof_old || eof_new) {
        MKASSERT(false); // TODO
      }

      // If both files are still in play, but we diverged, check to see whether
      // we have finished a run where the data matched
      if (old_file_cursor > (int64_t)cur_entry.source_address) {
        // Non-zero data were matched - emit the current relocation to source
        // file
        relocations.emplace_back(cur_entry);
      }

      // We are now in patch context -
      // Reset the current relocation, and mark it as from the patch, at the
      // current patch accumulation offset
      cur_entry.patched_address = new_file_cursor;
      cur_entry.source_address = patch_data.size();
      cur_entry.is_patched = BktrRelocationEntry::SRC_PATCH;

      // Roll it forwards until we encounter a point where the files match
      // again, or EOF
      for (; new_file_cursor < (int64_t)new_data.size(); new_file_cursor++) {
        // Maybe print a progress msg
        if ((new_file_cursor & 0x000F'FFFF) == 0) { // ~10MiB
          const int64_t elapsed = mk::time::ms() - start;
          const double bytes_per_ms =
              ((double)new_file_cursor) / ((double)elapsed);
          const double mib_per_ms = bytes_per_ms / 1024.0 / 1024.0;
          const double mib_per_s = mib_per_ms * 1000;
          const double bytes_remaining = new_data.size() - new_file_cursor;
          const double ms_remaining = bytes_remaining / bytes_per_ms;
          const double minutes_remaining = ms_remaining / 1000 / 60;
          LOG("Checking rolling checksums for patch file:"
              " %.1f%%, %.1f MiB/s, Eta: %.1fmin    \r",
              ((double)new_file_cursor) * 100.0 / ((double)new_data.size()),
              mib_per_s, minutes_remaining);
        }

        // Roll new value into the adler ctx
        rolling_adler.roll_1(new_data[new_file_cursor]);

        // Where does the rolling adler block start?
        const int64_t block_start_offset =
            new_file_cursor < block_size ? 0 : new_file_cursor - block_size + 1;
        const int64_t current_block_size =
            new_file_cursor < block_size ? new_file_cursor + 1 : block_size;

        // If this rolling hash isn't in the map, just continue
        auto search = block_checksums_by_adler.find(rolling_adler.digest());
        if (search == block_checksums_by_adler.end()) {
          continue;
        }

        // If it is in there, generate a strong hash of the candidate blocks to
        // ensure it really does match
        const uint8_t *const block_start =
            reinterpret_cast<const uint8_t *>(&new_data[block_start_offset]);
        uint8_t strong_cksum[16];
        calculate_md5(block_start, current_block_size, strong_cksum);

        BlockChecksum *matched_block = nullptr;
        for (BlockChecksum *block : search->second) {
          // If the MD5 doesn't match, it was a spurious adler match
          if (memcmp(strong_cksum, block->strong_checksum, 16)) {
            // LOG("New file %016lx matches old file %016lx SPURIOUSLY\n",
            //     block_start_offset, block->block_offset);
            continue;
          }

          // Otherwise, these blocks really are equal
          LOG("New file %016lx matches old file %016lx\n", block_start_offset,
              block->block_offset);
          matched_block = block;
          break;
        }

        // If we didn't match a block, continue
        if (matched_block == nullptr) {
          continue;
        }

        // If we did match a block, we are back on track - append the changed
        // bytes to the patch file contents, and emit the relocation
        LOG("Emit relocation @%016x + %016x\n", cur_entry.patched_address,
            new_file_cursor - cur_entry.patched_address);
        patch_data.append(&new_data[cur_entry.patched_address],
                          new_file_cursor - cur_entry.patched_address);
        relocations.emplace_back(cur_entry);

        // Update the old file cursor to the matched position in the base file
        // so that we can go back to linear seek
        old_file_cursor = matched_block->block_offset + block_size - 1;

        // Go back to linear seek mode
        break;
      }
    }

    // Clear progress \r
    fprintf(stderr, "\n");
    const int64_t elapsed = mk::time::ms() - start;
    LOG("Processed %lu bytes of data in %ldms, %.1fMiB/s\n", new_data.size(),
        elapsed,
        ((double)(new_data.size() / 1024 / 1024)) * 1000.0 / ((double)elapsed));
  }

  // Wrap up the data + relocations and return
  Delta ret;
  ret.patch_data = patch_data;
  ret.relocations = relocations;
  return ret;
}

} // namespace delta
} // namespace mk
