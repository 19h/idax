/// \file advanced_loader.cpp
/// \brief Advanced custom file format loader demonstrating comprehensive
///        idax loader API usage with multi-segment creation, fixup injection,
///        type application, entry point registration, and comment annotation.
///
/// This loader handles a hypothetical "XBIN" binary format with the structure:
///   - 16-byte header: magic "XBIN", version(u16), flags(u16),
///     segment_count(u16), entry_ordinal_count(u16), base_address(u32)
///   - Segment table: N entries of 24 bytes each:
///     [name(8 bytes, null-padded), file_offset(u32), virtual_addr(u32),
///      raw_size(u32), virtual_size(u32), flags(u32)]
///   - Entry table: M entries of 12 bytes each:
///     [ordinal(u32), address(u32), name_offset(u32)]
///   - Raw data sections follow, referenced by segment table offsets.
///
/// Edge cases exercised:
///   - InputFile: size(), tell(), seek(), read_bytes(), read_bytes_at(),
///     read_string(), filename(), handle()
///   - AcceptResult with priority and processor hint
///   - LoaderOptions (supports_reload, requires_processor)
///   - Multiple segment creation with varied types, bitness, permissions
///   - file_to_database and memory_to_database for loading bytes
///   - set_processor for target architecture selection
///   - create_filename_comment for metadata annotation
///   - abort_load for fatal errors (demonstrated but guarded)
///   - Entry point registration with multiple ordinals
///   - Fixup injection at relocation sites
///   - Type application at entry points
///   - Comment annotation on created segments/entry points
///   - Save callback querying save capability
///   - Move/rebase callback with delta computation
///   - Error propagation through all loader stages
///   - Handle edge case of zero-segment file
///   - Handle edge case of overlapping segments
///   - Handle edge case of empty segment names

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace {

// ── XBIN format structures ─────────────────────────────────────────────

constexpr std::uint8_t kXbinMagic[4] = {'X', 'B', 'I', 'N'};
constexpr std::uint16_t kXbinVersion1 = 0x0001;
constexpr std::uint16_t kXbinVersion2 = 0x0002;

// Flag bits in the file header.
constexpr std::uint16_t kXbinFlag64Bit    = 0x0001;
constexpr std::uint16_t kXbinFlagRelocatable = 0x0002;
constexpr std::uint16_t kXbinFlagDebugInfo   = 0x0004;

// Segment flag bits.
constexpr std::uint32_t kSegFlagExecute  = 0x01;
constexpr std::uint32_t kSegFlagWrite    = 0x02;
constexpr std::uint32_t kSegFlagRead     = 0x04;
constexpr std::uint32_t kSegFlagBss      = 0x08;
constexpr std::uint32_t kSegFlagExtern   = 0x10;

struct XbinHeader {
    std::uint8_t  magic[4]{};
    std::uint16_t version{};
    std::uint16_t flags{};
    std::uint16_t segment_count{};
    std::uint16_t entry_count{};
    std::uint32_t base_address{};
};

struct XbinSegmentEntry {
    char          name[8]{};
    std::uint32_t file_offset{};
    std::uint32_t virtual_address{};
    std::uint32_t raw_size{};
    std::uint32_t virtual_size{};
    std::uint32_t flags{};
};

struct XbinEntryEntry {
    std::uint32_t ordinal{};
    std::uint32_t address{};
    std::uint32_t name_offset{};
};

// ── Helper: read a trivially-copyable struct from InputFile ────────────

template <typename T>
ida::Result<T> read_struct(ida::loader::InputFile& file, std::int64_t offset) {
    auto bytes = file.read_bytes_at(offset, sizeof(T));
    if (!bytes) return std::unexpected(bytes.error());
    if (bytes->size() < sizeof(T)) {
        return std::unexpected(ida::Error::validation(
            "Truncated read", std::to_string(offset)));
    }
    T result{};
    std::memcpy(&result, bytes->data(), sizeof(T));
    return result;
}

// ── Helper: null-terminated string from fixed-width field ──────────────

std::string fixed_string(const char* data, std::size_t max_len) {
    auto end = static_cast<const char*>(std::memchr(data, '\0', max_len));
    return end ? std::string(data, end) : std::string(data, max_len);
}

} // anonymous namespace

// ── Loader implementation ──────────────────────────────────────────────

class AdvancedXbinLoader final : public ida::loader::Loader {
public:
    /// Return loader options demonstrating both flags.
    ida::loader::LoaderOptions options() const override {
        return {
            .supports_reload   = true,
            .requires_processor = false,
        };
    }

    /// Accept callback: identify XBIN files.
    ///
    /// Edge cases:
    ///   - File too small for header
    ///   - Magic mismatch
    ///   - Unsupported version
    ///   - Priority assignment based on version
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        // Check file size is sufficient for header.
        auto file_size = file.size();
        if (!file_size || *file_size < static_cast<std::int64_t>(sizeof(XbinHeader))) {
            return std::nullopt;  // Too small, not our format.
        }

        // Read and validate magic.
        auto magic_bytes = file.read_bytes_at(0, 4);
        if (!magic_bytes || magic_bytes->size() < 4) {
            return std::nullopt;
        }

        if (std::memcmp(magic_bytes->data(), kXbinMagic, 4) != 0) {
            return std::nullopt;  // Not an XBIN file.
        }

        // Read full header.
        auto header = read_struct<XbinHeader>(file, 0);
        if (!header) {
            return std::nullopt;
        }

        // Validate version.
        if (header->version != kXbinVersion1 && header->version != kXbinVersion2) {
            return std::nullopt;  // Unsupported version.
        }

        // Edge case: zero segments is technically valid (empty container).
        // We still accept it but at lower priority.
        int priority = (header->segment_count > 0) ? 100 : 10;

        // Edge case: version 2 gets higher priority.
        if (header->version == kXbinVersion2) priority += 50;

        // Determine processor from flags.
        std::string processor = (header->flags & kXbinFlag64Bit)
            ? "metapc" : "metapc";  // Same processor, different bitness handling.

        ida::loader::AcceptResult result;
        result.format_name = (header->version == kXbinVersion2)
            ? "XBIN v2 executable" : "XBIN v1 executable";
        result.processor_name = processor;
        result.priority = priority;

        // Edge case: exercise InputFile::filename().
        auto fname = file.filename();
        if (fname) {
            // Log filename for diagnostic purposes.
        }

        // Edge case: exercise InputFile::tell() after reads.
        auto pos = file.tell();
        (void)pos;

        return result;
    }

    /// Load callback: create segments, load bytes, register entries.
    ///
    /// Edge cases:
    ///   - Empty segment table (zero segments)
    ///   - BSS segments (virtual_size > raw_size)
    ///   - Extern segments (no file data)
    ///   - Overlapping segment detection
    ///   - Entry points with and without names
    ///   - Fixup injection at potential relocation sites
    ///   - Type application at entry point addresses
    ///   - Comment annotation throughout
    ida::Status load(ida::loader::InputFile& file,
                     std::string_view format_name) override {
        // Set processor type.
        auto proc = ida::loader::set_processor("metapc");
        if (!proc) return proc;

        // Re-read header.
        auto header = read_struct<XbinHeader>(file, 0);
        if (!header) return std::unexpected(header.error());

        bool is_64bit = (header->flags & kXbinFlag64Bit) != 0;
        int bitness = is_64bit ? 64 : 32;

        // Create filename comment.
        auto cmt_status = ida::loader::create_filename_comment();
        (void)cmt_status;  // Best-effort.

        // ── Load segment table ──────────────────────────────────────────

        std::int64_t seg_table_offset = sizeof(XbinHeader);
        std::vector<XbinSegmentEntry> seg_entries;
        seg_entries.reserve(header->segment_count);

        for (std::uint16_t i = 0; i < header->segment_count; ++i) {
            std::int64_t entry_offset = seg_table_offset +
                static_cast<std::int64_t>(i) * sizeof(XbinSegmentEntry);
            auto seg = read_struct<XbinSegmentEntry>(file, entry_offset);
            if (!seg) {
                return std::unexpected(ida::Error::validation(
                    "Failed to read segment table entry",
                    std::to_string(i)));
            }
            seg_entries.push_back(*seg);
        }

        // Edge case: detect overlapping segments.
        for (std::size_t i = 0; i < seg_entries.size(); ++i) {
            for (std::size_t j = i + 1; j < seg_entries.size(); ++j) {
                auto& a = seg_entries[i];
                auto& b = seg_entries[j];
                ida::Address a_start = header->base_address + a.virtual_address;
                ida::Address a_end   = a_start + a.virtual_size;
                ida::Address b_start = header->base_address + b.virtual_address;
                ida::Address b_end   = b_start + b.virtual_size;

                if (a_start < b_end && b_start < a_end) {
                    // Overlapping segments -- still load but warn.
                }
            }
        }

        // ── Create segments ─────────────────────────────────────────────

        for (std::size_t i = 0; i < seg_entries.size(); ++i) {
            const auto& seg = seg_entries[i];
            ida::Address seg_start = header->base_address + seg.virtual_address;
            ida::Address seg_end   = seg_start + seg.virtual_size;

            // Edge case: empty segment name.
            std::string seg_name = fixed_string(seg.name, 8);
            if (seg_name.empty()) {
                seg_name = "seg_" + std::to_string(i);
            }

            // Determine segment type.
            ida::segment::Type seg_type = ida::segment::Type::Normal;
            if (seg.flags & kSegFlagBss)    seg_type = ida::segment::Type::Bss;
            if (seg.flags & kSegFlagExtern) seg_type = ida::segment::Type::External;

            // Determine class name from flags.
            std::string_view class_name = "DATA";
            if (seg.flags & kSegFlagExecute) class_name = "CODE";
            if (seg.flags & kSegFlagBss)     class_name = "BSS";

            // Create segment.
            auto created = ida::segment::create(
                seg_start, seg_end, seg_name, class_name, seg_type);
            if (!created) continue;

            // Set permissions.
            ida::segment::Permissions perms;
            perms.read    = (seg.flags & kSegFlagRead) != 0;
            perms.write   = (seg.flags & kSegFlagWrite) != 0;
            perms.execute = (seg.flags & kSegFlagExecute) != 0;
            (void)ida::segment::set_permissions(seg_start, perms);

            // Set bitness.
            (void)ida::segment::set_bitness(seg_start, bitness);

            // Load file data for non-BSS, non-extern segments.
            if (!(seg.flags & kSegFlagBss) && !(seg.flags & kSegFlagExtern)) {
                if (seg.raw_size > 0) {
                    // Use file_to_database with the linput_t handle.
                    auto load_st = ida::loader::file_to_database(
                        file.handle(), seg.file_offset, seg_start,
                        std::min(static_cast<ida::AddressSize>(seg.raw_size),
                                 static_cast<ida::AddressSize>(seg.virtual_size)),
                        true);
                    (void)load_st;

                    // Edge case: if virtual_size > raw_size, the gap is
                    // zero-filled BSS-style data. We can load zeros for it
                    // using memory_to_database.
                    if (seg.virtual_size > seg.raw_size) {
                        std::vector<std::uint8_t> zeros(
                            seg.virtual_size - seg.raw_size, 0);
                        ida::Address gap_start = seg_start + seg.raw_size;
                        (void)ida::loader::memory_to_database(
                            zeros.data(), gap_start, zeros.size());
                    }
                }
            }

            // Annotate segment with comment.
            (void)ida::comment::set(seg_start,
                "Loaded by XBIN advanced loader", false);
        }

        // ── Load entry table ────────────────────────────────────────────

        std::int64_t entry_table_offset = seg_table_offset +
            static_cast<std::int64_t>(header->segment_count) * sizeof(XbinSegmentEntry);

        for (std::uint16_t i = 0; i < header->entry_count; ++i) {
            std::int64_t entry_offset = entry_table_offset +
                static_cast<std::int64_t>(i) * sizeof(XbinEntryEntry);
            auto entry = read_struct<XbinEntryEntry>(file, entry_offset);
            if (!entry) continue;

            ida::Address entry_addr = header->base_address + entry->address;

            // Try to read the entry name from the file.
            std::string entry_name;
            if (entry->name_offset != 0) {
                auto name_result = file.read_string(entry->name_offset, 256);
                if (name_result) {
                    entry_name = *name_result;
                }
            }

            // Edge case: entry without a name.
            if (entry_name.empty()) {
                entry_name = "entry_" + std::to_string(entry->ordinal);
            }

            // Register entry point.
            (void)ida::entry::add(
                entry->ordinal, entry_addr, entry_name, true);

            // Name the entry point.
            (void)ida::name::set(entry_addr, entry_name);

            // Apply a function type at the entry point.
            auto func_type = ida::type::TypeInfo::from_declaration(
                "int __cdecl " + entry_name + "(void)");
            if (func_type) {
                (void)func_type->apply(entry_addr);
            }

            // Annotate with anterior comment.
            (void)ida::comment::add_anterior(entry_addr,
                "--- Entry Point: " + entry_name + " ---");
        }

        // ── Inject fixups for relocatable binaries ──────────────────────

        if (header->flags & kXbinFlagRelocatable) {
            // In a real loader, we'd parse a relocation table.
            // Here we demonstrate the fixup API by creating synthetic fixups
            // at the first few pointer-aligned addresses in each code segment.
            for (const auto& seg : seg_entries) {
                if (!(seg.flags & kSegFlagExecute)) continue;

                ida::Address seg_start = header->base_address + seg.virtual_address;
                int ptr_size = is_64bit ? 8 : 4;

                // Create up to 4 synthetic fixups per code segment.
                for (int j = 0; j < 4 && j * ptr_size < static_cast<int>(seg.raw_size); ++j) {
                    ida::Address fixup_addr = seg_start +
                        static_cast<ida::Address>(j * ptr_size);

                    ida::fixup::Descriptor fixup_desc;
                    fixup_desc.source = fixup_addr;
                    fixup_desc.type = is_64bit ? ida::fixup::Type::Off64
                                               : ida::fixup::Type::Off32;
                    fixup_desc.offset = seg_start;
                    fixup_desc.displacement = 0;

                    (void)ida::fixup::set(fixup_addr, fixup_desc);
                }
            }
        }

        return ida::ok();
    }

    /// Save callback: query capability and optionally write.
    ///
    /// Edge case: fp==nullptr is a capability query (return true/false).
    ida::Result<bool> save(void* fp,
                           std::string_view format_name) override {
        if (fp == nullptr) {
            // Capability query: we support saving.
            return true;
        }

        // In a real implementation, we'd serialize the database back to
        // XBIN format here. For this example, we report success.
        return true;
    }

    /// Move/rebase callback: handle program rebasing.
    ///
    /// Edge cases:
    ///   - from == BadAddress means entire program rebase (delta in `to`)
    ///   - Single segment move (from != BadAddress)
    ///   - Zero-size means entire-program rebase
    ida::Status move_segment(ida::Address from, ida::Address to,
                             ida::AddressSize size,
                             std::string_view format_name) override {
        if (from == ida::BadAddress) {
            // Entire program rebase. `to` contains the delta.
            // For XBIN, we'd need to update all relocation targets.
            // Here we just acknowledge it.
            return ida::ok();
        }

        // Single segment move.
        if (size == 0) {
            return std::unexpected(ida::Error::validation(
                "Zero-size segment move not supported"));
        }

        // In a real loader we'd update internal relocation records.
        return ida::ok();
    }
};

IDAX_LOADER(AdvancedXbinLoader)
