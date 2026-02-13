/// \file advanced_loader.cpp
/// \brief XBIN Format Loader — loads a hypothetical structured binary format
///        demonstrating realistic loader development patterns.
///
/// Real loaders must solve several problems at once:
///   - Reliably identify their file format from a magic signature
///   - Parse structured headers into segments with correct permissions
///   - Transfer raw file data into the IDA database
///   - Register entry points and apply types to them
///   - Handle edge cases (truncated files, overlapping segments, BSS gaps)
///   - Support save and rebase callbacks for round-trip workflows
///
/// This loader handles "XBIN", a hypothetical format designed to exercise
/// all of these paths. The file structure is:
///
///   Offset  Size  Field
///   0x00    4     Magic: "XBIN"
///   0x04    2     Version (1 or 2)
///   0x06    2     Flags (bit 0: 64-bit, bit 1: relocatable)
///   0x08    2     Segment count
///   0x0A    2     Entry count
///   0x0C    4     Base address
///   0x10    N*24  Segment table (see XbinSegmentEntry)
///   ...     M*12  Entry table (see XbinEntryEntry)
///   ...           Raw data referenced by segment file offsets
///
/// API surface exercised:
///   loader (Loader, InputFile, AcceptResult, LoaderOptions, file_to_database,
///   memory_to_database, set_processor, create_filename_comment, abort_load),
///   segment, name, comment, type, entry, fixup

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// Portable formatting helper (std::format requires macOS 13.3+ deployment target).
template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[2048];
    std::snprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

// ── XBIN format constants ──────────────────────────────────────────────

constexpr std::uint8_t kXbinMagic[4] = {'X', 'B', 'I', 'N'};
constexpr std::uint16_t kXbinVersion1 = 0x0001;
constexpr std::uint16_t kXbinVersion2 = 0x0002;

constexpr std::uint16_t kFlagIs64Bit      = 0x0001;
constexpr std::uint16_t kFlagRelocatable   = 0x0002;

constexpr std::uint32_t kSegExecute = 0x01;
constexpr std::uint32_t kSegWrite   = 0x02;
constexpr std::uint32_t kSegRead    = 0x04;
constexpr std::uint32_t kSegBss     = 0x08;
constexpr std::uint32_t kSegExtern  = 0x10;

// ── On-disk structures ─────────────────────────────────────────────────

struct XbinHeader {
    std::uint8_t  magic[4]{};
    std::uint16_t version{};
    std::uint16_t flags{};
    std::uint16_t segment_count{};
    std::uint16_t entry_count{};
    std::uint32_t base_address{};
};

struct XbinSegmentEntry {
    char          name[8]{};           // Null-padded segment name.
    std::uint32_t file_offset{};       // Offset of raw data in file.
    std::uint32_t virtual_address{};   // RVA relative to base_address.
    std::uint32_t raw_size{};          // Bytes in file.
    std::uint32_t virtual_size{};      // Bytes in memory (>= raw_size for BSS).
    std::uint32_t flags{};             // Permission and type flags.
};

struct XbinEntryEntry {
    std::uint32_t ordinal{};
    std::uint32_t address{};           // RVA relative to base_address.
    std::uint32_t name_offset{};       // File offset to name string (0 = none).
};

// ── Helper: read a POD struct from the input file ──────────────────────

template <typename T>
ida::Result<T> read_struct(ida::loader::InputFile& file, std::int64_t offset) {
    auto bytes = file.read_bytes_at(offset, sizeof(T));
    if (!bytes) return std::unexpected(bytes.error());
    if (bytes->size() < sizeof(T)) {
        return std::unexpected(ida::Error::validation(
            "Truncated read at file offset", std::to_string(offset)));
    }
    T result{};
    std::memcpy(&result, bytes->data(), sizeof(T));
    return result;
}

// ── Helper: extract null-terminated name from fixed-width field ────────

std::string fixed_name(const char* data, std::size_t max_len) {
    auto end = static_cast<const char*>(std::memchr(data, '\0', max_len));
    return end ? std::string(data, end) : std::string(data, max_len);
}

// ── Helper: detect overlapping segments and warn ───────────────────────

void warn_overlaps(const std::vector<XbinSegmentEntry>& entries,
                   std::uint32_t base) {
    for (std::size_t i = 0; i < entries.size(); ++i) {
        for (std::size_t j = i + 1; j < entries.size(); ++j) {
            ida::Address a_start = base + entries[i].virtual_address;
            ida::Address a_end   = a_start + entries[i].virtual_size;
            ida::Address b_start = base + entries[j].virtual_address;
            ida::Address b_end   = b_start + entries[j].virtual_size;

            if (a_start < b_end && b_start < a_end) {
                ida::ui::message(fmt(
                    "[XBIN] Warning: segments %zu and %zu overlap "
                    "([%#llx,%#llx) vs [%#llx,%#llx))\n",
                    i, j, (unsigned long long)a_start,
                    (unsigned long long)a_end,
                    (unsigned long long)b_start,
                    (unsigned long long)b_end));
            }
        }
    }
}

} // anonymous namespace

// ── Loader implementation ──────────────────────────────────────────────

class XbinLoader final : public ida::loader::Loader {
public:
    ida::loader::LoaderOptions options() const override {
        return {
            .supports_reload   = true,
            .requires_processor = false,
        };
    }

    // ── accept(): identify XBIN files ───────────────────────────────────

    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        // Reject files too small to hold a header.
        auto file_size = file.size();
        if (!file_size || *file_size < static_cast<std::int64_t>(sizeof(XbinHeader))) {
            return std::nullopt;
        }

        // Read and validate the magic signature.
        auto magic_bytes = file.read_bytes_at(0, 4);
        if (!magic_bytes || magic_bytes->size() < 4) return std::nullopt;
        if (std::memcmp(magic_bytes->data(), kXbinMagic, 4) != 0) {
            return std::nullopt;
        }

        auto header = read_struct<XbinHeader>(file, 0);
        if (!header) return std::nullopt;

        // Reject unsupported versions early rather than failing in load().
        if (header->version != kXbinVersion1 &&
            header->version != kXbinVersion2) {
            return std::nullopt;
        }

        // Build the accept result. Higher version gets higher priority
        // so IDA prefers the most capable loader variant.
        int priority = 100;
        if (header->version == kXbinVersion2) priority += 50;
        // Files with no segments are technically valid containers but
        // less likely to be what the user intended to load.
        if (header->segment_count == 0) priority = 10;

        ida::loader::AcceptResult result;
        result.format_name = (header->version == kXbinVersion2)
            ? "XBIN v2 executable" : "XBIN v1 executable";
        result.processor_name = "metapc";
        result.priority = priority;
        return result;
    }

    // ── load(): create segments, transfer bytes, register entries ────────

    ida::Status load(ida::loader::InputFile& file,
                     std::string_view format_name) override {
        auto set_proc = ida::loader::set_processor("metapc");
        if (!set_proc) return set_proc;

        auto header = read_struct<XbinHeader>(file, 0);
        if (!header) return std::unexpected(header.error());

        bool is_64bit = (header->flags & kFlagIs64Bit) != 0;
        int  bitness  = is_64bit ? 64 : 32;

        // Add a filename comment at the top of the database for context.
        ida::loader::create_filename_comment();

        // ── Parse segment table ─────────────────────────────────────────

        std::int64_t seg_table_off = sizeof(XbinHeader);
        std::vector<XbinSegmentEntry> seg_entries;
        seg_entries.reserve(header->segment_count);

        for (std::uint16_t i = 0; i < header->segment_count; ++i) {
            auto off = seg_table_off +
                static_cast<std::int64_t>(i) * sizeof(XbinSegmentEntry);
            auto seg = read_struct<XbinSegmentEntry>(file, off);
            if (!seg) {
                return std::unexpected(ida::Error::validation(
                    "Truncated segment table",
                    fmt("entry %u at offset %lld", (unsigned)i, (long long)off)));
            }
            seg_entries.push_back(*seg);
        }

        warn_overlaps(seg_entries, header->base_address);

        // ── Create segments and load data ───────────────────────────────

        for (std::size_t i = 0; i < seg_entries.size(); ++i) {
            const auto& seg = seg_entries[i];
            ida::Address seg_start = header->base_address + seg.virtual_address;
            ida::Address seg_end   = seg_start + seg.virtual_size;

            std::string name = fixed_name(seg.name, 8);
            if (name.empty()) name = fmt("seg_%zu", i);

            // Map flags to idax types.
            auto seg_type = ida::segment::Type::Normal;
            if (seg.flags & kSegBss)    seg_type = ida::segment::Type::Bss;
            if (seg.flags & kSegExtern) seg_type = ida::segment::Type::External;

            std::string_view class_name = "DATA";
            if (seg.flags & kSegExecute) class_name = "CODE";
            if (seg.flags & kSegBss)     class_name = "BSS";

            auto created = ida::segment::create(
                seg_start, seg_end, name, class_name, seg_type);
            if (!created) continue;

            ida::segment::set_bitness(seg_start, bitness);
            ida::segment::set_permissions(seg_start, {
                .read    = (seg.flags & kSegRead)    != 0,
                .write   = (seg.flags & kSegWrite)   != 0,
                .execute = (seg.flags & kSegExecute) != 0,
            });

            // Transfer raw bytes from file. BSS and extern segments
            // have no file data to transfer.
            if (!(seg.flags & (kSegBss | kSegExtern)) && seg.raw_size > 0) {
                auto load_size = std::min(
                    static_cast<ida::AddressSize>(seg.raw_size),
                    static_cast<ida::AddressSize>(seg.virtual_size));
                ida::loader::file_to_database(
                    file.handle(), seg.file_offset, seg_start, load_size, true);

                // If virtual_size > raw_size, the gap is uninitialized memory
                // (like .bss at the tail of a data segment). Fill with zeros
                // using memory_to_database so IDA treats these bytes as defined.
                if (seg.virtual_size > seg.raw_size) {
                    std::vector<std::uint8_t> zeros(
                        seg.virtual_size - seg.raw_size, 0);
                    ida::loader::memory_to_database(
                        zeros.data(), seg_start + seg.raw_size, zeros.size());
                }
            }

            ida::comment::set(seg_start,
                fmt("XBIN segment '%s': %#llx-%#llx, %s",
                    name.c_str(), (unsigned long long)seg_start,
                    (unsigned long long)seg_end,
                    std::string(class_name).c_str()),
                false);
        }

        // ── Parse and register entry points ─────────────────────────────

        std::int64_t entry_off = seg_table_off +
            static_cast<std::int64_t>(header->segment_count) * sizeof(XbinSegmentEntry);

        for (std::uint16_t i = 0; i < header->entry_count; ++i) {
            auto off = entry_off +
                static_cast<std::int64_t>(i) * sizeof(XbinEntryEntry);
            auto entry = read_struct<XbinEntryEntry>(file, off);
            if (!entry) continue;

            ida::Address ea = header->base_address + entry->address;

            // Read the entry name from the file if a name offset is given.
            std::string entry_name;
            if (entry->name_offset != 0) {
                if (auto nr = file.read_string(entry->name_offset, 256)) {
                    entry_name = *nr;
                }
            }
            if (entry_name.empty()) {
                entry_name = fmt("entry_%u", entry->ordinal);
            }

            ida::entry::add(entry->ordinal, ea, entry_name, true);
            ida::name::set(ea, entry_name);

            // Apply a basic function type so the decompiler has something
            // to start with.
            auto func_type = ida::type::TypeInfo::from_declaration(
                "int __cdecl " + entry_name + "(void)");
            if (func_type) {
                func_type->apply(ea);
            }

            ida::comment::add_anterior(ea,
                fmt("--- XBIN Entry: '%s' (ordinal %u) ---",
                    entry_name.c_str(), entry->ordinal));
        }

        // ── Inject fixups for relocatable binaries ──────────────────────

        if (header->flags & kFlagRelocatable) {
            // A real loader would parse a dedicated relocation table here.
            // We synthesize a few fixups at pointer-aligned addresses in
            // code segments to demonstrate the fixup creation API.
            int ptr_size = is_64bit ? 8 : 4;
            for (const auto& seg : seg_entries) {
                if (!(seg.flags & kSegExecute)) continue;

                ida::Address seg_start = header->base_address + seg.virtual_address;
                int count = std::min(4, static_cast<int>(seg.raw_size / ptr_size));

                for (int j = 0; j < count; ++j) {
                    ida::Address fixup_ea = seg_start +
                        static_cast<ida::Address>(j * ptr_size);

                    ida::fixup::Descriptor fd;
                    fd.source       = fixup_ea;
                    fd.type         = is_64bit ? ida::fixup::Type::Off64
                                               : ida::fixup::Type::Off32;
                    fd.offset       = seg_start;
                    fd.displacement = 0;
                    ida::fixup::set(fixup_ea, fd);
                }
            }
        }

        return ida::ok();
    }

    // ── save(): capability query and serialization ──────────────────────

    ida::Result<bool> save(void* fp,
                           std::string_view format_name) override {
        // When fp is nullptr, IDA is asking whether we support saving.
        // Returning true enables "File > Produce file" for our format.
        if (fp == nullptr) return true;

        // A real implementation would serialize the database back to
        // XBIN format here. For this example we just report success.
        return true;
    }

    // ── move_segment(): handle program rebasing ─────────────────────────

    ida::Status move_segment(ida::Address from, ida::Address to,
                             ida::AddressSize size,
                             std::string_view format_name) override {
        // from == BadAddress means whole-program rebase; `to` is the delta.
        // A real loader would update all relocation records here.
        if (from == ida::BadAddress) return ida::ok();

        if (size == 0) {
            return std::unexpected(ida::Error::validation(
                "Zero-size segment move is not meaningful"));
        }

        return ida::ok();
    }
};

IDAX_LOADER(XbinLoader)
