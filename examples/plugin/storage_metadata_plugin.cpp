/// \file storage_metadata_plugin.cpp
/// \brief Binary Fingerprinting plugin — identifies and catalogs binaries by
///        computing structural fingerprints and persisting them across sessions.
///
/// When analyzing malware families or firmware revisions, analysts need to
/// track "which version of this binary am I looking at?" and compare
/// structural characteristics across samples. This plugin computes a
/// fingerprint based on:
///
///   - Database metadata (MD5, image base, address range)
///   - Segment layout digest (names, sizes, permissions)
///   - Function histogram (count by size bucket, thunk/library ratios)
///   - Entry point signatures (ordinals, names, addresses)
///   - Fixup distribution (type frequency, density per segment)
///   - String count and average length in data segments
///   - Address-space coverage (code vs data vs unknown ratios)
///
/// The fingerprint is persisted into a netnode so it survives across
/// sessions. On each run, the plugin compares the current fingerprint
/// against the last stored one and highlights what changed (useful for
/// detecting database drift after multi-analyst collaboration).
///
/// API surface exercised:
///   storage (alt/sup/hash/blob, copy/move, error paths), database,
///   segment, function, entry, fixup, data, address, search, comment,
///   type, analysis, diagnostics, name

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <numeric>
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

// ── Fingerprint data model ─────────────────────────────────────────────

struct SegmentDigest {
    std::string  name;
    ida::Address start;
    ida::Address end;
    int          bitness;
    bool         readable;
    bool         writable;
    bool         executable;
};

struct FunctionHistogram {
    std::size_t total{};
    std::size_t thunks{};
    std::size_t library{};
    std::size_t tiny{};    // < 32 bytes
    std::size_t small{};   // 32..255 bytes
    std::size_t medium{};  // 256..4095 bytes
    std::size_t large{};   // >= 4096 bytes
};

struct FixupProfile {
    std::size_t total{};
    std::unordered_map<int, std::size_t> type_counts;
};

struct AddressCoverage {
    std::size_t code_items{};
    std::size_t data_items{};
    std::size_t unknown_items{};
};

struct Fingerprint {
    // Identity.
    std::string  binary_path;
    std::string  binary_md5;
    ida::Address image_base{ida::BadAddress};
    ida::Address range_min{ida::BadAddress};
    ida::Address range_max{ida::BadAddress};

    // Structure.
    std::vector<SegmentDigest> segments;
    FunctionHistogram          functions;
    std::size_t                entry_count{};
    FixupProfile               fixups;
    AddressCoverage            coverage;
    std::size_t                string_count{};
    std::size_t                avg_string_length{};
};

// ── Step 1: Collect database identity ──────────────────────────────────

void collect_identity(Fingerprint& fp) {
    if (auto p = ida::database::input_file_path()) fp.binary_path = *p;
    if (auto m = ida::database::input_md5())       fp.binary_md5  = *m;
    if (auto b = ida::database::image_base())      fp.image_base  = *b;
    if (auto lo = ida::database::min_address())    fp.range_min   = *lo;
    if (auto hi = ida::database::max_address())    fp.range_max   = *hi;

    // Check snapshot state — if we're working from a snapshot, note it.
    // This matters because snapshots can diverge from the original binary.
    if (auto is_snap = ida::database::is_snapshot_database()) {
        if (*is_snap) {
            ida::ui::message("[Fingerprint] Warning: running on a snapshot database. "
                             "Fingerprint may differ from base.\n");
        }
    }

    // Enumerate top-level snapshots for context.
    if (auto snaps = ida::database::snapshots()) {
        if (!snaps->empty()) {
            ida::ui::message(fmt(
                "[Fingerprint] %zu snapshots exist in this database\n",
                snaps->size()));
        }
    }
}

// ── Step 2: Digest segment layout ──────────────────────────────────────

void digest_segments(Fingerprint& fp) {
    for (auto seg : ida::segment::all()) {
        auto perms = seg.permissions();
        fp.segments.push_back({
            .name       = seg.name(),
            .start      = seg.start(),
            .end        = seg.end(),
            .bitness    = seg.bitness(),
            .readable   = perms.read,
            .writable   = perms.write,
            .executable = perms.execute,
        });
    }
}

// ── Step 3: Build function histogram ───────────────────────────────────

void histogram_functions(Fingerprint& fp) {
    // FunctionIterator returns by value — use `auto f`, not `auto& f`.
    for (auto f : ida::function::all()) {
        ++fp.functions.total;

        if (f.is_thunk())   ++fp.functions.thunks;
        if (f.is_library()) ++fp.functions.library;

        auto sz = f.size();
        if (sz < 32)          ++fp.functions.tiny;
        else if (sz < 256)    ++fp.functions.small;
        else if (sz < 4096)   ++fp.functions.medium;
        else                  ++fp.functions.large;
    }
}

// ── Step 4: Profile fixup distribution ─────────────────────────────────

void profile_fixups(Fingerprint& fp) {
    // FixupIterator returns by value — same pattern as FunctionIterator.
    for (auto fix : ida::fixup::all()) {
        ++fp.fixups.total;
        ++fp.fixups.type_counts[static_cast<int>(fix.type)];

        // Cap at 50000 to keep runtime bounded on large binaries.
        if (fp.fixups.total >= 50000) break;
    }
}

// ── Step 5: Count entry points ─────────────────────────────────────────

void count_entries(Fingerprint& fp) {
    if (auto cnt = ida::entry::count()) {
        fp.entry_count = *cnt;
    }
}

// ── Step 6: Measure address-space coverage ─────────────────────────────

void measure_coverage(Fingerprint& fp) {
    if (fp.range_min == ida::BadAddress) return;

    // Sample the first 64K items to estimate coverage ratios.
    ida::Address end = std::min(fp.range_min + 0x10000,
                                fp.range_max != ida::BadAddress
                                    ? fp.range_max : fp.range_min + 0x10000);

    std::size_t items_scanned = 0;
    for (auto addr : ida::address::ItemRange(fp.range_min, end)) {
        if (ida::address::is_code(addr))      ++fp.coverage.code_items;
        else if (ida::address::is_data(addr)) ++fp.coverage.data_items;
        else                                  ++fp.coverage.unknown_items;

        if (++items_scanned > 50000) break;
    }
}

// ── Step 7: Recover string statistics ──────────────────────────────────

void count_strings(Fingerprint& fp) {
    std::size_t total_length = 0;

    for (const auto& seg : fp.segments) {
        // Only scan non-executable segments for strings.
        if (seg.executable) continue;

        std::size_t seg_strings = 0;
        for (auto addr : ida::address::ItemRange(seg.start, seg.end)) {
            if (!ida::address::is_data(addr)) continue;

            auto str = ida::data::read_string(addr, 0);
            if (!str || str->size() < 4) continue;

            ++fp.string_count;
            total_length += str->size();
            ++seg_strings;

            // Cap per segment to avoid spending too long on huge data sections.
            if (seg_strings > 1000) break;
        }
    }

    if (fp.string_count > 0) {
        fp.avg_string_length = total_length / fp.string_count;
    }
}

// ── Step 8: Persist fingerprint to netnode ──────────────────────────────
//
// Storage layout (using high indices to avoid the idalib index-0 crash):
//   alt 100 'A' = function count
//   alt 101 'A' = entry count
//   alt 102 'A' = fixup count
//   alt 103 'A' = segment count
//   alt 104 'A' = string count
//   alt 105 'A' = code_items
//   alt 106 'A' = data_items
//   alt 107 'A' = unknown_items
//   hash "md5"  'H' = binary MD5
//   hash "path" 'H' = binary path
//   blob 200    'B' = serialized segment names (newline-separated)

void persist_fingerprint(const Fingerprint& fp) {
    auto node = ida::storage::Node::open("idax_fingerprint", true);
    if (!node) {
        ida::ui::message(fmt(
            "[Fingerprint] Failed to open storage node: %s\n",
            node.error().message.c_str()));
        return;
    }

    auto& n = *node;

    // Store numeric summary as alt values.
    n.set_alt(100, static_cast<std::uint64_t>(fp.functions.total), 'A');
    n.set_alt(101, static_cast<std::uint64_t>(fp.entry_count),     'A');
    n.set_alt(102, static_cast<std::uint64_t>(fp.fixups.total),    'A');
    n.set_alt(103, static_cast<std::uint64_t>(fp.segments.size()), 'A');
    n.set_alt(104, static_cast<std::uint64_t>(fp.string_count),    'A');
    n.set_alt(105, static_cast<std::uint64_t>(fp.coverage.code_items),    'A');
    n.set_alt(106, static_cast<std::uint64_t>(fp.coverage.data_items),    'A');
    n.set_alt(107, static_cast<std::uint64_t>(fp.coverage.unknown_items), 'A');

    // Store identity strings as hash values.
    n.set_hash("md5",  fp.binary_md5,  'H');
    n.set_hash("path", fp.binary_path, 'H');

    // Store segment names as a blob (newline-separated).
    std::string seg_names;
    for (const auto& seg : fp.segments) {
        if (!seg_names.empty()) seg_names += '\n';
        seg_names += seg.name;
    }
    std::vector<std::uint8_t> seg_blob(seg_names.begin(), seg_names.end());
    seg_blob.push_back(0);  // Null terminator for blob_string() compatibility.
    n.set_blob(200, seg_blob, 'B');

    // Verify roundtrip: read back the MD5 hash.
    auto stored_md5 = n.hash("md5", 'H');
    if (stored_md5 && *stored_md5 != fp.binary_md5) {
        ida::ui::message("[Fingerprint] Warning: hash roundtrip mismatch\n");
    }

    // Verify blob roundtrip.
    auto blob_read = n.blob_string(200, 'B');
    if (blob_read && *blob_read != seg_names) {
        ida::ui::message("[Fingerprint] Warning: blob roundtrip mismatch\n");
    }

    ida::ui::message("[Fingerprint] Fingerprint persisted to netnode\n");
}

// ── Step 9: Compare against previous fingerprint ───────────────────────

void compare_with_previous(const Fingerprint& fp) {
    auto node = ida::storage::Node::open("idax_fingerprint", false);
    if (!node) {
        ida::ui::message("[Fingerprint] No previous fingerprint found — first run.\n");
        return;
    }

    auto& n = *node;

    // Read previous function count.
    auto prev_funcs = n.alt(100, 'A');
    if (prev_funcs) {
        auto current = static_cast<std::uint64_t>(fp.functions.total);
        if (*prev_funcs != current) {
            ida::ui::message(fmt(
                "[Fingerprint] Delta: functions %llu -> %llu (%+lld)\n",
                (unsigned long long)*prev_funcs,
                (unsigned long long)current,
                (long long)(static_cast<std::int64_t>(current) -
                static_cast<std::int64_t>(*prev_funcs))));
        }
    }

    // Read previous segment layout.
    auto prev_seg_blob = n.blob_string(200, 'B');
    if (prev_seg_blob) {
        std::string current_names;
        for (const auto& seg : fp.segments) {
            if (!current_names.empty()) current_names += '\n';
            current_names += seg.name;
        }
        if (*prev_seg_blob != current_names) {
            ida::ui::message("[Fingerprint] Delta: segment layout changed\n");
        }
    }

    // Read previous MD5 to detect binary replacement.
    auto prev_md5 = n.hash("md5", 'H');
    if (prev_md5 && *prev_md5 != fp.binary_md5) {
        ida::ui::message(fmt(
            "[Fingerprint] Warning: binary MD5 changed (%s -> %s). "
            "The underlying file may have been replaced.\n",
            prev_md5->c_str(), fp.binary_md5.c_str()));
    }
}

// ── Step 10: Create summary type and annotate ──────────────────────────

void annotate_fingerprint(const Fingerprint& fp) {
    // Create a struct type summarizing the fingerprint for type-library
    // persistence. This demonstrates the type construction API.
    auto summary_type = ida::type::TypeInfo::create_struct();
    summary_type.add_member("function_count", ida::type::TypeInfo::uint32(), 0);
    summary_type.add_member("entry_count",    ida::type::TypeInfo::uint32(), 4);
    summary_type.add_member("fixup_count",    ida::type::TypeInfo::uint32(), 8);
    summary_type.add_member("string_count",   ida::type::TypeInfo::uint32(), 12);
    summary_type.save_as("idax_fingerprint_summary");

    // Comment the image base with the fingerprint digest.
    if (fp.image_base != ida::BadAddress) {
        ida::comment::set(fp.image_base, fmt(
            "Fingerprint: %zu funcs, %zu entries, %zu fixups, %zu strings | MD5: %s",
            fp.functions.total, fp.entry_count,
            fp.fixups.total, fp.string_count,
            fp.binary_md5.substr(0, 8).c_str()), true);
    }
}

// ── Step 11: Print the report ──────────────────────────────────────────

void print_fingerprint(const Fingerprint& fp) {
    ida::ui::message("\n");
    ida::ui::message("===========================================================\n");
    ida::ui::message("                 BINARY FINGERPRINT\n");
    ida::ui::message("===========================================================\n");
    ida::ui::message(fmt("  File:        %s\n", fp.binary_path.c_str()));
    ida::ui::message(fmt("  MD5:         %s\n", fp.binary_md5.c_str()));
    ida::ui::message(fmt("  Image base:  %#llx\n", (unsigned long long)fp.image_base));
    ida::ui::message(fmt("  Range:       %#llx - %#llx\n",
                                 (unsigned long long)fp.range_min,
                                 (unsigned long long)fp.range_max));
    ida::ui::message("-----------------------------------------------------------\n");

    // Segment layout.
    ida::ui::message(fmt("  Segments (%zu)\n", fp.segments.size()));
    for (const auto& seg : fp.segments) {
        ida::ui::message(fmt(
            "    %-12s %#010llx-%#010llx  %dbit  %s%s%s\n",
            seg.name.c_str(), (unsigned long long)seg.start,
            (unsigned long long)seg.end, seg.bitness,
            seg.readable   ? "R" : "-",
            seg.writable   ? "W" : "-",
            seg.executable ? "X" : "-"));
    }

    // Function histogram.
    ida::ui::message("-----------------------------------------------------------\n");
    ida::ui::message(fmt("  Functions:   %zu total\n", fp.functions.total));
    ida::ui::message(fmt("    Thunks:    %zu\n", fp.functions.thunks));
    ida::ui::message(fmt("    Library:   %zu\n", fp.functions.library));
    ida::ui::message(fmt("    Tiny:      %zu (<32B)\n", fp.functions.tiny));
    ida::ui::message(fmt("    Small:     %zu (32-255B)\n", fp.functions.small));
    ida::ui::message(fmt("    Medium:    %zu (256-4095B)\n", fp.functions.medium));
    ida::ui::message(fmt("    Large:     %zu (>=4096B)\n", fp.functions.large));

    // Entry points & fixups.
    ida::ui::message("-----------------------------------------------------------\n");
    ida::ui::message(fmt("  Entry pts:   %zu\n", fp.entry_count));
    ida::ui::message(fmt("  Fixups:      %zu\n", fp.fixups.total));
    if (!fp.fixups.type_counts.empty()) {
        for (auto& [type, count] : fp.fixups.type_counts) {
            auto pct_x10 = fp.fixups.total > 0
                ? count * 1000 / fp.fixups.total : std::size_t(0);
            ida::ui::message(fmt(
                "    Type %2d: %6zu (%zu.%zu%%)\n",
                type, count, pct_x10 / 10, pct_x10 % 10));
        }
    }

    // Coverage.
    ida::ui::message("-----------------------------------------------------------\n");
    auto total_items = fp.coverage.code_items + fp.coverage.data_items
                     + fp.coverage.unknown_items;
    if (total_items > 0) {
        auto code_pct  = fp.coverage.code_items * 1000 / total_items;
        auto data_pct  = fp.coverage.data_items * 1000 / total_items;
        auto unk_pct   = fp.coverage.unknown_items * 1000 / total_items;
        ida::ui::message(fmt(
            "  Coverage (first 64K):  code %zu.%zu%%  data %zu.%zu%%  unknown %zu.%zu%%\n",
            code_pct / 10, code_pct % 10,
            data_pct / 10, data_pct % 10,
            unk_pct / 10, unk_pct % 10));
    }

    // Strings.
    ida::ui::message(fmt("  Strings:     %zu (avg length %zu)\n",
                                 fp.string_count, fp.avg_string_length));
    ida::ui::message("===========================================================\n\n");
}

// ── Plugin orchestration ───────────────────────────────────────────────

void run_fingerprint() {
    ida::ui::message("[Fingerprint] Starting binary fingerprint...\n");

    // Ensure analysis is complete before fingerprinting.
    ida::analysis::wait();

    Fingerprint fp;

    collect_identity(fp);
    digest_segments(fp);
    histogram_functions(fp);
    profile_fixups(fp);
    count_entries(fp);
    measure_coverage(fp);
    count_strings(fp);

    // Compare against a previously stored fingerprint, if any.
    compare_with_previous(fp);

    // Persist the new fingerprint.
    persist_fingerprint(fp);

    // Create type and annotate the database.
    annotate_fingerprint(fp);

    // Print the final report.
    print_fingerprint(fp);

    // Log completion via diagnostics.
    ida::diagnostics::log(ida::diagnostics::LogLevel::Info,
        "fingerprint",
        fmt("Fingerprint complete: %zu funcs, %zu segs, %zu fixups",
                    fp.functions.total, fp.segments.size(), fp.fixups.total));
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct BinaryFingerprintPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name    = "Binary Fingerprint",
            .hotkey  = "Ctrl-Shift-F",
            .comment = "Compute and persist a structural fingerprint",
            .help    = "Computes a structural fingerprint (segment layout, "
                       "function histogram, fixup distribution, string stats, "
                       "coverage ratios) and persists it in a netnode. On "
                       "subsequent runs, highlights what changed.",
        };
    }

    ida::Status run(std::size_t) override {
        run_fingerprint();
        return ida::ok();
    }
};
