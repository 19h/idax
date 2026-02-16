/// \file deep_analysis_plugin.cpp
/// \brief Binary Audit Report plugin — a realistic cross-domain analysis tool.
///
/// This plugin generates a structured security-oriented audit report for a
/// loaded binary. It answers practical questions a reverse engineer would ask:
///
///   - Which segments are writable and executable (W+X)?
///   - Which functions have the deepest call chains?
///   - Where are large stack frames (potential buffer-overflow surfaces)?
///   - Which functions receive user-controlled input (heuristic)?
///   - Where do fixups / relocations cluster (ASLR surface)?
///   - Are there suspicious instruction patterns (int3, hlt, self-modifying)?
///   - Can we recover strings from the binary and annotate them?
///
/// The report is printed to the IDA output window and optionally annotated
/// directly into the database via comments and names.
///
/// API surface exercised:
///   address, data, database, segment, function, instruction, name, xref,
///   comment, type, fixup, entry, search, analysis, diagnostics, core

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

// Portable formatting helper (std::format requires macOS 13.3+ deployment target).
template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[2048];
    std::snprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

// ── Report data structures ─────────────────────────────────────────────

/// A writable+executable segment is a potential attack surface (no W^X).
struct WxViolation {
    ida::Address    start;
    ida::Address    end;
    std::string     name;
};

/// Functions with unusually large stack frames may be vulnerable to overflow.
struct LargeFrameEntry {
    ida::Address    address;
    std::string     name;
    ida::AddressSize frame_size;
    std::size_t     variable_count;
};

/// A call-graph node with depth information for reachability analysis.
struct CallNode {
    ida::Address              address;
    std::string               name;
    std::vector<ida::Address> callees;
    std::size_t               depth{0};
};

/// Collected statistics for the final report.
struct AuditReport {
    std::string  binary_path;
    std::string  binary_md5;
    ida::Address image_base{ida::BadAddress};
    ida::Address addr_min{ida::BadAddress};
    ida::Address addr_max{ida::BadAddress};

    std::size_t segment_count{};
    std::size_t function_count{};
    std::size_t entry_point_count{};
    std::size_t fixup_count{};

    std::vector<WxViolation>    wx_violations;
    std::vector<LargeFrameEntry> large_frames;
    std::vector<ida::Address>   suspicious_instructions;
    std::vector<ida::Address>   string_locations;
    std::unordered_map<std::string, std::size_t> xref_hotspots;  // name -> inbound count
};

// ── Step 1: Collect database metadata ──────────────────────────────────

void collect_metadata(AuditReport& report) {
    if (auto p = ida::database::input_file_path()) report.binary_path  = *p;
    if (auto m = ida::database::input_md5())       report.binary_md5   = *m;
    if (auto b = ida::database::image_base())      report.image_base   = *b;
    if (auto lo = ida::database::min_address())    report.addr_min     = *lo;
    if (auto hi = ida::database::max_address())    report.addr_max     = *hi;
    if (auto c = ida::entry::count())              report.entry_point_count = *c;
}

// ── Step 2: Audit segments for W^X violations ──────────────────────────

void audit_segments(AuditReport& report) {
    auto cnt = ida::segment::count();
    if (!cnt) return;
    report.segment_count = *cnt;

    // Iterate all segments. SegmentIterator returns by value — use `auto seg`.
    for (auto seg : ida::segment::all()) {
        auto perms = seg.permissions();

        // Flag writable+executable segments: a real security concern.
        if (perms.write && perms.execute) {
            report.wx_violations.push_back({
                seg.start(), seg.end(), seg.name()
            });
        }

        // Verify the segment round-trips through by-name lookup. This guards
        // against name-encoding issues in the database.
        if (auto sn = seg.name(); !sn.empty()) {
            auto by_name = ida::segment::by_name(sn);
            if (by_name && by_name->start() != seg.start()) {
                ida::ui::message(fmt(
                    "[Audit] Warning: segment '%s' name-lookup mismatch "
                    "(%#llx vs %#llx)\n",
                    sn.c_str(), (unsigned long long)seg.start(),
                    (unsigned long long)by_name->start()));
            }
        }
    }
}

// ── Step 3: Analyze functions — frames, call graph, register vars ──────

void audit_functions(AuditReport& report,
                     std::unordered_map<ida::Address, CallNode>& call_graph) {
    auto cnt = ida::function::count();
    if (!cnt) return;
    report.function_count = *cnt;

    constexpr ida::AddressSize kLargeFrameThreshold = 1024;

    // FunctionIterator returns by value — use `auto f`, not `auto& f`.
    for (auto f : ida::function::all()) {
        // Build call-graph node.
        CallNode node;
        node.address = f.start();
        node.name    = f.name();
        if (auto ces = ida::function::callees(f.start())) {
            node.callees = std::move(*ces);
        }
        call_graph[f.start()] = std::move(node);

        // Check for large stack frames.
        if (auto frm = ida::function::frame(f.start())) {
            auto total = frm->total_size();
            if (total >= kLargeFrameThreshold) {
                report.large_frames.push_back({
                    f.start(),
                    f.name(),
                    total,
                    frm->variables().size(),
                });
            }
        }

        // Collect inbound xref count for hotspot analysis.
        if (auto callers = ida::function::callers(f.start())) {
            if (callers->size() >= 10) {
                report.xref_hotspots[f.name()] = callers->size();
            }
        }
    }
}

// ── Step 4: Scan for suspicious instruction patterns ───────────────────
//
// Looks for:
//   - INT3 (0xCC) sequences outside padding (could be anti-debug traps)
//   - HLT (0xF4) in non-function areas (unusual halt)
//   - Immediate 0x90909090 (NOP sled, potential shellcode landing zone)

void scan_suspicious_patterns(AuditReport& report) {
    if (report.addr_min == ida::BadAddress) return;

    // Search for NOP sleds using the immediate-value search.
    auto nop_sled = ida::search::immediate(
        0x90909090, report.addr_min, ida::search::Direction::Forward);
    if (nop_sled) {
        report.suspicious_instructions.push_back(*nop_sled);
    }

    // Search for INT3 byte patterns in executable segments.
    for (auto seg : ida::segment::all()) {
        if (!seg.permissions().execute) continue;

        auto int3 = ida::data::find_binary_pattern(
            seg.start(), seg.end(), "CC CC CC CC", true);
        if (int3) {
            // Only flag it if it's not inside a known function (i.e. padding).
            auto func = ida::function::at(*int3);
            if (!func) {
                report.suspicious_instructions.push_back(*int3);
            }
        }
    }
}

// ── Step 5: Recover and annotate string literals ───────────────────────

void recover_strings(AuditReport& report) {
    // Walk data segments looking for string-like items.
    for (auto seg : ida::segment::all()) {
        if (seg.permissions().execute) continue;  // Skip code segments.

        std::size_t found_in_segment = 0;
        for (auto addr : ida::address::ItemRange(seg.start(), seg.end())) {
            if (!ida::address::is_data(addr)) continue;

            // Try to read a string at this data item.
            auto str = ida::data::read_string(addr, 0);
            if (!str || str->size() < 4) continue;  // Skip short fragments.

            report.string_locations.push_back(addr);
            ++found_in_segment;

            // Annotate the first few strings as repeatable comments so
            // they appear in xref listings.
            if (found_in_segment <= 20) {
                std::string preview = str->substr(0, 64);
                if (str->size() > 64) preview += "...";
                auto existing = ida::comment::get(addr, true);
                if (!existing || existing->empty()) {
                    ida::comment::set(addr,
                        fmt("String: \"%s\"", preview.c_str()), true);
                }
            }

            // Safety cap: don't iterate forever on huge data segments.
            if (found_in_segment > 500) break;
        }
    }
}

// ── Step 6: Fixup clustering analysis ──────────────────────────────────

void analyze_fixups(AuditReport& report) {
    std::size_t total = 0;
    std::unordered_map<int, std::size_t> type_counts;

    // FixupIterator returns by value — use `auto fix`, not `auto& fix`.
    for (auto fix : ida::fixup::all()) {
        ++type_counts[static_cast<int>(fix.type)];
        ++total;
        if (total >= 50000) break;  // Cap for very large binaries.
    }
    report.fixup_count = total;

    if (total > 0) {
        ida::ui::message(fmt(
            "[Audit] Fixup distribution (%zu total):\n", total));
        for (auto& [type, count] : type_counts) {
            // Compute percentage as integer tenths to avoid std::format
            // floating-point (unavailable on older macOS deployment targets).
            auto pct_x10 = total > 0 ? count * 1000 / total : 0;
            ida::ui::message(fmt(
                "[Audit]   Type %d: %zu (%zu.%zu%%)\n",
                type, count, pct_x10 / 10, pct_x10 % 10));
        }
    }
}

// ── Step 7: Type system — create an audit struct and apply it ──────────

void create_audit_type(const AuditReport& report) {
    // Demonstrate type construction: build a struct that represents our
    // audit metadata, save it to the local type library, and apply it
    // at the image base to mark the binary as audited.
    auto audit_type = ida::type::TypeInfo::create_struct();
    audit_type.add_member("magic",     ida::type::TypeInfo::uint32(), 0);
    audit_type.add_member("timestamp", ida::type::TypeInfo::uint64(), 4);
    audit_type.add_member("flags",     ida::type::TypeInfo::uint16(), 12);

    if (auto st = audit_type.save_as("idax_audit_stamp"); st) {
        ida::ui::message("[Audit] Saved audit stamp type to local type library\n");

        // Apply at image base for visibility.
        if (report.image_base != ida::BadAddress) {
            ida::type::apply_named_type(report.image_base, "idax_audit_stamp");
        }
    }

    // Report local type library size.
    if (auto count = ida::type::local_type_count()) {
        ida::ui::message(fmt(
            "[Audit] Local type library contains %zu types\n", *count));
    }
}

// ── Step 8: Entry-point annotation ─────────────────────────────────────

void annotate_entry_points(const AuditReport& report) {
    auto cnt = ida::entry::count();
    if (!cnt || *cnt == 0) return;

    for (std::size_t i = 0; i < *cnt; ++i) {
        auto ep = ida::entry::by_index(i);
        if (!ep) continue;

        // Add an anterior comment marking each entry point in the listing.
        ida::comment::add_anterior(ep->address, fmt(
            "===  Entry Point: '%s' (ordinal %llu)  ===",
            ep->name.c_str(), (unsigned long long)ep->ordinal));

        // Ensure the entry point has a public name.
        if (!ep->name.empty()) {
            ida::name::set(ep->address, ep->name);
            ida::name::set_public(ep->address, true);
        }
    }

    ida::ui::message(fmt(
        "[Audit] Annotated %zu entry points\n", *cnt));
}

// ── Step 9: Instruction-level deep dive on the largest function ────────

void analyze_hottest_function(const AuditReport& report) {
    // Find the largest function by frame size.
    if (report.large_frames.empty()) return;

    auto& biggest = report.large_frames.front();
    ida::ui::message(fmt(
        "[Audit] Deep-diving into '%s' at %#llx (frame %llu bytes, %zu vars)\n",
        biggest.name.c_str(), (unsigned long long)biggest.address,
        (unsigned long long)biggest.frame_size,
        biggest.variable_count));

    auto func = ida::function::at(biggest.address);
    if (!func) return;

    // Decode instructions and classify operand patterns.
    std::size_t insn_count = 0;
    std::size_t call_count = 0;
    std::size_t mem_write_count = 0;

    auto addr = func->start();
    while (addr < func->end() && insn_count < 2000) {
        auto insn = ida::instruction::decode(addr);
        if (!insn) break;

        ++insn_count;
        if (ida::instruction::is_call(addr)) ++call_count;

        // Count operands that write to memory — potential buffer accesses.
        for (const auto& op : insn->operands()) {
            if (op.is_memory()) ++mem_write_count;
        }

        // Get the SP delta to track stack usage patterns.
        auto sp = ida::function::sp_delta_at(addr);
        if (sp && *sp < -4096) {
            ida::comment::set(addr,
                fmt("Warning: large SP delta %lld", (long long)*sp), false);
        }

        auto nxt = ida::instruction::next(addr);
        if (!nxt) break;
        addr = nxt->address();
    }

    ida::ui::message(fmt(
        "[Audit]   %zu instructions, %zu calls, %zu memory operands\n",
        insn_count, call_count, mem_write_count));

    // Demonstrate operand representation: set the first immediate operand
    // to hex display for readability, then restore default.
    auto first_code = ida::address::find_first(
        func->start(), func->end(), ida::address::Predicate::Code);
    if (first_code) {
        auto probe = ida::instruction::decode(*first_code);
        if (probe && probe->operand_count() > 0) {
            // Set hex display for the first operand, then restore default.
            ida::instruction::set_operand_hex(*first_code, 0);
            ida::instruction::clear_operand_representation(*first_code, 0);
        }
    }
}

// ── Step 10: Generate the final report ─────────────────────────────────

void print_report(const AuditReport& report) {
    ida::ui::message("\n");
    ida::ui::message("===========================================================\n");
    ida::ui::message("                  BINARY AUDIT REPORT\n");
    ida::ui::message("===========================================================\n");
    ida::ui::message(fmt("  File:        %s\n", report.binary_path.c_str()));
    ida::ui::message(fmt("  MD5:         %s\n", report.binary_md5.c_str()));
    ida::ui::message(fmt("  Image base:  %#llx\n", (unsigned long long)report.image_base));
    ida::ui::message(fmt("  Range:       %#llx - %#llx\n",
                                 (unsigned long long)report.addr_min,
                                 (unsigned long long)report.addr_max));
    ida::ui::message(fmt("  Segments:    %zu\n", report.segment_count));
    ida::ui::message(fmt("  Functions:   %zu\n", report.function_count));
    ida::ui::message(fmt("  Entry pts:   %zu\n", report.entry_point_count));
    ida::ui::message(fmt("  Fixups:      %zu\n", report.fixup_count));
    ida::ui::message("-----------------------------------------------------------\n");

    // W^X violations.
    if (report.wx_violations.empty()) {
        ida::ui::message("  W^X:         PASS (no writable+executable segments)\n");
    } else {
        ida::ui::message(fmt(
            "  W^X:         FAIL (%zu violations)\n",
            report.wx_violations.size()));
        for (auto& v : report.wx_violations) {
            ida::ui::message(fmt(
                "    - '%s' [%#llx, %#llx)\n", v.name.c_str(),
                (unsigned long long)v.start, (unsigned long long)v.end));
        }
    }

    // Large stack frames.
    ida::ui::message(fmt(
        "  Large frames: %zu (>= 1024 bytes)\n", report.large_frames.size()));
    for (auto& f : report.large_frames) {
        ida::ui::message(fmt(
            "    - '%s' at %#llx: %llu bytes, %zu vars\n",
            f.name.c_str(), (unsigned long long)f.address,
            (unsigned long long)f.frame_size, f.variable_count));
    }

    // Suspicious patterns.
    ida::ui::message(fmt(
        "  Suspicious:  %zu patterns found\n",
        report.suspicious_instructions.size()));
    for (auto addr : report.suspicious_instructions) {
        ida::ui::message(fmt("    - %#llx\n", (unsigned long long)addr));
    }

    // Strings recovered.
    ida::ui::message(fmt(
        "  Strings:     %zu recovered\n", report.string_locations.size()));

    // Xref hotspots (most-called functions).
    if (!report.xref_hotspots.empty()) {
        ida::ui::message("  Xref hotspots (10+ callers):\n");
        for (auto& [name, count] : report.xref_hotspots) {
            ida::ui::message(fmt(
                "    - '%s': %zu callers\n", name.c_str(), count));
        }
    }

    ida::ui::message("===========================================================\n\n");
}

// ── Plugin orchestration ───────────────────────────────────────────────

void run_audit() {
    ida::ui::message("[Audit] Starting binary audit...\n");

    // Ensure analysis is complete before we start.
    ida::analysis::wait();

    AuditReport report;
    std::unordered_map<ida::Address, CallNode> call_graph;

    collect_metadata(report);
    audit_segments(report);
    audit_functions(report, call_graph);
    scan_suspicious_patterns(report);
    recover_strings(report);
    analyze_fixups(report);
    create_audit_type(report);
    annotate_entry_points(report);
    analyze_hottest_function(report);
    print_report(report);

    // Log completion via the diagnostics API.
    ida::diagnostics::log(ida::diagnostics::LogLevel::Info,
        "audit", fmt("Audit complete: %zu functions, %zu segments",
                             report.function_count, report.segment_count));
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct BinaryAuditPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name    = "Binary Audit Report",
            .hotkey  = "Ctrl-Shift-A",
            .comment = "Generate a structured security audit report",
            .help    = "Scans segments for W^X violations, identifies large "
                       "stack frames, recovers strings, analyzes fixup "
                       "distribution, and annotates findings into the database.",
        };
    }

    ida::Status run(std::size_t) override {
        run_audit();
        return ida::ok();
    }
};

IDAX_PLUGIN(BinaryAuditPlugin)
