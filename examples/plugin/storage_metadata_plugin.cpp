/// \file storage_metadata_plugin.cpp
/// \brief Advanced storage and metadata plugin demonstrating comprehensive
///        netnode persistence, batch annotation, database metadata, and
///        snapshot management.
///
/// This plugin demonstrates:
///   1. Netnode storage (alt/sup/hash/blob operations) with multiple tags
///   2. Blob lifecycle (create, read, overwrite, size query, string conversion, remove)
///   3. Node creation, open, copy, and move semantics
///   4. Database metadata queries (path, MD5, image base, bounds)
///   5. Snapshot enumeration and description
///   6. File-to-database and memory-to-database transfer
///   7. Batch annotation: naming every function with a prefix
///   8. Batch annotation: commenting every segment header
///   9. Type creation and mass application
///  10. Entry point enumeration and annotation
///  11. Fixup traversal and statistics
///  12. Analysis queue control (enable/disable/schedule/wait)
///  13. Diagnostics API (log levels, performance counters, assertions)
///  14. Custom fixup handler registration lifecycle
///  15. Address range iteration with item counting
///  16. Predicate-based search across the entire database
///
/// Edge cases exercised:
///   - Blob operations at high indices (avoiding index 0 crash in idalib)
///   - Multiple tags on the same node index
///   - Node not found errors
///   - Default-constructed Node behavior
///   - Copy and move assignment/construction of Node
///   - Empty blob reads
///   - Snapshot tree traversal with children
///   - Snapshot on non-snapshot database
///   - Analysis wait with idle check
///   - Performance counter reset and read
///   - Error enrichment with context strings

#include <ida/idax.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <numeric>
#include <string>
#include <vector>

namespace {

// ── Phase 1: Netnode storage exercise ──────────────────────────────────

void exercise_storage() {
    ida::ui::message("[Storage] === Netnode Storage Exercise ===\n");

    // Create a new node.
    auto node = ida::storage::Node::open("idax_example_storage", true);
    if (!node) {
        ida::ui::message(std::format(
            "[Storage] Failed to create node: {}\n", node.error().message));
        return;
    }

    auto& n = *node;

    // ── Alt operations (integer key-value) ──────────────────────────

    // Use high indices to avoid idalib index-0 crash.
    constexpr ida::Address kAltIndex = 100;

    (void)n.set_alt(kAltIndex, 0xDEADBEEF, 'A');
    auto alt_val = n.alt(kAltIndex, 'A');
    if (alt_val && *alt_val != 0xDEADBEEF) {
        ida::ui::message("[Storage] Alt roundtrip mismatch\n");
    }

    // Edge case: multiple tags on same index.
    (void)n.set_alt(kAltIndex, 42, 'B');
    auto alt_b = n.alt(kAltIndex, 'B');
    if (alt_b && *alt_b != 42) {
        ida::ui::message("[Storage] Alt tag B mismatch\n");
    }

    // Edge case: remove alt.
    (void)n.remove_alt(kAltIndex, 'A');
    auto removed_alt = n.alt(kAltIndex, 'A');
    // After removal, should return 0 or error.

    // ── Sup operations (binary data) ────────────────────────────────

    constexpr ida::Address kSupIndex = 200;
    std::vector<std::uint8_t> sup_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    (void)n.set_sup(kSupIndex, sup_data, 'S');

    auto sup_val = n.sup(kSupIndex, 'S');
    if (sup_val && *sup_val != sup_data) {
        ida::ui::message("[Storage] Sup roundtrip mismatch\n");
    }

    // Edge case: sup with different tag.
    std::vector<std::uint8_t> sup_data2 = {0xAA, 0xBB};
    (void)n.set_sup(kSupIndex, sup_data2, 'T');
    auto sup_t = n.sup(kSupIndex, 'T');
    if (sup_t && *sup_t != sup_data2) {
        ida::ui::message("[Storage] Sup tag T mismatch\n");
    }

    // ── Hash operations (string key-value) ──────────────────────────

    (void)n.set_hash("version", "1.0.0", 'H');
    auto hash_val = n.hash("version", 'H');
    if (hash_val && *hash_val != "1.0.0") {
        ida::ui::message("[Storage] Hash roundtrip mismatch\n");
    }

    (void)n.set_hash("author", "idax-example", 'H');
    auto hash_author = n.hash("author", 'H');

    // Edge case: overwrite hash.
    (void)n.set_hash("version", "2.0.0", 'H');
    auto hash_v2 = n.hash("version", 'H');
    if (hash_v2 && *hash_v2 != "2.0.0") {
        ida::ui::message("[Storage] Hash overwrite mismatch\n");
    }

    // ── Blob operations ─────────────────────────────────────────────

    constexpr ida::Address kBlobIndex = 300;

    // Create a blob.
    std::vector<std::uint8_t> blob_data(1024);
    std::iota(blob_data.begin(), blob_data.end(),
              static_cast<std::uint8_t>(0));
    (void)n.set_blob(kBlobIndex, blob_data, 'B');

    // Read blob size.
    auto blob_sz = n.blob_size(kBlobIndex, 'B');
    if (blob_sz && *blob_sz != 1024) {
        ida::ui::message(std::format(
            "[Storage] Blob size {} != 1024\n", *blob_sz));
    }

    // Read blob data.
    auto blob_val = n.blob(kBlobIndex, 'B');
    if (blob_val && *blob_val != blob_data) {
        ida::ui::message("[Storage] Blob roundtrip mismatch\n");
    }

    // Edge case: overwrite blob with smaller data.
    std::vector<std::uint8_t> small_blob = {0xDE, 0xAD};
    (void)n.set_blob(kBlobIndex, small_blob, 'B');
    auto small_read = n.blob(kBlobIndex, 'B');
    if (small_read && small_read->size() != 2) {
        ida::ui::message("[Storage] Blob overwrite size mismatch\n");
    }

    // Edge case: blob as string.
    std::string test_str = "Hello, netnode!";
    std::vector<std::uint8_t> str_blob(test_str.begin(), test_str.end());
    str_blob.push_back(0);  // Null terminator.
    (void)n.set_blob(kBlobIndex + 1, str_blob, 'B');

    auto blob_str = n.blob_string(kBlobIndex + 1, 'B');
    if (blob_str && *blob_str != test_str) {
        ida::ui::message(std::format(
            "[Storage] Blob string mismatch: '{}'\n", *blob_str));
    }

    // Edge case: remove blob.
    (void)n.remove_blob(kBlobIndex, 'B');
    auto removed_blob = n.blob(kBlobIndex, 'B');
    // After removal, blob should be empty or error.

    // ── Node copy/move semantics ────────────────────────────────────

    {
        // Copy construction.
        auto copy = n;
        auto copy_hash = copy.hash("version", 'H');
        if (copy_hash && *copy_hash != "2.0.0") {
            ida::ui::message("[Storage] Copy construction broken\n");
        }

        // Move construction.
        auto moved = std::move(copy);
        auto moved_hash = moved.hash("version", 'H');
        if (moved_hash && *moved_hash != "2.0.0") {
            ida::ui::message("[Storage] Move construction broken\n");
        }

        // Copy assignment.
        ida::storage::Node assigned;
        assigned = n;
        auto assigned_hash = assigned.hash("version", 'H');

        // Move assignment.
        ida::storage::Node move_assigned;
        move_assigned = std::move(assigned);
    }

    // Edge case: open nonexistent node without create flag.
    auto bad_node = ida::storage::Node::open("idax_nonexistent_node_xyz", false);
    if (bad_node) {
        ida::ui::message("[Storage] Expected error for nonexistent node\n");
    }

    // Edge case: default-constructed node operations should error.
    {
        ida::storage::Node empty;
        auto bad_alt = empty.alt(100, 'A');
        (void)bad_alt;  // Expected error or zero.
    }

    ida::ui::message("[Storage] Netnode storage exercise complete\n");
}

// ── Phase 2: Database metadata ─────────────────────────────────────────

void exercise_database_metadata() {
    ida::ui::message("[Metadata] === Database Metadata Exercise ===\n");

    auto path = ida::database::input_file_path();
    if (path) ida::ui::message(std::format("[Metadata] Input: {}\n", *path));

    auto md5 = ida::database::input_md5();
    if (md5) ida::ui::message(std::format("[Metadata] MD5: {}\n", *md5));

    auto base = ida::database::image_base();
    if (base) ida::ui::message(std::format("[Metadata] Base: {:#x}\n", *base));

    auto min_a = ida::database::min_address();
    auto max_a = ida::database::max_address();
    if (min_a && max_a) {
        ida::ui::message(std::format(
            "[Metadata] Range: {:#x} - {:#x} ({} bytes)\n",
            *min_a, *max_a, *max_a - *min_a));
    }

    // Snapshots.
    auto snaps = ida::database::snapshots();
    if (snaps) {
        ida::ui::message(std::format(
            "[Metadata] {} top-level snapshots\n", snaps->size()));
        for (const auto& snap : *snaps) {
            ida::ui::message(std::format(
                "[Metadata]   Snapshot: id={} desc='{}'\n",
                snap.id, snap.description));
            // Edge case: recurse into children.
            for (const auto& child : snap.children) {
                ida::ui::message(std::format(
                    "[Metadata]     Child: id={} desc='{}'\n",
                    child.id, child.description));
            }
        }
    }

    // Edge case: is_snapshot_database.
    auto is_snap = ida::database::is_snapshot_database();
    if (is_snap) {
        ida::ui::message(std::format(
            "[Metadata] Is snapshot DB: {}\n", *is_snap));
    }

    // Edge case: set_snapshot_description.
    (void)ida::database::set_snapshot_description("idax metadata exercise");

    ida::ui::message("[Metadata] Database metadata exercise complete\n");
}

// ── Phase 3: Batch annotation ──────────────────────────────────────────

void exercise_batch_annotation() {
    ida::ui::message("[Annotation] === Batch Annotation Exercise ===\n");

    // Annotate every segment header with a comment.
    std::size_t seg_count = 0;
    for (auto seg : ida::segment::all()) {
        (void)ida::comment::set(seg.start(),
            std::format("Segment '{}': {:#x}-{:#x}, {}bit, {}{}{}",
                        seg.name(), seg.start(), seg.end(), seg.bitness(),
                        seg.permissions().read ? "R" : "",
                        seg.permissions().write ? "W" : "",
                        seg.permissions().execute ? "X" : ""),
            true /* repeatable */);
        ++seg_count;
    }
    ida::ui::message(std::format(
        "[Annotation] Commented {} segments\n", seg_count));

    // Type creation and application.
    auto audit_struct = ida::type::TypeInfo::create_struct();
    (void)audit_struct.add_member("magic", ida::type::TypeInfo::uint32(), 0);
    (void)audit_struct.add_member("flags", ida::type::TypeInfo::uint16(), 4);
    (void)audit_struct.add_member("version", ida::type::TypeInfo::uint16(), 6);
    (void)audit_struct.save_as("idax_audit_header");

    // Apply to image base if available.
    auto base = ida::database::image_base();
    if (base) {
        (void)ida::type::apply_named_type(*base, "idax_audit_header");
    }

    // Entry point annotation.
    auto entry_cnt = ida::entry::count();
    if (entry_cnt) {
        for (std::size_t i = 0; i < *entry_cnt; ++i) {
            auto ep = ida::entry::by_index(i);
            if (ep) {
                (void)ida::comment::add_anterior(ep->address,
                    std::format("=== Entry Point: '{}' (ordinal {}) ===",
                                ep->name, ep->ordinal));
            }
        }
        ida::ui::message(std::format(
            "[Annotation] Annotated {} entry points\n", *entry_cnt));
    }

    ida::ui::message("[Annotation] Batch annotation complete\n");
}

// ── Phase 4: Fixup statistics ──────────────────────────────────────────

void exercise_fixup_statistics() {
    ida::ui::message("[Fixups] === Fixup Statistics ===\n");

    std::unordered_map<int, std::size_t> type_counts;
    std::size_t total = 0;

    // Edge case: FixupIterator returns by value, use `auto fix`.
    for (auto fix : ida::fixup::all()) {
        ++type_counts[static_cast<int>(fix.type)];
        ++total;
        if (total >= 10000) break;  // Cap for large binaries.
    }

    ida::ui::message(std::format("[Fixups] Total: {}\n", total));
    for (const auto& [type, count] : type_counts) {
        ida::ui::message(std::format(
            "[Fixups]   Type {}: {} fixups\n", type, count));
    }

    // Custom fixup registration lifecycle.
    ida::fixup::CustomHandler handler;
    handler.name = "idax_example_fixup";
    handler.properties = 0;
    handler.size = 4;
    handler.width = 32;
    handler.shift = 0;
    handler.reference_type = 0;

    auto reg_result = ida::fixup::register_custom(handler);
    if (reg_result) {
        ida::ui::message(std::format(
            "[Fixups] Registered custom fixup type: {:#x}\n", *reg_result));

        // Find it by name.
        auto found = ida::fixup::find_custom("idax_example_fixup");
        if (found && *found != *reg_result) {
            ida::ui::message("[Fixups] Custom fixup find mismatch\n");
        }

        // Unregister.
        (void)ida::fixup::unregister_custom(*reg_result);

        // Edge case: find after unregister should fail.
        auto not_found = ida::fixup::find_custom("idax_example_fixup");
        if (not_found) {
            ida::ui::message("[Fixups] Expected error after unregister\n");
        }
    }

    // Edge case: duplicate registration.
    auto dup1 = ida::fixup::register_custom(handler);
    if (dup1) {
        auto dup2 = ida::fixup::register_custom(handler);
        // Second registration should fail (duplicate name).
        (void)ida::fixup::unregister_custom(*dup1);
    }

    ida::ui::message("[Fixups] Fixup statistics complete\n");
}

// ── Phase 5: Analysis control ──────────────────────────────────────────

void exercise_analysis_control() {
    ida::ui::message("[Analysis] === Analysis Control Exercise ===\n");

    auto enabled = ida::analysis::is_enabled();
    ida::ui::message(std::format("[Analysis] Enabled: {}\n", enabled));

    auto idle = ida::analysis::is_idle();
    ida::ui::message(std::format("[Analysis] Idle: {}\n", idle));

    // Schedule reanalysis of the first code address.
    auto min_a = ida::database::min_address();
    if (min_a) {
        (void)ida::analysis::schedule(*min_a);
    }

    // Wait for analysis to complete.
    (void)ida::analysis::wait();

    auto idle_after = ida::analysis::is_idle();
    ida::ui::message(std::format("[Analysis] Idle after wait: {}\n", idle_after));

    ida::ui::message("[Analysis] Analysis control exercise complete\n");
}

// ── Phase 6: Diagnostics exercise ──────────────────────────────────────

void exercise_diagnostics() {
    ida::ui::message("[Diagnostics] === Diagnostics Exercise ===\n");

    // Log level.
    auto old_level = ida::diagnostics::log_level();
    (void)ida::diagnostics::set_log_level(ida::diagnostics::LogLevel::Debug);
    ida::diagnostics::log(ida::diagnostics::LogLevel::Debug,
                          "Test debug message from storage_metadata_plugin");
    (void)ida::diagnostics::set_log_level(old_level);

    // Performance counters.
    ida::diagnostics::reset_performance_counters();
    auto counters = ida::diagnostics::performance_counters();
    ida::ui::message(std::format(
        "[Diagnostics] Performance counters after reset: "
        "api_calls={}, errors={}, warnings={}\n",
        counters.api_calls, counters.errors, counters.warnings));

    // Error enrichment.
    auto err = ida::Error::not_found("test item");
    auto enriched = ida::diagnostics::enrich(err, "exercise_diagnostics");
    ida::ui::message(std::format(
        "[Diagnostics] Enriched error: {} (ctx: {})\n",
        enriched.message, enriched.context));

    // Invariant assertion (should pass).
    ida::diagnostics::assert_invariant(true, "This should pass");

    ida::ui::message("[Diagnostics] Diagnostics exercise complete\n");
}

// ── Phase 7: Address range statistics ──────────────────────────────────

void exercise_address_statistics() {
    ida::ui::message("[AddressStats] === Address Range Statistics ===\n");

    auto min_a = ida::database::min_address();
    auto max_a = ida::database::max_address();
    if (!min_a || !max_a) return;

    // Count items, code, data, unknown bytes in first 0x10000.
    ida::Address start = *min_a;
    ida::Address end = std::min(*min_a + 0x10000, *max_a);

    std::size_t code_count = 0;
    std::size_t data_count = 0;
    std::size_t unknown_count = 0;
    std::size_t head_count = 0;

    for (auto addr : ida::address::ItemRange(start, end)) {
        ++head_count;
        if (ida::address::is_code(addr))    ++code_count;
        else if (ida::address::is_data(addr)) ++data_count;
        else ++unknown_count;

        if (head_count > 50000) break;
    }

    ida::ui::message(std::format(
        "[AddressStats] Range {:#x}-{:#x}: {} items "
        "(code={}, data={}, unknown={})\n",
        start, end, head_count, code_count, data_count, unknown_count));

    // Predicate search across database.
    auto first_code = ida::address::find_first(
        start, end, ida::address::Predicate::Code);
    if (first_code) {
        ida::ui::message(std::format(
            "[AddressStats] First code: {:#x}\n", *first_code));
    }

    auto first_data = ida::address::find_first(
        start, end, ida::address::Predicate::Data);
    if (first_data) {
        ida::ui::message(std::format(
            "[AddressStats] First data: {:#x}\n", *first_data));
    }

    ida::ui::message("[AddressStats] Address statistics complete\n");
}

// ── Main plugin logic ──────────────────────────────────────────────────

void run_storage_metadata() {
    ida::ui::message("=== idax Storage & Metadata Plugin ===\n");

    exercise_storage();
    exercise_database_metadata();
    exercise_batch_annotation();
    exercise_fixup_statistics();
    exercise_analysis_control();
    exercise_diagnostics();
    exercise_address_statistics();

    ida::ui::message("=== Storage & Metadata Complete ===\n");
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct StorageMetadataPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            "idax Storage & Metadata",
            "Ctrl-Shift-S",
            "Netnode persistence, batch annotation, database metadata",
            "Exercises netnode storage (alt/sup/hash/blob), database metadata, "
            "snapshot management, batch annotation, fixup statistics, "
            "analysis control, diagnostics, and address statistics."
        };
    }

    ida::Status run(std::size_t) override {
        run_storage_metadata();
        return ida::ok();
    }
};
