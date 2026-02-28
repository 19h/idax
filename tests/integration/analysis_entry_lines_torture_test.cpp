/// \file analysis_entry_lines_torture_test.cpp
/// \brief Dedicated integration tests for under-tested domains:
///   - ida::analysis (scheduling, wait, enable/disable, cancel, revert)
///   - ida::entry (entry point CRUD, forwarders, ordinals)
///   - ida::lines (color tag creation, stripping, advance, addr tags)
///   - ida::database metadata (all metadata queries, snapshots)
///
/// These domains previously had only smoke-test level coverage.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <string>
#include <vector>

namespace {

// ── ida::analysis ───────────────────────────────────────────────────────

void test_analysis_enable_disable() {
    SECTION("analysis: enable/disable roundtrip");

    bool was_enabled = ida::analysis::is_enabled();

    // Disable
    ida::analysis::set_enabled(false);
    CHECK(ida::analysis::is_enabled() == false);

    // Re-enable
    ida::analysis::set_enabled(true);
    CHECK(ida::analysis::is_enabled() == true);

    // Restore original state
    ida::analysis::set_enabled(was_enabled);
}

void test_analysis_idle() {
    SECTION("analysis: idle check");

    // After wait(), the analyzer should be idle
    ida::analysis::wait();
    CHECK(ida::analysis::is_idle());
}

void test_analysis_wait_idempotent() {
    SECTION("analysis: wait idempotent");

    // Calling wait() multiple times should be safe
    ida::analysis::wait();
    ida::analysis::wait();
    ida::analysis::wait();
    CHECK(ida::analysis::is_idle());
}

void test_analysis_schedule() {
    SECTION("analysis: scheduling operations");

    // Get a known code address
    auto segs = ida::segment::all();
    if (segs.empty()) { SKIP("no segments"); return; }

    auto seg = segs[0];
    ida::Address addr = seg.start;

    // Schedule various analysis types — these should not crash
    auto s1 = ida::analysis::schedule(addr);
    CHECK_OK(s1);

    auto s2 = ida::analysis::schedule_code(addr);
    CHECK_OK(s2);

    auto s3 = ida::analysis::schedule_range(seg.start, seg.end);
    CHECK_OK(s3);

    // Wait for analysis to complete
    ida::analysis::wait();
    CHECK(ida::analysis::is_idle());
}

void test_analysis_cancel_revert() {
    SECTION("analysis: cancel and revert");

    auto segs = ida::segment::all();
    if (segs.empty()) { SKIP("no segments"); return; }

    auto seg = segs[0];

    // Cancel should not crash even on already-analyzed ranges
    auto s1 = ida::analysis::cancel(seg.start, seg.end);
    CHECK_OK(s1);

    // Revert decisions should not crash
    auto s2 = ida::analysis::revert_decisions(seg.start, seg.end);
    CHECK_OK(s2);

    // Re-analyze to restore state
    ida::analysis::wait();
}

void test_analysis_schedule_function() {
    SECTION("analysis: schedule function reanalysis");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    auto func = funcs[0];
    auto s = ida::analysis::schedule_function(func.start);
    CHECK_OK(s);

    ida::analysis::wait();
    CHECK(ida::analysis::is_idle());
}

void test_analysis_schedule_reanalysis() {
    SECTION("analysis: schedule reanalysis");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    auto func = funcs[0];
    auto s1 = ida::analysis::schedule_reanalysis(func.start);
    CHECK_OK(s1);

    auto s2 = ida::analysis::schedule_reanalysis_range(func.start, func.end);
    CHECK_OK(s2);

    ida::analysis::wait();
}

// ── ida::entry ──────────────────────────────────────────────────────────

void test_entry_count() {
    SECTION("entry: count");

    auto count = ida::entry::count();
    CHECK(count >= 0); // May be 0 for stripped binaries

    // If entries exist, by_index should work
    if (count > 0) {
        auto e = ida::entry::by_index(0);
        CHECK_OK(e);
    }
}

void test_entry_by_index_all() {
    SECTION("entry: iterate all by index");

    auto count = ida::entry::count();
    for (int i = 0; i < count; ++i) {
        auto e = ida::entry::by_index(i);
        CHECK_OK(e);
        if (e.has_value()) {
            CHECK(e->address != ida::BadAddress);
        }
    }
}

void test_entry_by_index_out_of_range() {
    SECTION("entry: by_index out of range");

    auto count = ida::entry::count();
    auto e = ida::entry::by_index(count + 100);
    CHECK(!e.has_value());
}

void test_entry_by_ordinal() {
    SECTION("entry: by_ordinal");

    auto count = ida::entry::count();
    if (count == 0) { SKIP("no entries"); return; }

    // Get the first entry to know its ordinal
    auto first = ida::entry::by_index(0);
    CHECK_OK(first);
    if (!first.has_value()) return;

    auto e = ida::entry::by_ordinal(first->ordinal);
    CHECK_OK(e);
    if (e.has_value()) {
        CHECK(e->address == first->address);
    }
}

void test_entry_forwarder() {
    SECTION("entry: forwarder operations");

    auto count = ida::entry::count();
    if (count == 0) { SKIP("no entries"); return; }

    auto first = ida::entry::by_index(0);
    CHECK_OK(first);
    if (!first.has_value()) return;

    // Get forwarder (likely empty for most entries)
    auto fwd = ida::entry::forwarder(first->ordinal);
    CHECK_OK(fwd);
    // Value may be empty string — that's fine
}

void test_entry_add_rename_remove() {
    SECTION("entry: add/rename lifecycle");

    // Try to add an entry at the start of a known function
    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions for entry test"); return; }

    // Use a high ordinal unlikely to conflict
    uint64_t test_ordinal = 0xFFFE;
    auto func = funcs[0];

    auto add_r = ida::entry::add(test_ordinal, func.start, "test_entry_torture", true);
    if (!add_r.has_value()) {
        // May fail if ordinal already in use — that's ok, not a test failure
        SKIP("entry::add failed (may be ordinal conflict)");
        return;
    }

    // Rename
    auto rename_r = ida::entry::rename(test_ordinal, "test_entry_renamed");
    CHECK_OK(rename_r);

    // Read back
    auto e = ida::entry::by_ordinal(test_ordinal);
    CHECK_OK(e);
    if (e.has_value()) {
        CHECK(e->name == "test_entry_renamed");
    }
}

// ── ida::lines ──────────────────────────────────────────────────────────

void test_lines_colstr() {
    SECTION("lines: colstr tag creation");

    auto tagged = ida::lines::colstr("hello", ida::lines::Color::Keyword);
    CHECK(!tagged.empty());
    CHECK(tagged.size() > 5); // Should have at least ON + color + text + OFF + color

    // The plain text should be recoverable
    auto plain = ida::lines::tag_remove(tagged);
    CHECK(plain == "hello");
}

void test_lines_colstr_all_colors() {
    SECTION("lines: colstr with all color variants");

    std::vector<ida::lines::Color> colors = {
        ida::lines::Color::Default,
        ida::lines::Color::RegularComment,
        ida::lines::Color::RepeatableComment,
        ida::lines::Color::AutoComment,
        ida::lines::Color::Instruction,
        ida::lines::Color::DataName,
        ida::lines::Color::RegularDataName,
        ida::lines::Color::DemangledName,
        ida::lines::Color::Symbol,
        ida::lines::Color::CharLiteral,
        ida::lines::Color::String,
        ida::lines::Color::Number,
        ida::lines::Color::Void,
        ida::lines::Color::CodeReference,
        ida::lines::Color::DataReference,
        ida::lines::Color::CodeRefTail,
        ida::lines::Color::DataRefTail,
        ida::lines::Color::Error,
        ida::lines::Color::Prefix,
        ida::lines::Color::BinaryPrefix,
        ida::lines::Color::Extra,
        ida::lines::Color::AltOperand,
        ida::lines::Color::HiddenName,
        ida::lines::Color::LibraryName,
        ida::lines::Color::LocalName,
        ida::lines::Color::DummyCodeName,
        ida::lines::Color::AsmDirective,
        ida::lines::Color::Macro,
        ida::lines::Color::DataString,
        ida::lines::Color::DataChar,
        ida::lines::Color::DataNumber,
        ida::lines::Color::Keyword,
        ida::lines::Color::Register,
        ida::lines::Color::ImportedName,
        ida::lines::Color::SegmentName,
        ida::lines::Color::UnknownName,
        ida::lines::Color::CodeName,
        ida::lines::Color::UserName,
        ida::lines::Color::Collapsed,
    };

    for (auto color : colors) {
        auto tagged = ida::lines::colstr("test", color);
        CHECK(!tagged.empty());
        auto plain = ida::lines::tag_remove(tagged);
        CHECK(plain == "test");
    }
}

void test_lines_tag_remove_plain() {
    SECTION("lines: tag_remove on plain text");

    auto plain = ida::lines::tag_remove("no tags here");
    CHECK(plain == "no tags here");

    auto empty = ida::lines::tag_remove("");
    CHECK(empty.empty());
}

void test_lines_tag_strlen() {
    SECTION("lines: tag_strlen");

    auto tagged = ida::lines::colstr("hello", ida::lines::Color::Keyword);
    auto len = ida::lines::tag_strlen(tagged);
    CHECK(len == 5); // "hello" is 5 visible characters

    // Plain text
    auto plain_len = ida::lines::tag_strlen("plain");
    CHECK(plain_len == 5);

    // Empty
    auto empty_len = ida::lines::tag_strlen("");
    CHECK(empty_len == 0);
}

void test_lines_tag_advance() {
    SECTION("lines: tag_advance");

    auto tagged = ida::lines::colstr("AB", ida::lines::Color::Number);

    // At position 0, should skip past the color ON tag
    int skip0 = ida::lines::tag_advance(tagged, 0);
    CHECK(skip0 >= 1);

    // On plain text, advance is always 1
    int skip_plain = ida::lines::tag_advance("abc", 0);
    CHECK(skip_plain == 1);
}

void test_lines_addr_tag_roundtrip() {
    SECTION("lines: make/decode addr tag roundtrip");

    for (int idx = 0; idx < 100; ++idx) {
        auto tag = ida::lines::make_addr_tag(idx);
        CHECK(!tag.empty());

        auto decoded = ida::lines::decode_addr_tag(tag, 0);
        CHECK(decoded == idx);
    }
}

void test_lines_nested_tags() {
    SECTION("lines: nested color tags");

    auto inner = ida::lines::colstr("inner", ida::lines::Color::Number);
    auto outer = ida::lines::colstr(inner + " outer", ida::lines::Color::Keyword);

    auto plain = ida::lines::tag_remove(outer);
    CHECK_CONTAINS(plain, "inner");
    CHECK_CONTAINS(plain, "outer");
}

void test_lines_tag_control_constants() {
    SECTION("lines: tag control byte constants");

    CHECK(ida::lines::kColorOn == '\x01');
    CHECK(ida::lines::kColorOff == '\x02');
    CHECK(ida::lines::kColorEsc == '\x03');
    CHECK(ida::lines::kColorInv == '\x04');
    CHECK(ida::lines::kColorAddr == 0x28);
    CHECK(ida::lines::kColorAddrSize == 16);
}

// ── ida::database metadata ──────────────────────────────────────────────

void test_database_metadata() {
    SECTION("database: metadata queries");

    // Input file path
    auto path = ida::database::input_file_path();
    CHECK_OK(path);
    if (path.has_value()) {
        CHECK(!path->empty());
    }

    // File type
    auto ftype = ida::database::file_type_name();
    CHECK_OK(ftype);

    // MD5
    auto md5 = ida::database::input_md5();
    CHECK_OK(md5);
    if (md5.has_value()) {
        CHECK(md5->size() == 32); // hex string
    }

    // Compiler info
    auto cinfo = ida::database::compiler_info();
    CHECK_OK(cinfo);

    // Image base
    auto base = ida::database::image_base();
    CHECK_OK(base);

    // Processor
    auto pid = ida::database::processor_id();
    CHECK_OK(pid);

    auto pname = ida::database::processor_name();
    CHECK_OK(pname);
    if (pname.has_value()) {
        CHECK(!pname->empty());
    }

    // Bitness
    auto bits = ida::database::address_bitness();
    CHECK_OK(bits);
    if (bits.has_value()) {
        CHECK(*bits == 16 || *bits == 32 || *bits == 64);
    }

    // Endianness
    auto big = ida::database::is_big_endian();
    CHECK_OK(big);

    // ABI
    auto abi = ida::database::abi_name();
    CHECK_OK(abi);
}

void test_database_address_bounds() {
    SECTION("database: address bounds");

    auto min_addr = ida::database::min_address();
    CHECK_OK(min_addr);

    auto max_addr = ida::database::max_address();
    CHECK_OK(max_addr);

    if (min_addr.has_value() && max_addr.has_value()) {
        CHECK(*min_addr < *max_addr);
    }

    auto bounds = ida::database::address_bounds();
    CHECK_OK(bounds);
    if (bounds.has_value()) {
        CHECK(bounds->start < bounds->end);
    }

    auto span = ida::database::address_span();
    CHECK_OK(span);
    if (span.has_value()) {
        CHECK(*span > 0);
    }
}

void test_database_imports() {
    SECTION("database: import modules");

    auto imports = ida::database::import_modules();
    CHECK_OK(imports);
    if (imports.has_value()) {
        for (auto& mod : *imports) {
            // Each module should have a name (may be empty for some formats)
            // Each symbol should have an address
            for (auto& sym : mod.symbols) {
                CHECK(sym.address != ida::BadAddress || !sym.name.empty());
            }
        }
    }
}

void test_database_snapshots() {
    SECTION("database: snapshot queries");

    auto is_snap = ida::database::is_snapshot_database();
    CHECK_OK(is_snap);

    auto snaps = ida::database::snapshots();
    CHECK_OK(snaps);
    // Snapshot list may be empty — that's fine
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_path>\n";
        return 1;
    }

    // Initialize and open database
    ida::database::init(argc, argv);
    ida::database::open(argv[1], true);
    ida::analysis::wait();

    // analysis tests
    test_analysis_enable_disable();
    test_analysis_idle();
    test_analysis_wait_idempotent();
    test_analysis_schedule();
    test_analysis_cancel_revert();
    test_analysis_schedule_function();
    test_analysis_schedule_reanalysis();

    // entry tests
    test_entry_count();
    test_entry_by_index_all();
    test_entry_by_index_out_of_range();
    test_entry_by_ordinal();
    test_entry_forwarder();
    test_entry_add_rename_remove();

    // lines tests
    test_lines_colstr();
    test_lines_colstr_all_colors();
    test_lines_tag_remove_plain();
    test_lines_tag_strlen();
    test_lines_tag_advance();
    test_lines_addr_tag_roundtrip();
    test_lines_nested_tags();
    test_lines_tag_control_constants();

    // database metadata tests
    test_database_metadata();
    test_database_address_bounds();
    test_database_imports();
    test_database_snapshots();

    ida::database::close(false);

    return idax_test::report("analysis_entry_lines_torture_test");
}
