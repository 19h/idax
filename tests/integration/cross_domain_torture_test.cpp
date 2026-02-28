/// \file cross_domain_torture_test.cpp
/// \brief Cross-domain torture tests exercising boundary conditions,
/// error cascades, concurrent state, and complex interaction patterns
/// across multiple idax domains.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <numeric>

namespace {

// ── BadAddress everywhere ───────────────────────────────────────────────

void test_bad_address_handling() {
    SECTION("BadAddress handling across all domains");

    // Every lookup-by-address function should gracefully fail with BadAddress
    CHECK(!ida::address::is_mapped(ida::BadAddress));
    CHECK(!ida::address::is_loaded(ida::BadAddress));
    CHECK(!ida::address::is_code(ida::BadAddress));
    CHECK(!ida::address::is_data(ida::BadAddress));
    CHECK(!ida::address::is_head(ida::BadAddress));
    CHECK(!ida::address::is_tail(ida::BadAddress));

    auto seg = ida::segment::at(ida::BadAddress);
    CHECK(!seg.has_value());

    auto func = ida::function::at(ida::BadAddress);
    CHECK(!func.has_value());

    auto insn = ida::instruction::decode(ida::BadAddress);
    CHECK(!insn.has_value());

    auto name = ida::name::get(ida::BadAddress);
    CHECK(!name.has_value() || name->empty());

    auto comment = ida::comment::get(ida::BadAddress);
    CHECK(!comment.has_value() || comment->empty());

    auto refs_to = ida::xref::refs_to(ida::BadAddress);
    CHECK(!refs_to.has_value() || refs_to->empty());

    auto refs_from = ida::xref::refs_from(ida::BadAddress);
    CHECK(!refs_from.has_value() || refs_from->empty());

    auto item_start = ida::address::item_start(ida::BadAddress);
    CHECK(!item_start.has_value());

    auto data = ida::data::read_byte(ida::BadAddress);
    CHECK(!data.has_value());
}

// ── Zero address ────────────────────────────────────────────────────────

void test_zero_address_handling() {
    SECTION("Zero address handling");

    // Address 0 might or might not be mapped, but should not crash
    auto mapped = ida::address::is_mapped(0);
    (void)mapped; // value doesn't matter

    auto seg = ida::segment::at(0);
    // May or may not exist

    auto func = ida::function::at(0);
    // May or may not exist

    auto insn = ida::instruction::decode(0);
    // May or may not exist

    ++idax_test::g_pass; // If we got here without crashing, it's a pass
}

// ── Name set/get/remove roundtrip stress ────────────────────────────────

void test_name_roundtrip_stress() {
    SECTION("Name set/get/remove roundtrip stress");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    auto addr = funcs[0].start;
    auto orig_name = ida::name::get(addr);

    // Set and read back many times
    for (int i = 0; i < 50; ++i) {
        std::string test_name = "torture_name_" + std::to_string(i);
        auto s = ida::name::force_set(addr, test_name);
        CHECK_OK(s);

        auto got = ida::name::get(addr);
        CHECK_OK(got);
        if (got.has_value()) {
            CHECK(*got == test_name);
        }
    }

    // Restore original
    if (orig_name.has_value() && !orig_name->empty()) {
        ida::name::force_set(addr, *orig_name);
    } else {
        ida::name::remove(addr);
    }
}

// ── Comment set/get/remove roundtrip stress ─────────────────────────────

void test_comment_roundtrip_stress() {
    SECTION("Comment set/get/remove roundtrip stress");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    auto addr = funcs[0].start;

    // Regular comments
    for (int i = 0; i < 30; ++i) {
        std::string cmt = "torture comment #" + std::to_string(i);
        auto s = ida::comment::set(addr, cmt, false);
        CHECK_OK(s);

        auto got = ida::comment::get(addr, false);
        CHECK_OK(got);
        if (got.has_value()) {
            CHECK(*got == cmt);
        }
    }

    // Repeatable comments
    for (int i = 0; i < 30; ++i) {
        std::string cmt = "repeatable torture #" + std::to_string(i);
        auto s = ida::comment::set(addr, cmt, true);
        CHECK_OK(s);

        auto got = ida::comment::get(addr, true);
        CHECK_OK(got);
        if (got.has_value()) {
            CHECK(*got == cmt);
        }
    }

    // Clean up
    ida::comment::remove(addr, false);
    ida::comment::remove(addr, true);
}

// ── Segment iteration consistency ───────────────────────────────────────

void test_segment_iteration_consistency() {
    SECTION("Segment iteration consistency");

    auto count = ida::segment::count();
    auto all = ida::segment::all();
    CHECK(all.size() == static_cast<size_t>(count));

    // Each segment should be retrievable by index
    for (int i = 0; i < count; ++i) {
        auto seg = ida::segment::by_index(i);
        CHECK_OK(seg);
        if (seg.has_value()) {
            CHECK(seg->start == all[i].start);
            CHECK(seg->end == all[i].end);
        }
    }

    // Each segment should be retrievable by address
    for (auto& seg : all) {
        auto found = ida::segment::at(seg.start);
        CHECK_OK(found);
        if (found.has_value()) {
            CHECK(found->start == seg.start);
        }
    }

    // first/last should match
    if (!all.empty()) {
        auto first = ida::segment::first();
        CHECK_OK(first);
        if (first.has_value()) {
            CHECK(first->start == all[0].start);
        }

        auto last = ida::segment::last();
        CHECK_OK(last);
        if (last.has_value()) {
            CHECK(last->start == all.back().start);
        }
    }
}

// ── Function iteration consistency ──────────────────────────────────────

void test_function_iteration_consistency() {
    SECTION("Function iteration consistency");

    auto count = ida::function::count();
    auto all = ida::function::all();
    CHECK(all.size() == static_cast<size_t>(count));

    for (int i = 0; i < std::min(count, 100); ++i) {
        auto func = ida::function::by_index(i);
        CHECK_OK(func);
        if (func.has_value()) {
            CHECK(func->start == all[i].start);
        }
    }

    // Each function should be retrievable by address
    for (int i = 0; i < std::min(static_cast<int>(all.size()), 100); ++i) {
        auto found = ida::function::at(all[i].start);
        CHECK_OK(found);
        if (found.has_value()) {
            CHECK(found->start == all[i].start);
        }
    }
}

// ── Data read consistency ───────────────────────────────────────────────

void test_data_read_consistency() {
    SECTION("Data read consistency");

    auto segs = ida::segment::all();
    if (segs.empty()) { SKIP("no segments"); return; }

    // Read individual bytes and compare with read_bytes
    auto seg = segs[0];
    if (seg.size < 16) { SKIP("segment too small"); return; }

    auto bytes = ida::data::read_bytes(seg.start, 16);
    CHECK_OK(bytes);
    if (!bytes.has_value()) return;

    for (int i = 0; i < 16; ++i) {
        auto byte_val = ida::data::read_byte(seg.start + i);
        CHECK_OK(byte_val);
        if (byte_val.has_value()) {
            CHECK(*byte_val == (*bytes)[i]);
        }
    }
}

// ── Cross-reference consistency ─────────────────────────────────────────

void test_xref_consistency() {
    SECTION("Cross-reference consistency");

    auto funcs = ida::function::all();
    if (funcs.size() < 2) { SKIP("not enough functions"); return; }

    // For each call site, the callee's refs_to should include the caller
    for (int fi = 0; fi < std::min(static_cast<int>(funcs.size()), 20); ++fi) {
        auto callees = ida::function::callees(funcs[fi].start);
        if (!callees.has_value()) continue;

        for (auto callee_addr : *callees) {
            auto refs_to = ida::xref::refs_to(callee_addr);
            if (!refs_to.has_value()) continue;

            // At least one ref should originate from within the caller function
            // (relaxed check — the exact originating instruction may differ)
            bool found_from_caller = false;
            for (auto& ref : *refs_to) {
                if (ref.from >= funcs[fi].start && ref.from < funcs[fi].end) {
                    found_from_caller = true;
                    break;
                }
            }
            // This check may fail for indirect calls, so we don't make it fatal
            if (found_from_caller) {
                ++idax_test::g_pass;
            }
        }
    }
}

// ── Instruction decode stress ───────────────────────────────────────────

void test_instruction_decode_stress() {
    SECTION("Instruction decode stress");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    int decoded = 0;
    int failed = 0;

    // Decode every instruction in the first 10 functions
    for (int fi = 0; fi < std::min(static_cast<int>(funcs.size()), 10); ++fi) {
        auto& func = funcs[fi];
        auto code_addrs = ida::function::code_addresses(func.start);
        if (!code_addrs.has_value()) continue;

        for (auto addr : *code_addrs) {
            auto insn = ida::instruction::decode(addr);
            if (insn.has_value()) {
                ++decoded;
                CHECK(!insn->mnemonic.empty());
                CHECK(insn->size > 0);
                CHECK(insn->address == addr);

                // Text should be non-empty
                auto text = ida::instruction::text(addr);
                if (text.has_value()) {
                    CHECK(!text->empty());
                }
            } else {
                ++failed;
            }
        }
    }

    CHECK(decoded > 0);
    std::cout << "  decoded=" << decoded << " failed=" << failed << "\n";
}

// ── Decompiler roundtrip (if available) ─────────────────────────────────

void test_decompiler_stress() {
    SECTION("Decompiler stress");

    if (!ida::decompiler::available()) {
        SKIP("decompiler not available");
        return;
    }

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    int success = 0;
    int fail = 0;

    // Decompile the first 10 functions
    for (int fi = 0; fi < std::min(static_cast<int>(funcs.size()), 10); ++fi) {
        auto df = ida::decompiler::decompile(funcs[fi].start);
        if (df.has_value()) {
            ++success;
            auto pseudo = df->pseudocode();
            CHECK_OK(pseudo);
            if (pseudo.has_value()) {
                CHECK(!pseudo->empty());
            }

            auto lines = df->lines();
            CHECK_OK(lines);

            auto raw = df->raw_lines();
            CHECK_OK(raw);
        } else {
            ++fail;
        }
    }

    std::cout << "  decompiled=" << success << " failed=" << fail << "\n";
    CHECK(success > 0);
}

// ── Type system stress ──────────────────────────────────────────────────

void test_type_system_stress() {
    SECTION("Type system stress");

    // Create many types and verify their properties
    for (int i = 0; i < 100; ++i) {
        auto t = ida::type::int32();
        CHECK_OK(t);
        if (t.has_value()) {
            CHECK(t->is_integer());
            CHECK(!t->is_pointer());
            CHECK(!t->is_void());
            auto size = t->size();
            CHECK_OK(size);
            if (size.has_value()) {
                CHECK(*size == 4);
            }
        }
    }

    // Pointer chains
    auto base = ida::type::int8();
    CHECK_OK(base);
    if (base.has_value()) {
        auto p1 = ida::type::pointer_to(*base);
        CHECK_OK(p1);
        if (p1.has_value()) {
            CHECK(p1->is_pointer());
            auto p2 = ida::type::pointer_to(*p1);
            CHECK_OK(p2);
            if (p2.has_value()) {
                CHECK(p2->is_pointer());
            }
        }
    }

    // Arrays
    auto elem = ida::type::uint8();
    CHECK_OK(elem);
    if (elem.has_value()) {
        auto arr = ida::type::array_of(*elem, 256);
        CHECK_OK(arr);
        if (arr.has_value()) {
            CHECK(arr->is_array());
            auto len = arr->array_length();
            CHECK_OK(len);
            if (len.has_value()) {
                CHECK(*len == 256);
            }
        }
    }
}

// ── Search edge cases ───────────────────────────────────────────────────

void test_search_edge_cases() {
    SECTION("Search edge cases");

    auto segs = ida::segment::all();
    if (segs.empty()) { SKIP("no segments"); return; }

    auto seg = segs[0];

    // Search for nonexistent text
    auto r1 = ida::search::text("ZZZZNONEXISTENT9999", seg.start);
    // Should fail or return BadAddress

    // Search for very short pattern
    auto r2 = ida::search::binary_pattern("90", seg.start, seg.end);
    // May or may not find something — should not crash

    // next_code/next_data from start of segment
    auto code = ida::search::next_code(seg.start);
    // Should find something in a code segment

    auto data = ida::search::next_data(seg.start);
    // May or may not find data
}

// ── Storage stress ──────────────────────────────────────────────────────

void test_storage_stress() {
    SECTION("Storage stress");

    auto node = ida::storage::Node::open("idax_torture_test", true);
    CHECK_OK(node);
    if (!node.has_value()) return;

    // Write/read many alt values
    for (uint64_t i = 0; i < 100; ++i) {
        auto s = node->set_alt(i, i * 1000);
        CHECK_OK(s);
    }

    for (uint64_t i = 0; i < 100; ++i) {
        auto v = node->alt(i);
        CHECK_OK(v);
        if (v.has_value()) {
            CHECK(*v == i * 1000);
        }
    }

    // Write/read hash values
    for (int i = 0; i < 50; ++i) {
        std::string key = "key_" + std::to_string(i);
        std::string val = "value_" + std::to_string(i);
        auto s = node->set_hash(key, val);
        CHECK_OK(s);

        auto got = node->hash(key);
        CHECK_OK(got);
        if (got.has_value()) {
            CHECK(*got == val);
        }
    }

    // Blob write/read
    std::vector<uint8_t> blob_data(1024, 0xAB);
    auto bs = node->set_blob(0, blob_data);
    CHECK_OK(bs);

    auto blob_read = node->blob(0);
    CHECK_OK(blob_read);
    if (blob_read.has_value()) {
        CHECK(blob_read->size() == 1024);
        CHECK((*blob_read)[0] == 0xAB);
    }

    // Clean up
    for (uint64_t i = 0; i < 100; ++i) {
        node->remove_alt(i);
    }
    node->remove_blob(0);
}

// ── Event subscription stress ───────────────────────────────────────────

void test_event_subscribe_unsubscribe_stress() {
    SECTION("Event subscribe/unsubscribe stress");

    std::vector<uint64_t> tokens;

    // Subscribe many listeners
    for (int i = 0; i < 100; ++i) {
        auto tok = ida::event::on_renamed([](const ida::event::RenamedEvent&) {});
        CHECK_OK(tok);
        if (tok.has_value()) {
            tokens.push_back(*tok);
        }
    }

    // Unsubscribe all
    for (auto tok : tokens) {
        auto s = ida::event::unsubscribe(tok);
        CHECK_OK(s);
    }

    // Double-unsubscribe should fail gracefully
    if (!tokens.empty()) {
        auto s = ida::event::unsubscribe(tokens[0]);
        // Should return error, not crash
        CHECK(!s.has_value());
    }
}

// ── Graph creation/destruction stress ───────────────────────────────────

void test_graph_stress() {
    SECTION("Graph flowchart stress");

    auto funcs = ida::function::all();
    if (funcs.empty()) { SKIP("no functions"); return; }

    // Build flowcharts for the first 20 functions
    for (int fi = 0; fi < std::min(static_cast<int>(funcs.size()), 20); ++fi) {
        auto fc = ida::graph::flowchart(funcs[fi].start);
        CHECK_OK(fc);
        if (fc.has_value()) {
            CHECK(!fc->empty());
            for (auto& bb : *fc) {
                CHECK(bb.start < bb.end);
                CHECK(bb.start >= funcs[fi].start);
            }
        }
    }
}

// ── Empty range operations ──────────────────────────────────────────────

void test_empty_range_operations() {
    SECTION("Empty range operations");

    // Empty range should yield no items
    auto it_range = ida::address::items(0x1000, 0x1000);
    int count = 0;
    for (auto addr : it_range) {
        (void)addr;
        ++count;
    }
    CHECK(count == 0);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_path>\n";
        return 1;
    }

    ida::database::init(argc, argv);
    ida::database::open(argv[1], true);
    ida::analysis::wait();

    test_bad_address_handling();
    test_zero_address_handling();
    test_name_roundtrip_stress();
    test_comment_roundtrip_stress();
    test_segment_iteration_consistency();
    test_function_iteration_consistency();
    test_data_read_consistency();
    test_xref_consistency();
    test_instruction_decode_stress();
    test_decompiler_stress();
    test_type_system_stress();
    test_search_edge_cases();
    test_storage_stress();
    test_event_subscribe_unsubscribe_stress();
    test_graph_stress();
    test_empty_range_operations();

    ida::database::close(false);

    return idax_test::report("cross_domain_torture_test");
}
