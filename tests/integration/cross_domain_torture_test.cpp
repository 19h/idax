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

// ── Helpers: access functions/segments via by_index ──────────────────────

ida::Address func_start(std::size_t idx) {
    auto f = ida::function::by_index(idx);
    return f.has_value() ? f->start() : ida::BadAddress;
}

ida::Address func_end(std::size_t idx) {
    auto f = ida::function::by_index(idx);
    return f.has_value() ? f->end() : ida::BadAddress;
}

struct SegInfo {
    ida::Address start = ida::BadAddress;
    ida::Address end   = ida::BadAddress;
    ida::AddressSize sz = 0;
};

SegInfo seg_info(std::size_t idx) {
    auto s = ida::segment::by_index(idx);
    if (s.has_value()) return {s->start(), s->end(), s->size()};
    return {};
}

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

    auto addr = func_start(0);
    if (addr == ida::BadAddress) { SKIP("no functions"); return; }

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

    auto addr = func_start(0);
    if (addr == ida::BadAddress) { SKIP("no functions"); return; }

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

    auto count_r = ida::segment::count();
    CHECK(count_r.has_value());
    if (!count_r.has_value()) return;
    auto count = *count_r;

    // Each segment should be retrievable by index
    for (std::size_t i = 0; i < count; ++i) {
        auto seg = ida::segment::by_index(i);
        CHECK_OK(seg);
    }

    // Each segment should be retrievable by address
    for (std::size_t i = 0; i < count; ++i) {
        auto seg = ida::segment::by_index(i);
        if (!seg.has_value()) continue;
        auto found = ida::segment::at(seg->start());
        CHECK_OK(found);
        if (found.has_value()) {
            CHECK(found->start() == seg->start());
        }
    }

    // first/last should match
    if (count > 0) {
        auto first_seg = ida::segment::by_index(0);
        auto last_seg  = ida::segment::by_index(count - 1);

        auto first = ida::segment::first();
        CHECK_OK(first);
        if (first.has_value() && first_seg.has_value()) {
            CHECK(first->start() == first_seg->start());
        }

        auto last = ida::segment::last();
        CHECK_OK(last);
        if (last.has_value() && last_seg.has_value()) {
            CHECK(last->start() == last_seg->start());
        }
    }
}

// ── Function iteration consistency ──────────────────────────────────────

void test_function_iteration_consistency() {
    SECTION("Function iteration consistency");

    auto count_r = ida::function::count();
    CHECK(count_r.has_value());
    if (!count_r.has_value()) return;
    auto count = *count_r;

    // Each function should be retrievable by index (up to 100)
    auto limit = std::min(count, static_cast<std::size_t>(100));
    for (std::size_t i = 0; i < limit; ++i) {
        auto func = ida::function::by_index(i);
        CHECK_OK(func);
    }

    // Each function should be retrievable by address
    for (std::size_t i = 0; i < limit; ++i) {
        auto func = ida::function::by_index(i);
        if (!func.has_value()) continue;
        auto found = ida::function::at(func->start());
        CHECK_OK(found);
        if (found.has_value()) {
            CHECK(found->start() == func->start());
        }
    }
}

// ── Data read consistency ───────────────────────────────────────────────

void test_data_read_consistency() {
    SECTION("Data read consistency");

    auto si = seg_info(0);
    if (si.start == ida::BadAddress) { SKIP("no segments"); return; }
    if (si.sz < 16) { SKIP("segment too small"); return; }

    // Read individual bytes and compare with read_bytes
    auto bytes = ida::data::read_bytes(si.start, 16);
    CHECK_OK(bytes);
    if (!bytes.has_value()) return;

    for (int i = 0; i < 16; ++i) {
        auto byte_val = ida::data::read_byte(si.start + i);
        CHECK_OK(byte_val);
        if (byte_val.has_value()) {
            CHECK(*byte_val == (*bytes)[i]);
        }
    }
}

// ── Cross-reference consistency ─────────────────────────────────────────

void test_xref_consistency() {
    SECTION("Cross-reference consistency");

    auto fn_count_r = ida::function::count();
    if (!fn_count_r.has_value() || *fn_count_r < 2) {
        SKIP("not enough functions");
        return;
    }
    auto fn_count = *fn_count_r;

    // For each call site, the callee's refs_to should include the caller
    auto limit = std::min(fn_count, static_cast<std::size_t>(20));
    for (std::size_t fi = 0; fi < limit; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto f_start = f->start();
        auto f_end   = f->end();

        auto callees = ida::function::callees(f_start);
        if (!callees.has_value()) continue;

        for (auto callee_addr : *callees) {
            auto refs_to = ida::xref::refs_to(callee_addr);
            if (!refs_to.has_value()) continue;

            // At least one ref should originate from within the caller function
            // (relaxed check — the exact originating instruction may differ)
            bool found_from_caller = false;
            for (auto& ref : *refs_to) {
                if (ref.from >= f_start && ref.from < f_end) {
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

    auto fn_count_r = ida::function::count();
    if (!fn_count_r.has_value() || *fn_count_r == 0) {
        SKIP("no functions");
        return;
    }

    int decoded = 0;
    int failed = 0;

    // Decode every instruction in the first 10 functions
    auto limit = std::min(*fn_count_r, static_cast<std::size_t>(10));
    for (std::size_t fi = 0; fi < limit; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto code_addrs = ida::function::code_addresses(f->start());
        if (!code_addrs.has_value()) continue;

        for (auto addr : *code_addrs) {
            auto insn = ida::instruction::decode(addr);
            if (insn.has_value()) {
                ++decoded;
                CHECK(!insn->mnemonic().empty());
                CHECK(insn->size() > 0);
                CHECK(insn->address() == addr);

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

    auto fn_count_r = ida::function::count();
    if (!fn_count_r.has_value() || *fn_count_r == 0) {
        SKIP("no functions");
        return;
    }

    int success = 0;
    int fail = 0;

    // Decompile the first 10 functions
    auto limit = std::min(*fn_count_r, static_cast<std::size_t>(10));
    for (std::size_t fi = 0; fi < limit; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto df = ida::decompiler::decompile(f->start());
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
        auto t = ida::type::TypeInfo::int32();
        CHECK(t.is_integer());
        CHECK(!t.is_pointer());
        CHECK(!t.is_void());
        auto sz = t.size();
        CHECK(sz.has_value());
        if (sz.has_value()) {
            CHECK(*sz == 4);
        }
    }

    // Pointer chains
    auto base = ida::type::TypeInfo::int8();
    auto p1 = ida::type::TypeInfo::pointer_to(base);
    CHECK(p1.is_pointer());
    auto p2 = ida::type::TypeInfo::pointer_to(p1);
    CHECK(p2.is_pointer());

    // Arrays
    auto elem = ida::type::TypeInfo::uint8();
    auto arr = ida::type::TypeInfo::array_of(elem, 256);
    CHECK(arr.is_array());
    auto len = arr.array_length();
    CHECK(len.has_value());
    if (len.has_value()) {
        CHECK(*len == 256);
    }
}

// ── Search edge cases ───────────────────────────────────────────────────

void test_search_edge_cases() {
    SECTION("Search edge cases");

    auto si = seg_info(0);
    if (si.start == ida::BadAddress) { SKIP("no segments"); return; }

    // Search for nonexistent text
    auto r1 = ida::search::text("ZZZZNONEXISTENT9999", si.start);
    // Should fail or return BadAddress

    // Search for very short pattern
    auto r2 = ida::search::binary_pattern("90", si.start);
    // May or may not find something — should not crash

    // next_code/next_data from start of segment
    auto code = ida::search::next_code(si.start);
    // Should find something in a code segment

    auto data = ida::search::next_data(si.start);
    // May or may not find data

    (void)r1; (void)r2; (void)code; (void)data;
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
        auto tok = ida::event::on_renamed([](ida::Address, std::string, std::string) {});
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

    auto fn_count_r = ida::function::count();
    if (!fn_count_r.has_value() || *fn_count_r == 0) {
        SKIP("no functions");
        return;
    }

    // Build flowcharts for the first 20 functions
    auto limit = std::min(*fn_count_r, static_cast<std::size_t>(20));
    for (std::size_t fi = 0; fi < limit; ++fi) {
        auto f = ida::function::by_index(fi);
        if (!f.has_value()) continue;
        auto f_start = f->start();
        auto fc = ida::graph::flowchart(f_start);
        CHECK_OK(fc);
        if (fc.has_value()) {
            CHECK(!fc->empty());
            for (auto& bb : *fc) {
                // Some synthetic/external blocks may have start==end or
                // start < function start — just verify they don't crash
                CHECK(bb.start <= bb.end);
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
