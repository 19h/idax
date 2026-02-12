/// \file smoke_test.cpp
/// \brief End-to-end smoke test for idax using idalib.
///
/// Opens a real ELF binary, waits for auto-analysis, and exercises the
/// major idax wrapper namespaces: database, segment, function, address,
/// data, instruction, name, xref, comment, search, analysis, entry, type.

#include <ida/idax.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

// ── Minimal test harness ────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"           \
                      << __LINE__ << ")\n";                               \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                     \
                      << _r.error().message << " (" << __FILE__           \
                      << ":" << __LINE__ << ")\n";                        \
        }                                                                 \
    } while (false)

#define CHECK_VAL(expr, check)                                            \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value() && (check)) {                                  \
            ++g_pass;                                                     \
        } else if (!_r.has_value()) {                                     \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                     \
                      << _r.error().message << " (" << __FILE__           \
                      << ":" << __LINE__ << ")\n";                        \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " value check failed ("           \
                      << __FILE__ << ":" << __LINE__ << ")\n";            \
        }                                                                 \
    } while (false)

// ── Test sections ───────────────────────────────────────────────────────

static void test_database() {
    std::cout << "--- database ---\n";

    auto path = ida::database::input_file_path();
    CHECK_OK(path);
    if (path) std::cout << "  input: " << *path << "\n";

    auto md5 = ida::database::input_md5();
    CHECK_OK(md5);
    if (md5) {
        CHECK(md5->size() == 32);
        std::cout << "  md5: " << *md5 << "\n";
    }

    auto base = ida::database::image_base();
    CHECK_OK(base);
    if (base) std::cout << "  image_base: 0x" << std::hex << *base << std::dec << "\n";

    auto lo = ida::database::min_address();
    auto hi = ida::database::max_address();
    CHECK_OK(lo);
    CHECK_OK(hi);
    if (lo && hi) {
        CHECK(*lo < *hi);
        std::cout << "  range: [0x" << std::hex << *lo << ", 0x" << *hi << ")\n"
                  << std::dec;
    }
}

static void test_segments() {
    std::cout << "--- segments ---\n";

    auto cnt = ida::segment::count();
    CHECK_OK(cnt);
    if (cnt) {
        CHECK(*cnt > 0);
        std::cout << "  count: " << *cnt << "\n";
    }

    // Iterate all segments.
    auto range = ida::segment::all();
    int n = 0;
    for (auto seg : range) {
        ++n;
        std::cout << "  [" << (n - 1) << "] "
                  << seg.name() << "  0x" << std::hex << seg.start()
                  << "-0x" << seg.end() << std::dec
                  << "  bits=" << seg.bitness()
                  << "  rwx=" << seg.permissions().read
                  << seg.permissions().write
                  << seg.permissions().execute
                  << "\n";
    }
    CHECK(n > 0);

    // Lookup by index 0 should succeed.
    auto s0 = ida::segment::by_index(0);
    CHECK_OK(s0);
}

static void test_functions() {
    std::cout << "--- functions ---\n";

    auto cnt = ida::function::count();
    CHECK_OK(cnt);
    if (cnt) {
        CHECK(*cnt > 0);
        std::cout << "  count: " << *cnt << "\n";
    }

    // Iterate functions.
    auto range = ida::function::all();
    int n = 0;
    for (auto fn : range) {
        if (n < 10) {
            std::cout << "  " << fn.name()
                      << "  0x" << std::hex << fn.start()
                      << "-0x" << fn.end() << std::dec
                      << "  bits=" << fn.bitness()
                      << "\n";
        }
        ++n;
    }
    CHECK(n > 0);
    std::cout << "  (showed first " << std::min(n, 10) << " of " << n << ")\n";

    // Look up "main" by name (should exist in this binary).
    auto main_addr = ida::name::resolve("main");
    if (main_addr) {
        auto fn = ida::function::at(*main_addr);
        CHECK_OK(fn);
        if (fn) {
            CHECK(fn->name() == "main" || fn->name().find("main") != std::string::npos);
            std::cout << "  main() at 0x" << std::hex << fn->start() << std::dec
                      << "  size=" << fn->size() << "\n";
        }
    } else {
        std::cout << "  (main not resolved by name, trying scan)\n";
        // Fallback: scan functions for one containing "main".
        for (auto fn : ida::function::all()) {
            if (fn.name().find("main") != std::string::npos) {
                std::cout << "  found: " << fn.name() << " at 0x" << std::hex
                          << fn.start() << std::dec << "\n";
                break;
            }
        }
    }
}

static void test_address_predicates() {
    std::cout << "--- address predicates ---\n";

    auto lo = ida::database::min_address();
    if (!lo) return;

    // The min address should be mapped.
    CHECK(ida::address::is_mapped(*lo));

    // Find the first code address.
    for (auto ea : ida::address::items(*lo, *lo + 0x10000)) {
        if (ida::address::is_code(ea)) {
            std::cout << "  first code at 0x" << std::hex << ea << std::dec << "\n";
            CHECK(!ida::address::is_tail(ea));
            CHECK(ida::address::is_head(ea));
            break;
        }
    }
}

static void test_data_read() {
    std::cout << "--- data read ---\n";

    auto lo = ida::database::min_address();
    if (!lo) return;

    // Read the ELF magic bytes (0x7f 'E' 'L' 'F').
    auto bytes = ida::data::read_bytes(*lo, 4);
    CHECK_OK(bytes);
    if (bytes) {
        CHECK(bytes->size() == 4);
        if (bytes->size() >= 4) {
            CHECK((*bytes)[0] == 0x7f);
            CHECK((*bytes)[1] == 'E');
            CHECK((*bytes)[2] == 'L');
            CHECK((*bytes)[3] == 'F');
            std::cout << "  ELF magic verified at 0x" << std::hex << *lo
                      << std::dec << "\n";
        }
    }

    // Read single byte.
    auto b = ida::data::read_byte(*lo);
    CHECK_OK(b);
    if (b) CHECK(*b == 0x7f);
}

static void test_instructions() {
    std::cout << "--- instructions ---\n";

    // Find a function and decode its first instruction.
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto insn = ida::instruction::decode(f0->start());
    CHECK_OK(insn);
    if (insn) {
        std::cout << "  at 0x" << std::hex << insn->address() << std::dec
                  << ": " << insn->mnemonic()
                  << "  size=" << insn->size()
                  << "  ops=" << insn->operand_count()
                  << "\n";
        CHECK(insn->size() > 0);
        CHECK(!insn->mnemonic().empty());
    }

    // Get rendered disassembly text.
    auto txt = ida::instruction::text(f0->start());
    CHECK_OK(txt);
    if (txt) {
        CHECK(!txt->empty());
        std::cout << "  text: " << *txt << "\n";
    }
}

static void test_names() {
    std::cout << "--- names ---\n";

    // The first function should have a name.
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto nm = ida::name::get(f0->start());
    CHECK_OK(nm);
    if (nm) {
        CHECK(!nm->empty());
        std::cout << "  name at first func: " << *nm << "\n";
    }
}

static void test_xrefs() {
    std::cout << "--- xrefs ---\n";

    // Find a function and check for xrefs to it.
    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto refs = ida::xref::refs_to(*main_addr);
    CHECK_OK(refs);
    if (refs) {
        int count = 0;
        for (auto& ref : *refs) {
            if (count < 5) {
                std::cout << "  ref_to main from 0x" << std::hex << ref.from
                          << std::dec << " code=" << ref.is_code << "\n";
            }
            ++count;
        }
        std::cout << "  total refs to main: " << count << "\n";
    }
}

static void test_comments() {
    std::cout << "--- comments ---\n";

    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    // Set a comment, read it back, then remove it.
    auto status = ida::comment::set(f0->start(), "idax test comment");
    CHECK_OK(status);

    auto cmt = ida::comment::get(f0->start());
    CHECK_OK(cmt);
    if (cmt) {
        CHECK(*cmt == "idax test comment");
        std::cout << "  comment: " << *cmt << "\n";
    }

    auto rm = ida::comment::remove(f0->start());
    CHECK_OK(rm);
}

static void test_entry_points() {
    std::cout << "--- entries ---\n";

    auto cnt = ida::entry::count();
    CHECK_OK(cnt);
    if (cnt) {
        std::cout << "  count: " << *cnt << "\n";
        if (*cnt > 0) {
            auto e = ida::entry::by_index(0);
            CHECK_OK(e);
            if (e) {
                std::cout << "  entry[0]: " << e->name << " at 0x"
                          << std::hex << e->address << std::dec << "\n";
            }
        }
    }
}

static void test_type_basics() {
    std::cout << "--- type basics ---\n";

    auto ti = ida::type::TypeInfo::int32();
    CHECK(ti.is_integer());
    CHECK(!ti.is_pointer());

    auto pi = ida::type::TypeInfo::pointer_to(ti);
    CHECK(pi.is_pointer());

    auto arr = ida::type::TypeInfo::array_of(ti, 10);
    CHECK(arr.is_array());

    auto sz = ti.size();
    CHECK_OK(sz);
    if (sz) {
        CHECK(*sz == 4);
        std::cout << "  int32 size: " << *sz << "\n";
    }

    auto type_str = ti.to_string();
    CHECK_OK(type_str);
    if (type_str) {
        std::cout << "  int32 repr: " << *type_str << "\n";
    }
}

// ── Main ────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    // 1. Initialize idalib.
    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    // 2. Open the binary with auto-analysis.
    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    // 3. Wait for auto-analysis.
    ida::analysis::wait();

    // 4. Run tests.
    test_database();
    test_segments();
    test_functions();
    test_address_predicates();
    test_data_read();
    test_instructions();
    test_names();
    test_xrefs();
    test_comments();
    test_entry_points();
    test_type_basics();

    // 5. Report.
    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";

    // 6. Close without saving.
    ida::database::close(false);

    return g_fail > 0 ? 1 : 0;
}
