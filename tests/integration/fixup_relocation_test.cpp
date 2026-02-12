/// \file fixup_relocation_test.cpp
/// \brief Integration checks for ida::fixup set/get roundtrip, traversal, and error paths.

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                             \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                   \
                      << _r.error().message << " (" << __FILE__         \
                      << ":" << __LINE__ << ")\n";                     \
        }                                                                 \
    } while (false)

#define CHECK_ERR(expr, cat)                                              \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (!_r.has_value() && _r.error().category == (cat)) {           \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            if (_r.has_value())                                           \
                std::cerr << "FAIL: " #expr " => expected error but got value" \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            else                                                          \
                std::cerr << "FAIL: " #expr " => wrong error category"   \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        }                                                                 \
    } while (false)

// ---------------------------------------------------------------------------
// Test: set/get roundtrip
// ---------------------------------------------------------------------------
void test_set_get_roundtrip() {
    std::cout << "--- fixup set/get roundtrip ---\n";

    // Pick an address in the database where we can safely set a fixup.
    // Use min_address + some offset to avoid clobbering important metadata.
    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    // Use an address in the middle of the text segment
    ida::Address test_ea = *lo + 0x100;

    // Make sure there's no existing fixup there (clean up from prior runs)
    ida::fixup::remove(test_ea);
    CHECK(!ida::fixup::exists(test_ea));

    // Set a fixup
    ida::fixup::Descriptor desc;
    desc.source = test_ea;
    desc.type = ida::fixup::Type::Off32;
    desc.selector = 1;
    desc.offset = *lo;
    desc.displacement = 42;

    CHECK_OK(ida::fixup::set(test_ea, desc));

    // Verify it exists
    CHECK(ida::fixup::exists(test_ea));

    // Retrieve and compare
    auto retrieved = ida::fixup::at(test_ea);
    CHECK_OK(retrieved);
    if (retrieved) {
        CHECK(retrieved->source == test_ea);
        CHECK(retrieved->type == ida::fixup::Type::Off32);
        CHECK(retrieved->selector == 1);
        CHECK(retrieved->offset == *lo);
        CHECK(retrieved->displacement == 42);
    }

    // Clean up
    CHECK_OK(ida::fixup::remove(test_ea));
    CHECK(!ida::fixup::exists(test_ea));
}

// ---------------------------------------------------------------------------
// Test: different fixup types
// ---------------------------------------------------------------------------
void test_fixup_types() {
    std::cout << "--- fixup type variants ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    struct TypeTest {
        ida::fixup::Type type;
        const char* name;
    };

    TypeTest types[] = {
        {ida::fixup::Type::Off8,  "Off8"},
        {ida::fixup::Type::Off16, "Off16"},
        {ida::fixup::Type::Off32, "Off32"},
        {ida::fixup::Type::Off64, "Off64"},
        {ida::fixup::Type::Hi8,   "Hi8"},
        {ida::fixup::Type::Low8,  "Low8"},
    };

    ida::Address base_ea = *lo + 0x200;

    for (std::size_t i = 0; i < std::size(types); ++i) {
        ida::Address ea = base_ea + i * 0x10;

        // Ensure clean
        ida::fixup::remove(ea);

        ida::fixup::Descriptor desc;
        desc.source = ea;
        desc.type = types[i].type;
        desc.offset = *lo;

        auto set_res = ida::fixup::set(ea, desc);
        CHECK_OK(set_res);

        auto got = ida::fixup::at(ea);
        CHECK_OK(got);
        if (got) {
            CHECK(got->type == types[i].type);
        }

        // Clean up
        ida::fixup::remove(ea);
    }
}

// ---------------------------------------------------------------------------
// Test: contains check
// ---------------------------------------------------------------------------
void test_contains() {
    std::cout << "--- fixup contains check ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    ida::Address test_ea = *lo + 0x300;
    ida::fixup::remove(test_ea);

    // Before setting: should not contain
    CHECK(!ida::fixup::contains(test_ea, 1));

    // Set fixup
    ida::fixup::Descriptor desc;
    desc.source = test_ea;
    desc.type = ida::fixup::Type::Off32;
    desc.offset = *lo;
    CHECK_OK(ida::fixup::set(test_ea, desc));

    // Now should contain
    CHECK(ida::fixup::contains(test_ea, 1));

    // Wider range should also contain
    CHECK(ida::fixup::contains(test_ea - 0x10, 0x20));

    // Clean up
    ida::fixup::remove(test_ea);
}

// ---------------------------------------------------------------------------
// Test: traversal (first/next/prev)
// ---------------------------------------------------------------------------
void test_traversal() {
    std::cout << "--- fixup traversal ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    // Set two fixups at known addresses
    ida::Address ea1 = *lo + 0x400;
    ida::Address ea2 = *lo + 0x410;

    ida::fixup::remove(ea1);
    ida::fixup::remove(ea2);

    ida::fixup::Descriptor d1;
    d1.source = ea1;
    d1.type = ida::fixup::Type::Off32;
    d1.offset = *lo;
    CHECK_OK(ida::fixup::set(ea1, d1));

    ida::fixup::Descriptor d2;
    d2.source = ea2;
    d2.type = ida::fixup::Type::Off64;
    d2.offset = *lo;
    CHECK_OK(ida::fixup::set(ea2, d2));

    // first() should return something (might be our ea1 or earlier)
    auto first = ida::fixup::first();
    CHECK_OK(first);
    if (first) {
        CHECK(*first <= ea1);  // first fixup is at or before ea1
    }

    // next(ea1) should reach ea2 eventually
    auto after_ea1 = ida::fixup::next(ea1);
    CHECK_OK(after_ea1);
    if (after_ea1) {
        CHECK(*after_ea1 >= ea2 || *after_ea1 > ea1);  // monotonically advancing
    }

    // prev(ea2) should be at or before ea1
    auto before_ea2 = ida::fixup::prev(ea2);
    CHECK_OK(before_ea2);
    if (before_ea2) {
        CHECK(*before_ea2 <= ea1);
    }

    // Clean up
    ida::fixup::remove(ea1);
    ida::fixup::remove(ea2);
}

// ---------------------------------------------------------------------------
// Test: FixupRange iteration
// ---------------------------------------------------------------------------
void test_range_iteration() {
    std::cout << "--- fixup range iteration ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo) return;

    // Set a couple of fixups
    ida::Address ea1 = *lo + 0x500;
    ida::Address ea2 = *lo + 0x510;

    ida::fixup::remove(ea1);
    ida::fixup::remove(ea2);

    ida::fixup::Descriptor d;
    d.type = ida::fixup::Type::Off32;
    d.offset = *lo;

    d.source = ea1;
    CHECK_OK(ida::fixup::set(ea1, d));
    d.source = ea2;
    CHECK_OK(ida::fixup::set(ea2, d));

    // Iterate all fixups and count
    std::size_t count = 0;
    bool found_ea1 = false;
    bool found_ea2 = false;

    for (auto desc : ida::fixup::all()) {
        ++count;
        if (desc.source == ea1) found_ea1 = true;
        if (desc.source == ea2) found_ea2 = true;
        // Safety: don't iterate forever
        if (count > 100000) break;
    }

    CHECK(count >= 2);
    CHECK(found_ea1);
    CHECK(found_ea2);
    std::cout << "  total fixups iterated: " << count << "\n";

    // Clean up
    ida::fixup::remove(ea1);
    ida::fixup::remove(ea2);
}

// ---------------------------------------------------------------------------
// Test: error paths
// ---------------------------------------------------------------------------
void test_error_paths() {
    std::cout << "--- fixup error paths ---\n";

    // at() on address with no fixup
    CHECK_ERR(ida::fixup::at(ida::BadAddress), ida::ErrorCategory::NotFound);

    // exists() at BadAddress
    CHECK(!ida::fixup::exists(ida::BadAddress));

    // Custom fixup: empty name
    ida::fixup::CustomHandler bad_handler;
    bad_handler.name = "";
    CHECK_ERR(ida::fixup::register_custom(bad_handler), ida::ErrorCategory::Validation);

    // Unregister nonexistent custom type
    CHECK_ERR(ida::fixup::unregister_custom(0xFFFF), ida::ErrorCategory::NotFound);

    // find_custom with empty name
    CHECK_ERR(ida::fixup::find_custom(""), ida::ErrorCategory::Validation);

    // find_custom with nonexistent name
    CHECK_ERR(ida::fixup::find_custom("idax_no_such_fixup_handler"), ida::ErrorCategory::NotFound);
}

// ---------------------------------------------------------------------------
// Test: custom fixup registration lifecycle
// ---------------------------------------------------------------------------
void test_custom_fixup_lifecycle() {
    std::cout << "--- custom fixup registration lifecycle ---\n";

    ida::fixup::CustomHandler handler;
    handler.name = "idax_test_custom_fixup";
    handler.size = 4;
    handler.width = 32;

    auto id = ida::fixup::register_custom(handler);
    CHECK_OK(id);
    if (!id) return;

    std::cout << "  registered custom fixup type id: " << *id << "\n";

    // Find it by name
    auto found = ida::fixup::find_custom("idax_test_custom_fixup");
    CHECK_OK(found);
    if (found) {
        CHECK(*found == *id);
    }

    // Unregister
    CHECK_OK(ida::fixup::unregister_custom(*id));

    // After unregister, find should fail
    auto gone = ida::fixup::find_custom("idax_test_custom_fixup");
    CHECK(!gone.has_value());
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    CHECK_OK(ida::analysis::wait());

    test_set_get_roundtrip();
    test_fixup_types();
    test_contains();
    test_traversal();
    test_range_iteration();
    test_error_paths();
    test_custom_fixup_lifecycle();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
