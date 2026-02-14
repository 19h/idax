/// \file data_mutation_safety_test.cpp
/// \brief Integration checks for ida::data mutation safety behavior.

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
#include <string>
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

void test_patch_and_original(ida::Address ea) {
    std::cout << "--- patch/original semantics ---\n";

    auto original = ida::data::read_byte(ea);
    CHECK_OK(original);
    if (!original)
        return;

    const std::uint8_t patched =
        (*original == 0xFFu) ? 0x00u : static_cast<std::uint8_t>(*original + 1u);

    CHECK_OK(ida::data::patch_byte(ea, patched));

    auto after_patch = ida::data::read_byte(ea);
    CHECK_OK(after_patch);
    if (after_patch)
        CHECK(*after_patch == patched);

    auto preserved_original = ida::data::original_byte(ea);
    CHECK_OK(preserved_original);
    if (preserved_original)
        CHECK(*preserved_original == *original);

    CHECK_OK(ida::data::revert_patch(ea));

    auto after_restore = ida::data::read_byte(ea);
    CHECK_OK(after_restore);
    if (after_restore)
        CHECK(*after_restore == *original);

    auto second_revert = ida::data::revert_patch(ea);
    CHECK(!second_revert.has_value());
    if (!second_revert)
        CHECK(second_revert.error().category == ida::ErrorCategory::NotFound);
}

void test_write_roundtrip(ida::Address ea) {
    std::cout << "--- write roundtrip ---\n";

    auto original = ida::data::read_bytes(ea, 4);
    CHECK_OK(original);
    if (!original || original->size() != 4)
        return;

    std::vector<std::uint8_t> mutated = *original;
    for (auto& b : mutated)
        b ^= 0x5Au;

    if (mutated == *original)
        mutated[0] ^= 0x01u;

    CHECK_OK(ida::data::write_bytes(ea, mutated));

    auto read_mutated = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_mutated);
    if (read_mutated)
        CHECK(*read_mutated == mutated);

    CHECK_OK(ida::data::write_bytes(ea, *original));

    auto read_restored = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_restored);
    if (read_restored)
        CHECK(*read_restored == *original);
}

void test_typed_value_facade(ida::Address ea) {
    std::cout << "--- typed value facade ---\n";

    auto i32 = ida::type::TypeInfo::int32();
    auto read_i32 = ida::data::read_typed(ea, i32);
    CHECK_OK(read_i32);
    if (read_i32) {
        CHECK(read_i32->kind == ida::data::TypedValueKind::SignedInteger
              || read_i32->kind == ida::data::TypedValueKind::UnsignedInteger);
    }

    auto byte_array = ida::type::TypeInfo::array_of(ida::type::TypeInfo::uint8(), 4);
    auto typed_bytes = ida::data::read_typed(ea, byte_array);
    CHECK_OK(typed_bytes);
    if (typed_bytes) {
        CHECK(typed_bytes->kind == ida::data::TypedValueKind::Bytes);
        if (typed_bytes->kind == ida::data::TypedValueKind::Bytes)
            CHECK(typed_bytes->bytes.size() == 4);
    }

    auto original = ida::data::read_bytes(ea, 4);
    CHECK_OK(original);
    if (!original || original->size() != 4)
        return;

    ida::data::TypedValue mutated;
    mutated.kind = ida::data::TypedValueKind::Bytes;
    mutated.bytes = *original;
    for (auto& b : mutated.bytes)
        b ^= 0xA5u;

    if (mutated.bytes == *original)
        mutated.bytes[0] ^= 0x01u;

    CHECK_OK(ida::data::write_typed(ea, byte_array, mutated));

    auto read_mutated = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_mutated);
    if (read_mutated)
        CHECK(*read_mutated == mutated.bytes);

    CHECK_OK(ida::data::write_bytes(ea, *original));

    ida::data::TypedValue wrong_size;
    wrong_size.kind = ida::data::TypedValueKind::Bytes;
    wrong_size.bytes = {0x41, 0x42};
    auto mismatch = ida::data::write_typed(ea, byte_array, wrong_size);
    CHECK(!mismatch.has_value());
    if (!mismatch)
        CHECK(mismatch.error().category == ida::ErrorCategory::Validation);
}

void test_define_undefine_unknown() {
    std::cout << "--- define/undefine unknown ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo)
        return;

    auto hi = ida::database::max_address();
    CHECK_OK(hi);
    if (!hi)
        return;

    auto unknown = ida::search::next_unknown(*lo);
    if (!unknown) {
        CHECK(unknown.error().category == ida::ErrorCategory::NotFound);
        std::cout << "  (no unknown bytes found in fixture; skipping mutation check)\n";
        return;
    }

    CHECK_OK(ida::data::define_byte(*unknown, 1));
    CHECK(ida::address::is_data(*unknown));

    CHECK_OK(ida::data::undefine(*unknown, 1));
    CHECK(ida::address::is_unknown(*unknown));

    if (*unknown + 4 < *hi) {
        auto make_float = ida::data::define_float(*unknown, 1);
        if (!make_float) {
            CHECK(make_float.error().category == ida::ErrorCategory::SdkFailure);
            std::cout << "  (define_float unsupported at selected address; skipping)\n";
        } else {
            CHECK_OK(make_float);
            auto size = ida::address::item_size(*unknown);
            CHECK_OK(size);
            if (size)
                CHECK_OK(ida::data::undefine(*unknown, *size));
        }
    }

    if (*unknown + 8 < *hi) {
        auto make_double = ida::data::define_double(*unknown, 1);
        if (!make_double) {
            CHECK(make_double.error().category == ida::ErrorCategory::SdkFailure);
            std::cout << "  (define_double unsupported at selected address; skipping)\n";
        } else {
            CHECK_OK(make_double);
            auto size = ida::address::item_size(*unknown);
            CHECK_OK(size);
            if (size)
                CHECK_OK(ida::data::undefine(*unknown, *size));
        }
    }
}

void test_error_paths() {
    std::cout << "--- mutation safety error paths ---\n";

    auto bad_read = ida::data::read_byte(ida::BadAddress);
    CHECK(!bad_read.has_value());
    if (!bad_read)
        CHECK(bad_read.error().category == ida::ErrorCategory::NotFound);

    auto bad_original = ida::data::original_dword(ida::BadAddress);
    CHECK(!bad_original.has_value());
    if (!bad_original)
        CHECK(bad_original.error().category == ida::ErrorCategory::NotFound);

    auto lo = ida::database::min_address();
    auto hi = ida::database::max_address();
    CHECK_OK(lo);
    CHECK_OK(hi);
    if (!lo || !hi)
        return;

    auto empty_pattern = ida::data::find_binary_pattern(*lo, *hi, "");
    CHECK(!empty_pattern.has_value());
    if (!empty_pattern)
        CHECK(empty_pattern.error().category == ida::ErrorCategory::Validation);
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

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (lo) {
        test_patch_and_original(*lo);
        test_write_roundtrip(*lo);
        test_typed_value_facade(*lo);
    }

    test_define_undefine_unknown();
    test_error_paths();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
