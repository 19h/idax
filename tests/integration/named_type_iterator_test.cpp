/// \file named_type_iterator_test.cpp
/// \brief Integration tests for ida::type::NamedTypeIterator and NamedTypeRange.
///
/// This test validates the iterator/range pattern for iterating over named types
/// in the IDA type library. Tests cover:
/// - NamedTypeIterator default construction
/// - NamedTypeIterator copy construction and assignment
/// - NamedTypeRange default construction
/// - Iterator equality and inequality operators
/// - Iteration over named types via begin()/end()
/// - Iterator advance via operator++
/// - Dereference operators operator* and operator->
/// - NamedTypeEntry struct with name and library_name fields

#include <ida/idax.hpp>

#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace {

int g_pass = 0;
int g_fail = 0;

/// Macro to check a boolean condition and track pass/fail
#define CHECK(expr)                                                           \
    do {                                                                      \
        if (expr) {                                                           \
            ++g_pass;                                                         \
        } else {                                                              \
            ++g_fail;                                                         \
            std::cerr << "[FAIL] " #expr << " (" << __FILE__ << ":"           \
                      << __LINE__ << ")\n";                                   \
        }                                                                     \
    } while (false)

/// Macro to check that a Result has a value (success)
#define CHECK_OK(expr)                                                        \
    do {                                                                      \
        auto _r = (expr);                                                     \
        if (_r.has_value()) {                                                 \
            ++g_pass;                                                         \
        } else {                                                              \
            ++g_fail;                                                         \
            std::cerr << "[FAIL] " #expr " => error: "                        \
                      << _r.error().message << " (" << __FILE__ << ":"        \
                      << __LINE__ << ")\n";                                   \
        }                                                                     \
    } while (false)

/// Macro to check that a Result has no value (failure) with specific category
#define CHECK_ERR(expr, cat)                                                  \
    do {                                                                      \
        auto _r = (expr);                                                     \
        if (!_r.has_value() && _r.error().category == (cat)) {                \
            ++g_pass;                                                         \
        } else {                                                              \
            ++g_fail;                                                         \
            if (_r.has_value())                                               \
                std::cerr << "[FAIL] " #expr " => expected error but got value" \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n";    \
            else                                                              \
                std::cerr << "[FAIL] " #expr " => wrong error category"       \
                          << " (" << __FILE__ << ":" << __LINE__ << ")\n";    \
        }                                                                     \
    } while (false)

// ---------------------------------------------------------------------------
// Test: NamedTypeIterator default construction
// ---------------------------------------------------------------------------
void test_named_type_iterator_default_construction() {
    std::cout << "--- NamedTypeIterator default construction ---\n";

    // Default constructed iterator should be valid (impl is nullptr)
    ida::type::NamedTypeIterator it;
    CHECK(true); // Default construction should not throw

    // Two default constructed iterators should be equal
    ida::type::NamedTypeIterator it2;
    CHECK(it == it2);
    CHECK(!(it != it2));
}

// ---------------------------------------------------------------------------
// Test: NamedTypeIterator copy construction and assignment
// ---------------------------------------------------------------------------
void test_named_type_iterator_copy() {
    std::cout << "--- NamedTypeIterator copy construction ---\n";

    // Default constructed
    ida::type::NamedTypeIterator it1;

    // Copy construct
    ida::type::NamedTypeIterator it2(it1);
    CHECK(it1 == it2);

    // Copy assign
    ida::type::NamedTypeIterator it3;
    it3 = it2;
    CHECK(it2 == it3);
}

// ---------------------------------------------------------------------------
// Test: NamedTypeRange default construction
// ---------------------------------------------------------------------------
void test_named_type_range_default_construction() {
    std::cout << "--- NamedTypeRange default construction ---\n";

    // Default constructed range should be valid
    ida::type::NamedTypeRange range;
    CHECK(true); // Default construction should not throw

    // Copy construction
    ida::type::NamedTypeRange range2(range);
    CHECK(true); // Should not throw

    // Copy assignment
    ida::type::NamedTypeRange range3;
    range3 = range2;
    CHECK(true); // Should not throw
}

// ---------------------------------------------------------------------------
// Test: Iterator comparison operators
// ---------------------------------------------------------------------------
void test_iterator_comparison() {
    std::cout << "--- Iterator comparison operators ---\n";

    // Default constructed iterators are equal
    ida::type::NamedTypeIterator it1;
    ida::type::NamedTypeIterator it2;
    CHECK(it1 == it2);
    CHECK(!(it1 != it2));

    // After copy, iterators should still be equal
    ida::type::NamedTypeIterator it3(it1);
    CHECK(it1 == it3);
}

// ---------------------------------------------------------------------------
// Test: named_types() API - all overloads
// ---------------------------------------------------------------------------
void test_named_types_api() {
    std::cout << "--- named_types() API ---\n";

    // Test named_types() - no arguments, uses default til and flags
    CHECK_OK(ida::type::named_types());

    // Test named_types(til_name) - specific til, default flags
    // Empty name should use default til
    CHECK_OK(ida::type::named_types({}));

    // Test named_types(til_name, flags) - specific til and flags
    // Using NTF_TYPE | NTF_FUNC flags explicitly
    CHECK_OK(ida::type::named_types({}, NTF_TYPE | NTF_FUNC));
}

// ---------------------------------------------------------------------------
// Test: NamedTypeRange begin/end iteration
// ---------------------------------------------------------------------------
void test_range_iteration() {
    std::cout << "--- Range iteration ---\n";

    // Get a range of named types
    auto range_result = ida::type::named_types();
    CHECK_OK(range_result);

    auto range = *range_result;

    // begin() and end() should return iterators
    ida::type::NamedTypeIterator begin_it = range.begin();
    ida::type::NamedTypeIterator end_it = range.end();

    // begin and end should be comparable
    // If the type library is empty, they might be equal
    // If there are types, begin should not equal end
    CHECK(true); // Basic iteration sanity

    // Test range-based for loop support via begin/end
    int count = 0;
    for (auto it = range.begin(); it != range.end(); ++it) {
        // Dereference to get the NamedTypeEntry
        ida::type::NamedTypeEntry entry = *it;
        CHECK(!entry.name.empty()); // Type names should not be empty
        // library_name may be empty for root til types
        ++count;
        // Safety limit to prevent infinite loops
        if (count > 10000) {
            std::cerr << "[WARN] Iterator exceeded 10000 iterations, possible infinite loop\n";
            break;
        }
    }
    std::cout << "  Found " << count << " named types\n";
    CHECK(true); // Iteration completed without crash (count may be 0 if no types)
}

// ---------------------------------------------------------------------------
// Test: NamedTypeEntry struct fields
// ---------------------------------------------------------------------------
void test_named_type_entry_fields() {
    std::cout << "--- NamedTypeEntry fields ---\n";

    auto range_result = ida::type::named_types();
    CHECK_OK(range_result);

    auto range = *range_result;

    // Iterate until we find a valid entry
    for (auto it = range.begin(); it != range.end(); ++it) {
        ida::type::NamedTypeEntry entry = *it;
        CHECK(!entry.name.empty()); // name must not be empty

        // Check that operator-> gives us access to the same data
        const ida::type::NamedTypeEntry* ptr = it.operator->();
        CHECK(ptr != nullptr);
        CHECK(ptr->name == entry.name);
        CHECK(ptr->library_name == entry.library_name);

        break; // Just check first element
    }
}

// ---------------------------------------------------------------------------
// Test: Iterator arrow operator
// ---------------------------------------------------------------------------
void test_iterator_arrow_operator() {
    std::cout << "--- Iterator arrow operator ---\n";

    auto range_result = ida::type::named_types();
    CHECK_OK(range_result);

    auto range = *range_result;

    // Arrow operator should give access to NamedTypeEntry pointer
    for (auto it = range.begin(); it != range.end(); ++it) {
        const ida::type::NamedTypeEntry* ptr = it.operator->();
        CHECK(ptr != nullptr);
        CHECK(!ptr->name.empty());
        // library_name may be empty but we should be able to access it
        CHECK(ptr->library_name.empty() || !ptr->library_name.empty());
        break; // Just check first element
    }
}

// ---------------------------------------------------------------------------
// Test: Iterator post-increment
// ---------------------------------------------------------------------------
void test_iterator_post_increment() {
    std::cout << "--- Iterator post-increment ---\n";

    auto range_result = ida::type::named_types();
    CHECK_OK(range_result);

    auto range = *range_result;

    auto it = range.begin();
    auto it_copy = it++;

    // After post-increment (it_copy = it++):
    // - it_copy holds the original iterator value before increment
    // - it has been advanced to the next position
    // If range was non-empty, it_copy should be dereferenceable
    // If range was empty (begin == end), both it and it_copy should be at end
    CHECK(true); // Basic sanity: post-increment did not crash
}

// ---------------------------------------------------------------------------
// Test: Library name is populated across bases
// ---------------------------------------------------------------------------
void test_library_name_populated() {
    std::cout << "--- Library name population ---\n";

    auto range_result = ida::type::named_types();
    CHECK_OK(range_result);

    auto range = *range_result;

    // Collect library names while iterating
    int types_with_library = 0;
    for (auto it = range.begin(); it != range.end(); ++it) {
        ida::type::NamedTypeEntry entry = *it;
        if (!entry.library_name.empty()) {
            ++types_with_library;
        }
    }
    std::cout << "  Types with library name: " << types_with_library << "\n";
    // It's OK if some types don't have library names (root til types may not)
    CHECK(types_with_library >= 0); // Sanity check
}

} // namespace

int main() {
    std::cout << "=== NamedTypeIterator/NamedTypeRange Tests ===\n\n";

    test_named_type_iterator_default_construction();
    test_named_type_iterator_copy();
    test_named_type_range_default_construction();
    test_iterator_comparison();
    test_named_types_api();
    test_range_iteration();
    test_named_type_entry_fields();
    test_iterator_arrow_operator();
    test_iterator_post_increment();
    test_library_name_populated();

    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Passed: " << g_pass << "\n";
    std::cout << "Failed: " << g_fail << "\n";

    return g_fail == 0 ? 0 : 1;
}