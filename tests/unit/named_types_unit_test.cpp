/// \file named_types_unit_test.cpp
/// \brief Unit tests for NamedTypeIterator, NamedTypeRange, and named_types() API.
///
/// Tests compile-time type traits, default construction, copy semantics,
/// comparison operators, and iterator category conformance. Does NOT require
/// IDA runtime — pure compile-time + offline unit checks.

#include <ida/idax.hpp>
#include <ida/type.hpp>

#include <cstdio>
#include <iterator>
#include <string>
#include <type_traits>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; std::printf("  FAIL: %s\n", msg); }                   \
    } while (0)

// ============================================================================
// NamedTypeEntry struct tests
// ============================================================================

void test_named_type_entry() {
    // Default constructible
    CHECK(std::is_default_constructible_v<ida::type::NamedTypeEntry>,
          "NamedTypeEntry is default constructible");

    ida::type::NamedTypeEntry entry;
    CHECK(entry.name.empty(), "Default-constructed NamedTypeEntry has empty name");
    CHECK(entry.library_name.empty(), "Default-constructed NamedTypeEntry has empty library_name");

    // Aggregate initialization
    ida::type::NamedTypeEntry e2{"LPCSTR", "mssdk_win7"};
    CHECK(e2.name == "LPCSTR", "NamedTypeEntry name set correctly");
    CHECK(e2.library_name == "mssdk_win7", "NamedTypeEntry library_name set correctly");
}

// ============================================================================
// NamedTypeIterator type traits and construction
// ============================================================================

void test_named_type_iterator_traits() {
    using Iter = ida::type::NamedTypeIterator;

    // Default constructible
    CHECK(std::is_default_constructible_v<Iter>,
          "NamedTypeIterator is default constructible");

    // Copy constructible
    CHECK(std::is_copy_constructible_v<Iter>,
          "NamedTypeIterator is copy constructible");

    // Copy assignable
    CHECK(std::is_copy_assignable_v<Iter>,
          "NamedTypeIterator is copy assignable");

    // Destructible
    CHECK(std::is_destructible_v<Iter>,
          "NamedTypeIterator is destructible");

    // Iterator traits
    using traits = std::iterator_traits<Iter>;
    static_assert(std::is_same_v<traits::iterator_category, std::input_iterator_tag>,
                  "NamedTypeIterator has input_iterator_tag");
    static_assert(std::is_same_v<traits::value_type, ida::type::NamedTypeEntry>,
                  "NamedTypeIterator value_type is NamedTypeEntry");
    static_assert(std::is_same_v<traits::difference_type, std::ptrdiff_t>,
                  "NamedTypeIterator difference_type is ptrdiff_t");
    static_assert(std::is_same_v<traits::pointer, const ida::type::NamedTypeEntry*>,
                  "NamedTypeIterator pointer is const NamedTypeEntry*");
    static_assert(std::is_same_v<traits::reference, const ida::type::NamedTypeEntry&>,
                  "NamedTypeIterator reference is const NamedTypeEntry&");

    // Default construction
    Iter it;
    CHECK(true, "NamedTypeIterator default construction succeeds");

    // Copy construction
    Iter it2 = it;
    CHECK(true, "NamedTypeIterator copy construction succeeds");

    // Copy assignment
    it2 = it;
    CHECK(true, "NamedTypeIterator copy assignment succeeds");

    // Comparison of default-constructed iterators
    CHECK(it == it2, "Two default-constructed NamedTypeIterators compare equal");

    // Post-increment
    Iter it3 = it++;
    (void)it3;
    CHECK(true, "NamedTypeIterator post-increment compiles");
}

// ============================================================================
// NamedTypeRange type traits and construction
// ============================================================================

void test_named_type_range_traits() {
    using Range = ida::type::NamedTypeRange;

    // Default constructible
    CHECK(std::is_default_constructible_v<Range>,
          "NamedTypeRange is default constructible");

    // Copy constructible
    CHECK(std::is_copy_constructible_v<Range>,
          "NamedTypeRange is copy constructible");

    // Copy assignable
    CHECK(std::is_copy_assignable_v<Range>,
          "NamedTypeRange is copy assignable");

    // Destructible
    CHECK(std::is_destructible_v<Range>,
          "NamedTypeRange is destructible");

    // Default construction
    Range r;
    CHECK(true, "NamedTypeRange default construction succeeds");

    // Copy construction
    Range r2 = r;
    CHECK(true, "NamedTypeRange copy construction succeeds");

    // Copy assignment
    r2 = r;
    CHECK(true, "NamedTypeRange copy assignment succeeds");

    // begin() and end() return iterators
    auto it = r.begin();
    auto end = r.end();
    CHECK(std::is_same_v<decltype(it), ida::type::NamedTypeIterator>,
          "NamedTypeRange::begin() returns NamedTypeIterator");
    CHECK(std::is_same_v<decltype(end), ida::type::NamedTypeIterator>,
          "NamedTypeRange::end() returns NamedTypeIterator");

    // begin == end for empty/default-constructed range
    CHECK(it == end, "Default-constructed NamedTypeRange has begin() == end()");
}

// ============================================================================
// named_types() function signature tests
// ============================================================================

void test_named_types_function_signatures() {
    // Check all three overloads exist

    // Zero-argument overload
    using Fn0 = ida::Result<ida::type::NamedTypeRange>(*)();
    Fn0 f0 = &ida::type::named_types;
    (void)f0;
    CHECK(true, "named_types() zero-argument overload exists");

    // One-argument overload (til_name)
    using Fn1 = ida::Result<ida::type::NamedTypeRange>(*)(std::string_view);
    Fn1 f1 = &ida::type::named_types;
    (void)f1;
    CHECK(true, "named_types(std::string_view) one-argument overload exists");

    // Two-argument overload (til_name, flags)
    using Fn2 = ida::Result<ida::type::NamedTypeRange>(*)(std::string_view, int);
    Fn2 f2 = &ida::type::named_types;
    (void)f2;
    CHECK(true, "named_types(std::string_view, int) two-argument overload exists");
}

// ============================================================================
// Iterator semantics: empty range
// ============================================================================

void test_empty_range_semantics() {
    ida::type::NamedTypeRange empty_range;
    auto it = empty_range.begin();
    auto end = empty_range.end();

    CHECK(it == end, "Empty range: begin() == end()");
    CHECK(!(it != end), "Empty range: !(begin() != end())");

    // Incrementing an end iterator should be a no-op
    auto it2 = it;
    ++it2;
    CHECK(it2 == end, "Incrementing end iterator remains at end");
}

// ============================================================================
// Iterator semantics: copying and comparison
// ============================================================================

void test_iterator_copy_semantics() {
    ida::type::NamedTypeIterator it1;
    ida::type::NamedTypeIterator it2 = it1;
    CHECK(it1 == it2, "Copy-constructed iterators compare equal");

    ida::type::NamedTypeIterator it3;
    it3 = it1;
    CHECK(it1 == it3, "Copy-assigned iterators compare equal");

    // Self-assignment
    it3 = it3;
    CHECK(true, "Iterator self-assignment does not crash");
}

// ============================================================================
// Result type compatibility with named_types
// ============================================================================

void test_result_compatibility() {
    // named_types returns Result<NamedTypeRange>
    using ResultType = std::expected<ida::type::NamedTypeRange, ida::Error>;
    auto result = ida::type::named_types();

    CHECK(std::is_same_v<decltype(result), ResultType>,
          "named_types() returns Result<NamedTypeRange>");

    // Result type supports error checking
    if (!result) {
        CHECK(true, "Result type supports error checking (no TILs loaded is expected)");
        auto err = result.error();
        CHECK(!err.message.empty(), "Error has a non-empty message");
    } else {
        // If there ARE TILs, we can iterate
        CHECK(true, "Result contains a valid NamedTypeRange");
        auto& range = *result;
        auto it = range.begin();
        auto end = range.end();
        // Iteration should be valid even if empty
        for (; it != end; ++it) {
            const auto& entry = *it;
            CHECK(!entry.name.empty(), "Named type entry has non-empty name");
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== named_types unit tests ===\n\n");

    std::printf("[NamedTypeEntry]\n");
    test_named_type_entry();

    std::printf("\n[NamedTypeIterator traits]\n");
    test_named_type_iterator_traits();

    std::printf("\n[NamedTypeRange traits]\n");
    test_named_type_range_traits();

    std::printf("\n[named_types() signatures]\n");
    test_named_types_function_signatures();

    std::printf("\n[Empty range semantics]\n");
    test_empty_range_semantics();

    std::printf("\n[Iterator copy semantics]\n");
    test_iterator_copy_semantics();

    std::printf("\n[Result compatibility]\n");
    test_result_compatibility();

    std::printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
