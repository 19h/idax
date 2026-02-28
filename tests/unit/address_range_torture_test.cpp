/// \file address_range_torture_test.cpp
/// \brief Exhaustive offline unit tests for ida::address::Range, Address types,
/// BadAddress sentinel, and iterator default contracts.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <limits>
#include <vector>
#include <algorithm>

namespace {

// ── Range basic semantics ───────────────────────────────────────────────

void test_range_basic() {
    SECTION("Range basic semantics");

    ida::address::Range r{0x1000, 0x2000};
    CHECK(r.size() == 0x1000);
    CHECK(r.contains(0x1000));
    CHECK(r.contains(0x1FFF));
    CHECK(!r.contains(0x2000)); // half-open: end excluded
    CHECK(!r.contains(0x0FFF));
    CHECK(!r.empty());
}

// ── Range empty cases ───────────────────────────────────────────────────

void test_range_empty() {
    SECTION("Range empty cases");

    // start == end
    ida::address::Range r1{0x1000, 0x1000};
    CHECK(r1.empty());
    CHECK(r1.size() == 0);
    CHECK(!r1.contains(0x1000));

    // start > end (inverted)
    ida::address::Range r2{0x2000, 0x1000};
    CHECK(r2.empty());
    CHECK(r2.size() == 0);
    CHECK(!r2.contains(0x1500));

    // zero-zero
    ida::address::Range r3{0, 0};
    CHECK(r3.empty());
    CHECK(r3.size() == 0);
}

// ── Range with BadAddress ───────────────────────────────────────────────

void test_range_bad_address() {
    SECTION("Range with BadAddress");

    // Default range
    ida::address::Range r1{ida::BadAddress, ida::BadAddress};
    CHECK(r1.empty());
    CHECK(r1.size() == 0);

    // Range from 0 to BadAddress = entire address space
    ida::address::Range r2{0, ida::BadAddress};
    CHECK(!r2.empty());
    CHECK(r2.size() == ida::BadAddress);  // UINT64_MAX
    CHECK(r2.contains(0));
    CHECK(r2.contains(ida::BadAddress - 1));
    CHECK(!r2.contains(ida::BadAddress)); // end excluded

    // Single byte at BadAddress-1
    ida::address::Range r3{ida::BadAddress - 1, ida::BadAddress};
    CHECK(!r3.empty());
    CHECK(r3.size() == 1);
    CHECK(r3.contains(ida::BadAddress - 1));
    CHECK(!r3.contains(ida::BadAddress));
}

// ── Range boundary values ───────────────────────────────────────────────

void test_range_boundaries() {
    SECTION("Range boundary values");

    // Single byte range
    ida::address::Range r1{0, 1};
    CHECK(!r1.empty());
    CHECK(r1.size() == 1);
    CHECK(r1.contains(0));
    CHECK(!r1.contains(1));

    // Max possible range
    ida::address::Range r2{0, std::numeric_limits<uint64_t>::max()};
    CHECK(!r2.empty());
    CHECK(r2.size() == std::numeric_limits<uint64_t>::max());

    // Large range
    ida::address::Range r3{0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
    CHECK(!r3.empty());
    CHECK(r3.size() == 0x8000000000000000ULL);
    CHECK(r3.contains(0x7FFFFFFFFFFFFFFF));
    CHECK(r3.contains(0xFFFFFFFFFFFFFFFE));
    CHECK(!r3.contains(0xFFFFFFFFFFFFFFFF));
}

// ── Address type aliases ────────────────────────────────────────────────

void test_address_types() {
    SECTION("Address type aliases");

    // Address is uint64_t
    ida::Address a = 0xDEADBEEFCAFEBABEULL;
    CHECK(a == 0xDEADBEEFCAFEBABEULL);

    // AddressDelta is int64_t
    ida::AddressDelta d = -1;
    CHECK(d == -1);
    CHECK(static_cast<ida::AddressDelta>(INT64_MIN) == INT64_MIN);

    // AddressSize is uint64_t
    ida::AddressSize s = 0;
    CHECK(s == 0);
    s = UINT64_MAX;
    CHECK(s == UINT64_MAX);
}

// ── BadAddress sentinel ─────────────────────────────────────────────────

void test_bad_address() {
    SECTION("BadAddress sentinel");

    CHECK(ida::BadAddress == 0xFFFFFFFFFFFFFFFFULL);
    CHECK(ida::BadAddress == ~ida::Address{0});
    CHECK(ida::BadAddress == std::numeric_limits<ida::Address>::max());

    // Arithmetic with BadAddress
    CHECK(ida::BadAddress + 1 == 0); // wraps around
    CHECK(ida::BadAddress - 1 == 0xFFFFFFFFFFFFFFFEULL);
}

// ── Range contains edge stress ──────────────────────────────────────────

void test_range_contains_stress() {
    SECTION("Range contains edge stress");

    ida::address::Range r{0x400000, 0x500000};

    // Test many addresses
    for (ida::Address a = 0x400000; a < 0x400100; ++a) {
        CHECK(r.contains(a));
    }

    for (ida::Address a = 0x4FFFF0; a < 0x500000; ++a) {
        CHECK(r.contains(a));
    }

    CHECK(!r.contains(0x500000));
    CHECK(!r.contains(0x500001));
    CHECK(!r.contains(0x3FFFFF));
}

// ── Range comparison and equality ───────────────────────────────────────

void test_range_not_implicitly_comparable() {
    SECTION("Range member-wise comparison");

    ida::address::Range a{0x1000, 0x2000};
    ida::address::Range b{0x1000, 0x2000};
    ida::address::Range c{0x1000, 0x3000};

    // Struct comparison (member-wise)
    CHECK(a.start == b.start);
    CHECK(a.end == b.end);
    CHECK(a.start == c.start);
    CHECK(a.end != c.end);

    CHECK(a.size() == b.size());
    CHECK(a.size() != c.size());
}

// ── Iterator default construction ───────────────────────────────────────

void test_iterator_defaults() {
    SECTION("Iterator default construction");

    ida::address::ItemIterator a;
    ida::address::ItemIterator b;
    CHECK(a == b); // Default iterators compare equal (sentinel)

    ida::address::PredicateIterator c;
    ida::address::PredicateIterator d;
    CHECK(c == d);
}

// ── Predicate enum ──────────────────────────────────────────────────────

void test_predicate_enum() {
    SECTION("Predicate enum values");

    // All variants exist and are distinct
    std::vector<ida::address::Predicate> preds = {
        ida::address::Predicate::Mapped,
        ida::address::Predicate::Loaded,
        ida::address::Predicate::Code,
        ida::address::Predicate::Data,
        ida::address::Predicate::Unknown,
        ida::address::Predicate::Head,
        ida::address::Predicate::Tail,
    };

    CHECK(preds.size() == 7);
    for (size_t i = 0; i < preds.size(); ++i) {
        for (size_t j = i + 1; j < preds.size(); ++j) {
            CHECK(preds[i] != preds[j]);
        }
    }
}

// ── Range size overflow ─────────────────────────────────────────────────

void test_range_size_overflow() {
    SECTION("Range size with maximum values");

    // Size when end wraps? No — end > start so no wrap for normal ranges
    ida::address::Range r{1, 0};
    CHECK(r.size() == 0); // inverted => 0

    // Max size
    ida::address::Range r2{0, UINT64_MAX};
    CHECK(r2.size() == UINT64_MAX);
}

// ── Range contains with 0 ──────────────────────────────────────────────

void test_range_contains_zero() {
    SECTION("Range containing address 0");

    ida::address::Range r{0, 0x100};
    CHECK(r.contains(0));
    CHECK(r.contains(0xFF));
    CHECK(!r.contains(0x100));
}

} // namespace

int main() {
    test_range_basic();
    test_range_empty();
    test_range_bad_address();
    test_range_boundaries();
    test_address_types();
    test_bad_address();
    test_range_contains_stress();
    test_range_not_implicitly_comparable();
    test_iterator_defaults();
    test_predicate_enum();
    test_range_size_overflow();
    test_range_contains_zero();

    return idax_test::report("address_range_torture_test");
}
