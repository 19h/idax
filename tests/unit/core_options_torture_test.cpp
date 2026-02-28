/// \file core_options_torture_test.cpp
/// \brief Exhaustive offline unit tests for ida::OperationOptions,
/// ida::RangeOptions, ida::WaitOptions from core.hpp.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <cstdint>

namespace {

// ── OperationOptions defaults ───────────────────────────────────────────

void test_operation_options_defaults() {
    SECTION("OperationOptions defaults");

    ida::OperationOptions o;
    CHECK(o.strict_validation == true);
    CHECK(o.allow_partial_results == false);
    CHECK(o.cancel_on_user_break == true);
    CHECK(o.quiet == true);
}

// ── OperationOptions mutation ───────────────────────────────────────────

void test_operation_options_mutation() {
    SECTION("OperationOptions mutation");

    ida::OperationOptions o;
    o.strict_validation = false;
    o.allow_partial_results = true;
    o.cancel_on_user_break = false;
    o.quiet = false;

    CHECK(o.strict_validation == false);
    CHECK(o.allow_partial_results == true);
    CHECK(o.cancel_on_user_break == false);
    CHECK(o.quiet == false);

    // Reset
    o.strict_validation = true;
    o.quiet = true;
    CHECK(o.strict_validation == true);
    CHECK(o.quiet == true);
}

// ── OperationOptions copy ───────────────────────────────────────────────

void test_operation_options_copy() {
    SECTION("OperationOptions copy");

    ida::OperationOptions o1;
    o1.strict_validation = false;

    auto o2 = o1;
    CHECK(o2.strict_validation == false);
    CHECK(o2.allow_partial_results == false);
    CHECK(o2.cancel_on_user_break == true);
    CHECK(o2.quiet == true);

    // Modify copy doesn't affect original
    o2.quiet = false;
    CHECK(o1.quiet == true);
}

// ── RangeOptions defaults ───────────────────────────────────────────────

void test_range_options_defaults() {
    SECTION("RangeOptions defaults");

    ida::RangeOptions r;
    CHECK(r.start == ida::BadAddress);
    CHECK(r.end == ida::BadAddress);
    CHECK(r.inclusive_end == false);
}

// ── RangeOptions mutation ───────────────────────────────────────────────

void test_range_options_mutation() {
    SECTION("RangeOptions mutation");

    ida::RangeOptions r;
    r.start = 0x1000;
    r.end = 0x2000;
    r.inclusive_end = true;

    CHECK(r.start == 0x1000);
    CHECK(r.end == 0x2000);
    CHECK(r.inclusive_end == true);

    // Full address space
    r.start = 0;
    r.end = ida::BadAddress;
    CHECK(r.start == 0);
    CHECK(r.end == ida::BadAddress);
}

// ── RangeOptions copy ───────────────────────────────────────────────────

void test_range_options_copy() {
    SECTION("RangeOptions copy");

    ida::RangeOptions r1;
    r1.start = 0x400000;
    r1.end = 0x500000;
    r1.inclusive_end = true;

    auto r2 = r1;
    CHECK(r2.start == 0x400000);
    CHECK(r2.end == 0x500000);
    CHECK(r2.inclusive_end == true);

    r2.start = 0;
    CHECK(r1.start == 0x400000); // original unchanged
}

// ── WaitOptions defaults ────────────────────────────────────────────────

void test_wait_options_defaults() {
    SECTION("WaitOptions defaults");

    ida::WaitOptions w;
    CHECK(w.timeout_ms == 0);
    CHECK(w.poll_interval_ms == 10);
}

// ── WaitOptions mutation ────────────────────────────────────────────────

void test_wait_options_mutation() {
    SECTION("WaitOptions mutation");

    ida::WaitOptions w;
    w.timeout_ms = 5000;
    w.poll_interval_ms = 100;

    CHECK(w.timeout_ms == 5000);
    CHECK(w.poll_interval_ms == 100);

    // Edge values
    w.timeout_ms = UINT32_MAX;
    w.poll_interval_ms = 0;
    CHECK(w.timeout_ms == UINT32_MAX);
    CHECK(w.poll_interval_ms == 0);

    w.timeout_ms = 0;
    w.poll_interval_ms = 1;
    CHECK(w.timeout_ms == 0);
    CHECK(w.poll_interval_ms == 1);
}

// ── WaitOptions copy ────────────────────────────────────────────────────

void test_wait_options_copy() {
    SECTION("WaitOptions copy");

    ida::WaitOptions w1;
    w1.timeout_ms = 3000;

    auto w2 = w1;
    CHECK(w2.timeout_ms == 3000);
    CHECK(w2.poll_interval_ms == 10);

    w2.poll_interval_ms = 50;
    CHECK(w1.poll_interval_ms == 10);
}

// ── All options aggregate test ──────────────────────────────────────────

void test_options_aggregate() {
    SECTION("Options aggregate initialization");

    // Brace initialization
    ida::OperationOptions o{.strict_validation = false, .allow_partial_results = true,
                            .cancel_on_user_break = false, .quiet = false};
    CHECK(!o.strict_validation);
    CHECK(o.allow_partial_results);
    CHECK(!o.cancel_on_user_break);
    CHECK(!o.quiet);

    ida::RangeOptions r{.start = 0, .end = 100, .inclusive_end = true};
    CHECK(r.start == 0);
    CHECK(r.end == 100);
    CHECK(r.inclusive_end);

    ida::WaitOptions w{.timeout_ms = 1000, .poll_interval_ms = 5};
    CHECK(w.timeout_ms == 1000);
    CHECK(w.poll_interval_ms == 5);
}

// ── Stress: many options created ────────────────────────────────────────

void test_options_stress() {
    SECTION("Options stress");

    std::vector<ida::OperationOptions> ops(10000);
    CHECK(ops.size() == 10000);
    CHECK(ops[0].strict_validation == true);
    CHECK(ops[9999].quiet == true);

    std::vector<ida::RangeOptions> ranges(10000);
    CHECK(ranges[0].start == ida::BadAddress);
    CHECK(ranges[9999].end == ida::BadAddress);
}

} // namespace

int main() {
    test_operation_options_defaults();
    test_operation_options_mutation();
    test_operation_options_copy();
    test_range_options_defaults();
    test_range_options_mutation();
    test_range_options_copy();
    test_wait_options_defaults();
    test_wait_options_mutation();
    test_wait_options_copy();
    test_options_aggregate();
    test_options_stress();

    return idax_test::report("core_options_torture_test");
}
