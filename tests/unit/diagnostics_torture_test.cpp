/// \file diagnostics_torture_test.cpp
/// \brief Exhaustive offline unit tests for ida::diagnostics.
///
/// Tests log levels, counters, invariant assertions, error enrichment,
/// stress logging, and edge cases.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <string>
#include <thread>

namespace {

using namespace ida::diagnostics;

// ── Log level roundtrip ─────────────────────────────────────────────────

void test_log_level_roundtrip() {
    SECTION("Log level roundtrip");

    auto levels = {LogLevel::Error, LogLevel::Warning, LogLevel::Info,
                   LogLevel::Debug, LogLevel::Trace};
    for (auto level : levels) {
        auto s = set_log_level(level);
        CHECK(s.has_value());
        CHECK(log_level() == level);
    }
}

// ── Log level ordering ──────────────────────────────────────────────────

void test_log_level_ordering() {
    SECTION("Log level ordering");

    CHECK(static_cast<int>(LogLevel::Error) == 0);
    CHECK(static_cast<int>(LogLevel::Warning) == 1);
    CHECK(static_cast<int>(LogLevel::Info) == 2);
    CHECK(static_cast<int>(LogLevel::Debug) == 3);
    CHECK(static_cast<int>(LogLevel::Trace) == 4);

    // Ordering
    CHECK(LogLevel::Error < LogLevel::Warning);
    CHECK(LogLevel::Warning < LogLevel::Info);
    CHECK(LogLevel::Info < LogLevel::Debug);
    CHECK(LogLevel::Debug < LogLevel::Trace);
}

// ── Performance counters ────────────────────────────────────────────────

void test_performance_counters() {
    SECTION("Performance counters reset and increment");

    reset_performance_counters();
    auto c0 = performance_counters();
    CHECK(c0.log_messages == 0);
    CHECK(c0.invariant_failures == 0);

    // Log some messages
    set_log_level(LogLevel::Trace);
    log(LogLevel::Info, "test", "message 1");
    log(LogLevel::Debug, "test", "message 2");
    log(LogLevel::Trace, "test", "message 3");

    auto c1 = performance_counters();
    CHECK(c1.log_messages >= 3);

    // Trigger invariant failure
    auto inv = assert_invariant(false, "expected to fail");
    CHECK(!inv.has_value());

    auto c2 = performance_counters();
    CHECK(c2.invariant_failures >= 1);
}

// ── Invariant assertions ────────────────────────────────────────────────

void test_invariant_assertions() {
    SECTION("Invariant assertions");

    // True => ok
    auto ok_result = assert_invariant(true, "this is fine");
    CHECK(ok_result.has_value());

    // False => error
    auto bad_result = assert_invariant(false, "this is broken");
    CHECK(!bad_result.has_value());
    CHECK(bad_result.error().category == ida::ErrorCategory::Internal);
    CHECK_CONTAINS(bad_result.error().message, "invariant");
}

// ── Error enrichment ────────────────────────────────────────────────────

void test_error_enrichment() {
    SECTION("Error enrichment");

    // Enrich empty context
    auto e1 = enrich(ida::Error::internal("msg", ""), "added ctx");
    CHECK(e1.context == "added ctx");
    CHECK(e1.message == "msg");

    // Enrich existing context
    auto e2 = enrich(ida::Error::internal("msg", "base"), "extra");
    CHECK_CONTAINS(e2.context, "base");
    CHECK_CONTAINS(e2.context, "extra");

    // Chain enrichments
    auto e3 = enrich(enrich(ida::Error::validation("m", "a"), "b"), "c");
    CHECK_CONTAINS(e3.context, "a");
    CHECK_CONTAINS(e3.context, "b");
    CHECK_CONTAINS(e3.context, "c");
}

// ── Log with various domains ────────────────────────────────────────────

void test_log_various_domains() {
    SECTION("Log with various domains");

    set_log_level(LogLevel::Trace);
    reset_performance_counters();

    // Normal domains
    log(LogLevel::Error, "database", "error message");
    log(LogLevel::Warning, "segment", "warning message");
    log(LogLevel::Info, "function", "info message");
    log(LogLevel::Debug, "instruction", "debug message");
    log(LogLevel::Trace, "xref", "trace message");

    auto c = performance_counters();
    CHECK(c.log_messages >= 5);
}

// ── Log with empty strings ──────────────────────────────────────────────

void test_log_empty_strings() {
    SECTION("Log with empty strings");

    set_log_level(LogLevel::Trace);
    reset_performance_counters();

    // Empty domain and message
    log(LogLevel::Info, "", "");
    log(LogLevel::Debug, "domain", "");
    log(LogLevel::Trace, "", "message");

    auto c = performance_counters();
    CHECK(c.log_messages >= 3);
}

// ── Stress: many log messages ───────────────────────────────────────────

void test_log_stress() {
    SECTION("Log stress test");

    set_log_level(LogLevel::Trace);
    reset_performance_counters();

    constexpr int N = 1000;
    for (int i = 0; i < N; ++i) {
        log(LogLevel::Trace, "stress", "message " + std::to_string(i));
    }

    auto c = performance_counters();
    CHECK(c.log_messages >= static_cast<uint64_t>(N));
}

// ── Counter reset idempotent ────────────────────────────────────────────

void test_counter_reset_idempotent() {
    SECTION("Counter reset idempotent");

    reset_performance_counters();
    auto c1 = performance_counters();
    CHECK(c1.log_messages == 0);
    CHECK(c1.invariant_failures == 0);

    reset_performance_counters();
    auto c2 = performance_counters();
    CHECK(c2.log_messages == 0);
    CHECK(c2.invariant_failures == 0);
}

// ── Multiple invariant failures ─────────────────────────────────────────

void test_multiple_invariant_failures() {
    SECTION("Multiple invariant failures");

    reset_performance_counters();

    for (int i = 0; i < 50; ++i) {
        auto r = assert_invariant(false, "fail #" + std::to_string(i));
        CHECK(!r.has_value());
    }

    auto c = performance_counters();
    CHECK(c.invariant_failures >= 50);
}

// ── Log level filtering (higher levels not counted when filtered) ────────

void test_log_level_filtering() {
    SECTION("Log level filtering");

    // Set to Error — only Error messages should be processed
    set_log_level(LogLevel::Error);
    reset_performance_counters();

    log(LogLevel::Error, "test", "this should log");
    log(LogLevel::Warning, "test", "this may be filtered");
    log(LogLevel::Info, "test", "this may be filtered");
    log(LogLevel::Debug, "test", "this may be filtered");
    log(LogLevel::Trace, "test", "this may be filtered");

    auto c = performance_counters();
    // At minimum the Error message should be counted
    CHECK(c.log_messages >= 1);
}

// ── Enrich preserves category ───────────────────────────────────────────

void test_enrich_preserves_category() {
    SECTION("Enrich preserves category and code");

    auto base = ida::Error{ida::ErrorCategory::SdkFailure, 42, "sdk error", "original"};
    auto enriched = enrich(base, "additional info");

    CHECK(enriched.category == ida::ErrorCategory::SdkFailure);
    CHECK(enriched.code == 42);
    CHECK(enriched.message == "sdk error");
    CHECK_CONTAINS(enriched.context, "original");
    CHECK_CONTAINS(enriched.context, "additional info");
}

} // namespace

int main() {
    test_log_level_roundtrip();
    test_log_level_ordering();
    test_performance_counters();
    test_invariant_assertions();
    test_error_enrichment();
    test_log_various_domains();
    test_log_empty_strings();
    test_log_stress();
    test_counter_reset_idempotent();
    test_multiple_invariant_failures();
    test_log_level_filtering();
    test_enrich_preserves_category();

    return idax_test::report("diagnostics_torture_test");
}
