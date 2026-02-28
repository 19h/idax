/// \file error_torture_test.cpp
/// \brief Exhaustive offline unit tests for ida::Error, ida::Result<T>, ida::Status.
///
/// Tests every Error constructor, factory method, field, edge case,
/// Result/Status algebra, ok() helper, and expected-based patterns.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <string>
#include <vector>
#include <optional>

namespace {

// ── Error factory constructors ──────────────────────────────────────────

void test_error_factories() {
    SECTION("Error factory constructors");

    // validation
    {
        auto e = ida::Error::validation("bad input", "ctx");
        CHECK(e.category == ida::ErrorCategory::Validation);
        CHECK(e.message == "bad input");
        CHECK(e.context == "ctx");
        CHECK(e.code == 0);
    }

    // not_found
    {
        auto e = ida::Error::not_found("missing", "lookup");
        CHECK(e.category == ida::ErrorCategory::NotFound);
        CHECK(e.message == "missing");
        CHECK(e.context == "lookup");
    }

    // conflict
    {
        auto e = ida::Error::conflict("already exists", "create");
        CHECK(e.category == ida::ErrorCategory::Conflict);
        CHECK(e.message == "already exists");
        CHECK(e.context == "create");
    }

    // unsupported
    {
        auto e = ida::Error::unsupported("not available", "feature");
        CHECK(e.category == ida::ErrorCategory::Unsupported);
        CHECK(e.message == "not available");
        CHECK(e.context == "feature");
    }

    // sdk
    {
        auto e = ida::Error::sdk("SDK error", "call");
        CHECK(e.category == ida::ErrorCategory::SdkFailure);
        CHECK(e.message == "SDK error");
        CHECK(e.context == "call");
    }

    // internal
    {
        auto e = ida::Error::internal("bug", "");
        CHECK(e.category == ida::ErrorCategory::Internal);
        CHECK(e.message == "bug");
        CHECK(e.context.empty());
    }
}

// ── Error with empty strings ────────────────────────────────────────────

void test_error_empty_strings() {
    SECTION("Error with empty strings");

    auto e1 = ida::Error::validation("", "");
    CHECK(e1.message.empty());
    CHECK(e1.context.empty());
    CHECK(e1.category == ida::ErrorCategory::Validation);

    auto e2 = ida::Error::internal("");
    CHECK(e2.context.empty());
}

// ── Error with very long strings ────────────────────────────────────────

void test_error_long_strings() {
    SECTION("Error with long strings");

    std::string long_msg(10000, 'x');
    std::string long_ctx(10000, 'y');

    auto e = ida::Error::validation(long_msg, long_ctx);
    CHECK(e.message.size() == 10000);
    CHECK(e.context.size() == 10000);
    CHECK(e.message == long_msg);
    CHECK(e.context == long_ctx);
}

// ── Error with special characters ───────────────────────────────────────

void test_error_special_chars() {
    SECTION("Error with special characters");

    auto e = ida::Error::validation("msg with\nnewline\ttab", "ctx with \"quotes\"");
    CHECK_CONTAINS(e.message, "\n");
    CHECK_CONTAINS(e.message, "\t");
    CHECK_CONTAINS(e.context, "\"");

    // Unicode
    auto e2 = ida::Error::validation("error: über", "ctx: ñ");
    CHECK_CONTAINS(e2.message, "über");
}

// ── Error copy/move semantics ───────────────────────────────────────────

void test_error_copy_move() {
    SECTION("Error copy/move semantics");

    auto e1 = ida::Error::validation("original", "ctx");

    // Copy
    auto e2 = e1;
    CHECK(e2.category == ida::ErrorCategory::Validation);
    CHECK(e2.message == "original");
    CHECK(e2.context == "ctx");
    CHECK(e1.message == "original"); // original unchanged

    // Move
    auto e3 = std::move(e1);
    CHECK(e3.category == ida::ErrorCategory::Validation);
    CHECK(e3.message == "original");
    CHECK(e3.context == "ctx");
}

// ── Error default construction ──────────────────────────────────────────

void test_error_default() {
    SECTION("Error default construction");

    ida::Error e{};
    CHECK(e.category == ida::ErrorCategory::Internal);
    CHECK(e.code == 0);
    CHECK(e.message.empty());
    CHECK(e.context.empty());
}

// ── ErrorCategory values ────────────────────────────────────────────────

void test_error_category_values() {
    SECTION("ErrorCategory enum values");

    // Verify all variants exist and are distinct
    std::vector<ida::ErrorCategory> cats = {
        ida::ErrorCategory::Validation,
        ida::ErrorCategory::NotFound,
        ida::ErrorCategory::Conflict,
        ida::ErrorCategory::Unsupported,
        ida::ErrorCategory::SdkFailure,
        ida::ErrorCategory::Internal,
    };

    for (size_t i = 0; i < cats.size(); ++i) {
        for (size_t j = i + 1; j < cats.size(); ++j) {
            CHECK(cats[i] != cats[j]);
        }
    }
}

// ── Result<T> success paths ─────────────────────────────────────────────

void test_result_success() {
    SECTION("Result<T> success paths");

    // int
    ida::Result<int> r1 = 42;
    CHECK(r1.has_value());
    CHECK(*r1 == 42);

    // string
    ida::Result<std::string> r2 = std::string("hello");
    CHECK(r2.has_value());
    CHECK(*r2 == "hello");

    // bool
    ida::Result<bool> r3 = true;
    CHECK(r3.has_value());
    CHECK(*r3 == true);

    // vector
    ida::Result<std::vector<int>> r4 = std::vector<int>{1, 2, 3};
    CHECK(r4.has_value());
    CHECK(r4->size() == 3);

    // uint64
    ida::Result<uint64_t> r5 = uint64_t(0xFFFFFFFFFFFFFFFF);
    CHECK(r5.has_value());
    CHECK(*r5 == 0xFFFFFFFFFFFFFFFF);

    // zero
    ida::Result<int> r6 = 0;
    CHECK(r6.has_value());
    CHECK(*r6 == 0);
}

// ── Result<T> error paths ───────────────────────────────────────────────

void test_result_error() {
    SECTION("Result<T> error paths");

    ida::Result<int> r1 = std::unexpected(ida::Error::validation("bad"));
    CHECK(!r1.has_value());
    CHECK(r1.error().category == ida::ErrorCategory::Validation);
    CHECK(r1.error().message == "bad");

    ida::Result<std::string> r2 = std::unexpected(ida::Error::not_found("missing"));
    CHECK(!r2.has_value());
    CHECK(r2.error().category == ida::ErrorCategory::NotFound);
}

// ── Status success/error ────────────────────────────────────────────────

void test_status() {
    SECTION("Status success/error");

    // ok()
    ida::Status s1 = ida::ok();
    CHECK(s1.has_value());

    // Error
    ida::Status s2 = std::unexpected(ida::Error::internal("fail"));
    CHECK(!s2.has_value());
    CHECK(s2.error().category == ida::ErrorCategory::Internal);

    // Direct construction
    ida::Status s3{};
    CHECK(s3.has_value());
}

// ── Result monadic operations ───────────────────────────────────────────

void test_result_monadic() {
    SECTION("Result monadic operations");

    // transform (map)
    ida::Result<int> r1 = 42;
    auto r2 = r1.transform([](int v) { return v * 2; });
    CHECK(r2.has_value());
    CHECK(*r2 == 84);

    // transform on error
    ida::Result<int> r3 = std::unexpected(ida::Error::validation("bad"));
    auto r4 = r3.transform([](int v) { return v * 2; });
    CHECK(!r4.has_value());

    // and_then (flat_map)
    ida::Result<int> r5 = 42;
    auto r6 = r5.and_then([](int v) -> ida::Result<std::string> {
        return std::to_string(v);
    });
    CHECK(r6.has_value());
    CHECK(*r6 == "42");

    // and_then propagating error
    ida::Result<int> r7 = std::unexpected(ida::Error::internal("x"));
    auto r8 = r7.and_then([](int v) -> ida::Result<std::string> {
        return std::to_string(v);
    });
    CHECK(!r8.has_value());

    // value_or
    ida::Result<int> r9 = std::unexpected(ida::Error::validation("x"));
    CHECK(r9.value_or(99) == 99);

    ida::Result<int> r10 = 42;
    CHECK(r10.value_or(99) == 42);
}

// ── Error code field ────────────────────────────────────────────────────

void test_error_code_field() {
    SECTION("Error code field");

    ida::Error e{ida::ErrorCategory::SdkFailure, 404, "not found", ""};
    CHECK(e.code == 404);
    CHECK(e.category == ida::ErrorCategory::SdkFailure);

    ida::Error e2{ida::ErrorCategory::Internal, -1, "negative code", ""};
    CHECK(e2.code == -1);

    ida::Error e3{ida::ErrorCategory::Validation, 0, "", ""};
    CHECK(e3.code == 0);

    // Max int
    ida::Error e4{ida::ErrorCategory::Internal, INT32_MAX, "", ""};
    CHECK(e4.code == INT32_MAX);

    // Min int
    ida::Error e5{ida::ErrorCategory::Internal, INT32_MIN, "", ""};
    CHECK(e5.code == INT32_MIN);
}

// ── Stress: many errors ─────────────────────────────────────────────────

void test_error_stress() {
    SECTION("Error creation stress");

    constexpr int N = 10000;
    std::vector<ida::Error> errors;
    errors.reserve(N);

    for (int i = 0; i < N; ++i) {
        errors.push_back(ida::Error::validation(
            "error #" + std::to_string(i),
            "ctx #" + std::to_string(i)
        ));
    }

    CHECK(errors.size() == N);
    CHECK(errors[0].message == "error #0");
    CHECK(errors[N - 1].message == "error #" + std::to_string(N - 1));
    CHECK(errors[N / 2].category == ida::ErrorCategory::Validation);
}

// ── Result<T> with move-only types ──────────────────────────────────────

void test_result_move_only() {
    SECTION("Result with move-only types");

    struct MoveOnly {
        int value;
        MoveOnly(int v) : value(v) {}
        MoveOnly(const MoveOnly&) = delete;
        MoveOnly& operator=(const MoveOnly&) = delete;
        MoveOnly(MoveOnly&&) = default;
        MoveOnly& operator=(MoveOnly&&) = default;
    };

    ida::Result<MoveOnly> r = MoveOnly(42);
    CHECK(r.has_value());
    CHECK(r->value == 42);

    auto r2 = std::move(r);
    CHECK(r2.has_value());
    CHECK(r2->value == 42);
}

} // namespace

int main() {
    test_error_factories();
    test_error_empty_strings();
    test_error_long_strings();
    test_error_special_chars();
    test_error_copy_move();
    test_error_default();
    test_error_category_values();
    test_result_success();
    test_result_error();
    test_status();
    test_result_monadic();
    test_error_code_field();
    test_error_stress();
    test_result_move_only();

    return idax_test::report("error_torture_test");
}
