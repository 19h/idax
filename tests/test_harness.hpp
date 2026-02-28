/// \file test_harness.hpp
/// \brief Shared test utilities for all idax C++ tests.
///
/// Consolidates the CHECK/CHECK_OK/CHECK_VAL/CHECK_ERR macros, test counters,
/// and common helpers used across unit and integration tests.

#ifndef IDAX_TEST_HARNESS_HPP
#define IDAX_TEST_HARNESS_HPP

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <chrono>
#include <functional>
#include <vector>
#include <sstream>
#include <type_traits>

namespace idax_test {

// ── Global test counters ────────────────────────────────────────────────

inline int g_pass = 0;
inline int g_fail = 0;
inline int g_skip = 0;

// ── Section tracking ────────────────────────────────────────────────────

inline std::string g_current_section;

inline void begin_section(const char* name) {
    g_current_section = name;
    std::cout << "\n=== " << name << " ===\n";
}

// ── Core check functions ────────────────────────────────────────────────

inline void check(bool ok, const char* expr, const char* file, int line) {
    if (ok) {
        ++g_pass;
    } else {
        ++g_fail;
        std::cerr << "[FAIL] " << file << ":" << line << ": " << expr << "\n";
    }
}

inline void skip(const char* reason, const char* file, int line) {
    ++g_skip;
    std::cout << "[SKIP] " << file << ":" << line << ": " << reason << "\n";
}

// ── Report ──────────────────────────────────────────────────────────────

inline int report(const char* test_name) {
    std::cout << "\n" << test_name << ": "
              << g_pass << " passed, "
              << g_fail << " failed";
    if (g_skip > 0) {
        std::cout << ", " << g_skip << " skipped";
    }
    std::cout << "\n";
    return g_fail > 0 ? 1 : 0;
}

// ── Timer utility ───────────────────────────────────────────────────────

struct Timer {
    std::chrono::steady_clock::time_point start;
    const char* label;

    Timer(const char* l) : start(std::chrono::steady_clock::now()), label(l) {}
    ~Timer() {
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        std::cout << "  [timer] " << label << ": " << ms << " ms\n";
    }
};

} // namespace idax_test

// ── Macros ──────────────────────────────────────────────────────────────

/// Basic boolean check.
#define CHECK(expr) \
    idax_test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

/// Check that a std::expected (Result/Status) has a value.
#define CHECK_OK(expr) \
    do { \
        auto&& _r = (expr); \
        if (_r.has_value()) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #expr << " -> error: " \
                      << _r.error().message << " [" << _r.error().context << "]\n"; \
        } \
    } while (0)

/// Check that a std::expected has a value AND the value satisfies a predicate.
#define CHECK_VAL(expr, value_check) \
    do { \
        auto&& _r = (expr); \
        if (_r.has_value()) { \
            auto&& _v = *_r; \
            if (value_check) { \
                ++idax_test::g_pass; \
            } else { \
                ++idax_test::g_fail; \
                std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                          << ": " << #expr << " value check failed: " << #value_check << "\n"; \
            } \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #expr << " -> error: " \
                      << _r.error().message << " [" << _r.error().context << "]\n"; \
        } \
    } while (0)

/// Check that a std::expected has an error of a specific category.
#define CHECK_ERR(expr, cat) \
    do { \
        auto&& _r = (expr); \
        if (!_r.has_value() && _r.error().category == (cat)) { \
            ++idax_test::g_pass; \
        } else if (_r.has_value()) { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #expr << " expected error " << #cat << " but got success\n"; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #expr << " expected error " << #cat \
                      << " but got different error: " << _r.error().message << "\n"; \
        } \
    } while (0)

/// Check that a std::expected has any error (category-agnostic).
#define CHECK_IS_ERR(expr) \
    do { \
        auto&& _r = (expr); \
        if (!_r.has_value()) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #expr << " expected error but got success\n"; \
        } \
    } while (0)

/// Check equality of two values.
#define CHECK_EQ(a, b) \
    do { \
        auto&& _a = (a); \
        auto&& _b = (b); \
        if (_a == _b) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #a << " == " << #b << "\n"; \
        } \
    } while (0)

/// Check inequality.
#define CHECK_NE(a, b) \
    do { \
        auto&& _a = (a); \
        auto&& _b = (b); \
        if (_a != _b) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #a << " != " << #b << "\n"; \
        } \
    } while (0)

/// Check that a < b.
#define CHECK_LT(a, b) \
    do { \
        auto&& _a = (a); \
        auto&& _b = (b); \
        if (_a < _b) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #a << " < " << #b << "\n"; \
        } \
    } while (0)

/// Check that a > b.
#define CHECK_GT(a, b) \
    do { \
        auto&& _a = (a); \
        auto&& _b = (b); \
        if (_a > _b) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": " << #a << " > " << #b << "\n"; \
        } \
    } while (0)

/// Check that a string contains a substring.
#define CHECK_CONTAINS(haystack, needle) \
    do { \
        std::string _h(haystack); \
        std::string _n(needle); \
        if (_h.find(_n) != std::string::npos) { \
            ++idax_test::g_pass; \
        } else { \
            ++idax_test::g_fail; \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ \
                      << ": string does not contain \"" << _n << "\"\n"; \
        } \
    } while (0)

/// Skip a test with a reason.
#define SKIP(reason) \
    idax_test::skip(reason, __FILE__, __LINE__)

/// Begin a named test section.
#define SECTION(name) \
    idax_test::begin_section(name)

#endif // IDAX_TEST_HARNESS_HPP
