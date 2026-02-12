/// \file diagnostics.hpp
/// \brief Shared diagnostics, logging, and lightweight counters.

#ifndef IDAX_DIAGNOSTICS_HPP
#define IDAX_DIAGNOSTICS_HPP

#include <ida/error.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace ida::diagnostics {

enum class LogLevel {
    Error = 0,
    Warning,
    Info,
    Debug,
    Trace,
};

struct PerformanceCounters {
    std::uint64_t log_messages{0};
    std::uint64_t invariant_failures{0};
};

Status set_log_level(LogLevel level);
LogLevel log_level();

void log(LogLevel level, std::string_view domain, std::string_view message);

/// Enrich an existing error with additional context text.
Error enrich(Error base, std::string_view context_suffix);

/// Assertion-like invariant helper for non-obvious runtime expectations.
Status assert_invariant(bool condition, std::string_view message);

void reset_performance_counters();
PerformanceCounters performance_counters();

} // namespace ida::diagnostics

#endif // IDAX_DIAGNOSTICS_HPP
