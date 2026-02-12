/// \file diagnostics.cpp
/// \brief Implementation of shared diagnostics/logging helpers.

#include <ida/diagnostics.hpp>

#include <atomic>
#include <iostream>
#include <mutex>

namespace ida::diagnostics {

namespace {

std::atomic<LogLevel> g_level{LogLevel::Warning};
std::mutex g_io_mutex;
PerformanceCounters g_counters;

const char* level_name(LogLevel level) {
    switch (level) {
        case LogLevel::Error:   return "error";
        case LogLevel::Warning: return "warning";
        case LogLevel::Info:    return "info";
        case LogLevel::Debug:   return "debug";
        case LogLevel::Trace:   return "trace";
    }
    return "unknown";
}

} // namespace

Status set_log_level(LogLevel level) {
    g_level.store(level, std::memory_order_relaxed);
    return ida::ok();
}

LogLevel log_level() {
    return g_level.load(std::memory_order_relaxed);
}

void log(LogLevel level, std::string_view domain, std::string_view message) {
    if (static_cast<int>(level) > static_cast<int>(log_level()))
        return;

    {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        std::cerr << "[idax][" << level_name(level) << "][" << domain << "] "
                  << message << "\n";
    }
    ++g_counters.log_messages;
}

Error enrich(Error base, std::string_view context_suffix) {
    if (!base.context.empty())
        base.context += " | ";
    base.context += std::string(context_suffix);
    return base;
}

Status assert_invariant(bool condition, std::string_view message) {
    if (condition)
        return ida::ok();

    ++g_counters.invariant_failures;
    log(LogLevel::Error, "invariant", message);
    return std::unexpected(Error::internal("Invariant failed", std::string(message)));
}

void reset_performance_counters() {
    g_counters = {};
}

PerformanceCounters performance_counters() {
    return g_counters;
}

} // namespace ida::diagnostics
