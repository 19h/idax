/// \file diagnostics_bind.cpp
/// \brief NAN bindings for ida::diagnostics — logging, invariants, and counters.

#include "helpers.hpp"
#include <ida/diagnostics.hpp>

namespace idax_node {
namespace {

// ── LogLevel string <-> enum conversion ─────────────────────────────────

static const char* LogLevelToString(ida::diagnostics::LogLevel level) {
    switch (level) {
        case ida::diagnostics::LogLevel::Error:   return "error";
        case ida::diagnostics::LogLevel::Warning: return "warning";
        case ida::diagnostics::LogLevel::Info:    return "info";
        case ida::diagnostics::LogLevel::Debug:   return "debug";
        case ida::diagnostics::LogLevel::Trace:   return "trace";
    }
    return "info";
}

static bool StringToLogLevel(const std::string& s, ida::diagnostics::LogLevel& out) {
    if (s == "error")   { out = ida::diagnostics::LogLevel::Error;   return true; }
    if (s == "warning") { out = ida::diagnostics::LogLevel::Warning; return true; }
    if (s == "info")    { out = ida::diagnostics::LogLevel::Info;    return true; }
    if (s == "debug")   { out = ida::diagnostics::LogLevel::Debug;   return true; }
    if (s == "trace")   { out = ida::diagnostics::LogLevel::Trace;   return true; }
    return false;
}

// ── NAN methods ─────────────────────────────────────────────────────────

// setLogLevel(level: string)
NAN_METHOD(SetLogLevel) {
    std::string levelStr;
    if (!GetStringArg(info, 0, levelStr)) return;

    ida::diagnostics::LogLevel level;
    if (!StringToLogLevel(levelStr, level)) {
        Nan::ThrowTypeError("Invalid log level: expected 'error', 'warning', 'info', 'debug', or 'trace'");
        return;
    }

    IDAX_CHECK_STATUS(ida::diagnostics::set_log_level(level));
}

// logLevel() -> string
NAN_METHOD(GetLogLevel) {
    auto level = ida::diagnostics::log_level();
    info.GetReturnValue().Set(FromString(LogLevelToString(level)));
}

// log(level: string, domain: string, message: string)
NAN_METHOD(Log) {
    std::string levelStr;
    if (!GetStringArg(info, 0, levelStr)) return;

    ida::diagnostics::LogLevel level;
    if (!StringToLogLevel(levelStr, level)) {
        Nan::ThrowTypeError("Invalid log level: expected 'error', 'warning', 'info', 'debug', or 'trace'");
        return;
    }

    std::string domain;
    if (!GetStringArg(info, 1, domain)) return;

    std::string message;
    if (!GetStringArg(info, 2, message)) return;

    ida::diagnostics::log(level, domain, message);
}

// assertInvariant(condition: bool, message: string)
NAN_METHOD(AssertInvariant) {
    if (info.Length() < 1 || !info[0]->IsBoolean()) {
        Nan::ThrowTypeError("Expected boolean condition argument");
        return;
    }
    bool condition = Nan::To<bool>(info[0]).FromJust();

    std::string message;
    if (!GetStringArg(info, 1, message)) return;

    IDAX_CHECK_STATUS(ida::diagnostics::assert_invariant(condition, message));
}

// resetPerformanceCounters()
NAN_METHOD(ResetPerformanceCounters) {
    ida::diagnostics::reset_performance_counters();
}

// performanceCounters() -> { logMessages: number, invariantFailures: number }
NAN_METHOD(GetPerformanceCounters) {
    auto counters = ida::diagnostics::performance_counters();

    auto obj = ObjectBuilder()
        .setSize("logMessages", static_cast<std::size_t>(counters.log_messages))
        .setSize("invariantFailures", static_cast<std::size_t>(counters.invariant_failures))
        .build();

    info.GetReturnValue().Set(obj);
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitDiagnostics(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "diagnostics");

    SetMethod(ns, "setLogLevel",              SetLogLevel);
    SetMethod(ns, "logLevel",                 GetLogLevel);
    SetMethod(ns, "log",                      Log);
    SetMethod(ns, "assertInvariant",          AssertInvariant);
    SetMethod(ns, "resetPerformanceCounters", ResetPerformanceCounters);
    SetMethod(ns, "performanceCounters",      GetPerformanceCounters);
}

} // namespace idax_node
