/// \file debugger.hpp
/// \brief Debugger control: process/thread lifecycle, breakpoints, memory.

#ifndef IDAX_DEBUGGER_HPP
#define IDAX_DEBUGGER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ida::debugger {

enum class ProcessState {
    NoProcess,
    Running,
    Suspended,
};

Status start(std::string_view path = {},
             std::string_view args = {},
             std::string_view working_dir = {});
Status attach(int pid);
Status detach();
Status terminate();

Status suspend();
Status resume();
Status step_into();
Status step_over();
Status step_out();
Status run_to(Address ea);

Result<ProcessState> state();

/// Current instruction pointer (program counter).
Result<Address> instruction_pointer();

/// Current stack pointer.
Result<Address> stack_pointer();

/// Read a CPU register by name (as uint64_t).
Result<std::uint64_t> register_value(std::string_view reg_name);

/// Write a CPU register by name.
Status set_register(std::string_view reg_name, std::uint64_t value);

Status add_breakpoint(Address ea);
Status remove_breakpoint(Address ea);
Result<bool> has_breakpoint(Address ea);

Result<std::vector<std::uint8_t>> read_memory(Address ea, AddressSize size);
Status write_memory(Address ea, std::span<const std::uint8_t> bytes);

// ── Debugger event subscriptions ────────────────────────────────────────

using DebuggerToken = std::uint64_t;

/// Module info delivered with process/library events.
struct ModuleInfo {
    std::string name;
    Address     base{};
    AddressSize size{};
};

/// Exception info delivered with the exception event.
struct ExceptionInfo {
    Address       ea{};
    std::uint32_t code{};
    bool          can_continue{false};
    std::string   message;
};

/// Breakpoint change kind (for on_breakpoint_changed).
enum class BreakpointChange {
    Added,
    Removed,
    Changed,
};

// ── Tier 1: Essential events ────────────────────────────────────────────

/// New process started (or loaded). Callback receives module info of the main module.
Result<DebuggerToken> on_process_started(
    std::function<void(const ModuleInfo&)> callback);

/// Process exited. Callback receives the exit code.
Result<DebuggerToken> on_process_exited(
    std::function<void(int exit_code)> callback);

/// Process suspended (e.g. after a step, breakpoint, or explicit suspend).
Result<DebuggerToken> on_process_suspended(
    std::function<void(Address ea)> callback);

/// A user-defined breakpoint was hit.
Result<DebuggerToken> on_breakpoint_hit(
    std::function<void(int thread_id, Address ea)> callback);

/// One instruction was step-traced. Return true to suppress logging.
/// Only fires when step tracing is enabled.
Result<DebuggerToken> on_trace(
    std::function<bool(int thread_id, Address ip)> callback);

/// An exception occurred during debugging.
Result<DebuggerToken> on_exception(
    std::function<void(const ExceptionInfo&)> callback);

// ── Tier 2: Thread/library lifecycle ────────────────────────────────────

/// New thread started. Callback receives thread ID and name.
Result<DebuggerToken> on_thread_started(
    std::function<void(int thread_id, std::string name)> callback);

/// Thread exited. Callback receives thread ID and exit code.
Result<DebuggerToken> on_thread_exited(
    std::function<void(int thread_id, int exit_code)> callback);

/// Library loaded. Callback receives module info.
Result<DebuggerToken> on_library_loaded(
    std::function<void(const ModuleInfo&)> callback);

/// Library unloaded. Callback receives library name.
Result<DebuggerToken> on_library_unloaded(
    std::function<void(std::string name)> callback);

// ── Tier 3: Async completion & breakpoint management ────────────────────

/// Breakpoint was added/removed/changed in the breakpoint list.
Result<DebuggerToken> on_breakpoint_changed(
    std::function<void(BreakpointChange change, Address ea)> callback);

/// Unsubscribe a debugger event by token.
Status debugger_unsubscribe(DebuggerToken token);

/// RAII guard that unsubscribes a debugger event on destruction.
class ScopedDebuggerSubscription {
public:
    explicit ScopedDebuggerSubscription(DebuggerToken token) : token_(token) {}
    ~ScopedDebuggerSubscription() { debugger_unsubscribe(token_); }

    ScopedDebuggerSubscription(const ScopedDebuggerSubscription&) = delete;
    ScopedDebuggerSubscription& operator=(const ScopedDebuggerSubscription&) = delete;
    ScopedDebuggerSubscription(ScopedDebuggerSubscription&& o) noexcept : token_(o.token_) { o.token_ = 0; }
    ScopedDebuggerSubscription& operator=(ScopedDebuggerSubscription&& o) noexcept {
        if (this != &o) { debugger_unsubscribe(token_); token_ = o.token_; o.token_ = 0; }
        return *this;
    }

    [[nodiscard]] DebuggerToken token() const noexcept { return token_; }

private:
    DebuggerToken token_{0};
};

} // namespace ida::debugger

#endif // IDAX_DEBUGGER_HPP
