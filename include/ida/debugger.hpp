/// \file debugger.hpp
/// \brief Debugger control: process/thread lifecycle, breakpoints, memory.

#ifndef IDAX_DEBUGGER_HPP
#define IDAX_DEBUGGER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <ida/type.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
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

struct BackendInfo {
    std::string name;
    std::string display_name;
    bool remote{false};
    bool supports_appcall{false};
    bool supports_attach{false};
    bool loaded{false};
};

/// Enumerate available debugger backends discovered by IDA.
Result<std::vector<BackendInfo>> available_backends();

/// Return the currently loaded debugger backend.
///
/// Returns `NotFound` when no backend is loaded.
Result<BackendInfo> current_backend();

/// Load a debugger backend by name.
///
/// \p backend_name can match either backend short name or display name.
Status load_backend(std::string_view backend_name, bool use_remote = false);

Status start(std::string_view path = {},
             std::string_view args = {},
             std::string_view working_dir = {});
Status request_start(std::string_view path = {},
                     std::string_view args = {},
                     std::string_view working_dir = {});
Status attach(int pid);
Status request_attach(int pid, int event_id = -1);
Status detach();
Status terminate();

Status suspend();
Status resume();
Status step_into();
Status step_over();
Status step_out();
Status run_to(Address address);

Result<ProcessState> state();

/// Current instruction pointer (program counter).
Result<Address> instruction_pointer();

/// Current stack pointer.
Result<Address> stack_pointer();

/// Read a CPU register by name (as uint64_t).
Result<std::uint64_t> register_value(std::string_view reg_name);

/// Write a CPU register by name.
Status set_register(std::string_view reg_name, std::uint64_t value);

Status add_breakpoint(Address address);
Status remove_breakpoint(Address address);
Result<bool> has_breakpoint(Address address);

Result<std::vector<std::uint8_t>> read_memory(Address address, AddressSize size);
Status write_memory(Address address, std::span<const std::uint8_t> bytes);

// ── Request-queue execution helpers ─────────────────────────────────────

/// True if there is a debugger request currently being processed.
bool is_request_running();

/// Execute queued debugger requests posted via `request_*` helpers.
Status run_requests();

Status request_suspend();
Status request_resume();
Status request_step_into();
Status request_step_over();
Status request_step_out();
Status request_run_to(Address address);

// ── Thread and register introspection ───────────────────────────────────

struct ThreadInfo {
    int         id{0};
    std::string name;
    bool        is_current{false};
};

struct RegisterInfo {
    std::string name;
    bool        read_only{false};
    bool        instruction_pointer{false};
    bool        stack_pointer{false};
    bool        frame_pointer{false};
    bool        may_contain_address{false};
    bool        custom_format{false};
};

Result<std::size_t> thread_count();
Result<int> thread_id_at(std::size_t index);
Result<std::string> thread_name_at(std::size_t index);
Result<int> current_thread_id();
Result<std::vector<ThreadInfo>> threads();

Status select_thread(int thread_id);
Status request_select_thread(int thread_id);
Status suspend_thread(int thread_id);
Status request_suspend_thread(int thread_id);
Status resume_thread(int thread_id);
Status request_resume_thread(int thread_id);

Result<RegisterInfo> register_info(std::string_view register_name);
Result<bool> is_integer_register(std::string_view register_name);
Result<bool> is_floating_register(std::string_view register_name);
Result<bool> is_custom_register(std::string_view register_name);

// ── Appcall + external executor surface ────────────────────────────────

enum class AppcallValueKind {
    SignedInteger,
    UnsignedInteger,
    FloatingPoint,
    String,
    Address,
    Boolean,
};

struct AppcallValue {
    AppcallValueKind kind{AppcallValueKind::SignedInteger};

    std::int64_t  signed_value{0};
    std::uint64_t unsigned_value{0};
    double        floating_value{0.0};
    std::string   string_value;
    Address       address_value{BadAddress};
    bool          boolean_value{false};
};

struct AppcallOptions {
    std::optional<int> thread_id;
    bool               manual{false};
    bool               include_debug_event{false};
    std::optional<std::uint32_t> timeout_milliseconds;
};

struct AppcallRequest {
    Address            function_address{BadAddress};
    ida::type::TypeInfo function_type;
    std::vector<AppcallValue> arguments;
    AppcallOptions      options;
};

struct AppcallResult {
    AppcallValue return_value;
    std::string  diagnostics;
};

class AppcallExecutor {
public:
    virtual ~AppcallExecutor() = default;
    virtual Result<AppcallResult> execute(const AppcallRequest& request) = 0;
};

/// Execute a debugger appcall through IDA's debugger backend.
Result<AppcallResult> appcall(const AppcallRequest& request);

/// Cleanup a manual appcall frame.
Status cleanup_appcall(std::optional<int> thread_id = std::nullopt);

/// Register an external appcall-style executor (for example emulation engines).
Status register_executor(std::string_view name,
                         std::shared_ptr<AppcallExecutor> executor);

/// Unregister a previously registered external executor.
Status unregister_executor(std::string_view name);

/// Execute through a named external executor.
Result<AppcallResult> appcall_with_executor(std::string_view name,
                                            const AppcallRequest& request);

// ── Debugger event subscriptions ────────────────────────────────────────

using Token = std::uint64_t;

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
Result<Token> on_process_started(
    std::function<void(const ModuleInfo&)> callback);

/// Process exited. Callback receives the exit code.
Result<Token> on_process_exited(
    std::function<void(int exit_code)> callback);

/// Process suspended (e.g. after a step, breakpoint, or explicit suspend).
Result<Token> on_process_suspended(
    std::function<void(Address address)> callback);

/// A user-defined breakpoint was hit.
Result<Token> on_breakpoint_hit(
    std::function<void(int thread_id, Address address)> callback);

/// One instruction was step-traced. Return true to suppress logging.
/// Only fires when step tracing is enabled.
Result<Token> on_trace(
    std::function<bool(int thread_id, Address ip)> callback);

/// An exception occurred during debugging.
Result<Token> on_exception(
    std::function<void(const ExceptionInfo&)> callback);

// ── Tier 2: Thread/library lifecycle ────────────────────────────────────

/// New thread started. Callback receives thread ID and name.
Result<Token> on_thread_started(
    std::function<void(int thread_id, std::string name)> callback);

/// Thread exited. Callback receives thread ID and exit code.
Result<Token> on_thread_exited(
    std::function<void(int thread_id, int exit_code)> callback);

/// Library loaded. Callback receives module info.
Result<Token> on_library_loaded(
    std::function<void(const ModuleInfo&)> callback);

/// Library unloaded. Callback receives library name.
Result<Token> on_library_unloaded(
    std::function<void(std::string name)> callback);

// ── Tier 3: Async completion & breakpoint management ────────────────────

/// Breakpoint was added/removed/changed in the breakpoint list.
Result<Token> on_breakpoint_changed(
    std::function<void(BreakpointChange change, Address address)> callback);

/// Unsubscribe a debugger event by token.
Status unsubscribe(Token token);

/// RAII guard that unsubscribes a debugger event on destruction.
class ScopedSubscription {
public:
    explicit ScopedSubscription(Token token) : token_(token) {}
    ~ScopedSubscription() { (void)unsubscribe(token_); }

    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;
    ScopedSubscription(ScopedSubscription&& o) noexcept : token_(o.token_) { o.token_ = 0; }
    ScopedSubscription& operator=(ScopedSubscription&& o) noexcept {
        if (this != &o) { (void)unsubscribe(token_); token_ = o.token_; o.token_ = 0; }
        return *this;
    }

    [[nodiscard]] Token token() const noexcept { return token_; }

private:
    Token token_{0};
};

} // namespace ida::debugger

#endif // IDAX_DEBUGGER_HPP
