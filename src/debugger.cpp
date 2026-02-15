/// \file debugger.cpp
/// \brief Implementation of ida::debugger — process control, breakpoints, memory.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/debugger.hpp>

#include <dbg.hpp>
#include <expr.hpp>
#include <idd.hpp>
#include <loader.hpp>

#include <cstring>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace ida::debugger {

namespace {

std::string copy_cstr(const char* text) {
    return text != nullptr ? std::string(text) : std::string();
}

bool backend_name_matches(const BackendInfo& backend, std::string_view name) {
    if (!backend.name.empty() && name == backend.name)
        return true;
    return !backend.display_name.empty() && name == backend.display_name;
}

BackendInfo make_backend_info(const dbg_info_t& info, const debugger_t* current_dbg) {
    BackendInfo out;
    if (info.dbg != nullptr)
        out.name = copy_cstr(info.dbg->name);
    if (info.pi != nullptr)
        out.display_name = copy_cstr(info.pi->name);
    if (out.display_name.empty())
        out.display_name = out.name;

    if (info.dbg != nullptr) {
        out.remote = (info.dbg->flags & DBG_FLAG_REMOTE) != 0;
        out.supports_appcall = (info.dbg->flags & DBG_HAS_APPCALL) != 0;
        out.supports_attach = (info.dbg->flags & DBG_HAS_ATTACH_PROCESS) != 0;
    }

    if (current_dbg != nullptr
        && current_dbg->name != nullptr
        && info.dbg != nullptr
        && info.dbg->name != nullptr)
    {
        out.loaded = std::strcmp(current_dbg->name, info.dbg->name) == 0;
        if (out.loaded) {
            const bool current_remote = (current_dbg->flags & DBG_FLAG_REMOTE) != 0;
            if (current_remote != out.remote)
                out.loaded = false;
        }
    }

    return out;
}

} // namespace

Result<std::vector<BackendInfo>> available_backends() {
    const dbg_info_t* infos = nullptr;
    const size_t count = get_debugger_plugins(&infos);

    std::vector<BackendInfo> out;
    out.reserve(count);

    if (infos == nullptr || count == 0)
        return out;

    for (size_t index = 0; index < count; ++index) {
        const dbg_info_t& info = infos[index];
        if (info.dbg == nullptr)
            continue;
        out.push_back(make_backend_info(info, dbg));
    }

    return out;
}

Result<BackendInfo> current_backend() {
    if (dbg == nullptr)
        return std::unexpected(Error::not_found("No debugger backend loaded"));

    auto backends = available_backends();
    if (!backends)
        return std::unexpected(backends.error());

    for (const BackendInfo& backend : *backends) {
        if (backend.loaded)
            return backend;
    }

    BackendInfo fallback;
    fallback.name = copy_cstr(dbg->name);
    fallback.display_name = fallback.name;
    fallback.remote = (dbg->flags & DBG_FLAG_REMOTE) != 0;
    fallback.supports_appcall = (dbg->flags & DBG_HAS_APPCALL) != 0;
    fallback.supports_attach = (dbg->flags & DBG_HAS_ATTACH_PROCESS) != 0;
    fallback.loaded = true;
    return fallback;
}

Status load_backend(std::string_view backend_name, bool use_remote) {
    if (backend_name.empty())
        return std::unexpected(Error::validation("backend_name cannot be empty"));

    std::string sdk_name(backend_name);
    if (auto backends = available_backends(); backends) {
        const BackendInfo* matched_exact = nullptr;
        const BackendInfo* matched_any = nullptr;
        for (const BackendInfo& backend : *backends) {
            if (!backend_name_matches(backend, backend_name))
                continue;
            if (backend.remote == use_remote) {
                matched_exact = &backend;
                break;
            }
            if (matched_any == nullptr)
                matched_any = &backend;
        }

        const BackendInfo* chosen = matched_exact != nullptr ? matched_exact : matched_any;
        if (chosen != nullptr && !chosen->name.empty())
            sdk_name = chosen->name;
    }

    if (sdk_name.empty()) {
        return std::unexpected(Error::validation(
            "Resolved debugger backend name is empty",
            std::string(backend_name)));
    }

    if (!load_debugger(sdk_name.c_str(), use_remote)) {
        return std::unexpected(Error::sdk(
            "load_debugger failed",
            "name='" + sdk_name + "' remote=" + (use_remote ? "true" : "false")));
    }
    return ida::ok();
}

// ── Session lifecycle ───────────────────────────────────────────────────

Status start(std::string_view path, std::string_view args,
             std::string_view working_dir) {
    // Materialize stable null-terminated strings for the SDK call.
    std::string sp(path), sa(args), sd(working_dir);
    int rc = start_process(
        sp.empty() ? nullptr : sp.c_str(),
        sa.empty() ? nullptr : sa.c_str(),
        sd.empty() ? nullptr : sd.c_str());
    if (rc <= 0)
        return std::unexpected(Error::sdk("start_process failed",
                                          "return code: " + std::to_string(rc)));
    return ida::ok();
}

Status request_start(std::string_view path,
                     std::string_view args,
                     std::string_view working_dir) {
    std::string sp(path), sa(args), sd(working_dir);
    int rc = request_start_process(
        sp.empty() ? nullptr : sp.c_str(),
        sa.empty() ? nullptr : sa.c_str(),
        sd.empty() ? nullptr : sd.c_str());
    if (rc <= 0)
        return std::unexpected(Error::sdk("request_start_process failed",
                                          "return code: " + std::to_string(rc)));
    return ida::ok();
}

Status attach(int pid) {
    int rc = attach_process(pid, -1);
    if (rc <= 0)
        return std::unexpected(Error::sdk("attach_process failed",
                                          "return code: " + std::to_string(rc)));
    return ida::ok();
}

Status request_attach(int pid, int event_id) {
    int rc = request_attach_process(pid, event_id);
    if (rc <= 0)
        return std::unexpected(Error::sdk("request_attach_process failed",
                                          "return code: " + std::to_string(rc)));
    return ida::ok();
}

Status detach() {
    if (!detach_process())
        return std::unexpected(Error::sdk("detach_process failed"));
    return ida::ok();
}

Status terminate() {
    if (!exit_process())
        return std::unexpected(Error::sdk("exit_process failed"));
    return ida::ok();
}

// ── Execution control ───────────────────────────────────────────────────

Status suspend() {
    if (!suspend_process())
        return std::unexpected(Error::sdk("suspend_process failed"));
    return ida::ok();
}

Status resume() {
    if (!continue_process())
        return std::unexpected(Error::sdk("continue_process failed"));
    return ida::ok();
}

Status step_into() {
    if (!::step_into())
        return std::unexpected(Error::sdk("step_into failed"));
    return ida::ok();
}

Status step_over() {
    if (!::step_over())
        return std::unexpected(Error::sdk("step_over failed"));
    return ida::ok();
}

Status step_out() {
    if (!step_until_ret())
        return std::unexpected(Error::sdk("step_until_ret failed"));
    return ida::ok();
}

Status run_to(Address ea) {
    if (!::run_to(static_cast<ea_t>(ea)))
        return std::unexpected(Error::sdk("run_to failed",
                                          std::to_string(ea)));
    return ida::ok();
}

// ── State inspection ────────────────────────────────────────────────────

Result<ProcessState> state() {
    int s = get_process_state();
    switch (s) {
        case DSTATE_NOTASK: return ProcessState::NoProcess;
        case DSTATE_RUN:    return ProcessState::Running;
        case DSTATE_SUSP:   return ProcessState::Suspended;
        default:            return ProcessState::NoProcess;
    }
}

// ── Register and pointer access ─────────────────────────────────────

Result<Address> instruction_pointer() {
    ea_t ip;
    if (!get_ip_val(&ip))
        return std::unexpected(Error::sdk("get_ip_val failed "
                                          "(debugger not suspended?)"));
    return static_cast<Address>(ip);
}

Result<Address> stack_pointer() {
    ea_t sp;
    if (!get_sp_val(&sp))
        return std::unexpected(Error::sdk("get_sp_val failed "
                                          "(debugger not suspended?)"));
    return static_cast<Address>(sp);
}

Result<std::uint64_t> register_value(std::string_view reg_name) {
    std::string rn(reg_name);
    uint64 val;
    if (!get_reg_val(rn.c_str(), &val))
        return std::unexpected(Error::sdk("get_reg_val failed", rn));
    return static_cast<std::uint64_t>(val);
}

Status set_register(std::string_view reg_name, std::uint64_t value) {
    std::string rn(reg_name);
    if (!set_reg_val(rn.c_str(), static_cast<uint64>(value)))
        return std::unexpected(Error::sdk("set_reg_val failed", rn));
    return ida::ok();
}

// ── Breakpoints ─────────────────────────────────────────────────────────

Status add_breakpoint(Address ea) {
    if (!add_bpt(static_cast<ea_t>(ea)))
        return std::unexpected(Error::sdk("add_bpt failed",
                                          std::to_string(ea)));
    return ida::ok();
}

Status remove_breakpoint(Address ea) {
    if (!del_bpt(static_cast<ea_t>(ea)))
        return std::unexpected(Error::not_found("No breakpoint at address",
                                                std::to_string(ea)));
    return ida::ok();
}

Result<bool> has_breakpoint(Address ea) {
    return exist_bpt(static_cast<ea_t>(ea));
}

// ── Memory access ───────────────────────────────────────────────────────

Result<std::vector<std::uint8_t>> read_memory(Address ea, AddressSize size) {
    std::vector<std::uint8_t> buf(static_cast<size_t>(size));
    ssize_t n = read_dbg_memory(static_cast<ea_t>(ea), buf.data(), buf.size());
    if (n < 0)
        return std::unexpected(Error::sdk("read_dbg_memory failed",
                                          std::to_string(ea)));
    buf.resize(static_cast<size_t>(n));
    return buf;
}

Status write_memory(Address ea, std::span<const std::uint8_t> bytes) {
    ssize_t n = write_dbg_memory(static_cast<ea_t>(ea), bytes.data(), bytes.size());
    if (n < 0 || static_cast<size_t>(n) != bytes.size())
        return std::unexpected(Error::sdk("write_dbg_memory failed",
                                          std::to_string(ea)));
    return ida::ok();
}

// ── Request-queue execution helpers ─────────────────────────────────────

bool is_request_running() {
    return ::is_request_running();
}

Status run_requests() {
    if (!::run_requests())
        return std::unexpected(Error::sdk("run_requests failed"));
    return ida::ok();
}

Status request_suspend() {
    if (!request_suspend_process())
        return std::unexpected(Error::sdk("request_suspend_process failed"));
    return ida::ok();
}

Status request_resume() {
    if (!request_continue_process())
        return std::unexpected(Error::sdk("request_continue_process failed"));
    return ida::ok();
}

Status request_step_into() {
    if (!::request_step_into())
        return std::unexpected(Error::sdk("request_step_into failed"));
    return ida::ok();
}

Status request_step_over() {
    if (!::request_step_over())
        return std::unexpected(Error::sdk("request_step_over failed"));
    return ida::ok();
}

Status request_step_out() {
    if (!::request_step_until_ret())
        return std::unexpected(Error::sdk("request_step_until_ret failed"));
    return ida::ok();
}

Status request_run_to(Address address) {
    if (address == BadAddress)
        return std::unexpected(Error::validation("Invalid run-to address"));
    if (!::request_run_to(static_cast<ea_t>(address)))
        return std::unexpected(Error::sdk("request_run_to failed",
                                          std::to_string(address)));
    return ida::ok();
}

// ── Thread and register introspection ───────────────────────────────────

Result<std::size_t> thread_count() {
    int qty = get_thread_qty();
    if (qty < 0)
        return std::unexpected(Error::sdk("get_thread_qty failed"));
    return static_cast<std::size_t>(qty);
}

Result<int> thread_id_at(std::size_t index) {
    auto qty = thread_count();
    if (!qty)
        return std::unexpected(qty.error());
    if (index >= *qty)
        return std::unexpected(Error::not_found("Thread index out of range",
                                                std::to_string(index)));

    thid_t tid = getn_thread(static_cast<int>(index));
    if (tid == NO_THREAD)
        return std::unexpected(Error::not_found("Thread not found at index",
                                                std::to_string(index)));
    return static_cast<int>(tid);
}

Result<std::string> thread_name_at(std::size_t index) {
    auto tid = thread_id_at(index);
    if (!tid)
        return std::unexpected(tid.error());

    const char* name = getn_thread_name(static_cast<int>(index));
    if (name == nullptr)
        return std::unexpected(Error::not_found("Thread name unavailable",
                                                std::to_string(*tid)));
    return std::string(name);
}

Result<int> current_thread_id() {
    thid_t tid = get_current_thread();
    if (tid == NO_THREAD)
        return std::unexpected(Error::not_found("No current thread"));
    return static_cast<int>(tid);
}

Result<std::vector<ThreadInfo>> threads() {
    auto qty = thread_count();
    if (!qty)
        return std::unexpected(qty.error());

    thid_t current = get_current_thread();
    std::vector<ThreadInfo> out;
    out.reserve(*qty);

    for (std::size_t i = 0; i < *qty; ++i) {
        thid_t tid = getn_thread(static_cast<int>(i));
        if (tid == NO_THREAD)
            continue;

        ThreadInfo ti;
        ti.id = static_cast<int>(tid);
        if (const char* name = getn_thread_name(static_cast<int>(i)); name != nullptr)
            ti.name = name;
        ti.is_current = (current != NO_THREAD && tid == current);
        out.push_back(std::move(ti));
    }
    return out;
}

Status select_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    if (!::select_thread(static_cast<thid_t>(thread_id)))
        return std::unexpected(Error::not_found("Thread not found",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Status request_select_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    if (!::request_select_thread(static_cast<thid_t>(thread_id)))
        return std::unexpected(Error::not_found("Thread not found",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Status suspend_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    int rc = ::suspend_thread(static_cast<thid_t>(thread_id));
    if (rc < 0)
        return std::unexpected(Error::sdk("suspend_thread failed",
                                          std::to_string(thread_id)));
    if (rc == 0)
        return std::unexpected(Error::not_found("Thread not found or cannot be suspended",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Status request_suspend_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    int rc = ::request_suspend_thread(static_cast<thid_t>(thread_id));
    if (rc < 0)
        return std::unexpected(Error::sdk("request_suspend_thread failed",
                                          std::to_string(thread_id)));
    if (rc == 0)
        return std::unexpected(Error::not_found("Thread not found or cannot be suspended",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Status resume_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    int rc = ::resume_thread(static_cast<thid_t>(thread_id));
    if (rc < 0)
        return std::unexpected(Error::sdk("resume_thread failed",
                                          std::to_string(thread_id)));
    if (rc == 0)
        return std::unexpected(Error::not_found("Thread not found or cannot be resumed",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Status request_resume_thread(int thread_id) {
    if (thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(thread_id)));
    int rc = ::request_resume_thread(static_cast<thid_t>(thread_id));
    if (rc < 0)
        return std::unexpected(Error::sdk("request_resume_thread failed",
                                          std::to_string(thread_id)));
    if (rc == 0)
        return std::unexpected(Error::not_found("Thread not found or cannot be resumed",
                                                std::to_string(thread_id)));
    return ida::ok();
}

Result<RegisterInfo> register_info(std::string_view register_name) {
    if (register_name.empty())
        return std::unexpected(Error::validation("register_name cannot be empty"));

    std::string rn(register_name);
    register_info_t sdk_info{};
    if (!get_dbg_reg_info(rn.c_str(), &sdk_info))
        return std::unexpected(Error::not_found("Debugger register not found", rn));

    RegisterInfo out;
    out.name = sdk_info.name != nullptr ? std::string(sdk_info.name) : rn;
    out.read_only = (sdk_info.flags & REGISTER_READONLY) != 0;
    out.instruction_pointer = (sdk_info.flags & REGISTER_IP) != 0;
    out.stack_pointer = (sdk_info.flags & REGISTER_SP) != 0;
    out.frame_pointer = (sdk_info.flags & REGISTER_FP) != 0;
    out.may_contain_address = (sdk_info.flags & REGISTER_ADDRESS) != 0;
    out.custom_format = (sdk_info.flags & REGISTER_CUSTFMT) != 0;
    return out;
}

Result<bool> is_integer_register(std::string_view register_name) {
    auto info = register_info(register_name);
    if (!info)
        return std::unexpected(info.error());
    return ::is_reg_integer(info->name.c_str());
}

Result<bool> is_floating_register(std::string_view register_name) {
    auto info = register_info(register_name);
    if (!info)
        return std::unexpected(info.error());
    return ::is_reg_float(info->name.c_str());
}

Result<bool> is_custom_register(std::string_view register_name) {
    auto info = register_info(register_name);
    if (!info)
        return std::unexpected(info.error());
    return ::is_reg_custom(info->name.c_str());
}

// ── Appcall + external executor surface ────────────────────────────────

namespace {

Result<thid_t> to_thread_id(const AppcallOptions& options) {
    if (!options.thread_id)
        return NO_THREAD;
    if (*options.thread_id <= 0)
        return std::unexpected(Error::validation("thread_id must be positive",
                                                 std::to_string(*options.thread_id)));
    return static_cast<thid_t>(*options.thread_id);
}

Result<int> to_appcall_flags(const AppcallOptions& options) {
    int flags = 0;
    if (options.manual)
        flags |= APPCALL_MANUAL;
    if (options.include_debug_event)
        flags |= APPCALL_DEBEV;
    if (options.timeout_milliseconds) {
        if (*options.timeout_milliseconds > 0xFFFFu) {
            return std::unexpected(Error::validation(
                "timeout_milliseconds exceeds APPCALL limit",
                std::to_string(*options.timeout_milliseconds)));
        }
        flags |= SET_APPCALL_TIMEOUT(*options.timeout_milliseconds);
    }
    return flags;
}

Result<ida::type::TypeInfo> normalize_appcall_type(const ida::type::TypeInfo& input) {
    ida::type::TypeInfo resolved = input;
    if (input.is_typedef()) {
        auto unaliased = input.resolve_typedef();
        if (!unaliased)
            return std::unexpected(unaliased.error());
        resolved = *unaliased;
    }

    if (resolved.is_function())
        return resolved;

    if (resolved.is_pointer()) {
        auto pointee = resolved.pointee_type();
        if (!pointee)
            return std::unexpected(pointee.error());
        if (pointee->is_function())
            return *pointee;
    }

    return std::unexpected(Error::validation(
        "Appcall requires a function or pointer-to-function type"));
}

Status to_idc_value(idc_value_t* out, const AppcallValue& value) {
    if (out == nullptr)
        return std::unexpected(Error::internal("null idc value destination"));

    switch (value.kind) {
        case AppcallValueKind::SignedInteger:
            out->set_int64(static_cast<int64>(value.signed_value));
            return ida::ok();
        case AppcallValueKind::UnsignedInteger:
            if (value.unsigned_value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return std::unexpected(Error::validation(
                    "Unsigned appcall value exceeds IDC signed range",
                    std::to_string(value.unsigned_value)));
            }
            out->set_int64(static_cast<int64>(value.unsigned_value));
            return ida::ok();
        case AppcallValueKind::FloatingPoint:
        {
            fpvalue_t fp;
            if (fp.from_double(value.floating_value) != REAL_ERROR_OK) {
                return std::unexpected(Error::validation(
                    "Floating-point argument conversion failed",
                    std::to_string(value.floating_value)));
            }
            out->set_float(fp);
            return ida::ok();
        }
        case AppcallValueKind::String:
            out->set_string(value.string_value.c_str());
            return ida::ok();
        case AppcallValueKind::Address:
            if (value.address_value > static_cast<Address>(std::numeric_limits<std::int64_t>::max())) {
                return std::unexpected(Error::validation(
                    "Address appcall value exceeds IDC signed range",
                    std::to_string(value.address_value)));
            }
            out->set_int64(static_cast<int64>(value.address_value));
            return ida::ok();
        case AppcallValueKind::Boolean:
            out->set_long(value.boolean_value ? 1 : 0);
            return ida::ok();
    }

    return std::unexpected(Error::validation("Unsupported appcall argument kind"));
}

Result<std::string> render_idc_value(const idc_value_t& value) {
    qstring out;
    if (!print_idcv(&out, value, nullptr, 0))
        return std::unexpected(Error::sdk("print_idcv failed"));
    return ida::detail::to_string(out);
}

Result<AppcallValue> from_idc_value(const idc_value_t& value, bool pointer_return) {
    AppcallValue out;

    auto numeric_to_output = [&](std::int64_t signed_number) -> AppcallValue {
        AppcallValue converted;
        converted.signed_value = signed_number;
        converted.unsigned_value = static_cast<std::uint64_t>(signed_number);
        if (pointer_return) {
            converted.kind = AppcallValueKind::Address;
            converted.address_value = static_cast<Address>(converted.unsigned_value);
        } else {
            converted.kind = AppcallValueKind::SignedInteger;
        }
        return converted;
    };

    switch (value.vtype) {
        case VT_LONG:
            return numeric_to_output(static_cast<std::int64_t>(value.num));
        case VT_INT64:
            return numeric_to_output(static_cast<std::int64_t>(value.i64));
        case VT_FLOAT:
        {
            double d = 0.0;
            if (value.e.to_double(&d) != REAL_ERROR_OK) {
                return std::unexpected(Error::unsupported(
                    "Unsupported floating-point return value format"));
            }
            out.kind = AppcallValueKind::FloatingPoint;
            out.floating_value = d;
            return out;
        }
        case VT_STR:
            out.kind = AppcallValueKind::String;
            out.string_value = ida::detail::to_string(value.qstr());
            return out;
        case VT_PVOID:
            out.kind = AppcallValueKind::Address;
            out.address_value = static_cast<Address>(reinterpret_cast<std::uintptr_t>(value.pvoid));
            out.unsigned_value = static_cast<std::uint64_t>(out.address_value);
            return out;
        default:
            break;
    }

    idc_value_t numeric(value);
    if (idcv_num(&numeric) == eOk) {
        if (numeric.vtype == VT_LONG)
            return numeric_to_output(static_cast<std::int64_t>(numeric.num));
        if (numeric.vtype == VT_INT64)
            return numeric_to_output(static_cast<std::int64_t>(numeric.i64));
    }

    return std::unexpected(Error::unsupported(
        "Unsupported appcall return value kind",
        std::to_string(static_cast<int>(value.vtype))));
}

class ExecutorRegistry {
public:
    static ExecutorRegistry& instance() {
        static ExecutorRegistry registry;
        return registry;
    }

    Status register_named(std::string_view name,
                          const std::shared_ptr<AppcallExecutor>& executor) {
        if (name.empty())
            return std::unexpected(Error::validation("Executor name cannot be empty"));
        if (!executor)
            return std::unexpected(Error::validation("Executor pointer cannot be null"));

        std::lock_guard<std::mutex> lock(mutex_);
        const std::string key(name);
        if (executors_.contains(key)) {
            return std::unexpected(Error::conflict(
                "Executor is already registered", key));
        }
        executors_.emplace(key, executor);
        return ida::ok();
    }

    Status unregister_named(std::string_view name) {
        if (name.empty())
            return std::unexpected(Error::validation("Executor name cannot be empty"));

        std::lock_guard<std::mutex> lock(mutex_);
        const std::string key(name);
        auto it = executors_.find(key);
        if (it == executors_.end()) {
            return std::unexpected(Error::not_found(
                "Executor is not registered", key));
        }
        executors_.erase(it);
        return ida::ok();
    }

    Result<std::shared_ptr<AppcallExecutor>> find_named(std::string_view name) {
        if (name.empty())
            return std::unexpected(Error::validation("Executor name cannot be empty"));

        std::lock_guard<std::mutex> lock(mutex_);
        const std::string key(name);
        auto it = executors_.find(key);
        if (it == executors_.end()) {
            return std::unexpected(Error::not_found(
                "Executor is not registered", key));
        }
        return it->second;
    }

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<AppcallExecutor>> executors_;
};

} // anonymous namespace

Result<AppcallResult> appcall(const AppcallRequest& request) {
    if (request.function_address == BadAddress) {
        return std::unexpected(Error::validation("Invalid function address"));
    }

    auto type_info = normalize_appcall_type(request.function_type);
    if (!type_info)
        return std::unexpected(type_info.error());

    auto thread_id = to_thread_id(request.options);
    if (!thread_id)
        return std::unexpected(thread_id.error());

    auto flags = to_appcall_flags(request.options);
    if (!flags)
        return std::unexpected(flags.error());

    const auto* impl = ida::type::TypeInfoAccess::get(*type_info);
    if (impl == nullptr) {
        return std::unexpected(Error::internal("TypeInfo implementation is null"));
    }

    std::vector<idc_value_t> argv(request.arguments.size());
    for (std::size_t i = 0; i < request.arguments.size(); ++i) {
        auto status = to_idc_value(&argv[i], request.arguments[i]);
        if (!status) {
            auto err = status.error();
            std::string context = "argument_index=" + std::to_string(i);
            if (!err.context.empty())
                context += ":" + err.context;
            err.context = context;
            return std::unexpected(err);
        }
    }

    idc_value_t return_value;
    error_t rc = dbg_appcall(&return_value,
                             static_cast<ea_t>(request.function_address),
                             *thread_id,
                             &impl->ti,
                             argv.empty() ? nullptr : argv.data(),
                             argv.size());
    if (rc != eOk) {
        std::string context = "error_code=" + std::to_string(rc);
        if (auto rendered = render_idc_value(return_value); rendered && !rendered->empty())
            context += ", return=" + *rendered;
        return std::unexpected(Error::sdk("dbg_appcall failed", context));
    }

    bool pointer_return = false;
    if (auto return_type = type_info->function_return_type(); return_type) {
        pointer_return = return_type->is_pointer();
    }

    auto converted = from_idc_value(return_value, pointer_return);
    if (!converted)
        return std::unexpected(converted.error());

    AppcallResult result;
    result.return_value = std::move(*converted);
    return result;
}

Status cleanup_appcall(std::optional<int> thread_id) {
    thid_t tid = NO_THREAD;
    if (thread_id) {
        if (*thread_id <= 0) {
            return std::unexpected(Error::validation("thread_id must be positive",
                                                     std::to_string(*thread_id)));
        }
        tid = static_cast<thid_t>(*thread_id);
    }

    error_t rc = ::cleanup_appcall(tid);
    if (rc != eOk) {
        return std::unexpected(Error::sdk("cleanup_appcall failed",
                                          "error_code=" + std::to_string(rc)));
    }
    return ida::ok();
}

Status register_executor(std::string_view name,
                         std::shared_ptr<AppcallExecutor> executor) {
    return ExecutorRegistry::instance().register_named(name, executor);
}

Status unregister_executor(std::string_view name) {
    return ExecutorRegistry::instance().unregister_named(name);
}

Result<AppcallResult> appcall_with_executor(std::string_view name,
                                            const AppcallRequest& request) {
    auto executor = ExecutorRegistry::instance().find_named(name);
    if (!executor)
        return std::unexpected(executor.error());

    auto result = (*executor)->execute(request);
    if (!result) {
        auto err = result.error();
        std::string prefix = "executor=" + std::string(name);
        if (err.context.empty())
            err.context = prefix;
        else
            err.context = prefix + ":" + err.context;
        return std::unexpected(err);
    }
    return result;
}

// ── Debugger event listener ─────────────────────────────────────────────

namespace {

/// Singleton debugger event listener (HT_DBG), same pattern as UiListener / IdbListener.
class DbgListener : public event_listener_t {
public:
    struct Subscription {
        Token token;
        int notification_code;
        // handler returns ssize_t: 0 = pass through, non-zero = consume
        std::function<ssize_t(va_list)> handler;
    };

    static DbgListener& instance() {
        static DbgListener inst;
        return inst;
    }

    Token subscribe(int code, std::function<ssize_t(va_list)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        ensure_hooked();
        Token token = ++next_token_;
        subs_.push_back({token, code, std::move(handler)});
        return token;
    }

    bool unsubscribe(Token token) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = subs_.begin(); it != subs_.end(); ++it) {
            if (it->token == token) {
                subs_.erase(it);
                if (subs_.empty())
                    ensure_unhooked();
                return true;
            }
        }
        return false;
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override {
        std::vector<std::function<ssize_t(va_list)>> matched;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& s : subs_) {
                if (s.notification_code == static_cast<int>(code))
                    matched.push_back(s.handler);
            }
        }
        ssize_t result = 0;
        for (auto& h : matched) {
            ssize_t r = h(va);
            if (r != 0) result = r;
        }
        return result;
    }

private:
    DbgListener() = default;

    void ensure_hooked() {
        if (!hooked_) {
            hook_event_listener(HT_DBG, this, nullptr);
            hooked_ = true;
        }
    }

    void ensure_unhooked() {
        if (hooked_) {
            unhook_event_listener(HT_DBG, this);
            hooked_ = false;
        }
    }

    std::mutex mutex_;
    std::vector<Subscription> subs_;
    Token next_token_{0};
    bool hooked_{false};
};

} // anonymous namespace

// ── Tier 1 ──────────────────────────────────────────────────────────────

Result<Token> on_process_started(
    std::function<void(const ModuleInfo&)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_process_start,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            ModuleInfo mi;
            mi.base = static_cast<Address>(ev->ea);
            const auto& mod = ev->modinfo();
            mi.name = ida::detail::to_string(mod.name);
            mi.base = static_cast<Address>(mod.base);
            mi.size = static_cast<AddressSize>(mod.size);
            cb(mi);
            return 0;
        });
    return token;
}

Result<Token> on_process_exited(
    std::function<void(int exit_code)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_process_exit,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            cb(ev->exit_code());
            return 0;
        });
    return token;
}

Result<Token> on_process_suspended(
    std::function<void(Address ea)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_suspend_process,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            cb(static_cast<Address>(ev->ea));
            return 0;
        });
    return token;
}

Result<Token> on_breakpoint_hit(
    std::function<void(int thread_id, Address ea)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_bpt,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            thid_t tid = va_arg(va, thid_t);
            ea_t bptea = va_arg(va, ea_t);
            // int* warn = va_arg(va, int*); — leave at default
            cb(static_cast<int>(tid), static_cast<Address>(bptea));
            return 0;
        });
    return token;
}

Result<Token> on_trace(
    std::function<bool(int thread_id, Address ip)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_trace,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            thid_t tid = va_arg(va, thid_t);
            ea_t ip = va_arg(va, ea_t);
            bool suppress = cb(static_cast<int>(tid), static_cast<Address>(ip));
            return suppress ? 1 : 0;
        });
    return token;
}

Result<Token> on_exception(
    std::function<void(const ExceptionInfo&)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_exception,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            // int* warn = va_arg(va, int*); — leave at default
            const auto& exc = ev->exc();
            ExceptionInfo ei;
            ei.ea = static_cast<Address>(exc.ea);
            ei.code = static_cast<std::uint32_t>(exc.code);
            ei.can_continue = exc.can_cont;
            ei.message = ida::detail::to_string(exc.info);
            cb(ei);
            return 0;
        });
    return token;
}

// ── Tier 2 ──────────────────────────────────────────────────────────────

Result<Token> on_thread_started(
    std::function<void(int thread_id, std::string name)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_thread_start,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            cb(static_cast<int>(ev->tid),
               ida::detail::to_string(ev->info()));
            return 0;
        });
    return token;
}

Result<Token> on_thread_exited(
    std::function<void(int thread_id, int exit_code)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_thread_exit,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            cb(static_cast<int>(ev->tid), ev->exit_code());
            return 0;
        });
    return token;
}

Result<Token> on_library_loaded(
    std::function<void(const ModuleInfo&)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_library_load,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            const auto& mod = ev->modinfo();
            ModuleInfo mi;
            mi.name = ida::detail::to_string(mod.name);
            mi.base = static_cast<Address>(mod.base);
            mi.size = static_cast<AddressSize>(mod.size);
            cb(mi);
            return 0;
        });
    return token;
}

Result<Token> on_library_unloaded(
    std::function<void(std::string name)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_library_unload,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            const debug_event_t* ev = va_arg(va, const debug_event_t*);
            cb(ida::detail::to_string(ev->info()));
            return 0;
        });
    return token;
}

// ── Tier 3 ──────────────────────────────────────────────────────────────

Result<Token> on_breakpoint_changed(
    std::function<void(BreakpointChange change, Address ea)> callback) {
    auto token = DbgListener::instance().subscribe(
        dbg_bpt_changed,
        [cb = std::move(callback)](va_list va) -> ssize_t {
            int bptev = va_arg(va, int);
            bpt_t* bpt = va_arg(va, bpt_t*);
            BreakpointChange chg;
            switch (bptev) {
                case BPTEV_ADDED:   chg = BreakpointChange::Added; break;
                case BPTEV_REMOVED: chg = BreakpointChange::Removed; break;
                case BPTEV_CHANGED: chg = BreakpointChange::Changed; break;
                default:            chg = BreakpointChange::Changed; break;
            }
            cb(chg, static_cast<Address>(bpt->ea));
            return 0;
        });
    return token;
}

// ── Unsubscribe ─────────────────────────────────────────────────────────

Status unsubscribe(Token token) {
    if (!DbgListener::instance().unsubscribe(token))
        return std::unexpected(Error::not_found("Debugger subscription not found",
                                                std::to_string(token)));
    return ida::ok();
}

} // namespace ida::debugger
