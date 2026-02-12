/// \file debugger.cpp
/// \brief Implementation of ida::debugger — process control, breakpoints, memory.

#include "detail/sdk_bridge.hpp"
#include <ida/debugger.hpp>

#include <dbg.hpp>
#include <idd.hpp>
#include <mutex>

namespace ida::debugger {

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

Status attach(int pid) {
    int rc = attach_process(pid, -1);
    if (rc <= 0)
        return std::unexpected(Error::sdk("attach_process failed",
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
        return std::unexpected(Error::sdk("run_to failed"));
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
        return std::unexpected(Error::sdk("add_bpt failed"));
    return ida::ok();
}

Status remove_breakpoint(Address ea) {
    if (!del_bpt(static_cast<ea_t>(ea)))
        return std::unexpected(Error::not_found("No breakpoint at address"));
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
        return std::unexpected(Error::sdk("read_dbg_memory failed"));
    buf.resize(static_cast<size_t>(n));
    return buf;
}

Status write_memory(Address ea, std::span<const std::uint8_t> bytes) {
    ssize_t n = write_dbg_memory(static_cast<ea_t>(ea), bytes.data(), bytes.size());
    if (n < 0 || static_cast<size_t>(n) != bytes.size())
        return std::unexpected(Error::sdk("write_dbg_memory failed"));
    return ida::ok();
}

// ── Debugger event listener ─────────────────────────────────────────────

namespace {

/// Singleton debugger event listener (HT_DBG), same pattern as UiListener / IdbListener.
class DbgListener : public event_listener_t {
public:
    struct Subscription {
        DebuggerToken token;
        int notification_code;
        // handler returns ssize_t: 0 = pass through, non-zero = consume
        std::function<ssize_t(va_list)> handler;
    };

    static DbgListener& instance() {
        static DbgListener inst;
        return inst;
    }

    DebuggerToken subscribe(int code, std::function<ssize_t(va_list)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        ensure_hooked();
        DebuggerToken token = ++next_token_;
        subs_.push_back({token, code, std::move(handler)});
        return token;
    }

    bool unsubscribe(DebuggerToken token) {
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
    DebuggerToken next_token_{0};
    bool hooked_{false};
};

} // anonymous namespace

// ── Tier 1 ──────────────────────────────────────────────────────────────

Result<DebuggerToken> on_process_started(
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

Result<DebuggerToken> on_process_exited(
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

Result<DebuggerToken> on_process_suspended(
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

Result<DebuggerToken> on_breakpoint_hit(
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

Result<DebuggerToken> on_trace(
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

Result<DebuggerToken> on_exception(
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

Result<DebuggerToken> on_thread_started(
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

Result<DebuggerToken> on_thread_exited(
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

Result<DebuggerToken> on_library_loaded(
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

Result<DebuggerToken> on_library_unloaded(
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

Result<DebuggerToken> on_breakpoint_changed(
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

Status debugger_unsubscribe(DebuggerToken token) {
    if (!DbgListener::instance().unsubscribe(token))
        return std::unexpected(Error::not_found("Debugger subscription not found"));
    return ida::ok();
}

} // namespace ida::debugger
