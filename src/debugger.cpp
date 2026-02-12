/// \file debugger.cpp
/// \brief Implementation of ida::debugger — process control, breakpoints, memory.

#include "detail/sdk_bridge.hpp"
#include <ida/debugger.hpp>

#include <dbg.hpp>

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

} // namespace ida::debugger
