/// \file debugger.hpp
/// \brief Debugger control: process/thread lifecycle, breakpoints, memory.

#ifndef IDAX_DEBUGGER_HPP
#define IDAX_DEBUGGER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
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

} // namespace ida::debugger

#endif // IDAX_DEBUGGER_HPP
