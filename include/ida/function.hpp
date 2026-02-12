/// \file function.hpp
/// \brief Function operations: creation, query, traversal, chunks, frames.
///
/// All functions are represented by opaque Function value objects.
/// Chunk/tail complexity is exposed through the Chunk abstraction.
/// Stack frames are accessed through the StackFrame and FrameVariable types.

#ifndef IDAX_FUNCTION_HPP
#define IDAX_FUNCTION_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

// Forward-declare TypeInfo to avoid circular include.
namespace ida::type { class TypeInfo; }

namespace ida::function {

// ── Chunk value object ──────────────────────────────────────────────────

/// A contiguous address range belonging to a function.
/// A function has one entry chunk and zero or more tail chunks.
struct Chunk {
    Address     start{};
    Address     end{};
    bool        is_tail{false};   ///< True if this is a tail chunk (not the entry).
    Address     owner{};          ///< Entry address of owning function (valid for tails).

    [[nodiscard]] AddressSize size() const noexcept { return end - start; }
};

// ── Frame variable ──────────────────────────────────────────────────────

/// Describes a single stack variable in a function's frame.
struct FrameVariable {
    std::string name;
    std::size_t byte_offset{0};   ///< Offset from frame base, in bytes.
    std::size_t byte_size{0};     ///< Size of the variable in bytes.
    std::string comment;
    bool        is_special{false}; ///< True for __return_address / __saved_registers.
};

// ── Stack frame value object ────────────────────────────────────────────

/// Snapshot of a function's stack frame layout.
class StackFrame {
public:
    /// Size of local variables area (bytes).
    [[nodiscard]] AddressSize local_variables_size() const noexcept { return local_size_; }
    /// Size of saved-registers area (bytes).
    [[nodiscard]] AddressSize saved_registers_size() const noexcept { return regs_size_; }
    /// Size of arguments area (bytes).
    [[nodiscard]] AddressSize arguments_size()       const noexcept { return args_size_; }
    /// Total frame size (locals + regs + retaddr + args).
    [[nodiscard]] AddressSize total_size()           const noexcept { return total_size_; }

    /// All frame variables (local vars, arguments, gaps; excludes specials by default).
    [[nodiscard]] const std::vector<FrameVariable>& variables() const noexcept { return vars_; }

private:
    friend struct StackFrameAccess;

    AddressSize local_size_{};
    AddressSize regs_size_{};
    AddressSize args_size_{};
    AddressSize total_size_{};
    std::vector<FrameVariable> vars_;
};

// ── Function value object ───────────────────────────────────────────────

class Function {
public:
    [[nodiscard]] Address     start()     const noexcept { return start_; }
    [[nodiscard]] Address     end()       const noexcept { return end_; }
    [[nodiscard]] AddressSize size()      const noexcept { return end_ - start_; }
    [[nodiscard]] std::string name()      const { return name_; }
    [[nodiscard]] int         bitness()   const noexcept { return bitness_; }

    [[nodiscard]] bool returns()    const noexcept { return returns_; }
    [[nodiscard]] bool is_library() const noexcept { return library_; }
    [[nodiscard]] bool is_thunk()   const noexcept { return thunk_; }
    [[nodiscard]] bool is_hidden()  const noexcept { return hidden_; }

    /// Size of local variables in the stack frame.
    [[nodiscard]] AddressSize frame_local_size()  const noexcept { return frsize_; }
    /// Size of saved registers area.
    [[nodiscard]] AddressSize frame_regs_size()   const noexcept { return frregs_; }
    /// Size of arguments on the stack.
    [[nodiscard]] AddressSize frame_args_size()   const noexcept { return argsize_; }

    /// Re-read from database.
    Status refresh();

private:
    friend struct FunctionAccess;

    Address     start_{};
    Address     end_{};
    std::string name_;
    int         bitness_{};
    bool        returns_{true};
    bool        library_{false};
    bool        thunk_{false};
    bool        hidden_{false};
    AddressSize frsize_{};
    AddressSize frregs_{};
    AddressSize argsize_{};
};

// ── CRUD ────────────────────────────────────────────────────────────────

/// Create a function. If \p end is BadAddress, IDA determines the bounds.
Result<Function> create(Address start, Address end = BadAddress);

/// Delete the function containing \p ea.
Status remove(Address ea);

// ── Lookup ──────────────────────────────────────────────────────────────

/// Function containing the given address (entry or tail chunk).
Result<Function> at(Address ea);

/// Function by positional index (0-based).
Result<Function> by_index(std::size_t idx);

/// Total number of functions.
Result<std::size_t> count();

/// Get the name of the function containing \p ea.
Result<std::string> name_at(Address ea);

// ── Boundary mutation ───────────────────────────────────────────────────

Status set_start(Address ea, Address new_start);
Status set_end(Address ea, Address new_end);

// ── Comment access ──────────────────────────────────────────────────────

Result<std::string> comment(Address ea, bool repeatable = false);
Status set_comment(Address ea, std::string_view text, bool repeatable = false);

// ── Relationship helpers ────────────────────────────────────────────────

/// Addresses of all functions that call \p ea (via code xrefs to function entry).
Result<std::vector<Address>> callers(Address ea);

/// Addresses of all functions called from the function at \p ea.
Result<std::vector<Address>> callees(Address ea);

// ── Chunk operations ────────────────────────────────────────────────────

/// Get all chunks (entry + tails) for the function containing \p ea.
/// The entry chunk is always first in the returned vector.
Result<std::vector<Chunk>> chunks(Address ea);

/// Get only tail chunks for the function containing \p ea.
Result<std::vector<Chunk>> tail_chunks(Address ea);

/// Number of chunks (entry + tails) for the function at \p ea.
Result<std::size_t> chunk_count(Address ea);

/// Append a tail chunk to the function at \p func_ea.
Status add_tail(Address func_ea, Address tail_start, Address tail_end);

/// Remove a tail chunk starting at \p tail_ea from the function at \p func_ea.
Status remove_tail(Address func_ea, Address tail_ea);

// ── Frame operations ────────────────────────────────────────────────────

/// Retrieve a snapshot of the stack frame for the function at \p ea.
Result<StackFrame> frame(Address ea);

/// Get the cumulative SP delta before the instruction at \p ea.
/// The delta is relative to the function's initial stack pointer.
Result<AddressDelta> sp_delta_at(Address ea);

/// Define a stack variable in the function's frame.
Status define_stack_variable(Address func_ea, std::string_view name,
                             std::int32_t frame_offset,
                             const ida::type::TypeInfo& type);

// ── Register variable operations ────────────────────────────────────────

/// A register variable definition: renames a CPU register within a range.
struct RegisterVariable {
    Address     range_start{};    ///< Start of the range where the alias is valid.
    Address     range_end{};      ///< End of the range (exclusive).
    std::string canonical_name;   ///< CPU register name (e.g. "eax").
    std::string user_name;        ///< User-defined alias (e.g. "loop_counter").
    std::string comment;
};

/// Define a register variable in the function at \p func_ea.
/// @param func_ea  Function entry address.
/// @param range_start  Start address of the range where the alias applies.
/// @param range_end  End address (exclusive).
/// @param register_name  Canonical CPU register name (e.g. "eax").
/// @param user_name  User-defined alias for the register.
/// @param cmt  Optional comment.
Status add_register_variable(Address func_ea,
                             Address range_start, Address range_end,
                             std::string_view register_name,
                             std::string_view user_name,
                             std::string_view cmt = {});

/// Find a register variable at an address by canonical register name.
Result<RegisterVariable> find_register_variable(Address func_ea,
                                                 Address ea,
                                                 std::string_view register_name);

/// Delete a register variable definition.
Status delete_register_variable(Address func_ea,
                                Address range_start, Address range_end,
                                std::string_view register_name);

/// Rename an existing register variable.
Status rename_register_variable(Address func_ea,
                                Address ea,
                                std::string_view register_name,
                                std::string_view new_user_name);

/// Check if there are any register variables at the given address.
Result<bool> has_register_variables(Address func_ea, Address ea);

// ── Traversal ───────────────────────────────────────────────────────────

class FunctionIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = Function;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const Function*;
    using reference         = Function;

    FunctionIterator() = default;
    explicit FunctionIterator(std::size_t index, std::size_t total);

    reference operator*() const;
    FunctionIterator& operator++();
    FunctionIterator  operator++(int);

    friend bool operator==(const FunctionIterator& a, const FunctionIterator& b) noexcept {
        return a.idx_ == b.idx_;
    }
    friend bool operator!=(const FunctionIterator& a, const FunctionIterator& b) noexcept {
        return !(a == b);
    }

private:
    std::size_t idx_{0};
    std::size_t total_{0};
};

class FunctionRange {
public:
    FunctionRange();
    [[nodiscard]] FunctionIterator begin() const;
    [[nodiscard]] FunctionIterator end()   const;
private:
    std::size_t total_{0};
};

/// Iterable range of all functions.
FunctionRange all();

} // namespace ida::function

#endif // IDAX_FUNCTION_HPP
