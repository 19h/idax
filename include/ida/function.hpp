/// \file function.hpp
/// \brief Function operations: creation, query, traversal, frame access.
///
/// All functions are represented by opaque Function value objects.
/// Chunk/tail complexity is hidden behind the public surface.

#ifndef IDAX_FUNCTION_HPP
#define IDAX_FUNCTION_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <iterator>
#include <string>

namespace ida::function {

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
