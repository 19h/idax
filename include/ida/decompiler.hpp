/// \file decompiler.hpp
/// \brief Decompiler facade: availability, decompilation, pseudocode access.
///
/// The decompiler wraps the Hex-Rays SDK. All decompiler functions return
/// errors if the decompiler is not available (not installed or not licensed).

#ifndef IDAX_DECOMPILER_HPP
#define IDAX_DECOMPILER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <vector>

namespace ida::decompiler {

/// Check whether a Hex-Rays decompiler is available.
/// Must be called before other decompiler functions.
/// Returns true if the decompiler was initialized successfully.
Result<bool> available();

/// A local variable in a decompiled function.
struct LocalVariable {
    std::string name;
    std::string type_name;   ///< Type as a C declaration string.
    bool        is_argument{false};
    int         width{0};    ///< Size in bytes.
};

/// Decompiled-function handle.
///
/// Holds the result of a decompilation. Pseudocode text and local variables
/// are available as long as this object is alive.
class DecompiledFunction {
public:
    /// Get the full pseudocode as a single string.
    [[nodiscard]] Result<std::string> pseudocode() const;

    /// Get the pseudocode as individual lines (stripped of color codes).
    [[nodiscard]] Result<std::vector<std::string>> lines() const;

    /// Get the function prototype/declaration line.
    [[nodiscard]] Result<std::string> declaration() const;

    /// Number of local variables (including arguments).
    [[nodiscard]] Result<std::size_t> variable_count() const;

    /// Get all local variables.
    [[nodiscard]] Result<std::vector<LocalVariable>> variables() const;

    /// Rename a local variable (persistent — saved to database).
    Status rename_variable(std::string_view old_name, std::string_view new_name);

    // ── Lifecycle ───────────────────────────────────────────────────────
    struct Impl;
    explicit DecompiledFunction(Impl* p) : impl_(p) {}
    ~DecompiledFunction();

    DecompiledFunction(const DecompiledFunction&) = delete;
    DecompiledFunction& operator=(const DecompiledFunction&) = delete;
    DecompiledFunction(DecompiledFunction&&) noexcept;
    DecompiledFunction& operator=(DecompiledFunction&&) noexcept;

private:
    Impl* impl_{nullptr};
};

/// Decompile the function at \p ea.
/// The decompiler must be available (call available() first or handle the error).
Result<DecompiledFunction> decompile(Address ea);

} // namespace ida::decompiler

#endif // IDAX_DECOMPILER_HPP
