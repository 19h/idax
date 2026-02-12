/// \file decompiler.hpp
/// \brief Decompiler facade: availability, decompilation, pseudocode access.

#ifndef IDAX_DECOMPILER_HPP
#define IDAX_DECOMPILER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <vector>

namespace ida::decompiler {

/// Is a decompiler available for the current processor?
Result<bool> available();

/// Decompiled-function handle.
class DecompiledFunction {
public:
    Result<std::string>              pseudocode() const;
    Result<std::vector<std::string>> lines()      const;
    Result<std::size_t>              variable_count() const;

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
Result<DecompiledFunction> decompile(Address ea);

} // namespace ida::decompiler

#endif // IDAX_DECOMPILER_HPP
