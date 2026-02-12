/// \file decompiler.cpp
/// \brief Stub implementation of ida::decompiler.
///
/// The decompiler (Hex-Rays) requires hexrays.hpp which may not be available
/// at build time. This file provides stub implementations that report
/// decompiler unavailability.

#include "detail/sdk_bridge.hpp"
#include <ida/decompiler.hpp>

namespace ida::decompiler {

// ── Availability ────────────────────────────────────────────────────────

Result<bool> available() {
    // Without hexrays.hpp linked, the decompiler is never available.
    return false;
}

// ── DecompiledFunction stubs ────────────────────────────────────────────

struct DecompiledFunction::Impl {
    // Placeholder — filled in when hexrays support is compiled.
};

DecompiledFunction::~DecompiledFunction() {
    delete impl_;
}

DecompiledFunction::DecompiledFunction(DecompiledFunction&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

DecompiledFunction& DecompiledFunction::operator=(DecompiledFunction&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

Result<std::string> DecompiledFunction::pseudocode() const {
    return std::unexpected(Error::unsupported("Decompiler not available"));
}

Result<std::vector<std::string>> DecompiledFunction::lines() const {
    return std::unexpected(Error::unsupported("Decompiler not available"));
}

Result<std::size_t> DecompiledFunction::variable_count() const {
    return std::unexpected(Error::unsupported("Decompiler not available"));
}

// ── Decompile ───────────────────────────────────────────────────────────

Result<DecompiledFunction> decompile(Address /*ea*/) {
    return std::unexpected(Error::unsupported("Decompiler not available"));
}

} // namespace ida::decompiler
