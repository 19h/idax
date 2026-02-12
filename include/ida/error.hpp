/// \file error.hpp
/// \brief Core error and result types for idax.
///
/// Provides ida::Error, ida::Result<T>, and ida::Status as the canonical
/// error model used throughout every idax namespace.

#ifndef IDAX_ERROR_HPP
#define IDAX_ERROR_HPP

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace ida {

// ── Error category ──────────────────────────────────────────────────────

/// Broad classification of an error's origin.
enum class ErrorCategory {
    Validation,   ///< Caller-supplied argument was invalid.
    NotFound,     ///< The requested object does not exist.
    Conflict,     ///< Operation conflicts with existing state.
    Unsupported,  ///< The operation is not supported in the current context.
    SdkFailure,   ///< The underlying IDA SDK call failed.
    Internal,     ///< Bug inside idax itself.
};

// ── Error ───────────────────────────────────────────────────────────────

/// Structured error value carried through every Result / Status.
struct Error {
    ErrorCategory category{ErrorCategory::Internal};
    int           code{0};
    std::string   message;
    std::string   context;

    /// Convenience constructors.
    static Error validation(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::Validation, 0, std::move(msg), std::move(ctx)};
    }
    static Error not_found(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::NotFound, 0, std::move(msg), std::move(ctx)};
    }
    static Error conflict(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::Conflict, 0, std::move(msg), std::move(ctx)};
    }
    static Error unsupported(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::Unsupported, 0, std::move(msg), std::move(ctx)};
    }
    static Error sdk(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::SdkFailure, 0, std::move(msg), std::move(ctx)};
    }
    static Error internal(std::string msg, std::string ctx = {}) {
        return {ErrorCategory::Internal, 0, std::move(msg), std::move(ctx)};
    }
};

// ── Result / Status aliases ─────────────────────────────────────────────

/// A value-or-error return type.
template <typename T>
using Result = std::expected<T, Error>;

/// A void-or-error return type (for operations that succeed or fail).
using Status = std::expected<void, Error>;

/// Helper: return a successful void Status.
inline Status ok() { return {}; }

} // namespace ida

#endif // IDAX_ERROR_HPP
