/// \file problem.hpp
/// \brief Typed analysis-problem lists.

#ifndef IDAX_PROBLEM_HPP
#define IDAX_PROBLEM_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida::problem {

/// A closed semantic analysis-problem category.
enum class Kind : std::uint8_t {
    MissingOffsetBase    = 1,
    MissingName          = 2,
    MissingForcedOperand = 3,
    MissingComment       = 4,
    MissingReferences    = 5,
    IgnoredJumpTable     = 6,
    DisassemblyFailure   = 7,
    AlreadyItemHead      = 8,
    FlowBeyondLimits     = 9,
    TooManyLines         = 10,
    StackTraceFailure    = 11,
    Attention            = 12,
    AnalysisDecision     = 13,
    RolledBackDecision   = 14,
    FlairCollision       = 15,
    FlairIndecision      = 16,
};

/// Return the copied description recorded for a problem.
///
/// `std::nullopt` means no description is recorded at that kind/address.
Result<std::optional<std::string>> description(Kind kind, Address address);

/// Record a problem at an address.
///
/// A disengaged message preserves the SDK's default-description behavior;
/// an explicitly empty message remains distinct. Embedded NUL is rejected.
Status remember(Kind kind, Address address,
                std::optional<std::string_view> message = std::nullopt);

/// Return the first problem address greater than or equal to `at_or_after`.
///
/// `std::nullopt` means the selected problem list has no matching address.
Result<std::optional<Address>> next(Kind kind, Address at_or_after = 0);

/// Remove a problem marker, returning whether it existed.
Result<bool> remove(Kind kind, Address address);

/// Return the copied short or long display name of a problem kind.
Result<std::string> name(Kind kind, bool long_form = true);

/// Return whether the selected problem exists at an address.
Result<bool> contains(Kind kind, Address address);

} // namespace ida::problem

#endif // IDAX_PROBLEM_HPP
