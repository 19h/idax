/// \file exception.hpp
/// \brief Architecture-independent C++ and structured-exception regions.

#ifndef IDAX_EXCEPTION_HPP
#define IDAX_EXCEPTION_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace ida::exception {

/// Metadata common to C++ catch and SEH handler bodies.
struct HandlerMetadata {
    /// One or more fragmented half-open handler regions.
    std::vector<address::Range> regions;

    /// Frame-pointer-relative displacement to the guarded stack region.
    std::optional<AddressDelta> stack_displacement;

    /// Frame register identifier, or absence when no register is known.
    std::optional<int> frame_register;
};

/// Semantic selector used by a C++ catch handler.
enum class CatchSelectorKind : std::uint8_t {
    Typed,
    CatchAll,
    Cleanup,
};

/// A typed, catch-all, or cleanup C++ catch selector.
struct CatchSelector {
    CatchSelectorKind kind{CatchSelectorKind::CatchAll};

    /// Non-negative native type identifier; meaningful only for `Typed`.
    std::int64_t type_identifier{0};
};

/// One C++ catch or cleanup handler.
struct CatchHandler {
    HandlerMetadata metadata;

    /// Frame-pointer-relative exception-object displacement.
    std::optional<AddressDelta> object_displacement;

    CatchSelector selector;
};

/// Semantic disposition used when an SEH record has no filter regions.
enum class SehDisposition : std::int8_t {
    ContinueExecution = -1,
    ContinueSearch    = 0,
    ExecuteHandler    = 1,
};

/// One structured-exception handler.
struct SehHandler {
    HandlerMetadata metadata;

    /// Fragmented filter-callback regions.
    std::vector<address::Range> filter_regions;

    /// Required when `filter_regions` is empty; absent otherwise.
    std::optional<SehDisposition> disposition;
};

/// C++ handler set for a protected region.
struct CppHandlers {
    std::vector<CatchHandler> catches;
};

/// Discriminated C++ or SEH handler payload.
using HandlerSet = std::variant<CppHandlers, SehHandler>;

/// Input definition for one architecture-independent exception region.
struct BlockDefinition {
    /// One or more fragmented half-open protected regions.
    std::vector<address::Range> protected_regions;

    HandlerSet handlers{CppHandlers{}};
};

/// Retrieved exception region with its host-calculated nesting level.
struct Block {
    BlockDefinition definition;
    std::uint8_t nesting_level{0};
};

/// Semantic address-membership classes.
enum class Location : std::uint32_t {
    CppTry            = 0x01,
    CppHandler        = 0x02,
    SehTry            = 0x04,
    SehHandler        = 0x08,
    SehFilter         = 0x10,
    Any               = 0x1F,
    UnwindFallthrough = 0x20,
};

/// Combine membership classes for `contains`.
[[nodiscard]] constexpr Location operator|(Location lhs, Location rhs) noexcept {
    return static_cast<Location>(
        static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
}

/// Retrieve exception regions intersecting a half-open address range.
Result<std::vector<Block>> list(address::Range range);

/// Delete every exception-region record intersecting a range.
Status remove(address::Range range);

/// Add one validated C++ or SEH region definition.
Status add(const BlockDefinition& block);

/// Find the start of a surrounding system exception-handling region.
///
/// `std::nullopt` means the address has no surrounding system region.
Result<std::optional<Address>> system_region_start(Address address);

/// Return whether an address matches any requested semantic location class.
Result<bool> contains(Address address, Location locations = Location::Any);

} // namespace ida::exception

#endif // IDAX_EXCEPTION_HPP
