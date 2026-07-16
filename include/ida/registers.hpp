/// \file registers.hpp
/// \brief Opaque register-value tracking with copied semantic results.

#ifndef IDAX_REGISTERS_HPP
#define IDAX_REGISTERS_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::registers {

/// Exhaustive semantic state returned by the pinned register tracker.
enum class TrackingState : std::uint8_t {
    Undefined,
    DeadEnd,
    Aborted,
    BadInstruction,
    UnknownInstruction,
    FunctionInput,
    LoopVariant,
    IncompatibleValues,
    TooManyReferences,
    TooManyValues,
    Constant,
    StackPointerDelta,
};

/// Whether a reference was added or removed for cache invalidation.
enum class ReferenceMutation : std::uint8_t {
    Added,
    Removed,
};

/// Copied origin metadata for one tracked value or terminal state.
struct ValueOrigin {
    Address address{BadAddress};
    std::uint16_t instruction_code{0};
    bool short_instruction{false};
    bool program_counter_based{false};
    bool global_offset_table_like{false};
};

/// One possible tracked value and its defining origin.
///
/// Exactly one numeric field is populated for known states. Both remain empty
/// for state-only causes, which are represented through `TrackedValue::cause`.
struct ValueCandidate {
    std::optional<std::uint64_t> constant;
    std::optional<AddressDelta> stack_pointer_delta;
    ValueOrigin origin;
};

/// Complete owned result of one backward register-value query.
struct TrackedValue {
    TrackingState state{TrackingState::Undefined};
    std::vector<ValueCandidate> candidates;
    std::optional<ValueOrigin> cause;
    std::optional<std::int32_t> aborting_depth;
    std::string description;

    [[nodiscard]] bool known() const noexcept {
        return state == TrackingState::Constant
            || state == TrackingState::StackPointerDelta;
    }
};

/// Result of native nearest-of-two base-register selection.
struct NearestValue {
    std::size_t selected_index{0};
    std::string register_name;
    TrackedValue value;
};

/// Track a named register before executing the instruction at `address`.
///
/// `max_depth` accepts `-1` (function-wide configured depth), `0` (configured
/// default), or a positive explicit basic-block depth.
Result<TrackedValue> track(Address address, std::string_view register_name,
                           int max_depth = 0);

/// Return a unique constant, or empty optional when the tracked state is not
/// one unique constant.
Result<std::optional<std::uint64_t>> constant_at(
    Address address, std::string_view register_name, int max_depth = 0);

/// Return the default stack-pointer-relative delta before `address`.
Result<std::optional<AddressDelta>> stack_delta_at(Address address);

/// Return a named register's stack-pointer-relative delta before `address`.
Result<std::optional<AddressDelta>> stack_delta_at(
    Address address, std::string_view register_name);

/// Select the first value the native tracker can establish from two distinct
/// base registers, trying local linear flow before the complete function.
Result<std::optional<NearestValue>> nearest_at(
    Address address, std::string_view first_register,
    std::string_view second_register);

/// Clear all cached control-flow-derived register values.
Status clear_control_flow_cache();
/// Clear all cached data-reference-derived register values.
Status clear_data_reference_cache();

/// Notify the tracker that one control-flow reference changed.
Status control_flow_reference_changed(Address from, Address to,
                                      ReferenceMutation mutation);
/// Notify the tracker that one data reference targeting `to` changed.
Status data_reference_changed(Address to, ReferenceMutation mutation);

} // namespace ida::registers

#endif // IDAX_REGISTERS_HPP
