/// \file registers.cpp
/// \brief Implementation of opaque register-value tracking.

#include "detail/sdk_bridge.hpp"

#include <ida/registers.hpp>

#define IDA_REGFINDER_LEGACY_COMPAT
#include <regfinder.hpp>
#undef IDA_REGFINDER_LEGACY_COMPAT

#include <algorithm>
#include <limits>
#include <type_traits>

// The exact 9.4 SDK commit redirects these two source-level helpers to
// reg_finder94_* compatibility exports.  The release libraries retain the
// legacy ABI names, so declare those official signatures after suppressing
// only the header's inline redirects.
idaman bool ida_export find_reg_value_info(
    reg_value_info_t* rvi, ea_t ea, int reg, int max_depth = 0);
idaman int ida_export find_nearest_rvi(
    reg_value_info_t* rvi, ea_t ea, const int reg[2]);

namespace ida::registers {

namespace {

using NativeFindValue = int (idaapi *)(uint64*, ea_t, int);
using NativeFindStackValue = int (idaapi *)(sval_t*, ea_t, int);
using NativeFindValueInfo = bool (idaapi *)(reg_value_info_t*, ea_t, int, int);
using NativeFindNamedValueInfo = bool (idaapi *)(
    reg_value_info_t*, ea_t, const char*, int);
using NativeFindNearest = int (idaapi *)(
    reg_value_info_t*, ea_t, const int[2]);
using NativeInvalidateFlow = void (idaapi *)(ea_t, ea_t, cref_t);
using NativeInvalidateData = void (idaapi *)(ea_t, dref_t);
static_assert(std::is_same_v<decltype(&::find_reg_value), NativeFindValue>);
static_assert(std::is_same_v<decltype(&::find_sp_value), NativeFindStackValue>);
static_assert(std::is_same_v<decltype(&::find_reg_value_info),
                             NativeFindValueInfo>);
static_assert(std::is_same_v<decltype(&::find_regname_value_info),
                             NativeFindNamedValueInfo>);
static_assert(std::is_same_v<decltype(&::find_nearest_rvi), NativeFindNearest>);
static_assert(std::is_same_v<decltype(&::invalidate_regfinder_cache),
                             NativeInvalidateFlow>);
static_assert(std::is_same_v<decltype(&::invalidate_regfinder_xrefs_cache),
                             NativeInvalidateData>);
static_assert(reg_value_def_t::SHORT_INSN == 0x0001);
static_assert(reg_value_def_t::PC_BASED == 0x0010);
static_assert(reg_value_def_t::LIKE_GOT == 0x0020);

Status validate_address(Address address, std::string_view field) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            std::string(field) + " cannot be BadAddress"));
    }
    return ok();
}

Status validate_depth(int max_depth) {
    if (max_depth < -1) {
        return std::unexpected(Error::validation(
            "Register tracking depth cannot be less than -1",
            std::to_string(max_depth)));
    }
    return ok();
}

Result<reg_info_t> resolve_register(std::string_view register_name) {
    if (register_name.empty()) {
        return std::unexpected(Error::validation(
            "Register name cannot be empty"));
    }
    if (register_name.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Register name contains an embedded NUL byte"));
    }
    const std::string owned(register_name);
    reg_info_t info{};
    if (!::parse_reg_name(&info, owned.c_str())) {
        return std::unexpected(Error::not_found(
            "Register name is not recognized by the current processor",
            owned));
    }
    if (info.reg < 0 || info.size <= 0 || info.size > 8) {
        return std::unexpected(Error::unsupported(
            "Register has unsupported tracking metadata", owned));
    }
    return info;
}

TrackingState classify_state(const reg_value_info_t& value) {
    if (value.empty())
        return TrackingState::Undefined;
    if (value.is_dead_end())
        return TrackingState::DeadEnd;
    if (value.aborted())
        return TrackingState::Aborted;
    if (value.is_badinsn())
        return TrackingState::BadInstruction;
    if (value.is_unkinsn())
        return TrackingState::UnknownInstruction;
    if (value.is_unkfunc())
        return TrackingState::FunctionInput;
    if (value.is_unkloop())
        return TrackingState::LoopVariant;
    if (value.is_unkmult())
        return TrackingState::IncompatibleValues;
    if (value.is_unkxref())
        return TrackingState::TooManyReferences;
    if (value.is_unkvals())
        return TrackingState::TooManyValues;
    if (value.is_num())
        return TrackingState::Constant;
    if (value.is_spd())
        return TrackingState::StackPointerDelta;
    return TrackingState::Undefined;
}

ValueOrigin copy_origin(const reg_value_def_t& definition) {
    return ValueOrigin{
        .address = static_cast<Address>(definition.def_ea),
        .instruction_code = definition.def_itype,
        .short_instruction = definition.is_short_insn(),
        .program_counter_based = definition.is_pc_based(),
        .global_offset_table_like = definition.is_like_got(),
    };
}

Result<TrackedValue> copy_tracked_value(reg_value_info_t value) {
    value.truncate();
    TrackedValue result;
    result.state = classify_state(value);
    result.description = detail::to_string(value.dstr());

    const bool is_constant = result.state == TrackingState::Constant;
    const bool is_stack_delta =
        result.state == TrackingState::StackPointerDelta;
    if (is_constant || is_stack_delta) {
        result.candidates.reserve(value.vals_size());
        for (const reg_value_def_t* current = value.vals_begin();
             current != value.vals_end(); ++current) {
            ValueCandidate candidate;
            if (is_constant)
                candidate.constant = current->val;
            else
                candidate.stack_pointer_delta =
                    static_cast<AddressDelta>(current->val);
            candidate.origin = copy_origin(*current);
            result.candidates.push_back(std::move(candidate));
        }
    } else if (value.vals_size() != 0) {
        result.cause = copy_origin(*value.vals_begin());
    }

    if (result.state == TrackingState::Aborted) {
        const int depth = value.get_aborting_depth();
        if (depth >= 0)
            result.aborting_depth = depth;
    }

    const bool classified = value.empty()
        || result.state != TrackingState::Undefined;
    if (!classified) {
        return std::unexpected(Error::unsupported(
            "Register tracker returned an unknown native state"));
    }
    if ((is_constant || is_stack_delta) && result.candidates.empty()) {
        return std::unexpected(Error::internal(
            "Known register state contains no value candidates"));
    }
    return result;
}

Result<std::optional<AddressDelta>> unique_stack_delta(
    const TrackedValue& value) {
    if (value.state != TrackingState::StackPointerDelta
        || value.candidates.empty()) {
        return std::optional<AddressDelta>{};
    }
    const auto& first = value.candidates.front().stack_pointer_delta;
    if (!first)
        return std::unexpected(Error::internal(
            "Stack-delta candidate has no signed value"));
    for (const auto& candidate : value.candidates) {
        if (!candidate.stack_pointer_delta
            || *candidate.stack_pointer_delta != *first) {
            return std::optional<AddressDelta>{};
        }
    }
    return first;
}

} // namespace

Result<TrackedValue> track(Address address, std::string_view register_name,
                           int max_depth) {
    if (auto status = validate_address(address, "Tracking address"); !status)
        return std::unexpected(status.error());
    if (auto status = validate_depth(max_depth); !status)
        return std::unexpected(status.error());
    auto register_info = resolve_register(register_name);
    if (!register_info)
        return std::unexpected(register_info.error());

    reg_value_info_t native;
    const std::string owned(register_name);
    if (!::find_regname_value_info(&native, static_cast<ea_t>(address),
                                   owned.c_str(), max_depth)) {
        return std::unexpected(Error::unsupported(
            "Current processor does not support register-value tracking",
            owned));
    }
    return copy_tracked_value(std::move(native));
}

Result<std::optional<std::uint64_t>> constant_at(
    Address address, std::string_view register_name, int max_depth) {
    if (auto status = validate_address(address, "Tracking address"); !status)
        return std::unexpected(status.error());
    if (auto status = validate_depth(max_depth); !status)
        return std::unexpected(status.error());
    auto register_info = resolve_register(register_name);
    if (!register_info)
        return std::unexpected(register_info.error());

    // The dedicated convenience export uses the configured default depth and
    // reports only one unambiguous number. Preserve alias-width semantics by
    // truncating its full base-register result to parse_reg_name()'s width.
    if (max_depth == 0) {
        uint64 native = 0;
        const int code = ::find_reg_value(
            &native, static_cast<ea_t>(address), register_info->reg);
        if (code < 0) {
            return std::unexpected(Error::unsupported(
                "Current processor does not support register-value tracking",
                std::string(register_name)));
        }
        if (code == 0)
            return std::optional<std::uint64_t>{};
        if (register_info->size < static_cast<int>(sizeof(native))) {
            const unsigned bits = static_cast<unsigned>(register_info->size) * 8U;
            native &= (uint64{1} << bits) - 1U;
        }
        return std::optional<std::uint64_t>{native};
    }

    auto value = track(address, register_name, max_depth);
    if (!value)
        return std::unexpected(value.error());
    if (value->state != TrackingState::Constant || value->candidates.empty())
        return std::optional<std::uint64_t>{};
    const auto& first = value->candidates.front().constant;
    if (!first) {
        return std::unexpected(Error::internal(
            "Constant candidate has no unsigned value"));
    }
    for (const auto& candidate : value->candidates) {
        if (!candidate.constant || *candidate.constant != *first)
            return std::optional<std::uint64_t>{};
    }
    return first;
}

Result<std::optional<AddressDelta>> stack_delta_at(Address address) {
    if (auto status = validate_address(address, "Tracking address"); !status)
        return std::unexpected(status.error());
    sval_t native = 0;
    const int code = ::find_sp_value(&native, static_cast<ea_t>(address), -1);
    if (code < 0) {
        return std::unexpected(Error::unsupported(
            "Current processor does not support stack-value tracking"));
    }
    if (code == 0)
        return std::optional<AddressDelta>{};
    return std::optional<AddressDelta>{static_cast<AddressDelta>(native)};
}

Result<std::optional<AddressDelta>> stack_delta_at(
    Address address, std::string_view register_name) {
    auto value = track(address, register_name);
    if (!value)
        return std::unexpected(value.error());
    return unique_stack_delta(*value);
}

Result<std::optional<NearestValue>> nearest_at(
    Address address, std::string_view first_register,
    std::string_view second_register) {
    if (auto status = validate_address(address, "Tracking address"); !status)
        return std::unexpected(status.error());
    auto first = resolve_register(first_register);
    if (!first)
        return std::unexpected(first.error());
    auto second = resolve_register(second_register);
    if (!second)
        return std::unexpected(second.error());
    if (first->reg == second->reg) {
        return std::unexpected(Error::validation(
            "Nearest-register query requires two distinct base registers"));
    }

    reg_value_info_t support_probe;
    if (!::find_reg_value_info(&support_probe, static_cast<ea_t>(address),
                               first->reg, 0)) {
        return std::unexpected(Error::unsupported(
            "Current processor does not support register-value tracking"));
    }

    const int native_registers[2]{first->reg, second->reg};
    reg_value_info_t native;
    const int selected = ::find_nearest_rvi(
        &native, static_cast<ea_t>(address), native_registers);
    if (selected < 0)
        return std::optional<NearestValue>{};
    if (selected > 1) {
        return std::unexpected(Error::internal(
            "Native nearest-register result is outside 0..1",
            std::to_string(selected)));
    }
    auto value = copy_tracked_value(std::move(native));
    if (!value)
        return std::unexpected(value.error());
    const std::string selected_name(
        selected == 0 ? first_register : second_register);
    return std::optional<NearestValue>{NearestValue{
        .selected_index = static_cast<std::size_t>(selected),
        .register_name = selected_name,
        .value = std::move(*value),
    }};
}

Status clear_control_flow_cache() {
    ::invalidate_regfinder_cache();
    return ok();
}

Status clear_data_reference_cache() {
    ::invalidate_regfinder_xrefs_cache();
    return ok();
}

Status control_flow_reference_changed(Address from, Address to,
                                      ReferenceMutation mutation) {
    if (auto status = validate_address(from, "Reference source"); !status)
        return status;
    if (auto status = validate_address(to, "Reference target"); !status)
        return status;
    cref_t native;
    switch (mutation) {
        case ReferenceMutation::Added: native = fl_F; break;
        case ReferenceMutation::Removed: native = fl_U; break;
        default:
            return std::unexpected(Error::validation(
                "Unknown register-reference mutation"));
    }
    ::invalidate_regfinder_cache(static_cast<ea_t>(to),
                                 static_cast<ea_t>(from), native);
    return ok();
}

Status data_reference_changed(Address to, ReferenceMutation mutation) {
    if (auto status = validate_address(to, "Reference target"); !status)
        return status;
    dref_t native;
    switch (mutation) {
        case ReferenceMutation::Added: native = dr_W; break;
        case ReferenceMutation::Removed: native = dr_O; break;
        default:
            return std::unexpected(Error::validation(
                "Unknown register-reference mutation"));
    }
    ::invalidate_regfinder_xrefs_cache(static_cast<ea_t>(to), native);
    return ok();
}

} // namespace ida::registers
