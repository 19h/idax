/// \file offset.cpp
/// \brief Implementation of opaque operand offset/reference semantics.

#include "detail/sdk_bridge.hpp"
#include <ida/offset.hpp>

#include <limits>
#include <string>

namespace ida::offset {

namespace {

static_assert(REF_OFF8 == 10);
static_assert(REF_OFF16 == 1);
static_assert(REF_OFF32 == 2);
static_assert(REF_OFF64 == 9);
static_assert(REF_LOW8 == 3);
static_assert(REF_LOW16 == 4);
static_assert(REF_LOW32 == 11);
static_assert(REF_HIGH8 == 5);
static_assert(REF_HIGH16 == 6);
static_assert(REF_HIGH32 == 12);
static_assert(REFINFO_RVAOFF == 0x0010);
static_assert(REFINFO_PASTEND == 0x0020);
static_assert(REFINFO_CUSTOM == 0x0040);
static_assert(REFINFO_NOBASE == 0x0080);
static_assert(REFINFO_SUBTRACT == 0x0100);
static_assert(REFINFO_SIGNEDOP == 0x0200);
static_assert(REFINFO_IGNZERO == 0x0400);
static_assert(REFINFO_NO_ONES == 0x0800);
static_assert(REFINFO_SELFREF == 0x1000);
static_assert(REFINFO_USER == 0x2000);
static_assert(OPND_OUTER == 0x80);
static_assert(OPND_MASK == 0x0F);

Status validate_address(Address address, std::string_view operation) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "BadAddress is not a valid offset/reference address",
            std::string(operation)));
    }
    segment_info_t segment;
    if (!get_segment_info(&segment, static_cast<ea_t>(address))) {
        return std::unexpected(Error::not_found(
            "No segment contains the offset/reference address",
            std::to_string(address)));
    }
    return ida::ok();
}

Result<int> native_location(OperandLocation location) {
    if (location.index >= UA_MAXOP) {
        return std::unexpected(Error::validation(
            "Operand index must be in [0, 8)",
            std::to_string(location.index)));
    }
    int result = static_cast<int>(location.index);
    if (location.outer)
        result |= OPND_OUTER;
    return result;
}

Status validate_outer_capability(Address address, OperandLocation location) {
    if (!location.outer)
        return ida::ok();
    insn_t instruction;
    if (decode_insn(&instruction, static_cast<ea_t>(address)) <= 0) {
        return std::unexpected(Error::validation(
            "Outer offsets require a decodable instruction",
            std::to_string(address)));
    }
    const op_t& operand = instruction.ops[location.index];
    if (operand.type == o_void
        || (operand.flags & OF_OUTER_DISP) == 0
        || operand.offo == 0) {
        return std::unexpected(Error::unsupported(
            "Operand has no processor-defined outer displacement",
            std::to_string(address) + ":" + std::to_string(location.index)));
    }
    return ida::ok();
}

bool is_full_width_kind(ReferenceKind kind) {
    return kind == ReferenceKind::Offset8
        || kind == ReferenceKind::Offset16
        || kind == ReferenceKind::Offset32
        || kind == ReferenceKind::Offset64;
}

Result<ReferenceType> reference_type_from_native(uint32 native_type) {
    switch (native_type) {
    case REF_OFF8: return ReferenceType{ReferenceKind::Offset8, {}};
    case REF_OFF16: return ReferenceType{ReferenceKind::Offset16, {}};
    case REF_OFF32: return ReferenceType{ReferenceKind::Offset32, {}};
    case REF_OFF64: return ReferenceType{ReferenceKind::Offset64, {}};
    case REF_LOW8: return ReferenceType{ReferenceKind::Low8, {}};
    case REF_LOW16: return ReferenceType{ReferenceKind::Low16, {}};
    case REF_LOW32: return ReferenceType{ReferenceKind::Low32, {}};
    case REF_HIGH8: return ReferenceType{ReferenceKind::High8, {}};
    case REF_HIGH16: return ReferenceType{ReferenceKind::High16, {}};
    case REF_HIGH32: return ReferenceType{ReferenceKind::High32, {}};
    default: break;
    }
    if ((native_type & REFINFO_CUSTOM) == 0) {
        return std::unexpected(Error::unsupported(
            "Unknown native reference type", std::to_string(native_type)));
    }

    refinfo_desc_vec_t descriptors;
    get_refinfo_descs(&descriptors);
    for (const auto& descriptor : descriptors) {
        if (descriptor.type != native_type)
            continue;
        if (descriptor.name == nullptr || descriptor.name[0] == '\0') {
            return std::unexpected(Error::internal(
                "SDK returned a custom reference type without a name"));
        }
        return ReferenceType{ReferenceKind::Custom, descriptor.name};
    }
    return std::unexpected(Error::unsupported(
        "Registered custom reference type is unavailable",
        std::to_string(native_type)));
}

Result<uint32> reference_type_to_native(const ReferenceType& type) {
    if (type.kind != ReferenceKind::Custom && !type.custom_name.empty()) {
        return std::unexpected(Error::validation(
            "Standard reference types must not carry a custom name"));
    }
    switch (type.kind) {
    case ReferenceKind::Offset8: return REF_OFF8;
    case ReferenceKind::Offset16: return REF_OFF16;
    case ReferenceKind::Offset32: return REF_OFF32;
    case ReferenceKind::Offset64: return REF_OFF64;
    case ReferenceKind::Low8: return REF_LOW8;
    case ReferenceKind::Low16: return REF_LOW16;
    case ReferenceKind::Low32: return REF_LOW32;
    case ReferenceKind::High8: return REF_HIGH8;
    case ReferenceKind::High16: return REF_HIGH16;
    case ReferenceKind::High32: return REF_HIGH32;
    case ReferenceKind::Custom: break;
    }

    if (type.custom_name.empty()) {
        return std::unexpected(Error::validation(
            "Custom reference type name must not be empty"));
    }
    if (type.custom_name.find('\0') != std::string::npos) {
        return std::unexpected(Error::validation(
            "Custom reference type name must not contain NUL bytes"));
    }
    refinfo_desc_vec_t descriptors;
    get_refinfo_descs(&descriptors);
    for (const auto& descriptor : descriptors) {
        if ((descriptor.type & REFINFO_CUSTOM) == 0
            || descriptor.name == nullptr
            || type.custom_name != descriptor.name) {
            continue;
        }
        return descriptor.type;
    }
    return std::unexpected(Error::not_found(
        "Custom reference type is not registered", type.custom_name));
}

bool target_is_optional(uint32 native_type) {
    return is_reftype_target_optional(static_cast<reftype_t>(native_type));
}

Result<refinfo_t> reference_info_to_native(
    Address address, const ReferenceInfo& info) {
    auto native_type = reference_type_to_native(info.type);
    if (!native_type)
        return std::unexpected(native_type.error());
    if (info.target && *info.target == BadAddress) {
        return std::unexpected(Error::validation(
            "Reference target must not be BadAddress"));
    }
    if (info.base && *info.base == BadAddress) {
        return std::unexpected(Error::validation(
            "Reference base must not be BadAddress"));
    }
    if (!info.target && !target_is_optional(*native_type)) {
        return std::unexpected(Error::validation(
            "Reference type requires an explicit target"));
    }
    if (info.options.sign_extend_operand
        && !is_full_width_kind(info.type.kind)) {
        return std::unexpected(Error::validation(
            "Signed operand mode requires a full-width standard reference"));
    }
    if (info.options.relative_virtual_address && info.options.self_relative) {
        return std::unexpected(Error::validation(
            "RVA and self-relative reference modes are mutually exclusive"));
    }

    uint32 flags = *native_type;
    if (info.options.relative_virtual_address) flags |= REFINFO_RVAOFF;
    if (info.options.allow_past_end) flags |= REFINFO_PASTEND;
    if (info.options.suppress_base_reference) flags |= REFINFO_NOBASE;
    if (info.options.subtract_operand) flags |= REFINFO_SUBTRACT;
    if (info.options.sign_extend_operand) flags |= REFINFO_SIGNEDOP;
    if (info.options.accept_zero) flags |= REFINFO_IGNZERO;
    if (info.options.reject_all_ones) flags |= REFINFO_NO_ONES;
    if (info.options.self_relative) flags |= REFINFO_SELFREF;
    if (info.options.ignore_fixup) flags |= REFINFO_USER;

    ea_t native_base = info.base
        ? static_cast<ea_t>(*info.base) : BADADDR;
    if (info.options.relative_virtual_address) {
        const ea_t forced = get_imagebase();
        if (info.base && *info.base != static_cast<Address>(forced)) {
            return std::unexpected(Error::conflict(
                "RVA reference base must match the image base"));
        }
        native_base = forced;
    } else if (info.options.self_relative) {
        const ea_t forced = static_cast<ea_t>(address);
        if (info.base && *info.base != address) {
            return std::unexpected(Error::conflict(
                "Self-relative reference base must match the reference address"));
        }
        native_base = forced;
    }

    refinfo_t native;
    native.init(
        flags,
        native_base,
        info.target ? static_cast<ea_t>(*info.target) : BADADDR,
        static_cast<adiff_t>(info.target_delta));
    return native;
}

Result<ReferenceInfo> reference_info_from_native(const refinfo_t& native) {
    auto type = reference_type_from_native(native.type());
    if (!type)
        return std::unexpected(type.error());
    ReferenceInfo result;
    result.type = std::move(*type);
    if (native.target != BADADDR)
        result.target = static_cast<Address>(native.target);
    if (native.base != BADADDR)
        result.base = static_cast<Address>(native.base);
    result.target_delta = static_cast<AddressDelta>(native.tdelta);
    result.options.relative_virtual_address = native.is_rvaoff();
    result.options.allow_past_end = native.is_pastend();
    result.options.suppress_base_reference = native.no_base_xref();
    result.options.subtract_operand = native.is_subtract();
    result.options.sign_extend_operand = native.is_signed();
    result.options.accept_zero = native.is_ignore_zero();
    result.options.reject_all_ones = native.is_no_ones();
    result.options.self_relative = native.is_selfref();
    result.options.ignore_fixup = native.is_user();
    return result;
}

bool same_native_info(const refinfo_t& left, const refinfo_t& right) {
    return left.target == right.target
        && left.base == right.base
        && left.tdelta == right.tdelta
        && left.flags == right.flags;
}

bool query_native_reference(refinfo_t* out, Address address, int location) {
    return get_refinfo(out, static_cast<ea_t>(address), location);
}

Status restore_reference(
    Address address,
    int location,
    bool outer,
    const std::optional<refinfo_t>& previous) {
    if (previous) {
        if (!op_offset_ex(static_cast<ea_t>(address), location, &*previous)) {
            return std::unexpected(Error::internal(
                "Failed to restore prior reference metadata"));
        }
        refinfo_t restored;
        if (!query_native_reference(&restored, address, location)
            || !same_native_info(restored, *previous)) {
            return std::unexpected(Error::internal(
                "Prior reference metadata restoration did not round-trip"));
        }
        return ida::ok();
    }

    if (!clr_op_type(static_cast<ea_t>(address), location)) {
        return std::unexpected(Error::internal(
            "Failed to clear partially applied reference metadata"));
    }
    refinfo_t absent;
    if (query_native_reference(&absent, address, location)
        || (!outer && is_off(get_flags(static_cast<ea_t>(address)), location))) {
        return std::unexpected(Error::internal(
            "Partially applied reference metadata remained after rollback"));
    }
    return ida::ok();
}

int render_flags(RenderOptions options) {
    int flags = 0;
    if (options.append_zero_field)
        flags |= GETN_APPZERO;
    if (options.avoid_dummy_names)
        flags |= GETN_NODUMMY;
    return flags;
}

Result<RenderedExpression> copy_rendered_expression(qstring& output, int result) {
    if (result != 1 && result != 2) {
        return std::unexpected(Error::sdk(
            "Reference cannot be rendered as an offset expression"));
    }
    ::tag_remove(&output);
    return RenderedExpression{
        .text = ida::detail::to_string(output),
        .complexity = result == 1
            ? ExpressionComplexity::Simple
            : ExpressionComplexity::Complex,
    };
}

Result<dref_t> native_data_type(xref::DataType type) {
    switch (type) {
    case xref::DataType::Offset: return dr_O;
    case xref::DataType::Write: return dr_W;
    case xref::DataType::Read: return dr_R;
    case xref::DataType::Text: return dr_T;
    case xref::DataType::Informational: return dr_I;
    }
    return std::unexpected(Error::validation(
        "Invalid data-reference type"));
}

} // namespace

Result<std::vector<ReferenceTypeDescriptor>> reference_types() {
    refinfo_desc_vec_t descriptors;
    get_refinfo_descs(&descriptors);
    std::vector<ReferenceTypeDescriptor> result;
    result.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        if (descriptor.name == nullptr || descriptor.desc == nullptr) {
            return std::unexpected(Error::internal(
                "SDK returned malformed reference type metadata"));
        }
        auto type = reference_type_from_native(descriptor.type);
        if (!type)
            return std::unexpected(type.error());
        result.push_back(ReferenceTypeDescriptor{
            .type = std::move(*type),
            .name = descriptor.name,
            .description = descriptor.desc,
            .target_optional = target_is_optional(descriptor.type),
        });
    }
    return result;
}

Result<ReferenceType> default_reference_type(Address address) {
    auto valid = validate_address(address, "default type");
    if (!valid)
        return std::unexpected(valid.error());
    return reference_type_from_native(
        get_default_reftype(static_cast<ea_t>(address)));
}

Result<std::optional<ReferenceInfo>> reference_info(
    Address address, OperandLocation location) {
    auto valid = validate_address(address, "reference query");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    refinfo_t native;
    if (!query_native_reference(&native, address, *native_operand))
        return std::optional<ReferenceInfo>{};
    auto copied = reference_info_from_native(native);
    if (!copied)
        return std::unexpected(copied.error());
    return std::optional<ReferenceInfo>{std::move(*copied)};
}

Status apply_reference(
    Address address, OperandLocation location, const ReferenceInfo& info) {
    auto valid = validate_address(address, "reference apply");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    auto outer = validate_outer_capability(address, location);
    if (!outer)
        return std::unexpected(outer.error());

    refinfo_t before;
    const bool had_before = query_native_reference(
        &before, address, *native_operand);
    const flags64_t flags = get_flags(static_cast<ea_t>(address));
    if (!location.outer && is_defarg(flags, *native_operand)
        && !is_off(flags, *native_operand)) {
        return std::unexpected(Error::conflict(
            "Operand already has a non-offset representation",
            std::to_string(address) + ":" + std::to_string(location.index)));
    }
    if (!location.outer && is_off(flags, *native_operand) && !had_before) {
        return std::unexpected(Error::conflict(
            "Operand offset representation has no readable reference metadata"));
    }
    const std::optional<refinfo_t> previous = had_before
        ? std::optional<refinfo_t>{before} : std::nullopt;

    auto requested = reference_info_to_native(address, info);
    if (!requested)
        return std::unexpected(requested.error());
    if (!op_offset_ex(
            static_cast<ea_t>(address), *native_operand, &*requested)) {
        auto rollback = restore_reference(
            address, *native_operand, location.outer, previous);
        if (!rollback) {
            return std::unexpected(Error::internal(
                "Reference apply was rejected and rollback failed",
                rollback.error().message));
        }
        return std::unexpected(Error::sdk(
            "SDK rejected offset reference metadata",
            std::to_string(address) + ":" + std::to_string(location.index)));
    }

    refinfo_t observed;
    if (query_native_reference(&observed, address, *native_operand)
        && same_native_info(observed, *requested)) {
        return ida::ok();
    }
    auto rollback = restore_reference(
        address, *native_operand, location.outer, previous);
    if (!rollback) {
        return std::unexpected(Error::internal(
            "Reference apply postcondition failed and rollback failed",
            rollback.error().message));
    }
    return std::unexpected(Error::sdk(
        "Reference apply did not produce the requested metadata",
        std::to_string(address) + ":" + std::to_string(location.index)));
}

Result<bool> remove_reference(Address address, OperandLocation location) {
    auto valid = validate_address(address, "reference removal");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    refinfo_t previous;
    if (!query_native_reference(&previous, address, *native_operand))
        return false;

    if (!del_refinfo(static_cast<ea_t>(address), *native_operand)) {
        return std::unexpected(Error::sdk(
            "Failed to remove reference metadata",
            std::to_string(address) + ":" + std::to_string(location.index)));
    }
    if (!clr_op_type(static_cast<ea_t>(address), *native_operand)) {
        auto rollback = restore_reference(
            address, *native_operand, location.outer, previous);
        if (!rollback) {
            return std::unexpected(Error::internal(
                "Reference representation removal and rollback failed",
                rollback.error().message));
        }
        return std::unexpected(Error::sdk(
            "Failed to clear reference operand representation"));
    }

    refinfo_t absent;
    const bool metadata_remains = query_native_reference(
        &absent, address, *native_operand);
    const bool representation_remains = !location.outer
        && is_off(get_flags(static_cast<ea_t>(address)), *native_operand);
    if (!metadata_remains && !representation_remains)
        return true;

    auto rollback = restore_reference(
        address, *native_operand, location.outer, previous);
    if (!rollback) {
        return std::unexpected(Error::internal(
            "Reference removal postcondition and rollback failed",
            rollback.error().message));
    }
    return std::unexpected(Error::sdk(
        "Reference removal did not clear all stored state"));
}

Result<RenderedExpression> render_stored_expression(
    Address address,
    OperandLocation location,
    Address from,
    AddressDelta operand_value,
    RenderOptions options) {
    auto valid = validate_address(address, "stored reference rendering");
    if (!valid)
        return std::unexpected(valid.error());
    if (from == BadAddress)
        return std::unexpected(Error::validation("Render source must not be BadAddress"));
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    refinfo_t present;
    if (!query_native_reference(&present, address, *native_operand)) {
        return std::unexpected(Error::not_found(
            "Operand has no offset reference metadata"));
    }
    qstring output;
    const int rendered = get_offset_expression(
        &output,
        static_cast<ea_t>(address),
        *native_operand,
        static_cast<ea_t>(from),
        static_cast<adiff_t>(operand_value),
        render_flags(options));
    return copy_rendered_expression(output, rendered);
}

Result<RenderedExpression> render_expression(
    Address address,
    OperandLocation location,
    const ReferenceInfo& info,
    Address from,
    AddressDelta operand_value,
    RenderOptions options) {
    auto valid = validate_address(address, "explicit reference rendering");
    if (!valid)
        return std::unexpected(valid.error());
    if (from == BadAddress)
        return std::unexpected(Error::validation("Render source must not be BadAddress"));
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    auto native_info = reference_info_to_native(address, info);
    if (!native_info)
        return std::unexpected(native_info.error());
    qstring output;
    const int rendered = get_offset_expr(
        &output,
        static_cast<ea_t>(address),
        *native_operand,
        *native_info,
        static_cast<ea_t>(from),
        static_cast<adiff_t>(operand_value),
        render_flags(options));
    return copy_rendered_expression(output, rendered);
}

Result<std::optional<Address>> possible_offset32_target(Address address) {
    auto valid = validate_address(address, "OFF32 candidate query");
    if (!valid)
        return std::unexpected(valid.error());
    const ea_t result = can_be_off32(static_cast<ea_t>(address));
    if (result == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(result)};
}

Result<std::optional<Address>> calculate_offset_base(
    Address address, OperandLocation location) {
    auto valid = validate_address(address, "offset base calculation");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    const ea_t result = calc_offset_base(
        static_cast<ea_t>(address), *native_operand);
    if (result == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(result)};
}

Result<std::optional<Address>> probable_base(
    Address address, std::uint64_t operand_value) {
    auto valid = validate_address(address, "probable base calculation");
    if (!valid)
        return std::unexpected(valid.error());
    const ea_t result = calc_probable_base_by_value(
        static_cast<ea_t>(address), static_cast<uval_t>(operand_value));
    if (result == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(result)};
}

Result<ReferenceCalculation> calculate_reference(
    Address from, const ReferenceInfo& info, AddressDelta operand_value) {
    auto valid = validate_address(from, "reference calculation");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_info = reference_info_to_native(from, info);
    if (!native_info)
        return std::unexpected(native_info.error());
    ea_t target = BADADDR;
    ea_t base = BADADDR;
    if (!calc_reference_data(
            &target,
            &base,
            static_cast<ea_t>(from),
            *native_info,
            static_cast<adiff_t>(operand_value))) {
        return std::unexpected(Error::sdk(
            "Reference target/base calculation failed"));
    }
    ReferenceCalculation result;
    if (target != BADADDR)
        result.target = static_cast<Address>(target);
    if (base != BADADDR)
        result.base = static_cast<Address>(base);
    return result;
}

Result<Address> add_operand_data_references(
    Address instruction_address,
    OperandLocation location,
    xref::DataType type) {
    auto valid = validate_address(instruction_address, "operand xref creation");
    if (!valid)
        return std::unexpected(valid.error());
    auto native_operand = native_location(location);
    if (!native_operand)
        return std::unexpected(native_operand.error());
    auto outer = validate_outer_capability(instruction_address, location);
    if (!outer)
        return std::unexpected(outer.error());
    auto native_type = native_data_type(type);
    if (!native_type)
        return std::unexpected(native_type.error());

    insn_t instruction;
    if (decode_insn(&instruction, static_cast<ea_t>(instruction_address)) <= 0) {
        return std::unexpected(Error::validation(
            "Address does not decode as an instruction",
            std::to_string(instruction_address)));
    }
    const op_t& operand = instruction.ops[location.index];
    if (operand.type == o_void) {
        return std::unexpected(Error::validation(
            "Instruction has no operand at the requested index"));
    }
    refinfo_t info;
    if (!query_native_reference(&info, instruction_address, *native_operand)) {
        return std::unexpected(Error::not_found(
            "Instruction operand has no offset reference metadata"));
    }

    const int encoded_offset = static_cast<unsigned char>(
        location.outer ? operand.offo : operand.offb);
    const adiff_t operand_value = location.outer
        ? static_cast<adiff_t>(operand.value)
        : operand.type == o_imm
            ? static_cast<adiff_t>(operand.value)
            : static_cast<adiff_t>(operand.addr);
    if (instruction.ea > std::numeric_limits<ea_t>::max()
                           - static_cast<ea_t>(encoded_offset)) {
        return std::unexpected(Error::validation(
            "Encoded operand location overflows the address space"));
    }
    const ea_t target = add_refinfo_dref(
        instruction,
        instruction.ea + encoded_offset,
        info,
        operand_value,
        *native_type,
        encoded_offset);
    if (target == BADADDR) {
        return std::unexpected(Error::sdk(
            "Reference-aware data-xref creation failed"));
    }

    xrefblk_t reference;
    bool found = false;
    for (bool current = reference.first_from(instruction.ea, XREF_DATA);
         current;
         current = reference.next_from()) {
        if (reference.to == target
            && reference.type == static_cast<uchar>(*native_type)) {
            found = true;
            break;
        }
    }
    if (!found) {
        return std::unexpected(Error::sdk(
            "Reference-aware data-xref postcondition failed"));
    }
    return static_cast<Address>(target);
}

Result<std::optional<Address>> calculate_base_value(
    Address target, Address base) {
    if (target == BadAddress || base == BadAddress) {
        return std::unexpected(Error::validation(
            "Base-value inputs must not be BadAddress"));
    }
    const ea_t result = calc_basevalue(
        static_cast<ea_t>(target), static_cast<ea_t>(base));
    if (result == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(result)};
}

} // namespace ida::offset
