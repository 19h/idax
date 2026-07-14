/// \file instruction.cpp
/// \brief Implementation of ida::instruction — decode, create, operand access.

#include "detail/sdk_bridge.hpp"
#include <ida/instruction.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>

namespace ida::instruction {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

/// Map SDK optype_t to our OperandType enum.
OperandType map_operand_type(optype_t t) {
    switch (t) {
        case o_void:    return OperandType::None;
        case o_reg:     return OperandType::Register;
        case o_mem:     return OperandType::MemoryDirect;
        case o_phrase:  return OperandType::MemoryPhrase;
        case o_displ:   return OperandType::MemoryDisplacement;
        case o_imm:     return OperandType::Immediate;
        case o_far:     return OperandType::FarAddress;
        case o_near:    return OperandType::NearAddress;
        case o_idpspec0: return OperandType::ProcessorSpecific0;
        case o_idpspec1: return OperandType::ProcessorSpecific1;
        case o_idpspec2: return OperandType::ProcessorSpecific2;
        case o_idpspec3: return OperandType::ProcessorSpecific3;
        case o_idpspec4: return OperandType::ProcessorSpecific4;
        case o_idpspec5: return OperandType::ProcessorSpecific5;
        default:         return OperandType::None;
    }
}

std::string to_lower_ascii(std::string text) {
    std::transform(text.begin(),
                   text.end(),
                   text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size()
        && text.compare(0, prefix.size(), prefix) == 0;
}

bool is_decimal_suffix(std::string_view text, std::size_t start) {
    if (start >= text.size())
        return false;
    for (std::size_t index = start; index < text.size(); ++index) {
        if (!std::isdigit(static_cast<unsigned char>(text[index])))
            return false;
    }
    return true;
}

RegisterCategory classify_register_name(std::string_view register_name) {
    if (register_name.empty())
        return RegisterCategory::Unknown;

    const std::string lowered = to_lower_ascii(std::string(register_name));

    if (lowered == "cs" || lowered == "ds" || lowered == "es"
        || lowered == "fs" || lowered == "gs" || lowered == "ss") {
        return RegisterCategory::Segment;
    }

    if (starts_with(lowered, "xmm") || starts_with(lowered, "ymm")
        || starts_with(lowered, "zmm") || starts_with(lowered, "mm")
        || starts_with(lowered, "q")) {
        return RegisterCategory::Vector;
    }

    if (starts_with(lowered, "k") && is_decimal_suffix(lowered, 1))
        return RegisterCategory::Mask;

    if (starts_with(lowered, "st") || starts_with(lowered, "fp")
        || starts_with(lowered, "fpr")) {
        return RegisterCategory::FloatingPoint;
    }

    if (starts_with(lowered, "cr"))
        return RegisterCategory::Control;

    if (starts_with(lowered, "dr"))
        return RegisterCategory::Debug;

    if (starts_with(lowered, "r") || starts_with(lowered, "e")
        || starts_with(lowered, "a") || starts_with(lowered, "b")
        || starts_with(lowered, "c") || starts_with(lowered, "d")
        || starts_with(lowered, "s") || starts_with(lowered, "t")
        || starts_with(lowered, "x") || starts_with(lowered, "w")) {
        return RegisterCategory::GeneralPurpose;
    }

    return RegisterCategory::Other;
}

int width_from_register_name(std::string_view register_name) {
    const std::string lowered = to_lower_ascii(std::string(register_name));

    if (starts_with(lowered, "zmm") || starts_with(lowered, "q"))
        return 64;
    if (starts_with(lowered, "ymm"))
        return 32;
    if (starts_with(lowered, "xmm"))
        return 16;
    if (starts_with(lowered, "mm"))
        return 8;
    if (starts_with(lowered, "k") && is_decimal_suffix(lowered, 1))
        return 8;
    if (starts_with(lowered, "st") || starts_with(lowered, "fp"))
        return 10;

    return 0;
}

int operand_byte_width(const op_t& op) {
    const size_t width = get_dtype_size(op.dtype);
    return width == 0 || width == BADSIZE ? 0 : static_cast<int>(width);
}

Result<insn_t> decode_raw_instruction(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return std::unexpected(Error::sdk("decode_insn failed", std::to_string(ea)));
    return raw;
}

struct ExactStructMemberIdentity {
    tid_t structure_tid{BADNODE};
    tid_t member_tid{BADADDR};
};

Result<ExactStructMemberIdentity>
resolve_exact_struct_member(std::string_view structure_name,
                            std::size_t member_byte_offset) {
    if (structure_name.empty())
        return std::unexpected(Error::validation("Structure name must not be empty"));
    if (structure_name.find('\0') != std::string_view::npos)
        return std::unexpected(Error::validation(
            "Structure name must not contain NUL bytes"));
    if (member_byte_offset > std::numeric_limits<std::uint64_t>::max() / 8)
        return std::unexpected(Error::validation("Member byte offset is too large"));

    const std::string name(structure_name);
    tinfo_t type;
    if (!type.get_named_type(get_idati(), name.c_str()))
        return std::unexpected(Error::not_found("Structure not found", name));
    if (!type.is_udt() || type.is_forward_decl())
        return std::unexpected(Error::validation(
            "Exact member paths require a complete struct or union", name));
    if (type.is_from_subtil() || type.get_ordinal() == 0)
        return std::unexpected(Error::conflict(
            "Exact member paths require a saved local UDT", name));

    udt_type_data_t details;
    if (!type.get_udt_details(&details))
        return std::unexpected(Error::sdk("Failed to get UDT details", name));

    const std::uint64_t bit_offset =
        static_cast<std::uint64_t>(member_byte_offset) * 8;
    std::optional<std::size_t> member_index;
    for (std::size_t index = 0; index < details.size(); ++index) {
        if (details[index].offset != bit_offset)
            continue;
        if (member_index) {
            return std::unexpected(Error::conflict(
                "Member byte offset is ambiguous",
                name + ":" + std::to_string(member_byte_offset)));
        }
        member_index = index;
    }
    if (!member_index) {
        return std::unexpected(Error::not_found(
            "No exact UDT member at byte offset",
            name + ":" + std::to_string(member_byte_offset)));
    }

    const tid_t structure_tid = get_named_type_tid(name.c_str());
    if (structure_tid == BADNODE || structure_tid == BADADDR)
        return std::unexpected(Error::conflict(
            "Structure has no stable database identity", name));
    const tid_t member_tid = type.get_udm_tid(*member_index);
    if (member_tid == BADNODE || member_tid == BADADDR)
        return std::unexpected(Error::conflict(
            "UDT member has no stable database identity",
            name + ":" + std::to_string(member_byte_offset)));
    return ExactStructMemberIdentity{structure_tid, member_tid};
}

struct NativeStructOffsetPath {
    std::vector<tid_t> components;
    adiff_t delta{0};
};

Result<NativeStructOffsetPath>
native_struct_offset_path(Address ea, int n) {
    if (ea == BadAddress)
        return std::unexpected(Error::validation("Address must not be BadAddress"));
    if (n < 0 || n >= UA_MAXOP)
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(n)));
    tid_t path[MAXSTRUCPATH] = {};
    adiff_t delta = 0;
    const int length = get_stroff_path(path, &delta, ea, n);
    if (length <= 0) {
        if (is_stroff(get_flags(ea), n)) {
            return std::unexpected(Error::sdk(
                "Operand is marked as a struct offset but its path is unavailable",
                std::to_string(ea) + ":" + std::to_string(n)));
        }
        return std::unexpected(Error::not_found(
            "Operand has no struct-offset path",
            std::to_string(ea) + ":" + std::to_string(n)));
    }
    if (length > static_cast<int>(MAXSTRUCPATH))
        return std::unexpected(Error::sdk("Struct-offset path exceeds SDK bound"));

    NativeStructOffsetPath result;
    result.delta = delta;
    result.components.assign(path, path + length);
    return result;
}

std::string decode_operand_register_name(Address address,
                                         int operand_index,
                                         const op_t& op,
                                         int byte_width) {
    if (op.type != o_reg && op.type != o_phrase && op.type != o_displ)
        return {};

    qstring text;
    const size_t width = op.type == o_reg && byte_width > 0
        ? static_cast<size_t>(byte_width)
        : 8;
    if (get_reg_name(&text, op.reg, width, -1) <= 0)
        return {};

    tag_remove(&text);
    std::string register_name = ida::detail::to_string(text);
    if (register_name.empty()) {
        qstring operand_text;
        if (!print_operand(&operand_text, address, operand_index))
            return {};
        tag_remove(&operand_text);
        register_name = ida::detail::to_string(operand_text);
    }
    return register_name;
}

} // anonymous namespace

// ── Internal access helper ──────────────────────────────────────────────

struct InstructionAccess {
    static Instruction populate(const insn_t& raw, const std::string& mnemonic_text) {
        Instruction insn;
        insn.ea_    = static_cast<Address>(raw.ea);
        insn.size_  = static_cast<AddressSize>(raw.size);
        insn.itype_ = raw.itype;
        insn.mnemonic_ = mnemonic_text;

        processor_t* processor = get_ph();
        const uint32 feature = processor ? raw.get_canon_feature(*processor) : 0;

        // Collect non-void operands.
        for (int i = 0; i < UA_MAXOP; ++i) {
            const op_t& op = raw.ops[i];
            if (op.type == o_void)
                break;

            Operand operand;
            operand.index_ = i;
            operand.type_  = map_operand_type(static_cast<optype_t>(op.type));
            operand.reg_   = op.reg;
            operand.value_ = static_cast<std::uint64_t>(op.value);
            operand.addr_  = static_cast<Address>(op.addr);
            operand.byte_width_ = operand_byte_width(op);
            operand.encoded_value_offset_ = static_cast<std::uint8_t>(
                static_cast<unsigned char>(op.offb));
            operand.secondary_encoded_value_offset_ = static_cast<std::uint8_t>(
                static_cast<unsigned char>(op.offo));
            operand.read_ = has_cf_use(feature, i);
            operand.written_ = has_cf_chg(feature, i);

            if (operand.type_ == OperandType::Register
                || operand.type_ == OperandType::MemoryPhrase
                || operand.type_ == OperandType::MemoryDisplacement) {
                operand.register_name_ = decode_operand_register_name(insn.ea_, i, op, operand.byte_width_);
                operand.register_category_ = classify_register_name(operand.register_name_);
                if (operand.type_ == OperandType::Register && operand.byte_width_ <= 0)
                    operand.byte_width_ = width_from_register_name(operand.register_name_);
            }

            insn.operands_.push_back(operand);
        }

        return insn;
    }
};

// ── Instruction::operand ────────────────────────────────────────────────

Result<Operand> Instruction::operand(std::size_t index) const {
    if (index >= operands_.size())
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(index)));
    return operands_[index];
}

// ── Decode / create ─────────────────────────────────────────────────────

Result<Instruction> from_raw_insn(const void* raw_insn) {
    if (!raw_insn) return std::unexpected(Error::validation("Null raw_insn"));
    const insn_t* raw = static_cast<const insn_t*>(raw_insn);
    
    qstring qmnem;
    print_insn_mnem(&qmnem, raw->ea);
    std::string mnem = ida::detail::to_string(qmnem);

    return InstructionAccess::populate(*raw, mnem);
}

Result<Instruction> decode(Address ea) {
    insn_t raw;
    int sz = decode_insn(&raw, ea);
    if (sz <= 0)
        return std::unexpected(Error::sdk("decode_insn failed", std::to_string(ea)));

    // Get mnemonic text.
    qstring qmnem;
    print_insn_mnem(&qmnem, ea);
    std::string mnem = ida::detail::to_string(qmnem);

    return InstructionAccess::populate(raw, mnem);
}

Result<Instruction> create(Address ea) {
    insn_t raw;
    int sz = ::create_insn(ea, &raw);
    if (sz <= 0)
        return std::unexpected(Error::sdk("create_insn failed", std::to_string(ea)));

    // Get mnemonic text.
    qstring qmnem;
    print_insn_mnem(&qmnem, ea);
    std::string mnem = ida::detail::to_string(qmnem);

    return InstructionAccess::populate(raw, mnem);
}

Result<std::string> text(Address ea) {
    qstring buf;
    if (!generate_disasm_line(&buf, ea, GENDSM_FORCE_CODE))
        return std::unexpected(Error::sdk("generate_disasm_line failed", std::to_string(ea)));

    // Remove color/tag escape codes from the output.
    tag_remove(&buf);
    return ida::detail::to_string(buf);
}

// ── Operand representation controls ─────────────────────────────────────

Status set_operand_hex(Address ea, int n) {
    if (!op_hex(ea, n))
        return std::unexpected(Error::sdk("op_hex failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_decimal(Address ea, int n) {
    if (!op_dec(ea, n))
        return std::unexpected(Error::sdk("op_dec failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_octal(Address ea, int n) {
    if (!op_oct(ea, n))
        return std::unexpected(Error::sdk("op_oct failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_binary(Address ea, int n) {
    if (!op_bin(ea, n))
        return std::unexpected(Error::sdk("op_bin failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_character(Address ea, int n) {
    if (!op_chr(ea, n))
        return std::unexpected(Error::sdk("op_chr failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_float(Address ea, int n) {
    if (!op_flt(ea, n))
        return std::unexpected(Error::sdk("op_flt failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_format(Address ea, int n, OperandFormat format, Address base) {
    switch (format) {
    case OperandFormat::Default:
        return clear_operand_representation(ea, n);
    case OperandFormat::Hex:
        return set_operand_hex(ea, n);
    case OperandFormat::Decimal:
        return set_operand_decimal(ea, n);
    case OperandFormat::Octal:
        return set_operand_octal(ea, n);
    case OperandFormat::Binary:
        return set_operand_binary(ea, n);
    case OperandFormat::Character:
        return set_operand_character(ea, n);
    case OperandFormat::Float:
        return set_operand_float(ea, n);
    case OperandFormat::Offset:
        return set_operand_offset(ea, n, base);
    case OperandFormat::StackVariable:
        return set_operand_stack_variable(ea, n);
    }
    return std::unexpected(Error::validation("Unknown operand format"));
}

Status set_operand_offset(Address ea, int n, Address base) {
    if (!op_plain_offset(ea, n, base))
        return std::unexpected(Error::sdk("op_plain_offset failed", std::to_string(ea)));
    return ida::ok();
}

Status set_operand_enum(Address ea,
                        int n,
                        std::string_view enum_name,
                        std::uint8_t serial) {
    if (ea == BadAddress)
        return std::unexpected(Error::validation("Address must not be BadAddress"));
    if (n < -1 || n >= UA_MAXOP)
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(n)));
    if (enum_name.empty())
        return std::unexpected(Error::validation("Enum name must not be empty"));
    if (enum_name.find('\0') != std::string_view::npos)
        return std::unexpected(Error::validation("Enum name must not contain NUL bytes"));

    const std::string name(enum_name);
    tinfo_t type;
    if (!type.get_named_type(get_idati(), name.c_str()))
        return std::unexpected(Error::not_found("Enum type not found", name));
    if (!type.is_enum())
        return std::unexpected(Error::validation("Named type is not an enum", name));

    const tid_t tid = get_named_type_tid(name.c_str());
    if (tid == BADNODE || tid == BADADDR)
        return std::unexpected(Error::not_found("Enum type has no local identity", name));
    const int sdk_operand = n == -1 ? OPND_ALL : n;
    if (!op_enum(ea, sdk_operand, tid, serial)) {
        return std::unexpected(Error::sdk("op_enum failed",
                                          std::to_string(ea) + ":" + std::to_string(n)));
    }
    return ida::ok();
}

Result<OperandEnum> operand_enum(Address ea, int n) {
    if (ea == BadAddress)
        return std::unexpected(Error::validation("Address must not be BadAddress"));
    if (n < -1 || n >= UA_MAXOP)
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(n)));

    uchar serial = 0;
    const int sdk_operand = n == -1 ? OPND_ALL : n;
    const tid_t tid = get_enum_id(&serial, ea, sdk_operand);
    if (tid == BADNODE || tid == BADADDR) {
        return std::unexpected(Error::not_found("Operand has no enum representation",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    }

    qstring name;
    if (!get_tid_name(&name, tid) || name.empty()) {
        return std::unexpected(Error::not_found("Operand enum name is unavailable",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    }

    OperandEnum result;
    result.name = ida::detail::to_string(name);
    result.serial = static_cast<std::uint8_t>(serial);
    return result;
}

Status set_operand_struct_offset(Address ea,
                                 int n,
                                 std::string_view structure_name,
                                 AddressDelta delta) {
    if (structure_name.empty()) {
        return std::unexpected(Error::validation("Structure name must not be empty"));
    }

    const std::string name_text(structure_name);
    const tid_t structure_id = get_named_type_tid(name_text.c_str());
    if (structure_id == BADNODE || structure_id == BADADDR) {
        return std::unexpected(Error::not_found("Structure not found", name_text));
    }

    auto raw = decode_raw_instruction(ea);
    if (!raw)
        return std::unexpected(raw.error());

    const tid_t path[1] = {structure_id};
    if (!op_stroff(*raw, n, path, 1, static_cast<adiff_t>(delta))) {
        return std::unexpected(Error::sdk("op_stroff failed",
                                          std::to_string(ea) + ":" + std::to_string(n)));
    }
    return ida::ok();
}

Result<bool> ensure_operand_struct_member_offset(
    Address ea,
    int n,
    std::string_view structure_name,
    std::size_t member_byte_offset,
    AddressDelta delta) {
    if (ea == BadAddress)
        return std::unexpected(Error::validation("Address must not be BadAddress"));
    if (n < 0 || n >= UA_MAXOP)
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(n)));

    auto identity = resolve_exact_struct_member(structure_name, member_byte_offset);
    if (!identity)
        return std::unexpected(identity.error());
    const std::vector<tid_t> expected{
        identity->structure_tid,
        identity->member_tid,
    };

    auto existing = native_struct_offset_path(ea, n);
    if (existing) {
        if (existing->components == expected
            && existing->delta == static_cast<adiff_t>(delta)) {
            return false;
        }
        return std::unexpected(Error::conflict(
            "Operand already has an incompatible struct-offset path",
            std::to_string(ea) + ":" + std::to_string(n)));
    }
    if (existing.error().category != ErrorCategory::NotFound)
        return std::unexpected(existing.error());

    if (is_defarg(get_flags(ea), n)) {
        return std::unexpected(Error::conflict(
            "Operand already has an incompatible representation",
            std::to_string(ea) + ":" + std::to_string(n)));
    }

    auto raw = decode_raw_instruction(ea);
    if (!raw)
        return std::unexpected(raw.error());
    if (!op_stroff(*raw,
                   n,
                   expected.data(),
                   static_cast<int>(expected.size()),
                   static_cast<adiff_t>(delta))) {
        (void)clr_op_type(ea, n);
        return std::unexpected(Error::sdk(
            "op_stroff failed",
            std::to_string(ea) + ":" + std::to_string(n)));
    }

    auto verified = native_struct_offset_path(ea, n);
    if (!verified || verified->components != expected
        || verified->delta != static_cast<adiff_t>(delta)) {
        (void)clr_op_type(ea, n);
        return std::unexpected(Error::sdk(
            "Struct-offset path verification failed",
            std::to_string(ea) + ":" + std::to_string(n)));
    }
    return true;
}

Status set_operand_based_struct_offset(Address ea,
                                       int n,
                                       Address operand_value,
                                       Address base) {
    auto raw = decode_raw_instruction(ea);
    if (!raw)
        return std::unexpected(raw.error());

    if (!op_based_stroff(*raw,
                         n,
                         static_cast<adiff_t>(operand_value),
                         static_cast<ea_t>(base))) {
        return std::unexpected(Error::sdk("op_based_stroff failed",
                                          std::to_string(ea) + ":" + std::to_string(n)));
    }
    return ida::ok();
}

Result<StructOffsetPath> operand_struct_offset_path(Address ea, int n) {
    auto native = native_struct_offset_path(ea, n);
    if (!native)
        return std::unexpected(native.error());
    if (native->components.empty())
        return std::unexpected(Error::sdk("Struct-offset path has no root component"));

    StructOffsetPath result;
    result.delta = static_cast<AddressDelta>(native->delta);

    qstring root_name;
    if (!get_tid_name(&root_name, native->components.front()) || root_name.empty()) {
        return std::unexpected(Error::not_found(
            "Struct-offset root name is unavailable",
            std::to_string(ea) + ":" + std::to_string(n)));
    }
    result.structure_name = ida::detail::to_string(root_name);
    result.member_names.reserve(native->components.size() - 1);
    for (std::size_t index = 1; index < native->components.size(); ++index) {
        tinfo_t owner;
        udm_t member;
        if (owner.get_udm_by_tid(&member, native->components[index]) < 0) {
            return std::unexpected(Error::not_found(
                "Struct-offset member name is unavailable",
                std::to_string(ea) + ":" + std::to_string(n)
                    + ":" + std::to_string(index)));
        }
        if (member.name.empty()) {
            return std::unexpected(Error::not_found(
                "Struct-offset member name is empty",
                std::to_string(ea) + ":" + std::to_string(n)
                    + ":" + std::to_string(index)));
        }
        result.member_names.push_back(ida::detail::to_string(member.name));
    }
    return result;
}

Result<std::vector<std::string>> operand_struct_offset_path_names(Address ea, int n) {
    auto path = operand_struct_offset_path(ea, n);
    if (!path) {
        return std::unexpected(path.error());
    }

    std::vector<std::string> names;
    names.reserve(1 + path->member_names.size());
    names.push_back(path->structure_name);
    names.insert(names.end(), path->member_names.begin(), path->member_names.end());
    return names;
}

Status set_operand_stack_variable(Address ea, int n) {
    if (!op_stkvar(ea, n))
        return std::unexpected(Error::sdk("op_stkvar failed", std::to_string(ea)));
    return ida::ok();
}

Status clear_operand_representation(Address ea, int n) {
    if (!clr_op_type(ea, n))
        return std::unexpected(Error::sdk("clr_op_type failed", std::to_string(ea)));
    return ida::ok();
}

Status set_forced_operand(Address ea, int n, std::string_view txt) {
    std::string s(txt);
    if (!::set_forced_operand(ea, n, s.empty() ? "" : s.c_str()))
        return std::unexpected(Error::sdk("set_forced_operand failed", std::to_string(ea)));
    return ida::ok();
}

Result<std::string> get_forced_operand(Address ea, int n) {
    qstring buf;
    ssize_t sz = ::get_forced_operand(&buf, ea, n);
    if (sz < 0)
        return std::unexpected(Error::not_found("No forced operand",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    return ida::detail::to_string(buf);
}

Result<std::string> operand_text(Address ea, int n) {
    qstring text;
    if (!print_operand(&text, ea, n))
        return std::unexpected(Error::sdk("print_operand failed",
                                          std::to_string(ea) + ":" + std::to_string(n)));
    return ida::detail::to_string(text);
}

Result<int> operand_byte_width(Address ea, int n) {
    auto insn = decode(ea);
    if (!insn)
        return std::unexpected(insn.error());

    auto op = insn->operand(static_cast<std::size_t>(n));
    if (!op)
        return std::unexpected(op.error());
    return op->byte_width();
}

Result<std::string> operand_register_name(Address ea, int n) {
    auto insn = decode(ea);
    if (!insn)
        return std::unexpected(insn.error());

    auto op = insn->operand(static_cast<std::size_t>(n));
    if (!op)
        return std::unexpected(op.error());
    if (!op->is_register()) {
        return std::unexpected(Error::not_found("Operand is not a register",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    }
    if (op->register_name().empty()) {
        return std::unexpected(Error::not_found("Register name is unavailable",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    }
    return op->register_name();
}

Result<RegisterCategory> operand_register_category(Address ea, int n) {
    auto insn = decode(ea);
    if (!insn)
        return std::unexpected(insn.error());

    auto op = insn->operand(static_cast<std::size_t>(n));
    if (!op)
        return std::unexpected(op.error());
    if (!op->is_register()) {
        return std::unexpected(Error::not_found("Operand is not a register",
                                                std::to_string(ea) + ":" + std::to_string(n)));
    }
    return op->register_category();
}

Status toggle_operand_sign(Address ea, int n) {
    if (!::toggle_sign(ea, n))
        return std::unexpected(Error::sdk("toggle_sign failed", std::to_string(ea)));
    return ida::ok();
}

Status toggle_operand_negate(Address ea, int n) {
    if (!::toggle_bnot(ea, n))
        return std::unexpected(Error::sdk("toggle_bnot failed", std::to_string(ea)));
    return ida::ok();
}

// ── Instruction-level xref conveniences ─────────────────────────────────

Result<std::vector<Address>> code_refs_from(Address ea) {
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode)
            result.push_back(static_cast<Address>(xb.to));
    }
    return result;
}

Result<std::vector<Address>> data_refs_from(Address ea) {
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (!xb.iscode)
            result.push_back(static_cast<Address>(xb.to));
    }
    return result;
}

Result<std::vector<Address>> call_targets(Address ea) {
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
            result.push_back(static_cast<Address>(xb.to));
    }
    return result;
}

Result<std::vector<Address>> jump_targets(Address ea) {
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode && (xb.type == fl_JN || xb.type == fl_JF))
            result.push_back(static_cast<Address>(xb.to));
    }
    return result;
}

bool has_fall_through(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return false;
    // An instruction has fall-through if it doesn't unconditionally transfer control.
    // Check if there is a flow xref (fl_F) from this instruction.
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode && xb.type == fl_F)
            return true;
    }
    return false;
}

bool is_call(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return false;
    // Check for call xrefs from this instruction.
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
            return true;
    }
    return false;
}

bool is_return(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return false;
    // A return instruction has no code xrefs from it at all (except possibly flow to next
    // for conditional returns). The SDK way: check if is_ret_insn returns true.
    return is_ret_insn(raw);
}

bool is_jump(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return false;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (xb.iscode && (xb.type == fl_JN || xb.type == fl_JF))
            return true;
    }
    return false;
}

bool is_conditional_jump(Address ea) {
    insn_t raw;
    if (decode_insn(&raw, ea) <= 0)
        return false;
    xrefblk_t xb;
    bool has_jump = false;
    bool has_fallthrough = false;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
        if (!xb.iscode)
            continue;
        if (xb.type == fl_JN || xb.type == fl_JF)
            has_jump = true;
        if (xb.type == fl_F)
            has_fallthrough = true;
    }
    return has_jump && has_fallthrough;
}

Result<Instruction> next(Address ea) {
    // Find the next head (instruction or data) after ea.
    ea_t next_ea = next_head(ea, BADADDR);
    if (next_ea == BADADDR)
        return std::unexpected(Error::not_found("No next instruction"));
    return decode(next_ea);
}

Result<Instruction> prev(Address ea) {
    ea_t prev_ea = prev_head(ea, 0);
    if (prev_ea == BADADDR)
        return std::unexpected(Error::not_found("No previous instruction"));
    return decode(prev_ea);
}

} // namespace ida::instruction
