/// \file instruction.cpp
/// \brief Implementation of ida::instruction — decode, create, operand access.

#include "detail/sdk_bridge.hpp"
#include <ida/instruction.hpp>

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

} // anonymous namespace

// ── Internal access helper ──────────────────────────────────────────────

struct InstructionAccess {
    static Instruction populate(const insn_t& raw, const std::string& mnemonic_text) {
        Instruction insn;
        insn.ea_    = static_cast<Address>(raw.ea);
        insn.size_  = static_cast<AddressSize>(raw.size);
        insn.itype_ = raw.itype;
        insn.mnemonic_ = mnemonic_text;

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

            insn.operands_.push_back(operand);
        }

        return insn;
    }
};

// ── Instruction::operand ────────────────────────────────────────────────

Result<Operand> Instruction::operand(std::size_t idx) const {
    if (idx >= operands_.size())
        return std::unexpected(Error::validation("Operand index out of range",
                                                 std::to_string(idx)));
    return operands_[idx];
}

// ── Decode / create ─────────────────────────────────────────────────────

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

Status set_op_hex(Address ea, int n) {
    if (!op_hex(ea, n))
        return std::unexpected(Error::sdk("op_hex failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_decimal(Address ea, int n) {
    if (!op_dec(ea, n))
        return std::unexpected(Error::sdk("op_dec failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_octal(Address ea, int n) {
    if (!op_oct(ea, n))
        return std::unexpected(Error::sdk("op_oct failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_binary(Address ea, int n) {
    if (!op_bin(ea, n))
        return std::unexpected(Error::sdk("op_bin failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_character(Address ea, int n) {
    if (!op_chr(ea, n))
        return std::unexpected(Error::sdk("op_chr failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_float(Address ea, int n) {
    if (!op_flt(ea, n))
        return std::unexpected(Error::sdk("op_flt failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_offset(Address ea, int n, Address base) {
    if (!op_plain_offset(ea, n, base))
        return std::unexpected(Error::sdk("op_plain_offset failed", std::to_string(ea)));
    return ida::ok();
}

Status set_op_stack_variable(Address ea, int n) {
    if (!op_stkvar(ea, n))
        return std::unexpected(Error::sdk("op_stkvar failed", std::to_string(ea)));
    return ida::ok();
}

Status clear_op_representation(Address ea, int n) {
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

Status toggle_op_sign(Address ea, int n) {
    if (!::toggle_sign(ea, n))
        return std::unexpected(Error::sdk("toggle_sign failed", std::to_string(ea)));
    return ida::ok();
}

Status toggle_op_negate(Address ea, int n) {
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
