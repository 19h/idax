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

} // namespace ida::instruction
