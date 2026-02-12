/// \file instruction.hpp
/// \brief Instruction decode, operand access, and text rendering.

#ifndef IDAX_INSTRUCTION_HPP
#define IDAX_INSTRUCTION_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace ida::instruction {

// ── Operand type enum ───────────────────────────────────────────────────

enum class OperandType {
    None,
    Register,
    MemoryDirect,
    MemoryPhrase,
    MemoryDisplacement,
    Immediate,
    FarAddress,
    NearAddress,
    ProcessorSpecific0,
    ProcessorSpecific1,
    ProcessorSpecific2,
    ProcessorSpecific3,
    ProcessorSpecific4,
    ProcessorSpecific5,
};

// ── Operand value object ────────────────────────────────────────────────

class Operand {
public:
    [[nodiscard]] int         index()    const noexcept { return index_; }
    [[nodiscard]] OperandType type()     const noexcept { return type_; }

    [[nodiscard]] bool is_register()  const noexcept { return type_ == OperandType::Register; }
    [[nodiscard]] bool is_immediate() const noexcept { return type_ == OperandType::Immediate; }
    [[nodiscard]] bool is_memory()    const noexcept {
        return type_ == OperandType::MemoryDirect
            || type_ == OperandType::MemoryPhrase
            || type_ == OperandType::MemoryDisplacement;
    }

    [[nodiscard]] std::uint16_t register_id()    const noexcept { return reg_; }
    [[nodiscard]] std::uint64_t value()          const noexcept { return value_; }
    [[nodiscard]] Address       target_address() const noexcept { return addr_; }
    [[nodiscard]] std::int64_t  displacement()   const noexcept { return static_cast<std::int64_t>(value_); }

private:
    friend class Instruction;
    friend struct InstructionAccess;
    int            index_{};
    OperandType    type_{OperandType::None};
    std::uint16_t  reg_{};
    std::uint64_t  value_{};
    Address        addr_{};
};

// ── Instruction value object ────────────────────────────────────────────

class Instruction {
public:
    [[nodiscard]] Address     address()        const noexcept { return ea_; }
    [[nodiscard]] AddressSize size()           const noexcept { return size_; }
    [[nodiscard]] std::uint16_t opcode()       const noexcept { return itype_; }
    [[nodiscard]] std::string   mnemonic()     const { return mnemonic_; }

    [[nodiscard]] std::size_t operand_count()  const noexcept { return operands_.size(); }
    [[nodiscard]] Result<Operand> operand(std::size_t idx) const;

    [[nodiscard]] const std::vector<Operand>& operands() const noexcept { return operands_; }

private:
    friend struct InstructionAccess;

    Address            ea_{};
    AddressSize        size_{};
    std::uint16_t      itype_{};
    std::string        mnemonic_;
    std::vector<Operand> operands_;
};

// ── Decode / create ─────────────────────────────────────────────────────

/// Decode an instruction without modifying the database.
Result<Instruction> decode(Address ea);

/// Create an instruction in the database (marks bytes as code).
Result<Instruction> create(Address ea);

/// Get the rendered disassembly text at an address.
Result<std::string> text(Address ea);

} // namespace ida::instruction

#endif // IDAX_INSTRUCTION_HPP
