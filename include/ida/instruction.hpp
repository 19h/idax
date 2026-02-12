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

// ── Operand representation controls ─────────────────────────────────────

/// Set operand display format to hexadecimal.
Status set_op_hex(Address ea, int n);

/// Set operand display format to decimal.
Status set_op_decimal(Address ea, int n);

/// Set operand display format to octal.
Status set_op_octal(Address ea, int n);

/// Set operand display format to binary.
Status set_op_binary(Address ea, int n);

/// Set operand display format to character constant.
Status set_op_character(Address ea, int n);

/// Set operand display format to floating point.
Status set_op_float(Address ea, int n);

/// Set operand as an offset reference. \p base is the offset base (0 for auto).
Status set_op_offset(Address ea, int n, Address base = 0);

/// Set operand to display as a stack variable.
Status set_op_stack_variable(Address ea, int n);

/// Clear operand representation (reset to default/undefined).
Status clear_op_representation(Address ea, int n);

/// Set or clear forced (manual) operand text.
/// Pass empty string to remove forced operand.
Status set_forced_operand(Address ea, int n, std::string_view text);

/// Retrieve forced (manual) operand text, if any.
Result<std::string> get_forced_operand(Address ea, int n);

/// Toggle sign inversion on operand display.
Status toggle_op_sign(Address ea, int n);

/// Toggle bitwise negation on operand display.
Status toggle_op_negate(Address ea, int n);

} // namespace ida::instruction

#endif // IDAX_INSTRUCTION_HPP
