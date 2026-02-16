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

enum class OperandFormat {
    Default,
    Hex,
    Decimal,
    Octal,
    Binary,
    Character,
    Float,
    Offset,
    StackVariable,
};

enum class RegisterClass {
    Unknown,
    GeneralPurpose,
    Segment,
    FloatingPoint,
    Vector,
    Mask,
    Control,
    Debug,
    Other,
};

/// Structured representation of an operand struct-offset path.
///
/// A path may contain nested structure/union ids. The `delta` field matches
/// SDK `get_stroff_path()` semantics.
struct StructOffsetPath {
    std::vector<std::uint64_t> structure_ids;
    AddressDelta               delta{0};
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
    [[nodiscard]] int           byte_width()     const noexcept { return byte_width_; }
    [[nodiscard]] std::string   register_name()  const { return register_name_; }
    [[nodiscard]] RegisterClass register_class() const noexcept { return register_class_; }
    [[nodiscard]] bool is_vector_register() const noexcept {
        return register_class_ == RegisterClass::Vector;
    }
    [[nodiscard]] bool is_mask_register() const noexcept {
        return register_class_ == RegisterClass::Mask;
    }

private:
    friend class Instruction;
    friend struct InstructionAccess;
    int            index_{};
    OperandType    type_{OperandType::None};
    std::uint16_t  reg_{};
    std::uint64_t  value_{};
    Address        addr_{};
    int            byte_width_{};
    std::string    register_name_;
    RegisterClass  register_class_{RegisterClass::Unknown};
};

// ── Instruction value object ────────────────────────────────────────────

class Instruction {
public:
    [[nodiscard]] Address     address()        const noexcept { return ea_; }
    [[nodiscard]] AddressSize size()           const noexcept { return size_; }
    [[nodiscard]] std::uint16_t opcode()       const noexcept { return itype_; }
    [[nodiscard]] std::string   mnemonic()     const { return mnemonic_; }

    [[nodiscard]] std::size_t operand_count()  const noexcept { return operands_.size(); }
    [[nodiscard]] Result<Operand> operand(std::size_t index) const;

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
Result<Instruction> decode(Address address);

/// Create an instruction in the database (marks bytes as code).
Result<Instruction> create(Address address);

/// Get the rendered disassembly text at an address.
Result<std::string> text(Address address);

// ── Operand representation controls ─────────────────────────────────────

/// Set operand display format to hexadecimal.
Status set_operand_hex(Address address, int n);

/// Set operand display format to decimal.
Status set_operand_decimal(Address address, int n);

/// Set operand display format to octal.
Status set_operand_octal(Address address, int n);

/// Set operand display format to binary.
Status set_operand_binary(Address address, int n);

/// Set operand display format to character constant.
Status set_operand_character(Address address, int n);

/// Set operand display format to floating point.
Status set_operand_float(Address address, int n);

/// Generic operand format setter.
Status set_operand_format(Address address, int n, OperandFormat format, Address base = 0);

/// Set operand as an offset reference. \p base is the offset base (0 for auto).
Status set_operand_offset(Address address, int n, Address base = 0);

/// Set operand to display as a structure member offset by structure name.
///
/// This mirrors SDK `op_stroff()` for single-structure paths.
/// `delta` denotes the difference between the structure base and pointer.
Status set_operand_struct_offset(Address address,
                                 int n,
                                 std::string_view structure_name,
                                 AddressDelta delta = 0);

/// Set operand to display as a structure member offset by structure id.
///
/// `structure_id` is a raw SDK structure id (`tid_t`).
Status set_operand_struct_offset(Address address,
                                 int n,
                                 std::uint64_t structure_id,
                                 AddressDelta delta = 0);

/// Set operand representation as a structure offset using an explicit base.
///
/// This mirrors SDK `op_based_stroff()`.
Status set_operand_based_struct_offset(Address address,
                                       int n,
                                       Address operand_value,
                                       Address base);

/// Read struct-offset path metadata for an operand.
///
/// This mirrors SDK `get_stroff_path()` and returns NotFound when no struct
/// offset path is present on the operand.
Result<StructOffsetPath> operand_struct_offset_path(Address address, int n);

/// Read struct-offset path metadata as resolved type names.
///
/// Name lookup falls back to `tid_<id>` for unresolved entries.
Result<std::vector<std::string>> operand_struct_offset_path_names(Address address, int n);

/// Set operand to display as a stack variable.
Status set_operand_stack_variable(Address address, int n);

/// Clear operand representation (reset to default/undefined).
Status clear_operand_representation(Address address, int n);

/// Set or clear forced (manual) operand text.
/// Pass empty string to remove forced operand.
Status set_forced_operand(Address address, int n, std::string_view text);

/// Retrieve forced (manual) operand text, if any.
Result<std::string> get_forced_operand(Address address, int n);

/// Render only the operand text for operand index \p n.
Result<std::string> operand_text(Address address, int n);

/// Structured byte-width query for operand index \p n.
Result<int> operand_byte_width(Address address, int n);

/// Register name for operand index \p n.
/// Returns NotFound when the operand is not a register.
Result<std::string> operand_register_name(Address address, int n);

/// Structured register classification for operand index \p n.
/// Returns NotFound when the operand is not a register.
Result<RegisterClass> operand_register_class(Address address, int n);

/// Toggle sign inversion on operand display.
Status toggle_operand_sign(Address address, int n);

/// Toggle bitwise negation on operand display.
Status toggle_operand_negate(Address address, int n);

// ── Instruction-level xref conveniences ─────────────────────────────────

/// Code cross-references originating from the instruction at \p address.
/// Returns target addresses of call/jump/flow references.
Result<std::vector<Address>> code_refs_from(Address address);

/// Data cross-references originating from the instruction at \p address.
/// Returns target addresses of data reads/writes/offsets.
Result<std::vector<Address>> data_refs_from(Address address);

/// All call targets from the instruction at \p address (fl_CN/fl_CF only).
Result<std::vector<Address>> call_targets(Address address);

/// All jump targets from the instruction at \p address (fl_JN/fl_JF only).
Result<std::vector<Address>> jump_targets(Address address);

/// Does the instruction at \p address have fall-through to the next instruction?
bool has_fall_through(Address address);

/// Is the instruction at \p address a call instruction?
bool is_call(Address address);

/// Is the instruction at \p address a return instruction?
bool is_return(Address address);

/// Is the instruction at \p address any jump instruction?
bool is_jump(Address address);

/// Is the instruction at \p address a conditional jump instruction?
bool is_conditional_jump(Address address);

/// Decode the next instruction sequentially after \p address.
Result<Instruction> next(Address address);

/// Decode the previous instruction before \p address.
Result<Instruction> prev(Address address);

} // namespace ida::instruction

#endif // IDAX_INSTRUCTION_HPP
