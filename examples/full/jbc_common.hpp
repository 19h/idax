#ifndef IDAX_EXAMPLES_FULL_JBC_COMMON_HPP
#define IDAX_EXAMPLES_FULL_JBC_COMMON_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <string_view>

namespace idax::examples::jbc {

constexpr std::uint32_t kMagicVersion1 = 0x004D414A;  // "JAM\0" as LE dword.
constexpr std::uint32_t kMagicVersion2 = 0x014D414A;  // "JAM\1" as LE dword.
constexpr std::size_t kMinimumHeaderSize = 52;

constexpr const char* kSegmentStrings = ".strtab";
constexpr const char* kSegmentCode = ".code";
constexpr const char* kSegmentData = ".data";

constexpr const char* kStateNodeName = "$ JBC";
constexpr std::uint64_t kStateCodeBaseIndex = 1;
constexpr std::uint64_t kStateStringBaseIndex = 2;

constexpr int kRegisterSp = 0;
constexpr int kRegisterPc = 1;
constexpr int kRegisterAcc = 2;
constexpr int kRegisterCs = 3;
constexpr int kRegisterDs = 4;
constexpr int kRegisterCount = 5;

enum class OperandKind : std::uint8_t {
    None = 0,
    Immediate32,
    Variable,
    Address,
    StringOffset,
    State,
    Count,
};

enum InstructionFlag : std::uint16_t {
    FlagNone = 0,
    FlagBranch = 1u << 0,
    FlagCall = 1u << 1,
    FlagReturn = 1u << 2,
    FlagStop = 1u << 3,
    FlagJtag = 1u << 4,
    FlagStack = 1u << 5,
    FlagIo = 1u << 6,
    FlagConditional = 1u << 7,
    FlagUnimplemented = 1u << 8,
};

inline bool has_flag(std::uint16_t flags, InstructionFlag flag) {
    return (flags & static_cast<std::uint16_t>(flag)) != 0;
}

struct InstructionDefinition {
    std::uint8_t opcode;
    std::string_view mnemonic;
    OperandKind operand1;
    OperandKind operand2;
    OperandKind operand3;
    std::int8_t stack_delta;
    std::uint16_t flags;
};

inline int argument_count(std::uint8_t opcode) {
    return (opcode >> 6) & 0x3;
}

inline int instruction_size(std::uint8_t opcode) {
    return 1 + (argument_count(opcode) * 4);
}

inline std::uint32_t read_big_endian_u32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24)
         | (static_cast<std::uint32_t>(data[1]) << 16)
         | (static_cast<std::uint32_t>(data[2]) << 8)
         | static_cast<std::uint32_t>(data[3]);
}

inline std::uint32_t read_little_endian_u32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0])
         | (static_cast<std::uint32_t>(data[1]) << 8)
         | (static_cast<std::uint32_t>(data[2]) << 16)
         | (static_cast<std::uint32_t>(data[3]) << 24);
}

inline std::string_view jtag_state_name(std::uint8_t state) {
    static constexpr std::array<const char*, 16> kNames = {
        "TEST_LOGIC_RESET", "RUN_TEST_IDLE",
        "SELECT_DR_SCAN", "CAPTURE_DR", "SHIFT_DR", "EXIT1_DR",
        "PAUSE_DR", "EXIT2_DR", "UPDATE_DR",
        "SELECT_IR_SCAN", "CAPTURE_IR", "SHIFT_IR", "EXIT1_IR",
        "PAUSE_IR", "EXIT2_IR", "UPDATE_IR",
    };
    if (state < kNames.size())
        return kNames[state];
    return "UNKNOWN_STATE";
}

inline const auto& instruction_table() {
    static const std::array<InstructionDefinition, 66> kTable = {{
        {0x00, "nop",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagNone},
        {0x01, "dup",  OperandKind::None,       OperandKind::None,       OperandKind::None,       1,  FlagStack},
        {0x02, "swp",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagStack},
        {0x03, "add",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x04, "sub",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x05, "mult", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x06, "div",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x07, "mod",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x08, "shl",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x09, "shr",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x0A, "not",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagNone},
        {0x0B, "and",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x0C, "or",   OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x0D, "xor",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x0E, "inv",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagNone},
        {0x0F, "gt",   OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x10, "lt",   OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x11, "ret",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagReturn},
        {0x12, "cmps", OperandKind::None,       OperandKind::None,       OperandKind::None,      -3,  FlagNone},
        {0x13, "pint", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagIo},
        {0x14, "prnt", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagIo},
        {0x15, "dss",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x16, "dssc", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x17, "iss",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x18, "issc", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x19, "vss",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  static_cast<std::uint16_t>(FlagJtag | FlagUnimplemented)},
        {0x1A, "vssc", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  static_cast<std::uint16_t>(FlagJtag | FlagUnimplemented)},
        {0x1B, "vmpf", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  static_cast<std::uint16_t>(FlagJtag | FlagUnimplemented)},
        {0x1C, "dpr",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x1D, "dprl", OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x1E, "dpo",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x1F, "dpol", OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x20, "ipr",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x21, "iprl", OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x22, "ipo",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagJtag},
        {0x23, "ipol", OperandKind::None,       OperandKind::None,       OperandKind::None,      -2,  FlagJtag},
        {0x24, "pchr", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagIo},
        {0x25, "exit", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagStop},
        {0x26, "equ",  OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagNone},
        {0x27, "popt", OperandKind::None,       OperandKind::None,       OperandKind::None,      -1,  FlagStack},
        {0x28, "trst", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  static_cast<std::uint16_t>(FlagJtag | FlagUnimplemented)},
        {0x29, "frq",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagUnimplemented},
        {0x2A, "frqu", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagUnimplemented},
        {0x2B, "pd32", OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagUnimplemented},
        {0x2C, "abs",  OperandKind::None,       OperandKind::None,       OperandKind::None,       0,  FlagNone},
        {0x2D, "bch0", OperandKind::None,       OperandKind::None,       OperandKind::None,       3,  FlagStack},
        {0x2E, "bch1", OperandKind::None,       OperandKind::None,       OperandKind::None,       2,  static_cast<std::uint16_t>(FlagStack | FlagUnimplemented)},
        {0x2F, "psh0", OperandKind::None,       OperandKind::None,       OperandKind::None,       1,  FlagStack},
        {0x40, "pshl", OperandKind::Immediate32, OperandKind::None,       OperandKind::None,       1,  FlagStack},
        {0x41, "pshv", OperandKind::Variable,    OperandKind::None,       OperandKind::None,       1,  FlagStack},
        {0x42, "jmp",  OperandKind::Address,     OperandKind::None,       OperandKind::None,       0,  FlagBranch},
        {0x43, "call", OperandKind::Address,     OperandKind::None,       OperandKind::None,       0,  FlagCall},
        {0x45, "pstr", OperandKind::StringOffset, OperandKind::None,      OperandKind::None,       0,  FlagIo},
        {0x47, "sint", OperandKind::State,       OperandKind::None,       OperandKind::None,       0,  FlagJtag},
        {0x48, "st",   OperandKind::State,       OperandKind::None,       OperandKind::None,       0,  FlagJtag},
        {0x49, "istp", OperandKind::State,       OperandKind::None,       OperandKind::None,       0,  FlagJtag},
        {0x4A, "dstp", OperandKind::State,       OperandKind::None,       OperandKind::None,       0,  FlagJtag},
        {0x50, "jmpz", OperandKind::Address,     OperandKind::None,       OperandKind::None,      -1,  static_cast<std::uint16_t>(FlagBranch | FlagConditional)},
        {0x51, "ds",   OperandKind::Variable,    OperandKind::None,       OperandKind::None,      -3,  FlagJtag},
        {0x52, "is",   OperandKind::Variable,    OperandKind::None,       OperandKind::None,      -3,  FlagJtag},
        {0x57, "expt", OperandKind::StringOffset, OperandKind::None,      OperandKind::None,      -1,  FlagIo},
        {0x80, "copy", OperandKind::Variable,    OperandKind::Variable,   OperandKind::None,      -4,  FlagNone},
        {0x82, "dsc",  OperandKind::Variable,    OperandKind::Variable,   OperandKind::None,      -5,  FlagJtag},
        {0x83, "isc",  OperandKind::Variable,    OperandKind::Variable,   OperandKind::None,      -5,  FlagJtag},
        {0x84, "wait", OperandKind::State,       OperandKind::State,      OperandKind::None,      -4,  FlagJtag},
        {0xC0, "cmpa", OperandKind::Variable,    OperandKind::Variable,   OperandKind::Variable,  -6,  FlagNone},
    }};
    return kTable;
}

inline const InstructionDefinition* lookup_instruction(std::uint8_t opcode) {
    const auto& table = instruction_table();
    for (const auto& entry : table) {
        if (entry.opcode == opcode)
            return &entry;
    }
    return nullptr;
}

inline OperandKind operand_kind(const InstructionDefinition* def, int operand_index) {
    if (def == nullptr)
        return OperandKind::Immediate32;
    switch (operand_index) {
    case 0: return def->operand1;
    case 1: return def->operand2;
    case 2: return def->operand3;
    default: return OperandKind::None;
    }
}

}  // namespace idax::examples::jbc

#endif  // IDAX_EXAMPLES_FULL_JBC_COMMON_HPP
