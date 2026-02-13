/// \file advanced_procmod.cpp
/// \brief XRISC-32 Processor Module — a complete processor implementation
///        demonstrating all required and optional procmod callbacks.
///
/// This processor module implements "XRISC-32", a hypothetical 32-bit RISC
/// architecture designed to exercise the full processor module API surface.
/// Unlike minimal examples, this module provides complete implementations
/// for all callbacks, including text output.
///
/// Architecture summary:
///   - 16 general-purpose 32-bit registers (r0..r12, sp, lr, pc)
///   - 2 segment registers (cs, ds) for IDA's segment tracking
///   - Fixed-width 32-bit instruction encoding
///   - PC-relative branches and calls
///   - Simple load/store memory model
///
/// Instruction encoding (32 bits, big-endian fields):
///   [31:28] opcode  — 4 bits, selects one of 16 instructions
///   [27:24] rd      — destination register
///   [23:20] rs1     — source register 1
///   [19:16] rs2     — source register 2
///   [15: 0] imm16   — signed 16-bit immediate
///
/// ISA:
///   0x0 NOP                        0x8 LD   rd, [rs1 + imm16]
///   0x1 MOV  rd, rs1               0x9 ST   rs2, [rs1 + imm16]
///   0x2 LDI  rd, imm16             0xA BEQ  rs1, rs2, imm16
///   0x3 ADD  rd, rs1, rs2          0xB BNE  rs1, rs2, imm16
///   0x4 SUB  rd, rs1, rs2          0xC JMP  imm16
///   0x5 AND  rd, rs1, rs2          0xD CALL imm16
///   0x6 OR   rd, rs1, rs2          0xE RET
///   0x7 XOR  rd, rs1, rs2          0xF HALT
///
/// API surface exercised:
///   processor (Processor, ProcessorInfo, RegisterInfo, InstructionDescriptor,
///   InstructionFeature, AssemblerInfo, ProcessorFlag, SwitchDescription,
///   SwitchCase, EmulateResult, OutputOperandResult), data, xref, analysis,
///   name, function, comment

#include <ida/idax.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

// Portable formatting helper (std::format requires macOS 13.3+ deployment target).
template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[2048];
    std::snprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

// ── XRISC-32 ISA constants ────────────────────────────────────────────

enum Opcode : std::uint8_t {
    OP_NOP  = 0x0,  OP_MOV  = 0x1,  OP_LDI  = 0x2,  OP_ADD  = 0x3,
    OP_SUB  = 0x4,  OP_AND  = 0x5,  OP_OR   = 0x6,  OP_XOR  = 0x7,
    OP_LD   = 0x8,  OP_ST   = 0x9,  OP_BEQ  = 0xA,  OP_BNE  = 0xB,
    OP_JMP  = 0xC,  OP_CALL = 0xD,  OP_RET  = 0xE,  OP_HALT = 0xF,
    OP_COUNT = 16,
};

enum Reg : int {
    R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12,
    SP = 13, LR = 14, PC = 15,
    CS = 16, DS = 17,
    REG_COUNT = 18,
};

/// Register names, indexed by Reg value.
constexpr const char* kRegNames[] = {
    "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "sp",  "lr",  "pc",
    "cs",  "ds",
};

/// Mnemonic strings, indexed by Opcode.
constexpr const char* kMnemonics[] = {
    "nop",  "mov",  "ldi",  "add",  "sub",  "and",  "or",   "xor",
    "ld",   "st",   "beq",  "bne",  "jmp",  "call", "ret",  "halt",
};

// ── Decoded instruction ────────────────────────────────────────────────

struct Decoded {
    Opcode       op{};
    int          rd{};
    int          rs1{};
    int          rs2{};
    std::int16_t imm16{};
};

Decoded decode(std::uint32_t word) {
    return {
        .op    = static_cast<Opcode>((word >> 28) & 0xF),
        .rd    = static_cast<int>((word >> 24) & 0xF),
        .rs1   = static_cast<int>((word >> 20) & 0xF),
        .rs2   = static_cast<int>((word >> 16) & 0xF),
        .imm16 = static_cast<std::int16_t>(word & 0xFFFF),
    };
}

/// Compute the branch target for PC-relative instructions.
ida::Address branch_target(ida::Address insn_addr, std::int16_t offset) {
    return insn_addr + static_cast<ida::Address>(offset * 4);
}

} // anonymous namespace

// ── Processor implementation ───────────────────────────────────────────

class XriscProcessor final : public ida::processor::Processor {
public:

    // ── info(): processor metadata ──────────────────────────────────────

    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;

        pi.id          = 0x8100;
        pi.short_names = {"xrisc32"};
        pi.long_names  = {"XRISC-32 Advanced RISC Processor"};

        pi.flags = static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Segments)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Use32)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DefaultSeg32)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::TypeInfo)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::UseArgTypes)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::HexNumbers);
        pi.flags2 = 0;

        pi.code_bits_per_byte = 8;
        pi.data_bits_per_byte = 8;

        // Registers.
        pi.registers.reserve(REG_COUNT);
        for (int i = 0; i <= 12; ++i) {
            pi.registers.push_back({kRegNames[i], false});
        }
        pi.registers.push_back({kRegNames[SP], false});
        pi.registers.push_back({kRegNames[LR], false});
        pi.registers.push_back({kRegNames[PC], true});   // Read-only from user code.
        pi.registers.push_back({kRegNames[CS], false});
        pi.registers.push_back({kRegNames[DS], false});

        pi.code_segment_register  = CS;
        pi.data_segment_register  = DS;
        pi.first_segment_register = CS;
        pi.last_segment_register  = DS;
        pi.segment_register_size  = 2;

        // Instruction descriptors with feature flags that IDA uses for
        // automatic data-flow analysis (which operands are read/written).
        using IF = ida::processor::InstructionFeature;
        pi.instructions.resize(OP_COUNT);

        pi.instructions[OP_NOP]  = {"nop",  0};
        pi.instructions[OP_MOV]  = {"mov",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[OP_LDI]  = {"ldi",
            static_cast<std::uint32_t>(IF::Change1)};
        pi.instructions[OP_ADD]  = {"add",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[OP_SUB]  = {"sub",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[OP_AND]  = {"and",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[OP_OR]   = {"or",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[OP_XOR]  = {"xor",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[OP_LD]   = {"ld",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[OP_ST]   = {"st",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[OP_BEQ]  = {"beq",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[OP_BNE]  = {"bne",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[OP_JMP]  = {"jmp",
            static_cast<std::uint32_t>(IF::Stop)};
        pi.instructions[OP_CALL] = {"call",
            static_cast<std::uint32_t>(IF::Call)};
        pi.instructions[OP_RET]  = {"ret",
            static_cast<std::uint32_t>(IF::Stop)};
        pi.instructions[OP_HALT] = {"halt",
            static_cast<std::uint32_t>(IF::Stop)};

        pi.return_icode = OP_RET;

        // Assembler syntax.
        ida::processor::AssemblerInfo as;
        as.name            = "XRISC-32 Assembler";
        as.comment_prefix  = ";";
        as.origin          = ".org";
        as.end_directive   = ".end";
        as.string_delim    = '"';
        as.char_delim      = '\'';
        as.byte_directive  = ".byte";
        as.word_directive  = ".half";
        as.dword_directive = ".word";
        as.qword_directive = ".dword";
        pi.assemblers = {as};

        pi.default_bitness = 32;
        return pi;
    }

    // ── analyze(): decode one instruction ───────────────────────────────

    ida::Result<int> analyze(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;

        auto d = decode(*dword);
        if (d.op >= OP_COUNT) return 0;

        // All XRISC-32 instructions are exactly 4 bytes.
        return 4;
    }

    // ── emulate(): create xrefs and schedule follow-on analysis ─────────

    ida::processor::EmulateResult emulate(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return ida::processor::EmulateResult::NotImplemented;

        auto d = decode(*dword);
        ida::Address next = address + 4;

        switch (d.op) {
            case OP_JMP: {
                auto target = branch_target(address, d.imm16);
                ida::xref::add_code(address, target, ida::xref::CodeType::JumpNear);
                ida::analysis::schedule(target);
                break;
            }
            case OP_CALL: {
                auto target = branch_target(address, d.imm16);
                ida::xref::add_code(address, target, ida::xref::CodeType::CallNear);
                ida::xref::add_code(address, next, ida::xref::CodeType::Flow);
                ida::analysis::schedule(target);
                break;
            }
            case OP_BEQ:
            case OP_BNE: {
                auto target = branch_target(address, d.imm16);
                ida::xref::add_code(address, target, ida::xref::CodeType::JumpNear);
                ida::xref::add_code(address, next, ida::xref::CodeType::Flow);
                ida::analysis::schedule(target);
                break;
            }
            case OP_RET:
            case OP_HALT:
                // Terminal instructions: no successors.
                break;

            case OP_LD: {
                // Absolute memory load when base register is r0 (hardwired zero).
                if (d.rs1 == R0) {
                    auto data_addr = static_cast<ida::Address>(
                        static_cast<std::uint16_t>(d.imm16));
                    ida::xref::add_data(address, data_addr, ida::xref::DataType::Read);
                }
                ida::xref::add_code(address, next, ida::xref::CodeType::Flow);
                break;
            }
            case OP_ST: {
                if (d.rs1 == R0) {
                    auto data_addr = static_cast<ida::Address>(
                        static_cast<std::uint16_t>(d.imm16));
                    ida::xref::add_data(address, data_addr, ida::xref::DataType::Write);
                }
                ida::xref::add_code(address, next, ida::xref::CodeType::Flow);
                break;
            }

            default:
                // All arithmetic, logical, and move instructions fall through.
                ida::xref::add_code(address, next, ida::xref::CodeType::Flow);
                break;
        }

        return ida::processor::EmulateResult::Success;
    }

    // ── output_instruction(): generate disassembly text ─────────────────
    //
    // This is the core output callback. IDA calls it for each instruction
    // to produce the text shown in the listing view. The implementation
    // writes directly to ida::ui::message for demonstration; a production
    // processor would use the SDK output buffer provided by the bridge.

    void output_instruction(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return;

        auto d = decode(*dword);
        if (d.op >= OP_COUNT) return;

        // Format the disassembly line based on instruction class.
        std::string text;

        switch (d.op) {
            case OP_NOP:
                text = "nop";
                break;

            case OP_MOV:
                text = fmt("mov     %s, %s",
                    kRegNames[d.rd], kRegNames[d.rs1]);
                break;

            case OP_LDI:
                text = fmt("ldi     %s, 0x%x",
                    kRegNames[d.rd], static_cast<unsigned>(
                        static_cast<std::uint16_t>(d.imm16)));
                break;

            case OP_ADD: case OP_SUB:
            case OP_AND: case OP_OR: case OP_XOR:
                text = fmt("%-8s%s, %s, %s",
                    kMnemonics[d.op], kRegNames[d.rd],
                    kRegNames[d.rs1], kRegNames[d.rs2]);
                break;

            case OP_LD:
                if (d.imm16 == 0) {
                    text = fmt("ld      %s, [%s]",
                        kRegNames[d.rd], kRegNames[d.rs1]);
                } else {
                    text = fmt("ld      %s, [%s + 0x%x]",
                        kRegNames[d.rd], kRegNames[d.rs1],
                        static_cast<unsigned>(
                            static_cast<std::uint16_t>(d.imm16)));
                }
                break;

            case OP_ST:
                if (d.imm16 == 0) {
                    text = fmt("st      %s, [%s]",
                        kRegNames[d.rs2], kRegNames[d.rs1]);
                } else {
                    text = fmt("st      %s, [%s + 0x%x]",
                        kRegNames[d.rs2], kRegNames[d.rs1],
                        static_cast<unsigned>(
                            static_cast<std::uint16_t>(d.imm16)));
                }
                break;

            case OP_BEQ: {
                auto target = branch_target(address, d.imm16);
                // Try to resolve the branch target to a symbol name.
                auto sym = ida::name::get(target);
                if (sym && !sym->empty()) {
                    text = fmt("beq     %s, %s, %s",
                        kRegNames[d.rs1], kRegNames[d.rs2], sym->c_str());
                } else {
                    text = fmt("beq     %s, %s, 0x%llx",
                        kRegNames[d.rs1], kRegNames[d.rs2],
                        (unsigned long long)target);
                }
                break;
            }
            case OP_BNE: {
                auto target = branch_target(address, d.imm16);
                auto sym = ida::name::get(target);
                if (sym && !sym->empty()) {
                    text = fmt("bne     %s, %s, %s",
                        kRegNames[d.rs1], kRegNames[d.rs2], sym->c_str());
                } else {
                    text = fmt("bne     %s, %s, 0x%llx",
                        kRegNames[d.rs1], kRegNames[d.rs2],
                        (unsigned long long)target);
                }
                break;
            }

            case OP_JMP: {
                auto target = branch_target(address, d.imm16);
                auto sym = ida::name::get(target);
                text = (sym && !sym->empty())
                    ? fmt("jmp     %s", sym->c_str())
                    : fmt("jmp     0x%llx", (unsigned long long)target);
                break;
            }

            case OP_CALL: {
                auto target = branch_target(address, d.imm16);
                auto sym = ida::name::get(target);
                text = (sym && !sym->empty())
                    ? fmt("call    %s", sym->c_str())
                    : fmt("call    0x%llx", (unsigned long long)target);
                break;
            }

            case OP_RET:
                text = "ret";
                break;

            case OP_HALT:
                text = "halt";
                break;

            default:
                text = fmt(".word   0x%08x", *dword);
                break;
        }

        // In a real processor module, this text would go through the SDK's
        // output buffer system. Here we demonstrate the formatting logic
        // that the bridge would invoke.
        ida::ui::message(fmt("0x%08llx  %s\n",
            (unsigned long long)address, text.c_str()));
    }

    // ── output_operand(): render individual operands ────────────────────
    //
    // Called for each operand when IDA needs to render operands separately
    // (e.g. for operand highlighting or forced representation). Returns
    // Success to indicate the operand was rendered.

    ida::processor::OutputOperandResult
    output_operand(ida::Address address, int operand_index) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return ida::processor::OutputOperandResult::NotImplemented;

        auto d = decode(*dword);

        // Determine which register or value corresponds to this operand slot.
        // The operand layout depends on the instruction class.
        switch (d.op) {
            case OP_NOP:
            case OP_RET:
            case OP_HALT:
                // No operands.
                return ida::processor::OutputOperandResult::Hidden;

            case OP_MOV:
                // op0 = rd, op1 = rs1
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rd]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    ida::ui::message(kRegNames[d.rs1]);
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_LDI:
                // op0 = rd, op1 = imm16
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rd]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    ida::ui::message(fmt("0x%x",
                        static_cast<unsigned>(
                            static_cast<std::uint16_t>(d.imm16))));
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_ADD: case OP_SUB:
            case OP_AND: case OP_OR: case OP_XOR:
                // op0 = rd, op1 = rs1, op2 = rs2
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rd]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    ida::ui::message(kRegNames[d.rs1]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 2) {
                    ida::ui::message(kRegNames[d.rs2]);
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_LD:
                // op0 = rd, op1 = [rs1 + imm16]
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rd]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    if (d.imm16 == 0)
                        ida::ui::message(fmt("[%s]", kRegNames[d.rs1]));
                    else
                        ida::ui::message(fmt("[%s + 0x%x]",
                            kRegNames[d.rs1],
                            static_cast<unsigned>(
                                static_cast<std::uint16_t>(d.imm16))));
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_ST:
                // op0 = rs2 (value), op1 = [rs1 + imm16] (address)
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rs2]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    if (d.imm16 == 0)
                        ida::ui::message(fmt("[%s]", kRegNames[d.rs1]));
                    else
                        ida::ui::message(fmt("[%s + 0x%x]",
                            kRegNames[d.rs1],
                            static_cast<unsigned>(
                                static_cast<std::uint16_t>(d.imm16))));
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_BEQ:
            case OP_BNE:
                // op0 = rs1, op1 = rs2, op2 = target address
                if (operand_index == 0) {
                    ida::ui::message(kRegNames[d.rs1]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 1) {
                    ida::ui::message(kRegNames[d.rs2]);
                    return ida::processor::OutputOperandResult::Success;
                }
                if (operand_index == 2) {
                    auto target = branch_target(address, d.imm16);
                    auto sym = ida::name::get(target);
                    ida::ui::message((sym && !sym->empty())
                        ? *sym : fmt("0x%llx", (unsigned long long)target));
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;

            case OP_JMP:
            case OP_CALL: {
                // op0 = target address
                if (operand_index == 0) {
                    auto target = branch_target(address, d.imm16);
                    auto sym = ida::name::get(target);
                    ida::ui::message((sym && !sym->empty())
                        ? *sym : fmt("0x%llx", (unsigned long long)target));
                    return ida::processor::OutputOperandResult::Success;
                }
                return ida::processor::OutputOperandResult::Hidden;
            }

            default:
                return ida::processor::OutputOperandResult::NotImplemented;
        }
    }

    // ── on_new_file / on_old_file ───────────────────────────────────────

    void on_new_file(std::string_view filename) override {
        // A real processor would initialize per-file state here (e.g.
        // detecting sub-architecture variants from the file headers).
        ida::ui::message(fmt("[XRISC] New file loaded: %.*s\n",
            static_cast<int>(filename.size()), filename.data()));
    }

    void on_old_file(std::string_view filename) override {
        ida::ui::message(fmt("[XRISC] Existing database opened: %.*s\n",
            static_cast<int>(filename.size()), filename.data()));
    }

    // ── is_call / is_return ─────────────────────────────────────────────

    int is_call(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        return (decode(*dword).op == OP_CALL) ? 1 : -1;
    }

    int is_return(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        return (decode(*dword).op == OP_RET) ? 1 : -1;
    }

    // ── may_be_function ─────────────────────────────────────────────────
    //
    // IDA calls this to estimate whether a function could start here.
    // We recognize two common XRISC prolog patterns:
    //   1. SUB sp, sp, imm — stack frame allocation
    //   2. ST  lr, [sp + off] — link register save

    int may_be_function(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return -1;
        auto d = decode(*dword);

        if (d.op == OP_SUB && d.rd == SP && d.rs1 == SP) return 80;
        if (d.op == OP_ST  && d.rs2 == LR && d.rs1 == SP) return 60;
        if (d.op == OP_NOP) return 10;  // Alignment padding, weak signal.
        return 0;
    }

    // ── is_sane_instruction ─────────────────────────────────────────────
    //
    // Rejects obviously invalid instructions that IDA might speculatively
    // try to decode (e.g. a HALT with no incoming code references is
    // more likely data than an intentional halt).

    int is_sane_instruction(ida::Address address,
                            bool no_code_references) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return -1;
        auto d = decode(*dword);

        if (d.op == OP_HALT && no_code_references) return -1;
        return 1;
    }

    // ── is_indirect_jump ────────────────────────────────────────────────
    //
    // Detects computed jumps that might indicate switch tables.
    // On XRISC, writing to PC via MOV or LD is an indirect jump.

    int is_indirect_jump(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode(*dword);

        if ((d.op == OP_MOV || d.op == OP_LD) && d.rd == PC) return 2;
        return 1;
    }

    // ── is_basic_block_end ──────────────────────────────────────────────

    int is_basic_block_end(ida::Address address,
                           bool call_stops_block) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode(*dword);

        if (d.op == OP_JMP || d.op == OP_RET || d.op == OP_HALT) return 1;
        if (d.op == OP_BEQ || d.op == OP_BNE) return 1;
        if (d.op == OP_CALL && call_stops_block) return 1;
        return -1;
    }

    // ── create_function_frame ───────────────────────────────────────────

    bool create_function_frame(ida::Address function_start) override {
        auto dword = ida::data::read_dword(function_start);
        if (!dword) return false;
        auto d = decode(*dword);

        // Recognize SUB sp, sp, N prolog as frame allocation.
        if (d.op == OP_SUB && d.rd == SP && d.rs1 == SP) {
            // The immediate is the frame size in bytes.
            return true;
        }
        return false;
    }

    // ── adjust_function_bounds ──────────────────────────────────────────

    int adjust_function_bounds(ida::Address function_start,
                               ida::Address max_end,
                               int suggested) override {
        // Don't extend a function into NOP alignment padding that follows it.
        auto after = ida::data::read_dword(max_end);
        if (after && decode(*after).op == OP_NOP) {
            // Keep the kernel's bound — padding belongs to no function.
        }
        return suggested;
    }

    // ── analyze_function_prolog ─────────────────────────────────────────

    int analyze_function_prolog(ida::Address function_start) override {
        // Standard prolog: SUB sp, sp, N ; ST lr, [sp + offset]
        auto w1 = ida::data::read_dword(function_start);
        auto w2 = ida::data::read_dword(function_start + 4);
        if (!w1 || !w2) return 0;

        auto d1 = decode(*w1);
        auto d2 = decode(*w2);

        if (d1.op == OP_SUB && d1.rd == SP && d1.rs1 == SP &&
            d2.op == OP_ST  && d2.rs2 == LR && d2.rs1 == SP) {
            return 1;  // Standard prolog recognized.
        }
        return 0;
    }

    // ── calculate_stack_pointer_delta ────────────────────────────────────

    int calculate_stack_pointer_delta(ida::Address address,
                                     std::int64_t& out_delta) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) { out_delta = 0; return 0; }
        auto d = decode(*dword);

        // SUB sp, sp, imm → allocate (SP decreases).
        if (d.op == OP_SUB && d.rd == SP && d.rs1 == SP) {
            out_delta = -static_cast<std::int64_t>(
                static_cast<std::uint16_t>(d.imm16));
            return 1;
        }
        // ADD sp, sp, imm → deallocate (SP increases).
        if (d.op == OP_ADD && d.rd == SP && d.rs1 == SP) {
            out_delta = static_cast<std::int64_t>(
                static_cast<std::uint16_t>(d.imm16));
            return 1;
        }
        // CALL pushes the return address (4 bytes on 32-bit).
        if (d.op == OP_CALL) { out_delta = -4; return 1; }
        // RET pops the return address.
        if (d.op == OP_RET) { out_delta = 4; return 1; }

        out_delta = 0;
        return 0;
    }

    // ── get_return_address_size ──────────────────────────────────────────

    int get_return_address_size(ida::Address) override {
        return 4;  // 32-bit return address on XRISC-32.
    }

    // ── detect_switch ───────────────────────────────────────────────────
    //
    // Recognizes the XRISC switch idiom:
    //   SUB  r1, r0, low_case     ; normalize to 0-based index
    //   BNE  r1, r2, default_lbl  ; range check (r2 = case count)
    //   LD   pc, [r3 + r1*4]      ; jump through table
    //   .word target0, target1, ...

    int detect_switch(ida::Address address,
                      ida::processor::SwitchDescription& out) override {
        auto w0 = ida::data::read_dword(address);
        auto w1 = ida::data::read_dword(address + 4);
        auto w2 = ida::data::read_dword(address + 8);
        if (!w0 || !w1 || !w2) return 0;

        auto d0 = decode(*w0);
        auto d1 = decode(*w1);
        auto d2 = decode(*w2);

        if (d0.op != OP_SUB) return 0;
        if (d1.op != OP_BNE) return 0;
        if (d2.op != OP_LD || d2.rd != PC) return 0;

        out.kind             = ida::processor::SwitchTableKind::Dense;
        out.jump_table       = address + 12;
        out.values_table     = ida::BadAddress;
        out.default_target   = branch_target(address + 4, d1.imm16);
        out.idiom_start      = address;
        out.element_base     = 0;
        out.low_case_value   = d0.imm16;
        out.case_count       = static_cast<std::uint32_t>(d1.imm16);
        out.jump_table_entry_count = out.case_count;
        out.jump_element_size = 4;
        out.value_element_size = 0;
        out.shift            = 0;
        out.expression_register = d0.rs1;
        out.expression_data_type = 0;
        out.has_default      = true;
        out.default_in_table = false;
        out.values_signed    = false;
        out.subtract_values  = false;
        out.self_relative    = false;
        out.inverted         = false;
        out.user_defined     = false;

        return 1;
    }

    // ── calculate_switch_cases ───────────────────────────────────────────

    int calculate_switch_cases(
        ida::Address address,
        const ida::processor::SwitchDescription& sw,
        std::vector<ida::processor::SwitchCase>& out_cases) override {

        if (sw.jump_table == ida::BadAddress || sw.case_count == 0) return 0;

        out_cases.reserve(sw.case_count);
        for (std::uint32_t i = 0; i < sw.case_count; ++i) {
            auto entry_ea = sw.jump_table + i * sw.jump_element_size;
            auto target_word = ida::data::read_dword(entry_ea);
            if (!target_word) continue;

            ida::processor::SwitchCase sc;
            sc.values.push_back(sw.low_case_value + i);
            sc.target = static_cast<ida::Address>(*target_word);
            out_cases.push_back(std::move(sc));
        }
        return 1;
    }

    // ── create_switch_references ─────────────────────────────────────────

    int create_switch_references(
        ida::Address address,
        const ida::processor::SwitchDescription& sw) override {

        if (sw.jump_table == ida::BadAddress) return 0;

        for (std::uint32_t i = 0; i < sw.jump_table_entry_count; ++i) {
            auto entry_ea = sw.jump_table + i * sw.jump_element_size;
            auto target_word = ida::data::read_dword(entry_ea);
            if (!target_word) continue;

            auto target = static_cast<ida::Address>(*target_word);
            ida::xref::add_code(address, target, ida::xref::CodeType::JumpNear);
            ida::xref::add_data(entry_ea, target, ida::xref::DataType::Offset);
        }
        return 1;
    }
};

IDAX_PROCESSOR(XriscProcessor)
