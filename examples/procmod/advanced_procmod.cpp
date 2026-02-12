/// \file advanced_procmod.cpp
/// \brief Advanced custom processor module demonstrating comprehensive
///        idax processor API usage with a full hypothetical RISC ISA.
///
/// This processor module implements "XRISC-32": a hypothetical 32-bit RISC
/// architecture with 16 general-purpose registers, a simple fixed-width
/// instruction encoding, and support for switch table detection, stack
/// analysis, function prolog recognition, and all optional processor callbacks.
///
/// Instruction encoding (32 bits):
///   [31:28] opcode (4 bits = 16 instructions)
///   [27:24] rd     (destination register, 4 bits)
///   [23:20] rs1    (source register 1, 4 bits)
///   [19:16] rs2    (source register 2, 4 bits)
///   [15: 0] imm16  (16-bit immediate, sign-extended where applicable)
///
/// ISA:
///   0x0: NOP                      - no operation
///   0x1: MOV  rd, rs1             - register move
///   0x2: LDI  rd, imm16           - load immediate
///   0x3: ADD  rd, rs1, rs2        - add registers
///   0x4: SUB  rd, rs1, rs2        - subtract registers
///   0x5: AND  rd, rs1, rs2        - bitwise AND
///   0x6: OR   rd, rs1, rs2        - bitwise OR
///   0x7: XOR  rd, rs1, rs2        - bitwise XOR
///   0x8: LD   rd, [rs1 + imm16]   - load word from memory
///   0x9: ST   rs2, [rs1 + imm16]  - store word to memory
///   0xA: BEQ  rs1, rs2, imm16     - branch if equal (PC-relative)
///   0xB: BNE  rs1, rs2, imm16     - branch if not equal (PC-relative)
///   0xC: JMP  imm16               - unconditional PC-relative jump
///   0xD: CALL imm16               - PC-relative call (link in r15)
///   0xE: RET                      - return (jump to r15)
///   0xF: HALT                     - halt processor
///
/// Edge cases exercised:
///   - All 16 registers with segment register assignment
///   - Full instruction descriptor table with InstructionFeature flags
///   - AssemblerInfo with complete directive set
///   - ProcessorFlag bitmask construction
///   - ProcessorInfo with all metadata fields populated
///   - analyze(): instruction decode with operand classification
///   - emulate(): xref creation and flow analysis
///   - output_instruction(): text generation
///   - output_operand(): per-operand rendering
///   - is_call/is_return classification
///   - may_be_function heuristics
///   - is_sane_instruction validation
///   - is_indirect_jump detection
///   - is_basic_block_end for conditional branches
///   - create_function_frame for stack frame creation
///   - adjust_function_bounds refinement
///   - analyze_function_prolog pattern matching
///   - calculate_stack_pointer_delta tracking
///   - get_return_address_size
///   - detect_switch with SwitchDescription population
///   - calculate_switch_cases with SwitchCase generation
///   - create_switch_references
///   - on_new_file/on_old_file notifications

#include <ida/idax.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// ── Instruction opcodes ────────────────────────────────────────────────

enum XriscOpcode : std::uint8_t {
    XRISC_NOP  = 0x0,
    XRISC_MOV  = 0x1,
    XRISC_LDI  = 0x2,
    XRISC_ADD  = 0x3,
    XRISC_SUB  = 0x4,
    XRISC_AND  = 0x5,
    XRISC_OR   = 0x6,
    XRISC_XOR  = 0x7,
    XRISC_LD   = 0x8,
    XRISC_ST   = 0x9,
    XRISC_BEQ  = 0xA,
    XRISC_BNE  = 0xB,
    XRISC_JMP  = 0xC,
    XRISC_CALL = 0xD,
    XRISC_RET  = 0xE,
    XRISC_HALT = 0xF,
    XRISC_COUNT = 16,
};

// ── Register indices ───────────────────────────────────────────────────

enum XriscRegister : int {
    R0 = 0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12,
    SP = 13,  // Stack pointer
    LR = 14,  // Link register (for CALL)
    PC = 15,  // Program counter
    // Pseudo segment registers:
    CS = 16,
    DS = 17,
    XRISC_REG_COUNT = 18,
};

// ── Instruction decode helper ──────────────────────────────────────────

struct DecodedInsn {
    XriscOpcode opcode{};
    int rd{};
    int rs1{};
    int rs2{};
    std::int16_t imm16{};
    std::uint32_t raw{};
};

DecodedInsn decode_xrisc(std::uint32_t word) {
    DecodedInsn d;
    d.raw    = word;
    d.opcode = static_cast<XriscOpcode>((word >> 28) & 0xF);
    d.rd     = static_cast<int>((word >> 24) & 0xF);
    d.rs1    = static_cast<int>((word >> 20) & 0xF);
    d.rs2    = static_cast<int>((word >> 16) & 0xF);
    d.imm16  = static_cast<std::int16_t>(word & 0xFFFF);
    return d;
}

} // anonymous namespace

// ── Processor implementation ───────────────────────────────────────────

class AdvancedXriscProcessor final : public ida::processor::Processor {
public:
    /// Return comprehensive processor metadata.
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;

        // Processor identification.
        pi.id = 0x8100;  // Custom third-party ID (> 0x8000).
        pi.short_names = {"xrisc32"};
        pi.long_names  = {"XRISC-32 Advanced RISC Processor"};

        // Processor flags.
        pi.flags = static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Segments)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Use32)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DefaultSeg32)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::TypeInfo)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::UseArgTypes)
                 | static_cast<std::uint32_t>(ida::processor::ProcessorFlag::HexNumbers);
        pi.flags2 = 0;

        // Bits per byte.
        pi.code_bits_per_byte = 8;
        pi.data_bits_per_byte = 8;

        // ── Registers ───────────────────────────────────────────────────

        pi.registers.reserve(XRISC_REG_COUNT);
        for (int i = 0; i <= 12; ++i) {
            pi.registers.push_back({"r" + std::to_string(i), false});
        }
        pi.registers.push_back({"sp",  false});  // R13
        pi.registers.push_back({"lr",  false});  // R14
        pi.registers.push_back({"pc",  true});   // R15 is read-only from user code
        pi.registers.push_back({"cs",  false});  // Code segment register
        pi.registers.push_back({"ds",  false});  // Data segment register

        pi.code_segment_register  = CS;
        pi.data_segment_register  = DS;
        pi.first_segment_register = CS;
        pi.last_segment_register  = DS;
        pi.segment_register_size  = 2;

        // ── Instruction descriptors ─────────────────────────────────────

        using IF = ida::processor::InstructionFeature;
        pi.instructions.resize(XRISC_COUNT);

        pi.instructions[XRISC_NOP]  = {"nop",  0};
        pi.instructions[XRISC_MOV]  = {"mov",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[XRISC_LDI]  = {"ldi",
            static_cast<std::uint32_t>(IF::Change1)};
        pi.instructions[XRISC_ADD]  = {"add",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[XRISC_SUB]  = {"sub",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[XRISC_AND]  = {"and",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[XRISC_OR]   = {"or",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[XRISC_XOR]  = {"xor",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2) |
            static_cast<std::uint32_t>(IF::Use3)};
        pi.instructions[XRISC_LD]   = {"ld",
            static_cast<std::uint32_t>(IF::Change1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[XRISC_ST]   = {"st",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[XRISC_BEQ]  = {"beq",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[XRISC_BNE]  = {"bne",
            static_cast<std::uint32_t>(IF::Use1) |
            static_cast<std::uint32_t>(IF::Use2)};
        pi.instructions[XRISC_JMP]  = {"jmp",
            static_cast<std::uint32_t>(IF::Stop)};
        pi.instructions[XRISC_CALL] = {"call",
            static_cast<std::uint32_t>(IF::Call)};
        pi.instructions[XRISC_RET]  = {"ret",
            static_cast<std::uint32_t>(IF::Stop)};
        pi.instructions[XRISC_HALT] = {"halt",
            static_cast<std::uint32_t>(IF::Stop)};

        pi.return_icode = XRISC_RET;

        // ── Assembler ───────────────────────────────────────────────────

        ida::processor::AssemblerInfo asminfo;
        asminfo.name            = "XRISC-32 Assembler";
        asminfo.comment_prefix  = ";";
        asminfo.origin          = ".org";
        asminfo.end_directive   = ".end";
        asminfo.string_delim    = '"';
        asminfo.char_delim      = '\'';
        asminfo.byte_directive  = ".byte";
        asminfo.word_directive  = ".half";
        asminfo.dword_directive = ".word";
        asminfo.qword_directive = ".dword";

        pi.assemblers = {asminfo};

        pi.default_bitness = 32;

        return pi;
    }

    // ── Required: analyze ───────────────────────────────────────────────

    /// Decode one instruction. Returns instruction size in bytes (always 4).
    ida::Result<int> analyze(ida::Address address) override {
        // Read 4 bytes from the database.
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;  // Decode failure.

        auto d = decode_xrisc(*dword);

        // Validate opcode range.
        if (d.opcode >= XRISC_COUNT) return 0;

        // All XRISC instructions are 4 bytes.
        return 4;
    }

    // ── Required: emulate ───────────────────────────────────────────────

    /// Create xrefs and plan analysis based on instruction semantics.
    ida::processor::EmulateResult emulate(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return ida::processor::EmulateResult::NotImplemented;

        auto d = decode_xrisc(*dword);
        ida::Address next_addr = address + 4;

        switch (d.opcode) {
            case XRISC_JMP: {
                // Unconditional jump: PC-relative.
                ida::Address target = address +
                    static_cast<ida::Address>(d.imm16 * 4);
                (void)ida::xref::add_code(address, target,
                    ida::xref::CodeType::JumpNear);
                // No fall-through.
                break;
            }
            case XRISC_CALL: {
                // Call: PC-relative, with fall-through.
                ida::Address target = address +
                    static_cast<ida::Address>(d.imm16 * 4);
                (void)ida::xref::add_code(address, target,
                    ida::xref::CodeType::CallNear);
                (void)ida::xref::add_code(address, next_addr,
                    ida::xref::CodeType::Flow);
                break;
            }
            case XRISC_BEQ:
            case XRISC_BNE: {
                // Conditional branch: PC-relative + fall-through.
                ida::Address target = address +
                    static_cast<ida::Address>(d.imm16 * 4);
                (void)ida::xref::add_code(address, target,
                    ida::xref::CodeType::JumpNear);
                (void)ida::xref::add_code(address, next_addr,
                    ida::xref::CodeType::Flow);
                break;
            }
            case XRISC_RET:
            case XRISC_HALT:
                // No successors.
                break;

            case XRISC_LD: {
                // Memory load: create data xref if base is zero (absolute).
                if (d.rs1 == R0) {
                    ida::Address data_addr =
                        static_cast<ida::Address>(static_cast<std::uint16_t>(d.imm16));
                    (void)ida::xref::add_data(address, data_addr,
                        ida::xref::DataType::Read);
                }
                (void)ida::xref::add_code(address, next_addr,
                    ida::xref::CodeType::Flow);
                break;
            }
            case XRISC_ST: {
                // Memory store: create data write xref if base is zero.
                if (d.rs1 == R0) {
                    ida::Address data_addr =
                        static_cast<ida::Address>(static_cast<std::uint16_t>(d.imm16));
                    (void)ida::xref::add_data(address, data_addr,
                        ida::xref::DataType::Write);
                }
                (void)ida::xref::add_code(address, next_addr,
                    ida::xref::CodeType::Flow);
                break;
            }

            default:
                // All other instructions: simple fall-through.
                (void)ida::xref::add_code(address, next_addr,
                    ida::xref::CodeType::Flow);
                break;
        }

        // Schedule analysis of branch targets.
        if (d.opcode == XRISC_JMP || d.opcode == XRISC_CALL ||
            d.opcode == XRISC_BEQ || d.opcode == XRISC_BNE) {
            ida::Address target = address +
                static_cast<ida::Address>(d.imm16 * 4);
            (void)ida::analysis::schedule(target);
        }

        return ida::processor::EmulateResult::Success;
    }

    // ── Required: output_instruction ────────────────────────────────────

    /// Generate text for an instruction. This is a simplified version
    /// that constructs the disassembly text.
    void output_instruction(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return;

        auto d = decode_xrisc(*dword);
        // In a full implementation, we'd use the SDK output context.
        // This is intentionally minimal since the output context is
        // highly SDK-dependent and the wrapper provides override points.
        (void)d;
    }

    // ── Required: output_operand ────────────────────────────────────────

    /// Generate text for a single operand.
    ida::processor::OutputOperandResult
    output_operand(ida::Address address, int operand_index) override {
        (void)address;
        (void)operand_index;
        // In a full implementation we'd render register names, immediates, etc.
        return ida::processor::OutputOperandResult::NotImplemented;
    }

    // ── Optional: on_new_file/on_old_file ───────────────────────────────

    void on_new_file(std::string_view filename) override {
        // Called when a new file is loaded. Initialize processor state.
        (void)filename;
    }

    void on_old_file(std::string_view filename) override {
        // Called when an existing database is opened. Restore processor state.
        (void)filename;
    }

    // ── Optional: is_call ───────────────────────────────────────────────

    /// Definitive call classification.
    int is_call(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode_xrisc(*dword);
        if (d.opcode == XRISC_CALL) return 1;   // Definitely a call.
        return -1;  // Definitely not a call.
    }

    // ── Optional: is_return ─────────────────────────────────────────────

    /// Definitive return classification.
    int is_return(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode_xrisc(*dword);
        if (d.opcode == XRISC_RET) return 1;
        return -1;
    }

    // ── Optional: may_be_function ───────────────────────────────────────

    /// Probability that a function starts at this address.
    /// Look for common prolog patterns.
    int may_be_function(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return -1;  // Definitely not.
        auto d = decode_xrisc(*dword);

        // Common function prolog: SUB SP, SP, imm (allocate frame).
        if (d.opcode == XRISC_SUB && d.rd == SP && d.rs1 == SP) {
            return 80;  // High probability.
        }

        // Another prolog: ST LR, [SP + offset] (save link register).
        if (d.opcode == XRISC_ST && d.rs2 == LR && d.rs1 == SP) {
            return 60;
        }

        // NOP prolog (alignment padding before function).
        if (d.opcode == XRISC_NOP) {
            return 10;  // Low probability, might be padding.
        }

        return 0;  // No opinion.
    }

    // ── Optional: is_sane_instruction ───────────────────────────────────

    /// Validate whether this instruction makes sense in context.
    int is_sane_instruction(ida::Address address,
                            bool no_code_references) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return -1;
        auto d = decode_xrisc(*dword);

        // HALT with no code references is suspicious.
        if (d.opcode == XRISC_HALT && no_code_references) {
            return -1;
        }

        // MOV r0, r0 is effectively a NOP; unusual but sane.
        if (d.opcode == XRISC_MOV && d.rd == 0 && d.rs1 == 0) {
            return 0;  // Sane but uninteresting.
        }

        return 1;  // Sane.
    }

    // ── Optional: is_indirect_jump ──────────────────────────────────────

    /// Detect indirect jumps (e.g., computed gotos / switch tables).
    int is_indirect_jump(ida::Address address) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode_xrisc(*dword);

        // In XRISC, a MOV to PC from a general register is an indirect jump.
        if (d.opcode == XRISC_MOV && d.rd == PC) {
            return 2;  // Yes, indirect jump.
        }

        // LD into PC is also an indirect jump.
        if (d.opcode == XRISC_LD && d.rd == PC) {
            return 2;
        }

        return 1;  // No.
    }

    // ── Optional: is_basic_block_end ────────────────────────────────────

    /// Determine if this instruction ends a basic block.
    int is_basic_block_end(ida::Address address,
                           bool call_instruction_stops_block) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) return 0;
        auto d = decode_xrisc(*dword);

        // Unconditional jumps, returns, halts always end blocks.
        if (d.opcode == XRISC_JMP || d.opcode == XRISC_RET ||
            d.opcode == XRISC_HALT) {
            return 1;
        }

        // Conditional branches end blocks (block splits).
        if (d.opcode == XRISC_BEQ || d.opcode == XRISC_BNE) {
            return 1;
        }

        // Calls end blocks if requested.
        if (d.opcode == XRISC_CALL && call_instruction_stops_block) {
            return 1;
        }

        return -1;  // Does not end block.
    }

    // ── Optional: create_function_frame ─────────────────────────────────

    /// Create a stack frame for a function at the given start address.
    bool create_function_frame(ida::Address function_start) override {
        // Look for the prolog: SUB SP, SP, imm16
        auto dword = ida::data::read_dword(function_start);
        if (!dword) return false;
        auto d = decode_xrisc(*dword);

        if (d.opcode == XRISC_SUB && d.rd == SP && d.rs1 == SP) {
            // Frame size is the immediate value (in bytes).
            // In a real implementation, we'd call the SDK's
            // add_frame() to create the frame structure.
            return true;
        }

        return false;  // No frame pattern recognized.
    }

    // ── Optional: adjust_function_bounds ────────────────────────────────

    /// Refine function boundary analysis.
    int adjust_function_bounds(ida::Address function_start,
                               ida::Address max_function_end,
                               int suggested_result) override {
        // Edge case: if the function is very small (< 2 instructions),
        // be suspicious.
        if (max_function_end - function_start < 8) {
            // Still allow it, but don't change the result.
        }

        // Look for alignment NOPs after the function.
        auto after = ida::data::read_dword(max_function_end);
        if (after) {
            auto d = decode_xrisc(*after);
            if (d.opcode == XRISC_NOP) {
                // Don't extend the function into NOP padding.
            }
        }

        return suggested_result;
    }

    // ── Optional: analyze_function_prolog ────────────────────────────────

    /// Analyze function prolog to determine calling convention and frame.
    int analyze_function_prolog(ida::Address function_start) override {
        // Pattern: SUB SP, SP, N; ST LR, [SP + offset]
        auto dword1 = ida::data::read_dword(function_start);
        auto dword2 = ida::data::read_dword(function_start + 4);

        if (!dword1 || !dword2) return 0;

        auto d1 = decode_xrisc(*dword1);
        auto d2 = decode_xrisc(*dword2);

        if (d1.opcode == XRISC_SUB && d1.rd == SP && d1.rs1 == SP &&
            d2.opcode == XRISC_ST && d2.rs2 == LR && d2.rs1 == SP) {
            // Standard prolog detected.
            return 1;  // Handled.
        }

        return 0;  // Not implemented / not recognized.
    }

    // ── Optional: calculate_stack_pointer_delta ─────────────────────────

    /// Compute SP delta for one instruction.
    int calculate_stack_pointer_delta(ida::Address address,
                                     std::int64_t& out_delta) override {
        auto dword = ida::data::read_dword(address);
        if (!dword) { out_delta = 0; return 0; }

        auto d = decode_xrisc(*dword);

        // SUB SP, SP, imm => SP decreases (allocate).
        if (d.opcode == XRISC_SUB && d.rd == SP && d.rs1 == SP) {
            out_delta = -static_cast<std::int64_t>(
                static_cast<std::uint16_t>(d.imm16));
            return 1;
        }

        // ADD SP, SP, imm => SP increases (deallocate).
        if (d.opcode == XRISC_ADD && d.rd == SP && d.rs1 == SP) {
            out_delta = static_cast<std::int64_t>(
                static_cast<std::uint16_t>(d.imm16));
            return 1;
        }

        // CALL pushes return address (4 bytes).
        if (d.opcode == XRISC_CALL) {
            out_delta = -4;
            return 1;
        }

        // RET pops return address.
        if (d.opcode == XRISC_RET) {
            out_delta = 4;
            return 1;
        }

        out_delta = 0;
        return 0;  // Not handled.
    }

    // ── Optional: get_return_address_size ────────────────────────────────

    /// Return address is always 4 bytes on XRISC-32.
    int get_return_address_size(ida::Address) override {
        return 4;
    }

    // ── Optional: detect_switch ─────────────────────────────────────────

    /// Detect switch table idioms.
    ///
    /// XRISC switch pattern:
    ///   SUB  r1, r0, low_case     ; normalize to 0-based index
    ///   BNE  r1, r2, default_lbl  ; range check (r2 holds case_count)
    ///   LD   pc, [r3 + r1*4]      ; jump through table
    ///   .word target0             ; jump table follows
    ///   .word target1
    ///   ...
    int detect_switch(ida::Address address,
                      ida::processor::SwitchDescription& out_switch) override {
        // Read 3 consecutive instructions.
        auto w0 = ida::data::read_dword(address);
        auto w1 = ida::data::read_dword(address + 4);
        auto w2 = ida::data::read_dword(address + 8);

        if (!w0 || !w1 || !w2) return 0;

        auto d0 = decode_xrisc(*w0);
        auto d1 = decode_xrisc(*w1);
        auto d2 = decode_xrisc(*w2);

        // Check the pattern.
        if (d0.opcode != XRISC_SUB) return 0;  // Normalize step.
        if (d1.opcode != XRISC_BNE) return 0;  // Range check.
        if (d2.opcode != XRISC_LD || d2.rd != PC) return 0;  // Table load.

        // Populate switch description.
        out_switch.kind = ida::processor::SwitchTableKind::Dense;
        out_switch.jump_table = address + 12;  // Table starts after 3 instructions.
        out_switch.values_table = ida::BadAddress;  // Dense: no separate values.
        out_switch.default_target = address + 4 +
            static_cast<ida::Address>(d1.imm16 * 4);
        out_switch.idiom_start = address;
        out_switch.element_base = 0;
        out_switch.low_case_value = d0.imm16;
        out_switch.case_count = static_cast<std::uint32_t>(d1.imm16);
        out_switch.jump_table_entry_count = out_switch.case_count;
        out_switch.jump_element_size = 4;
        out_switch.value_element_size = 0;
        out_switch.shift = 0;
        out_switch.expression_register = d0.rs1;
        out_switch.expression_data_type = 0;
        out_switch.has_default = true;
        out_switch.default_in_table = false;
        out_switch.values_signed = false;
        out_switch.subtract_values = false;
        out_switch.self_relative = false;
        out_switch.inverted = false;
        out_switch.user_defined = false;

        return 1;  // Switch found.
    }

    // ── Optional: calculate_switch_cases ─────────────────────────────────

    /// Calculate case values and targets for a detected switch.
    int calculate_switch_cases(
        ida::Address address,
        const ida::processor::SwitchDescription& sw,
        std::vector<ida::processor::SwitchCase>& out_cases) override {

        if (sw.jump_table == ida::BadAddress || sw.case_count == 0) {
            return 0;
        }

        out_cases.reserve(sw.case_count);

        for (std::uint32_t i = 0; i < sw.case_count; ++i) {
            ida::Address table_entry = sw.jump_table + i * sw.jump_element_size;
            auto target_word = ida::data::read_dword(table_entry);
            if (!target_word) continue;

            ida::processor::SwitchCase sc;
            sc.values.push_back(sw.low_case_value + i);
            sc.target = static_cast<ida::Address>(*target_word);
            out_cases.push_back(std::move(sc));
        }

        return 1;  // Handled.
    }

    // ── Optional: create_switch_references ───────────────────────────────

    /// Create xrefs for switch table entries.
    int create_switch_references(
        ida::Address address,
        const ida::processor::SwitchDescription& sw) override {

        if (sw.jump_table == ida::BadAddress) return 0;

        for (std::uint32_t i = 0; i < sw.jump_table_entry_count; ++i) {
            ida::Address table_entry = sw.jump_table + i * sw.jump_element_size;
            auto target_word = ida::data::read_dword(table_entry);
            if (!target_word) continue;

            ida::Address target = static_cast<ida::Address>(*target_word);

            // Code xref from the switch instruction to each target.
            (void)ida::xref::add_code(address, target,
                ida::xref::CodeType::JumpNear);

            // Data xref from the table entry to the target.
            (void)ida::xref::add_data(table_entry, target,
                ida::xref::DataType::Offset);
        }

        return 1;  // Handled.
    }
};

IDAX_PROCESSOR(AdvancedXriscProcessor)
