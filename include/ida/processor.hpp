/// \file processor.hpp
/// \brief Processor module development helpers.
///
/// Provides data types for defining processor registers, instructions,
/// assembler syntax, and the Processor base class for custom processor modules.
///
/// To create a custom processor module:
/// 1. Subclass ida::processor::Processor
/// 2. Override info(), analyze(), emulate(), output_instruction(), output_operand()
/// 3. Use IDAX_PROCESSOR(YourProcessor) macro at file scope to export

#ifndef IDAX_PROCESSOR_HPP
#define IDAX_PROCESSOR_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdio>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ida::processor {

// ── Register descriptor ─────────────────────────────────────────────────

/// Describes a single processor register.
struct RegisterInfo {
    std::string name;
    bool        read_only{false};
};

// ── Instruction descriptor ──────────────────────────────────────────────

/// Feature flags for instruction descriptors.
/// These correspond to the SDK's CF_* flags.
enum class InstructionFeature : std::uint32_t {
    None        = 0,
    Stop        = 0x00001,   ///< Does not pass execution to next insn.
    Call        = 0x00002,   ///< Is a CALL instruction.
    Change1     = 0x00004,   ///< Modifies operand 1.
    Change2     = 0x00008,   ///< Modifies operand 2.
    Change3     = 0x00010,   ///< Modifies operand 3.
    Change4     = 0x00020,   ///< Modifies operand 4.
    Change5     = 0x00040,   ///< Modifies operand 5.
    Change6     = 0x00080,   ///< Modifies operand 6.
    Use1        = 0x00100,   ///< Uses operand 1.
    Use2        = 0x00200,   ///< Uses operand 2.
    Use3        = 0x00400,   ///< Uses operand 3.
    Use4        = 0x00800,   ///< Uses operand 4.
    Use5        = 0x01000,   ///< Uses operand 5.
    Use6        = 0x02000,   ///< Uses operand 6.
    Jump        = 0x04000,   ///< Indirect jump/call.
    Shift       = 0x08000,   ///< Bit-shift instruction.
    HighLevel   = 0x10000,   ///< May appear in HLL function.
};

/// Describes a single instruction in the processor's instruction set.
struct InstructionDescriptor {
    std::string   mnemonic;
    std::uint32_t feature_flags{0};
    std::uint8_t  operand_count{0};
    std::string   description;
    bool          privileged{false};
};

// ── Assembler syntax descriptor ─────────────────────────────────────────

/// Describes assembler syntax preferences.
/// This is a simplified view of the SDK's complex asm_t struct.
struct AssemblerInfo {
    std::string name;           ///< Assembler name (for menus).
    std::string comment_prefix; ///< Comment delimiter (e.g. ";").
    std::string origin;         ///< Origin directive (e.g. "org").
    std::string end_directive;  ///< End directive (e.g. "end").
    char        string_delim{'\"'}; ///< String literal delimiter.
    char        char_delim{'\''};   ///< Character literal delimiter.

    // Data directives.
    std::string byte_directive;   ///< e.g. "db"
    std::string word_directive;   ///< e.g. "dw"
    std::string dword_directive;  ///< e.g. "dd"
    std::string qword_directive;  ///< e.g. "dq"

    // Extended directives (assembler-surface parity helpers).
    std::string oword_directive;
    std::string float_directive;
    std::string double_directive;
    std::string tbyte_directive;
    std::string align_directive;
    std::string include_directive;
    std::string public_directive;
    std::string weak_directive;
    std::string external_directive;
    std::string current_ip_symbol;

    bool uppercase_mnemonics{false};
    bool uppercase_registers{false};
    bool requires_colon_after_labels{false};
    bool supports_quoted_names{true};
};

// ── Processor flags ─────────────────────────────────────────────────────

/// Processor feature flags (corresponds to SDK PR_* flags).
enum class ProcessorFlag : std::uint32_t {
    None            = 0,
    Segments        = 0x000001,  ///< PR_SEGS: use segments.
    Use32           = 0x000002,  ///< PR_USE32: supports 32-bit addressing.
    Use64           = 0x000004,  ///< PR_USE64: supports 64-bit addressing.
    DefaultSeg32    = 0x000008,  ///< PR_DEFSEG32: default segment is 32-bit.
    DefaultSeg64    = 0x000010,  ///< PR_DEFSEG64: default segment is 64-bit.
    TypeInfo        = 0x000020,  ///< PR_TYPEINFO: supports type information.
    UseArgTypes     = 0x000040,  ///< PR_USE_ARG_TYPES: use argument types.
    ConditionalInsns = 0x000080, ///< PR_CNDINSNS: has conditional instructions.
    NoSegMove       = 0x000100,  ///< PR_NO_SEGMOVE: no segment move.
    HexNumbers      = 0x000200,  ///< PRN_HEX: use hex numbers by default.
    DecimalNumbers  = 0x000400,  ///< PRN_DEC: use decimal numbers by default.
    OctalNumbers    = 0x000800,  ///< PRN_OCT: use octal numbers by default.
};

/// Processor metadata provided by a Processor subclass.
struct ProcessorInfo {
    std::int32_t id{0};              ///< Processor ID (PLFM_* or >0x8000 for third-party).
    std::vector<std::string> short_names;  ///< Short names (<9 chars each).
    std::vector<std::string> long_names;   ///< Long descriptive names.
    std::uint32_t flags{0};          ///< PR_* flags (or-ed ProcessorFlag values).
    std::uint32_t flags2{0};         ///< PR2_* flags.

    int code_bits_per_byte{8};       ///< Bits per byte in CODE segments.
    int data_bits_per_byte{8};       ///< Bits per byte in DATA segments.

    std::vector<RegisterInfo> registers;     ///< All processor registers.
    int code_segment_register{0};            ///< Index of CS register.
    int data_segment_register{1};            ///< Index of DS register.
    int first_segment_register{0};           ///< First sreg index.
    int last_segment_register{1};            ///< Last sreg index.
    int segment_register_size{0};            ///< Size of a segment register in bytes.

    std::vector<InstructionDescriptor> instructions;  ///< Instruction set.
    int return_icode{0};                     ///< Icode of the return instruction.

    std::vector<AssemblerInfo> assemblers;   ///< Assembler definitions.

    int default_bitness{32};                 ///< Default bitness (16/32/64).
};

// ── Switch detection descriptors ────────────────────────────────────────

/// High-level switch table shape.
enum class SwitchTableKind {
    Dense,     ///< Case values form a contiguous range.
    Sparse,    ///< Explicit values table is present.
    Indirect,  ///< Values table contains indexes into the jump table.
    Custom,    ///< Processor-specific custom table handling.
};

/// Opaque, SDK-free description of a detected switch idiom.
struct SwitchDescription {
    SwitchTableKind kind{SwitchTableKind::Dense};

    Address jump_table{BadAddress};
    Address values_table{BadAddress};
    Address default_target{BadAddress};
    Address idiom_start{BadAddress};
    Address element_base{0};

    std::int64_t low_case_value{0};
    std::int64_t indirect_low_case_value{0};

    std::uint32_t case_count{0};
    std::uint32_t jump_table_entry_count{0};

    std::uint8_t jump_element_size{0};
    std::uint8_t value_element_size{0};
    std::uint8_t shift{0};

    int expression_register{-1};
    std::uint8_t expression_data_type{0};

    bool has_default{false};
    bool default_in_table{false};
    bool values_signed{false};
    bool subtract_values{false};
    bool self_relative{false};
    bool inverted{false};
    bool user_defined{false};
};

/// One switch destination and all case values mapping to it.
struct SwitchCase {
    std::vector<std::int64_t> values;
    Address target{BadAddress};
};

// ── Analysis/output result types ────────────────────────────────────────

/// Result of emulate() callback.
enum class EmulateResult : int {
    NotImplemented =  0,  ///< Use default kernel emulation.
    Success        =  1,  ///< Emulation successful.
    DeleteInsn     = -1,  ///< Delete this instruction.
};

/// Result of output_operand() callback.
enum class OutputOperandResult : int {
    NotImplemented =  0,  ///< Use default kernel output.
    Success        =  1,  ///< Operand rendered successfully.
    Hidden         = -1,  ///< Operand should be hidden.
};

/// Result of context-driven instruction formatting.
enum class OutputInstructionResult : int {
    NotImplemented = 0,
    Success = 1,
};

/// SDK-opaque output builder for processor text rendering callbacks.
class OutputContext {
public:
    OutputContext& append(std::string_view text) {
        buffer_.append(text.data(), text.size());
        return *this;
    }

    OutputContext& mnemonic(std::string_view text) { return append(text); }
    OutputContext& register_name(std::string_view text) { return append(text); }

    OutputContext& immediate(std::int64_t value, int radix = 16) {
        if (radix == 10) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(value));
            return append(buf);
        }
        if (radix == 8) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "0%llo", static_cast<unsigned long long>(value));
            return append(buf);
        }
        if (radix == 2) {
            append("0b");
            bool started = false;
            std::uint64_t bits = static_cast<std::uint64_t>(value);
            for (int i = 63; i >= 0; --i) {
                bool bit = ((bits >> i) & 1U) != 0;
                if (bit) started = true;
                if (started || i == 0)
                    append(bit ? "1" : "0");
            }
            return *this;
        }

        char buf[64];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
        return append(buf);
    }

    OutputContext& address(Address address) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(address));
        return append(buf);
    }

    OutputContext& character(char ch) {
        buffer_.push_back(ch);
        return *this;
    }

    OutputContext& space() { return character(' '); }
    OutputContext& comma() { return character(','); }

    void clear() { buffer_.clear(); }

    [[nodiscard]] bool empty() const { return buffer_.empty(); }
    [[nodiscard]] const std::string& text() const { return buffer_; }

    [[nodiscard]] std::string take() {
        std::string out = std::move(buffer_);
        buffer_.clear();
        return out;
    }

private:
    std::string buffer_;
};

// ── Processor base class ────────────────────────────────────────────────

/// Base class for custom processor modules.
///
/// Subclass this and override the required methods. The on_event() dispatcher
/// routes SDK events to your typed virtual methods.
///
/// Required overrides:
/// - info() — return processor metadata
/// - analyze() — decode one instruction, fill result, return byte length
/// - emulate() — create xrefs, plan analysis, return 1 on success
/// - output_instruction() — generate text for an instruction
/// - output_operand() — generate text for a single operand
class Processor {
public:
    virtual ~Processor() = default;

    /// Return processor metadata (registers, instructions, assembler, etc.).
    virtual ProcessorInfo info() const = 0;

    // ── Required analysis callbacks ─────────────────────────────────────

    /// Analyze one instruction at the current position.
    /// @param address  The address being analyzed.
    /// @return Instruction size in bytes, or 0 on decode failure.
    virtual Result<int> analyze(Address address) = 0;

    /// Emulate an instruction (create xrefs, plan analysis, etc.).
    /// @param address  The address of the instruction.
    virtual EmulateResult emulate(Address address) = 0;

    // ── Required output callbacks ───────────────────────────────────────

    /// Generate text output for an instruction.
    /// Use the output context methods to write text.
    /// @param address  The instruction address.
    virtual void output_instruction(Address address) = 0;

    /// Generate text for a single operand.
    /// @param address  The instruction address.
    /// @param operand_index  The operand number (0-based).
    virtual OutputOperandResult output_operand(Address address, int operand_index) = 0;

    /// Optional context-driven instruction formatter.
    ///
    /// Default behavior falls back to `output_instruction(address)` and returns
    /// `OutputInstructionResult::NotImplemented`.
    virtual OutputInstructionResult output_instruction_with_context(
            Address address,
            OutputContext& output) {
        (void)output;
        output_instruction(address);
        return OutputInstructionResult::NotImplemented;
    }

    /// Optional context-driven operand formatter.
    ///
    /// Default behavior falls back to `output_operand(address, operand_index)`.
    virtual OutputOperandResult output_operand_with_context(
            Address address,
            int operand_index,
            OutputContext& output) {
        (void)output;
        return output_operand(address, operand_index);
    }

    // ── Optional analysis callbacks ─────────────────────────────────────

    /// Called when a new file or old file is loaded.
    virtual void on_new_file(std::string_view filename) { (void)filename; }
    virtual void on_old_file(std::string_view filename) { (void)filename; }

    /// Check if an instruction is a call.
    /// @return 1=yes, -1=no, 0=use default heuristics.
    virtual int is_call(Address address) { (void)address; return 0; }

    /// Check if an instruction is a return.
    /// @return 1=yes, -1=no, 0=use default heuristics.
    virtual int is_return(Address address) { (void)address; return 0; }

    /// Can a function start at this address?
    /// @return Probability 0..100, or -1 for "definitely not".
    virtual int may_be_function(Address address) { (void)address; return 0; }

    /// Is this instruction sane for this file type?
    /// @param no_code_references  true when no code refs point to this instruction.
    /// @return >=0 = sane, <0 = unlikely/invalid in this context.
    virtual int is_sane_instruction(Address address, bool no_code_references) {
        (void)address;
        (void)no_code_references;
        return 0;
    }

    /// Is this instruction an indirect jump?
    /// @return 0 = use default flag-based logic, 1 = no, 2 = yes.
    virtual int is_indirect_jump(Address address) { (void)address; return 0; }

    /// Is this instruction a basic-block terminator?
    /// Useful for architectures with delay slots.
    /// @return 0 = unknown, -1 = no, 1 = yes.
    virtual int is_basic_block_end(Address address, bool call_instruction_stops_block) {
        (void)address;
        (void)call_instruction_stops_block;
        return 0;
    }

    /// Create a function frame (stack frame layout).
    /// @return true if frame was created.
    virtual bool create_function_frame(Address function_start) {
        (void)function_start;
        return false;
    }

    /// Final chance to adjust function-boundary analysis result.
    /// @param function_start  Candidate function start.
    /// @param max_function_end  Maximum kernel-computed end bound.
    /// @param suggested_result  Kernel suggestion (0=undef, 1=ok, 2=exists).
    /// @return Updated result code (typically pass through suggested_result).
    virtual int adjust_function_bounds(Address function_start,
                                       Address max_function_end,
                                       int suggested_result) {
        (void)function_start;
        (void)max_function_end;
        return suggested_result;
    }

    /// Analyze function prolog/epilog and adjust attributes/purge.
    /// @return 1 = handled, 0 = not implemented.
    virtual int analyze_function_prolog(Address function_start) {
        (void)function_start;
        return 0;
    }

    /// Compute stack-pointer delta for one instruction.
    /// @param out_delta  Receives SP change when handled.
    /// @return 1 = handled, 0 = not implemented.
    virtual int calculate_stack_pointer_delta(Address address,
                                              std::int64_t& out_delta) {
        (void)address;
        out_delta = 0;
        return 0;
    }

    /// Get the return address size for a function.
    /// @return Size in bytes, or 0 if not implemented.
    virtual int get_return_address_size(Address function_start) {
        (void)function_start;
        return 0;
    }

    /// Detect and describe a switch/jump-table idiom.
    /// @return 1 = switch found, -1 = definitely not a switch, 0 = not implemented.
    virtual int detect_switch(Address address, SwitchDescription& out_switch) {
        (void)address;
        (void)out_switch;
        return 0;
    }

    /// Calculate switch case values and corresponding targets for custom switches.
    /// @return 1 = handled, 0 = not implemented.
    virtual int calculate_switch_cases(Address address,
                                       const SwitchDescription& switch_description,
                                       std::vector<SwitchCase>& out_cases) {
        (void)address;
        (void)switch_description;
        (void)out_cases;
        return 0;
    }

    /// Create xrefs for a custom switch table.
    /// @return 1 = handled, 0 = not implemented.
    virtual int create_switch_references(Address address,
                                         const SwitchDescription& switch_description) {
        (void)address;
        (void)switch_description;
        return 0;
    }
};

} // namespace ida::processor

/// Registration macro for idax processor modules.
/// Place at file scope in your processor source file.
#define IDAX_PROCESSOR(ProcessorClass)                                       \
    namespace {                                                              \
    static ProcessorClass* g_idax_processor_instance = nullptr;              \
    }                                                                        \
    extern "C" {                                                             \
    void idax_processor_bridge_init(void** out_processor);                   \
    }                                                                        \
    void idax_processor_bridge_init(void** out_processor) {                  \
        if (!g_idax_processor_instance)                                      \
            g_idax_processor_instance = new ProcessorClass();                \
        *out_processor = g_idax_processor_instance;                          \
    }

#endif // IDAX_PROCESSOR_HPP
