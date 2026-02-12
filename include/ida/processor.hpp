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
#include <cstdint>
#include <string>
#include <string_view>
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

    int cnbits{8};                   ///< Bits per byte in CODE segments.
    int dnbits{8};                   ///< Bits per byte in DATA segments.

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
    /// @param out_mnemonic  Set to the mnemonic index.
    /// @param out_size  Set to the instruction size in bytes.
    /// @param address  The address being analyzed.
    /// @return Instruction size in bytes, or 0 on decode failure.
    virtual int analyze(Address address) = 0;

    /// Emulate an instruction (create xrefs, plan analysis, etc.).
    /// @param address  The address of the instruction.
    /// @return 1 on success, -1 to delete instruction, 0 for not implemented.
    virtual int emulate(Address address) = 0;

    // ── Required output callbacks ───────────────────────────────────────

    /// Generate text output for an instruction.
    /// Use the output context methods to write text.
    /// @param address  The instruction address.
    virtual void output_instruction(Address address) = 0;

    /// Generate text for a single operand.
    /// @param address  The instruction address.
    /// @param operand_index  The operand number (0-based).
    /// @return 1 = ok, -1 = hidden operand, 0 = not implemented.
    virtual int output_operand(Address address, int operand_index) = 0;

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

    /// Create a function frame (stack frame layout).
    /// @return true if frame was created.
    virtual bool create_function_frame(Address function_start) {
        (void)function_start;
        return false;
    }

    /// Get the return address size for a function.
    /// @return Size in bytes, or 0 if not implemented.
    virtual int get_return_address_size(Address function_start) {
        (void)function_start;
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
