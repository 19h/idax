/// \file processor.cpp
/// \brief SDK-private bridge from ida::processor::Processor to an IDA procmod.

#include <ida/processor.hpp>

#include "detail/processor_bridge_validation.hpp"
#include "detail/sdk_bridge.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <string>
#include <utility>
#include <vector>

extern "C" void idax_processor_bridge_init_fallback(void** out_processor) {
    if (out_processor != nullptr)
        *out_processor = nullptr;
}

#if defined(_MSC_VER)
extern "C" void idax_processor_bridge_init(void** out_processor);
#pragma comment(linker, "/alternatename:idax_processor_bridge_init=idax_processor_bridge_init_fallback")
#elif defined(__GNUC__) || defined(__clang__)
extern "C" void __attribute__((weak))
idax_processor_bridge_init(void** out_processor) {
    idax_processor_bridge_init_fallback(out_processor);
}
#else
extern "C" void idax_processor_bridge_init(void** out_processor);
#endif

extern "C" void idax_processor_bridge_link_anchor() {}

namespace {

using ida::processor::AnalyzeDetails;
using ida::processor::AnalyzeOperand;
using ida::processor::AnalyzeOperandKind;
using ida::processor::OutputContext;
using ida::processor::OutputInstructionResult;
using ida::processor::OutputOperandResult;
using ida::processor::OutputTokenKind;
using ida::processor::Processor;
using ida::processor::ProcessorInfo;
using ida::processor::SwitchCase;
using ida::processor::SwitchDescription;
using ida::processor::SwitchTableKind;

static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Segments) == PR_SEGS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Use32) == PR_USE32);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DefaultSeg32) == PR_DEFSEG32);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::RegisterNames) == PR_RNAMESOK);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::AdjustSegments) == PR_ADJSEGS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::HexNumbers) == PRN_HEX);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::OctalNumbers) == PRN_OCT);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DecimalNumbers) == PRN_DEC);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::BinaryNumbers) == PRN_BIN);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::WordInstructions) == PR_WORD_INS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::NoChange) == PR_NOCHANGE);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Assemble) == PR_ASSEMBLE);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::AlignData) == PR_ALIGN);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::TypeInfo) == PR_TYPEINFO);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Use64) == PR_USE64);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::SegmentRegistersOther) == PR_SGROTHER);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::StackGrowsUp) == PR_STACK_UP);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::BinaryMemory) == PR_BINMEM);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::SegmentTranslation) == PR_SEGTRANS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::CheckCrossReferences) == PR_CHK_XREF);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::NoSegMove) == PR_NO_SEGMOVE);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::UseArgTypes) == PR_USE_ARG_TYPES);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::ScaleStackVariables) == PR_SCALE_STKVARS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DelayedBranches) == PR_DELAYED);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::AlignInstructions) == PR_ALIGN_INSN);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::Purging) == PR_PURGING);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::ConditionalInsns) == PR_CNDINSNS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::UseTbyte) == PR_USE_TBYTE);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::DefaultSeg64) == PR_DEFSEG64);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag::OuterOperands) == PR_OUTER);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::Mappings) == PR2_MAPPINGS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::IdpOptions) == PR2_IDP_OPTS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::Code16Bit) == PR2_CODE16_BIT);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::Macro) == PR2_MACRO);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::UseCalcRel) == PR2_USE_CALCREL);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::RelativeBits) == PR2_REL_BITS);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::Force16BitTypes) == PR2_FORCE_16BIT);
static_assert(static_cast<std::uint32_t>(ida::processor::ProcessorFlag2::IgnoreIdaGuess) == PR2_IGNORE_IDA_GUESS);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Stop) == CF_STOP);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Call) == CF_CALL);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change1) == CF_CHG1);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change2) == CF_CHG2);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change3) == CF_CHG3);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change4) == CF_CHG4);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change5) == CF_CHG5);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change6) == CF_CHG6);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use1) == CF_USE1);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use2) == CF_USE2);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use3) == CF_USE3);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use4) == CF_USE4);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use5) == CF_USE5);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use6) == CF_USE6);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Jump) == CF_JUMP);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Shift) == CF_SHFT);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::HighLevel) == CF_HLL);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change7) == CF_CHG7);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Change8) == CF_CHG8);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use7) == CF_USE7);
static_assert(static_cast<std::uint32_t>(ida::processor::InstructionFeature::Use8) == CF_USE8);
static_assert(ida::detail::processor_bridge::kMaximumOperands == UA_MAXOP);
static_assert(ida::detail::processor_bridge::kMaximumDataTypeCode == dt_half);

Processor* bridge_processor_instance() {
    void* raw = nullptr;
    idax_processor_bridge_init(&raw);
    return static_cast<Processor*>(raw);
}

const char* optional_text(const std::string& text) {
    return text.empty() ? nullptr : text.c_str();
}

struct DescriptorState {
    Processor* processor{nullptr};
    ProcessorInfo info;
    bool valid{true};
    std::string error;

    std::vector<const char*> short_names;
    std::vector<const char*> long_names;
    std::vector<const char*> register_names;
    std::vector<instruc_t> instructions;
    std::vector<asm_t> assemblers;
    std::vector<const asm_t*> assembler_pointers;

    DescriptorState() {
        try {
            processor = bridge_processor_instance();
            if (processor == nullptr) {
                invalidate("IDAX_PROCESSOR registration did not provide an instance");
            } else {
                info = processor->info();
            }
        } catch (const std::exception& exception) {
            invalidate(std::string("processor registration threw: ") + exception.what());
        } catch (...) {
            invalidate("processor registration threw a non-standard exception");
        }

        if (processor != nullptr) {
            if (const char* validation_error =
                    ida::detail::processor_bridge::processor_info_error(info)) {
                invalidate(validation_error);
            }
        }

        normalize_and_validate();
        materialize_names();
        materialize_registers();
        materialize_instructions();
        materialize_assemblers();
    }

    void invalidate(std::string message) {
        if (valid) {
            valid = false;
            error = std::move(message);
        }
    }

    void normalize_and_validate() {
        if (info.id <= 0x8000) {
            info.id = 0x8001;
            invalidate("ProcessorInfo.id must be a third-party processor ID above 0x8000");
        }
        if (info.short_names.empty()) {
            info.short_names.push_back("idaxbad");
            invalidate("ProcessorInfo.short_names must not be empty");
        }
        for (auto& name : info.short_names) {
            if (name.empty() || name.size() >= 9) {
                invalidate("Processor short names must contain 1..8 bytes");
                name = "idaxbad";
            }
        }

        if (info.long_names.empty())
            info.long_names = info.short_names;
        if (info.long_names.size() != info.short_names.size()) {
            invalidate("ProcessorInfo long/short name counts must match");
            info.long_names.resize(info.short_names.size(), info.short_names.front());
        }
        for (std::size_t index = 0; index < info.long_names.size(); ++index) {
            if (info.long_names[index].empty()) {
                invalidate("Processor long names must not be empty");
                info.long_names[index] = info.short_names[index];
            }
        }

        if (info.registers.empty()) {
            info.registers.push_back({"cs", false});
            info.registers.push_back({"ds", false});
            invalidate("ProcessorInfo.registers must not be empty");
        }
        if (info.registers.size()
            > ida::detail::processor_bridge::kMaximumRegisters) {
            invalidate("ProcessorInfo contains too many registers");
            info.registers.resize(ida::detail::processor_bridge::kMaximumRegisters);
        }
        for (auto& register_info : info.registers) {
            if (register_info.name.empty()) {
                invalidate("Processor register names must not be empty");
                register_info.name = "invalid";
            }
        }
        const auto register_count = static_cast<int>(info.registers.size());
        const std::array<int, 4> register_indices = {
            info.first_segment_register,
            info.last_segment_register,
            info.code_segment_register,
            info.data_segment_register,
        };
        if (std::any_of(register_indices.begin(), register_indices.end(),
                        [register_count](int index) {
                            return index < 0 || index >= register_count;
                        })) {
            invalidate("ProcessorInfo segment-register index is out of range");
            info.first_segment_register = 0;
            info.last_segment_register = register_count - 1;
            info.code_segment_register = 0;
            info.data_segment_register = register_count - 1;
        }
        if (info.first_segment_register > info.last_segment_register) {
            invalidate("ProcessorInfo segment-register range is inverted");
            std::swap(info.first_segment_register, info.last_segment_register);
        }
        if (info.segment_register_size < 0 || info.segment_register_size > 8) {
            invalidate("ProcessorInfo.segment_register_size must be in 0..8");
            info.segment_register_size = 0;
        }

        if (info.instructions.empty()) {
            info.instructions.push_back({"invalid", 0, 0, {}, false});
            invalidate("ProcessorInfo.instructions must not be empty");
        }
        if (info.instructions.size()
            > ida::detail::processor_bridge::kMaximumInstructions) {
            invalidate("ProcessorInfo contains too many instructions");
            info.instructions.resize(
                ida::detail::processor_bridge::kMaximumInstructions);
        }
        for (auto& instruction : info.instructions) {
            if (instruction.mnemonic.empty()) {
                invalidate("Processor instruction mnemonics must not be empty");
                instruction.mnemonic = "invalid";
            }
            if (instruction.operand_count > UA_MAXOP) {
                invalidate("Processor instruction operand count exceeds eight");
                instruction.operand_count = UA_MAXOP;
            }
        }
        if (info.return_icode < 0
            || static_cast<std::size_t>(info.return_icode) >= info.instructions.size()) {
            invalidate("ProcessorInfo.return_icode is out of range");
            info.return_icode = 0;
        }

        if (info.code_bits_per_byte <= 0 || info.code_bits_per_byte > 64
            || info.data_bits_per_byte <= 0 || info.data_bits_per_byte > 64) {
            invalidate("Processor byte widths must be in 1..64");
            info.code_bits_per_byte = 8;
            info.data_bits_per_byte = 8;
        }
        if (info.default_bitness != 16
            && info.default_bitness != 32
            && info.default_bitness != 64) {
            invalidate("ProcessorInfo.default_bitness must be 16, 32, or 64");
            info.default_bitness = 32;
        }

        if (info.assemblers.empty()) {
            ida::processor::AssemblerInfo assembler;
            assembler.name = "idax generic assembler";
            assembler.comment_prefix = ";";
            assembler.origin = ".org";
            assembler.end_directive = ".end";
            assembler.byte_directive = ".byte";
            assembler.word_directive = ".word";
            assembler.dword_directive = ".dword";
            assembler.qword_directive = ".qword";
            assembler.oword_directive = ".oword";
            assembler.float_directive = ".float";
            assembler.double_directive = ".double";
            assembler.tbyte_directive = ".tbyte";
            assembler.align_directive = ".align";
            assembler.include_directive = ".include %s";
            assembler.public_directive = ".global";
            assembler.weak_directive = ".weak";
            assembler.external_directive = ".extern";
            assembler.current_ip_symbol = "$";
            info.assemblers.push_back(std::move(assembler));
        }
        for (auto& assembler : info.assemblers) {
            if (assembler.name.empty()) {
                assembler.name = "idax invalid assembler";
                invalidate("Processor assembler names must not be empty");
            }
        }
    }

    void materialize_names() {
        short_names.reserve(info.short_names.size() + 1);
        for (const auto& name : info.short_names)
            short_names.push_back(name.c_str());
        short_names.push_back(nullptr);

        long_names.reserve(info.long_names.size() + 1);
        for (const auto& name : info.long_names)
            long_names.push_back(name.c_str());
        long_names.push_back(nullptr);
    }

    void materialize_registers() {
        register_names.reserve(info.registers.size());
        for (const auto& register_info : info.registers)
            register_names.push_back(register_info.name.c_str());
    }

    void materialize_instructions() {
        instructions.reserve(info.instructions.size());
        for (const auto& instruction : info.instructions) {
            instructions.push_back(instruc_t{
                instruction.mnemonic.c_str(),
                static_cast<uint32>(instruction.feature_flags),
            });
        }
    }

    static asm_t make_assembler(const ida::processor::AssemblerInfo& source) {
        asm_t assembler{};
        assembler.flag = ASH_HEXF3;
        if (source.requires_colon_after_labels)
            assembler.flag |= AS_COLON;
        assembler.name = optional_text(source.name);
        assembler.origin = optional_text(source.origin);
        assembler.end = optional_text(source.end_directive);
        assembler.cmnt = optional_text(source.comment_prefix);
        assembler.ascsep = source.string_delim;
        assembler.accsep = source.char_delim;
        assembler.esccodes = "\"'";
        assembler.a_ascii = optional_text(source.byte_directive);
        assembler.a_byte = optional_text(source.byte_directive);
        assembler.a_word = optional_text(source.word_directive);
        assembler.a_dword = optional_text(source.dword_directive);
        assembler.a_qword = optional_text(source.qword_directive);
        assembler.a_oword = optional_text(source.oword_directive);
        assembler.a_float = optional_text(source.float_directive);
        assembler.a_double = optional_text(source.double_directive);
        assembler.a_tbyte = optional_text(source.tbyte_directive);
        assembler.a_curip = optional_text(source.current_ip_symbol);
        assembler.a_public = optional_text(source.public_directive);
        assembler.a_weak = optional_text(source.weak_directive);
        assembler.a_extrn = optional_text(source.external_directive);
        assembler.a_align = optional_text(source.align_directive);
        assembler.lbrace = '(';
        assembler.rbrace = ')';
        assembler.a_mod = "%";
        assembler.a_band = "&";
        assembler.a_bor = "|";
        assembler.a_xor = "^";
        assembler.a_bnot = "~";
        assembler.a_shl = "<<";
        assembler.a_shr = ">>";
        assembler.a_include_fmt = optional_text(source.include_directive);
        return assembler;
    }

    void materialize_assemblers() {
        assemblers.reserve(info.assemblers.size());
        for (const auto& assembler : info.assemblers)
            assemblers.push_back(make_assembler(assembler));

        assembler_pointers.reserve(assemblers.size() + 1);
        for (const auto& assembler : assemblers)
            assembler_pointers.push_back(&assembler);
        assembler_pointers.push_back(nullptr);
    }
};

DescriptorState& descriptor_state() {
    static DescriptorState state;
    return state;
}

void report_callback_error(const char* operation, const std::string& detail) {
    msg("[idax processor] %s failed: %s\n", operation, detail.c_str());
}

void report_result_error(const char* operation, const ida::Error& error) {
    std::string detail = error.message;
    if (!error.context.empty()) {
        detail += " (";
        detail += error.context;
        detail += ')';
    }
    report_callback_error(operation, detail);
}

bool materialize_operand(op_t& target, const AnalyzeOperand& source) {
    const auto& state = descriptor_state();
    if (!ida::detail::processor_bridge::analyze_operand_is_valid(state.info, source))
        return false;
    target.dtype = static_cast<op_dtype_t>(source.data_type_code);
    target.specflag1 = static_cast<char>(source.processor_flags & 0xFFU);
    target.specflag2 = static_cast<char>((source.processor_flags >> 8U) & 0xFFU);
    target.specflag3 = static_cast<char>((source.processor_flags >> 16U) & 0xFFU);
    target.specflag4 = static_cast<char>((source.processor_flags >> 24U) & 0xFFU);

    const auto set_register = [&]() -> bool {
        if (!source.has_register
            || source.register_index < 0
            || static_cast<std::size_t>(source.register_index)
                >= descriptor_state().info.registers.size()) {
            return false;
        }
        target.reg = static_cast<std::uint16_t>(source.register_index);
        return true;
    };
    const auto set_address = [&]() -> bool {
        if (!source.has_target_address || source.target_address == ida::BadAddress)
            return false;
        target.addr = static_cast<ea_t>(source.target_address);
        return true;
    };

    switch (source.kind) {
    case AnalyzeOperandKind::None:
        target.type = o_void;
        return true;
    case AnalyzeOperandKind::Register:
        target.type = o_reg;
        return set_register();
    case AnalyzeOperandKind::Immediate:
        if (!source.has_immediate)
            return false;
        target.type = o_imm;
        target.value = static_cast<uval_t>(source.immediate_value);
        return true;
    case AnalyzeOperandKind::NearAddress:
        target.type = o_near;
        return set_address();
    case AnalyzeOperandKind::FarAddress:
        target.type = o_far;
        return set_address();
    case AnalyzeOperandKind::DirectMemory:
        target.type = o_mem;
        return set_address();
    case AnalyzeOperandKind::IndirectMemory:
        target.type = o_phrase;
        return set_register();
    case AnalyzeOperandKind::Displacement:
        if (!source.has_displacement || !set_register())
            return false;
        target.type = o_displ;
        target.addr = static_cast<ea_t>(source.displacement);
        return true;
    case AnalyzeOperandKind::ProcessorSpecific0:
    case AnalyzeOperandKind::ProcessorSpecific1:
    case AnalyzeOperandKind::ProcessorSpecific2:
    case AnalyzeOperandKind::ProcessorSpecific3:
    case AnalyzeOperandKind::ProcessorSpecific4:
    case AnalyzeOperandKind::ProcessorSpecific5: {
        const int offset = static_cast<int>(source.kind)
                         - static_cast<int>(AnalyzeOperandKind::ProcessorSpecific0);
        target.type = static_cast<optype_t>(o_idpspec0 + offset);
        if (source.has_immediate)
            target.value = static_cast<uval_t>(source.immediate_value);
        if (source.has_target_address)
            target.addr = static_cast<ea_t>(source.target_address);
        if (source.has_register
            && source.register_index >= 0
            && source.register_index <= std::numeric_limits<std::uint16_t>::max()) {
            target.reg = static_cast<std::uint16_t>(source.register_index);
        }
        return true;
    }
    }
    return false;
}

bool materialize_instruction(insn_t& target, const AnalyzeDetails& details) {
    const auto& state = descriptor_state();
    if (!state.valid
        || !ida::detail::processor_bridge::analyze_details_are_valid(
            state.info, details)) {
        return false;
    }

    std::array<bool, UA_MAXOP> populated{};
    for (const auto& operand : details.operands) {
        if (operand.index >= UA_MAXOP || populated[operand.index])
            return false;
        if (!materialize_operand(target.ops[operand.index], operand))
            return false;
        populated[operand.index] = true;
    }

    target.itype = details.instruction_code;
    target.size = static_cast<std::uint16_t>(details.size);
    return true;
}

color_t token_color(OutputTokenKind kind) {
    switch (kind) {
    case OutputTokenKind::Mnemonic:       return COLOR_INSN;
    case OutputTokenKind::Register:       return COLOR_REG;
    case OutputTokenKind::Immediate:
    case OutputTokenKind::Number:         return COLOR_NUMBER;
    case OutputTokenKind::Address:
    case OutputTokenKind::Symbol:         return COLOR_LOCNAME;
    case OutputTokenKind::Comment:        return COLOR_AUTOCMT;
    case OutputTokenKind::Keyword:        return COLOR_KEYWORD;
    case OutputTokenKind::StringLiteral:  return COLOR_STRING;
    case OutputTokenKind::OperatorSymbol:
    case OutputTokenKind::Punctuation:    return COLOR_SYMBOL;
    case OutputTokenKind::PlainText:
    case OutputTokenKind::Whitespace:     return 0;
    }
    return 0;
}

void render_tokens(outctx_t& context, const OutputContext& output) {
    for (const auto& token : output.tokens())
        context.out_line(token.text.c_str(), token_color(token.kind));
}

bool render_default_instruction(outctx_t& context, Processor& processor) {
    OutputContext mnemonic;
    const auto mnemonic_result = processor.output_mnemonic_with_context(
        static_cast<ida::Address>(context.insn.ea), mnemonic);
    if (mnemonic_result == OutputInstructionResult::Success) {
        if (mnemonic.empty())
            return false;
        render_tokens(context, mnemonic);
    } else {
        const auto& state = descriptor_state();
        const auto instruction_index = static_cast<std::size_t>(context.insn.itype);
        if (instruction_index >= state.info.instructions.size())
            return false;
        context.out_line(
            state.info.instructions[instruction_index].mnemonic.c_str(), COLOR_INSN);
    }

    bool emitted_operand = false;
    for (int index = 0; index < UA_MAXOP; ++index) {
        const auto& operand = context.insn.ops[index];
        if (operand.type == o_void || !operand.shown())
            continue;
        OutputContext output;
        const auto result = processor.output_operand_with_context(
            static_cast<ida::Address>(context.insn.ea), index, output);
        if (result == OutputOperandResult::Hidden)
            continue;
        if (result == OutputOperandResult::Success) {
            if (output.empty())
                return false;
            if (emitted_operand) {
                context.out_symbol(',');
                context.out_char(' ');
            }
            render_tokens(context, output);
            emitted_operand = true;
            continue;
        }
        const auto saved_output = context.outbuf;
        if (emitted_operand) {
            context.out_symbol(',');
            context.out_char(' ');
        }
        if (context.out_one_operand(index))
            emitted_operand = true;
        else
            context.outbuf = saved_output;
    }
    context.set_gen_cmt();
    context.flush_outbuf();
    return true;
}

SwitchDescription copy_switch_description(const switch_info_t& source) {
    SwitchDescription result;
    if (source.is_custom())
        result.kind = SwitchTableKind::Custom;
    else if (source.is_indirect())
        result.kind = SwitchTableKind::Indirect;
    else if (source.is_sparse())
        result.kind = SwitchTableKind::Sparse;
    else
        result.kind = SwitchTableKind::Dense;

    result.jump_table = static_cast<ida::Address>(source.jumps);
    if (source.is_sparse())
        result.values_table = static_cast<ida::Address>(source.values);
    result.default_target = static_cast<ida::Address>(source.defjump);
    result.idiom_start = static_cast<ida::Address>(source.startea);
    result.element_base = static_cast<ida::Address>(source.elbase);
    result.low_case_value = static_cast<std::int64_t>(source.get_lowcase());
    result.indirect_low_case_value = static_cast<std::int64_t>(source.ind_lowcase);
    result.case_count = source.ncases;
    result.jump_table_entry_count = static_cast<std::uint32_t>(source.get_jtable_size());
    result.jump_element_size = static_cast<std::uint8_t>(source.get_jtable_element_size());
    result.value_element_size = static_cast<std::uint8_t>(source.get_vtable_element_size());
    result.shift = static_cast<std::uint8_t>(source.get_shift());
    result.expression_register = source.regnum;
    result.expression_data_type = source.regdtype;
    result.has_default = source.has_default();
    result.default_in_table = (source.flags & SWI_DEF_IN_TBL) != 0;
    result.values_signed = (source.flags & SWI_SIGNED) != 0;
    result.subtract_values = source.is_subtract();
    result.self_relative = (source.flags & SWI_SELFREL) != 0;
    result.inverted = (source.flags & SWI_JMP_INV) != 0;
    result.user_defined = source.is_user_defined();
    return result;
}

bool materialize_switch(switch_info_t& target, const SwitchDescription& source) {
    const auto& state = descriptor_state();
    if (!state.valid
        || !ida::detail::processor_bridge::switch_description_is_valid(
            state.info, source)) {
        return false;
    }

    target.clear();
    switch (source.kind) {
    case SwitchTableKind::Dense:
        break;
    case SwitchTableKind::Sparse:
        target.flags |= SWI_SPARSE;
        break;
    case SwitchTableKind::Indirect:
        target.flags |= SWI_SPARSE | SWI_INDIRECT;
        break;
    case SwitchTableKind::Custom:
        target.flags |= SWI_CUSTOM;
        break;
    }
    if (source.default_in_table) target.flags |= SWI_DEF_IN_TBL;
    if (source.values_signed) target.flags |= SWI_SIGNED;
    if (source.subtract_values) target.flags |= SWI_SUBTRACT;
    if (source.self_relative) target.flags |= SWI_SELFREL;
    if (source.inverted) target.flags |= SWI_JMP_INV;
    if (source.user_defined) target.flags |= SWI_USER;

    target.ncases = static_cast<std::uint16_t>(source.case_count);
    target.jumps = static_cast<ea_t>(source.jump_table);
    if ((target.flags & SWI_SPARSE) != 0)
        target.values = static_cast<ea_t>(source.values_table);
    else
        target.lowcase = static_cast<uval_t>(source.low_case_value);
    target.defjump = source.has_default
        ? static_cast<ea_t>(source.default_target)
        : BADADDR;
    target.startea = static_cast<ea_t>(source.idiom_start);
    target.jcases = static_cast<int>(source.jump_table_entry_count);
    target.ind_lowcase = static_cast<sval_t>(source.indirect_low_case_value);
    if (source.element_base != 0)
        target.set_elbase(static_cast<ea_t>(source.element_base));
    target.set_expr(source.expression_register,
                    static_cast<op_dtype_t>(source.expression_data_type));
    if (source.jump_element_size != 0)
        target.set_jtable_element_size(source.jump_element_size);
    if (source.value_element_size != 0)
        target.set_vtable_element_size(source.value_element_size);
    target.set_shift(source.shift);
    return true;
}

class IdaxProcessorModule final : public procmod_t {
public:
    explicit IdaxProcessorModule(Processor& processor)
        : processor_(processor) {}

    ssize_t idaapi on_event(ssize_t message_id, va_list arguments) override {
        try {
            return dispatch(message_id, arguments);
        } catch (const std::exception& exception) {
            report_callback_error("event callback", exception.what());
        } catch (...) {
            report_callback_error("event callback", "non-standard exception");
        }
        return 0;
    }

private:
    ssize_t dispatch(ssize_t message_id, va_list arguments) {
        switch (message_id) {
        case processor_t::ev_newfile: {
            const char* filename = va_arg(arguments, const char*);
            processor_.on_new_file(filename != nullptr ? filename : "");
            return 1;
        }
        case processor_t::ev_oldfile: {
            const char* filename = va_arg(arguments, const char*);
            processor_.on_old_file(filename != nullptr ? filename : "");
            return 1;
        }
        case processor_t::ev_ana_insn: {
            auto* instruction = va_arg(arguments, insn_t*);
            if (instruction == nullptr)
                return 0;
            auto details = processor_.analyze_with_details(
                static_cast<ida::Address>(instruction->ea));
            if (!details) {
                report_result_error("analyze", details.error());
                return 0;
            }
            if (!materialize_instruction(*instruction, *details)) {
                report_callback_error("analyze", "invalid instruction details");
                return 0;
            }
            return details->size;
        }
        case processor_t::ev_emu_insn: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            if (instruction == nullptr)
                return 0;
            return static_cast<ssize_t>(processor_.emulate(
                static_cast<ida::Address>(instruction->ea)));
        }
        case processor_t::ev_out_mnem: {
            auto* context = va_arg(arguments, outctx_t*);
            if (context == nullptr)
                return 0;
            OutputContext output;
            const auto result = processor_.output_mnemonic_with_context(
                static_cast<ida::Address>(context->insn.ea), output);
            if (result != OutputInstructionResult::Success)
                return static_cast<ssize_t>(result);
            if (output.empty()) {
                report_callback_error("output mnemonic", "successful callback emitted no text");
                return 0;
            }
            context->out_custom_mnem(output.text().c_str());
            return 1;
        }
        case processor_t::ev_out_insn: {
            auto* context = va_arg(arguments, outctx_t*);
            if (context == nullptr)
                return 0;
            OutputContext output;
            const auto result = processor_.output_instruction_with_context(
                static_cast<ida::Address>(context->insn.ea), output);
            if (result == OutputInstructionResult::NotImplemented) {
                if (!render_default_instruction(*context, processor_)) {
                    report_callback_error(
                        "output instruction", "canonical fallback emitted no text");
                    return 0;
                }
                return 1;
            }
            if (output.empty()) {
                report_callback_error("output instruction", "successful callback emitted no text");
                return 0;
            }
            render_tokens(*context, output);
            context->set_gen_cmt();
            context->flush_outbuf();
            return 1;
        }
        case processor_t::ev_out_operand: {
            auto* context = va_arg(arguments, outctx_t*);
            const auto* operand = va_arg(arguments, const op_t*);
            if (context == nullptr || operand == nullptr)
                return 0;
            OutputContext output;
            const auto result = processor_.output_operand_with_context(
                static_cast<ida::Address>(context->insn.ea), operand->n, output);
            if (result == OutputOperandResult::Success && output.empty()) {
                report_callback_error("output operand", "successful callback emitted no text");
                return 0;
            }
            if (result == OutputOperandResult::Success)
                render_tokens(*context, output);
            return static_cast<ssize_t>(result);
        }
        case processor_t::ev_is_call_insn: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            return instruction != nullptr
                ? processor_.is_call(static_cast<ida::Address>(instruction->ea))
                : 0;
        }
        case processor_t::ev_is_ret_insn: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            (void)va_argi(arguments, int);
            return instruction != nullptr
                ? processor_.is_return(static_cast<ida::Address>(instruction->ea))
                : 0;
        }
        case processor_t::ev_may_be_func: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            (void)va_argi(arguments, int);
            return instruction != nullptr
                ? processor_.may_be_function(static_cast<ida::Address>(instruction->ea))
                : 0;
        }
        case processor_t::ev_is_sane_insn: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            const int no_code_references = va_argi(arguments, int);
            return instruction != nullptr
                ? processor_.is_sane_instruction(
                    static_cast<ida::Address>(instruction->ea),
                    no_code_references != 0)
                : 0;
        }
        case processor_t::ev_is_indirect_jump: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            return instruction != nullptr
                ? processor_.is_indirect_jump(
                    static_cast<ida::Address>(instruction->ea))
                : 0;
        }
        case processor_t::ev_is_basic_block_end: {
            const auto* instruction = va_arg(arguments, const insn_t*);
            const bool calls_stop = va_argi(arguments, bool);
            return instruction != nullptr
                ? processor_.is_basic_block_end(
                    static_cast<ida::Address>(instruction->ea), calls_stop)
                : 0;
        }
        case processor_t::ev_func_bounds: {
            auto* possible_result = va_arg(arguments, int*);
            auto* function = va_arg(arguments, func_t*);
            const ea_t maximum_end = va_arg(arguments, ea_t);
            if (possible_result == nullptr || function == nullptr)
                return 0;
            *possible_result = processor_.adjust_function_bounds(
                static_cast<ida::Address>(function->start_ea),
                static_cast<ida::Address>(maximum_end),
                *possible_result);
            return 1;
        }
        case processor_t::ev_function_bounds: {
            auto* possible_result = va_arg(arguments, int*);
            auto* function = va_arg(arguments, fchunk_info_t*);
            const ea_t maximum_end = va_arg(arguments, ea_t);
            if (possible_result == nullptr || function == nullptr)
                return 0;
            *possible_result = processor_.adjust_function_bounds(
                static_cast<ida::Address>(function->start_ea),
                static_cast<ida::Address>(maximum_end),
                *possible_result);
            return 1;
        }
        case processor_t::ev_create_func_frame: {
            auto* function = va_arg(arguments, func_t*);
            return function != nullptr
                && processor_.create_function_frame(
                    static_cast<ida::Address>(function->start_ea))
                ? 1 : 0;
        }
        case processor_t::ev_create_function_frame: {
            const ea_t function_start = va_arg(arguments, ea_t);
            return processor_.create_function_frame(
                static_cast<ida::Address>(function_start)) ? 1 : 0;
        }
        case processor_t::ev_get_frame_retsize: {
            auto* out_size = va_arg(arguments, int*);
            const auto* function = va_arg(arguments, const func_t*);
            if (out_size == nullptr || function == nullptr)
                return 0;
            const int size = processor_.get_return_address_size(
                static_cast<ida::Address>(function->start_ea));
            if (size <= 0)
                return 0;
            *out_size = size;
            return 1;
        }
        case processor_t::ev_get_function_retsize: {
            auto* out_size = va_arg(arguments, int*);
            const ea_t function_start = va_arg(arguments, ea_t);
            if (out_size == nullptr)
                return 0;
            const int size = processor_.get_return_address_size(
                static_cast<ida::Address>(function_start));
            if (size <= 0)
                return 0;
            *out_size = size;
            return 1;
        }
        case processor_t::ev_analyze_prolog: {
            const ea_t function_start = va_arg(arguments, ea_t);
            return processor_.analyze_function_prolog(
                static_cast<ida::Address>(function_start));
        }
        case processor_t::ev_calc_spdelta: {
            auto* out_delta = va_arg(arguments, sval_t*);
            const auto* instruction = va_arg(arguments, const insn_t*);
            if (out_delta == nullptr || instruction == nullptr)
                return 0;
            std::int64_t delta = 0;
            const int result = processor_.calculate_stack_pointer_delta(
                static_cast<ida::Address>(instruction->ea), delta);
            if (result != 0)
                *out_delta = static_cast<sval_t>(delta);
            return result;
        }
        case processor_t::ev_is_switch: {
            auto* switch_info = va_arg(arguments, switch_info_t*);
            const auto* instruction = va_arg(arguments, const insn_t*);
            if (switch_info == nullptr || instruction == nullptr)
                return 0;
            SwitchDescription description;
            const int result = processor_.detect_switch(
                static_cast<ida::Address>(instruction->ea), description);
            if (result == 1 && !materialize_switch(*switch_info, description)) {
                report_callback_error("detect_switch", "invalid switch description");
                return 0;
            }
            return result;
        }
        case processor_t::ev_calc_switch_cases: {
            auto* values = va_arg(arguments, casevec_t*);
            auto* targets = va_arg(arguments, eavec_t*);
            const ea_t instruction_address = va_arg(arguments, ea_t);
            const auto* switch_info = va_arg(arguments, const switch_info_t*);
            if ((values == nullptr && targets == nullptr) || switch_info == nullptr)
                return 0;
            std::vector<SwitchCase> cases;
            const auto description = copy_switch_description(*switch_info);
            const int result = processor_.calculate_switch_cases(
                static_cast<ida::Address>(instruction_address),
                description, cases);
            if (result <= 0)
                return result;
            if (!ida::detail::processor_bridge::switch_cases_are_valid(
                    description, cases)) {
                report_callback_error(
                    "calculate_switch_cases", "invalid switch cases");
                return 0;
            }
            if (targets != nullptr)
                targets->clear();
            if (values != nullptr)
                values->clear();
            for (const auto& switch_case : cases) {
                if (targets != nullptr)
                    targets->push_back(static_cast<ea_t>(switch_case.target));
                if (values != nullptr) {
                    svalvec_t one_case;
                    for (const auto value : switch_case.values)
                        one_case.push_back(static_cast<sval_t>(value));
                    values->push_back(std::move(one_case));
                }
            }
            return result;
        }
        case processor_t::ev_create_switch_xrefs: {
            const ea_t instruction_address = va_arg(arguments, ea_t);
            const auto* switch_info = va_arg(arguments, const switch_info_t*);
            return switch_info != nullptr
                ? processor_.create_switch_references(
                    static_cast<ida::Address>(instruction_address),
                    copy_switch_description(*switch_info))
                : 0;
        }
        default:
            return 0;
        }
    }

    Processor& processor_;
};

ssize_t idaapi idax_processor_notify(void*, int message_id, va_list) {
    if (message_id != processor_t::ev_get_procmod)
        return 0;

    auto& state = descriptor_state();
    if (!state.valid || state.processor == nullptr) {
        report_callback_error("registration", state.error);
        return 0;
    }
    return static_cast<ssize_t>(reinterpret_cast<std::size_t>(
        new IdaxProcessorModule(*state.processor)));
}

processor_t make_processor_descriptor() {
    auto& state = descriptor_state();
    processor_t descriptor{};
    descriptor.version = IDP_INTERFACE_VERSION;
    descriptor.id = state.info.id;
    descriptor.flag = ida::detail::processor_bridge::normalized_processor_flags(
        state.info.flags, state.info.default_bitness);
    descriptor.flag2 = state.info.flags2;

    descriptor.cnbits = state.info.code_bits_per_byte;
    descriptor.dnbits = state.info.data_bits_per_byte;
    descriptor.psnames = state.short_names.data();
    descriptor.plnames = state.long_names.data();
    descriptor.assemblers = state.assembler_pointers.data();
    descriptor._notify = idax_processor_notify;
    descriptor.reg_names = state.register_names.data();
    descriptor.regs_num = static_cast<int32>(state.register_names.size());
    descriptor.reg_first_sreg = state.info.first_segment_register;
    descriptor.reg_last_sreg = state.info.last_segment_register;
    descriptor.segreg_size = state.info.segment_register_size;
    descriptor.reg_code_sreg = state.info.code_segment_register;
    descriptor.reg_data_sreg = state.info.data_segment_register;
    descriptor.instruc_start = 0;
    descriptor.instruc_end = static_cast<int32>(state.instructions.size());
    descriptor.instruc = state.instructions.data();
    descriptor.icode_return = state.info.return_icode;
    return descriptor;
}

} // namespace

idaman processor_t ida_module_data LPH = make_processor_descriptor();
