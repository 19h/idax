#include <ida/idax.hpp>

#include "../full/jbc_common.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

using idax::examples::jbc::FlagBranch;
using idax::examples::jbc::FlagCall;
using idax::examples::jbc::FlagConditional;
using idax::examples::jbc::FlagJtag;
using idax::examples::jbc::FlagReturn;
using idax::examples::jbc::FlagStop;
using idax::examples::jbc::InstructionDefinition;
using idax::examples::jbc::OperandKind;
using idax::examples::jbc::argument_count;
using idax::examples::jbc::has_flag;
using idax::examples::jbc::instruction_size;
using idax::examples::jbc::jtag_state_name;
using idax::examples::jbc::kRegisterAcc;
using idax::examples::jbc::kRegisterCount;
using idax::examples::jbc::kRegisterCs;
using idax::examples::jbc::kRegisterDs;
using idax::examples::jbc::kRegisterPc;
using idax::examples::jbc::kRegisterSp;
using idax::examples::jbc::kStateCodeBaseIndex;
using idax::examples::jbc::kStateNodeName;
using idax::examples::jbc::kStateStringBaseIndex;
using idax::examples::jbc::lookup_instruction;
using idax::examples::jbc::operand_kind;
using idax::examples::jbc::read_big_endian_u32;

std::string unknown_mnemonic(std::uint8_t opcode) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "op_%02X", opcode);
    return buffer;
}

std::uint32_t feature_flags(std::uint8_t opcode,
                            const InstructionDefinition* def) {
    using Feature = ida::processor::InstructionFeature;

    std::uint32_t flags = 0;
    const int argc = argument_count(opcode);
    if (argc >= 1)
        flags |= static_cast<std::uint32_t>(Feature::Use1);
    if (argc >= 2)
        flags |= static_cast<std::uint32_t>(Feature::Use2);
    if (argc >= 3)
        flags |= static_cast<std::uint32_t>(Feature::Use3);

    if (def != nullptr) {
        if (has_flag(def->flags, FlagCall))
            flags |= static_cast<std::uint32_t>(Feature::Call);
        if (has_flag(def->flags, FlagBranch))
            flags |= static_cast<std::uint32_t>(Feature::Jump);
        if (has_flag(def->flags, FlagStop) || has_flag(def->flags, FlagReturn))
            flags |= static_cast<std::uint32_t>(Feature::Stop);
    }

    return flags;
}

struct DecodedInstruction {
    std::uint8_t opcode{0};
    int argument_count{0};
    int size{0};
    std::array<std::uint32_t, 3> arguments{0, 0, 0};
    const InstructionDefinition* definition{nullptr};
};

ida::Result<DecodedInstruction> decode_instruction(ida::Address address) {
    auto opcode = ida::data::read_byte(address);
    if (!opcode)
        return std::unexpected(opcode.error());

    DecodedInstruction decoded;
    decoded.opcode = *opcode;
    decoded.argument_count = argument_count(decoded.opcode);
    decoded.size = instruction_size(decoded.opcode);
    decoded.definition = lookup_instruction(decoded.opcode);

    if (decoded.argument_count > 0) {
        auto bytes = ida::data::read_bytes(
            address + 1, static_cast<ida::AddressSize>(decoded.argument_count * 4));
        if (!bytes)
            return std::unexpected(bytes.error());
        if (bytes->size() != static_cast<std::size_t>(decoded.argument_count * 4)) {
            return std::unexpected(ida::Error::validation(
                "Truncated JBC instruction arguments", std::to_string(address)));
        }
        for (int index = 0; index < decoded.argument_count; ++index) {
            decoded.arguments[index] = read_big_endian_u32(bytes->data() + (index * 4));
        }
    }

    return decoded;
}

bool has_segment(ida::Address address) {
    auto seg = ida::segment::at(address);
    return seg.has_value();
}

class JbcFullProcessor final : public ida::processor::Processor {
public:
    ida::processor::ProcessorInfo info() const override {
        ida::processor::ProcessorInfo pi;
        pi.id = 0x8BC0;
        pi.short_names = {"jbc"};
        pi.long_names = {"JAM Byte-Code (idax full example processor)"};

        using Flag = ida::processor::ProcessorFlag;
        pi.flags = static_cast<std::uint32_t>(Flag::Segments)
                 | static_cast<std::uint32_t>(Flag::Use32)
                 | static_cast<std::uint32_t>(Flag::DefaultSeg32)
                 | static_cast<std::uint32_t>(Flag::HexNumbers);

        pi.code_bits_per_byte = 8;
        pi.data_bits_per_byte = 8;
        pi.default_bitness = 32;

        pi.registers = {
            {"sp", false},
            {"pc", false},
            {"acc", false},
            {"cs", false},
            {"ds", false},
        };
        pi.code_segment_register = kRegisterCs;
        pi.data_segment_register = kRegisterDs;
        pi.first_segment_register = kRegisterCs;
        pi.last_segment_register = kRegisterDs;
        pi.segment_register_size = 2;

        pi.instructions.resize(256);
        for (std::uint16_t opcode = 0; opcode <= 0xFF; ++opcode) {
            const auto* def = lookup_instruction(static_cast<std::uint8_t>(opcode));
            ida::processor::InstructionDescriptor descriptor;
            descriptor.mnemonic = def ? std::string(def->mnemonic)
                                      : unknown_mnemonic(static_cast<std::uint8_t>(opcode));
            descriptor.feature_flags = feature_flags(static_cast<std::uint8_t>(opcode), def);
            descriptor.operand_count = static_cast<std::uint8_t>(argument_count(
                static_cast<std::uint8_t>(opcode)));
            pi.instructions[opcode] = std::move(descriptor);
        }

        pi.return_icode = 0x11;

        ida::processor::AssemblerInfo assembler;
        assembler.name = "JAM Byte-Code Assembler";
        assembler.comment_prefix = ";";
        assembler.origin = ".org";
        assembler.end_directive = ".end";
        assembler.byte_directive = ".byte";
        assembler.word_directive = ".word";
        assembler.dword_directive = ".dword";
        assembler.align_directive = ".align";
        assembler.public_directive = ".global";
        assembler.external_directive = ".extern";
        assembler.current_ip_symbol = "$";
        pi.assemblers = {assembler};

        return pi;
    }

    ida::Result<int> analyze(ida::Address address) override {
        auto details = analyze_with_details(address);
        if (!details)
            return 0;
        return details->size;
    }

    ida::Result<ida::processor::AnalyzeDetails>
    analyze_with_details(ida::Address address) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return std::unexpected(decoded.error());
        return build_analyze_details(*decoded);
    }

    ida::processor::EmulateResult emulate(ida::Address address) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return ida::processor::EmulateResult::NotImplemented;

        const auto& instruction = *decoded;
        bool flow = true;

        if (instruction.definition != nullptr) {
            if (has_flag(instruction.definition->flags, FlagReturn)
                || has_flag(instruction.definition->flags, FlagStop)) {
                flow = false;
            }
            if (has_flag(instruction.definition->flags, FlagBranch)
                && !has_flag(instruction.definition->flags, FlagConditional)) {
                flow = false;
            }
        }

        if (instruction.definition != nullptr && instruction.argument_count >= 1) {
            const auto kind = operand_kind(instruction.definition, 0);
            const auto value = instruction.arguments[0];

            if (kind == OperandKind::Address) {
                const ida::Address target = code_base_ + static_cast<ida::Address>(value);
                if (has_segment(target)) {
                    if (has_flag(instruction.definition->flags, FlagCall)) {
                        ida::xref::add_code(address, target, ida::xref::CodeType::CallNear);
                    } else if (has_flag(instruction.definition->flags, FlagBranch)) {
                        ida::xref::add_code(address, target, ida::xref::CodeType::JumpNear);
                    } else {
                        ida::xref::add_code(address, target, ida::xref::CodeType::Flow);
                    }
                }
            } else if (kind == OperandKind::StringOffset) {
                const ida::Address target = string_base_ + static_cast<ida::Address>(value);
                if (has_segment(target)) {
                    ida::xref::add_data(address, target, ida::xref::DataType::Read);
                }
            }
        }

        if (instruction.definition != nullptr && instruction.argument_count >= 2) {
            const auto kind = operand_kind(instruction.definition, 1);
            if (kind == OperandKind::Address) {
                const ida::Address target =
                    code_base_ + static_cast<ida::Address>(instruction.arguments[1]);
                if (has_segment(target)) {
                    ida::xref::add_code(address, target, ida::xref::CodeType::JumpNear);
                }
            }
        }

        if (flow) {
            ida::xref::add_code(address,
                                address + static_cast<ida::Address>(instruction.size),
                                ida::xref::CodeType::Flow);
        }

        return ida::processor::EmulateResult::Success;
    }

    void output_instruction(ida::Address address) override {
        ida::processor::OutputContext output;
        (void)output_instruction_with_context(address, output);
    }

    ida::processor::OutputOperandResult
    output_operand(ida::Address address, int operand_index) override {
        ida::processor::OutputContext output;
        return output_operand_with_context(address, operand_index, output);
    }

    ida::processor::OutputInstructionResult
    output_instruction_with_context(ida::Address address,
                                    ida::processor::OutputContext& output) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return ida::processor::OutputInstructionResult::NotImplemented;

        const auto& instruction = *decoded;

        auto mnemonic_result = output_mnemonic_with_context(address, output);
        if (mnemonic_result != ida::processor::OutputInstructionResult::Success)
            return mnemonic_result;

        for (int index = 0; index < instruction.argument_count; ++index) {
            if (index == 0) {
                output.space();
            } else {
                output.comma().space();
            }
            append_operand_text(output, instruction, index);
        }

        if (instruction.definition != nullptr
            && has_flag(instruction.definition->flags, FlagJtag)
            && operand_kind(instruction.definition, 0) == OperandKind::State
            && instruction.argument_count >= 1) {
            std::string note = "; ";
            note += std::string(jtag_state_name(
                static_cast<std::uint8_t>(instruction.arguments[0])));
            output.space().comment(note);
        }

        return ida::processor::OutputInstructionResult::Success;
    }

    ida::processor::OutputInstructionResult
    output_mnemonic_with_context(ida::Address address,
                                 ida::processor::OutputContext& output) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return ida::processor::OutputInstructionResult::NotImplemented;

        const std::string mnemonic = decoded->definition
            ? std::string(decoded->definition->mnemonic)
            : unknown_mnemonic(decoded->opcode);
        output.mnemonic(mnemonic);
        return ida::processor::OutputInstructionResult::Success;
    }

    ida::processor::OutputOperandResult
    output_operand_with_context(ida::Address address,
                                int operand_index,
                                ida::processor::OutputContext& output) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return ida::processor::OutputOperandResult::NotImplemented;
        if (operand_index < 0 || operand_index >= decoded->argument_count)
            return ida::processor::OutputOperandResult::Hidden;

        append_operand_text(output, *decoded, operand_index);
        return ida::processor::OutputOperandResult::Success;
    }

    void on_new_file(std::string_view filename) override {
        (void)filename;
        reload_state();
    }

    void on_old_file(std::string_view filename) override {
        (void)filename;
        reload_state();
    }

    int is_call(ida::Address address) override {
        auto decoded = decode_with_cache(address);
        if (!decoded || decoded->definition == nullptr)
            return 0;
        return has_flag(decoded->definition->flags, FlagCall) ? 1 : -1;
    }

    int is_return(ida::Address address) override {
        auto decoded = decode_with_cache(address);
        if (!decoded || decoded->definition == nullptr)
            return 0;
        return has_flag(decoded->definition->flags, FlagReturn) ? 1 : -1;
    }

    int may_be_function(ida::Address address) override {
        auto decoded = decode_with_cache(address);
        if (!decoded)
            return 0;
        if (decoded->opcode == 0x43)
            return 100;
        return 50;
    }

    int is_basic_block_end(ida::Address address,
                           bool call_instruction_stops_block) override {
        (void)call_instruction_stops_block;

        auto decoded = decode_with_cache(address);
        if (!decoded || decoded->definition == nullptr)
            return 0;

        if (has_flag(decoded->definition->flags, FlagReturn)
            || has_flag(decoded->definition->flags, FlagStop)) {
            return 1;
        }
        if (has_flag(decoded->definition->flags, FlagBranch)
            && !has_flag(decoded->definition->flags, FlagConditional)) {
            return 1;
        }
        return -1;
    }

private:
    ida::Address code_base_{0};
    ida::Address string_base_{0};
    ida::Address cached_decode_address_{ida::BadAddress};
    bool has_cached_decode_{false};
    DecodedInstruction cached_decode_{};

    static ida::processor::AnalyzeOperandKind
    to_operand_kind(OperandKind kind) {
        switch (kind) {
        case OperandKind::Address:
            return ida::processor::AnalyzeOperandKind::NearAddress;
        case OperandKind::StringOffset:
            return ida::processor::AnalyzeOperandKind::DirectMemory;
        case OperandKind::Variable:
            return ida::processor::AnalyzeOperandKind::ProcessorSpecific0;
        case OperandKind::State:
        case OperandKind::Count:
        case OperandKind::Immediate32:
            return ida::processor::AnalyzeOperandKind::Immediate;
        case OperandKind::None:
            return ida::processor::AnalyzeOperandKind::None;
        }
        return ida::processor::AnalyzeOperandKind::None;
    }

    ida::Result<DecodedInstruction> decode_with_cache(ida::Address address) {
        if (has_cached_decode_ && cached_decode_address_ == address)
            return cached_decode_;

        auto decoded = decode_instruction(address);
        if (!decoded)
            return std::unexpected(decoded.error());

        cached_decode_address_ = address;
        cached_decode_ = *decoded;
        has_cached_decode_ = true;
        return cached_decode_;
    }

    ida::processor::AnalyzeDetails
    build_analyze_details(const DecodedInstruction& instruction) const {
        ida::processor::AnalyzeDetails details;
        details.size = instruction.size;
        details.operands.reserve(static_cast<std::size_t>(instruction.argument_count));

        for (int operand_index = 0; operand_index < instruction.argument_count; ++operand_index) {
            const auto value = instruction.arguments[operand_index];
            const auto operand_kind_value = operand_kind(instruction.definition, operand_index);

            ida::processor::AnalyzeOperand operand;
            operand.index = static_cast<std::size_t>(operand_index);
            operand.kind = to_operand_kind(operand_kind_value);
            operand.processor_flags = instruction.definition != nullptr
                ? instruction.definition->flags
                : 0;

            switch (operand_kind_value) {
            case OperandKind::Address:
                operand.has_target_address = true;
                operand.target_address = code_base_ + static_cast<ida::Address>(value);
                break;

            case OperandKind::StringOffset:
                operand.has_target_address = true;
                operand.target_address = string_base_ + static_cast<ida::Address>(value);
                break;

            case OperandKind::Variable:
            case OperandKind::State:
            case OperandKind::Count:
            case OperandKind::Immediate32:
                operand.has_immediate = true;
                operand.immediate_value = value;
                break;

            case OperandKind::None:
                break;
            }

            details.operands.push_back(std::move(operand));
        }

        return details;
    }

    void clear_decode_cache() {
        cached_decode_address_ = ida::BadAddress;
        cached_decode_ = DecodedInstruction{};
        has_cached_decode_ = false;
    }

    void reload_state() {
        code_base_ = 0;
        string_base_ = 0;
        clear_decode_cache();

        auto node = ida::storage::Node::open(kStateNodeName);
        if (!node)
            return;

        auto code = node->alt(kStateCodeBaseIndex);
        if (code)
            code_base_ = static_cast<ida::Address>(*code);

        auto str = node->alt(kStateStringBaseIndex);
        if (str)
            string_base_ = static_cast<ida::Address>(*str);
    }

    void append_operand_text(ida::processor::OutputContext& output,
                             const DecodedInstruction& instruction,
                             int operand_index) const {
        const auto value = instruction.arguments[operand_index];
        const auto kind = operand_kind(instruction.definition, operand_index);

        switch (kind) {
        case OperandKind::Address: {
            ida::Address target = code_base_ + static_cast<ida::Address>(value);
            auto symbol = ida::name::get(target);
            if (symbol && !symbol->empty()) {
                output.symbol(*symbol);
            } else {
                output.address(target);
            }
            break;
        }

        case OperandKind::Variable:
            output.keyword("var_").immediate(value, 10);
            break;

        case OperandKind::StringOffset: {
            ida::Address target = string_base_ + static_cast<ida::Address>(value);
            output.keyword("str").punctuation(":");
            auto symbol = ida::name::get(target);
            if (symbol && !symbol->empty()) {
                output.symbol(*symbol);
            } else {
                output.address(target);
            }
            break;
        }

        case OperandKind::State:
            output.keyword(jtag_state_name(static_cast<std::uint8_t>(value)));
            break;

        case OperandKind::Count:
        case OperandKind::Immediate32:
            output.immediate(value, 16);
            break;

        case OperandKind::None:
            break;
        }
    }
};

}  // namespace

IDAX_PROCESSOR(JbcFullProcessor)
