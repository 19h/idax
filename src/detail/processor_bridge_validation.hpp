#ifndef IDAX_DETAIL_PROCESSOR_BRIDGE_VALIDATION_HPP
#define IDAX_DETAIL_PROCESSOR_BRIDGE_VALIDATION_HPP

#include <ida/processor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unordered_set>

namespace ida::detail::processor_bridge {

inline constexpr std::size_t kMaximumOperands = 8;
inline constexpr std::uint32_t kMaximumDataTypeCode = 18;
inline constexpr std::size_t kMaximumRegisters =
    static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) + 1U;
inline constexpr std::size_t kMaximumInstructions = kMaximumRegisters;

inline constexpr std::uint32_t processor_flag_value(processor::ProcessorFlag flag) {
    return static_cast<std::uint32_t>(flag);
}

inline std::uint32_t normalized_processor_flags(std::uint32_t flags,
                                                int default_bitness) {
    constexpr std::uint32_t bitness_mask =
        processor_flag_value(processor::ProcessorFlag::Use32)
        | processor_flag_value(processor::ProcessorFlag::Use64)
        | processor_flag_value(processor::ProcessorFlag::DefaultSeg32)
        | processor_flag_value(processor::ProcessorFlag::DefaultSeg64);
    flags &= ~bitness_mask;
    if (default_bitness == 64) {
        flags |= processor_flag_value(processor::ProcessorFlag::Use64)
              | processor_flag_value(processor::ProcessorFlag::DefaultSeg64);
    } else if (default_bitness == 32) {
        flags |= processor_flag_value(processor::ProcessorFlag::Use32)
              | processor_flag_value(processor::ProcessorFlag::DefaultSeg32);
    }
    return flags;
}

inline const char* processor_info_error(const processor::ProcessorInfo& info) {
    if (info.id <= 0x8000)
        return "ProcessorInfo.id must be a third-party processor ID above 0x8000";
    if (info.short_names.empty())
        return "ProcessorInfo.short_names must not be empty";
    for (const auto& name : info.short_names) {
        if (name.empty() || name.size() >= 9)
            return "Processor short names must contain 1..8 bytes";
    }
    if (!info.long_names.empty()) {
        if (info.long_names.size() != info.short_names.size())
            return "ProcessorInfo long/short name counts must match";
        for (const auto& name : info.long_names) {
            if (name.empty())
                return "Processor long names must not be empty";
        }
    }

    if (info.registers.empty() || info.registers.size() > kMaximumRegisters)
        return "ProcessorInfo register count is outside 1..65536";
    for (const auto& register_info : info.registers) {
        if (register_info.name.empty())
            return "Processor register names must not be empty";
    }
    const auto register_count = static_cast<int>(info.registers.size());
    const std::array<int, 4> register_indices = {
        info.first_segment_register,
        info.last_segment_register,
        info.code_segment_register,
        info.data_segment_register,
    };
    for (const int index : register_indices) {
        if (index < 0 || index >= register_count)
            return "ProcessorInfo segment-register index is out of range";
    }
    if (info.first_segment_register > info.last_segment_register)
        return "ProcessorInfo segment-register range is inverted";
    if (info.segment_register_size < 0 || info.segment_register_size > 8)
        return "ProcessorInfo.segment_register_size must be in 0..8";

    if (info.instructions.empty()
        || info.instructions.size() > kMaximumInstructions) {
        return "ProcessorInfo instruction count is outside 1..65536";
    }
    for (const auto& instruction : info.instructions) {
        if (instruction.mnemonic.empty())
            return "Processor instruction mnemonics must not be empty";
        if (instruction.operand_count > kMaximumOperands)
            return "Processor instruction operand count exceeds eight";
    }
    if (info.return_icode < 0
        || static_cast<std::size_t>(info.return_icode) >= info.instructions.size()) {
        return "ProcessorInfo.return_icode is out of range";
    }

    if (info.code_bits_per_byte <= 0 || info.code_bits_per_byte > 64
        || info.data_bits_per_byte <= 0 || info.data_bits_per_byte > 64) {
        return "Processor byte widths must be in 1..64";
    }
    if (info.default_bitness != 16
        && info.default_bitness != 32
        && info.default_bitness != 64) {
        return "ProcessorInfo.default_bitness must be 16, 32, or 64";
    }
    for (const auto& assembler : info.assemblers) {
        if (assembler.name.empty())
            return "Processor assembler names must not be empty";
    }
    return nullptr;
}

inline bool processor_info_is_valid(const processor::ProcessorInfo& info) {
    return processor_info_error(info) == nullptr;
}

inline bool register_index_is_valid(const processor::ProcessorInfo& info,
                                    int register_index) {
    return register_index >= 0
        && static_cast<std::size_t>(register_index) < info.registers.size();
}

inline bool analyze_operand_is_valid(const processor::ProcessorInfo& info,
                                     const processor::AnalyzeOperand& operand) {
    if (operand.index >= kMaximumOperands
        || operand.data_type_code > kMaximumDataTypeCode) {
        return false;
    }

    const auto has_valid_register = [&] {
        return operand.has_register
            && register_index_is_valid(info, operand.register_index);
    };
    const auto has_valid_address = [&] {
        return operand.has_target_address
            && operand.target_address != BadAddress;
    };

    using Kind = processor::AnalyzeOperandKind;
    switch (operand.kind) {
    case Kind::None:
        return true;
    case Kind::Register:
    case Kind::IndirectMemory:
        return has_valid_register();
    case Kind::Immediate:
        return operand.has_immediate;
    case Kind::NearAddress:
    case Kind::FarAddress:
    case Kind::DirectMemory:
        return has_valid_address();
    case Kind::Displacement:
        return has_valid_register() && operand.has_displacement;
    case Kind::ProcessorSpecific0:
    case Kind::ProcessorSpecific1:
    case Kind::ProcessorSpecific2:
    case Kind::ProcessorSpecific3:
    case Kind::ProcessorSpecific4:
    case Kind::ProcessorSpecific5:
        return !operand.has_register || has_valid_register();
    }
    return false;
}

inline bool analyze_details_are_valid(const processor::ProcessorInfo& info,
                                      const processor::AnalyzeDetails& details) {
    if (details.size <= 0
        || details.size > std::numeric_limits<std::uint16_t>::max()
        || details.instruction_code >= info.instructions.size()
        || details.operands.size() > kMaximumOperands) {
        return false;
    }

    std::array<bool, kMaximumOperands> populated{};
    for (const auto& operand : details.operands) {
        if (!analyze_operand_is_valid(info, operand)
            || populated[operand.index]) {
            return false;
        }
        populated[operand.index] = true;
    }
    return true;
}

inline bool switch_element_size_is_valid(std::uint8_t size) {
    return size == 0 || size == 1 || size == 2 || size == 4 || size == 8;
}

inline bool switch_description_is_valid(
        const processor::ProcessorInfo& info,
        const processor::SwitchDescription& description) {
    using Kind = processor::SwitchTableKind;
    if (description.case_count == 0
        || description.case_count > std::numeric_limits<std::uint16_t>::max()
        || description.jump_table_entry_count == 0
        || description.jump_table_entry_count
            > static_cast<std::uint32_t>(std::numeric_limits<int>::max())
        || description.jump_table == BadAddress
        || description.element_base == BadAddress
        || ((description.kind == Kind::Sparse
             || description.kind == Kind::Indirect)
            && description.values_table == BadAddress)
        || (description.has_default
            && description.default_target == BadAddress)
        || description.expression_data_type > kMaximumDataTypeCode
        || description.expression_register < -1
        || (description.expression_register >= 0
            && !register_index_is_valid(info, description.expression_register))
        || !switch_element_size_is_valid(description.jump_element_size)
        || !switch_element_size_is_valid(description.value_element_size)
        || description.shift > 3) {
        return false;
    }

    switch (description.kind) {
    case Kind::Dense:
    case Kind::Sparse:
    case Kind::Indirect:
    case Kind::Custom:
        return true;
    }
    return false;
}

inline bool switch_cases_are_valid(
        const processor::SwitchDescription& description,
        const std::vector<processor::SwitchCase>& cases) {
    if (cases.empty() || cases.size() > description.case_count)
        return false;

    std::size_t value_count = 0;
    std::unordered_set<std::int64_t> observed_values;
    observed_values.reserve(description.case_count);
    for (const auto& switch_case : cases) {
        if (switch_case.target == BadAddress || switch_case.values.empty())
            return false;
        if (switch_case.values.size() > description.case_count - value_count)
            return false;
        value_count += switch_case.values.size();
        for (const auto value : switch_case.values) {
            if (!observed_values.insert(value).second)
                return false;
        }
    }
    return value_count == description.case_count;
}

} // namespace ida::detail::processor_bridge

#endif // IDAX_DETAIL_PROCESSOR_BRIDGE_VALIDATION_HPP
