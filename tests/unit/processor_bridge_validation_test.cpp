#include "detail/processor_bridge_validation.hpp"

#include <cstdint>
#include <iostream>
#include <limits>

namespace bridge = ida::detail::processor_bridge;
namespace processor = ida::processor;

namespace {

int failures = 0;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::cerr << "FAIL line " << __LINE__ << ": " #condition "\n"; \
            ++failures;                                                        \
        }                                                                      \
    } while (false)

processor::ProcessorInfo valid_info() {
    processor::ProcessorInfo info;
    info.id = 0x8001;
    info.short_names = {"valid"};
    info.registers = {{"r0", false}, {"r1", false}, {"cs", false}, {"ds", false}};
    info.instructions = {{"invalid", 0}, {"mov", 0}};
    return info;
}

processor::AnalyzeOperand valid_register_operand() {
    processor::AnalyzeOperand operand;
    operand.index = 0;
    operand.kind = processor::AnalyzeOperandKind::Register;
    operand.has_register = true;
    operand.register_index = 0;
    operand.data_type_code = 2;
    return operand;
}

processor::AnalyzeDetails valid_details() {
    processor::AnalyzeDetails details;
    details.instruction_code = 1;
    details.size = 4;
    details.operands = {valid_register_operand()};
    return details;
}

processor::SwitchDescription valid_switch() {
    processor::SwitchDescription description;
    description.kind = processor::SwitchTableKind::Dense;
    description.jump_table = 0x1000;
    description.case_count = 3;
    description.jump_table_entry_count = 3;
    description.jump_element_size = 4;
    description.expression_register = 0;
    description.expression_data_type = 2;
    return description;
}

void test_analysis_validation() {
    const auto info = valid_info();
    CHECK(bridge::analyze_details_are_valid(info, valid_details()));

    auto details = valid_details();
    details.size = 0;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.size = static_cast<int>(std::numeric_limits<std::uint16_t>::max()) + 1;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.instruction_code = 2;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.push_back(details.operands.front());
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().index = bridge::kMaximumOperands;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().data_type_code = bridge::kMaximumDataTypeCode + 1;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().has_register = false;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().register_index = 4;
    CHECK(!bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    auto& operand = details.operands.front();
    operand.kind = processor::AnalyzeOperandKind::Immediate;
    operand.has_register = false;
    CHECK(!bridge::analyze_details_are_valid(info, details));
    operand.has_immediate = true;
    CHECK(bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().kind = processor::AnalyzeOperandKind::NearAddress;
    details.operands.front().has_register = false;
    CHECK(!bridge::analyze_details_are_valid(info, details));
    details.operands.front().has_target_address = true;
    details.operands.front().target_address = 0x2000;
    CHECK(bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    details.operands.front().kind = processor::AnalyzeOperandKind::Displacement;
    CHECK(!bridge::analyze_details_are_valid(info, details));
    details.operands.front().has_displacement = true;
    CHECK(bridge::analyze_details_are_valid(info, details));

    details = valid_details();
    for (std::size_t index = 1; index < bridge::kMaximumOperands; ++index) {
        auto extra = valid_register_operand();
        extra.index = index;
        details.operands.push_back(extra);
    }
    CHECK(bridge::analyze_details_are_valid(info, details));
    auto ninth = valid_register_operand();
    ninth.index = 0;
    details.operands.push_back(ninth);
    CHECK(!bridge::analyze_details_are_valid(info, details));
}

void test_descriptor_validation() {
    CHECK(bridge::processor_info_is_valid(valid_info()));

    auto info = valid_info();
    info.id = 0x8000;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.short_names.clear();
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.short_names = {"toolong09"};
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.long_names = {"one", "two"};
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.registers.front().name.clear();
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.code_segment_register = 4;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.first_segment_register = 3;
    info.last_segment_register = 2;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.segment_register_size = 9;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.instructions.clear();
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.instructions.front().mnemonic.clear();
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.instructions.front().operand_count = 9;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.return_icode = 2;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.code_bits_per_byte = 65;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    info.default_bitness = 48;
    CHECK(!bridge::processor_info_is_valid(info));

    info = valid_info();
    processor::AssemblerInfo assembler;
    info.assemblers = {assembler};
    CHECK(!bridge::processor_info_is_valid(info));
}

void test_bitness_normalization() {
    using Flag = processor::ProcessorFlag;
    const auto value = [](Flag flag) { return static_cast<std::uint32_t>(flag); };
    const std::uint32_t unrelated = value(Flag::Segments) | value(Flag::TypeInfo);
    const std::uint32_t contradictory =
        unrelated | value(Flag::Use32) | value(Flag::Use64)
        | value(Flag::DefaultSeg32) | value(Flag::DefaultSeg64);

    const auto flags16 = bridge::normalized_processor_flags(contradictory, 16);
    CHECK(flags16 == unrelated);

    const auto flags32 = bridge::normalized_processor_flags(contradictory, 32);
    CHECK(flags32 == (unrelated | value(Flag::Use32) | value(Flag::DefaultSeg32)));

    const auto flags64 = bridge::normalized_processor_flags(contradictory, 64);
    CHECK(flags64 == (unrelated | value(Flag::Use64) | value(Flag::DefaultSeg64)));
}

void test_switch_validation() {
    const auto info = valid_info();
    CHECK(bridge::switch_description_is_valid(info, valid_switch()));

    auto description = valid_switch();
    description.jump_table = ida::BadAddress;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.kind = processor::SwitchTableKind::Sparse;
    CHECK(!bridge::switch_description_is_valid(info, description));
    description.values_table = 0x1800;
    CHECK(bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.has_default = true;
    CHECK(!bridge::switch_description_is_valid(info, description));
    description.default_target = 0x3000;
    CHECK(bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.case_count = 0;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.jump_table_entry_count = 0;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.case_count =
        static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()) + 1U;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.jump_table_entry_count =
        static_cast<std::uint32_t>(std::numeric_limits<int>::max()) + 1U;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.jump_element_size = 3;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.value_element_size = 16;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.shift = 4;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.expression_data_type = bridge::kMaximumDataTypeCode + 1;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.expression_register = -2;
    CHECK(!bridge::switch_description_is_valid(info, description));

    description = valid_switch();
    description.expression_register = 4;
    CHECK(!bridge::switch_description_is_valid(info, description));
}

void test_switch_case_validation() {
    const auto description = valid_switch();
    std::vector<processor::SwitchCase> cases = {
        {{0, 1}, 0x2000},
        {{2}, 0x3000},
    };
    CHECK(bridge::switch_cases_are_valid(description, cases));

    cases.clear();
    CHECK(!bridge::switch_cases_are_valid(description, cases));

    cases = {{{0, 1}, 0x2000}};
    CHECK(!bridge::switch_cases_are_valid(description, cases));

    cases = {{{0, 1}, 0x2000}, {{1}, 0x3000}};
    CHECK(!bridge::switch_cases_are_valid(description, cases));

    cases = {{{0, 1}, 0x2000}, {{2}, ida::BadAddress}};
    CHECK(!bridge::switch_cases_are_valid(description, cases));

    cases = {{{0, 1, 2}, 0x2000}, {{}, 0x3000}};
    CHECK(!bridge::switch_cases_are_valid(description, cases));
}

} // namespace

int main() {
    test_descriptor_validation();
    test_bitness_normalization();
    test_analysis_validation();
    test_switch_validation();
    test_switch_case_validation();
    if (failures != 0) {
        std::cerr << failures << " processor bridge validation failure(s)\n";
        return 1;
    }
    std::cout << "Processor bridge validation: PASS\n";
    return 0;
}
