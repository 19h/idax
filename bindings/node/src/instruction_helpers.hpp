#ifndef IDAX_NODE_INSTRUCTION_HELPERS_HPP
#define IDAX_NODE_INSTRUCTION_HELPERS_HPP
#include <ida/instruction.hpp>
namespace idax_node {
inline const char* BranchConditionToString(ida::instruction::BranchCondition condition) {
    switch (condition) {
        case ida::instruction::BranchCondition::None: return "none";
        case ida::instruction::BranchCondition::Always: return "always";
        case ida::instruction::BranchCondition::Equal: return "equal";
        case ida::instruction::BranchCondition::NotEqual: return "notEqual";
        case ida::instruction::BranchCondition::LessThanSigned: return "lessThanSigned";
        case ida::instruction::BranchCondition::LessThanOrEqualSigned: return "lessThanOrEqualSigned";
        case ida::instruction::BranchCondition::GreaterThanSigned: return "greaterThanSigned";
        case ida::instruction::BranchCondition::GreaterThanOrEqualSigned: return "greaterThanOrEqualSigned";
        case ida::instruction::BranchCondition::LessThanUnsigned: return "lessThanUnsigned";
        case ida::instruction::BranchCondition::LessThanOrEqualUnsigned: return "lessThanOrEqualUnsigned";
        case ida::instruction::BranchCondition::GreaterThanUnsigned: return "greaterThanUnsigned";
        case ida::instruction::BranchCondition::GreaterThanOrEqualUnsigned: return "greaterThanOrEqualUnsigned";
        case ida::instruction::BranchCondition::Zero: return "zero";
        case ida::instruction::BranchCondition::NotZero: return "notZero";
        case ida::instruction::BranchCondition::Negative: return "negative";
        case ida::instruction::BranchCondition::NotNegative: return "notNegative";
        case ida::instruction::BranchCondition::Overflow: return "overflow";
        case ida::instruction::BranchCondition::NoOverflow: return "noOverflow";
        case ida::instruction::BranchCondition::Parity: return "parity";
        case ida::instruction::BranchCondition::NoParity: return "noParity";
        case ida::instruction::BranchCondition::CountZero: return "countZero";
        case ida::instruction::BranchCondition::BitZero: return "bitZero";
        case ida::instruction::BranchCondition::BitNotZero: return "bitNotZero";
        case ida::instruction::BranchCondition::CountNotZero: return "countNotZero";
        case ida::instruction::BranchCondition::CountNotZeroAndEqual: return "countNotZeroAndEqual";
        case ida::instruction::BranchCondition::CountNotZeroAndNotEqual: return "countNotZeroAndNotEqual";
        case ida::instruction::BranchCondition::Unknown: return "unknown";
        case ida::instruction::BranchCondition::Never: return "never";
    }
    return "unknown";
}
}
#endif
