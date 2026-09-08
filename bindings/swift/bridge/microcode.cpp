#include "microcode.h"
#include "decompiler.h"
#include "support.hpp"
#include <ida/decompiler.hpp>
#include <ida/ui.hpp>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

namespace {
using namespace ida::decompiler;
using idax::swift::protect;
using idax::swift::require_runtime_thread;
using idax::swift::write_error;
int status(const ida::Status &result, IdaxSwiftError *error) {
    return result ? 0 : write_error(result.error(), error);
}
struct Budget {
    size_t nodes{};
    void enter(unsigned depth) {
        if (depth > 128 || ++nodes > 65536)
            throw ida::Error::validation("Microcode input exceeds depth 128 or 65536 nodes");
    }
};
template <class T> void check_array(const T *ptr, size_t count) {
    if (count > 65536 || (count && !ptr))
        throw ida::Error::validation("Invalid microcode input array");
}
template <class Enum> Enum enum_value(int value);
template <> MicrocodeCallingConvention enum_value<MicrocodeCallingConvention>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeCallingConvention::Unspecified):
        return MicrocodeCallingConvention::Unspecified;
    case static_cast<int>(MicrocodeCallingConvention::Cdecl):
        return MicrocodeCallingConvention::Cdecl;
    case static_cast<int>(MicrocodeCallingConvention::Stdcall):
        return MicrocodeCallingConvention::Stdcall;
    case static_cast<int>(MicrocodeCallingConvention::Fastcall):
        return MicrocodeCallingConvention::Fastcall;
    case static_cast<int>(MicrocodeCallingConvention::Thiscall):
        return MicrocodeCallingConvention::Thiscall;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeFunctionRole enum_value<MicrocodeFunctionRole>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeFunctionRole::Unknown):
        return MicrocodeFunctionRole::Unknown;
    case static_cast<int>(MicrocodeFunctionRole::Empty):
        return MicrocodeFunctionRole::Empty;
    case static_cast<int>(MicrocodeFunctionRole::Memset):
        return MicrocodeFunctionRole::Memset;
    case static_cast<int>(MicrocodeFunctionRole::Memset32):
        return MicrocodeFunctionRole::Memset32;
    case static_cast<int>(MicrocodeFunctionRole::Memset64):
        return MicrocodeFunctionRole::Memset64;
    case static_cast<int>(MicrocodeFunctionRole::Memcpy):
        return MicrocodeFunctionRole::Memcpy;
    case static_cast<int>(MicrocodeFunctionRole::Strcpy):
        return MicrocodeFunctionRole::Strcpy;
    case static_cast<int>(MicrocodeFunctionRole::Strlen):
        return MicrocodeFunctionRole::Strlen;
    case static_cast<int>(MicrocodeFunctionRole::Strcat):
        return MicrocodeFunctionRole::Strcat;
    case static_cast<int>(MicrocodeFunctionRole::Tail):
        return MicrocodeFunctionRole::Tail;
    case static_cast<int>(MicrocodeFunctionRole::Bug):
        return MicrocodeFunctionRole::Bug;
    case static_cast<int>(MicrocodeFunctionRole::Alloca):
        return MicrocodeFunctionRole::Alloca;
    case static_cast<int>(MicrocodeFunctionRole::ByteSwap):
        return MicrocodeFunctionRole::ByteSwap;
    case static_cast<int>(MicrocodeFunctionRole::Present):
        return MicrocodeFunctionRole::Present;
    case static_cast<int>(MicrocodeFunctionRole::ContainingRecord):
        return MicrocodeFunctionRole::ContainingRecord;
    case static_cast<int>(MicrocodeFunctionRole::FastFail):
        return MicrocodeFunctionRole::FastFail;
    case static_cast<int>(MicrocodeFunctionRole::ReadFlags):
        return MicrocodeFunctionRole::ReadFlags;
    case static_cast<int>(MicrocodeFunctionRole::IsMulOk):
        return MicrocodeFunctionRole::IsMulOk;
    case static_cast<int>(MicrocodeFunctionRole::SaturatedMul):
        return MicrocodeFunctionRole::SaturatedMul;
    case static_cast<int>(MicrocodeFunctionRole::BitTest):
        return MicrocodeFunctionRole::BitTest;
    case static_cast<int>(MicrocodeFunctionRole::BitTestAndSet):
        return MicrocodeFunctionRole::BitTestAndSet;
    case static_cast<int>(MicrocodeFunctionRole::BitTestAndReset):
        return MicrocodeFunctionRole::BitTestAndReset;
    case static_cast<int>(MicrocodeFunctionRole::BitTestAndComplement):
        return MicrocodeFunctionRole::BitTestAndComplement;
    case static_cast<int>(MicrocodeFunctionRole::VaArg):
        return MicrocodeFunctionRole::VaArg;
    case static_cast<int>(MicrocodeFunctionRole::VaCopy):
        return MicrocodeFunctionRole::VaCopy;
    case static_cast<int>(MicrocodeFunctionRole::VaStart):
        return MicrocodeFunctionRole::VaStart;
    case static_cast<int>(MicrocodeFunctionRole::VaEnd):
        return MicrocodeFunctionRole::VaEnd;
    case static_cast<int>(MicrocodeFunctionRole::RotateLeft):
        return MicrocodeFunctionRole::RotateLeft;
    case static_cast<int>(MicrocodeFunctionRole::RotateRight):
        return MicrocodeFunctionRole::RotateRight;
    case static_cast<int>(MicrocodeFunctionRole::CarryFlagSub3):
        return MicrocodeFunctionRole::CarryFlagSub3;
    case static_cast<int>(MicrocodeFunctionRole::OverflowFlagSub3):
        return MicrocodeFunctionRole::OverflowFlagSub3;
    case static_cast<int>(MicrocodeFunctionRole::AbsoluteValue):
        return MicrocodeFunctionRole::AbsoluteValue;
    case static_cast<int>(MicrocodeFunctionRole::ThreeWayCompare0):
        return MicrocodeFunctionRole::ThreeWayCompare0;
    case static_cast<int>(MicrocodeFunctionRole::ThreeWayCompare1):
        return MicrocodeFunctionRole::ThreeWayCompare1;
    case static_cast<int>(MicrocodeFunctionRole::WideMemCopy):
        return MicrocodeFunctionRole::WideMemCopy;
    case static_cast<int>(MicrocodeFunctionRole::WideMemSet):
        return MicrocodeFunctionRole::WideMemSet;
    case static_cast<int>(MicrocodeFunctionRole::WideStrCopy):
        return MicrocodeFunctionRole::WideStrCopy;
    case static_cast<int>(MicrocodeFunctionRole::WideStrLen):
        return MicrocodeFunctionRole::WideStrLen;
    case static_cast<int>(MicrocodeFunctionRole::WideStrCat):
        return MicrocodeFunctionRole::WideStrCat;
    case static_cast<int>(MicrocodeFunctionRole::SseCompare4):
        return MicrocodeFunctionRole::SseCompare4;
    case static_cast<int>(MicrocodeFunctionRole::SseCompare8):
        return MicrocodeFunctionRole::SseCompare8;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeInsertPolicy enum_value<MicrocodeInsertPolicy>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeInsertPolicy::Tail):
        return MicrocodeInsertPolicy::Tail;
    case static_cast<int>(MicrocodeInsertPolicy::Beginning):
        return MicrocodeInsertPolicy::Beginning;
    case static_cast<int>(MicrocodeInsertPolicy::BeforeTail):
        return MicrocodeInsertPolicy::BeforeTail;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeOpcode enum_value<MicrocodeOpcode>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeOpcode::NoOperation):
        return MicrocodeOpcode::NoOperation;
    case static_cast<int>(MicrocodeOpcode::Move):
        return MicrocodeOpcode::Move;
    case static_cast<int>(MicrocodeOpcode::Add):
        return MicrocodeOpcode::Add;
    case static_cast<int>(MicrocodeOpcode::Subtract):
        return MicrocodeOpcode::Subtract;
    case static_cast<int>(MicrocodeOpcode::Multiply):
        return MicrocodeOpcode::Multiply;
    case static_cast<int>(MicrocodeOpcode::ZeroExtend):
        return MicrocodeOpcode::ZeroExtend;
    case static_cast<int>(MicrocodeOpcode::LoadMemory):
        return MicrocodeOpcode::LoadMemory;
    case static_cast<int>(MicrocodeOpcode::StoreMemory):
        return MicrocodeOpcode::StoreMemory;
    case static_cast<int>(MicrocodeOpcode::BitwiseOr):
        return MicrocodeOpcode::BitwiseOr;
    case static_cast<int>(MicrocodeOpcode::BitwiseAnd):
        return MicrocodeOpcode::BitwiseAnd;
    case static_cast<int>(MicrocodeOpcode::BitwiseXor):
        return MicrocodeOpcode::BitwiseXor;
    case static_cast<int>(MicrocodeOpcode::ShiftLeft):
        return MicrocodeOpcode::ShiftLeft;
    case static_cast<int>(MicrocodeOpcode::ShiftRightLogical):
        return MicrocodeOpcode::ShiftRightLogical;
    case static_cast<int>(MicrocodeOpcode::ShiftRightArithmetic):
        return MicrocodeOpcode::ShiftRightArithmetic;
    case static_cast<int>(MicrocodeOpcode::FloatAdd):
        return MicrocodeOpcode::FloatAdd;
    case static_cast<int>(MicrocodeOpcode::FloatSub):
        return MicrocodeOpcode::FloatSub;
    case static_cast<int>(MicrocodeOpcode::FloatMul):
        return MicrocodeOpcode::FloatMul;
    case static_cast<int>(MicrocodeOpcode::FloatDiv):
        return MicrocodeOpcode::FloatDiv;
    case static_cast<int>(MicrocodeOpcode::IntegerToFloat):
        return MicrocodeOpcode::IntegerToFloat;
    case static_cast<int>(MicrocodeOpcode::FloatToFloat):
        return MicrocodeOpcode::FloatToFloat;
    case static_cast<int>(MicrocodeOpcode::SignedExtend):
        return MicrocodeOpcode::SignedExtend;
    case static_cast<int>(MicrocodeOpcode::Call):
        return MicrocodeOpcode::Call;
    case static_cast<int>(MicrocodeOpcode::IndirectCall):
        return MicrocodeOpcode::IndirectCall;
    case static_cast<int>(MicrocodeOpcode::Goto):
        return MicrocodeOpcode::Goto;
    case static_cast<int>(MicrocodeOpcode::IndirectJump):
        return MicrocodeOpcode::IndirectJump;
    case static_cast<int>(MicrocodeOpcode::Return):
        return MicrocodeOpcode::Return;
    case static_cast<int>(MicrocodeOpcode::Other):
        return MicrocodeOpcode::Other;
    case static_cast<int>(MicrocodeOpcode::Negate):
        return MicrocodeOpcode::Negate;
    case static_cast<int>(MicrocodeOpcode::LogicalNot):
        return MicrocodeOpcode::LogicalNot;
    case static_cast<int>(MicrocodeOpcode::BitwiseNot):
        return MicrocodeOpcode::BitwiseNot;
    case static_cast<int>(MicrocodeOpcode::LowPart):
        return MicrocodeOpcode::LowPart;
    case static_cast<int>(MicrocodeOpcode::HighPart):
        return MicrocodeOpcode::HighPart;
    case static_cast<int>(MicrocodeOpcode::UnsignedDivide):
        return MicrocodeOpcode::UnsignedDivide;
    case static_cast<int>(MicrocodeOpcode::SignedDivide):
        return MicrocodeOpcode::SignedDivide;
    case static_cast<int>(MicrocodeOpcode::UnsignedRemainder):
        return MicrocodeOpcode::UnsignedRemainder;
    case static_cast<int>(MicrocodeOpcode::SignedRemainder):
        return MicrocodeOpcode::SignedRemainder;
    case static_cast<int>(MicrocodeOpcode::CarryFromAdd):
        return MicrocodeOpcode::CarryFromAdd;
    case static_cast<int>(MicrocodeOpcode::OverflowFromAdd):
        return MicrocodeOpcode::OverflowFromAdd;
    case static_cast<int>(MicrocodeOpcode::CarryFromShiftLeft):
        return MicrocodeOpcode::CarryFromShiftLeft;
    case static_cast<int>(MicrocodeOpcode::CarryFromShiftRight):
        return MicrocodeOpcode::CarryFromShiftRight;
    case static_cast<int>(MicrocodeOpcode::SetNegative):
        return MicrocodeOpcode::SetNegative;
    case static_cast<int>(MicrocodeOpcode::SetOverflow):
        return MicrocodeOpcode::SetOverflow;
    case static_cast<int>(MicrocodeOpcode::SetParity):
        return MicrocodeOpcode::SetParity;
    case static_cast<int>(MicrocodeOpcode::SetNotEqual):
        return MicrocodeOpcode::SetNotEqual;
    case static_cast<int>(MicrocodeOpcode::SetEqual):
        return MicrocodeOpcode::SetEqual;
    case static_cast<int>(MicrocodeOpcode::SetGreaterThanOrEqualUnsigned):
        return MicrocodeOpcode::SetGreaterThanOrEqualUnsigned;
    case static_cast<int>(MicrocodeOpcode::SetLessThanUnsigned):
        return MicrocodeOpcode::SetLessThanUnsigned;
    case static_cast<int>(MicrocodeOpcode::SetGreaterThanUnsigned):
        return MicrocodeOpcode::SetGreaterThanUnsigned;
    case static_cast<int>(MicrocodeOpcode::SetLessThanOrEqualUnsigned):
        return MicrocodeOpcode::SetLessThanOrEqualUnsigned;
    case static_cast<int>(MicrocodeOpcode::SetGreaterThanSigned):
        return MicrocodeOpcode::SetGreaterThanSigned;
    case static_cast<int>(MicrocodeOpcode::SetGreaterThanOrEqualSigned):
        return MicrocodeOpcode::SetGreaterThanOrEqualSigned;
    case static_cast<int>(MicrocodeOpcode::SetLessThanSigned):
        return MicrocodeOpcode::SetLessThanSigned;
    case static_cast<int>(MicrocodeOpcode::SetLessThanOrEqualSigned):
        return MicrocodeOpcode::SetLessThanOrEqualSigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfNonzero):
        return MicrocodeOpcode::JumpIfNonzero;
    case static_cast<int>(MicrocodeOpcode::JumpIfNotEqual):
        return MicrocodeOpcode::JumpIfNotEqual;
    case static_cast<int>(MicrocodeOpcode::JumpIfEqual):
        return MicrocodeOpcode::JumpIfEqual;
    case static_cast<int>(MicrocodeOpcode::JumpIfGreaterThanOrEqualUnsigned):
        return MicrocodeOpcode::JumpIfGreaterThanOrEqualUnsigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfLessThanUnsigned):
        return MicrocodeOpcode::JumpIfLessThanUnsigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfGreaterThanUnsigned):
        return MicrocodeOpcode::JumpIfGreaterThanUnsigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfLessThanOrEqualUnsigned):
        return MicrocodeOpcode::JumpIfLessThanOrEqualUnsigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfGreaterThanSigned):
        return MicrocodeOpcode::JumpIfGreaterThanSigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfGreaterThanOrEqualSigned):
        return MicrocodeOpcode::JumpIfGreaterThanOrEqualSigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfLessThanSigned):
        return MicrocodeOpcode::JumpIfLessThanSigned;
    case static_cast<int>(MicrocodeOpcode::JumpIfLessThanOrEqualSigned):
        return MicrocodeOpcode::JumpIfLessThanOrEqualSigned;
    case static_cast<int>(MicrocodeOpcode::JumpTable):
        return MicrocodeOpcode::JumpTable;
    case static_cast<int>(MicrocodeOpcode::Push):
        return MicrocodeOpcode::Push;
    case static_cast<int>(MicrocodeOpcode::Pop):
        return MicrocodeOpcode::Pop;
    case static_cast<int>(MicrocodeOpcode::Undefined):
        return MicrocodeOpcode::Undefined;
    case static_cast<int>(MicrocodeOpcode::External):
        return MicrocodeOpcode::External;
    case static_cast<int>(MicrocodeOpcode::FloatToSignedInteger):
        return MicrocodeOpcode::FloatToSignedInteger;
    case static_cast<int>(MicrocodeOpcode::FloatToUnsignedInteger):
        return MicrocodeOpcode::FloatToUnsignedInteger;
    case static_cast<int>(MicrocodeOpcode::UnsignedIntegerToFloat):
        return MicrocodeOpcode::UnsignedIntegerToFloat;
    case static_cast<int>(MicrocodeOpcode::FloatNegate):
        return MicrocodeOpcode::FloatNegate;
    case static_cast<int>(MicrocodeOpcode::LoadConstant):
        return MicrocodeOpcode::LoadConstant;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeOperandKind enum_value<MicrocodeOperandKind>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeOperandKind::Empty):
        return MicrocodeOperandKind::Empty;
    case static_cast<int>(MicrocodeOperandKind::Register):
        return MicrocodeOperandKind::Register;
    case static_cast<int>(MicrocodeOperandKind::LocalVariable):
        return MicrocodeOperandKind::LocalVariable;
    case static_cast<int>(MicrocodeOperandKind::RegisterPair):
        return MicrocodeOperandKind::RegisterPair;
    case static_cast<int>(MicrocodeOperandKind::GlobalAddress):
        return MicrocodeOperandKind::GlobalAddress;
    case static_cast<int>(MicrocodeOperandKind::StackVariable):
        return MicrocodeOperandKind::StackVariable;
    case static_cast<int>(MicrocodeOperandKind::HelperReference):
        return MicrocodeOperandKind::HelperReference;
    case static_cast<int>(MicrocodeOperandKind::BlockReference):
        return MicrocodeOperandKind::BlockReference;
    case static_cast<int>(MicrocodeOperandKind::NestedInstruction):
        return MicrocodeOperandKind::NestedInstruction;
    case static_cast<int>(MicrocodeOperandKind::UnsignedImmediate):
        return MicrocodeOperandKind::UnsignedImmediate;
    case static_cast<int>(MicrocodeOperandKind::SignedImmediate):
        return MicrocodeOperandKind::SignedImmediate;
    case static_cast<int>(MicrocodeOperandKind::AddressReference):
        return MicrocodeOperandKind::AddressReference;
    case static_cast<int>(MicrocodeOperandKind::CallArguments):
        return MicrocodeOperandKind::CallArguments;
    case static_cast<int>(MicrocodeOperandKind::StringConstant):
        return MicrocodeOperandKind::StringConstant;
    case static_cast<int>(MicrocodeOperandKind::FloatingPointConstant):
        return MicrocodeOperandKind::FloatingPointConstant;
    case static_cast<int>(MicrocodeOperandKind::Other):
        return MicrocodeOperandKind::Other;
    case static_cast<int>(MicrocodeOperandKind::SwitchCases):
        return MicrocodeOperandKind::SwitchCases;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeValueKind enum_value<MicrocodeValueKind>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeValueKind::Register):
        return MicrocodeValueKind::Register;
    case static_cast<int>(MicrocodeValueKind::LocalVariable):
        return MicrocodeValueKind::LocalVariable;
    case static_cast<int>(MicrocodeValueKind::RegisterPair):
        return MicrocodeValueKind::RegisterPair;
    case static_cast<int>(MicrocodeValueKind::GlobalAddress):
        return MicrocodeValueKind::GlobalAddress;
    case static_cast<int>(MicrocodeValueKind::StackVariable):
        return MicrocodeValueKind::StackVariable;
    case static_cast<int>(MicrocodeValueKind::HelperReference):
        return MicrocodeValueKind::HelperReference;
    case static_cast<int>(MicrocodeValueKind::BlockReference):
        return MicrocodeValueKind::BlockReference;
    case static_cast<int>(MicrocodeValueKind::NestedInstruction):
        return MicrocodeValueKind::NestedInstruction;
    case static_cast<int>(MicrocodeValueKind::UnsignedImmediate):
        return MicrocodeValueKind::UnsignedImmediate;
    case static_cast<int>(MicrocodeValueKind::SignedImmediate):
        return MicrocodeValueKind::SignedImmediate;
    case static_cast<int>(MicrocodeValueKind::Float32Immediate):
        return MicrocodeValueKind::Float32Immediate;
    case static_cast<int>(MicrocodeValueKind::Float64Immediate):
        return MicrocodeValueKind::Float64Immediate;
    case static_cast<int>(MicrocodeValueKind::ByteArray):
        return MicrocodeValueKind::ByteArray;
    case static_cast<int>(MicrocodeValueKind::Vector):
        return MicrocodeValueKind::Vector;
    case static_cast<int>(MicrocodeValueKind::TypeDeclarationView):
        return MicrocodeValueKind::TypeDeclarationView;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
template <> MicrocodeValueLocationKind enum_value<MicrocodeValueLocationKind>(int value) {
    switch (value) {
    case static_cast<int>(MicrocodeValueLocationKind::Unspecified):
        return MicrocodeValueLocationKind::Unspecified;
    case static_cast<int>(MicrocodeValueLocationKind::Register):
        return MicrocodeValueLocationKind::Register;
    case static_cast<int>(MicrocodeValueLocationKind::RegisterWithOffset):
        return MicrocodeValueLocationKind::RegisterWithOffset;
    case static_cast<int>(MicrocodeValueLocationKind::RegisterPair):
        return MicrocodeValueLocationKind::RegisterPair;
    case static_cast<int>(MicrocodeValueLocationKind::RegisterRelative):
        return MicrocodeValueLocationKind::RegisterRelative;
    case static_cast<int>(MicrocodeValueLocationKind::StackOffset):
        return MicrocodeValueLocationKind::StackOffset;
    case static_cast<int>(MicrocodeValueLocationKind::StaticAddress):
        return MicrocodeValueLocationKind::StaticAddress;
    case static_cast<int>(MicrocodeValueLocationKind::Scattered):
        return MicrocodeValueLocationKind::Scattered;
    default:
        throw ida::Error::validation("Invalid microcode enumeration");
    }
}
MicrocodeRegisterRange decode(const IdaxMicrocodeRegisterRange &value, Budget &budget,
                              unsigned depth);
MicrocodeSwitchCase decode(const IdaxMicrocodeSwitchCase &value, Budget &budget, unsigned depth);
MicrocodeCallArgumentProperties decode(const IdaxMicrocodeCallArgumentProperties &value,
                                       Budget &budget, unsigned depth);
MicrocodeLocationPart decode(const IdaxMicrocodeLocationPart &value, Budget &budget,
                             unsigned depth);
MicrocodeValueLocation decode(const IdaxMicrocodeValueLocation &value, Budget &budget,
                              unsigned depth);
MicrocodeOperand decode(const IdaxMicrocodeOperand &value, Budget &budget, unsigned depth);
MicrocodeInstruction decode(const IdaxMicrocodeInstruction &value, Budget &budget, unsigned depth);
MicrocodeValue decode(const IdaxSwiftMicrocodeValue &value, Budget &budget, unsigned depth);
MicrocodeMemoryRange decode(const IdaxSwiftMicrocodeMemoryRange &value, Budget &budget,
                            unsigned depth);
MicrocodeCallOptions decode(const IdaxSwiftMicrocodeCallOptions &value, Budget &budget,
                            unsigned depth);
MicrocodeRegisterRange decode(const IdaxMicrocodeRegisterRange &value, Budget &budget,
                              unsigned depth) {
    budget.enter(depth);
    MicrocodeRegisterRange out;
    out.register_id = value.register_id;
    out.byte_width = value.byte_width;
    return out;
}
MicrocodeSwitchCase decode(const IdaxMicrocodeSwitchCase &value, Budget &budget, unsigned depth) {
    budget.enter(depth);
    MicrocodeSwitchCase out;
    out.value = value.value;
    out.target_block = value.target_block;
    return out;
}
MicrocodeCallArgumentProperties decode(const IdaxMicrocodeCallArgumentProperties &value,
                                       Budget &budget, unsigned depth) {
    budget.enter(depth);
    MicrocodeCallArgumentProperties out;
    out.hidden = value.hidden;
    out.return_value_pointer = value.return_value_pointer;
    out.structure_argument = value.structure_argument;
    out.array_argument = value.array_argument;
    out.unused = value.unused;
    out.swift_self = value.swift_self;
    return out;
}
MicrocodeLocationPart decode(const IdaxMicrocodeLocationPart &value, Budget &budget,
                             unsigned depth) {
    budget.enter(depth);
    MicrocodeLocationPart out;
    out.kind = enum_value<MicrocodeValueLocationKind>(value.kind);
    out.register_id = value.register_id;
    out.second_register_id = value.second_register_id;
    out.register_offset = value.register_offset;
    out.register_relative_offset = value.register_relative_offset;
    out.stack_offset = value.stack_offset;
    out.static_address = value.static_address;
    out.byte_offset = value.byte_offset;
    out.byte_size = value.byte_size;
    return out;
}
MicrocodeValueLocation decode(const IdaxMicrocodeValueLocation &value, Budget &budget,
                              unsigned depth) {
    budget.enter(depth);
    MicrocodeValueLocation out;
    out.kind = enum_value<MicrocodeValueLocationKind>(value.kind);
    out.register_id = value.register_id;
    out.second_register_id = value.second_register_id;
    out.register_offset = value.register_offset;
    out.register_relative_offset = value.register_relative_offset;
    out.stack_offset = value.stack_offset;
    out.static_address = value.static_address;
    check_array(value.scattered_parts, value.scattered_part_count);
    out.scattered_parts.reserve(value.scattered_part_count);
    for (size_t i = 0; i < value.scattered_part_count; ++i)
        out.scattered_parts.push_back(decode(value.scattered_parts[i], budget, depth + 1));
    return out;
}
MicrocodeOperand decode(const IdaxMicrocodeOperand &value, Budget &budget, unsigned depth) {
    budget.enter(depth);
    MicrocodeOperand out;
    out.kind = enum_value<MicrocodeOperandKind>(value.kind);
    out.register_id = value.register_id;
    out.processor_register_id = value.processor_register_id;
    out.local_variable_index = value.local_variable_index;
    out.local_variable_offset = value.local_variable_offset;
    out.second_register_id = value.second_register_id;
    out.global_address = value.global_address;
    out.stack_offset = value.stack_offset;
    out.helper_name = value.helper_name ? value.helper_name : "";
    out.block_index = value.block_index;
    if (value.nested_instruction)
        out.nested_instruction = std::make_shared<MicrocodeInstruction>(
            decode(*value.nested_instruction, budget, depth + 1));
    out.unsigned_immediate = value.unsigned_immediate;
    out.signed_immediate = value.signed_immediate;
    out.byte_width = value.byte_width;
    out.mark_user_defined_type = value.mark_user_defined_type;
    if (value.referenced_operand)
        out.referenced_operand = std::make_shared<MicrocodeOperand>(
            decode(*value.referenced_operand, budget, depth + 1));
    check_array(value.call_arguments, value.call_argument_count);
    out.call_arguments.reserve(value.call_argument_count);
    for (size_t i = 0; i < value.call_argument_count; ++i)
        out.call_arguments.push_back(decode(value.call_arguments[i], budget, depth + 1));
    out.call_target = value.call_target;
    out.text = value.text ? value.text : "";
    out.string_constant = value.string_constant ? value.string_constant : "";
    if (value.has_floating_point_constant)
        out.floating_point_constant = value.floating_point_constant;
    out.global_name = value.global_name ? value.global_name : "";
    if (value.has_value_number)
        out.value_number = value.value_number;
    check_array(value.call_argument_properties, value.call_argument_property_count);
    out.call_argument_properties.reserve(value.call_argument_property_count);
    for (size_t i = 0; i < value.call_argument_property_count; ++i)
        out.call_argument_properties.push_back(
            decode(value.call_argument_properties[i], budget, depth + 1));
    check_array(value.call_return_operands, value.call_return_operand_count);
    out.call_return_operands.reserve(value.call_return_operand_count);
    for (size_t i = 0; i < value.call_return_operand_count; ++i)
        out.call_return_operands.push_back(
            decode(value.call_return_operands[i], budget, depth + 1));
    check_array(value.call_return_registers, value.call_return_register_count);
    out.call_return_registers.reserve(value.call_return_register_count);
    for (size_t i = 0; i < value.call_return_register_count; ++i)
        out.call_return_registers.push_back(
            decode(value.call_return_registers[i], budget, depth + 1));
    check_array(value.switch_cases, value.switch_case_count);
    out.switch_cases.reserve(value.switch_case_count);
    for (size_t i = 0; i < value.switch_case_count; ++i)
        out.switch_cases.push_back(decode(value.switch_cases[i], budget, depth + 1));
    if (value.has_switch_default_target)
        out.switch_default_target = value.switch_default_target;
    return out;
}
MicrocodeInstruction decode(const IdaxMicrocodeInstruction &value, Budget &budget, unsigned depth) {
    budget.enter(depth);
    MicrocodeInstruction out;
    out.opcode = enum_value<MicrocodeOpcode>(value.opcode);
    out.left = decode(value.left, budget, depth + 1);
    out.right = decode(value.right, budget, depth + 1);
    out.destination = decode(value.destination, budget, depth + 1);
    out.floating_point_instruction = value.floating_point_instruction;
    out.modifies_destination = value.modifies_destination;
    out.address = value.address;
    out.text = value.text ? value.text : "";
    return out;
}
MicrocodeValue decode(const IdaxSwiftMicrocodeValue &value, Budget &budget, unsigned depth) {
    budget.enter(depth);
    MicrocodeValue out;
    out.kind = enum_value<MicrocodeValueKind>(value.kind);
    out.register_id = value.register_id;
    out.local_variable_index = value.local_variable_index;
    out.local_variable_offset = value.local_variable_offset;
    out.second_register_id = value.second_register_id;
    out.global_address = value.global_address;
    out.stack_offset = value.stack_offset;
    out.helper_name = value.helper_name ? value.helper_name : "";
    out.block_index = value.block_index;
    if (value.nested_instruction)
        out.nested_instruction = std::make_shared<MicrocodeInstruction>(
            decode(*value.nested_instruction, budget, depth + 1));
    out.unsigned_immediate = value.unsigned_immediate;
    out.signed_immediate = value.signed_immediate;
    out.floating_immediate = value.floating_immediate;
    out.byte_width = value.byte_width;
    out.unsigned_integer = value.unsigned_integer;
    out.vector_element_byte_width = value.vector_element_byte_width;
    out.vector_element_count = value.vector_element_count;
    out.vector_elements_unsigned = value.vector_elements_unsigned;
    out.vector_elements_floating = value.vector_elements_floating;
    out.type_declaration = value.type_declaration ? value.type_declaration : "";
    out.argument_name = value.argument_name ? value.argument_name : "";
    out.argument_flags = value.argument_flags;
    out.location = decode(value.location, budget, depth + 1);
    return out;
}
MicrocodeMemoryRange decode(const IdaxSwiftMicrocodeMemoryRange &value, Budget &budget,
                            unsigned depth) {
    budget.enter(depth);
    MicrocodeMemoryRange out;
    out.address = value.address;
    out.byte_size = value.byte_size;
    return out;
}
MicrocodeCallOptions decode(const IdaxSwiftMicrocodeCallOptions &value, Budget &budget,
                            unsigned depth) {
    budget.enter(depth);
    MicrocodeCallOptions out;
    if (value.has_insert_policy)
        out.insert_policy = enum_value<MicrocodeInsertPolicy>(value.insert_policy);
    if (value.has_callee_address)
        out.callee_address = value.callee_address;
    if (value.has_solid_argument_count)
        out.solid_argument_count = value.solid_argument_count;
    if (value.has_call_stack_pointer_delta)
        out.call_stack_pointer_delta = value.call_stack_pointer_delta;
    if (value.has_stack_arguments_top)
        out.stack_arguments_top = value.stack_arguments_top;
    if (value.has_function_role)
        out.function_role = enum_value<MicrocodeFunctionRole>(value.function_role);
    if (value.has_return_location)
        out.return_location = decode(value.return_location, budget, depth + 1);
    out.return_type_declaration =
        value.return_type_declaration ? value.return_type_declaration : "";
    out.calling_convention = enum_value<MicrocodeCallingConvention>(value.calling_convention);
    out.mark_final = value.mark_final;
    out.mark_propagated = value.mark_propagated;
    out.mark_dead_return_registers = value.mark_dead_return_registers;
    out.mark_no_return = value.mark_no_return;
    out.mark_pure = value.mark_pure;
    out.mark_no_side_effects = value.mark_no_side_effects;
    out.mark_spoiled_lists_optimized = value.mark_spoiled_lists_optimized;
    out.mark_synthetic_has_call = value.mark_synthetic_has_call;
    out.mark_has_format_string = value.mark_has_format_string;
    if (value.has_auto_stack_start_offset)
        out.auto_stack_start_offset = value.auto_stack_start_offset;
    if (value.has_auto_stack_alignment)
        out.auto_stack_alignment = value.auto_stack_alignment;
    out.auto_stack_argument_locations = value.auto_stack_argument_locations;
    out.mark_explicit_locations = value.mark_explicit_locations;
    check_array(value.return_registers, value.return_registers_count);
    out.return_registers.reserve(value.return_registers_count);
    for (size_t i = 0; i < value.return_registers_count; ++i)
        out.return_registers.push_back(decode(value.return_registers[i], budget, depth + 1));
    check_array(value.spoiled_registers, value.spoiled_registers_count);
    out.spoiled_registers.reserve(value.spoiled_registers_count);
    for (size_t i = 0; i < value.spoiled_registers_count; ++i)
        out.spoiled_registers.push_back(decode(value.spoiled_registers[i], budget, depth + 1));
    check_array(value.passthrough_registers, value.passthrough_registers_count);
    out.passthrough_registers.reserve(value.passthrough_registers_count);
    for (size_t i = 0; i < value.passthrough_registers_count; ++i)
        out.passthrough_registers.push_back(
            decode(value.passthrough_registers[i], budget, depth + 1));
    check_array(value.dead_registers, value.dead_registers_count);
    out.dead_registers.reserve(value.dead_registers_count);
    for (size_t i = 0; i < value.dead_registers_count; ++i)
        out.dead_registers.push_back(decode(value.dead_registers[i], budget, depth + 1));
    check_array(value.visible_memory_ranges, value.visible_memory_ranges_count);
    out.visible_memory_ranges.reserve(value.visible_memory_ranges_count);
    for (size_t i = 0; i < value.visible_memory_ranges_count; ++i)
        out.visible_memory_ranges.push_back(
            decode(value.visible_memory_ranges[i], budget, depth + 1));
    out.visible_memory_all = value.visible_memory_all;
    return out;
}
struct ContextLease {
    std::atomic<unsigned> references{1};
    const MicrocodeContext *context;
    bool mutable_context;
    bool active{true};
};
thread_local unsigned filter_callback_depth{};
struct CallbackOwner {
    IdaxSwiftCallbacks callbacks;
    explicit CallbackOwner(IdaxSwiftCallbacks value) : callbacks(value) {}
    CallbackOwner(CallbackOwner &&other) noexcept : callbacks(std::exchange(other.callbacks, {})) {}
    ~CallbackOwner() {
        if (callbacks.destroy)
            callbacks.destroy(callbacks.context);
    }
};
struct Filter : MicrocodeFilter {
    CallbackOwner owner;
    explicit Filter(CallbackOwner &&value) : owner(std::move(value)) {
        idax_swift_decompiler_dependency_acquire();
    }
    ~Filter() override { idax_swift_decompiler_dependency_release(); }
    int invoke(const MicrocodeContext &context, bool mutable_context, int fallback) noexcept {
        try {
            IdaxSwiftError error{};
            struct ErrorScope {
                IdaxSwiftError &error;
                ~ErrorScope() { idax_swift_error_free(&error); }
            } error_scope{error};
            if (idax_swift_runtime_begin_activity(&error))
                return fallback;
            struct Activity {
                ~Activity() { idax_swift_runtime_end_activity(); }
            } activity;
            auto *lease = new ContextLease{{1}, &context, mutable_context};
            struct Scope {
                ContextLease *lease;
                Scope(ContextLease *value) : lease(value) { ++filter_callback_depth; }
                ~Scope() {
                    lease->active = false;
                    idax_swift_microcode_lease_release(lease);
                    --filter_callback_depth;
                }
            } scope(lease);
            IdaxSwiftNotification notification{};
            notification.phase = mutable_context ? 1 : 0;
            notification.lease = lease;
            notification.text = notification.secondary_text = notification.name = "";
            IdaxSwiftReply reply{};
            struct ReplyScope {
                IdaxSwiftReply &reply;
                ~ReplyScope() { std::free(reply.text); }
            } reply_scope{reply};
            if (owner.callbacks.invoke(owner.callbacks.context, &notification, &reply, &error) == 0)
                return reply.decision;
            ida::ui::message(std::string("IDAX Swift microcode callback: ") +
                             (error.message ? error.message : "Callback failed") + "\n");
        } catch (...) {
        }
        return fallback;
    }
    bool match(const MicrocodeContext &context) override { return invoke(context, false, 0) != 0; }
    MicrocodeApplyResult apply(MicrocodeContext &context) override {
        auto value = invoke(context, true, static_cast<int>(MicrocodeApplyResult::Error));
        return value >= 0 && value <= 2 ? static_cast<MicrocodeApplyResult>(value)
                                        : MicrocodeApplyResult::Error;
    }
};
struct FilterRegistration {
    FilterToken token{};
    std::shared_ptr<Filter> filter;
    ida::Status close() {
        if (!token)
            return ida::ok();
        if (filter_callback_depth)
            return std::unexpected(ida::Error::conflict(
                "Cannot unregister a microcode filter inside a filter callback"));
        auto result = unregister_microcode_filter(token);
        if (result) {
            token = 0;
            filter.reset();
        }
        return result;
    }
};
void destroy_filter_registration(void *opaque) {
    auto *registration = static_cast<FilterRegistration *>(opaque);
    if (registration->close())
        delete registration;
    // If the SDK refuses unregistration, preserve its callback owner and token.
}
int close_filter_registration(void *opaque, IdaxSwiftError *error) {
    return status(static_cast<FilterRegistration *>(opaque)->close(), error);
}
const MicrocodeContext &checked_context(void *opaque, bool mutable_context, IdaxSwiftError *error) {
    if (require_runtime_thread(error))
        throw ida::Error::conflict("Microcode context requires the runtime thread");
    auto *lease = static_cast<ContextLease *>(opaque);
    if (!lease || !lease->active)
        throw ida::Error::conflict("Microcode callback context has expired");
    if (mutable_context && !lease->mutable_context)
        throw ida::Error::conflict("Microcode match context is read-only");
    return *lease->context;
}
MicrocodeContext &mutable_context(void *opaque, IdaxSwiftError *error) {
    return const_cast<MicrocodeContext &>(checked_context(opaque, true, error));
}
int shim_status(int rc, IdaxSwiftError *error) {
    if (!rc)
        return 0;
    idax_swift_error_set(error, idax_last_error_category(), idax_last_error_code(),
                         idax_last_error_message_only(), idax_last_error_context());
    return -1;
}
} // namespace
extern "C" {
void idax_swift_microcode_lease_retain(void *opaque) {
    if (opaque)
        ++static_cast<ContextLease *>(opaque)->references;
}
void idax_swift_microcode_lease_release(void *opaque) {
    auto *lease = static_cast<ContextLease *>(opaque);
    if (lease && --lease->references == 0)
        delete lease;
}
int idax_swift_microcode_register(IdaxSwiftCallbacks callbacks, void **output,
                                  IdaxSwiftError *error) {
    CallbackOwner pending(callbacks);
    return protect(error, [&] {
        if (output)
            *output = nullptr;
        if (require_runtime_thread(error))
            return -1;
        if (!output || !callbacks.invoke || !callbacks.destroy)
            return write_error(ida::Error::validation("Invalid microcode callback descriptor"),
                               error);
        auto registration = std::make_unique<FilterRegistration>();
        auto filter = std::make_shared<Filter>(std::move(pending));
        auto token = register_microcode_filter(filter);
        if (!token)
            return write_error(token.error(), error);
        registration->token = *token;
        registration->filter = std::move(filter);
        return idax_swift_resource_adopt(registration.release(), destroy_filter_registration,
                                         1, output, error);
    });
}
int idax_swift_microcode_registration_close(void *opaque, IdaxSwiftError *error) {
    return protect(error, [&] {
        if (require_runtime_thread(error))
            return -1;
        if (!opaque)
            return write_error(ida::Error::validation("Missing filter registration"), error);
        return idax_swift_resource_close_with(opaque, close_filter_registration, error);
    });
}
int idax_swift_microcode_registration_valid(void *opaque, int *output,
                                            IdaxSwiftError *error) {
    return idax_swift_resource_is_open(opaque, output, error);
}
void idax_swift_microcode_registration_release(void *opaque) {
    if (opaque)
        idax_swift_enqueue_release(idax_swift_resource_release, opaque);
}
int idax_swift_microcode_query(void *opaque, int query, int index, uint64_t *output,
                               IdaxSwiftError *error) {
    return protect(error, [&] {
        const auto &context = checked_context(opaque, false, error);
        if (!output)
            return write_error(ida::Error::validation("Missing microcode output"), error);
        switch (query) {
        case 0:
            *output = context.address();
            return 0;
        case 1:
            *output = context.instruction_type();
            return 0;
        case 2:
            *output = context.has_opmask();
            return 0;
        case 3:
            *output = context.is_zero_masking();
            return 0;
        case 4:
            *output = context.opmask_register_number();
            return 0;
        case 5: {
            auto result = context.local_variable_count();
            if (!result)
                return write_error(result.error(), error);
            *output = *result;
            return 0;
        }
        case 6: {
            auto result = context.block_instruction_count();
            if (!result)
                return write_error(result.error(), error);
            *output = *result;
            return 0;
        }
        case 7: {
            auto result = context.has_instruction_at_index(index);
            if (!result)
                return write_error(result.error(), error);
            *output = *result;
            return 0;
        }
        case 8: {
            auto result = context.has_last_emitted_instruction();
            if (!result)
                return write_error(result.error(), error);
            *output = *result;
            return 0;
        }
        default:
            return write_error(ida::Error::validation("Unknown microcode query"), error);
        }
    });
}
int idax_swift_microcode_instruction(void *opaque, IdaxInstruction *output, IdaxSwiftError *error) {
    return protect(error, [&] {
        const auto &context = checked_context(opaque, false, error);
        return shim_status(idax_decompiler_microcode_context_instruction(&context, output), error);
    });
}
int idax_swift_microcode_block_instruction(void *opaque, int index, int last,
                                           IdaxMicrocodeInstruction *output,
                                           IdaxSwiftError *error) {
    return protect(error, [&] {
        const auto &context = checked_context(opaque, false, error);
        return shim_status(
            last ? idax_decompiler_microcode_context_last_emitted_instruction(&context, output)
                 : idax_decompiler_microcode_context_instruction_at_index(&context, index, output),
            error);
    });
}
int idax_swift_microcode_operation(void *opaque, int operation, int a, int b, int c, int d, int e,
                                   int policy, int mark_udt, int *output, IdaxSwiftError *error) {
    return protect(error, [&] {
        auto &context = mutable_context(opaque, error);
        auto placement =
            policy < 0 ? MicrocodeInsertPolicy::Tail : enum_value<MicrocodeInsertPolicy>(policy);
        switch (operation) {
        case 0:
            return status(context.remove_last_emitted_instruction(), error);
        case 1:
            return status(context.remove_instruction_at_index(a), error);
        case 2:
            return status(
                policy < 0 ? context.emit_noop() : context.emit_noop_with_policy(placement), error);
        case 3: {
            auto result = context.load_operand_register(a);
            if (!result)
                return write_error(result.error(), error);
            if (output)
                *output = *result;
            return 0;
        }
        case 4: {
            auto result = context.load_effective_address_register(a);
            if (!result)
                return write_error(result.error(), error);
            if (output)
                *output = *result;
            return 0;
        }
        case 5: {
            auto result = context.allocate_temporary_register(a);
            if (!result)
                return write_error(result.error(), error);
            if (output)
                *output = *result;
            return 0;
        }
        case 6:
            return status(context.store_operand_register(a, b, c, mark_udt != 0), error);
        case 7:
            return status(policy < 0 ? context.emit_move_register(a, b, c, mark_udt != 0)
                                     : context.emit_move_register_with_policy(a, b, c, placement,
                                                                              mark_udt != 0),
                          error);
        case 8:
            return status(policy < 0
                              ? context.emit_load_memory_register(a, b, c, d, e, mark_udt != 0)
                              : context.emit_load_memory_register_with_policy(
                                    a, b, c, d, e, placement, mark_udt != 0),
                          error);
        case 9:
            return status(policy < 0
                              ? context.emit_store_memory_register(a, b, c, d, e, mark_udt != 0)
                              : context.emit_store_memory_register_with_policy(
                                    a, b, c, d, e, placement, mark_udt != 0),
                          error);
        default:
            return write_error(ida::Error::validation("Unknown microcode operation"), error);
        }
    });
}
int idax_swift_microcode_emit(void *opaque, const IdaxMicrocodeInstruction *instructions,
                              size_t count, int single, int policy, IdaxSwiftError *error) {
    return protect(error, [&] {
        auto &context = mutable_context(opaque, error);
        check_array(instructions, count);
        Budget budget;
        std::vector<MicrocodeInstruction> values;
        values.reserve(count);
        for (size_t i = 0; i < count; ++i)
            values.push_back(decode(instructions[i], budget, 0));
        if (single) {
            if (values.size() != 1)
                return write_error(ida::Error::validation("Expected one microcode instruction"),
                                   error);
            return status(policy < 0
                              ? context.emit_instruction(values.front())
                              : context.emit_instruction_with_policy(
                                    values.front(), enum_value<MicrocodeInsertPolicy>(policy)),
                          error);
        }
        return status(policy < 0 ? context.emit_instructions(values)
                                 : context.emit_instructions_with_policy(
                                       values, enum_value<MicrocodeInsertPolicy>(policy)),
                      error);
    });
}
int idax_swift_microcode_helper(void *opaque, const char *name,
                                const IdaxSwiftMicrocodeValue *arguments, size_t count,
                                const IdaxSwiftMicrocodeCallOptions *options, int destination_kind,
                                int destination, int destination_width, int destination_unsigned,
                                const IdaxMicrocodeOperand *operand, IdaxSwiftError *error) {
    return protect(error, [&] {
        auto &context = mutable_context(opaque, error);
        if (!name)
            return write_error(ida::Error::validation("Missing helper name"), error);
        check_array(arguments, count);
        Budget budget;
        std::vector<MicrocodeValue> values;
        values.reserve(count);
        for (size_t i = 0; i < count; ++i)
            values.push_back(decode(arguments[i], budget, 0));
        MicrocodeCallOptions call_options;
        if (options)
            call_options = decode(*options, budget, 0);
        switch (destination_kind) {
        case 4:
            return status(context.emit_helper_call(name), error);
        case 0:
            return status(
                context.emit_helper_call_with_arguments_and_options(name, values, call_options),
                error);
        case 1:
            return status(context.emit_helper_call_with_arguments_to_register_and_options(
                              name, values, destination, destination_width, destination_unsigned,
                              call_options),
                          error);
        case 2:
            if (!operand)
                return write_error(ida::Error::validation("Missing helper destination operand"),
                                   error);
            return status(
                context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    name, values, decode(*operand, budget, 0), destination_unsigned, call_options),
                error);
        case 3:
            return status(context.emit_helper_call_with_arguments_to_operand_and_options(
                              name, values, destination, destination_width, destination_unsigned,
                              call_options),
                          error);
        default:
            return write_error(ida::Error::validation("Unknown helper destination kind"), error);
        }
    });
}
}
