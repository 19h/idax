/// \file instruction_bind.cpp
/// \brief NAN bindings for ida::instruction namespace.
///
/// Exposes instruction decode, operand access, operand formatting,
/// cross-reference queries, and instruction classification to JavaScript.

#include "helpers.hpp"
#include <ida/instruction.hpp>

namespace idax_node {
namespace {

// ── Enum-to-string helpers ──────────────────────────────────────────────

const char* OperandTypeToString(ida::instruction::OperandType t) {
    switch (t) {
        case ida::instruction::OperandType::None:               return "none";
        case ida::instruction::OperandType::Register:           return "register";
        case ida::instruction::OperandType::MemoryDirect:       return "memoryDirect";
        case ida::instruction::OperandType::MemoryPhrase:       return "memoryPhrase";
        case ida::instruction::OperandType::MemoryDisplacement: return "memoryDisplacement";
        case ida::instruction::OperandType::Immediate:          return "immediate";
        case ida::instruction::OperandType::FarAddress:         return "farAddress";
        case ida::instruction::OperandType::NearAddress:        return "nearAddress";
        case ida::instruction::OperandType::ProcessorSpecific0: return "processorSpecific0";
        case ida::instruction::OperandType::ProcessorSpecific1: return "processorSpecific1";
        case ida::instruction::OperandType::ProcessorSpecific2: return "processorSpecific2";
        case ida::instruction::OperandType::ProcessorSpecific3: return "processorSpecific3";
        case ida::instruction::OperandType::ProcessorSpecific4: return "processorSpecific4";
        case ida::instruction::OperandType::ProcessorSpecific5: return "processorSpecific5";
    }
    return "unknown";
}

const char* RegisterClassToString(ida::instruction::RegisterClass rc) {
    switch (rc) {
        case ida::instruction::RegisterClass::Unknown:        return "unknown";
        case ida::instruction::RegisterClass::GeneralPurpose: return "generalPurpose";
        case ida::instruction::RegisterClass::Segment:        return "segment";
        case ida::instruction::RegisterClass::FloatingPoint:  return "floatingPoint";
        case ida::instruction::RegisterClass::Vector:         return "vector";
        case ida::instruction::RegisterClass::Mask:           return "mask";
        case ida::instruction::RegisterClass::Control:        return "control";
        case ida::instruction::RegisterClass::Debug:          return "debug";
        case ida::instruction::RegisterClass::Other:          return "other";
    }
    return "unknown";
}

/// Parse OperandFormat from a string. Returns Default on unrecognized input.
ida::instruction::OperandFormat ParseOperandFormat(const std::string& s) {
    if (s == "hex")            return ida::instruction::OperandFormat::Hex;
    if (s == "decimal")        return ida::instruction::OperandFormat::Decimal;
    if (s == "octal")          return ida::instruction::OperandFormat::Octal;
    if (s == "binary")         return ida::instruction::OperandFormat::Binary;
    if (s == "character")      return ida::instruction::OperandFormat::Character;
    if (s == "float")          return ida::instruction::OperandFormat::Float;
    if (s == "offset")         return ida::instruction::OperandFormat::Offset;
    if (s == "stackVariable")  return ida::instruction::OperandFormat::StackVariable;
    return ida::instruction::OperandFormat::Default;
}

// ── Object conversion helpers ───────────────────────────────────────────

/// Convert an Operand to a JS object.
v8::Local<v8::Object> OperandToObject(const ida::instruction::Operand& op) {
    auto isolate = v8::Isolate::GetCurrent();
    return ObjectBuilder()
        .setInt("index", op.index())
        .setStr("type", OperandTypeToString(op.type()))
        .setBool("isRegister", op.is_register())
        .setBool("isImmediate", op.is_immediate())
        .setBool("isMemory", op.is_memory())
        .setInt("registerId", static_cast<int>(op.register_id()))
        .set("value", v8::BigInt::NewFromUnsigned(isolate, op.value()))
        .setAddr("targetAddress", op.target_address())
        .set("displacement", v8::BigInt::New(isolate, op.displacement()))
        .setInt("byteWidth", op.byte_width())
        .setStr("registerName", op.register_name())
        .setStr("registerClass", RegisterClassToString(op.register_class()))
        .build();
}

/// Convert an Instruction to a JS object.
v8::Local<v8::Object> InstructionToObject(const ida::instruction::Instruction& insn) {
    auto operands = Nan::New<v8::Array>(static_cast<int>(insn.operand_count()));
    for (std::size_t i = 0; i < insn.operand_count(); ++i) {
        Nan::Set(operands, static_cast<uint32_t>(i),
                 OperandToObject(insn.operands()[i]));
    }

    return ObjectBuilder()
        .setAddr("address", insn.address())
        .setAddressSize("size", insn.size())
        .setInt("opcode", static_cast<int>(insn.opcode()))
        .setStr("mnemonic", insn.mnemonic())
        .setInt("operandCount", static_cast<int>(insn.operand_count()))
        .set("operands", operands)
        .build();
}

// ── NAN method implementations ──────────────────────────────────────────

// decode(address) -> instruction object
NAN_METHOD(Decode) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto insn, ida::instruction::decode(addr));
    info.GetReturnValue().Set(InstructionToObject(insn));
}

// create(address) -> instruction object
NAN_METHOD(Create) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto insn, ida::instruction::create(addr));
    info.GetReturnValue().Set(InstructionToObject(insn));
}

// text(address) -> string
NAN_METHOD(Text) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto txt, ida::instruction::text(addr));
    info.GetReturnValue().Set(FromString(txt));
}

// ── Operand format setters ──────────────────────────────────────────────

NAN_METHOD(SetOperandHex) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_hex(addr, n));
}

NAN_METHOD(SetOperandDecimal) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_decimal(addr, n));
}

NAN_METHOD(SetOperandOctal) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_octal(addr, n));
}

NAN_METHOD(SetOperandBinary) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_binary(addr, n));
}

NAN_METHOD(SetOperandCharacter) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_character(addr, n));
}

NAN_METHOD(SetOperandFloat) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_float(addr, n));
}

// setOperandFormat(address, n, format, base?)
NAN_METHOD(SetOperandFormat) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    std::string fmtStr;
    if (!GetStringArg(info, 2, fmtStr)) return;
    auto fmt = ParseOperandFormat(fmtStr);

    ida::Address base = GetOptionalAddress(info, 3, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_format(addr, n, fmt, base));
}

// setOperandOffset(address, n, base?)
NAN_METHOD(SetOperandOffset) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    ida::Address base = GetOptionalAddress(info, 2, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_offset(addr, n, base));
}

// setOperandStructOffset(address, n, structName_or_structId, delta?)
// Overloaded: if arg 2 is string → by name, if number/BigInt → by id
NAN_METHOD(SetOperandStructOffset) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    if (info.Length() < 3 || info[2]->IsUndefined()) {
        Nan::ThrowTypeError("Missing structName or structId argument");
        return;
    }

    ida::AddressDelta delta = GetOptionalInt64(info, 3, 0);

    if (info[2]->IsString()) {
        std::string structName = ToString(info[2]);
        IDAX_CHECK_STATUS(
            ida::instruction::set_operand_struct_offset(addr, n, structName, delta));
    } else {
        // Treat as numeric structure id (BigInt or number)
        ida::Address structId;
        if (!ToAddress(info[2], structId)) {
            Nan::ThrowTypeError("Expected structName (string) or structId (number/BigInt)");
            return;
        }
        IDAX_CHECK_STATUS(
            ida::instruction::set_operand_struct_offset(addr, n, static_cast<std::uint64_t>(structId), delta));
    }
}

// setOperandBasedStructOffset(address, n, operandValue, base)
NAN_METHOD(SetOperandBasedStructOffset) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    ida::Address operandValue;
    if (!GetAddressArg(info, 2, operandValue)) return;
    ida::Address base;
    if (!GetAddressArg(info, 3, base)) return;

    IDAX_CHECK_STATUS(
        ida::instruction::set_operand_based_struct_offset(addr, n, operandValue, base));
}

// operandStructOffsetPath(address, n) -> { structureIds: BigInt[], delta: BigInt }
NAN_METHOD(OperandStructOffsetPath) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto path, ida::instruction::operand_struct_offset_path(addr, n));

    auto isolate = v8::Isolate::GetCurrent();
    auto idsArr = Nan::New<v8::Array>(static_cast<int>(path.structure_ids.size()));
    for (std::size_t i = 0; i < path.structure_ids.size(); ++i) {
        Nan::Set(idsArr, static_cast<uint32_t>(i),
                 v8::BigInt::NewFromUnsigned(isolate, path.structure_ids[i]));
    }

    auto result = ObjectBuilder()
        .set("structureIds", idsArr)
        .set("delta", FromAddressDelta(path.delta))
        .build();
    info.GetReturnValue().Set(result);
}

// operandStructOffsetPathNames(address, n) -> string[]
NAN_METHOD(OperandStructOffsetPathNames) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto names, ida::instruction::operand_struct_offset_path_names(addr, n));
    info.GetReturnValue().Set(StringVectorToArray(names));
}

// setOperandStackVariable(address, n)
NAN_METHOD(SetOperandStackVariable) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::set_operand_stack_variable(addr, n));
}

// clearOperandRepresentation(address, n)
NAN_METHOD(ClearOperandRepresentation) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::clear_operand_representation(addr, n));
}

// setForcedOperand(address, n, text)
NAN_METHOD(SetForcedOperand) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    std::string text;
    if (!GetStringArg(info, 2, text)) return;

    IDAX_CHECK_STATUS(ida::instruction::set_forced_operand(addr, n, text));
}

// getForcedOperand(address, n) -> string
NAN_METHOD(GetForcedOperand) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto text, ida::instruction::get_forced_operand(addr, n));
    info.GetReturnValue().Set(FromString(text));
}

// operandText(address, n) -> string
NAN_METHOD(OperandText) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto text, ida::instruction::operand_text(addr, n));
    info.GetReturnValue().Set(FromString(text));
}

// operandByteWidth(address, n) -> number
NAN_METHOD(OperandByteWidth) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto width, ida::instruction::operand_byte_width(addr, n));
    info.GetReturnValue().Set(Nan::New(width));
}

// operandRegisterName(address, n) -> string
NAN_METHOD(OperandRegisterName) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto name, ida::instruction::operand_register_name(addr, n));
    info.GetReturnValue().Set(FromString(name));
}

// operandRegisterClass(address, n) -> string
NAN_METHOD(OperandRegisterClass) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);

    IDAX_UNWRAP(auto rc, ida::instruction::operand_register_class(addr, n));
    info.GetReturnValue().Set(FromString(RegisterClassToString(rc)));
}

// toggleOperandSign(address, n)
NAN_METHOD(ToggleOperandSign) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::toggle_operand_sign(addr, n));
}

// toggleOperandNegate(address, n)
NAN_METHOD(ToggleOperandNegate) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    int n = GetOptionalInt(info, 1, 0);
    IDAX_CHECK_STATUS(ida::instruction::toggle_operand_negate(addr, n));
}

// ── Cross-reference helpers ─────────────────────────────────────────────

// codeRefsFrom(address) -> BigInt[]
NAN_METHOD(CodeRefsFrom) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::instruction::code_refs_from(addr));
    info.GetReturnValue().Set(AddressVectorToArray(refs));
}

// dataRefsFrom(address) -> BigInt[]
NAN_METHOD(DataRefsFrom) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto refs, ida::instruction::data_refs_from(addr));
    info.GetReturnValue().Set(AddressVectorToArray(refs));
}

// callTargets(address) -> BigInt[]
NAN_METHOD(CallTargets) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto targets, ida::instruction::call_targets(addr));
    info.GetReturnValue().Set(AddressVectorToArray(targets));
}

// jumpTargets(address) -> BigInt[]
NAN_METHOD(JumpTargets) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto targets, ida::instruction::jump_targets(addr));
    info.GetReturnValue().Set(AddressVectorToArray(targets));
}

// ── Instruction classification predicates ───────────────────────────────

NAN_METHOD(HasFallThrough) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    info.GetReturnValue().Set(Nan::New(ida::instruction::has_fall_through(addr)));
}

NAN_METHOD(IsCall) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    info.GetReturnValue().Set(Nan::New(ida::instruction::is_call(addr)));
}

NAN_METHOD(IsReturn) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    info.GetReturnValue().Set(Nan::New(ida::instruction::is_return(addr)));
}

NAN_METHOD(IsJump) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    info.GetReturnValue().Set(Nan::New(ida::instruction::is_jump(addr)));
}

NAN_METHOD(IsConditionalJump) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;
    info.GetReturnValue().Set(Nan::New(ida::instruction::is_conditional_jump(addr)));
}

// ── Sequential navigation ───────────────────────────────────────────────

// next(address) -> instruction object
NAN_METHOD(Next) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto insn, ida::instruction::next(addr));
    info.GetReturnValue().Set(InstructionToObject(insn));
}

// prev(address) -> instruction object
NAN_METHOD(Prev) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto insn, ida::instruction::prev(addr));
    info.GetReturnValue().Set(InstructionToObject(insn));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitInstruction(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "instruction");

    // Decode / create
    SetMethod(ns, "decode",  Decode);
    SetMethod(ns, "create",  Create);
    SetMethod(ns, "text",    Text);

    // Operand format setters
    SetMethod(ns, "setOperandHex",       SetOperandHex);
    SetMethod(ns, "setOperandDecimal",   SetOperandDecimal);
    SetMethod(ns, "setOperandOctal",     SetOperandOctal);
    SetMethod(ns, "setOperandBinary",    SetOperandBinary);
    SetMethod(ns, "setOperandCharacter", SetOperandCharacter);
    SetMethod(ns, "setOperandFloat",     SetOperandFloat);
    SetMethod(ns, "setOperandFormat",    SetOperandFormat);
    SetMethod(ns, "setOperandOffset",    SetOperandOffset);

    // Struct offset operations
    SetMethod(ns, "setOperandStructOffset",      SetOperandStructOffset);
    SetMethod(ns, "setOperandBasedStructOffset", SetOperandBasedStructOffset);
    SetMethod(ns, "operandStructOffsetPath",      OperandStructOffsetPath);
    SetMethod(ns, "operandStructOffsetPathNames", OperandStructOffsetPathNames);

    // Stack variable / clear / forced
    SetMethod(ns, "setOperandStackVariable",    SetOperandStackVariable);
    SetMethod(ns, "clearOperandRepresentation", ClearOperandRepresentation);
    SetMethod(ns, "setForcedOperand",           SetForcedOperand);
    SetMethod(ns, "getForcedOperand",           GetForcedOperand);

    // Operand queries
    SetMethod(ns, "operandText",          OperandText);
    SetMethod(ns, "operandByteWidth",     OperandByteWidth);
    SetMethod(ns, "operandRegisterName",  OperandRegisterName);
    SetMethod(ns, "operandRegisterClass", OperandRegisterClass);

    // Operand display toggles
    SetMethod(ns, "toggleOperandSign",   ToggleOperandSign);
    SetMethod(ns, "toggleOperandNegate", ToggleOperandNegate);

    // Cross-references
    SetMethod(ns, "codeRefsFrom",  CodeRefsFrom);
    SetMethod(ns, "dataRefsFrom",  DataRefsFrom);
    SetMethod(ns, "callTargets",   CallTargets);
    SetMethod(ns, "jumpTargets",   JumpTargets);

    // Classification predicates
    SetMethod(ns, "hasFallThrough",     HasFallThrough);
    SetMethod(ns, "isCall",             IsCall);
    SetMethod(ns, "isReturn",           IsReturn);
    SetMethod(ns, "isJump",             IsJump);
    SetMethod(ns, "isConditionalJump",  IsConditionalJump);

    // Sequential navigation
    SetMethod(ns, "next", Next);
    SetMethod(ns, "prev", Prev);
}

} // namespace idax_node
