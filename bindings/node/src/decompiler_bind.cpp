/// \file decompiler_bind.cpp
/// \brief NAN bindings for ida::decompiler — Hex-Rays decompilation, pseudocode
///        access, variable manipulation, address mapping, and event subscriptions.

#include "helpers.hpp"
#include <ida/decompiler.hpp>
#include <ida/instruction.hpp>
#include <ida/type.hpp>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace idax_node {
namespace {

// ── VariableStorage enum -> string ──────────────────────────────────────

static const char* StorageToString(ida::decompiler::VariableStorage storage) {
    switch (storage) {
        case ida::decompiler::VariableStorage::Unknown:  return "unknown";
        case ida::decompiler::VariableStorage::Register: return "register";
        case ida::decompiler::VariableStorage::Stack:    return "stack";
    }
    return "unknown";
}

// ── LocalVariable -> JS object ──────────────────────────────────────────

static v8::Local<v8::Object> VariableToJS(const ida::decompiler::LocalVariable& var) {
    return ObjectBuilder()
        .setStr("name",         var.name)
        .setStr("typeName",     var.type_name)
        .setBool("isArgument",  var.is_argument)
        .setInt("width",        var.width)
        .setBool("hasUserName", var.has_user_name)
        .setBool("hasNiceName", var.has_nice_name)
        .setStr("storage",      StorageToString(var.storage))
        .setStr("comment",      var.comment)
        .build();
}

// ── AddressMapping -> JS object ─────────────────────────────────────────

static v8::Local<v8::Object> AddressMappingToJS(const ida::decompiler::AddressMapping& m) {
    return ObjectBuilder()
        .setAddr("address",    m.address)
        .setInt("lineNumber",  m.line_number)
        .build();
}

// ── Instruction -> JS object (for MicrocodeContext::instruction) ────────

static const char* InstructionOperandTypeToString(ida::instruction::OperandType type) {
    switch (type) {
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

static const char* InstructionRegisterCategoryToString(ida::instruction::RegisterCategory category) {
    switch (category) {
        case ida::instruction::RegisterCategory::Unknown:        return "unknown";
        case ida::instruction::RegisterCategory::GeneralPurpose: return "generalPurpose";
        case ida::instruction::RegisterCategory::Segment:        return "segment";
        case ida::instruction::RegisterCategory::FloatingPoint:  return "floatingPoint";
        case ida::instruction::RegisterCategory::Vector:         return "vector";
        case ida::instruction::RegisterCategory::Mask:           return "mask";
        case ida::instruction::RegisterCategory::Control:        return "control";
        case ida::instruction::RegisterCategory::Debug:          return "debug";
        case ida::instruction::RegisterCategory::Other:          return "other";
    }
    return "unknown";
}

static v8::Local<v8::Object> InstructionOperandToJS(const ida::instruction::Operand& operand) {
    auto isolate = v8::Isolate::GetCurrent();
    return ObjectBuilder()
        .setInt("index", operand.index())
        .setStr("type", InstructionOperandTypeToString(operand.type()))
        .setBool("isRegister", operand.is_register())
        .setBool("isImmediate", operand.is_immediate())
        .setBool("isMemory", operand.is_memory())
        .setInt("registerId", static_cast<int>(operand.register_id()))
        .set("value", v8::BigInt::NewFromUnsigned(isolate, operand.value()))
        .setAddr("targetAddress", operand.target_address())
        .set("displacement", v8::BigInt::New(isolate, operand.displacement()))
        .setInt("byteWidth", operand.byte_width())
        .setStr("registerName", operand.register_name())
        .setStr("registerCategory", InstructionRegisterCategoryToString(operand.register_category()))
        .build();
}

static v8::Local<v8::Object> InstructionToJS(const ida::instruction::Instruction& instruction) {
    auto operands = Nan::New<v8::Array>(static_cast<int>(instruction.operand_count()));
    for (std::size_t i = 0; i < instruction.operand_count(); ++i) {
        Nan::Set(operands,
                 static_cast<uint32_t>(i),
                 InstructionOperandToJS(instruction.operands()[i]));
    }

    return ObjectBuilder()
        .setAddr("address", instruction.address())
        .setAddressSize("size", instruction.size())
        .setInt("opcode", static_cast<int>(instruction.opcode()))
        .setStr("mnemonic", instruction.mnemonic())
        .setInt("operandCount", static_cast<int>(instruction.operand_count()))
        .set("operands", operands)
        .build();
}

// ── Typed microcode model -> JS object ───────────────────────────────────

static const char* MicrocodeOpcodeToString(ida::decompiler::MicrocodeOpcode opcode) {
    switch (opcode) {
        case ida::decompiler::MicrocodeOpcode::NoOperation:          return "noOperation";
        case ida::decompiler::MicrocodeOpcode::Move:                 return "move";
        case ida::decompiler::MicrocodeOpcode::Add:                  return "add";
        case ida::decompiler::MicrocodeOpcode::Subtract:             return "subtract";
        case ida::decompiler::MicrocodeOpcode::Multiply:             return "multiply";
        case ida::decompiler::MicrocodeOpcode::ZeroExtend:           return "zeroExtend";
        case ida::decompiler::MicrocodeOpcode::LoadMemory:           return "loadMemory";
        case ida::decompiler::MicrocodeOpcode::StoreMemory:          return "storeMemory";
        case ida::decompiler::MicrocodeOpcode::BitwiseOr:            return "bitwiseOr";
        case ida::decompiler::MicrocodeOpcode::BitwiseAnd:           return "bitwiseAnd";
        case ida::decompiler::MicrocodeOpcode::BitwiseXor:           return "bitwiseXor";
        case ida::decompiler::MicrocodeOpcode::ShiftLeft:            return "shiftLeft";
        case ida::decompiler::MicrocodeOpcode::ShiftRightLogical:    return "shiftRightLogical";
        case ida::decompiler::MicrocodeOpcode::ShiftRightArithmetic: return "shiftRightArithmetic";
        case ida::decompiler::MicrocodeOpcode::FloatAdd:             return "floatAdd";
        case ida::decompiler::MicrocodeOpcode::FloatSub:             return "floatSub";
        case ida::decompiler::MicrocodeOpcode::FloatMul:             return "floatMul";
        case ida::decompiler::MicrocodeOpcode::FloatDiv:             return "floatDiv";
        case ida::decompiler::MicrocodeOpcode::IntegerToFloat:       return "integerToFloat";
        case ida::decompiler::MicrocodeOpcode::FloatToFloat:         return "floatToFloat";
    }
    return "unknown";
}

static const char* MicrocodeOperandKindToString(ida::decompiler::MicrocodeOperandKind kind) {
    switch (kind) {
        case ida::decompiler::MicrocodeOperandKind::Empty:             return "empty";
        case ida::decompiler::MicrocodeOperandKind::Register:          return "register";
        case ida::decompiler::MicrocodeOperandKind::LocalVariable:     return "localVariable";
        case ida::decompiler::MicrocodeOperandKind::RegisterPair:      return "registerPair";
        case ida::decompiler::MicrocodeOperandKind::GlobalAddress:     return "globalAddress";
        case ida::decompiler::MicrocodeOperandKind::StackVariable:     return "stackVariable";
        case ida::decompiler::MicrocodeOperandKind::HelperReference:   return "helperReference";
        case ida::decompiler::MicrocodeOperandKind::BlockReference:    return "blockReference";
        case ida::decompiler::MicrocodeOperandKind::NestedInstruction: return "nestedInstruction";
        case ida::decompiler::MicrocodeOperandKind::UnsignedImmediate: return "unsignedImmediate";
        case ida::decompiler::MicrocodeOperandKind::SignedImmediate:   return "signedImmediate";
    }
    return "unknown";
}

static v8::Local<v8::Object> MicrocodeInstructionToJS(const ida::decompiler::MicrocodeInstruction& instruction);

static v8::Local<v8::Object> MicrocodeOperandToJS(const ida::decompiler::MicrocodeOperand& operand) {
    auto isolate = v8::Isolate::GetCurrent();
    auto object = ObjectBuilder()
        .setStr("kind", MicrocodeOperandKindToString(operand.kind))
        .setInt("registerId", operand.register_id)
        .setInt("localVariableIndex", operand.local_variable_index)
        .set("localVariableOffset", v8::BigInt::New(isolate, operand.local_variable_offset))
        .setInt("secondRegisterId", operand.second_register_id)
        .setAddr("globalAddress", operand.global_address)
        .set("stackOffset", v8::BigInt::New(isolate, operand.stack_offset))
        .setStr("helperName", operand.helper_name)
        .setInt("blockIndex", operand.block_index)
        .set("unsignedImmediate", v8::BigInt::NewFromUnsigned(isolate, operand.unsigned_immediate))
        .set("signedImmediate", v8::BigInt::New(isolate, operand.signed_immediate))
        .setInt("byteWidth", operand.byte_width)
        .setBool("markUserDefinedType", operand.mark_user_defined_type);

    if (operand.nested_instruction != nullptr)
        object.set("nestedInstruction", MicrocodeInstructionToJS(*operand.nested_instruction));
    else
        object.setNull("nestedInstruction");

    return object.build();
}

static v8::Local<v8::Object> MicrocodeInstructionToJS(const ida::decompiler::MicrocodeInstruction& instruction) {
    return ObjectBuilder()
        .setStr("opcode", MicrocodeOpcodeToString(instruction.opcode))
        .set("left", MicrocodeOperandToJS(instruction.left))
        .set("right", MicrocodeOperandToJS(instruction.right))
        .set("destination", MicrocodeOperandToJS(instruction.destination))
        .setBool("floatingPointInstruction", instruction.floating_point_instruction)
        .build();
}

// ════════════════════════════════════════════════════════════════════════
// MicrocodeContextWrapper — ephemeral Nan::ObjectWrap for filter callbacks
// ════════════════════════════════════════════════════════════════════════

class MicrocodeContextWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init) {
        auto tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(FromString("MicrocodeContext"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        Nan::SetPrototypeMethod(tpl, "address", Address);
        Nan::SetPrototypeMethod(tpl, "instructionType", InstructionType);
        Nan::SetPrototypeMethod(tpl, "blockInstructionCount", BlockInstructionCount);
        Nan::SetPrototypeMethod(tpl, "hasInstructionAtIndex", HasInstructionAtIndex);
        Nan::SetPrototypeMethod(tpl, "instruction", Instruction);
        Nan::SetPrototypeMethod(tpl, "instructionAtIndex", InstructionAtIndex);
        Nan::SetPrototypeMethod(tpl, "hasLastEmittedInstruction", HasLastEmittedInstruction);
        Nan::SetPrototypeMethod(tpl, "lastEmittedInstruction", LastEmittedInstruction);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    }

    static v8::Local<v8::Object> NewInstance(ida::decompiler::MicrocodeContext* context) {
        Nan::EscapableHandleScope scope;
        auto cons = Nan::New(constructor());
        v8::Local<v8::Value> argv[] = {
            v8::External::New(v8::Isolate::GetCurrent(), context),
        };
        auto instance = Nan::NewInstance(cons, 1, argv).ToLocalChecked();
        return scope.Escape(instance);
    }

    static void Invalidate(v8::Local<v8::Object> object) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(object);
        if (wrapper != nullptr)
            wrapper->invalidate();
    }

private:
    explicit MicrocodeContextWrapper(ida::decompiler::MicrocodeContext* context)
        : context_(context) {}

    static bool EnsureValid(MicrocodeContextWrapper* wrapper) {
        if (wrapper != nullptr && wrapper->valid_ && wrapper->context_ != nullptr)
            return true;
        Nan::ThrowError("MicrocodeContext is only valid during filter callback execution");
        return false;
    }

    void invalidate() {
        valid_ = false;
        context_ = nullptr;
    }

    static NAN_METHOD(New) {
        if (!info.IsConstructCall()) {
            Nan::ThrowError("MicrocodeContext must be called with new");
            return;
        }
        if (info.Length() < 1 || !info[0]->IsExternal()) {
            Nan::ThrowTypeError("Internal MicrocodeContext constructor misuse");
            return;
        }

        auto* context = static_cast<ida::decompiler::MicrocodeContext*>(
            info[0].As<v8::External>()->Value());
        auto* wrapper = new MicrocodeContextWrapper(context);
        wrapper->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(Address) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;
        info.GetReturnValue().Set(FromAddress(wrapper->context_->address()));
    }

    static NAN_METHOD(InstructionType) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;
        info.GetReturnValue().Set(Nan::New(wrapper->context_->instruction_type()));
    }

    static NAN_METHOD(BlockInstructionCount) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;
        IDAX_UNWRAP(auto count, wrapper->context_->block_instruction_count());
        info.GetReturnValue().Set(Nan::New(count));
    }

    static NAN_METHOD(HasInstructionAtIndex) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;
        if (info.Length() < 1 || !info[0]->IsNumber()) {
            Nan::ThrowTypeError("Expected instruction index argument");
            return;
        }

        int instruction_index = Nan::To<int>(info[0]).FromJust();
        IDAX_UNWRAP(auto has_instruction,
                    wrapper->context_->has_instruction_at_index(instruction_index));
        info.GetReturnValue().Set(Nan::New(has_instruction));
    }

    static NAN_METHOD(Instruction) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;

        IDAX_UNWRAP(auto instruction, wrapper->context_->instruction());
        info.GetReturnValue().Set(InstructionToJS(instruction));
    }

    static NAN_METHOD(InstructionAtIndex) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;
        if (info.Length() < 1 || !info[0]->IsNumber()) {
            Nan::ThrowTypeError("Expected instruction index argument");
            return;
        }

        int instruction_index = Nan::To<int>(info[0]).FromJust();
        IDAX_UNWRAP(auto instruction,
                    wrapper->context_->instruction_at_index(instruction_index));
        info.GetReturnValue().Set(MicrocodeInstructionToJS(instruction));
    }

    static NAN_METHOD(HasLastEmittedInstruction) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;

        IDAX_UNWRAP(auto has_instruction, wrapper->context_->has_last_emitted_instruction());
        info.GetReturnValue().Set(Nan::New(has_instruction));
    }

    static NAN_METHOD(LastEmittedInstruction) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<MicrocodeContextWrapper>(info.Holder());
        if (!EnsureValid(wrapper))
            return;

        IDAX_UNWRAP(auto instruction, wrapper->context_->last_emitted_instruction());
        info.GetReturnValue().Set(MicrocodeInstructionToJS(instruction));
    }

    ida::decompiler::MicrocodeContext* context_{nullptr};
    bool valid_{true};

    static inline Nan::Persistent<v8::Function>& constructor() {
        static Nan::Persistent<v8::Function> ctor;
        return ctor;
    }
};

// ════════════════════════════════════════════════════════════════════════
// DecompiledFunctionWrapper — Nan::ObjectWrap around DecompiledFunction
// ════════════════════════════════════════════════════════════════════════

class DecompiledFunctionWrapper : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init) {
        auto tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(FromString("DecompiledFunction"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        // Instance methods
        Nan::SetPrototypeMethod(tpl, "pseudocode",     Pseudocode);
        Nan::SetPrototypeMethod(tpl, "lines",          Lines);
        Nan::SetPrototypeMethod(tpl, "rawLines",       RawLines);
        Nan::SetPrototypeMethod(tpl, "declaration",    Declaration);
        Nan::SetPrototypeMethod(tpl, "variableCount",  VariableCount);
        Nan::SetPrototypeMethod(tpl, "variables",      Variables);
        Nan::SetPrototypeMethod(tpl, "renameVariable", RenameVariable);
        Nan::SetPrototypeMethod(tpl, "retypeVariable", RetypeVariable);
        Nan::SetPrototypeMethod(tpl, "entryAddress",   EntryAddress);
        Nan::SetPrototypeMethod(tpl, "lineToAddress",  LineToAddress);
        Nan::SetPrototypeMethod(tpl, "addressMap",     AddressMap);
        Nan::SetPrototypeMethod(tpl, "refresh",        Refresh);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    }

    /// Create a new JS wrapper from a C++ DecompiledFunction (move semantics).
    static v8::Local<v8::Object> NewInstance(ida::decompiler::DecompiledFunction func) {
        Nan::EscapableHandleScope scope;

        // Allocate the C++ object on the heap via unique_ptr, then transfer
        // ownership to the wrapper in the New callback.
        pending_func_ = std::make_unique<ida::decompiler::DecompiledFunction>(std::move(func));

        auto cons = Nan::New(constructor());
        auto instance = Nan::NewInstance(cons, 0, nullptr).ToLocalChecked();

        return scope.Escape(instance);
    }

    static void DisposeAllLiveWrappers() {
        std::lock_guard<std::mutex> lock(live_mutex());
        for (auto* wrapper : live_wrappers()) {
            if (wrapper != nullptr)
                wrapper->func_.reset();
        }
        pending_func_.reset();
    }

private:
    explicit DecompiledFunctionWrapper(std::unique_ptr<ida::decompiler::DecompiledFunction> func)
        : func_(std::move(func)) {
        std::lock_guard<std::mutex> lock(live_mutex());
        live_wrappers().insert(this);
    }

    ~DecompiledFunctionWrapper() override {
        std::lock_guard<std::mutex> lock(live_mutex());
        live_wrappers().erase(this);
    }

    static bool EnsureAlive(DecompiledFunctionWrapper* wrapper) {
        if (wrapper != nullptr && wrapper->func_ != nullptr)
            return true;
        Nan::ThrowError("DecompiledFunction handle is no longer valid");
        return false;
    }

    ida::decompiler::DecompiledFunction& func() {
        return *func_;
    }

    // ── Constructor ─────────────────────────────────────────────────────

    static NAN_METHOD(New) {
        if (!info.IsConstructCall()) {
            Nan::ThrowError("DecompiledFunction must be called with new");
            return;
        }

        auto wrapper = new DecompiledFunctionWrapper(std::move(pending_func_));
        wrapper->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    // ── Instance methods ────────────────────────────────────────────────

    // pseudocode() -> string
    static NAN_METHOD(Pseudocode) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto text, wrapper->func().pseudocode());
        info.GetReturnValue().Set(FromString(text));
    }

    // lines() -> string[]
    static NAN_METHOD(Lines) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto lns, wrapper->func().lines());
        info.GetReturnValue().Set(StringVectorToArray(lns));
    }

    // rawLines() -> string[]
    static NAN_METHOD(RawLines) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto lns, wrapper->func().raw_lines());
        info.GetReturnValue().Set(StringVectorToArray(lns));
    }

    // declaration() -> string
    static NAN_METHOD(Declaration) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto decl, wrapper->func().declaration());
        info.GetReturnValue().Set(FromString(decl));
    }

    // variableCount() -> number
    static NAN_METHOD(VariableCount) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto count, wrapper->func().variable_count());
        info.GetReturnValue().Set(Nan::New(static_cast<double>(count)));
    }

    // variables() -> [{ name, typeName, isArgument, width, hasUserName, hasNiceName, storage, comment }]
    static NAN_METHOD(Variables) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto vars, wrapper->func().variables());

        auto arr = Nan::New<v8::Array>(static_cast<int>(vars.size()));
        for (size_t i = 0; i < vars.size(); ++i) {
            Nan::Set(arr, static_cast<uint32_t>(i), VariableToJS(vars[i]));
        }
        info.GetReturnValue().Set(arr);
    }

    // renameVariable(oldName: string, newName: string)
    static NAN_METHOD(RenameVariable) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        std::string oldName;
        if (!GetStringArg(info, 0, oldName)) return;

        std::string newName;
        if (!GetStringArg(info, 1, newName)) return;

        IDAX_CHECK_STATUS(wrapper->func().rename_variable(oldName, newName));
    }

    // retypeVariable(nameOrIndex, newType: string)
    //   - retypeVariable("varName", "int*")
    //   - retypeVariable(0, "unsigned int")
    static NAN_METHOD(RetypeVariable) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        if (info.Length() < 2) {
            Nan::ThrowTypeError("Expected (name|index, typeString) arguments");
            return;
        }

        // Parse the type string
        std::string typeStr;
        if (!GetStringArg(info, 1, typeStr)) return;

        auto typeResult = ida::type::TypeInfo::from_declaration(typeStr);
        if (!typeResult) {
            ThrowError(typeResult.error());
            return;
        }

        if (info[0]->IsString()) {
            // Retype by name
            std::string varName = ToString(info[0]);
            IDAX_CHECK_STATUS(wrapper->func().retype_variable(varName, *typeResult));
        } else if (info[0]->IsNumber()) {
            // Retype by index
            auto index = static_cast<std::size_t>(Nan::To<uint32_t>(info[0]).FromJust());
            IDAX_CHECK_STATUS(wrapper->func().retype_variable(index, *typeResult));
        } else {
            Nan::ThrowTypeError("First argument must be a variable name (string) or index (number)");
            return;
        }
    }

    // entryAddress() -> bigint
    static NAN_METHOD(EntryAddress) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        auto addr = wrapper->func().entry_address();
        info.GetReturnValue().Set(FromAddress(addr));
    }

    // lineToAddress(line: number) -> bigint
    static NAN_METHOD(LineToAddress) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;

        if (info.Length() < 1 || !info[0]->IsNumber()) {
            Nan::ThrowTypeError("Expected numeric line number argument");
            return;
        }
        int lineNumber = Nan::To<int>(info[0]).FromJust();

        IDAX_UNWRAP(auto addr, wrapper->func().line_to_address(lineNumber));
        info.GetReturnValue().Set(FromAddress(addr));
    }

    // addressMap() -> [{ address: bigint, lineNumber: number }]
    static NAN_METHOD(AddressMap) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_UNWRAP(auto mappings, wrapper->func().address_map());

        auto arr = Nan::New<v8::Array>(static_cast<int>(mappings.size()));
        for (size_t i = 0; i < mappings.size(); ++i) {
            Nan::Set(arr, static_cast<uint32_t>(i), AddressMappingToJS(mappings[i]));
        }
        info.GetReturnValue().Set(arr);
    }

    // refresh()
    static NAN_METHOD(Refresh) {
        auto* wrapper = Nan::ObjectWrap::Unwrap<DecompiledFunctionWrapper>(info.Holder());
        if (!EnsureAlive(wrapper)) return;
        IDAX_CHECK_STATUS(wrapper->func().refresh());
    }

    // ── Data members ────────────────────────────────────────────────────

    std::unique_ptr<ida::decompiler::DecompiledFunction> func_;

    // Temporary storage for transferring the DecompiledFunction into the
    // wrapper during construction. Set before Nan::NewInstance and consumed
    // inside the New callback.
    static std::unique_ptr<ida::decompiler::DecompiledFunction> pending_func_;

    static std::unordered_set<DecompiledFunctionWrapper*>& live_wrappers() {
        static std::unordered_set<DecompiledFunctionWrapper*> wrappers;
        return wrappers;
    }

    static std::mutex& live_mutex() {
        static std::mutex m;
        return m;
    }

    static inline Nan::Persistent<v8::Function>& constructor() {
        static Nan::Persistent<v8::Function> ctor;
        return ctor;
    }
};

// Static member definition
std::unique_ptr<ida::decompiler::DecompiledFunction>
    DecompiledFunctionWrapper::pending_func_ = nullptr;

// ════════════════════════════════════════════════════════════════════════
// Event subscription callback storage
// ════════════════════════════════════════════════════════════════════════
//
// We need to prevent JS callback pointers from being collected while the
// C++ subscription is alive. Store Persistent handles keyed by token.

static std::mutex g_subscriptions_mutex;
static std::unordered_map<ida::decompiler::Token, Nan::Persistent<v8::Function>*>
    g_subscriptions;

static void StoreCallback(ida::decompiler::Token token,
                          v8::Local<v8::Function> fn) {
    std::lock_guard<std::mutex> lock(g_subscriptions_mutex);
    auto* p = new Nan::Persistent<v8::Function>(fn);
    g_subscriptions[token] = p;
}

static void RemoveCallback(ida::decompiler::Token token) {
    std::lock_guard<std::mutex> lock(g_subscriptions_mutex);
    auto it = g_subscriptions.find(token);
    if (it != g_subscriptions.end()) {
        it->second->Reset();
        delete it->second;
        g_subscriptions.erase(it);
    }
}

static std::mutex g_microcode_filters_mutex;
static std::unordered_map<ida::decompiler::FilterToken,
                          std::shared_ptr<ida::decompiler::MicrocodeFilter>>
    g_microcode_filters;

class JsMicrocodeFilter final : public ida::decompiler::MicrocodeFilter {
public:
    JsMicrocodeFilter(v8::Local<v8::Function> match_callback,
                      v8::Local<v8::Function> apply_callback) {
        match_callback_.Reset(match_callback);
        apply_callback_.Reset(apply_callback);
    }

    ~JsMicrocodeFilter() override {
        match_callback_.Reset();
        apply_callback_.Reset();
    }

    bool match(const ida::decompiler::MicrocodeContext& context) override {
        auto* isolate = v8::Isolate::GetCurrent();
        if (isolate == nullptr)
            return false;
        Nan::HandleScope scope;

        auto callback = Nan::New(match_callback_);
        if (callback.IsEmpty())
            return false;

        auto context_object = MicrocodeContextWrapper::NewInstance(
            const_cast<ida::decompiler::MicrocodeContext*>(&context));
        v8::Local<v8::Value> argv[] = { context_object };

        Nan::TryCatch try_catch;
        auto result = Nan::Call(callback,
                                Nan::GetCurrentContext()->Global(),
                                1,
                                argv);
        MicrocodeContextWrapper::Invalidate(context_object);

        v8::Local<v8::Value> value;
        if (try_catch.HasCaught() || result.IsEmpty() || !result.ToLocal(&value))
            return false;
        return Nan::To<bool>(value).FromMaybe(false);
    }

    ida::decompiler::MicrocodeApplyResult apply(ida::decompiler::MicrocodeContext& context) override {
        auto* isolate = v8::Isolate::GetCurrent();
        if (isolate == nullptr)
            return ida::decompiler::MicrocodeApplyResult::Error;
        Nan::HandleScope scope;

        auto callback = Nan::New(apply_callback_);
        if (callback.IsEmpty())
            return ida::decompiler::MicrocodeApplyResult::Error;

        auto context_object = MicrocodeContextWrapper::NewInstance(&context);
        v8::Local<v8::Value> argv[] = { context_object };

        Nan::TryCatch try_catch;
        auto result = Nan::Call(callback,
                                Nan::GetCurrentContext()->Global(),
                                1,
                                argv);
        MicrocodeContextWrapper::Invalidate(context_object);

        v8::Local<v8::Value> value;
        if (try_catch.HasCaught() || result.IsEmpty() || !result.ToLocal(&value))
            return ida::decompiler::MicrocodeApplyResult::Error;
        return ParseApplyResult(value);
    }

private:
    static ida::decompiler::MicrocodeApplyResult ParseApplyResult(v8::Local<v8::Value> value) {
        if (value->IsString()) {
            std::string text = ToString(value);
            if (text == "handled")
                return ida::decompiler::MicrocodeApplyResult::Handled;
            if (text == "error")
                return ida::decompiler::MicrocodeApplyResult::Error;
            return ida::decompiler::MicrocodeApplyResult::NotHandled;
        }

        if (value->IsNumber()) {
            int code = Nan::To<int>(value).FromMaybe(0);
            switch (code) {
                case 1:
                    return ida::decompiler::MicrocodeApplyResult::Handled;
                case 2:
                    return ida::decompiler::MicrocodeApplyResult::Error;
                default:
                    return ida::decompiler::MicrocodeApplyResult::NotHandled;
            }
        }

        if (value->IsBoolean()) {
            return Nan::To<bool>(value).FromMaybe(false)
                ? ida::decompiler::MicrocodeApplyResult::Handled
                : ida::decompiler::MicrocodeApplyResult::NotHandled;
        }

        return ida::decompiler::MicrocodeApplyResult::NotHandled;
    }

    Nan::Persistent<v8::Function> match_callback_;
    Nan::Persistent<v8::Function> apply_callback_;
};

static void StoreMicrocodeFilter(ida::decompiler::FilterToken token,
                                 std::shared_ptr<ida::decompiler::MicrocodeFilter> filter) {
    std::lock_guard<std::mutex> lock(g_microcode_filters_mutex);
    g_microcode_filters[token] = std::move(filter);
}

static void RemoveMicrocodeFilter(ida::decompiler::FilterToken token) {
    std::lock_guard<std::mutex> lock(g_microcode_filters_mutex);
    g_microcode_filters.erase(token);
}

// ════════════════════════════════════════════════════════════════════════
// Free functions
// ════════════════════════════════════════════════════════════════════════

// available() -> bool
NAN_METHOD(Available) {
    IDAX_UNWRAP(auto avail, ida::decompiler::available());
    info.GetReturnValue().Set(Nan::New(avail));
}

// decompile(address) -> DecompiledFunctionWrapper
NAN_METHOD(Decompile) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_UNWRAP(auto func, ida::decompiler::decompile(addr));
    info.GetReturnValue().Set(DecompiledFunctionWrapper::NewInstance(std::move(func)));
}

// registerMicrocodeFilter(matchCallback, applyCallback) -> token (BigInt)
NAN_METHOD(RegisterMicrocodeFilter) {
    if (info.Length() < 2 || !info[0]->IsFunction() || !info[1]->IsFunction()) {
        Nan::ThrowTypeError("Expected (matchCallback, applyCallback) function arguments");
        return;
    }

    auto match_callback = info[0].As<v8::Function>();
    auto apply_callback = info[1].As<v8::Function>();
    auto filter = std::make_shared<JsMicrocodeFilter>(match_callback, apply_callback);

    IDAX_UNWRAP(auto token, ida::decompiler::register_microcode_filter(filter));
    StoreMicrocodeFilter(token, filter);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// unregisterMicrocodeFilter(token: BigInt)
NAN_METHOD(UnregisterMicrocodeFilter) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected microcode filter token argument");
        return;
    }

    ida::decompiler::FilterToken token = 0;
    if (info[0]->IsBigInt()) {
        bool lossless;
        token = info[0].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[0]->IsNumber()) {
        token = static_cast<ida::decompiler::FilterToken>(
            Nan::To<double>(info[0]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected BigInt or number for microcode filter token");
        return;
    }

    IDAX_CHECK_STATUS(ida::decompiler::unregister_microcode_filter(token));
    RemoveMicrocodeFilter(token);
}

// ── Event subscriptions ─────────────────────────────────────────────────

// onMaturityChanged(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint, newMaturity: number }
NAN_METHOD(OnMaturityChanged) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();

    // Create a weak shared reference that we capture in the lambda.
    // The persistent handle prevents GC.
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_maturity_changed(
        [persistent](const ida::decompiler::MaturityEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .setInt("newMaturity", static_cast<int>(event.new_maturity))
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:maturityChanged");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// onFuncPrinted(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint }
NAN_METHOD(OnFuncPrinted) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_func_printed(
        [persistent](const ida::decompiler::PseudocodeEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:funcPrinted");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// onRefreshPseudocode(callback) -> token (BigInt)
// callback receives: { functionAddress: bigint }
NAN_METHOD(OnRefreshPseudocode) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        Nan::ThrowTypeError("Expected callback function");
        return;
    }

    auto jsFn = info[0].As<v8::Function>();
    auto* persistent = new Nan::Callback(jsFn);

    IDAX_UNWRAP(auto token, ida::decompiler::on_refresh_pseudocode(
        [persistent](const ida::decompiler::PseudocodeEvent& event) {
            Nan::HandleScope scope;
            auto obj = ObjectBuilder()
                .setAddr("functionAddress", event.function_address)
                .build();
            v8::Local<v8::Value> argv[] = { obj };
            Nan::AsyncResource resource("idax:refreshPseudocode");
            persistent->Call(1, argv, &resource);
        }));

    StoreCallback(token, jsFn);

    auto isolate = v8::Isolate::GetCurrent();
    info.GetReturnValue().Set(v8::BigInt::NewFromUnsigned(isolate, token));
}

// unsubscribe(token: BigInt)
NAN_METHOD(Unsubscribe) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Expected subscription token argument");
        return;
    }

    ida::decompiler::Token token = 0;
    if (info[0]->IsBigInt()) {
        bool lossless;
        token = info[0].As<v8::BigInt>()->Uint64Value(&lossless);
    } else if (info[0]->IsNumber()) {
        token = static_cast<ida::decompiler::Token>(
            Nan::To<double>(info[0]).FromJust());
    } else {
        Nan::ThrowTypeError("Expected BigInt or number for subscription token");
        return;
    }

    IDAX_CHECK_STATUS(ida::decompiler::unsubscribe(token));
    RemoveCallback(token);
}

// markDirty(funcAddress, closeViews?: bool)
NAN_METHOD(MarkDirty) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool closeViews = GetOptionalBool(info, 1, false);

    IDAX_CHECK_STATUS(ida::decompiler::mark_dirty(addr, closeViews));
}

// markDirtyWithCallers(funcAddress, closeViews?: bool)
NAN_METHOD(MarkDirtyWithCallers) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    bool closeViews = GetOptionalBool(info, 1, false);

    IDAX_CHECK_STATUS(ida::decompiler::mark_dirty_with_callers(addr, closeViews));
}

} // anonymous namespace

void DisposeAllDecompilerFunctions() {
    DecompiledFunctionWrapper::DisposeAllLiveWrappers();
}

// ── Module registration ─────────────────────────────────────────────────

void InitDecompiler(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "decompiler");

    // Initialize the ObjectWrap constructor template
    MicrocodeContextWrapper::Init(ns);
    DecompiledFunctionWrapper::Init(ns);

    // Free functions
    SetMethod(ns, "available",  Available);
    SetMethod(ns, "decompile",  Decompile);
    SetMethod(ns, "registerMicrocodeFilter", RegisterMicrocodeFilter);
    SetMethod(ns, "unregisterMicrocodeFilter", UnregisterMicrocodeFilter);

    // Event subscriptions
    SetMethod(ns, "onMaturityChanged",     OnMaturityChanged);
    SetMethod(ns, "onFuncPrinted",         OnFuncPrinted);
    SetMethod(ns, "onRefreshPseudocode",   OnRefreshPseudocode);
    SetMethod(ns, "unsubscribe",           Unsubscribe);

    // Cache invalidation
    SetMethod(ns, "markDirty",             MarkDirty);
    SetMethod(ns, "markDirtyWithCallers",  MarkDirtyWithCallers);
}

} // namespace idax_node
