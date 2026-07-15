#include "decompiler_python.hpp"

#include <unordered_map>

namespace idax::python {

namespace {

struct MicrocodeContextState {
    ida::decompiler::MicrocodeContext* context{nullptr};
    bool valid{true};
};

class PythonMicrocodeContext {
public:
    explicit PythonMicrocodeContext(ida::decompiler::MicrocodeContext& context)
        : state_(std::make_shared<MicrocodeContextState>(
              MicrocodeContextState{&context, true})) {}

    ida::decompiler::MicrocodeContext& get(std::string_view operation) const {
        if (!state_->valid || state_->context == nullptr) {
            throw_error(ida::Error::conflict(
                "MicrocodeContext is only valid during filter callback execution",
                std::string(operation)));
        }
        return *state_->context;
    }

    void invalidate() noexcept {
        state_->valid = false;
        state_->context = nullptr;
    }

private:
    std::shared_ptr<MicrocodeContextState> state_;
};

class PythonMicrocodeFilter final : public ida::decompiler::MicrocodeFilter {
public:
    using ida::decompiler::MicrocodeFilter::MicrocodeFilter;

    bool match(const ida::decompiler::MicrocodeContext& context) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "match");
        if (!override)
            return false;
        PythonMicrocodeContext adapter(
            const_cast<ida::decompiler::MicrocodeContext&>(context));
        try {
            const bool result = override(adapter).cast<bool>();
            adapter.invalidate();
            return result;
        } catch (py::error_already_set& error) {
            adapter.invalidate();
            error.discard_as_unraisable(override);
        }
        return false;
    }

    ida::decompiler::MicrocodeApplyResult apply(
        ida::decompiler::MicrocodeContext& context) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "apply");
        if (!override)
            return ida::decompiler::MicrocodeApplyResult::Error;
        PythonMicrocodeContext adapter(context);
        try {
            auto result = override(adapter)
                .cast<ida::decompiler::MicrocodeApplyResult>();
            adapter.invalidate();
            return result;
        } catch (py::error_already_set& error) {
            adapter.invalidate();
            error.discard_as_unraisable(override);
        }
        return ida::decompiler::MicrocodeApplyResult::Error;
    }
};

std::unordered_map<ida::decompiler::FilterToken, py::object>& filter_roots() {
    static std::unordered_map<ida::decompiler::FilterToken, py::object> roots;
    return roots;
}

void unregister_filter(ida::decompiler::FilterToken token) {
    if (token == 0)
        return;
    unwrap(ida::decompiler::unregister_microcode_filter(token));
    filter_roots().erase(token);
}

class PythonScopedMicrocodeFilter {
public:
    explicit PythonScopedMicrocodeFilter(ida::decompiler::FilterToken token)
        : token_(token) {}
    ~PythonScopedMicrocodeFilter() {
        if (token_ == 0 || !Py_IsInitialized())
            return;
        py::gil_scoped_acquire acquire;
        (void)ida::decompiler::unregister_microcode_filter(token_);
        filter_roots().erase(token_);
    }

    ida::decompiler::FilterToken token() const noexcept { return token_; }
    bool valid() const noexcept { return token_ != 0; }
    void close() {
        unregister_filter(token_);
        token_ = 0;
    }

private:
    ida::decompiler::FilterToken token_{0};
};

template <typename Function>
void context_status(PythonMicrocodeContext& self,
                    std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    unwrap(std::forward<Function>(function)(self.get(operation)));
}

template <typename Function>
auto context_result(const PythonMicrocodeContext& self,
                    std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    return unwrap(std::forward<Function>(function)(self.get(operation)));
}

} // namespace

void bind_decompiler_microcode(py::module_& decompiler) {
    py::native_enum<ida::decompiler::MicrocodeApplyResult>(
        decompiler, "MicrocodeApplyResult", "enum.Enum")
        .value("NOT_HANDLED", ida::decompiler::MicrocodeApplyResult::NotHandled)
        .value("HANDLED", ida::decompiler::MicrocodeApplyResult::Handled)
        .value("ERROR", ida::decompiler::MicrocodeApplyResult::Error)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeOpcode>(
        decompiler, "MicrocodeOpcode", "enum.Enum")
        .value("NO_OPERATION", ida::decompiler::MicrocodeOpcode::NoOperation)
        .value("MOVE", ida::decompiler::MicrocodeOpcode::Move)
        .value("ADD", ida::decompiler::MicrocodeOpcode::Add)
        .value("SUBTRACT", ida::decompiler::MicrocodeOpcode::Subtract)
        .value("MULTIPLY", ida::decompiler::MicrocodeOpcode::Multiply)
        .value("ZERO_EXTEND", ida::decompiler::MicrocodeOpcode::ZeroExtend)
        .value("LOAD_MEMORY", ida::decompiler::MicrocodeOpcode::LoadMemory)
        .value("STORE_MEMORY", ida::decompiler::MicrocodeOpcode::StoreMemory)
        .value("BITWISE_OR", ida::decompiler::MicrocodeOpcode::BitwiseOr)
        .value("BITWISE_AND", ida::decompiler::MicrocodeOpcode::BitwiseAnd)
        .value("BITWISE_XOR", ida::decompiler::MicrocodeOpcode::BitwiseXor)
        .value("SHIFT_LEFT", ida::decompiler::MicrocodeOpcode::ShiftLeft)
        .value("SHIFT_RIGHT_LOGICAL", ida::decompiler::MicrocodeOpcode::ShiftRightLogical)
        .value("SHIFT_RIGHT_ARITHMETIC", ida::decompiler::MicrocodeOpcode::ShiftRightArithmetic)
        .value("FLOAT_ADD", ida::decompiler::MicrocodeOpcode::FloatAdd)
        .value("FLOAT_SUB", ida::decompiler::MicrocodeOpcode::FloatSub)
        .value("FLOAT_MUL", ida::decompiler::MicrocodeOpcode::FloatMul)
        .value("FLOAT_DIV", ida::decompiler::MicrocodeOpcode::FloatDiv)
        .value("INTEGER_TO_FLOAT", ida::decompiler::MicrocodeOpcode::IntegerToFloat)
        .value("FLOAT_TO_FLOAT", ida::decompiler::MicrocodeOpcode::FloatToFloat)
        .value("SIGNED_EXTEND", ida::decompiler::MicrocodeOpcode::SignedExtend)
        .value("CALL", ida::decompiler::MicrocodeOpcode::Call)
        .value("INDIRECT_CALL", ida::decompiler::MicrocodeOpcode::IndirectCall)
        .value("GOTO", ida::decompiler::MicrocodeOpcode::Goto)
        .value("INDIRECT_JUMP", ida::decompiler::MicrocodeOpcode::IndirectJump)
        .value("RETURN", ida::decompiler::MicrocodeOpcode::Return)
        .value("OTHER", ida::decompiler::MicrocodeOpcode::Other)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeOperandKind>(
        decompiler, "MicrocodeOperandKind", "enum.Enum")
        .value("EMPTY", ida::decompiler::MicrocodeOperandKind::Empty)
        .value("REGISTER", ida::decompiler::MicrocodeOperandKind::Register)
        .value("LOCAL_VARIABLE", ida::decompiler::MicrocodeOperandKind::LocalVariable)
        .value("REGISTER_PAIR", ida::decompiler::MicrocodeOperandKind::RegisterPair)
        .value("GLOBAL_ADDRESS", ida::decompiler::MicrocodeOperandKind::GlobalAddress)
        .value("STACK_VARIABLE", ida::decompiler::MicrocodeOperandKind::StackVariable)
        .value("HELPER_REFERENCE", ida::decompiler::MicrocodeOperandKind::HelperReference)
        .value("BLOCK_REFERENCE", ida::decompiler::MicrocodeOperandKind::BlockReference)
        .value("NESTED_INSTRUCTION", ida::decompiler::MicrocodeOperandKind::NestedInstruction)
        .value("UNSIGNED_IMMEDIATE", ida::decompiler::MicrocodeOperandKind::UnsignedImmediate)
        .value("SIGNED_IMMEDIATE", ida::decompiler::MicrocodeOperandKind::SignedImmediate)
        .value("ADDRESS_REFERENCE", ida::decompiler::MicrocodeOperandKind::AddressReference)
        .value("CALL_ARGUMENTS", ida::decompiler::MicrocodeOperandKind::CallArguments)
        .value("STRING_CONSTANT", ida::decompiler::MicrocodeOperandKind::StringConstant)
        .value("FLOATING_POINT_CONSTANT", ida::decompiler::MicrocodeOperandKind::FloatingPointConstant)
        .value("OTHER", ida::decompiler::MicrocodeOperandKind::Other)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeMaturity>(
        decompiler, "MicrocodeMaturity", "enum.Enum")
        .value("GENERATED", ida::decompiler::MicrocodeMaturity::Generated)
        .value("PREOPTIMIZED", ida::decompiler::MicrocodeMaturity::Preoptimized)
        .value("LOCALLY_OPTIMIZED", ida::decompiler::MicrocodeMaturity::LocallyOptimized)
        .value("CALLS_ANALYZED", ida::decompiler::MicrocodeMaturity::CallsAnalyzed)
        .value("GLOBALLY_OPTIMIZED1", ida::decompiler::MicrocodeMaturity::GloballyOptimized1)
        .value("GLOBALLY_OPTIMIZED2", ida::decompiler::MicrocodeMaturity::GloballyOptimized2)
        .value("GLOBALLY_OPTIMIZED3", ida::decompiler::MicrocodeMaturity::GloballyOptimized3)
        .value("LOCAL_VARIABLES", ida::decompiler::MicrocodeMaturity::LocalVariables)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeInsertPolicy>(
        decompiler, "MicrocodeInsertPolicy", "enum.Enum")
        .value("TAIL", ida::decompiler::MicrocodeInsertPolicy::Tail)
        .value("BEGINNING", ida::decompiler::MicrocodeInsertPolicy::Beginning)
        .value("BEFORE_TAIL", ida::decompiler::MicrocodeInsertPolicy::BeforeTail)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeValueKind>(
        decompiler, "MicrocodeValueKind", "enum.Enum")
        .value("REGISTER", ida::decompiler::MicrocodeValueKind::Register)
        .value("LOCAL_VARIABLE", ida::decompiler::MicrocodeValueKind::LocalVariable)
        .value("REGISTER_PAIR", ida::decompiler::MicrocodeValueKind::RegisterPair)
        .value("GLOBAL_ADDRESS", ida::decompiler::MicrocodeValueKind::GlobalAddress)
        .value("STACK_VARIABLE", ida::decompiler::MicrocodeValueKind::StackVariable)
        .value("HELPER_REFERENCE", ida::decompiler::MicrocodeValueKind::HelperReference)
        .value("BLOCK_REFERENCE", ida::decompiler::MicrocodeValueKind::BlockReference)
        .value("NESTED_INSTRUCTION", ida::decompiler::MicrocodeValueKind::NestedInstruction)
        .value("UNSIGNED_IMMEDIATE", ida::decompiler::MicrocodeValueKind::UnsignedImmediate)
        .value("SIGNED_IMMEDIATE", ida::decompiler::MicrocodeValueKind::SignedImmediate)
        .value("FLOAT32_IMMEDIATE", ida::decompiler::MicrocodeValueKind::Float32Immediate)
        .value("FLOAT64_IMMEDIATE", ida::decompiler::MicrocodeValueKind::Float64Immediate)
        .value("BYTE_ARRAY", ida::decompiler::MicrocodeValueKind::ByteArray)
        .value("VECTOR", ida::decompiler::MicrocodeValueKind::Vector)
        .value("TYPE_DECLARATION_VIEW", ida::decompiler::MicrocodeValueKind::TypeDeclarationView)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeValueLocationKind>(
        decompiler, "MicrocodeValueLocationKind", "enum.Enum")
        .value("UNSPECIFIED", ida::decompiler::MicrocodeValueLocationKind::Unspecified)
        .value("REGISTER", ida::decompiler::MicrocodeValueLocationKind::Register)
        .value("REGISTER_WITH_OFFSET", ida::decompiler::MicrocodeValueLocationKind::RegisterWithOffset)
        .value("REGISTER_PAIR", ida::decompiler::MicrocodeValueLocationKind::RegisterPair)
        .value("REGISTER_RELATIVE", ida::decompiler::MicrocodeValueLocationKind::RegisterRelative)
        .value("STACK_OFFSET", ida::decompiler::MicrocodeValueLocationKind::StackOffset)
        .value("STATIC_ADDRESS", ida::decompiler::MicrocodeValueLocationKind::StaticAddress)
        .value("SCATTERED", ida::decompiler::MicrocodeValueLocationKind::Scattered)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeArgumentFlag>(
        decompiler, "MicrocodeArgumentFlag", "enum.IntFlag")
        .value("HIDDEN_ARGUMENT", ida::decompiler::MicrocodeArgumentFlag::HiddenArgument)
        .value("RETURN_VALUE_POINTER", ida::decompiler::MicrocodeArgumentFlag::ReturnValuePointer)
        .value("STRUCT_ARGUMENT", ida::decompiler::MicrocodeArgumentFlag::StructArgument)
        .value("ARRAY_ARGUMENT", ida::decompiler::MicrocodeArgumentFlag::ArrayArgument)
        .value("UNUSED_ARGUMENT", ida::decompiler::MicrocodeArgumentFlag::UnusedArgument)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeCallingConvention>(
        decompiler, "MicrocodeCallingConvention", "enum.Enum")
        .value("UNSPECIFIED", ida::decompiler::MicrocodeCallingConvention::Unspecified)
        .value("CDECL", ida::decompiler::MicrocodeCallingConvention::Cdecl)
        .value("STDCALL", ida::decompiler::MicrocodeCallingConvention::Stdcall)
        .value("FASTCALL", ida::decompiler::MicrocodeCallingConvention::Fastcall)
        .value("THISCALL", ida::decompiler::MicrocodeCallingConvention::Thiscall)
        .finalize();
    py::native_enum<ida::decompiler::MicrocodeFunctionRole>(
        decompiler, "MicrocodeFunctionRole", "enum.Enum")
        .value("UNKNOWN", ida::decompiler::MicrocodeFunctionRole::Unknown)
        .value("EMPTY", ida::decompiler::MicrocodeFunctionRole::Empty)
        .value("MEMSET", ida::decompiler::MicrocodeFunctionRole::Memset)
        .value("MEMSET32", ida::decompiler::MicrocodeFunctionRole::Memset32)
        .value("MEMSET64", ida::decompiler::MicrocodeFunctionRole::Memset64)
        .value("MEMCPY", ida::decompiler::MicrocodeFunctionRole::Memcpy)
        .value("STRCPY", ida::decompiler::MicrocodeFunctionRole::Strcpy)
        .value("STRLEN", ida::decompiler::MicrocodeFunctionRole::Strlen)
        .value("STRCAT", ida::decompiler::MicrocodeFunctionRole::Strcat)
        .value("TAIL", ida::decompiler::MicrocodeFunctionRole::Tail)
        .value("BUG", ida::decompiler::MicrocodeFunctionRole::Bug)
        .value("ALLOCA", ida::decompiler::MicrocodeFunctionRole::Alloca)
        .value("BYTE_SWAP", ida::decompiler::MicrocodeFunctionRole::ByteSwap)
        .value("PRESENT", ida::decompiler::MicrocodeFunctionRole::Present)
        .value("CONTAINING_RECORD", ida::decompiler::MicrocodeFunctionRole::ContainingRecord)
        .value("FAST_FAIL", ida::decompiler::MicrocodeFunctionRole::FastFail)
        .value("READ_FLAGS", ida::decompiler::MicrocodeFunctionRole::ReadFlags)
        .value("IS_MUL_OK", ida::decompiler::MicrocodeFunctionRole::IsMulOk)
        .value("SATURATED_MUL", ida::decompiler::MicrocodeFunctionRole::SaturatedMul)
        .value("BIT_TEST", ida::decompiler::MicrocodeFunctionRole::BitTest)
        .value("BIT_TEST_AND_SET", ida::decompiler::MicrocodeFunctionRole::BitTestAndSet)
        .value("BIT_TEST_AND_RESET", ida::decompiler::MicrocodeFunctionRole::BitTestAndReset)
        .value("BIT_TEST_AND_COMPLEMENT", ida::decompiler::MicrocodeFunctionRole::BitTestAndComplement)
        .value("VA_ARG", ida::decompiler::MicrocodeFunctionRole::VaArg)
        .value("VA_COPY", ida::decompiler::MicrocodeFunctionRole::VaCopy)
        .value("VA_START", ida::decompiler::MicrocodeFunctionRole::VaStart)
        .value("VA_END", ida::decompiler::MicrocodeFunctionRole::VaEnd)
        .value("ROTATE_LEFT", ida::decompiler::MicrocodeFunctionRole::RotateLeft)
        .value("ROTATE_RIGHT", ida::decompiler::MicrocodeFunctionRole::RotateRight)
        .value("CARRY_FLAG_SUB3", ida::decompiler::MicrocodeFunctionRole::CarryFlagSub3)
        .value("OVERFLOW_FLAG_SUB3", ida::decompiler::MicrocodeFunctionRole::OverflowFlagSub3)
        .value("ABSOLUTE_VALUE", ida::decompiler::MicrocodeFunctionRole::AbsoluteValue)
        .value("THREE_WAY_COMPARE0", ida::decompiler::MicrocodeFunctionRole::ThreeWayCompare0)
        .value("THREE_WAY_COMPARE1", ida::decompiler::MicrocodeFunctionRole::ThreeWayCompare1)
        .value("WIDE_MEM_COPY", ida::decompiler::MicrocodeFunctionRole::WideMemCopy)
        .value("WIDE_MEM_SET", ida::decompiler::MicrocodeFunctionRole::WideMemSet)
        .value("WIDE_STR_COPY", ida::decompiler::MicrocodeFunctionRole::WideStrCopy)
        .value("WIDE_STR_LEN", ida::decompiler::MicrocodeFunctionRole::WideStrLen)
        .value("WIDE_STR_CAT", ida::decompiler::MicrocodeFunctionRole::WideStrCat)
        .value("SSE_COMPARE4", ida::decompiler::MicrocodeFunctionRole::SseCompare4)
        .value("SSE_COMPARE8", ida::decompiler::MicrocodeFunctionRole::SseCompare8)
        .finalize();

    py::class_<ida::decompiler::MicrocodeOperand,
               std::shared_ptr<ida::decompiler::MicrocodeOperand>>(
        decompiler, "MicrocodeOperand")
        .def(py::init<>())
        .def_readwrite("kind", &ida::decompiler::MicrocodeOperand::kind)
        .def_readwrite("register_id", &ida::decompiler::MicrocodeOperand::register_id)
        .def_readwrite("processor_register_id", &ida::decompiler::MicrocodeOperand::processor_register_id)
        .def_readwrite("local_variable_index", &ida::decompiler::MicrocodeOperand::local_variable_index)
        .def_readwrite("local_variable_offset", &ida::decompiler::MicrocodeOperand::local_variable_offset)
        .def_readwrite("second_register_id", &ida::decompiler::MicrocodeOperand::second_register_id)
        .def_readwrite("global_address", &ida::decompiler::MicrocodeOperand::global_address)
        .def_readwrite("stack_offset", &ida::decompiler::MicrocodeOperand::stack_offset)
        .def_readwrite("helper_name", &ida::decompiler::MicrocodeOperand::helper_name)
        .def_readwrite("block_index", &ida::decompiler::MicrocodeOperand::block_index)
        .def_readwrite("nested_instruction", &ida::decompiler::MicrocodeOperand::nested_instruction)
        .def_readwrite("unsigned_immediate", &ida::decompiler::MicrocodeOperand::unsigned_immediate)
        .def_readwrite("signed_immediate", &ida::decompiler::MicrocodeOperand::signed_immediate)
        .def_readwrite("byte_width", &ida::decompiler::MicrocodeOperand::byte_width)
        .def_readwrite("mark_user_defined_type", &ida::decompiler::MicrocodeOperand::mark_user_defined_type)
        .def_readwrite("referenced_operand", &ida::decompiler::MicrocodeOperand::referenced_operand)
        .def_readwrite("call_arguments", &ida::decompiler::MicrocodeOperand::call_arguments)
        .def_readwrite("call_target", &ida::decompiler::MicrocodeOperand::call_target)
        .def_readwrite("text", &ida::decompiler::MicrocodeOperand::text);
    py::class_<ida::decompiler::MicrocodeInstruction,
               std::shared_ptr<ida::decompiler::MicrocodeInstruction>>(
        decompiler, "MicrocodeInstruction")
        .def(py::init<>())
        .def_readwrite("opcode", &ida::decompiler::MicrocodeInstruction::opcode)
        .def_readwrite("left", &ida::decompiler::MicrocodeInstruction::left)
        .def_readwrite("right", &ida::decompiler::MicrocodeInstruction::right)
        .def_readwrite("destination", &ida::decompiler::MicrocodeInstruction::destination)
        .def_readwrite("floating_point_instruction", &ida::decompiler::MicrocodeInstruction::floating_point_instruction)
        .def_readwrite("modifies_destination", &ida::decompiler::MicrocodeInstruction::modifies_destination)
        .def_readwrite("address", &ida::decompiler::MicrocodeInstruction::address)
        .def_readwrite("text", &ida::decompiler::MicrocodeInstruction::text);

#define IDAX_PY_DECOMPILER_VALUE(type_name)                              \
    py::class_<ida::decompiler::type_name>(decompiler, #type_name).def(py::init<>())
    IDAX_PY_DECOMPILER_VALUE(MicrocodeGenerationOptions)
        .def_readwrite("maturity", &ida::decompiler::MicrocodeGenerationOptions::maturity)
        .def_readwrite("analyze_calls", &ida::decompiler::MicrocodeGenerationOptions::analyze_calls);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeLocationPart)
        .def_readwrite("kind", &ida::decompiler::MicrocodeLocationPart::kind)
        .def_readwrite("register_id", &ida::decompiler::MicrocodeLocationPart::register_id)
        .def_readwrite("second_register_id", &ida::decompiler::MicrocodeLocationPart::second_register_id)
        .def_readwrite("register_offset", &ida::decompiler::MicrocodeLocationPart::register_offset)
        .def_readwrite("register_relative_offset", &ida::decompiler::MicrocodeLocationPart::register_relative_offset)
        .def_readwrite("stack_offset", &ida::decompiler::MicrocodeLocationPart::stack_offset)
        .def_readwrite("static_address", &ida::decompiler::MicrocodeLocationPart::static_address)
        .def_readwrite("byte_offset", &ida::decompiler::MicrocodeLocationPart::byte_offset)
        .def_readwrite("byte_size", &ida::decompiler::MicrocodeLocationPart::byte_size);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeValueLocation)
        .def_readwrite("kind", &ida::decompiler::MicrocodeValueLocation::kind)
        .def_readwrite("register_id", &ida::decompiler::MicrocodeValueLocation::register_id)
        .def_readwrite("second_register_id", &ida::decompiler::MicrocodeValueLocation::second_register_id)
        .def_readwrite("register_offset", &ida::decompiler::MicrocodeValueLocation::register_offset)
        .def_readwrite("register_relative_offset", &ida::decompiler::MicrocodeValueLocation::register_relative_offset)
        .def_readwrite("stack_offset", &ida::decompiler::MicrocodeValueLocation::stack_offset)
        .def_readwrite("static_address", &ida::decompiler::MicrocodeValueLocation::static_address)
        .def_readwrite("scattered_parts", &ida::decompiler::MicrocodeValueLocation::scattered_parts);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeFunctionArgument)
        .def_readwrite("name", &ida::decompiler::MicrocodeFunctionArgument::name)
        .def_readwrite("location", &ida::decompiler::MicrocodeFunctionArgument::location)
        .def_readwrite("byte_width", &ida::decompiler::MicrocodeFunctionArgument::byte_width);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeBlock)
        .def_readwrite("index", &ida::decompiler::MicrocodeBlock::index)
        .def_readwrite("start_address", &ida::decompiler::MicrocodeBlock::start_address)
        .def_readwrite("end_address", &ida::decompiler::MicrocodeBlock::end_address)
        .def_readwrite("predecessors", &ida::decompiler::MicrocodeBlock::predecessors)
        .def_readwrite("successors", &ida::decompiler::MicrocodeBlock::successors)
        .def_readwrite("instructions", &ida::decompiler::MicrocodeBlock::instructions);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeFunction)
        .def_readwrite("entry_address", &ida::decompiler::MicrocodeFunction::entry_address)
        .def_readwrite("maturity", &ida::decompiler::MicrocodeFunction::maturity)
        .def_readwrite("arguments", &ida::decompiler::MicrocodeFunction::arguments)
        .def_readwrite("return_location", &ida::decompiler::MicrocodeFunction::return_location)
        .def_readwrite("blocks", &ida::decompiler::MicrocodeFunction::blocks);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeValue)
        .def_readwrite("kind", &ida::decompiler::MicrocodeValue::kind)
        .def_readwrite("register_id", &ida::decompiler::MicrocodeValue::register_id)
        .def_readwrite("local_variable_index", &ida::decompiler::MicrocodeValue::local_variable_index)
        .def_readwrite("local_variable_offset", &ida::decompiler::MicrocodeValue::local_variable_offset)
        .def_readwrite("second_register_id", &ida::decompiler::MicrocodeValue::second_register_id)
        .def_readwrite("global_address", &ida::decompiler::MicrocodeValue::global_address)
        .def_readwrite("stack_offset", &ida::decompiler::MicrocodeValue::stack_offset)
        .def_readwrite("helper_name", &ida::decompiler::MicrocodeValue::helper_name)
        .def_readwrite("block_index", &ida::decompiler::MicrocodeValue::block_index)
        .def_readwrite("nested_instruction", &ida::decompiler::MicrocodeValue::nested_instruction)
        .def_readwrite("unsigned_immediate", &ida::decompiler::MicrocodeValue::unsigned_immediate)
        .def_readwrite("signed_immediate", &ida::decompiler::MicrocodeValue::signed_immediate)
        .def_readwrite("floating_immediate", &ida::decompiler::MicrocodeValue::floating_immediate)
        .def_readwrite("byte_width", &ida::decompiler::MicrocodeValue::byte_width)
        .def_readwrite("unsigned_integer", &ida::decompiler::MicrocodeValue::unsigned_integer)
        .def_readwrite("vector_element_byte_width", &ida::decompiler::MicrocodeValue::vector_element_byte_width)
        .def_readwrite("vector_element_count", &ida::decompiler::MicrocodeValue::vector_element_count)
        .def_readwrite("vector_elements_unsigned", &ida::decompiler::MicrocodeValue::vector_elements_unsigned)
        .def_readwrite("vector_elements_floating", &ida::decompiler::MicrocodeValue::vector_elements_floating)
        .def_readwrite("type_declaration", &ida::decompiler::MicrocodeValue::type_declaration)
        .def_readwrite("argument_name", &ida::decompiler::MicrocodeValue::argument_name)
        .def_readwrite("argument_flags", &ida::decompiler::MicrocodeValue::argument_flags)
        .def_readwrite("location", &ida::decompiler::MicrocodeValue::location);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeRegisterRange)
        .def_readwrite("register_id", &ida::decompiler::MicrocodeRegisterRange::register_id)
        .def_readwrite("byte_width", &ida::decompiler::MicrocodeRegisterRange::byte_width);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeMemoryRange)
        .def_readwrite("address", &ida::decompiler::MicrocodeMemoryRange::address)
        .def_readwrite("byte_size", &ida::decompiler::MicrocodeMemoryRange::byte_size);
    IDAX_PY_DECOMPILER_VALUE(MicrocodeCallOptions)
        .def_readwrite("insert_policy", &ida::decompiler::MicrocodeCallOptions::insert_policy)
        .def_readwrite("callee_address", &ida::decompiler::MicrocodeCallOptions::callee_address)
        .def_readwrite("solid_argument_count", &ida::decompiler::MicrocodeCallOptions::solid_argument_count)
        .def_readwrite("call_stack_pointer_delta", &ida::decompiler::MicrocodeCallOptions::call_stack_pointer_delta)
        .def_readwrite("stack_arguments_top", &ida::decompiler::MicrocodeCallOptions::stack_arguments_top)
        .def_readwrite("function_role", &ida::decompiler::MicrocodeCallOptions::function_role)
        .def_readwrite("return_location", &ida::decompiler::MicrocodeCallOptions::return_location)
        .def_readwrite("return_type_declaration", &ida::decompiler::MicrocodeCallOptions::return_type_declaration)
        .def_readwrite("calling_convention", &ida::decompiler::MicrocodeCallOptions::calling_convention)
        .def_readwrite("mark_final", &ida::decompiler::MicrocodeCallOptions::mark_final)
        .def_readwrite("mark_propagated", &ida::decompiler::MicrocodeCallOptions::mark_propagated)
        .def_readwrite("mark_dead_return_registers", &ida::decompiler::MicrocodeCallOptions::mark_dead_return_registers)
        .def_readwrite("mark_no_return", &ida::decompiler::MicrocodeCallOptions::mark_no_return)
        .def_readwrite("mark_pure", &ida::decompiler::MicrocodeCallOptions::mark_pure)
        .def_readwrite("mark_no_side_effects", &ida::decompiler::MicrocodeCallOptions::mark_no_side_effects)
        .def_readwrite("mark_spoiled_lists_optimized", &ida::decompiler::MicrocodeCallOptions::mark_spoiled_lists_optimized)
        .def_readwrite("mark_synthetic_has_call", &ida::decompiler::MicrocodeCallOptions::mark_synthetic_has_call)
        .def_readwrite("mark_has_format_string", &ida::decompiler::MicrocodeCallOptions::mark_has_format_string)
        .def_readwrite("auto_stack_start_offset", &ida::decompiler::MicrocodeCallOptions::auto_stack_start_offset)
        .def_readwrite("auto_stack_alignment", &ida::decompiler::MicrocodeCallOptions::auto_stack_alignment)
        .def_readwrite("auto_stack_argument_locations", &ida::decompiler::MicrocodeCallOptions::auto_stack_argument_locations)
        .def_readwrite("mark_explicit_locations", &ida::decompiler::MicrocodeCallOptions::mark_explicit_locations)
        .def_readwrite("return_registers", &ida::decompiler::MicrocodeCallOptions::return_registers)
        .def_readwrite("spoiled_registers", &ida::decompiler::MicrocodeCallOptions::spoiled_registers)
        .def_readwrite("passthrough_registers", &ida::decompiler::MicrocodeCallOptions::passthrough_registers)
        .def_readwrite("dead_registers", &ida::decompiler::MicrocodeCallOptions::dead_registers)
        .def_readwrite("visible_memory_ranges", &ida::decompiler::MicrocodeCallOptions::visible_memory_ranges)
        .def_readwrite("visible_memory_all", &ida::decompiler::MicrocodeCallOptions::visible_memory_all);
#undef IDAX_PY_DECOMPILER_VALUE

    py::class_<PythonMicrocodeContext>(decompiler, "MicrocodeContext")
        .def_property_readonly("address", [](const PythonMicrocodeContext& self) {
            return self.get("address").address();
        })
        .def_property_readonly("instruction_type", [](const PythonMicrocodeContext& self) {
            return self.get("instruction_type").instruction_type();
        })
        .def_property_readonly("has_opmask", [](const PythonMicrocodeContext& self) {
            return self.get("has_opmask").has_opmask();
        })
        .def_property_readonly("is_zero_masking", [](const PythonMicrocodeContext& self) {
            return self.get("is_zero_masking").is_zero_masking();
        })
        .def_property_readonly("opmask_register_number", [](const PythonMicrocodeContext& self) {
            return self.get("opmask_register_number").opmask_register_number();
        })
#define IDAX_PY_CONTEXT_NOARG_RESULT(fn)                                 \
        .def(#fn, [](const PythonMicrocodeContext& self) {               \
            return context_result(self, "decompiler.MicrocodeContext." #fn, \
                [](const auto& context) { return context.fn(); });       \
        })
        IDAX_PY_CONTEXT_NOARG_RESULT(local_variable_count)
        IDAX_PY_CONTEXT_NOARG_RESULT(block_instruction_count)
        IDAX_PY_CONTEXT_NOARG_RESULT(instruction)
        IDAX_PY_CONTEXT_NOARG_RESULT(has_last_emitted_instruction)
        IDAX_PY_CONTEXT_NOARG_RESULT(last_emitted_instruction)
#undef IDAX_PY_CONTEXT_NOARG_RESULT
        .def("has_instruction_at_index", [](const PythonMicrocodeContext& self, int index) {
            return context_result(self, "decompiler.MicrocodeContext.has_instruction_at_index",
                [=](const auto& context) { return context.has_instruction_at_index(index); });
        }, py::arg("instruction_index"))
        .def("instruction_at_index", [](const PythonMicrocodeContext& self, int index) {
            return context_result(self, "decompiler.MicrocodeContext.instruction_at_index",
                [=](const auto& context) { return context.instruction_at_index(index); });
        }, py::arg("instruction_index"))
        .def("remove_last_emitted_instruction", [](PythonMicrocodeContext& self) {
            context_status(self, "decompiler.MicrocodeContext.remove_last_emitted_instruction",
                [](auto& context) { return context.remove_last_emitted_instruction(); });
        })
        .def("remove_instruction_at_index", [](PythonMicrocodeContext& self, int index) {
            context_status(self, "decompiler.MicrocodeContext.remove_instruction_at_index",
                [=](auto& context) { return context.remove_instruction_at_index(index); });
        }, py::arg("instruction_index"))
        .def("emit_noop", [](PythonMicrocodeContext& self) {
            context_status(self, "decompiler.MicrocodeContext.emit_noop",
                [](auto& context) { return context.emit_noop(); });
        })
        .def("emit_noop_with_policy", [](PythonMicrocodeContext& self,
                                           ida::decompiler::MicrocodeInsertPolicy policy) {
            context_status(self, "decompiler.MicrocodeContext.emit_noop_with_policy",
                [=](auto& context) { return context.emit_noop_with_policy(policy); });
        }, py::arg("policy"))
        .def("emit_instruction", [](PythonMicrocodeContext& self,
                                      const ida::decompiler::MicrocodeInstruction& value) {
            context_status(self, "decompiler.MicrocodeContext.emit_instruction",
                [&](auto& context) { return context.emit_instruction(value); });
        }, py::arg("instruction"))
        .def("emit_instruction_with_policy", [](PythonMicrocodeContext& self,
            const ida::decompiler::MicrocodeInstruction& value,
            ida::decompiler::MicrocodeInsertPolicy policy) {
            context_status(self, "decompiler.MicrocodeContext.emit_instruction_with_policy",
                [&](auto& context) { return context.emit_instruction_with_policy(value, policy); });
        }, py::arg("instruction"), py::arg("policy"))
        .def("emit_instructions", [](PythonMicrocodeContext& self,
            const std::vector<ida::decompiler::MicrocodeInstruction>& values) {
            context_status(self, "decompiler.MicrocodeContext.emit_instructions",
                [&](auto& context) { return context.emit_instructions(values); });
        }, py::arg("instructions"))
        .def("emit_instructions_with_policy", [](PythonMicrocodeContext& self,
            const std::vector<ida::decompiler::MicrocodeInstruction>& values,
            ida::decompiler::MicrocodeInsertPolicy policy) {
            context_status(self, "decompiler.MicrocodeContext.emit_instructions_with_policy",
                [&](auto& context) { return context.emit_instructions_with_policy(values, policy); });
        }, py::arg("instructions"), py::arg("policy"))
#define IDAX_PY_CONTEXT_INT_RESULT(fn, argument_name)                    \
        .def(#fn, [](const PythonMicrocodeContext& self, int value) {    \
            return context_result(self, "decompiler.MicrocodeContext." #fn, \
                [=](auto& context) { return context.fn(value); });       \
        }, py::arg(argument_name))
        IDAX_PY_CONTEXT_INT_RESULT(load_operand_register, "operand_index")
        IDAX_PY_CONTEXT_INT_RESULT(load_effective_address_register, "operand_index")
        IDAX_PY_CONTEXT_INT_RESULT(allocate_temporary_register, "byte_width")
#undef IDAX_PY_CONTEXT_INT_RESULT
        .def("store_operand_register", [](PythonMicrocodeContext& self,
            int operand_index, int source_register, int byte_width, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.store_operand_register",
                [=](auto& context) { return context.store_operand_register(
                    operand_index, source_register, byte_width, mark_udt); });
        }, py::arg("operand_index"), py::arg("source_register"),
           py::arg("byte_width"), py::arg("mark_user_defined_type") = false)
        .def("emit_move_register", [](PythonMicrocodeContext& self,
            int source, int destination, int width, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_move_register",
                [=](auto& context) { return context.emit_move_register(
                    source, destination, width, mark_udt); });
        }, py::arg("source_register"), py::arg("destination_register"),
           py::arg("byte_width"), py::arg("mark_user_defined_type") = false)
        .def("emit_move_register_with_policy", [](PythonMicrocodeContext& self,
            int source, int destination, int width,
            ida::decompiler::MicrocodeInsertPolicy policy, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_move_register_with_policy",
                [=](auto& context) { return context.emit_move_register_with_policy(
                    source, destination, width, policy, mark_udt); });
        }, py::arg("source_register"), py::arg("destination_register"),
           py::arg("byte_width"), py::arg("policy"),
           py::arg("mark_user_defined_type") = false)
        .def("emit_load_memory_register", [](PythonMicrocodeContext& self,
            int selector, int offset, int destination, int width,
            int offset_width, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_load_memory_register",
                [=](auto& context) { return context.emit_load_memory_register(
                    selector, offset, destination, width, offset_width, mark_udt); });
        }, py::arg("selector_register"), py::arg("offset_register"),
           py::arg("destination_register"), py::arg("byte_width"),
           py::arg("offset_byte_width"), py::arg("mark_user_defined_type") = false)
        .def("emit_load_memory_register_with_policy", [](PythonMicrocodeContext& self,
            int selector, int offset, int destination, int width, int offset_width,
            ida::decompiler::MicrocodeInsertPolicy policy, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_load_memory_register_with_policy",
                [=](auto& context) { return context.emit_load_memory_register_with_policy(
                    selector, offset, destination, width, offset_width, policy, mark_udt); });
        }, py::arg("selector_register"), py::arg("offset_register"),
           py::arg("destination_register"), py::arg("byte_width"),
           py::arg("offset_byte_width"), py::arg("policy"),
           py::arg("mark_user_defined_type") = false)
        .def("emit_store_memory_register", [](PythonMicrocodeContext& self,
            int source, int selector, int offset, int width,
            int offset_width, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_store_memory_register",
                [=](auto& context) { return context.emit_store_memory_register(
                    source, selector, offset, width, offset_width, mark_udt); });
        }, py::arg("source_register"), py::arg("selector_register"),
           py::arg("offset_register"), py::arg("byte_width"),
           py::arg("offset_byte_width"), py::arg("mark_user_defined_type") = false)
        .def("emit_store_memory_register_with_policy", [](PythonMicrocodeContext& self,
            int source, int selector, int offset, int width, int offset_width,
            ida::decompiler::MicrocodeInsertPolicy policy, bool mark_udt) {
            context_status(self, "decompiler.MicrocodeContext.emit_store_memory_register_with_policy",
                [=](auto& context) { return context.emit_store_memory_register_with_policy(
                    source, selector, offset, width, offset_width, policy, mark_udt); });
        }, py::arg("source_register"), py::arg("selector_register"),
           py::arg("offset_register"), py::arg("byte_width"),
           py::arg("offset_byte_width"), py::arg("policy"),
           py::arg("mark_user_defined_type") = false)
        .def("emit_helper_call", [](PythonMicrocodeContext& self, std::string name) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call",
                [&](auto& context) { return context.emit_helper_call(name); });
        }, py::arg("helper_name"))
        .def("emit_helper_call_with_arguments", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments",
                [&](auto& context) { return context.emit_helper_call_with_arguments(name, args); });
        }, py::arg("helper_name"), py::arg("arguments"))
        .def("emit_helper_call_with_arguments_and_options", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            const ida::decompiler::MicrocodeCallOptions& options) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_and_options",
                [&](auto& context) { return context.emit_helper_call_with_arguments_and_options(name, args, options); });
        }, py::arg("helper_name"), py::arg("arguments"), py::arg("options"))
        .def("emit_helper_call_with_arguments_to_register", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            int destination, int width, bool is_unsigned) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_register",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_register(
                    name, args, destination, width, is_unsigned); });
        }, py::arg("helper_name"), py::arg("arguments"),
           py::arg("destination_register"), py::arg("destination_byte_width"),
           py::arg("destination_unsigned") = true)
        .def("emit_helper_call_with_arguments_to_register_and_options", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            int destination, int width, bool is_unsigned,
            const ida::decompiler::MicrocodeCallOptions& options) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_register_and_options",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_register_and_options(
                    name, args, destination, width, is_unsigned, options); });
        }, py::arg("helper_name"), py::arg("arguments"),
           py::arg("destination_register"), py::arg("destination_byte_width"),
           py::arg("destination_unsigned"), py::arg("options"))
        .def("emit_helper_call_with_arguments_to_micro_operand", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            const ida::decompiler::MicrocodeOperand& destination, bool is_unsigned) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_micro_operand",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_micro_operand(
                    name, args, destination, is_unsigned); });
        }, py::arg("helper_name"), py::arg("arguments"), py::arg("destination"),
           py::arg("destination_unsigned") = true)
        .def("emit_helper_call_with_arguments_to_micro_operand_and_options", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            const ida::decompiler::MicrocodeOperand& destination, bool is_unsigned,
            const ida::decompiler::MicrocodeCallOptions& options) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_micro_operand_and_options",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    name, args, destination, is_unsigned, options); });
        }, py::arg("helper_name"), py::arg("arguments"), py::arg("destination"),
           py::arg("destination_unsigned"), py::arg("options"))
        .def("emit_helper_call_with_arguments_to_operand", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            int operand_index, int width, bool is_unsigned) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_operand",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_operand(
                    name, args, operand_index, width, is_unsigned); });
        }, py::arg("helper_name"), py::arg("arguments"),
           py::arg("destination_operand_index"), py::arg("destination_byte_width"),
           py::arg("destination_unsigned") = true)
        .def("emit_helper_call_with_arguments_to_operand_and_options", [](PythonMicrocodeContext& self,
            std::string name, const std::vector<ida::decompiler::MicrocodeValue>& args,
            int operand_index, int width, bool is_unsigned,
            const ida::decompiler::MicrocodeCallOptions& options) {
            context_status(self, "decompiler.MicrocodeContext.emit_helper_call_with_arguments_to_operand_and_options",
                [&](auto& context) { return context.emit_helper_call_with_arguments_to_operand_and_options(
                    name, args, operand_index, width, is_unsigned, options); });
        }, py::arg("helper_name"), py::arg("arguments"),
           py::arg("destination_operand_index"), py::arg("destination_byte_width"),
           py::arg("destination_unsigned"), py::arg("options"));

    py::class_<ida::decompiler::MicrocodeFilter, PythonMicrocodeFilter,
               std::shared_ptr<ida::decompiler::MicrocodeFilter>>(
        decompiler, "MicrocodeFilter")
        .def(py::init<>())
        .def("match", [](ida::decompiler::MicrocodeFilter& self,
                           const PythonMicrocodeContext& context) {
            return self.match(context.get("MicrocodeFilter.match"));
        }, py::arg("context"))
        .def("apply", [](ida::decompiler::MicrocodeFilter& self,
                           PythonMicrocodeContext& context) {
            return self.apply(context.get("MicrocodeFilter.apply"));
        }, py::arg("context"));
    py::class_<PythonScopedMicrocodeFilter>(decompiler, "ScopedMicrocodeFilter")
        .def(py::init<ida::decompiler::FilterToken>(), py::arg("token") = 0)
        .def_property_readonly("token", &PythonScopedMicrocodeFilter::token)
        .def_property_readonly("valid", &PythonScopedMicrocodeFilter::valid)
        .def("close", &PythonScopedMicrocodeFilter::close)
        .def("reset", &PythonScopedMicrocodeFilter::close)
        .def("__enter__", [](PythonScopedMicrocodeFilter& self)
             -> PythonScopedMicrocodeFilter& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](PythonScopedMicrocodeFilter& self,
                             py::object, py::object, py::object) {
            if (self.valid())
                self.close();
            return false;
        });

    decompiler.def("register_microcode_filter", [](py::object filter_object) {
        auto filter = filter_object.cast<
            std::shared_ptr<ida::decompiler::MicrocodeFilter>>();
        auto token = runtime_result("decompiler.register_microcode_filter", [&] {
            return ida::decompiler::register_microcode_filter(std::move(filter));
        });
        filter_roots().insert_or_assign(token, std::move(filter_object));
        return token;
    }, py::arg("filter"));
    decompiler.def("unregister_microcode_filter", [](
        ida::decompiler::FilterToken token) {
        ensure_runtime_thread("decompiler.unregister_microcode_filter");
        unregister_filter(token);
    }, py::arg("token"));
    decompiler.def("generate_microcode", [](
        ida::Address address,
        const ida::decompiler::MicrocodeGenerationOptions& options) {
        return runtime_result("decompiler.generate_microcode", [&] {
            return ida::decompiler::generate_microcode(address, options);
        });
    }, py::arg("function_address"),
       py::arg("options") = ida::decompiler::MicrocodeGenerationOptions{});
}

} // namespace idax::python
