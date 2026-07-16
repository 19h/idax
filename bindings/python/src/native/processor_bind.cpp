#include "opaque_handle.hpp"

#include <memory>

namespace idax::python {

namespace {

class PythonOutputContext {
public:
    PythonOutputContext()
        : owned_(std::make_unique<ida::processor::OutputContext>()) {}

    PythonOutputContext(ida::processor::OutputContext& output,
                        std::shared_ptr<OpaqueHandleState> state)
        : borrowed_(&output), state_(std::move(state)) {}

    ida::processor::OutputContext& get(std::string_view operation) const {
        if (owned_)
            return *owned_;
        if (borrowed_ != nullptr && state_ && state_->valid)
            return *borrowed_;
        throw_error(ida::Error::conflict(
            "OutputContext is no longer valid", std::string(operation)));
    }

private:
    std::unique_ptr<ida::processor::OutputContext> owned_;
    ida::processor::OutputContext* borrowed_{nullptr};
    std::shared_ptr<OpaqueHandleState> state_;
};

template <typename ResultType, typename... Arguments>
ida::Result<ResultType> invoke_processor_result(
    const py::function& callback,
    std::string_view operation,
    Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<ResultType>();
    } catch (py::error_already_set& error) {
        std::string detail = error.what();
        error.discard_as_unraisable(callback);
        return std::unexpected(ida::Error::internal(
            "Python processor callback failed",
            std::string(operation) + ":" + detail));
    } catch (...) {
        return std::unexpected(ida::Error::internal(
            "Non-Python processor callback failure", std::string(operation)));
    }
}

template <typename ResultType, typename... Arguments>
ResultType invoke_processor_value(
    const py::function& callback,
    std::string_view operation,
    ResultType fallback,
    Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<ResultType>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, std::string(operation).c_str());
        PyErr_WriteUnraisable(callback.ptr());
    }
    return fallback;
}

template <typename... Arguments>
void invoke_processor_void(const py::function& callback,
                           std::string_view operation,
                           Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, std::string(operation).c_str());
        PyErr_WriteUnraisable(callback.ptr());
    }
}

class PythonProcessor final : public ida::processor::Processor {
public:
    using ida::processor::Processor::Processor;

    ida::processor::ProcessorInfo info() const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "info");
        if (!override)
            return {};
        return invoke_processor_value(
            override, "processor.Processor.info",
            ida::processor::ProcessorInfo{});
    }

    ida::Result<int> analyze(ida::Address address) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "analyze");
        if (!override) {
            return std::unexpected(ida::Error::unsupported(
                "Python Processor.analyze override is required"));
        }
        return invoke_processor_result<int>(
            override, "processor.Processor.analyze", address);
    }

    ida::Result<ida::processor::AnalyzeDetails> analyze_with_details(
        ida::Address address) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "analyze_with_details");
        if (!override)
            return ida::processor::Processor::analyze_with_details(address);
        return invoke_processor_result<ida::processor::AnalyzeDetails>(
            override, "processor.Processor.analyze_with_details", address);
    }

    ida::processor::EmulateResult emulate(ida::Address address) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "emulate");
        if (!override)
            return ida::processor::EmulateResult::NotImplemented;
        return invoke_processor_value(
            override, "processor.Processor.emulate",
            ida::processor::EmulateResult::NotImplemented, address);
    }

    void output_instruction(ida::Address address) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "output_instruction");
        if (override)
            invoke_processor_void(
                override, "processor.Processor.output_instruction", address);
    }

    ida::processor::OutputOperandResult output_operand(
        ida::Address address, int operand_index) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "output_operand");
        if (!override)
            return ida::processor::OutputOperandResult::NotImplemented;
        return invoke_processor_value(
            override, "processor.Processor.output_operand",
            ida::processor::OutputOperandResult::NotImplemented,
            address, operand_index);
    }

    ida::processor::OutputInstructionResult output_mnemonic_with_context(
        ida::Address address, ida::processor::OutputContext& output) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "output_mnemonic_with_context");
        if (!override) {
            return ida::processor::Processor::output_mnemonic_with_context(
                address, output);
        }
        auto state = std::make_shared<OpaqueHandleState>();
        auto adapter = std::make_shared<PythonOutputContext>(output, state);
        auto result = invoke_processor_value(
            override, "processor.Processor.output_mnemonic_with_context",
            ida::processor::OutputInstructionResult::NotImplemented,
            address, adapter);
        state->valid = false;
        return result;
    }

    ida::processor::OutputInstructionResult output_instruction_with_context(
        ida::Address address, ida::processor::OutputContext& output) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "output_instruction_with_context");
        if (!override) {
            return ida::processor::Processor::output_instruction_with_context(
                address, output);
        }
        auto state = std::make_shared<OpaqueHandleState>();
        auto adapter = std::make_shared<PythonOutputContext>(output, state);
        auto result = invoke_processor_value(
            override, "processor.Processor.output_instruction_with_context",
            ida::processor::OutputInstructionResult::NotImplemented,
            address, adapter);
        state->valid = false;
        return result;
    }

    ida::processor::OutputOperandResult output_operand_with_context(
        ida::Address address, int operand_index,
        ida::processor::OutputContext& output) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "output_operand_with_context");
        if (!override) {
            return ida::processor::Processor::output_operand_with_context(
                address, operand_index, output);
        }
        auto state = std::make_shared<OpaqueHandleState>();
        auto adapter = std::make_shared<PythonOutputContext>(output, state);
        auto result = invoke_processor_value(
            override, "processor.Processor.output_operand_with_context",
            ida::processor::OutputOperandResult::NotImplemented,
            address, operand_index,
            adapter);
        state->valid = false;
        return result;
    }

#define IDAX_PY_PROCESSOR_VOID(name, argument_type)                       \
    void name(argument_type argument) override {                         \
        py::gil_scoped_acquire acquire;                                  \
        py::function override = py::get_override(this, #name);           \
        if (override)                                                     \
            invoke_processor_void(override, "processor.Processor." #name, \
                                  argument);                              \
    }
    IDAX_PY_PROCESSOR_VOID(on_new_file, std::string_view)
    IDAX_PY_PROCESSOR_VOID(on_old_file, std::string_view)
#undef IDAX_PY_PROCESSOR_VOID

#define IDAX_PY_PROCESSOR_ADDRESS_VALUE(name, result_type, fallback)      \
    result_type name(ida::Address address) override {                     \
        py::gil_scoped_acquire acquire;                                  \
        py::function override = py::get_override(this, #name);           \
        if (!override)                                                    \
            return ida::processor::Processor::name(address);             \
        return invoke_processor_value(override,                          \
            "processor.Processor." #name, fallback, address);            \
    }
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(is_call, int, 0)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(is_return, int, 0)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(may_be_function, int, 0)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(is_indirect_jump, int, 0)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(create_function_frame, bool, false)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(analyze_function_prolog, int, 0)
    IDAX_PY_PROCESSOR_ADDRESS_VALUE(get_return_address_size, int, 0)
#undef IDAX_PY_PROCESSOR_ADDRESS_VALUE

    int is_sane_instruction(ida::Address address,
                            bool no_code_references) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "is_sane_instruction");
        if (!override) {
            return ida::processor::Processor::is_sane_instruction(
                address, no_code_references);
        }
        return invoke_processor_value(
            override, "processor.Processor.is_sane_instruction", 0,
            address, no_code_references);
    }

    int is_basic_block_end(
        ida::Address address, bool call_instruction_stops_block) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "is_basic_block_end");
        if (!override) {
            return ida::processor::Processor::is_basic_block_end(
                address, call_instruction_stops_block);
        }
        return invoke_processor_value(
            override, "processor.Processor.is_basic_block_end", 0,
            address, call_instruction_stops_block);
    }

    int adjust_function_bounds(ida::Address function_start,
                               ida::Address maximum_end,
                               int suggested_result) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "adjust_function_bounds");
        if (!override) {
            return ida::processor::Processor::adjust_function_bounds(
                function_start, maximum_end, suggested_result);
        }
        return invoke_processor_value(
            override, "processor.Processor.adjust_function_bounds",
            suggested_result, function_start, maximum_end, suggested_result);
    }

    int calculate_stack_pointer_delta(
        ida::Address address, std::int64_t& out_delta) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(
            this, "calculate_stack_pointer_delta");
        if (!override) {
            return ida::processor::Processor::calculate_stack_pointer_delta(
                address, out_delta);
        }
        try {
            py::object result = override(address);
            if (result.is_none()) {
                out_delta = 0;
                return 0;
            }
            out_delta = result.cast<std::int64_t>();
            return 1;
        } catch (py::error_already_set& error) {
            error.discard_as_unraisable(override);
            out_delta = 0;
            return 0;
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError,
                            "Stack-pointer delta must be an integer or None");
            PyErr_WriteUnraisable(override.ptr());
            out_delta = 0;
            return 0;
        }
    }

    int detect_switch(ida::Address address,
                      ida::processor::SwitchDescription& out_switch) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "detect_switch");
        if (!override)
            return ida::processor::Processor::detect_switch(address, out_switch);
        try {
            auto result = override(address).cast<
                std::pair<int, std::optional<ida::processor::SwitchDescription>>>();
            if (result.second)
                out_switch = std::move(*result.second);
            return result.first;
        } catch (py::error_already_set& error) {
            error.discard_as_unraisable(override);
            return 0;
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError,
                            "Switch detection returned an invalid value");
            PyErr_WriteUnraisable(override.ptr());
            return 0;
        }
    }

    int calculate_switch_cases(
        ida::Address address,
        const ida::processor::SwitchDescription& description,
        std::vector<ida::processor::SwitchCase>& out_cases) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "calculate_switch_cases");
        if (!override) {
            return ida::processor::Processor::calculate_switch_cases(
                address, description, out_cases);
        }
        try {
            py::object result = override(address, description);
            if (result.is_none())
                return 0;
            out_cases = result.cast<std::vector<ida::processor::SwitchCase>>();
            return 1;
        } catch (py::error_already_set& error) {
            error.discard_as_unraisable(override);
            return 0;
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError,
                            "Switch-case calculation returned an invalid value");
            PyErr_WriteUnraisable(override.ptr());
            return 0;
        }
    }

    int create_switch_references(
        ida::Address address,
        const ida::processor::SwitchDescription& description) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "create_switch_references");
        if (!override) {
            return ida::processor::Processor::create_switch_references(
                address, description);
        }
        return invoke_processor_value(
            override, "processor.Processor.create_switch_references",
            false, address, description) ? 1 : 0;
    }
};

} // namespace

void bind_processor(py::module_& module) {
    py::module_ processor = module.def_submodule(
        "processor", "Custom processor-module descriptors and extension callbacks.");

    py::native_enum<ida::processor::InstructionFeature>(
        processor, "InstructionFeature", "enum.IntFlag")
#define IDAX_PY_PROCESSOR_FEATURE(name, python_name)                     \
        .value(python_name, ida::processor::InstructionFeature::name)
        IDAX_PY_PROCESSOR_FEATURE(None, "NONE")
        IDAX_PY_PROCESSOR_FEATURE(Stop, "STOP")
        IDAX_PY_PROCESSOR_FEATURE(Call, "CALL")
        IDAX_PY_PROCESSOR_FEATURE(Change1, "CHANGE1")
        IDAX_PY_PROCESSOR_FEATURE(Change2, "CHANGE2")
        IDAX_PY_PROCESSOR_FEATURE(Change3, "CHANGE3")
        IDAX_PY_PROCESSOR_FEATURE(Change4, "CHANGE4")
        IDAX_PY_PROCESSOR_FEATURE(Change5, "CHANGE5")
        IDAX_PY_PROCESSOR_FEATURE(Change6, "CHANGE6")
        IDAX_PY_PROCESSOR_FEATURE(Use1, "USE1")
        IDAX_PY_PROCESSOR_FEATURE(Use2, "USE2")
        IDAX_PY_PROCESSOR_FEATURE(Use3, "USE3")
        IDAX_PY_PROCESSOR_FEATURE(Use4, "USE4")
        IDAX_PY_PROCESSOR_FEATURE(Use5, "USE5")
        IDAX_PY_PROCESSOR_FEATURE(Use6, "USE6")
        IDAX_PY_PROCESSOR_FEATURE(Jump, "JUMP")
        IDAX_PY_PROCESSOR_FEATURE(Shift, "SHIFT")
        IDAX_PY_PROCESSOR_FEATURE(HighLevel, "HIGH_LEVEL")
        IDAX_PY_PROCESSOR_FEATURE(Change7, "CHANGE7")
        IDAX_PY_PROCESSOR_FEATURE(Change8, "CHANGE8")
        IDAX_PY_PROCESSOR_FEATURE(Use7, "USE7")
        IDAX_PY_PROCESSOR_FEATURE(Use8, "USE8")
#undef IDAX_PY_PROCESSOR_FEATURE
        .finalize();
    py::native_enum<ida::processor::ProcessorFlag>(
        processor, "ProcessorFlag", "enum.IntFlag")
#define IDAX_PY_PROCESSOR_FLAG(name, python_name)                        \
        .value(python_name, ida::processor::ProcessorFlag::name)
        IDAX_PY_PROCESSOR_FLAG(None, "NONE")
        IDAX_PY_PROCESSOR_FLAG(Segments, "SEGMENTS")
        IDAX_PY_PROCESSOR_FLAG(Use32, "USE32")
        IDAX_PY_PROCESSOR_FLAG(DefaultSeg32, "DEFAULT_SEG32")
        IDAX_PY_PROCESSOR_FLAG(RegisterNames, "REGISTER_NAMES")
        IDAX_PY_PROCESSOR_FLAG(AdjustSegments, "ADJUST_SEGMENTS")
        IDAX_PY_PROCESSOR_FLAG(OctalNumbers, "OCTAL_NUMBERS")
        IDAX_PY_PROCESSOR_FLAG(DecimalNumbers, "DECIMAL_NUMBERS")
        IDAX_PY_PROCESSOR_FLAG(BinaryNumbers, "BINARY_NUMBERS")
        IDAX_PY_PROCESSOR_FLAG(WordInstructions, "WORD_INSTRUCTIONS")
        IDAX_PY_PROCESSOR_FLAG(NoChange, "NO_CHANGE")
        IDAX_PY_PROCESSOR_FLAG(Assemble, "ASSEMBLE")
        IDAX_PY_PROCESSOR_FLAG(AlignData, "ALIGN_DATA")
        IDAX_PY_PROCESSOR_FLAG(TypeInfo, "TYPE_INFO")
        IDAX_PY_PROCESSOR_FLAG(Use64, "USE64")
        IDAX_PY_PROCESSOR_FLAG(SegmentRegistersOther, "SEGMENT_REGISTERS_OTHER")
        IDAX_PY_PROCESSOR_FLAG(StackGrowsUp, "STACK_GROWS_UP")
        IDAX_PY_PROCESSOR_FLAG(BinaryMemory, "BINARY_MEMORY")
        IDAX_PY_PROCESSOR_FLAG(SegmentTranslation, "SEGMENT_TRANSLATION")
        IDAX_PY_PROCESSOR_FLAG(CheckCrossReferences, "CHECK_CROSS_REFERENCES")
        IDAX_PY_PROCESSOR_FLAG(NoSegMove, "NO_SEG_MOVE")
        IDAX_PY_PROCESSOR_FLAG(UseArgTypes, "USE_ARG_TYPES")
        IDAX_PY_PROCESSOR_FLAG(ScaleStackVariables, "SCALE_STACK_VARIABLES")
        IDAX_PY_PROCESSOR_FLAG(DelayedBranches, "DELAYED_BRANCHES")
        IDAX_PY_PROCESSOR_FLAG(AlignInstructions, "ALIGN_INSTRUCTIONS")
        IDAX_PY_PROCESSOR_FLAG(Purging, "PURGING")
        IDAX_PY_PROCESSOR_FLAG(ConditionalInsns, "CONDITIONAL_INSNS")
        IDAX_PY_PROCESSOR_FLAG(UseTbyte, "USE_TBYTE")
        IDAX_PY_PROCESSOR_FLAG(DefaultSeg64, "DEFAULT_SEG64")
        IDAX_PY_PROCESSOR_FLAG(OuterOperands, "OUTER_OPERANDS")
        IDAX_PY_PROCESSOR_FLAG(HexNumbers, "HEX_NUMBERS")
#undef IDAX_PY_PROCESSOR_FLAG
        .finalize();
    py::native_enum<ida::processor::ProcessorFlag2>(
        processor, "ProcessorFlag2", "enum.IntFlag")
#define IDAX_PY_PROCESSOR_FLAG2(name, python_name)                       \
        .value(python_name, ida::processor::ProcessorFlag2::name)
        IDAX_PY_PROCESSOR_FLAG2(None, "NONE")
        IDAX_PY_PROCESSOR_FLAG2(Mappings, "MAPPINGS")
        IDAX_PY_PROCESSOR_FLAG2(IdpOptions, "IDP_OPTIONS")
        IDAX_PY_PROCESSOR_FLAG2(Code16Bit, "CODE16_BIT")
        IDAX_PY_PROCESSOR_FLAG2(Macro, "MACRO")
        IDAX_PY_PROCESSOR_FLAG2(UseCalcRel, "USE_CALC_REL")
        IDAX_PY_PROCESSOR_FLAG2(RelativeBits, "RELATIVE_BITS")
        IDAX_PY_PROCESSOR_FLAG2(Force16BitTypes, "FORCE16_BIT_TYPES")
        IDAX_PY_PROCESSOR_FLAG2(IgnoreIdaGuess, "IGNORE_IDA_GUESS")
#undef IDAX_PY_PROCESSOR_FLAG2
        .finalize();
#define IDAX_PY_PROCESSOR_ENUM(type_name)                                \
    py::native_enum<ida::processor::type_name>(                          \
        processor, #type_name, "enum.Enum")
    IDAX_PY_PROCESSOR_ENUM(SwitchTableKind)
        .value("DENSE", ida::processor::SwitchTableKind::Dense)
        .value("SPARSE", ida::processor::SwitchTableKind::Sparse)
        .value("INDIRECT", ida::processor::SwitchTableKind::Indirect)
        .value("CUSTOM", ida::processor::SwitchTableKind::Custom)
        .finalize();
    IDAX_PY_PROCESSOR_ENUM(EmulateResult)
        .value("NOT_IMPLEMENTED", ida::processor::EmulateResult::NotImplemented)
        .value("SUCCESS", ida::processor::EmulateResult::Success)
        .value("DELETE_INSTRUCTION", ida::processor::EmulateResult::DeleteInsn)
        .finalize();
    IDAX_PY_PROCESSOR_ENUM(OutputOperandResult)
        .value("NOT_IMPLEMENTED", ida::processor::OutputOperandResult::NotImplemented)
        .value("SUCCESS", ida::processor::OutputOperandResult::Success)
        .value("HIDDEN", ida::processor::OutputOperandResult::Hidden)
        .finalize();
    IDAX_PY_PROCESSOR_ENUM(OutputInstructionResult)
        .value("NOT_IMPLEMENTED", ida::processor::OutputInstructionResult::NotImplemented)
        .value("SUCCESS", ida::processor::OutputInstructionResult::Success)
        .finalize();
    IDAX_PY_PROCESSOR_ENUM(AnalyzeOperandKind)
#define IDAX_PY_ANALYZE_KIND(name, python_name)                          \
        .value(python_name, ida::processor::AnalyzeOperandKind::name)
        IDAX_PY_ANALYZE_KIND(None, "NONE")
        IDAX_PY_ANALYZE_KIND(Register, "REGISTER")
        IDAX_PY_ANALYZE_KIND(Immediate, "IMMEDIATE")
        IDAX_PY_ANALYZE_KIND(NearAddress, "NEAR_ADDRESS")
        IDAX_PY_ANALYZE_KIND(FarAddress, "FAR_ADDRESS")
        IDAX_PY_ANALYZE_KIND(DirectMemory, "DIRECT_MEMORY")
        IDAX_PY_ANALYZE_KIND(IndirectMemory, "INDIRECT_MEMORY")
        IDAX_PY_ANALYZE_KIND(Displacement, "DISPLACEMENT")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific0, "PROCESSOR_SPECIFIC0")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific1, "PROCESSOR_SPECIFIC1")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific2, "PROCESSOR_SPECIFIC2")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific3, "PROCESSOR_SPECIFIC3")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific4, "PROCESSOR_SPECIFIC4")
        IDAX_PY_ANALYZE_KIND(ProcessorSpecific5, "PROCESSOR_SPECIFIC5")
#undef IDAX_PY_ANALYZE_KIND
        .finalize();
    IDAX_PY_PROCESSOR_ENUM(OutputTokenKind)
#define IDAX_PY_OUTPUT_KIND(name, python_name)                           \
        .value(python_name, ida::processor::OutputTokenKind::name)
        IDAX_PY_OUTPUT_KIND(PlainText, "PLAIN_TEXT")
        IDAX_PY_OUTPUT_KIND(Mnemonic, "MNEMONIC")
        IDAX_PY_OUTPUT_KIND(Register, "REGISTER")
        IDAX_PY_OUTPUT_KIND(Immediate, "IMMEDIATE")
        IDAX_PY_OUTPUT_KIND(Address, "ADDRESS")
        IDAX_PY_OUTPUT_KIND(Symbol, "SYMBOL")
        IDAX_PY_OUTPUT_KIND(Comment, "COMMENT")
        IDAX_PY_OUTPUT_KIND(Keyword, "KEYWORD")
        IDAX_PY_OUTPUT_KIND(StringLiteral, "STRING_LITERAL")
        IDAX_PY_OUTPUT_KIND(Number, "NUMBER")
        IDAX_PY_OUTPUT_KIND(OperatorSymbol, "OPERATOR_SYMBOL")
        IDAX_PY_OUTPUT_KIND(Punctuation, "PUNCTUATION")
        IDAX_PY_OUTPUT_KIND(Whitespace, "WHITESPACE")
#undef IDAX_PY_OUTPUT_KIND
        .finalize();
#undef IDAX_PY_PROCESSOR_ENUM

#define IDAX_PY_PROCESSOR_VALUE(type_name)                              \
    py::class_<ida::processor::type_name>(processor, #type_name).def(py::init<>())
    IDAX_PY_PROCESSOR_VALUE(RegisterInfo)
        .def_readwrite("name", &ida::processor::RegisterInfo::name)
        .def_readwrite("read_only", &ida::processor::RegisterInfo::read_only);
    IDAX_PY_PROCESSOR_VALUE(InstructionDescriptor)
        .def_readwrite("mnemonic", &ida::processor::InstructionDescriptor::mnemonic)
        .def_readwrite("feature_flags", &ida::processor::InstructionDescriptor::feature_flags)
        .def_readwrite("operand_count", &ida::processor::InstructionDescriptor::operand_count)
        .def_readwrite("description", &ida::processor::InstructionDescriptor::description)
        .def_readwrite("privileged", &ida::processor::InstructionDescriptor::privileged);
    IDAX_PY_PROCESSOR_VALUE(AssemblerInfo)
#define IDAX_BIND_ASSEMBLER_FIELD(field) .def_readwrite(#field, &ida::processor::AssemblerInfo::field)
        IDAX_BIND_ASSEMBLER_FIELD(name)
        IDAX_BIND_ASSEMBLER_FIELD(comment_prefix)
        IDAX_BIND_ASSEMBLER_FIELD(origin)
        IDAX_BIND_ASSEMBLER_FIELD(end_directive)
        IDAX_BIND_ASSEMBLER_FIELD(string_delim)
        IDAX_BIND_ASSEMBLER_FIELD(char_delim)
        IDAX_BIND_ASSEMBLER_FIELD(byte_directive)
        IDAX_BIND_ASSEMBLER_FIELD(word_directive)
        IDAX_BIND_ASSEMBLER_FIELD(dword_directive)
        IDAX_BIND_ASSEMBLER_FIELD(qword_directive)
        IDAX_BIND_ASSEMBLER_FIELD(oword_directive)
        IDAX_BIND_ASSEMBLER_FIELD(float_directive)
        IDAX_BIND_ASSEMBLER_FIELD(double_directive)
        IDAX_BIND_ASSEMBLER_FIELD(tbyte_directive)
        IDAX_BIND_ASSEMBLER_FIELD(align_directive)
        IDAX_BIND_ASSEMBLER_FIELD(include_directive)
        IDAX_BIND_ASSEMBLER_FIELD(public_directive)
        IDAX_BIND_ASSEMBLER_FIELD(weak_directive)
        IDAX_BIND_ASSEMBLER_FIELD(external_directive)
        IDAX_BIND_ASSEMBLER_FIELD(current_ip_symbol)
        IDAX_BIND_ASSEMBLER_FIELD(uppercase_mnemonics)
        IDAX_BIND_ASSEMBLER_FIELD(uppercase_registers)
        IDAX_BIND_ASSEMBLER_FIELD(requires_colon_after_labels)
        IDAX_BIND_ASSEMBLER_FIELD(supports_quoted_names);
#undef IDAX_BIND_ASSEMBLER_FIELD
    IDAX_PY_PROCESSOR_VALUE(ProcessorInfo)
#define IDAX_BIND_PROCESSOR_INFO_FIELD(field) .def_readwrite(#field, &ida::processor::ProcessorInfo::field)
        IDAX_BIND_PROCESSOR_INFO_FIELD(id)
        IDAX_BIND_PROCESSOR_INFO_FIELD(short_names)
        IDAX_BIND_PROCESSOR_INFO_FIELD(long_names)
        IDAX_BIND_PROCESSOR_INFO_FIELD(flags)
        IDAX_BIND_PROCESSOR_INFO_FIELD(flags2)
        IDAX_BIND_PROCESSOR_INFO_FIELD(code_bits_per_byte)
        IDAX_BIND_PROCESSOR_INFO_FIELD(data_bits_per_byte)
        IDAX_BIND_PROCESSOR_INFO_FIELD(registers)
        IDAX_BIND_PROCESSOR_INFO_FIELD(code_segment_register)
        IDAX_BIND_PROCESSOR_INFO_FIELD(data_segment_register)
        IDAX_BIND_PROCESSOR_INFO_FIELD(first_segment_register)
        IDAX_BIND_PROCESSOR_INFO_FIELD(last_segment_register)
        IDAX_BIND_PROCESSOR_INFO_FIELD(segment_register_size)
        IDAX_BIND_PROCESSOR_INFO_FIELD(instructions)
        IDAX_BIND_PROCESSOR_INFO_FIELD(return_icode)
        IDAX_BIND_PROCESSOR_INFO_FIELD(assemblers)
        IDAX_BIND_PROCESSOR_INFO_FIELD(default_bitness);
#undef IDAX_BIND_PROCESSOR_INFO_FIELD
    IDAX_PY_PROCESSOR_VALUE(SwitchDescription)
#define IDAX_BIND_SWITCH_FIELD(field) .def_readwrite(#field, &ida::processor::SwitchDescription::field)
        IDAX_BIND_SWITCH_FIELD(kind)
        IDAX_BIND_SWITCH_FIELD(jump_table)
        IDAX_BIND_SWITCH_FIELD(values_table)
        IDAX_BIND_SWITCH_FIELD(default_target)
        IDAX_BIND_SWITCH_FIELD(idiom_start)
        IDAX_BIND_SWITCH_FIELD(element_base)
        IDAX_BIND_SWITCH_FIELD(low_case_value)
        IDAX_BIND_SWITCH_FIELD(indirect_low_case_value)
        IDAX_BIND_SWITCH_FIELD(case_count)
        IDAX_BIND_SWITCH_FIELD(jump_table_entry_count)
        IDAX_BIND_SWITCH_FIELD(jump_element_size)
        IDAX_BIND_SWITCH_FIELD(value_element_size)
        IDAX_BIND_SWITCH_FIELD(shift)
        IDAX_BIND_SWITCH_FIELD(expression_register)
        IDAX_BIND_SWITCH_FIELD(expression_data_type)
        IDAX_BIND_SWITCH_FIELD(has_default)
        IDAX_BIND_SWITCH_FIELD(default_in_table)
        IDAX_BIND_SWITCH_FIELD(values_signed)
        IDAX_BIND_SWITCH_FIELD(subtract_values)
        IDAX_BIND_SWITCH_FIELD(self_relative)
        IDAX_BIND_SWITCH_FIELD(inverted)
        IDAX_BIND_SWITCH_FIELD(user_defined);
#undef IDAX_BIND_SWITCH_FIELD
    IDAX_PY_PROCESSOR_VALUE(SwitchCase)
        .def_readwrite("values", &ida::processor::SwitchCase::values)
        .def_readwrite("target", &ida::processor::SwitchCase::target);
    IDAX_PY_PROCESSOR_VALUE(AnalyzeOperand)
#define IDAX_BIND_ANALYZE_FIELD(field) .def_readwrite(#field, &ida::processor::AnalyzeOperand::field)
        IDAX_BIND_ANALYZE_FIELD(index)
        IDAX_BIND_ANALYZE_FIELD(kind)
        IDAX_BIND_ANALYZE_FIELD(has_register)
        IDAX_BIND_ANALYZE_FIELD(register_index)
        IDAX_BIND_ANALYZE_FIELD(has_immediate)
        IDAX_BIND_ANALYZE_FIELD(immediate_value)
        IDAX_BIND_ANALYZE_FIELD(has_target_address)
        IDAX_BIND_ANALYZE_FIELD(target_address)
        IDAX_BIND_ANALYZE_FIELD(has_displacement)
        IDAX_BIND_ANALYZE_FIELD(displacement)
        IDAX_BIND_ANALYZE_FIELD(data_type_code)
        IDAX_BIND_ANALYZE_FIELD(processor_flags);
#undef IDAX_BIND_ANALYZE_FIELD
    IDAX_PY_PROCESSOR_VALUE(AnalyzeDetails)
        .def_readwrite("instruction_code", &ida::processor::AnalyzeDetails::instruction_code)
        .def_readwrite("size", &ida::processor::AnalyzeDetails::size)
        .def_readwrite("operands", &ida::processor::AnalyzeDetails::operands);
    IDAX_PY_PROCESSOR_VALUE(OutputToken)
        .def_readwrite("kind", &ida::processor::OutputToken::kind)
        .def_readwrite("text", &ida::processor::OutputToken::text);
#undef IDAX_PY_PROCESSOR_VALUE

    py::class_<PythonOutputContext, std::shared_ptr<PythonOutputContext>>(
        processor, "OutputContext")
        .def(py::init<>())
        .def("token", [](PythonOutputContext& self,
            ida::processor::OutputTokenKind kind, std::string text)
            -> PythonOutputContext& {
            self.get("processor.OutputContext.token").token(kind, text);
            return self;
        }, py::arg("kind"), py::arg("text"), py::return_value_policy::reference_internal)
#define IDAX_PY_OUTPUT_TEXT_METHOD(name)                                 \
        .def(#name, [](PythonOutputContext& self, std::string text)      \
            -> PythonOutputContext& {                                   \
            self.get("processor.OutputContext." #name).name(text);      \
            return self;                                                \
        }, py::arg("text"), py::return_value_policy::reference_internal)
        IDAX_PY_OUTPUT_TEXT_METHOD(append)
        IDAX_PY_OUTPUT_TEXT_METHOD(mnemonic)
        IDAX_PY_OUTPUT_TEXT_METHOD(register_name)
        IDAX_PY_OUTPUT_TEXT_METHOD(symbol)
        IDAX_PY_OUTPUT_TEXT_METHOD(keyword)
        IDAX_PY_OUTPUT_TEXT_METHOD(comment)
        IDAX_PY_OUTPUT_TEXT_METHOD(number)
        IDAX_PY_OUTPUT_TEXT_METHOD(operator_symbol)
        IDAX_PY_OUTPUT_TEXT_METHOD(punctuation)
#undef IDAX_PY_OUTPUT_TEXT_METHOD
        .def("whitespace", [](PythonOutputContext& self, std::string text)
            -> PythonOutputContext& {
            self.get("processor.OutputContext.whitespace").whitespace(text);
            return self;
        }, py::arg("text") = " ", py::return_value_policy::reference_internal)
        .def("string_literal", [](PythonOutputContext& self,
            std::string text, std::string quote) -> PythonOutputContext& {
            if (quote.size() != 1)
                throw_error(ida::Error::validation("Quote must be one character"));
            self.get("processor.OutputContext.string_literal")
                .string_literal(text, quote.front());
            return self;
        }, py::arg("text"), py::arg("quote") = "\"",
           py::return_value_policy::reference_internal)
        .def("immediate", [](PythonOutputContext& self,
            std::int64_t value, int radix) -> PythonOutputContext& {
            self.get("processor.OutputContext.immediate").immediate(value, radix);
            return self;
        }, py::arg("value"), py::arg("radix") = 16,
           py::return_value_policy::reference_internal)
        .def("address", [](PythonOutputContext& self,
            ida::Address address) -> PythonOutputContext& {
            self.get("processor.OutputContext.address").address(address);
            return self;
        }, py::arg("address"), py::return_value_policy::reference_internal)
        .def("character", [](PythonOutputContext& self,
            std::string character) -> PythonOutputContext& {
            if (character.size() != 1)
                throw_error(ida::Error::validation("Character must have length one"));
            self.get("processor.OutputContext.character").character(character.front());
            return self;
        }, py::arg("character"), py::return_value_policy::reference_internal)
#define IDAX_PY_OUTPUT_NOARG_CHAIN(name)                                 \
        .def(#name, [](PythonOutputContext& self) -> PythonOutputContext& { \
            self.get("processor.OutputContext." #name).name();           \
            return self;                                                 \
        }, py::return_value_policy::reference_internal)
        IDAX_PY_OUTPUT_NOARG_CHAIN(space)
        IDAX_PY_OUTPUT_NOARG_CHAIN(comma)
#undef IDAX_PY_OUTPUT_NOARG_CHAIN
        .def("clear", [](PythonOutputContext& self) {
            self.get("processor.OutputContext.clear").clear();
        })
        .def_property_readonly("empty", [](const PythonOutputContext& self) {
            return self.get("processor.OutputContext.empty").empty();
        })
        .def_property_readonly("text", [](const PythonOutputContext& self) {
            return self.get("processor.OutputContext.text").text();
        })
        .def_property_readonly("tokens", [](const PythonOutputContext& self) {
            return self.get("processor.OutputContext.tokens").tokens();
        })
        .def("take", [](PythonOutputContext& self) {
            return self.get("processor.OutputContext.take").take();
        })
        .def("take_tokens", [](PythonOutputContext& self) {
            return self.get("processor.OutputContext.take_tokens").take_tokens();
        });

    py::class_<ida::processor::Processor, PythonProcessor,
               std::shared_ptr<ida::processor::Processor>>(processor, "Processor")
        .def(py::init<>())
        .def("info", &ida::processor::Processor::info)
        .def("analyze", [](ida::processor::Processor& self, ida::Address address) {
            return unwrap(self.analyze(address));
        }, py::arg("address"))
        .def("analyze_with_details", [](ida::processor::Processor& self,
            ida::Address address) {
            return unwrap(self.analyze_with_details(address));
        }, py::arg("address"))
        .def("emulate", &ida::processor::Processor::emulate, py::arg("address"))
        .def("output_instruction", &ida::processor::Processor::output_instruction,
             py::arg("address"))
        .def("output_operand", &ida::processor::Processor::output_operand,
             py::arg("address"), py::arg("operand_index"))
        .def("output_mnemonic_with_context", [](ida::processor::Processor& self,
            ida::Address address, PythonOutputContext& output) {
            return self.output_mnemonic_with_context(
                address, output.get("processor.Processor.output_mnemonic_with_context"));
        }, py::arg("address"), py::arg("output"))
        .def("output_instruction_with_context", [](ida::processor::Processor& self,
            ida::Address address, PythonOutputContext& output) {
            return self.output_instruction_with_context(
                address, output.get("processor.Processor.output_instruction_with_context"));
        }, py::arg("address"), py::arg("output"))
        .def("output_operand_with_context", [](ida::processor::Processor& self,
            ida::Address address, int index, PythonOutputContext& output) {
            return self.output_operand_with_context(
                address, index,
                output.get("processor.Processor.output_operand_with_context"));
        }, py::arg("address"), py::arg("operand_index"), py::arg("output"))
        .def("on_new_file", &ida::processor::Processor::on_new_file,
             py::arg("filename"))
        .def("on_old_file", &ida::processor::Processor::on_old_file,
             py::arg("filename"))
#define IDAX_PY_PROCESSOR_ADDRESS_METHOD(name)                           \
        .def(#name, &ida::processor::Processor::name, py::arg("address"))
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(is_call)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(is_return)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(may_be_function)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(is_indirect_jump)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(create_function_frame)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(analyze_function_prolog)
        IDAX_PY_PROCESSOR_ADDRESS_METHOD(get_return_address_size)
#undef IDAX_PY_PROCESSOR_ADDRESS_METHOD
        .def("is_sane_instruction", &ida::processor::Processor::is_sane_instruction,
             py::arg("address"), py::arg("no_code_references"))
        .def("is_basic_block_end", &ida::processor::Processor::is_basic_block_end,
             py::arg("address"), py::arg("call_instruction_stops_block"))
        .def("adjust_function_bounds", &ida::processor::Processor::adjust_function_bounds,
             py::arg("function_start"), py::arg("maximum_end"),
             py::arg("suggested_result"))
        .def("calculate_stack_pointer_delta", [](ida::processor::Processor& self,
            ida::Address address) -> std::optional<std::int64_t> {
            std::int64_t delta = 0;
            if (self.calculate_stack_pointer_delta(address, delta) == 0)
                return std::nullopt;
            return delta;
        }, py::arg("address"))
        .def("detect_switch", [](ida::processor::Processor& self,
            ida::Address address) {
            ida::processor::SwitchDescription description;
            const int status = self.detect_switch(address, description);
            std::optional<ida::processor::SwitchDescription> result;
            if (status > 0)
                result = std::move(description);
            return std::make_pair(status, std::move(result));
        }, py::arg("address"))
        .def("calculate_switch_cases", [](ida::processor::Processor& self,
            ida::Address address,
            const ida::processor::SwitchDescription& description)
            -> std::optional<std::vector<ida::processor::SwitchCase>> {
            std::vector<ida::processor::SwitchCase> cases;
            if (self.calculate_switch_cases(address, description, cases) == 0)
                return std::nullopt;
            return cases;
        }, py::arg("address"), py::arg("description"))
        .def("create_switch_references", [](ida::processor::Processor& self,
            ida::Address address,
            const ida::processor::SwitchDescription& description) {
            return self.create_switch_references(address, description) != 0;
        }, py::arg("address"), py::arg("description"));
}

} // namespace idax::python
