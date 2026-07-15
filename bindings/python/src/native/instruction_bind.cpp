#include "common.hpp"

namespace idax::python {

void bind_instruction(py::module_& module) {
    py::module_ instruction = module.def_submodule(
        "instruction", "Instruction decode, operands, display, and xrefs.");

    py::native_enum<ida::instruction::OperandType>(
        instruction, "OperandType", "enum.Enum")
        .value("NONE", ida::instruction::OperandType::None)
        .value("REGISTER", ida::instruction::OperandType::Register)
        .value("MEMORY_DIRECT", ida::instruction::OperandType::MemoryDirect)
        .value("MEMORY_PHRASE", ida::instruction::OperandType::MemoryPhrase)
        .value("MEMORY_DISPLACEMENT", ida::instruction::OperandType::MemoryDisplacement)
        .value("IMMEDIATE", ida::instruction::OperandType::Immediate)
        .value("FAR_ADDRESS", ida::instruction::OperandType::FarAddress)
        .value("NEAR_ADDRESS", ida::instruction::OperandType::NearAddress)
        .value("PROCESSOR_SPECIFIC_0", ida::instruction::OperandType::ProcessorSpecific0)
        .value("PROCESSOR_SPECIFIC_1", ida::instruction::OperandType::ProcessorSpecific1)
        .value("PROCESSOR_SPECIFIC_2", ida::instruction::OperandType::ProcessorSpecific2)
        .value("PROCESSOR_SPECIFIC_3", ida::instruction::OperandType::ProcessorSpecific3)
        .value("PROCESSOR_SPECIFIC_4", ida::instruction::OperandType::ProcessorSpecific4)
        .value("PROCESSOR_SPECIFIC_5", ida::instruction::OperandType::ProcessorSpecific5)
        .finalize();
    py::native_enum<ida::instruction::OperandFormat>(
        instruction, "OperandFormat", "enum.Enum")
        .value("DEFAULT", ida::instruction::OperandFormat::Default)
        .value("HEX", ida::instruction::OperandFormat::Hex)
        .value("DECIMAL", ida::instruction::OperandFormat::Decimal)
        .value("OCTAL", ida::instruction::OperandFormat::Octal)
        .value("BINARY", ida::instruction::OperandFormat::Binary)
        .value("CHARACTER", ida::instruction::OperandFormat::Character)
        .value("FLOAT", ida::instruction::OperandFormat::Float)
        .value("OFFSET", ida::instruction::OperandFormat::Offset)
        .value("STACK_VARIABLE", ida::instruction::OperandFormat::StackVariable)
        .finalize();
    py::native_enum<ida::instruction::RegisterCategory>(
        instruction, "RegisterCategory", "enum.Enum")
        .value("UNKNOWN", ida::instruction::RegisterCategory::Unknown)
        .value("GENERAL_PURPOSE", ida::instruction::RegisterCategory::GeneralPurpose)
        .value("SEGMENT", ida::instruction::RegisterCategory::Segment)
        .value("FLOATING_POINT", ida::instruction::RegisterCategory::FloatingPoint)
        .value("VECTOR", ida::instruction::RegisterCategory::Vector)
        .value("MASK", ida::instruction::RegisterCategory::Mask)
        .value("CONTROL", ida::instruction::RegisterCategory::Control)
        .value("DEBUG", ida::instruction::RegisterCategory::Debug)
        .value("OTHER", ida::instruction::RegisterCategory::Other)
        .finalize();
    py::class_<ida::instruction::StructOffsetPath>(instruction, "StructOffsetPath")
        .def(py::init<>())
        .def_readwrite("structure_name",
                       &ida::instruction::StructOffsetPath::structure_name)
        .def_readwrite("member_names",
                       &ida::instruction::StructOffsetPath::member_names)
        .def_readwrite("delta", &ida::instruction::StructOffsetPath::delta);
    py::class_<ida::instruction::OperandEnum>(instruction, "OperandEnum")
        .def(py::init<>())
        .def_readwrite("name", &ida::instruction::OperandEnum::name)
        .def_readwrite("serial", &ida::instruction::OperandEnum::serial);
    py::class_<ida::instruction::Operand>(instruction, "Operand")
        .def_property_readonly("index", &ida::instruction::Operand::index)
        .def_property_readonly("type", &ida::instruction::Operand::type)
        .def_property_readonly("is_register", &ida::instruction::Operand::is_register)
        .def_property_readonly("is_immediate", &ida::instruction::Operand::is_immediate)
        .def_property_readonly("is_memory", &ida::instruction::Operand::is_memory)
        .def_property_readonly("register_id", &ida::instruction::Operand::register_id)
        .def_property_readonly("value", &ida::instruction::Operand::value)
        .def_property_readonly("target_address",
                               &ida::instruction::Operand::target_address)
        .def_property_readonly("displacement", &ida::instruction::Operand::displacement)
        .def_property_readonly("byte_width", &ida::instruction::Operand::byte_width)
        .def_property_readonly("encoded_value_byte_offset",
                               &ida::instruction::Operand::encoded_value_byte_offset)
        .def_property_readonly(
            "secondary_encoded_value_byte_offset",
            &ida::instruction::Operand::secondary_encoded_value_byte_offset)
        .def_property_readonly("register_name", &ida::instruction::Operand::register_name)
        .def_property_readonly("is_read", &ida::instruction::Operand::is_read)
        .def_property_readonly("is_written", &ida::instruction::Operand::is_written)
        .def_property_readonly("register_category",
                               &ida::instruction::Operand::register_category)
        .def_property_readonly("is_vector_register",
                               &ida::instruction::Operand::is_vector_register)
        .def_property_readonly("is_mask_register",
                               &ida::instruction::Operand::is_mask_register);
    py::class_<ida::instruction::Instruction>(instruction, "Instruction")
        .def_property_readonly("address", &ida::instruction::Instruction::address)
        .def_property_readonly("size", &ida::instruction::Instruction::size)
        .def_property_readonly("opcode", &ida::instruction::Instruction::opcode)
        .def_property_readonly("mnemonic", &ida::instruction::Instruction::mnemonic)
        .def_property_readonly("operand_count",
                               &ida::instruction::Instruction::operand_count)
        .def("operand", [](const ida::instruction::Instruction& self,
                            std::size_t index) {
            return unwrap(self.operand(index));
        }, py::arg("index"))
        .def_property_readonly("operands", [](const ida::instruction::Instruction& self) {
            return self.operands();
        });

#define IDAX_PY_INSTRUCTION_ADDRESS_RESULT(fn)                           \
    instruction.def(#fn, [](ida::Address address) {                      \
        return runtime_result("instruction." #fn, [=] { return ida::instruction::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(decode);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(create);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(text);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(code_refs_from);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(data_refs_from);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(call_targets);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(jump_targets);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(next);
    IDAX_PY_INSTRUCTION_ADDRESS_RESULT(prev);
#undef IDAX_PY_INSTRUCTION_ADDRESS_RESULT

#define IDAX_PY_INSTRUCTION_OPERAND_STATUS(fn)                           \
    instruction.def(#fn, [](ida::Address address, int operand_index) {   \
        runtime_status("instruction." #fn, [=] {                         \
            return ida::instruction::fn(address, operand_index);         \
        });                                                               \
    }, py::arg("address"), py::arg("operand_index"))
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_hex);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_decimal);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_octal);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_binary);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_character);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_float);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(set_operand_stack_variable);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(clear_operand_representation);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(toggle_operand_sign);
    IDAX_PY_INSTRUCTION_OPERAND_STATUS(toggle_operand_negate);
#undef IDAX_PY_INSTRUCTION_OPERAND_STATUS
    instruction.def("set_operand_format", [](ida::Address address,
                                               int operand_index,
                                               ida::instruction::OperandFormat format,
                                               ida::Address base) {
        runtime_status("instruction.set_operand_format", [=] {
            return ida::instruction::set_operand_format(
                address, operand_index, format, base);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("format"),
       py::arg("base") = 0);
    instruction.def("set_operand_offset", [](ida::Address address,
                                               int operand_index,
                                               ida::Address base) {
        runtime_status("instruction.set_operand_offset", [=] {
            return ida::instruction::set_operand_offset(address, operand_index, base);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("base") = 0);
    instruction.def("set_operand_enum", [](ida::Address address, int operand_index,
                                             std::string enum_name,
                                             std::uint8_t serial) {
        runtime_status("instruction.set_operand_enum", [&] {
            return ida::instruction::set_operand_enum(
                address, operand_index, enum_name, serial);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("enum_name"),
       py::arg("serial") = 0);
#define IDAX_PY_INSTRUCTION_OPERAND_RESULT(fn)                           \
    instruction.def(#fn, [](ida::Address address, int operand_index) {   \
        return runtime_result("instruction." #fn, [=] {                  \
            return ida::instruction::fn(address, operand_index);         \
        });                                                               \
    }, py::arg("address"), py::arg("operand_index"))
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_enum);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_struct_offset_path);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_struct_offset_path_names);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(get_forced_operand);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_text);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_byte_width);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_register_name);
    IDAX_PY_INSTRUCTION_OPERAND_RESULT(operand_register_category);
#undef IDAX_PY_INSTRUCTION_OPERAND_RESULT
    instruction.def("set_operand_struct_offset", [](
        ida::Address address, int operand_index, std::string structure_name,
        ida::AddressDelta delta) {
        runtime_status("instruction.set_operand_struct_offset", [&] {
            return ida::instruction::set_operand_struct_offset(
                address, operand_index, structure_name, delta);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("structure_name"),
       py::arg("delta") = 0);
    instruction.def("ensure_operand_struct_member_offset", [](
        ida::Address address, int operand_index, std::string structure_name,
        std::size_t member_byte_offset, ida::AddressDelta delta) {
        return runtime_result("instruction.ensure_operand_struct_member_offset", [&] {
            return ida::instruction::ensure_operand_struct_member_offset(
                address, operand_index, structure_name, member_byte_offset, delta);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("structure_name"),
       py::arg("member_byte_offset"), py::arg("delta") = 0);
    instruction.def("set_operand_based_struct_offset", [](
        ida::Address address, int operand_index, ida::Address operand_value,
        ida::Address base) {
        runtime_status("instruction.set_operand_based_struct_offset", [=] {
            return ida::instruction::set_operand_based_struct_offset(
                address, operand_index, operand_value, base);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("operand_value"),
       py::arg("base"));
    instruction.def("set_forced_operand", [](ida::Address address,
                                               int operand_index,
                                               std::string text) {
        runtime_status("instruction.set_forced_operand", [&] {
            return ida::instruction::set_forced_operand(address, operand_index, text);
        });
    }, py::arg("address"), py::arg("operand_index"), py::arg("text"));

#define IDAX_PY_INSTRUCTION_PREDICATE(fn)                                \
    instruction.def(#fn, [](ida::Address address) {                      \
        return runtime_call("instruction." #fn, [=] { return ida::instruction::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_INSTRUCTION_PREDICATE(has_fall_through);
    IDAX_PY_INSTRUCTION_PREDICATE(is_call);
    IDAX_PY_INSTRUCTION_PREDICATE(is_return);
    IDAX_PY_INSTRUCTION_PREDICATE(is_jump);
    IDAX_PY_INSTRUCTION_PREDICATE(is_conditional_jump);
#undef IDAX_PY_INSTRUCTION_PREDICATE
}

} // namespace idax::python
