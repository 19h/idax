#include "common.hpp"

namespace idax::python {

void bind_offset(py::module_& module) {
    py::module_ offset = module.def_submodule(
        "offset", "Opaque operand offset and reference semantics.");

    py::native_enum<ida::offset::ReferenceKind>(
        offset, "ReferenceKind", "enum.Enum")
        .value("OFFSET8", ida::offset::ReferenceKind::Offset8)
        .value("OFFSET16", ida::offset::ReferenceKind::Offset16)
        .value("OFFSET32", ida::offset::ReferenceKind::Offset32)
        .value("OFFSET64", ida::offset::ReferenceKind::Offset64)
        .value("LOW8", ida::offset::ReferenceKind::Low8)
        .value("LOW16", ida::offset::ReferenceKind::Low16)
        .value("LOW32", ida::offset::ReferenceKind::Low32)
        .value("HIGH8", ida::offset::ReferenceKind::High8)
        .value("HIGH16", ida::offset::ReferenceKind::High16)
        .value("HIGH32", ida::offset::ReferenceKind::High32)
        .value("CUSTOM", ida::offset::ReferenceKind::Custom)
        .finalize();

    py::class_<ida::offset::ReferenceType>(offset, "ReferenceType")
        .def(py::init<>())
        .def(py::init<ida::offset::ReferenceKind, std::string>(),
             py::arg("kind"), py::arg("custom_name") = std::string{})
        .def_readwrite("kind", &ida::offset::ReferenceType::kind)
        .def_readwrite("custom_name", &ida::offset::ReferenceType::custom_name);

    py::class_<ida::offset::ReferenceTypeDescriptor>(
        offset, "ReferenceTypeDescriptor")
        .def_readonly("type", &ida::offset::ReferenceTypeDescriptor::type)
        .def_readonly("name", &ida::offset::ReferenceTypeDescriptor::name)
        .def_readonly("description",
                      &ida::offset::ReferenceTypeDescriptor::description)
        .def_readonly("target_optional",
                      &ida::offset::ReferenceTypeDescriptor::target_optional);

    py::class_<ida::offset::OperandLocation>(offset, "OperandLocation")
        .def(py::init<>())
        .def(py::init<std::size_t, bool>(),
             py::arg("index"), py::arg("outer") = false)
        .def_readwrite("index", &ida::offset::OperandLocation::index)
        .def_readwrite("outer", &ida::offset::OperandLocation::outer);

    py::class_<ida::offset::ReferenceOptions>(offset, "ReferenceOptions")
        .def(py::init<>())
        .def_readwrite("relative_virtual_address",
                       &ida::offset::ReferenceOptions::relative_virtual_address)
        .def_readwrite("allow_past_end",
                       &ida::offset::ReferenceOptions::allow_past_end)
        .def_readwrite("suppress_base_reference",
                       &ida::offset::ReferenceOptions::suppress_base_reference)
        .def_readwrite("subtract_operand",
                       &ida::offset::ReferenceOptions::subtract_operand)
        .def_readwrite("sign_extend_operand",
                       &ida::offset::ReferenceOptions::sign_extend_operand)
        .def_readwrite("accept_zero",
                       &ida::offset::ReferenceOptions::accept_zero)
        .def_readwrite("reject_all_ones",
                       &ida::offset::ReferenceOptions::reject_all_ones)
        .def_readwrite("self_relative",
                       &ida::offset::ReferenceOptions::self_relative)
        .def_readwrite("ignore_fixup",
                       &ida::offset::ReferenceOptions::ignore_fixup);

    py::class_<ida::offset::ReferenceInfo>(offset, "ReferenceInfo")
        .def(py::init<>())
        .def_readwrite("type", &ida::offset::ReferenceInfo::type)
        .def_readwrite("target", &ida::offset::ReferenceInfo::target)
        .def_readwrite("base", &ida::offset::ReferenceInfo::base)
        .def_readwrite("target_delta", &ida::offset::ReferenceInfo::target_delta)
        .def_readwrite("options", &ida::offset::ReferenceInfo::options);

    py::native_enum<ida::offset::ExpressionComplexity>(
        offset, "ExpressionComplexity", "enum.Enum")
        .value("SIMPLE", ida::offset::ExpressionComplexity::Simple)
        .value("COMPLEX", ida::offset::ExpressionComplexity::Complex)
        .finalize();

    py::class_<ida::offset::RenderOptions>(offset, "RenderOptions")
        .def(py::init<>())
        .def(py::init<bool, bool>(),
             py::arg("append_zero_field") = false,
             py::arg("avoid_dummy_names") = false)
        .def_readwrite("append_zero_field",
                       &ida::offset::RenderOptions::append_zero_field)
        .def_readwrite("avoid_dummy_names",
                       &ida::offset::RenderOptions::avoid_dummy_names);

    py::class_<ida::offset::RenderedExpression>(offset, "RenderedExpression")
        .def_readonly("text", &ida::offset::RenderedExpression::text)
        .def_readonly("complexity",
                      &ida::offset::RenderedExpression::complexity);

    py::class_<ida::offset::ReferenceCalculation>(
        offset, "ReferenceCalculation")
        .def_readonly("target", &ida::offset::ReferenceCalculation::target)
        .def_readonly("base", &ida::offset::ReferenceCalculation::base);

    offset.def("reference_types", [] {
        return runtime_result("offset.reference_types",
                              ida::offset::reference_types);
    });
    offset.def("default_reference_type", [](ida::Address address) {
        return runtime_result("offset.default_reference_type", [=] {
            return ida::offset::default_reference_type(address);
        });
    }, py::arg("address"));
    offset.def("reference_info", [](ida::Address address,
                                      ida::offset::OperandLocation location) {
        return runtime_result("offset.reference_info", [=] {
            return ida::offset::reference_info(address, location);
        });
    }, py::arg("address"), py::arg("location"));
    offset.def("apply_reference", [](ida::Address address,
                                       ida::offset::OperandLocation location,
                                       const ida::offset::ReferenceInfo& info) {
        runtime_status("offset.apply_reference", [&] {
            return ida::offset::apply_reference(address, location, info);
        });
    }, py::arg("address"), py::arg("location"), py::arg("info"));
    offset.def("remove_reference", [](ida::Address address,
                                        ida::offset::OperandLocation location) {
        return runtime_result("offset.remove_reference", [=] {
            return ida::offset::remove_reference(address, location);
        });
    }, py::arg("address"), py::arg("location"));
    offset.def("render_stored_expression", [](
                   ida::Address address,
                   ida::offset::OperandLocation location,
                   ida::Address from,
                   ida::AddressDelta operand_value,
                   ida::offset::RenderOptions options) {
        return runtime_result("offset.render_stored_expression", [=] {
            return ida::offset::render_stored_expression(
                address, location, from, operand_value, options);
        });
    }, py::arg("address"), py::arg("location"), py::arg("from_address"),
       py::arg("operand_value"), py::arg("options") = ida::offset::RenderOptions{});
    offset.def("render_expression", [](
                   ida::Address address,
                   ida::offset::OperandLocation location,
                   const ida::offset::ReferenceInfo& info,
                   ida::Address from,
                   ida::AddressDelta operand_value,
                   ida::offset::RenderOptions options) {
        return runtime_result("offset.render_expression", [&] {
            return ida::offset::render_expression(
                address, location, info, from, operand_value, options);
        });
    }, py::arg("address"), py::arg("location"), py::arg("info"),
       py::arg("from_address"), py::arg("operand_value"),
       py::arg("options") = ida::offset::RenderOptions{});
    offset.def("possible_offset32_target", [](ida::Address address) {
        return runtime_result("offset.possible_offset32_target", [=] {
            return ida::offset::possible_offset32_target(address);
        });
    }, py::arg("address"));
    offset.def("calculate_offset_base", [](
                   ida::Address address,
                   ida::offset::OperandLocation location) {
        return runtime_result("offset.calculate_offset_base", [=] {
            return ida::offset::calculate_offset_base(address, location);
        });
    }, py::arg("address"), py::arg("location"));
    offset.def("probable_base", [](ida::Address address,
                                     std::uint64_t operand_value) {
        return runtime_result("offset.probable_base", [=] {
            return ida::offset::probable_base(address, operand_value);
        });
    }, py::arg("address"), py::arg("operand_value"));
    offset.def("calculate_reference", [](
                   ida::Address from,
                   const ida::offset::ReferenceInfo& info,
                   ida::AddressDelta operand_value) {
        return runtime_result("offset.calculate_reference", [&] {
            return ida::offset::calculate_reference(from, info, operand_value);
        });
    }, py::arg("from_address"), py::arg("info"), py::arg("operand_value"));
    offset.def("add_operand_data_references", [](
                   ida::Address address,
                   ida::offset::OperandLocation location,
                   ida::xref::DataType type) {
        return runtime_result("offset.add_operand_data_references", [=] {
            return ida::offset::add_operand_data_references(
                address, location, type);
        });
    }, py::arg("instruction_address"), py::arg("location"),
       py::arg("type") = ida::xref::DataType::Offset);
    offset.def("calculate_base_value", [](ida::Address target,
                                            ida::Address base) {
        return runtime_result("offset.calculate_base_value", [=] {
            return ida::offset::calculate_base_value(target, base);
        });
    }, py::arg("target"), py::arg("base"));
}

} // namespace idax::python
