#include "common.hpp"

namespace idax::python {

void bind_xref(py::module_& module) {
    py::module_ xref = module.def_submodule(
        "xref", "Cross-reference descriptors, enumeration, and mutation.");

    py::native_enum<ida::xref::CodeType>(xref, "CodeType", "enum.Enum")
        .value("CALL_FAR", ida::xref::CodeType::CallFar)
        .value("CALL_NEAR", ida::xref::CodeType::CallNear)
        .value("JUMP_FAR", ida::xref::CodeType::JumpFar)
        .value("JUMP_NEAR", ida::xref::CodeType::JumpNear)
        .value("FLOW", ida::xref::CodeType::Flow)
        .finalize();
    py::native_enum<ida::xref::DataType>(xref, "DataType", "enum.Enum")
        .value("OFFSET", ida::xref::DataType::Offset)
        .value("WRITE", ida::xref::DataType::Write)
        .value("READ", ida::xref::DataType::Read)
        .value("TEXT", ida::xref::DataType::Text)
        .value("INFORMATIONAL", ida::xref::DataType::Informational)
        .finalize();
    py::native_enum<ida::xref::ReferenceType>(xref, "ReferenceType", "enum.Enum")
        .value("UNKNOWN", ida::xref::ReferenceType::Unknown)
        .value("FLOW", ida::xref::ReferenceType::Flow)
        .value("CALL_NEAR", ida::xref::ReferenceType::CallNear)
        .value("CALL_FAR", ida::xref::ReferenceType::CallFar)
        .value("JUMP_NEAR", ida::xref::ReferenceType::JumpNear)
        .value("JUMP_FAR", ida::xref::ReferenceType::JumpFar)
        .value("OFFSET", ida::xref::ReferenceType::Offset)
        .value("READ", ida::xref::ReferenceType::Read)
        .value("WRITE", ida::xref::ReferenceType::Write)
        .value("TEXT", ida::xref::ReferenceType::Text)
        .value("INFORMATIONAL", ida::xref::ReferenceType::Informational)
        .finalize();

    py::class_<ida::xref::Reference>(xref, "Reference")
        .def(py::init<>())
        .def_readwrite("from_address", &ida::xref::Reference::from)
        .def_readwrite("to_address", &ida::xref::Reference::to)
        .def_readwrite("is_code", &ida::xref::Reference::is_code)
        .def_readwrite("type", &ida::xref::Reference::type)
        .def_readwrite("user_defined", &ida::xref::Reference::user_defined);
    py::class_<ida::xref::ReferenceRange>(xref, "ReferenceRange")
        .def("__iter__", [](const ida::xref::ReferenceRange& range) {
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>())
        .def("__len__", &ida::xref::ReferenceRange::size)
        .def("__bool__", [](const ida::xref::ReferenceRange& range) {
            return !range.empty();
        });

    xref.def("add_code", [](ida::Address from, ida::Address to,
                              ida::xref::CodeType type) {
        runtime_status("xref.add_code", [=] { return ida::xref::add_code(from, to, type); });
    }, py::arg("from_address"), py::arg("to_address"), py::arg("type"));
    xref.def("add_data", [](ida::Address from, ida::Address to,
                              ida::xref::DataType type) {
        runtime_status("xref.add_data", [=] { return ida::xref::add_data(from, to, type); });
    }, py::arg("from_address"), py::arg("to_address"), py::arg("type"));
    xref.def("remove_code", [](ida::Address from, ida::Address to) {
        runtime_status("xref.remove_code", [=] { return ida::xref::remove_code(from, to); });
    }, py::arg("from_address"), py::arg("to_address"));
    xref.def("remove_data", [](ida::Address from, ida::Address to) {
        runtime_status("xref.remove_data", [=] { return ida::xref::remove_data(from, to); });
    }, py::arg("from_address"), py::arg("to_address"));

    xref.def("refs_from", [](ida::Address address, py::object type) {
        if (type.is_none())
            return runtime_result("xref.refs_from", [=] { return ida::xref::refs_from(address); });
        auto value = type.cast<ida::xref::ReferenceType>();
        return runtime_result("xref.refs_from", [=] { return ida::xref::refs_from(address, value); });
    }, py::arg("address"), py::arg("type") = py::none());
    xref.def("refs_to", [](ida::Address address, py::object type) {
        if (type.is_none())
            return runtime_result("xref.refs_to", [=] { return ida::xref::refs_to(address); });
        auto value = type.cast<ida::xref::ReferenceType>();
        return runtime_result("xref.refs_to", [=] { return ida::xref::refs_to(address, value); });
    }, py::arg("address"), py::arg("type") = py::none());

#define IDAX_PY_XREF_ADDRESS_RESULT(fn)                                   \
    xref.def(#fn, [](ida::Address address) {                              \
        return runtime_result("xref." #fn, [=] { return ida::xref::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_XREF_ADDRESS_RESULT(code_refs_from);
    IDAX_PY_XREF_ADDRESS_RESULT(code_refs_to);
    IDAX_PY_XREF_ADDRESS_RESULT(data_refs_from);
    IDAX_PY_XREF_ADDRESS_RESULT(data_refs_to);
    IDAX_PY_XREF_ADDRESS_RESULT(refs_from_range);
    IDAX_PY_XREF_ADDRESS_RESULT(refs_to_range);
    IDAX_PY_XREF_ADDRESS_RESULT(code_refs_from_range);
    IDAX_PY_XREF_ADDRESS_RESULT(code_refs_to_range);
    IDAX_PY_XREF_ADDRESS_RESULT(data_refs_from_range);
    IDAX_PY_XREF_ADDRESS_RESULT(data_refs_to_range);
#undef IDAX_PY_XREF_ADDRESS_RESULT

#define IDAX_PY_XREF_CLASSIFY(fn)                                        \
    xref.def(#fn, [](ida::xref::ReferenceType type) { return ida::xref::fn(type); }, \
             py::arg("type"))
    IDAX_PY_XREF_CLASSIFY(is_call);
    IDAX_PY_XREF_CLASSIFY(is_jump);
    IDAX_PY_XREF_CLASSIFY(is_flow);
    IDAX_PY_XREF_CLASSIFY(is_data);
    IDAX_PY_XREF_CLASSIFY(is_data_read);
    IDAX_PY_XREF_CLASSIFY(is_data_write);
#undef IDAX_PY_XREF_CLASSIFY
}

} // namespace idax::python
