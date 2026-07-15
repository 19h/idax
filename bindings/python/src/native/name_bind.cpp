#include "common.hpp"

namespace idax::python {

void bind_name(py::module_& module) {
    py::module_ name = module.def_submodule(
        "name", "Naming, demangling, inventory, and name properties.");

    py::native_enum<ida::name::DemangleForm>(
        name, "DemangleForm", "enum.Enum")
        .value("SHORT", ida::name::DemangleForm::Short)
        .value("LONG", ida::name::DemangleForm::Long)
        .value("FULL", ida::name::DemangleForm::Full)
        .finalize();

    py::class_<ida::name::Entry>(name, "Entry")
        .def(py::init<>())
        .def_readwrite("address", &ida::name::Entry::address)
        .def_readwrite("name", &ida::name::Entry::name)
        .def_readwrite("user_defined", &ida::name::Entry::user_defined)
        .def_readwrite("auto_generated", &ida::name::Entry::auto_generated);
    py::class_<ida::name::ListOptions>(name, "ListOptions")
        .def(py::init<>())
        .def_readwrite("start", &ida::name::ListOptions::start)
        .def_readwrite("end", &ida::name::ListOptions::end)
        .def_readwrite("include_user_defined",
                       &ida::name::ListOptions::include_user_defined)
        .def_readwrite("include_auto_generated",
                       &ida::name::ListOptions::include_auto_generated);

#define IDAX_PY_NAME_ADDRESS_TEXT_STATUS(fn)                               \
    name.def(#fn, [](ida::Address address, std::string text) {             \
        runtime_status("name." #fn, [&] { return ida::name::fn(address, text); }); \
    }, py::arg("address"), py::arg("name"))
    IDAX_PY_NAME_ADDRESS_TEXT_STATUS(set);
    IDAX_PY_NAME_ADDRESS_TEXT_STATUS(force_set);
#undef IDAX_PY_NAME_ADDRESS_TEXT_STATUS

    name.def("remove", [](ida::Address address) {
        runtime_status("name.remove", [=] { return ida::name::remove(address); });
    }, py::arg("address"));
    name.def("get", [](ida::Address address) {
        return runtime_result("name.get", [=] { return ida::name::get(address); });
    }, py::arg("address"));
    name.def("demangled", [](py::object value, ida::name::DemangleForm form) {
        if (py::isinstance<py::str>(value)) {
            std::string symbol = value.cast<std::string>();
            return runtime_result("name.demangled", [&] {
                return ida::name::demangled(symbol, form);
            });
        }
        ida::Address address = value.cast<ida::Address>();
        return runtime_result("name.demangled", [=] {
            return ida::name::demangled(address, form);
        });
    }, py::arg("value"), py::arg("form") = ida::name::DemangleForm::Short);
    name.def("resolve", [](std::string text, ida::Address context) {
        return runtime_result("name.resolve", [&] {
            return ida::name::resolve(text, context);
        });
    }, py::arg("name"), py::arg("context") = ida::BadAddress);
    name.def("all", [](const ida::name::ListOptions& options) {
        return runtime_result("name.all", [&] { return ida::name::all(options); });
    }, py::arg("options") = ida::name::ListOptions{});
    name.def("all_user_defined", [](ida::Address start, ida::Address end) {
        return runtime_result("name.all_user_defined", [=] {
            return ida::name::all_user_defined(start, end);
        });
    }, py::arg("start") = ida::BadAddress, py::arg("end") = ida::BadAddress);

#define IDAX_PY_NAME_PREDICATE(fn)                                        \
    name.def(#fn, [](ida::Address address) {                              \
        return runtime_call("name." #fn, [=] { return ida::name::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_NAME_PREDICATE(is_public);
    IDAX_PY_NAME_PREDICATE(is_weak);
    IDAX_PY_NAME_PREDICATE(is_user_defined);
    IDAX_PY_NAME_PREDICATE(is_auto_generated);
#undef IDAX_PY_NAME_PREDICATE

    name.def("is_valid_identifier", [](std::string text) {
        return runtime_result("name.is_valid_identifier", [&] {
            return ida::name::is_valid_identifier(text);
        });
    }, py::arg("text"));
    name.def("sanitize_identifier", [](std::string text) {
        return runtime_result("name.sanitize_identifier", [&] {
            return ida::name::sanitize_identifier(text);
        });
    }, py::arg("text"));
    name.def("set_public", [](ida::Address address, bool value) {
        runtime_status("name.set_public", [=] {
            return ida::name::set_public(address, value);
        });
    }, py::arg("address"), py::arg("value") = true);
    name.def("set_weak", [](ida::Address address, bool value) {
        runtime_status("name.set_weak", [=] {
            return ida::name::set_weak(address, value);
        });
    }, py::arg("address"), py::arg("value") = true);
}

} // namespace idax::python
