#include "common.hpp"

namespace idax::python {

void bind_fixup(py::module_& module) {
    py::module_ fixup = module.def_submodule(
        "fixup", "Relocation descriptors, traversal, and custom handlers.");

    py::native_enum<ida::fixup::Type>(fixup, "Type", "enum.Enum")
        .value("OFF8", ida::fixup::Type::Off8)
        .value("OFF16", ida::fixup::Type::Off16)
        .value("SEG16", ida::fixup::Type::Seg16)
        .value("PTR16", ida::fixup::Type::Ptr16)
        .value("OFF32", ida::fixup::Type::Off32)
        .value("PTR32", ida::fixup::Type::Ptr32)
        .value("HI8", ida::fixup::Type::Hi8)
        .value("HI16", ida::fixup::Type::Hi16)
        .value("LOW8", ida::fixup::Type::Low8)
        .value("LOW16", ida::fixup::Type::Low16)
        .value("OFF64", ida::fixup::Type::Off64)
        .value("OFF8_SIGNED", ida::fixup::Type::Off8Signed)
        .value("OFF16_SIGNED", ida::fixup::Type::Off16Signed)
        .value("OFF32_SIGNED", ida::fixup::Type::Off32Signed)
        .value("CUSTOM", ida::fixup::Type::Custom)
        .finalize();
    py::native_enum<ida::fixup::HandlerProperty>(
        fixup, "HandlerProperty", "enum.IntFlag")
        .value("VERIFY", ida::fixup::HandlerProperty::Verify)
        .value("CODE", ida::fixup::HandlerProperty::Code)
        .value("FORCE_CODE", ida::fixup::HandlerProperty::ForceCode)
        .value("ABSOLUTE_OP", ida::fixup::HandlerProperty::AbsoluteOp)
        .value("SIGNED_OP", ida::fixup::HandlerProperty::SignedOp)
        .finalize();
    py::class_<ida::fixup::Descriptor>(fixup, "Descriptor")
        .def(py::init<>())
        .def_readwrite("source", &ida::fixup::Descriptor::source)
        .def_readwrite("type", &ida::fixup::Descriptor::type)
        .def_readwrite("flags", &ida::fixup::Descriptor::flags)
        .def_readwrite("base", &ida::fixup::Descriptor::base)
        .def_readwrite("target", &ida::fixup::Descriptor::target)
        .def_readwrite("selector", &ida::fixup::Descriptor::selector)
        .def_readwrite("offset", &ida::fixup::Descriptor::offset)
        .def_readwrite("displacement", &ida::fixup::Descriptor::displacement);
    py::class_<ida::fixup::CustomHandler>(fixup, "CustomHandler")
        .def(py::init<>())
        .def_readwrite("name", &ida::fixup::CustomHandler::name)
        .def_readwrite("properties", &ida::fixup::CustomHandler::properties)
        .def_readwrite("size", &ida::fixup::CustomHandler::size)
        .def_readwrite("width", &ida::fixup::CustomHandler::width)
        .def_readwrite("shift", &ida::fixup::CustomHandler::shift)
        .def_readwrite("reference_type", &ida::fixup::CustomHandler::reference_type);
    py::class_<ida::fixup::FixupRange>(fixup, "FixupRange")
        .def("__iter__", [](const ida::fixup::FixupRange& range) {
            ensure_runtime_thread("fixup.FixupRange.__iter__");
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>());

    fixup.def("at", [](ida::Address source) {
        return runtime_result("fixup.at", [=] { return ida::fixup::at(source); });
    }, py::arg("source"));
    fixup.def("set", [](ida::Address source, const ida::fixup::Descriptor& value) {
        runtime_status("fixup.set", [&] { return ida::fixup::set(source, value); });
    }, py::arg("source"), py::arg("descriptor"));
    fixup.def("remove", [](ida::Address source) {
        runtime_status("fixup.remove", [=] { return ida::fixup::remove(source); });
    }, py::arg("source"));
    fixup.def("exists", [](ida::Address source) {
        return runtime_call("fixup.exists", [=] { return ida::fixup::exists(source); });
    }, py::arg("source"));
    fixup.def("contains", [](ida::Address start, ida::AddressSize size) {
        return runtime_call("fixup.contains", [=] { return ida::fixup::contains(start, size); });
    }, py::arg("start"), py::arg("size"));
    fixup.def("in_range", [](ida::Address start, ida::Address end) {
        return runtime_result("fixup.in_range", [=] {
            return ida::fixup::in_range(start, end);
        });
    }, py::arg("start"), py::arg("end"));
#define IDAX_PY_FIXUP_RESULT(fn)                                         \
    fixup.def(#fn, [] { return runtime_result("fixup." #fn, ida::fixup::fn); })
    IDAX_PY_FIXUP_RESULT(first);
#undef IDAX_PY_FIXUP_RESULT
#define IDAX_PY_FIXUP_ADDRESS_RESULT(fn)                                 \
    fixup.def(#fn, [](ida::Address address) {                            \
        return runtime_result("fixup." #fn, [=] { return ida::fixup::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_FIXUP_ADDRESS_RESULT(next);
    IDAX_PY_FIXUP_ADDRESS_RESULT(prev);
#undef IDAX_PY_FIXUP_ADDRESS_RESULT
    fixup.def("all", [] { return runtime_call("fixup.all", ida::fixup::all); });
    fixup.def("register_custom", [](const ida::fixup::CustomHandler& handler) {
        return runtime_result("fixup.register_custom", [&] {
            return ida::fixup::register_custom(handler);
        });
    }, py::arg("handler"));
    fixup.def("unregister_custom", [](std::uint16_t type) {
        runtime_status("fixup.unregister_custom", [=] {
            return ida::fixup::unregister_custom(type);
        });
    }, py::arg("custom_type"));
    fixup.def("find_custom", [](std::string name) {
        return runtime_result("fixup.find_custom", [&] {
            return ida::fixup::find_custom(name);
        });
    }, py::arg("name"));
}

} // namespace idax::python
