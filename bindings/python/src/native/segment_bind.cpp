#include "common.hpp"

namespace idax::python {

void bind_segment(py::module_& module) {
    py::module_ segment = module.def_submodule(
        "segment", "Segment snapshots, mutation, lookup, and traversal.");

    py::native_enum<ida::segment::Type>(segment, "Type", "enum.Enum")
        .value("NORMAL", ida::segment::Type::Normal)
        .value("EXTERNAL", ida::segment::Type::External)
        .value("CODE", ida::segment::Type::Code)
        .value("DATA", ida::segment::Type::Data)
        .value("BSS", ida::segment::Type::Bss)
        .value("ABSOLUTE_SYMBOLS", ida::segment::Type::AbsoluteSymbols)
        .value("COMMON", ida::segment::Type::Common)
        .value("NULL", ida::segment::Type::Null)
        .value("UNDEFINED", ida::segment::Type::Undefined)
        .value("IMPORT", ida::segment::Type::Import)
        .value("INTERNAL_MEMORY", ida::segment::Type::InternalMemory)
        .value("GROUP", ida::segment::Type::Group)
        .finalize();

    py::class_<ida::segment::Permissions>(segment, "Permissions")
        .def(py::init<>())
        .def(py::init<bool, bool, bool>(), py::arg("read") = false,
             py::arg("write") = false, py::arg("execute") = false)
        .def_readwrite("read", &ida::segment::Permissions::read)
        .def_readwrite("write", &ida::segment::Permissions::write)
        .def_readwrite("execute", &ida::segment::Permissions::execute)
        .def("__repr__", [](const ida::segment::Permissions& value) {
            return "Permissions(read=" + std::string(value.read ? "True" : "False")
                + ", write=" + (value.write ? "True" : "False")
                + ", execute=" + (value.execute ? "True" : "False") + ")";
        });

    py::class_<ida::segment::Segment>(segment, "Segment")
        .def_property_readonly("start", &ida::segment::Segment::start)
        .def_property_readonly("end", &ida::segment::Segment::end)
        .def_property_readonly("size", &ida::segment::Segment::size)
        .def_property_readonly("bitness", &ida::segment::Segment::bitness)
        .def_property_readonly("type", &ida::segment::Segment::type)
        .def_property_readonly("permissions", &ida::segment::Segment::permissions)
        .def_property_readonly("name", &ida::segment::Segment::name)
        .def_property_readonly("class_name", &ida::segment::Segment::class_name)
        .def_property_readonly("is_visible", &ida::segment::Segment::is_visible)
        .def("refresh", [](ida::segment::Segment& value) {
            runtime_status("segment.Segment.refresh", [&] { return value.refresh(); });
        });
    py::class_<ida::segment::SegmentRange>(segment, "SegmentRange")
        .def("__iter__", [](const ida::segment::SegmentRange& range) {
            ensure_runtime_thread("segment.SegmentRange.__iter__");
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>());

    segment.def("create", [](ida::Address start, ida::Address end,
                               std::string name, std::string class_name,
                               ida::segment::Type type) {
        return runtime_result("segment.create", [&] {
            return ida::segment::create(start, end, name, class_name, type);
        });
    }, py::arg("start"), py::arg("end"), py::arg("name"),
       py::arg("class_name") = std::string{},
       py::arg("type") = ida::segment::Type::Normal);
    segment.def("remove", [](ida::Address address) {
        runtime_status("segment.remove", [=] { return ida::segment::remove(address); });
    }, py::arg("address"));

#define IDAX_PY_SEGMENT_ADDRESS_RESULT(fn)                                \
    segment.def(#fn, [](ida::Address address) {                           \
        return runtime_result("segment." #fn, [=] { return ida::segment::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_SEGMENT_ADDRESS_RESULT(at);
    IDAX_PY_SEGMENT_ADDRESS_RESULT(next);
    IDAX_PY_SEGMENT_ADDRESS_RESULT(prev);
#undef IDAX_PY_SEGMENT_ADDRESS_RESULT
    segment.def("by_name", [](std::string value) {
        return runtime_result("segment.by_name", [&] {
            return ida::segment::by_name(value);
        });
    }, py::arg("name"));
    segment.def("by_index", [](std::size_t index) {
        return runtime_result("segment.by_index", [=] {
            return ida::segment::by_index(index);
        });
    }, py::arg("index"));
    segment.def("count", [] { return runtime_result("segment.count", ida::segment::count); });

    segment.def("set_name", [](ida::Address address, std::string value) {
        runtime_status("segment.set_name", [&] {
            return ida::segment::set_name(address, value);
        });
    }, py::arg("address"), py::arg("name"));
    segment.def("set_class", [](ida::Address address, std::string value) {
        runtime_status("segment.set_class", [&] {
            return ida::segment::set_class(address, value);
        });
    }, py::arg("address"), py::arg("class_name"));
    segment.def("set_type", [](ida::Address address, ida::segment::Type value) {
        runtime_status("segment.set_type", [=] {
            return ida::segment::set_type(address, value);
        });
    }, py::arg("address"), py::arg("type"));
    segment.def("set_permissions", [](ida::Address address,
                                       ida::segment::Permissions value) {
        runtime_status("segment.set_permissions", [=] {
            return ida::segment::set_permissions(address, value);
        });
    }, py::arg("address"), py::arg("permissions"));
    segment.def("set_bitness", [](ida::Address address, int bits) {
        runtime_status("segment.set_bitness", [=] {
            return ida::segment::set_bitness(address, bits);
        });
    }, py::arg("address"), py::arg("bits"));
    segment.def("set_default_segment_register", [](ida::Address address,
                                                      int register_index,
                                                      std::uint64_t value) {
        runtime_status("segment.set_default_segment_register", [=] {
            return ida::segment::set_default_segment_register(
                address, register_index, value);
        });
    }, py::arg("address"), py::arg("register_index"), py::arg("value"));
    segment.def("set_default_segment_register_for_all", [](int register_index,
                                                              std::uint64_t value) {
        runtime_status("segment.set_default_segment_register_for_all", [=] {
            return ida::segment::set_default_segment_register_for_all(
                register_index, value);
        });
    }, py::arg("register_index"), py::arg("value"));
    segment.def("comment", [](ida::Address address, bool repeatable) {
        return runtime_result("segment.comment", [=] {
            return ida::segment::comment(address, repeatable);
        });
    }, py::arg("address"), py::arg("repeatable") = false);
    segment.def("set_comment", [](ida::Address address, std::string text,
                                    bool repeatable) {
        runtime_status("segment.set_comment", [&] {
            return ida::segment::set_comment(address, text, repeatable);
        });
    }, py::arg("address"), py::arg("text"), py::arg("repeatable") = false);
    segment.def("resize", [](ida::Address address, ida::Address new_start,
                               ida::Address new_end) {
        runtime_status("segment.resize", [=] {
            return ida::segment::resize(address, new_start, new_end);
        });
    }, py::arg("address"), py::arg("new_start"), py::arg("new_end"));
    segment.def("move", [](ida::Address address, ida::Address new_start) {
        runtime_status("segment.move", [=] {
            return ida::segment::move(address, new_start);
        });
    }, py::arg("address"), py::arg("new_start"));
    segment.def("all", [] {
        return runtime_call("segment.all", ida::segment::all);
    });
    segment.def("first", [] { return runtime_result("segment.first", ida::segment::first); });
    segment.def("last", [] { return runtime_result("segment.last", ida::segment::last); });
}

} // namespace idax::python
