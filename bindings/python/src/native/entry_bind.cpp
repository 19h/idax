#include "common.hpp"

namespace idax::python {

void bind_entry(py::module_& module) {
    py::module_ entry = module.def_submodule("entry", "Program entry points.");

    py::class_<ida::entry::EntryPoint>(entry, "EntryPoint")
        .def(py::init<>())
        .def_readwrite("ordinal", &ida::entry::EntryPoint::ordinal)
        .def_readwrite("address", &ida::entry::EntryPoint::address)
        .def_readwrite("name", &ida::entry::EntryPoint::name)
        .def_readwrite("forwarder", &ida::entry::EntryPoint::forwarder);

    entry.def("count", [] {
        return runtime_result("entry.count", ida::entry::count);
    });
    entry.def("by_index", [](std::size_t index) {
        return runtime_result("entry.by_index", [=] {
            return ida::entry::by_index(index);
        });
    }, py::arg("index"));
    entry.def("by_ordinal", [](std::uint64_t ordinal) {
        return runtime_result("entry.by_ordinal", [=] {
            return ida::entry::by_ordinal(ordinal);
        });
    }, py::arg("ordinal"));
    entry.def("add", [](std::uint64_t ordinal, ida::Address address,
                          std::string name, bool make_code) {
        runtime_status("entry.add", [&] {
            return ida::entry::add(ordinal, address, name, make_code);
        });
    }, py::arg("ordinal"), py::arg("address"), py::arg("name"),
       py::arg("make_code") = true);
    entry.def("rename", [](std::uint64_t ordinal, std::string name) {
        runtime_status("entry.rename", [&] {
            return ida::entry::rename(ordinal, name);
        });
    }, py::arg("ordinal"), py::arg("name"));
    entry.def("forwarder", [](std::uint64_t ordinal) {
        return runtime_result("entry.forwarder", [=] {
            return ida::entry::forwarder(ordinal);
        });
    }, py::arg("ordinal"));
    entry.def("set_forwarder", [](std::uint64_t ordinal, std::string target) {
        runtime_status("entry.set_forwarder", [&] {
            return ida::entry::set_forwarder(ordinal, target);
        });
    }, py::arg("ordinal"), py::arg("target"));
    entry.def("clear_forwarder", [](std::uint64_t ordinal) {
        runtime_status("entry.clear_forwarder", [=] {
            return ida::entry::clear_forwarder(ordinal);
        });
    }, py::arg("ordinal"));
}

} // namespace idax::python
