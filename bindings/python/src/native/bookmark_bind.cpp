#include "common.hpp"

namespace idax::python {

void bind_bookmark(py::module_& module) {
    py::module_ bookmark =
        module.def_submodule("bookmark", "Opaque address bookmark management.");

    bookmark.attr("MAX_SLOTS") = py::int_(ida::bookmark::MaxSlots);

    py::class_<ida::bookmark::Bookmark>(bookmark, "Bookmark")
        .def_readonly("address", &ida::bookmark::Bookmark::address)
        .def_readonly("slot", &ida::bookmark::Bookmark::slot)
        .def_readonly("description", &ida::bookmark::Bookmark::description)
        .def("__repr__", [](const ida::bookmark::Bookmark& value) {
            return "Bookmark(address=" + std::to_string(value.address) +
                   ", slot=" + std::to_string(value.slot) + ", description=" +
                   py::repr(py::str(value.description)).cast<std::string>() +
                   ")";
        });

    bookmark.def("all", [] {
        return runtime_result("bookmark.all",
                              [] { return ida::bookmark::all(); });
    });
    bookmark.def(
        "at",
        [](ida::Address address) {
            return runtime_result("bookmark.at",
                                  [=] { return ida::bookmark::at(address); });
        },
        py::arg("address"));
    bookmark.def(
        "at_slot",
        [](std::uint32_t slot) {
            return runtime_result("bookmark.at_slot",
                                  [=] { return ida::bookmark::at_slot(slot); });
        },
        py::arg("slot"));
    bookmark.def(
        "set",
        [](ida::Address address, const std::string& description,
           std::optional<std::uint32_t> slot) {
            return runtime_result("bookmark.set", [&] {
                return ida::bookmark::set(address, description, slot);
            });
        },
        py::arg("address"), py::arg("description"),
        py::arg("slot") = py::none());
    bookmark.def(
        "remove",
        [](ida::Address address) {
            return runtime_result("bookmark.remove", [=] {
                return ida::bookmark::remove(address);
            });
        },
        py::arg("address"));
    bookmark.def(
        "remove_slot",
        [](std::uint32_t slot) {
            return runtime_result("bookmark.remove_slot", [=] {
                return ida::bookmark::remove_slot(slot);
            });
        },
        py::arg("slot"));
}

} // namespace idax::python
