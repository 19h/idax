#include "common.hpp"

namespace idax::python {

void bind_path(py::module_& module) {
    py::module_ path = module.def_submodule(
        "path", "Portable filesystem path helpers accepting os.PathLike values.");

    path.def("basename", [](py::handle value) {
        return ida::path::basename(filesystem_path(value));
    }, py::arg("path"));
    path.def("dirname", [](py::handle value) {
        return ida::path::dirname(filesystem_path(value));
    }, py::arg("path"));
    path.def("is_directory", [](py::handle value) {
        return ida::path::is_directory(filesystem_path(value));
    }, py::arg("path"));
}

} // namespace idax::python
