#include "common.hpp"

#include <pybind11/pybind11.h>

PYBIND11_MODULE(_native, module) {
    module.doc() = "Private native extension for the idax Python package.";
    module.attr("__version__") = "0.1.0";
    module.attr("BAD_ADDRESS") = py::int_(ida::BadAddress);

    idax::python::bind_error_types(module);
    idax::python::bind_core(module);
    idax::python::bind_address(module);
    idax::python::bind_database(module);
    idax::python::bind_path(module);
    idax::python::bind_analysis(module);
    idax::python::bind_undo(module);
    idax::python::bind_problem(module);
    idax::python::bind_bookmark(module);
    idax::python::bind_exception(module);
    idax::python::bind_parser(module);
    idax::python::bind_directory(module);
    idax::python::bind_registry(module);
    idax::python::bind_registers(module);
    idax::python::bind_diagnostics(module);
    idax::python::bind_comment(module);
    idax::python::bind_entry(module);
    idax::python::bind_name(module);
    idax::python::bind_search(module);
    idax::python::bind_segment(module);
    idax::python::bind_xref(module);
    idax::python::bind_lines(module);
    idax::python::bind_lumina(module);
    idax::python::bind_type(module);
    idax::python::bind_fixup(module);
    idax::python::bind_function(module);
    idax::python::bind_instruction(module);
    idax::python::bind_storage(module);
    idax::python::bind_event(module);
    idax::python::bind_data(module);
    idax::python::bind_debugger(module);
    idax::python::bind_graph(module);
    idax::python::bind_decompiler(module);
    idax::python::bind_plugin(module);
    idax::python::bind_loader(module);
    idax::python::bind_processor(module);
    idax::python::bind_ui(module);
}
