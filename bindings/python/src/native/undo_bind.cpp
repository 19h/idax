#include "common.hpp"

namespace idax::python {

void bind_undo(py::module_& module) {
    py::module_ undo = module.def_submodule(
        "undo", "Opaque named restore points and undo/redo state.");

    undo.def("create_point", [](std::string_view action_name,
                                 std::string_view label) {
        return runtime_result("undo.create_point", [=] {
            return ida::undo::create_point(action_name, label);
        });
    }, py::arg("action_name"), py::arg("label"));
    undo.def("undo_action_label", [] {
        return runtime_result("undo.undo_action_label",
                              ida::undo::undo_action_label);
    });
    undo.def("redo_action_label", [] {
        return runtime_result("undo.redo_action_label",
                              ida::undo::redo_action_label);
    });
    undo.def("perform_undo", [] {
        return runtime_result("undo.perform_undo", ida::undo::perform_undo);
    });
    undo.def("perform_redo", [] {
        return runtime_result("undo.perform_redo", ida::undo::perform_redo);
    });
}

} // namespace idax::python
