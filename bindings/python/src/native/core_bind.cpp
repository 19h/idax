#include "common.hpp"

namespace idax::python {

void bind_core(py::module_& module) {
    py::module_ core = module.def_submodule("core", "Shared IDAX option values.");

    py::class_<ida::OperationOptions>(core, "OperationOptions")
        .def(py::init<>())
        .def_readwrite("strict_validation", &ida::OperationOptions::strict_validation)
        .def_readwrite("allow_partial_results", &ida::OperationOptions::allow_partial_results)
        .def_readwrite("cancel_on_user_break", &ida::OperationOptions::cancel_on_user_break)
        .def_readwrite("quiet", &ida::OperationOptions::quiet)
        .def("__repr__", [](const ida::OperationOptions& options) {
            return "OperationOptions(strict_validation="
                + std::string(options.strict_validation ? "True" : "False")
                + ", allow_partial_results="
                + std::string(options.allow_partial_results ? "True" : "False")
                + ", cancel_on_user_break="
                + std::string(options.cancel_on_user_break ? "True" : "False")
                + ", quiet=" + std::string(options.quiet ? "True" : "False") + ")";
        });

    py::class_<ida::RangeOptions>(core, "RangeOptions")
        .def(py::init<>())
        .def_readwrite("start", &ida::RangeOptions::start)
        .def_readwrite("end", &ida::RangeOptions::end)
        .def_readwrite("inclusive_end", &ida::RangeOptions::inclusive_end)
        .def("__repr__", [](const ida::RangeOptions& options) {
            return "RangeOptions(start=" + std::to_string(options.start)
                + ", end=" + std::to_string(options.end)
                + ", inclusive_end="
                + std::string(options.inclusive_end ? "True" : "False") + ")";
        });

    py::class_<ida::WaitOptions>(core, "WaitOptions")
        .def(py::init<>())
        .def_readwrite("timeout_ms", &ida::WaitOptions::timeout_ms)
        .def_readwrite("poll_interval_ms", &ida::WaitOptions::poll_interval_ms)
        .def("__repr__", [](const ida::WaitOptions& options) {
            return "WaitOptions(timeout_ms=" + std::to_string(options.timeout_ms)
                + ", poll_interval_ms=" + std::to_string(options.poll_interval_ms)
                + ")";
        });
}

} // namespace idax::python
