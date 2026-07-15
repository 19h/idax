#include "common.hpp"

namespace idax::python {

void bind_diagnostics(py::module_& module) {
    py::module_ diagnostics = module.def_submodule(
        "diagnostics", "Logging, structured error context, and performance counters.");

    py::native_enum<ida::diagnostics::LogLevel>(
        diagnostics, "LogLevel", "enum.Enum")
        .value("ERROR", ida::diagnostics::LogLevel::Error)
        .value("WARNING", ida::diagnostics::LogLevel::Warning)
        .value("INFO", ida::diagnostics::LogLevel::Info)
        .value("DEBUG", ida::diagnostics::LogLevel::Debug)
        .value("TRACE", ida::diagnostics::LogLevel::Trace)
        .export_values()
        .finalize();

    py::class_<ida::diagnostics::PerformanceCounters>(
        diagnostics, "PerformanceCounters")
        .def(py::init<>())
        .def_readwrite("log_messages",
                       &ida::diagnostics::PerformanceCounters::log_messages)
        .def_readwrite("invariant_failures",
                       &ida::diagnostics::PerformanceCounters::invariant_failures)
        .def("__repr__", [](const ida::diagnostics::PerformanceCounters& counters) {
            return "PerformanceCounters(log_messages="
                + std::to_string(counters.log_messages)
                + ", invariant_failures="
                + std::to_string(counters.invariant_failures) + ")";
        })
        .def("__eq__", [](const ida::diagnostics::PerformanceCounters& left,
                          const ida::diagnostics::PerformanceCounters& right) {
            return left.log_messages == right.log_messages
                && left.invariant_failures == right.invariant_failures;
        });

    diagnostics.def("set_log_level", [](ida::diagnostics::LogLevel level) {
        unwrap(ida::diagnostics::set_log_level(level));
    }, py::arg("level"));
    diagnostics.def("log_level", &ida::diagnostics::log_level);
    diagnostics.def("log", &ida::diagnostics::log,
                    py::arg("level"), py::arg("domain"), py::arg("message"));
    diagnostics.def("enrich", &ida::diagnostics::enrich,
                    py::arg("error"), py::arg("context_suffix"));
    diagnostics.def("assert_invariant", [](bool condition, std::string message) {
        unwrap(ida::diagnostics::assert_invariant(condition, message));
    }, py::arg("condition"), py::arg("message"));
    diagnostics.def("reset_performance_counters",
                    &ida::diagnostics::reset_performance_counters);
    diagnostics.def("performance_counters",
                    &ida::diagnostics::performance_counters);
}

} // namespace idax::python
