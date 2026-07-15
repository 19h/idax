#include "common.hpp"

namespace idax::python {

namespace {

template <typename Function>
void analysis_status(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    unwrap(std::forward<Function>(function)());
}

} // namespace

void bind_analysis(py::module_& module) {
    py::module_ analysis = module.def_submodule(
        "analysis", "Auto-analysis state, scheduling, waiting, and cancellation.");

    analysis.def("is_enabled", [] {
        ensure_runtime_thread("analysis.is_enabled");
        return ida::analysis::is_enabled();
    });
    analysis.def("set_enabled", [](bool enabled) {
        analysis_status("analysis.set_enabled", [=] {
            return ida::analysis::set_enabled(enabled);
        });
    }, py::arg("enabled"));
    analysis.def("is_idle", [] {
        ensure_runtime_thread("analysis.is_idle");
        return ida::analysis::is_idle();
    });
    analysis.def("wait", [] {
        analysis_status("analysis.wait", [] { return ida::analysis::wait(); });
    });
    analysis.def("wait_range", [](ida::Address start, ida::Address end) {
        analysis_status("analysis.wait_range", [=] {
            return ida::analysis::wait_range(start, end);
        });
    }, py::arg("start"), py::arg("end"));
    analysis.def("schedule", [](ida::Address address) {
        analysis_status("analysis.schedule", [=] {
            return ida::analysis::schedule(address);
        });
    }, py::arg("address"));
    analysis.def("schedule_range", [](ida::Address start, ida::Address end) {
        analysis_status("analysis.schedule_range", [=] {
            return ida::analysis::schedule_range(start, end);
        });
    }, py::arg("start"), py::arg("end"));
    analysis.def("schedule_code", [](ida::Address address) {
        analysis_status("analysis.schedule_code", [=] {
            return ida::analysis::schedule_code(address);
        });
    }, py::arg("address"));
    analysis.def("schedule_function", [](ida::Address address) {
        analysis_status("analysis.schedule_function", [=] {
            return ida::analysis::schedule_function(address);
        });
    }, py::arg("address"));
    analysis.def("schedule_reanalysis", [](ida::Address address) {
        analysis_status("analysis.schedule_reanalysis", [=] {
            return ida::analysis::schedule_reanalysis(address);
        });
    }, py::arg("address"));
    analysis.def("schedule_reanalysis_range", [](ida::Address start,
                                                   ida::Address end) {
        analysis_status("analysis.schedule_reanalysis_range", [=] {
            return ida::analysis::schedule_reanalysis_range(start, end);
        });
    }, py::arg("start"), py::arg("end"));
    analysis.def("cancel", [](ida::Address start, ida::Address end) {
        analysis_status("analysis.cancel", [=] {
            return ida::analysis::cancel(start, end);
        });
    }, py::arg("start"), py::arg("end"));
    analysis.def("revert_decisions", [](ida::Address start, ida::Address end) {
        analysis_status("analysis.revert_decisions", [=] {
            return ida::analysis::revert_decisions(start, end);
        });
    }, py::arg("start"), py::arg("end"));
}

} // namespace idax::python
