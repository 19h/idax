#include "common.hpp"

namespace idax::python {

void bind_problem(py::module_& module) {
    py::module_ problem = module.def_submodule(
        "problem", "Typed analysis-problem lists.");

    py::native_enum<ida::problem::Kind>(problem, "Kind", "enum.IntEnum")
        .value("MISSING_OFFSET_BASE", ida::problem::Kind::MissingOffsetBase)
        .value("MISSING_NAME", ida::problem::Kind::MissingName)
        .value("MISSING_FORCED_OPERAND", ida::problem::Kind::MissingForcedOperand)
        .value("MISSING_COMMENT", ida::problem::Kind::MissingComment)
        .value("MISSING_REFERENCES", ida::problem::Kind::MissingReferences)
        .value("IGNORED_JUMP_TABLE", ida::problem::Kind::IgnoredJumpTable)
        .value("DISASSEMBLY_FAILURE", ida::problem::Kind::DisassemblyFailure)
        .value("ALREADY_ITEM_HEAD", ida::problem::Kind::AlreadyItemHead)
        .value("FLOW_BEYOND_LIMITS", ida::problem::Kind::FlowBeyondLimits)
        .value("TOO_MANY_LINES", ida::problem::Kind::TooManyLines)
        .value("STACK_TRACE_FAILURE", ida::problem::Kind::StackTraceFailure)
        .value("ATTENTION", ida::problem::Kind::Attention)
        .value("ANALYSIS_DECISION", ida::problem::Kind::AnalysisDecision)
        .value("ROLLED_BACK_DECISION", ida::problem::Kind::RolledBackDecision)
        .value("FLAIR_COLLISION", ida::problem::Kind::FlairCollision)
        .value("FLAIR_INDECISION", ida::problem::Kind::FlairIndecision)
        .finalize();

    problem.def("description", [](ida::problem::Kind kind,
                                     ida::Address address) {
        return runtime_result("problem.description", [=] {
            return ida::problem::description(kind, address);
        });
    }, py::arg("kind"), py::arg("address"));
    problem.def("remember", [](ida::problem::Kind kind,
                                  ida::Address address,
                                  const std::optional<std::string>& message) {
        std::optional<std::string_view> view;
        if (message)
            view = *message;
        runtime_status("problem.remember", [=] {
            return ida::problem::remember(kind, address, view);
        });
    }, py::arg("kind"), py::arg("address"), py::arg("message") = py::none());
    problem.def("next", [](ida::problem::Kind kind,
                              ida::Address at_or_after) {
        return runtime_result("problem.next", [=] {
            return ida::problem::next(kind, at_or_after);
        });
    }, py::arg("kind"), py::arg("at_or_after") = 0);
    problem.def("remove", [](ida::problem::Kind kind,
                                ida::Address address) {
        return runtime_result("problem.remove", [=] {
            return ida::problem::remove(kind, address);
        });
    }, py::arg("kind"), py::arg("address"));
    problem.def("name", [](ida::problem::Kind kind, bool long_form) {
        return runtime_result("problem.name", [=] {
            return ida::problem::name(kind, long_form);
        });
    }, py::arg("kind"), py::arg("long_form") = true);
    problem.def("contains", [](ida::problem::Kind kind,
                                  ida::Address address) {
        return runtime_result("problem.contains", [=] {
            return ida::problem::contains(kind, address);
        });
    }, py::arg("kind"), py::arg("address"));
}

} // namespace idax::python
