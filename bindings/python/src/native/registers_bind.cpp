#include "common.hpp"

namespace idax::python {

void bind_registers(py::module_& module) {
    py::module_ registers = module.def_submodule(
        "registers", "Opaque register-value tracking with owned results.");

    py::native_enum<ida::registers::TrackingState>(
        registers, "TrackingState", "enum.Enum")
        .value("UNDEFINED", ida::registers::TrackingState::Undefined)
        .value("DEAD_END", ida::registers::TrackingState::DeadEnd)
        .value("ABORTED", ida::registers::TrackingState::Aborted)
        .value("BAD_INSTRUCTION", ida::registers::TrackingState::BadInstruction)
        .value("UNKNOWN_INSTRUCTION", ida::registers::TrackingState::UnknownInstruction)
        .value("FUNCTION_INPUT", ida::registers::TrackingState::FunctionInput)
        .value("LOOP_VARIANT", ida::registers::TrackingState::LoopVariant)
        .value("INCOMPATIBLE_VALUES", ida::registers::TrackingState::IncompatibleValues)
        .value("TOO_MANY_REFERENCES", ida::registers::TrackingState::TooManyReferences)
        .value("TOO_MANY_VALUES", ida::registers::TrackingState::TooManyValues)
        .value("CONSTANT", ida::registers::TrackingState::Constant)
        .value("STACK_POINTER_DELTA", ida::registers::TrackingState::StackPointerDelta)
        .finalize();

    py::native_enum<ida::registers::ReferenceMutation>(
        registers, "ReferenceMutation", "enum.Enum")
        .value("ADDED", ida::registers::ReferenceMutation::Added)
        .value("REMOVED", ida::registers::ReferenceMutation::Removed)
        .finalize();

    py::class_<ida::registers::ValueOrigin>(registers, "ValueOrigin")
        .def_readonly("address", &ida::registers::ValueOrigin::address)
        .def_readonly("instruction_code",
                      &ida::registers::ValueOrigin::instruction_code)
        .def_readonly("short_instruction",
                      &ida::registers::ValueOrigin::short_instruction)
        .def_readonly("program_counter_based",
                      &ida::registers::ValueOrigin::program_counter_based)
        .def_readonly("global_offset_table_like",
                      &ida::registers::ValueOrigin::global_offset_table_like);

    py::class_<ida::registers::ValueCandidate>(registers, "ValueCandidate")
        .def_readonly("constant", &ida::registers::ValueCandidate::constant)
        .def_readonly("stack_pointer_delta",
                      &ida::registers::ValueCandidate::stack_pointer_delta)
        .def_readonly("origin", &ida::registers::ValueCandidate::origin);

    py::class_<ida::registers::TrackedValue>(registers, "TrackedValue")
        .def_readonly("state", &ida::registers::TrackedValue::state)
        .def_readonly("candidates", &ida::registers::TrackedValue::candidates)
        .def_readonly("cause", &ida::registers::TrackedValue::cause)
        .def_readonly("aborting_depth",
                      &ida::registers::TrackedValue::aborting_depth)
        .def_readonly("description", &ida::registers::TrackedValue::description)
        .def_property_readonly("known",
            &ida::registers::TrackedValue::known);

    py::class_<ida::registers::NearestValue>(registers, "NearestValue")
        .def_readonly("selected_index",
                      &ida::registers::NearestValue::selected_index)
        .def_readonly("register_name",
                      &ida::registers::NearestValue::register_name)
        .def_readonly("value", &ida::registers::NearestValue::value);

    registers.def("track", [](ida::Address address,
                                  const std::string& register_name,
                                  int max_depth) {
        return runtime_result("registers.track", [&] {
            return ida::registers::track(address, register_name, max_depth);
        });
    }, py::arg("address"), py::arg("register_name"), py::arg("max_depth") = 0);

    registers.def("constant_at", [](ida::Address address,
                                        const std::string& register_name,
                                        int max_depth) {
        return runtime_result("registers.constant_at", [&] {
            return ida::registers::constant_at(
                address, register_name, max_depth);
        });
    }, py::arg("address"), py::arg("register_name"), py::arg("max_depth") = 0);

    registers.def("stack_delta_at", [](ida::Address address,
                                           const std::optional<std::string>& register_name) {
        return runtime_result("registers.stack_delta_at", [&] {
            if (register_name)
                return ida::registers::stack_delta_at(address, *register_name);
            return ida::registers::stack_delta_at(address);
        });
    }, py::arg("address"), py::arg("register_name") = py::none());

    registers.def("nearest_at", [](ida::Address address,
                                       const std::string& first_register,
                                       const std::string& second_register) {
        return runtime_result("registers.nearest_at", [&] {
            return ida::registers::nearest_at(
                address, first_register, second_register);
        });
    }, py::arg("address"), py::arg("first_register"),
       py::arg("second_register"));

    registers.def("clear_control_flow_cache", [] {
        runtime_status("registers.clear_control_flow_cache", [] {
            return ida::registers::clear_control_flow_cache();
        });
    });
    registers.def("clear_data_reference_cache", [] {
        runtime_status("registers.clear_data_reference_cache", [] {
            return ida::registers::clear_data_reference_cache();
        });
    });
    registers.def("control_flow_reference_changed",
        [](ida::Address from, ida::Address to,
           ida::registers::ReferenceMutation mutation) {
            runtime_status("registers.control_flow_reference_changed", [=] {
                return ida::registers::control_flow_reference_changed(
                    from, to, mutation);
            });
        }, py::arg("from_address"), py::arg("to_address"), py::arg("mutation"));
    registers.def("data_reference_changed",
        [](ida::Address to, ida::registers::ReferenceMutation mutation) {
            runtime_status("registers.data_reference_changed", [=] {
                return ida::registers::data_reference_changed(to, mutation);
            });
        }, py::arg("to_address"), py::arg("mutation"));
}

} // namespace idax::python
