#include "common.hpp"

namespace idax::python {

void bind_lumina(py::module_& module) {
    py::module_ lumina = module.def_submodule(
        "lumina", "Lumina metadata pull and push operations.");

    py::native_enum<ida::lumina::Feature>(lumina, "Feature", "enum.Enum")
        .value("PRIMARY_METADATA", ida::lumina::Feature::PrimaryMetadata)
        .value("DECOMPILER", ida::lumina::Feature::Decompiler)
        .value("TELEMETRY", ida::lumina::Feature::Telemetry)
        .value("SECONDARY_METADATA", ida::lumina::Feature::SecondaryMetadata)
        .finalize();
    py::native_enum<ida::lumina::PushMode>(lumina, "PushMode", "enum.Enum")
        .value("PREFER_BETTER_OR_DIFFERENT",
               ida::lumina::PushMode::PreferBetterOrDifferent)
        .value("OVERRIDE", ida::lumina::PushMode::Override)
        .value("KEEP_EXISTING", ida::lumina::PushMode::KeepExisting)
        .value("MERGE", ida::lumina::PushMode::Merge)
        .finalize();
    py::native_enum<ida::lumina::OperationCode>(
        lumina, "OperationCode", "enum.IntEnum")
        .value("BAD_PATTERN", ida::lumina::OperationCode::BadPattern)
        .value("NOT_FOUND", ida::lumina::OperationCode::NotFound)
        .value("ERROR", ida::lumina::OperationCode::Error)
        .value("OK", ida::lumina::OperationCode::Ok)
        .value("ADDED", ida::lumina::OperationCode::Added)
        .finalize();
    py::class_<ida::lumina::BatchResult>(lumina, "BatchResult")
        .def(py::init<>())
        .def_readwrite("requested", &ida::lumina::BatchResult::requested)
        .def_readwrite("completed", &ida::lumina::BatchResult::completed)
        .def_readwrite("succeeded", &ida::lumina::BatchResult::succeeded)
        .def_readwrite("failed", &ida::lumina::BatchResult::failed)
        .def_readwrite("codes", &ida::lumina::BatchResult::codes);

    lumina.def("has_connection", [](ida::lumina::Feature feature) {
        return runtime_result("lumina.has_connection", [=] {
            return ida::lumina::has_connection(feature);
        });
    }, py::arg("feature") = ida::lumina::Feature::PrimaryMetadata);
    lumina.def("close_connection", [](ida::lumina::Feature feature) {
        runtime_status("lumina.close_connection", [=] {
            return ida::lumina::close_connection(feature);
        });
    }, py::arg("feature") = ida::lumina::Feature::PrimaryMetadata);
    lumina.def("close_all_connections", [] {
        runtime_status("lumina.close_all_connections",
                       ida::lumina::close_all_connections);
    });
    lumina.def("pull", [](py::object addresses, bool auto_apply,
                            bool skip_frequency_update,
                            ida::lumina::Feature feature) {
        if (py::isinstance<py::int_>(addresses)) {
            auto address = addresses.cast<ida::Address>();
            return runtime_result("lumina.pull", [=] {
                return ida::lumina::pull(
                    address, auto_apply, skip_frequency_update, feature);
            });
        }
        auto values = addresses.cast<std::vector<ida::Address>>();
        return runtime_result("lumina.pull", [&] {
            return ida::lumina::pull(
                values, auto_apply, skip_frequency_update, feature);
        });
    }, py::arg("addresses"), py::arg("auto_apply") = true,
       py::arg("skip_frequency_update") = false,
       py::arg("feature") = ida::lumina::Feature::PrimaryMetadata);
    lumina.def("push", [](py::object addresses, ida::lumina::PushMode mode,
                            ida::lumina::Feature feature) {
        if (py::isinstance<py::int_>(addresses)) {
            auto address = addresses.cast<ida::Address>();
            return runtime_result("lumina.push", [=] {
                return ida::lumina::push(address, mode, feature);
            });
        }
        auto values = addresses.cast<std::vector<ida::Address>>();
        return runtime_result("lumina.push", [&] {
            return ida::lumina::push(values, mode, feature);
        });
    }, py::arg("addresses"),
       py::arg("mode") = ida::lumina::PushMode::PreferBetterOrDifferent,
       py::arg("feature") = ida::lumina::Feature::PrimaryMetadata);
}

} // namespace idax::python
