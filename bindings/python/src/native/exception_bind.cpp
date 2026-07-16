#include "common.hpp"

namespace idax::python {

void bind_exception(py::module_& module) {
    py::module_ exception = module.def_submodule(
        "exception", "Architecture-independent exception regions.");

    py::native_enum<ida::exception::CatchSelectorKind>(
        exception, "CatchSelectorKind", "enum.Enum")
        .value("TYPED", ida::exception::CatchSelectorKind::Typed)
        .value("CATCH_ALL", ida::exception::CatchSelectorKind::CatchAll)
        .value("CLEANUP", ida::exception::CatchSelectorKind::Cleanup)
        .finalize();

    py::native_enum<ida::exception::SehDisposition>(
        exception, "SehDisposition", "enum.Enum")
        .value("CONTINUE_EXECUTION", ida::exception::SehDisposition::ContinueExecution)
        .value("CONTINUE_SEARCH", ida::exception::SehDisposition::ContinueSearch)
        .value("EXECUTE_HANDLER", ida::exception::SehDisposition::ExecuteHandler)
        .finalize();

    py::native_enum<ida::exception::Location>(
        exception, "Location", "enum.Enum")
        .value("CPP_TRY", ida::exception::Location::CppTry)
        .value("CPP_HANDLER", ida::exception::Location::CppHandler)
        .value("SEH_TRY", ida::exception::Location::SehTry)
        .value("SEH_HANDLER", ida::exception::Location::SehHandler)
        .value("SEH_FILTER", ida::exception::Location::SehFilter)
        .value("ANY", ida::exception::Location::Any)
        .value("UNWIND_FALLTHROUGH", ida::exception::Location::UnwindFallthrough)
        .finalize();

    py::class_<ida::exception::HandlerMetadata>(exception, "HandlerMetadata")
        .def(py::init<>())
        .def_readwrite("regions", &ida::exception::HandlerMetadata::regions)
        .def_readwrite("stack_displacement",
                       &ida::exception::HandlerMetadata::stack_displacement)
        .def_readwrite("frame_register",
                       &ida::exception::HandlerMetadata::frame_register);

    py::class_<ida::exception::CatchSelector>(exception, "CatchSelector")
        .def(py::init<>())
        .def_readwrite("kind", &ida::exception::CatchSelector::kind)
        .def_readwrite("type_identifier",
                       &ida::exception::CatchSelector::type_identifier);

    py::class_<ida::exception::CatchHandler>(exception, "CatchHandler")
        .def(py::init<>())
        .def_readwrite("metadata", &ida::exception::CatchHandler::metadata)
        .def_readwrite("object_displacement",
                       &ida::exception::CatchHandler::object_displacement)
        .def_readwrite("selector", &ida::exception::CatchHandler::selector);

    py::class_<ida::exception::SehHandler>(exception, "SehHandler")
        .def(py::init<>())
        .def_readwrite("metadata", &ida::exception::SehHandler::metadata)
        .def_readwrite("filter_regions",
                       &ida::exception::SehHandler::filter_regions)
        .def_readwrite("disposition", &ida::exception::SehHandler::disposition);

    py::class_<ida::exception::CppHandlers>(exception, "CppHandlers")
        .def(py::init<>())
        .def_readwrite("catches", &ida::exception::CppHandlers::catches);

    py::class_<ida::exception::BlockDefinition>(exception, "BlockDefinition")
        .def(py::init<>())
        .def_readwrite("protected_regions",
                       &ida::exception::BlockDefinition::protected_regions)
        .def_readwrite("handlers", &ida::exception::BlockDefinition::handlers);

    py::class_<ida::exception::Block>(exception, "Block")
        .def_property_readonly("definition", [](const ida::exception::Block& block) {
            return block.definition;
        })
        .def_property_readonly("nesting_level", [](const ida::exception::Block& block) {
            return block.nesting_level;
        });

    exception.def("list", [](const ida::address::Range& range) {
        return runtime_result("exception.list", [=] {
            return ida::exception::list(range);
        });
    }, py::arg("range"));

    exception.def("remove", [](const ida::address::Range& range) {
        runtime_status("exception.remove", [=] {
            return ida::exception::remove(range);
        });
    }, py::arg("range"));

    exception.def("add", [](const ida::exception::BlockDefinition& definition) {
        runtime_status("exception.add", [&] {
            return ida::exception::add(definition);
        });
    }, py::arg("definition"));

    exception.def("system_region_start", [](ida::Address address) {
        return runtime_result("exception.system_region_start", [=] {
            return ida::exception::system_region_start(address);
        });
    }, py::arg("address"));

    exception.def("contains", [](ida::Address address, py::object locations) {
        std::uint32_t bits = 0;
        try {
            bits = static_cast<std::uint32_t>(
                locations.cast<ida::exception::Location>());
        } catch (const py::cast_error&) {
            for (const py::handle item : locations)
                bits |= static_cast<std::uint32_t>(
                    py::cast<ida::exception::Location>(item));
        }
        return runtime_result("exception.contains", [=] {
            return ida::exception::contains(
                address, static_cast<ida::exception::Location>(bits));
        });
    }, py::arg("address"), py::arg("locations") =
        ida::exception::Location::Any);
}

} // namespace idax::python
