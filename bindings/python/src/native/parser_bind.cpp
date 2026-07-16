#include "common.hpp"

namespace idax::python {
namespace {

ida::parser::Language parser_languages(py::object languages) {
    try {
        return languages.cast<ida::parser::Language>();
    } catch (const py::cast_error&) {
        std::uint32_t bits = 0;
        for (const py::handle language : languages)
            bits |= static_cast<std::uint32_t>(
                py::cast<ida::parser::Language>(language));
        return static_cast<ida::parser::Language>(bits);
    }
}

} // namespace

void bind_parser(py::module_& module) {
    py::module_ parser = module.def_submodule(
        "parser", "Third-party source-parser selection and type ingestion.");

    py::native_enum<ida::parser::Language>(parser, "Language", "enum.Enum")
        .value("C", ida::parser::Language::C)
        .value("CPP", ida::parser::Language::Cpp)
        .value("OBJECTIVE_C", ida::parser::Language::ObjectiveC)
        .value("SWIFT", ida::parser::Language::Swift)
        .value("GO", ida::parser::Language::Go)
        .value("OBJECTIVE_CPP", ida::parser::Language::ObjectiveCpp)
        .finalize();

    py::native_enum<ida::parser::InputKind>(
        parser, "InputKind", "enum.Enum")
        .value("SOURCE_TEXT", ida::parser::InputKind::SourceText)
        .value("FILE_PATH", ida::parser::InputKind::FilePath)
        .finalize();

    py::class_<ida::parser::ParseOptions>(parser, "ParseOptions")
        .def(py::init<>())
        .def_readwrite("input_kind", &ida::parser::ParseOptions::input_kind)
        .def_readwrite("discard_result", &ida::parser::ParseOptions::discard_result)
        .def_readwrite("define_base_macros", &ida::parser::ParseOptions::define_base_macros)
        .def_readwrite("suppress_warnings", &ida::parser::ParseOptions::suppress_warnings)
        .def_readwrite("ignore_errors", &ida::parser::ParseOptions::ignore_errors)
        .def_readwrite("allow_redeclarations", &ida::parser::ParseOptions::allow_redeclarations)
        .def_readwrite("no_decorate", &ida::parser::ParseOptions::no_decorate)
        .def_readwrite("assume_high_level", &ida::parser::ParseOptions::assume_high_level)
        .def_readwrite("lower_prototypes", &ida::parser::ParseOptions::lower_prototypes)
        .def_readwrite("raw_argument_names", &ida::parser::ParseOptions::raw_argument_names)
        .def_readwrite("relaxed_namespaces", &ida::parser::ParseOptions::relaxed_namespaces)
        .def_readwrite("exclude_base_types", &ida::parser::ParseOptions::exclude_base_types)
        .def_readwrite("allow_missing_semicolon", &ida::parser::ParseOptions::allow_missing_semicolon)
        .def_readwrite("standalone_declaration", &ida::parser::ParseOptions::standalone_declaration)
        .def_readwrite("allow_void", &ida::parser::ParseOptions::allow_void)
        .def_readwrite("no_mangle", &ida::parser::ParseOptions::no_mangle)
        .def_readwrite("pack_alignment", &ida::parser::ParseOptions::pack_alignment);

    py::class_<ida::parser::ParseReport>(parser, "ParseReport")
        .def(py::init<>())
        .def_readwrite("error_count", &ida::parser::ParseReport::error_count)
        .def_property_readonly("ok", &ida::parser::ParseReport::ok)
        .def("__bool__", &ida::parser::ParseReport::ok);

    parser.def("select", [](const std::optional<std::string>& name) {
        std::optional<std::string_view> view;
        if (name) view = *name;
        runtime_status("parser.select", [=] {
            return ida::parser::select(view);
        });
    }, py::arg("name") = py::none());

    parser.def("select_for", [](py::object languages) {
        const auto value = parser_languages(std::move(languages));
        runtime_status("parser.select_for", [=] {
            return ida::parser::select_for(value);
        });
    }, py::arg("languages"));

    parser.def("selected_name", [] {
        return runtime_result("parser.selected_name", [] {
            return ida::parser::selected_name();
        });
    });

    parser.def("set_arguments", [](const std::string& parser_name,
                                      const std::string& arguments) {
        runtime_status("parser.set_arguments", [&] {
            return ida::parser::set_arguments(parser_name, arguments);
        });
    }, py::arg("parser_name"), py::arg("arguments"));

    parser.def("parse_for", [](py::object languages,
                                  const std::string& input,
                                  ida::parser::InputKind input_kind) {
        const auto value = parser_languages(std::move(languages));
        return runtime_result("parser.parse_for", [&] {
            return ida::parser::parse_for(value, input, input_kind);
        });
    }, py::arg("languages"), py::arg("input"),
       py::arg("input_kind") = ida::parser::InputKind::SourceText);

    parser.def("parse_with", [](const std::string& parser_name,
                                   const std::string& input,
                                   ida::parser::InputKind input_kind) {
        return runtime_result("parser.parse_with", [&] {
            return ida::parser::parse_with(parser_name, input, input_kind);
        });
    }, py::arg("parser_name"), py::arg("input"),
       py::arg("input_kind") = ida::parser::InputKind::SourceText);

    parser.def("parse_with_options", [](const std::string& parser_name,
                                           const std::string& input,
                                           const ida::parser::ParseOptions& options) {
        return runtime_result("parser.parse_with_options", [&] {
            return ida::parser::parse_with_options(parser_name, input, options);
        });
    }, py::arg("parser_name"), py::arg("input"),
       py::arg("options") = ida::parser::ParseOptions{});

    parser.def("option", [](const std::string& parser_name,
                               const std::string& option_name) {
        return runtime_result("parser.option", [&] {
            return ida::parser::option(parser_name, option_name);
        });
    }, py::arg("parser_name"), py::arg("option_name"));

    parser.def("set_option", [](const std::string& parser_name,
                                   const std::string& option_name,
                                   const std::string& value) {
        runtime_status("parser.set_option", [&] {
            return ida::parser::set_option(parser_name, option_name, value);
        });
    }, py::arg("parser_name"), py::arg("option_name"), py::arg("value"));
}

} // namespace idax::python
