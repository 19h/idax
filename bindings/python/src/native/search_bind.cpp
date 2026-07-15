#include "common.hpp"

namespace idax::python {

void bind_search(py::module_& module) {
    py::module_ search = module.def_submodule(
        "search", "Text, immediate, binary-pattern, and item searches.");

    py::native_enum<ida::search::Direction>(
        search, "Direction", "enum.Enum")
        .value("FORWARD", ida::search::Direction::Forward)
        .value("BACKWARD", ida::search::Direction::Backward)
        .finalize();

#define IDAX_PY_SEARCH_OPTIONS(type)                                      \
    py::class_<ida::search::type>(search, #type)                          \
        .def(py::init<>())                                                 \
        .def_readwrite("direction", &ida::search::type::direction)       \
        .def_readwrite("skip_start", &ida::search::type::skip_start)     \
        .def_readwrite("no_break", &ida::search::type::no_break)         \
        .def_readwrite("no_show", &ida::search::type::no_show)           \
        .def_readwrite("break_on_cancel",                                \
                       &ida::search::type::break_on_cancel)
    IDAX_PY_SEARCH_OPTIONS(ImmediateOptions);
    IDAX_PY_SEARCH_OPTIONS(BinaryPatternOptions);
#undef IDAX_PY_SEARCH_OPTIONS

    py::class_<ida::search::TextOptions>(search, "TextOptions")
        .def(py::init<>())
        .def_readwrite("direction", &ida::search::TextOptions::direction)
        .def_readwrite("case_sensitive", &ida::search::TextOptions::case_sensitive)
        .def_readwrite("regex", &ida::search::TextOptions::regex)
        .def_readwrite("identifier", &ida::search::TextOptions::identifier)
        .def_readwrite("skip_start", &ida::search::TextOptions::skip_start)
        .def_readwrite("no_break", &ida::search::TextOptions::no_break)
        .def_readwrite("no_show", &ida::search::TextOptions::no_show)
        .def_readwrite("break_on_cancel", &ida::search::TextOptions::break_on_cancel);

    search.def("text", [](std::string query, ida::Address start,
                            ida::search::Direction direction,
                            bool case_sensitive) {
        return runtime_result("search.text", [&] {
            return ida::search::text(query, start, direction, case_sensitive);
        });
    }, py::arg("query"), py::arg("start"),
       py::arg("direction") = ida::search::Direction::Forward,
       py::arg("case_sensitive") = true);
    search.def("text", [](std::string query, ida::Address start,
                            const ida::search::TextOptions& options) {
        return runtime_result("search.text", [&] {
            return ida::search::text(query, start, options);
        });
    }, py::arg("query"), py::arg("start"), py::arg("options"));

    search.def("immediate", [](std::uint64_t value, ida::Address start,
                                 ida::search::Direction direction) {
        return runtime_result("search.immediate", [=] {
            return ida::search::immediate(value, start, direction);
        });
    }, py::arg("value"), py::arg("start"),
       py::arg("direction") = ida::search::Direction::Forward);
    search.def("immediate", [](std::uint64_t value, ida::Address start,
                                 const ida::search::ImmediateOptions& options) {
        return runtime_result("search.immediate", [&] {
            return ida::search::immediate(value, start, options);
        });
    }, py::arg("value"), py::arg("start"), py::arg("options"));
    search.def("binary_pattern", [](std::string pattern, ida::Address start,
                                      ida::search::Direction direction) {
        return runtime_result("search.binary_pattern", [&] {
            return ida::search::binary_pattern(pattern, start, direction);
        });
    }, py::arg("hex_pattern"), py::arg("start"),
       py::arg("direction") = ida::search::Direction::Forward);
    search.def("binary_pattern", [](std::string pattern, ida::Address start,
                                      const ida::search::BinaryPatternOptions& options) {
        return runtime_result("search.binary_pattern", [&] {
            return ida::search::binary_pattern(pattern, start, options);
        });
    }, py::arg("hex_pattern"), py::arg("start"), py::arg("options"));

#define IDAX_PY_SEARCH_NEXT(fn)                                           \
    search.def(#fn, [](ida::Address address) {                            \
        return runtime_result("search." #fn, [=] { return ida::search::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_SEARCH_NEXT(next_code);
    IDAX_PY_SEARCH_NEXT(next_data);
    IDAX_PY_SEARCH_NEXT(next_unknown);
    IDAX_PY_SEARCH_NEXT(next_error);
    IDAX_PY_SEARCH_NEXT(next_defined);
#undef IDAX_PY_SEARCH_NEXT
}

} // namespace idax::python
