#include "common.hpp"

namespace idax::python {

void bind_comment(py::module_& module) {
    py::module_ comment = module.def_submodule(
        "comment", "Ordinary, repeatable, anterior, and posterior comments.");

    comment.def("get", [](ida::Address address, bool repeatable) {
        return runtime_result("comment.get", [=] {
            return ida::comment::get(address, repeatable);
        });
    }, py::arg("address"), py::arg("repeatable") = false);
    comment.def("set", [](ida::Address address, std::string text, bool repeatable) {
        runtime_status("comment.set", [&] {
            return ida::comment::set(address, text, repeatable);
        });
    }, py::arg("address"), py::arg("text"), py::arg("repeatable") = false);
    comment.def("append", [](ida::Address address, std::string text, bool repeatable) {
        runtime_status("comment.append", [&] {
            return ida::comment::append(address, text, repeatable);
        });
    }, py::arg("address"), py::arg("text"), py::arg("repeatable") = false);
    comment.def("remove", [](ida::Address address, bool repeatable) {
        runtime_status("comment.remove", [=] {
            return ida::comment::remove(address, repeatable);
        });
    }, py::arg("address"), py::arg("repeatable") = false);

#define IDAX_PY_COMMENT_TEXT_STATUS(name)                                  \
    comment.def(#name, [](ida::Address address, std::string text) {        \
        runtime_status("comment." #name, [&] {                            \
            return ida::comment::name(address, text);                      \
        });                                                                \
    }, py::arg("address"), py::arg("text"))

    IDAX_PY_COMMENT_TEXT_STATUS(add_anterior);
    IDAX_PY_COMMENT_TEXT_STATUS(add_posterior);
#undef IDAX_PY_COMMENT_TEXT_STATUS

#define IDAX_PY_COMMENT_INDEX_RESULT(name)                                 \
    comment.def(#name, [](ida::Address address, int line_index) {          \
        return runtime_result("comment." #name, [=] {                    \
            return ida::comment::name(address, line_index);                \
        });                                                                \
    }, py::arg("address"), py::arg("line_index"))

    IDAX_PY_COMMENT_INDEX_RESULT(get_anterior);
    IDAX_PY_COMMENT_INDEX_RESULT(get_posterior);
#undef IDAX_PY_COMMENT_INDEX_RESULT

#define IDAX_PY_COMMENT_INDEX_TEXT_STATUS(name)                            \
    comment.def(#name, [](ida::Address address, int line_index,            \
                           std::string text) {                              \
        runtime_status("comment." #name, [&] {                            \
            return ida::comment::name(address, line_index, text);          \
        });                                                                \
    }, py::arg("address"), py::arg("line_index"), py::arg("text"))

    IDAX_PY_COMMENT_INDEX_TEXT_STATUS(set_anterior);
    IDAX_PY_COMMENT_INDEX_TEXT_STATUS(set_posterior);
#undef IDAX_PY_COMMENT_INDEX_TEXT_STATUS

#define IDAX_PY_COMMENT_INDEX_STATUS(name)                                 \
    comment.def(#name, [](ida::Address address, int line_index) {          \
        runtime_status("comment." #name, [=] {                            \
            return ida::comment::name(address, line_index);                \
        });                                                                \
    }, py::arg("address"), py::arg("line_index"))

    IDAX_PY_COMMENT_INDEX_STATUS(remove_anterior_line);
    IDAX_PY_COMMENT_INDEX_STATUS(remove_posterior_line);
#undef IDAX_PY_COMMENT_INDEX_STATUS

#define IDAX_PY_COMMENT_LINES_STATUS(name)                                 \
    comment.def(#name, [](ida::Address address,                            \
                           const std::vector<std::string>& lines) {        \
        runtime_status("comment." #name, [&] {                            \
            return ida::comment::name(address, lines);                     \
        });                                                                \
    }, py::arg("address"), py::arg("lines"))

    IDAX_PY_COMMENT_LINES_STATUS(set_anterior_lines);
    IDAX_PY_COMMENT_LINES_STATUS(set_posterior_lines);
#undef IDAX_PY_COMMENT_LINES_STATUS

#define IDAX_PY_COMMENT_ADDRESS_STATUS(name)                               \
    comment.def(#name, [](ida::Address address) {                          \
        runtime_status("comment." #name, [=] {                            \
            return ida::comment::name(address);                            \
        });                                                                \
    }, py::arg("address"))

    IDAX_PY_COMMENT_ADDRESS_STATUS(clear_anterior);
    IDAX_PY_COMMENT_ADDRESS_STATUS(clear_posterior);
#undef IDAX_PY_COMMENT_ADDRESS_STATUS

#define IDAX_PY_COMMENT_ADDRESS_RESULT(name)                               \
    comment.def(#name, [](ida::Address address) {                          \
        return runtime_result("comment." #name, [=] {                    \
            return ida::comment::name(address);                            \
        });                                                                \
    }, py::arg("address"))

    IDAX_PY_COMMENT_ADDRESS_RESULT(anterior_lines);
    IDAX_PY_COMMENT_ADDRESS_RESULT(posterior_lines);
#undef IDAX_PY_COMMENT_ADDRESS_RESULT

    comment.def("render", [](ida::Address address, bool include_repeatable,
                               bool include_extra_lines) {
        return runtime_result("comment.render", [=] {
            return ida::comment::render(
                address, include_repeatable, include_extra_lines);
        });
    }, py::arg("address"), py::arg("include_repeatable") = true,
       py::arg("include_extra_lines") = true);
}

} // namespace idax::python
