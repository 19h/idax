#ifndef IDAX_PYTHON_COMMON_HPP
#define IDAX_PYTHON_COMMON_HPP

#include <ida/idax.hpp>

#include <pybind11/functional.h>
#include <pybind11/native_enum.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <exception>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace py = pybind11;

namespace idax::python {

class BindingError final : public std::exception {
public:
    explicit BindingError(ida::Error error);

    [[nodiscard]] const ida::Error& error() const noexcept { return error_; }
    [[nodiscard]] const char* what() const noexcept override { return display_.c_str(); }

private:
    ida::Error error_;
    std::string display_;
};

[[noreturn]] void throw_error(ida::Error error);

template <typename T>
T unwrap(ida::Result<T> result) {
    if (!result)
        throw_error(std::move(result.error()));
    return std::move(*result);
}

inline void unwrap(ida::Status status) {
    if (!status)
        throw_error(std::move(status.error()));
}

void bind_error_types(py::module_& module);

void mark_runtime_thread();
void ensure_runtime_thread(std::string_view operation);

template <typename Function>
auto runtime_result(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    return unwrap(std::forward<Function>(function)());
}

template <typename Function>
void runtime_status(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    unwrap(std::forward<Function>(function)());
}

template <typename Function>
auto runtime_call(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    return std::forward<Function>(function)();
}

std::string filesystem_path(py::handle value);
std::vector<std::uint8_t> buffer_bytes(py::handle value);
py::bytes python_bytes(const std::vector<std::uint8_t>& value);

void bind_core(py::module_& module);
void bind_address(py::module_& module);
void bind_database(py::module_& module);
void bind_path(py::module_& module);
void bind_analysis(py::module_& module);
void bind_undo(py::module_& module);
void bind_diagnostics(py::module_& module);
void bind_comment(py::module_& module);
void bind_entry(py::module_& module);
void bind_name(py::module_& module);
void bind_search(py::module_& module);
void bind_segment(py::module_& module);
void bind_xref(py::module_& module);
void bind_lines(py::module_& module);
void bind_lumina(py::module_& module);
void bind_type(py::module_& module);
void bind_fixup(py::module_& module);
void bind_function(py::module_& module);
void bind_instruction(py::module_& module);
void bind_storage(py::module_& module);
void bind_event(py::module_& module);
void bind_data(py::module_& module);
void bind_debugger(py::module_& module);
void bind_graph(py::module_& module);
void bind_decompiler(py::module_& module);
void bind_plugin(py::module_& module);
void bind_loader(py::module_& module);
void bind_processor(py::module_& module);
void bind_ui(py::module_& module);

} // namespace idax::python

#endif // IDAX_PYTHON_COMMON_HPP
