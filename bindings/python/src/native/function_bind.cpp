#include "common.hpp"

namespace idax::python {

void bind_function(py::module_& module) {
    py::module_ function = module.def_submodule(
        "function", "Function snapshots, frames, chunks, and relationships.");

    py::class_<ida::function::Chunk>(function, "Chunk")
        .def(py::init<>())
        .def_readwrite("start", &ida::function::Chunk::start)
        .def_readwrite("end", &ida::function::Chunk::end)
        .def_readwrite("is_tail", &ida::function::Chunk::is_tail)
        .def_readwrite("owner", &ida::function::Chunk::owner)
        .def_property_readonly("size", &ida::function::Chunk::size);
    py::class_<ida::function::FrameVariable>(function, "FrameVariable")
        .def(py::init<>())
        .def_readwrite("name", &ida::function::FrameVariable::name)
        .def_readwrite("byte_offset", &ida::function::FrameVariable::byte_offset)
        .def_readwrite("byte_size", &ida::function::FrameVariable::byte_size)
        .def_readwrite("comment", &ida::function::FrameVariable::comment)
        .def_readwrite("is_special", &ida::function::FrameVariable::is_special);
    py::class_<ida::function::StackFrame>(function, "StackFrame")
        .def_property_readonly("local_variables_size",
                               &ida::function::StackFrame::local_variables_size)
        .def_property_readonly("saved_registers_size",
                               &ida::function::StackFrame::saved_registers_size)
        .def_property_readonly("arguments_size",
                               &ida::function::StackFrame::arguments_size)
        .def_property_readonly("total_size", &ida::function::StackFrame::total_size)
        .def_property_readonly("variables", [](const ida::function::StackFrame& self) {
            return self.variables();
        });
    py::class_<ida::function::Function>(function, "Function")
        .def_property_readonly("start", &ida::function::Function::start)
        .def_property_readonly("end", &ida::function::Function::end)
        .def_property_readonly("size", &ida::function::Function::size)
        .def_property_readonly("name", &ida::function::Function::name)
        .def_property_readonly("bitness", &ida::function::Function::bitness)
        .def_property_readonly("returns", &ida::function::Function::returns)
        .def_property_readonly("is_library", &ida::function::Function::is_library)
        .def_property_readonly("is_thunk", &ida::function::Function::is_thunk)
        .def_property_readonly("is_visible", &ida::function::Function::is_visible)
        .def_property_readonly("frame_local_size",
                               &ida::function::Function::frame_local_size)
        .def_property_readonly("frame_regs_size",
                               &ida::function::Function::frame_regs_size)
        .def_property_readonly("frame_args_size",
                               &ida::function::Function::frame_args_size)
        .def("refresh", [](ida::function::Function& self) {
            runtime_status("function.Function.refresh", [&] { return self.refresh(); });
        });
    py::class_<ida::function::RegisterVariable>(function, "RegisterVariable")
        .def(py::init<>())
        .def_readwrite("range_start", &ida::function::RegisterVariable::range_start)
        .def_readwrite("range_end", &ida::function::RegisterVariable::range_end)
        .def_readwrite("canonical_name",
                       &ida::function::RegisterVariable::canonical_name)
        .def_readwrite("user_name", &ida::function::RegisterVariable::user_name)
        .def_readwrite("comment", &ida::function::RegisterVariable::comment);
    py::class_<ida::function::FunctionRange>(function, "FunctionRange")
        .def("__iter__", [](const ida::function::FunctionRange& range) {
            ensure_runtime_thread("function.FunctionRange.__iter__");
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>());

    function.def("create", [](ida::Address start, ida::Address end) {
        return runtime_result("function.create", [=] {
            return ida::function::create(start, end);
        });
    }, py::arg("start"), py::arg("end") = ida::BadAddress);
    function.def("remove", [](ida::Address address) {
        runtime_status("function.remove", [=] { return ida::function::remove(address); });
    }, py::arg("address"));
#define IDAX_PY_FUNCTION_ADDRESS_RESULT(fn)                              \
    function.def(#fn, [](ida::Address address) {                         \
        return runtime_result("function." #fn, [=] { return ida::function::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_FUNCTION_ADDRESS_RESULT(at);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(name_at);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(is_outlined);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(callers);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(callees);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(chunks);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(tail_chunks);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(chunk_count);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(frame);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(sp_delta_at);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(register_variables);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(item_addresses);
    IDAX_PY_FUNCTION_ADDRESS_RESULT(code_addresses);
#undef IDAX_PY_FUNCTION_ADDRESS_RESULT
    function.def("by_index", [](std::size_t index) {
        return runtime_result("function.by_index", [=] {
            return ida::function::by_index(index);
        });
    }, py::arg("index"));
    function.def("count", [] {
        return runtime_result("function.count", ida::function::count);
    });
#define IDAX_PY_FUNCTION_TWO_ADDRESS_STATUS(fn, second)                  \
    function.def(#fn, [](ida::Address address, ida::Address value) {     \
        runtime_status("function." #fn, [=] { return ida::function::fn(address, value); }); \
    }, py::arg("address"), py::arg(second))
    IDAX_PY_FUNCTION_TWO_ADDRESS_STATUS(set_start, "new_start");
    IDAX_PY_FUNCTION_TWO_ADDRESS_STATUS(set_end, "new_end");
#undef IDAX_PY_FUNCTION_TWO_ADDRESS_STATUS
#define IDAX_PY_FUNCTION_ADDRESS_STATUS(fn)                              \
    function.def(#fn, [](ida::Address address) {                         \
        runtime_status("function." #fn, [=] { return ida::function::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_FUNCTION_ADDRESS_STATUS(update);
    IDAX_PY_FUNCTION_ADDRESS_STATUS(reanalyze);
#undef IDAX_PY_FUNCTION_ADDRESS_STATUS
    function.def("set_outlined", [](ida::Address address, bool outlined) {
        runtime_status("function.set_outlined", [=] {
            return ida::function::set_outlined(address, outlined);
        });
    }, py::arg("address"), py::arg("outlined"));
    function.def("comment", [](ida::Address address, bool repeatable) {
        return runtime_result("function.comment", [=] {
            return ida::function::comment(address, repeatable);
        });
    }, py::arg("address"), py::arg("repeatable") = false);
    function.def("set_comment", [](ida::Address address, std::string text,
                                     bool repeatable) {
        runtime_status("function.set_comment", [&] {
            return ida::function::set_comment(address, text, repeatable);
        });
    }, py::arg("address"), py::arg("text"), py::arg("repeatable") = false);
    function.def("add_tail", [](ida::Address function_address,
                                  ida::Address tail_start,
                                  ida::Address tail_end) {
        runtime_status("function.add_tail", [=] {
            return ida::function::add_tail(function_address, tail_start, tail_end);
        });
    }, py::arg("function_address"), py::arg("tail_start"), py::arg("tail_end"));
    function.def("remove_tail", [](ida::Address function_address,
                                     ida::Address tail_address) {
        runtime_status("function.remove_tail", [=] {
            return ida::function::remove_tail(function_address, tail_address);
        });
    }, py::arg("function_address"), py::arg("tail_address"));
    function.def("frame_variable_by_name", [](ida::Address address, std::string name) {
        return runtime_result("function.frame_variable_by_name", [&] {
            return ida::function::frame_variable_by_name(address, name);
        });
    }, py::arg("address"), py::arg("name"));
    function.def("frame_variable_by_offset", [](ida::Address address,
                                                  std::size_t byte_offset) {
        return runtime_result("function.frame_variable_by_offset", [=] {
            return ida::function::frame_variable_by_offset(address, byte_offset);
        });
    }, py::arg("address"), py::arg("byte_offset"));
    function.def("define_stack_variable", [](ida::Address function_address,
                                               std::string name,
                                               std::int32_t frame_offset,
                                               const ida::type::TypeInfo& type) {
        runtime_status("function.define_stack_variable", [&] {
            return ida::function::define_stack_variable(
                function_address, name, frame_offset, type);
        });
    }, py::arg("function_address"), py::arg("name"), py::arg("frame_offset"),
       py::arg("type"));
    function.def("set_prototype", [](ida::Address function_address,
                                      const ida::type::TypeInfo& type) {
        runtime_status("function.set_prototype", [&] {
            return ida::function::set_prototype(function_address, type);
        });
    }, py::arg("function_address"), py::arg("type"));
    function.def("apply_decl", [](ida::Address function_address,
                                    std::string declaration) {
        runtime_status("function.apply_decl", [&] {
            return ida::function::apply_decl(function_address, declaration);
        });
    }, py::arg("function_address"), py::arg("c_declaration"));
    function.def("declaration", [](ida::Address function_address,
                                     std::string name_override) {
        return runtime_result("function.declaration", [&] {
            return ida::function::declaration(function_address, name_override);
        });
    }, py::arg("function_address"), py::arg("name_override") = std::string{});
    function.def("add_register_variable", [](
        ida::Address function_address, ida::Address range_start,
        ida::Address range_end, std::string register_name,
        std::string user_name, std::string comment) {
        runtime_status("function.add_register_variable", [&] {
            return ida::function::add_register_variable(
                function_address, range_start, range_end, register_name,
                user_name, comment);
        });
    }, py::arg("function_address"), py::arg("range_start"),
       py::arg("range_end"), py::arg("register_name"), py::arg("user_name"),
       py::arg("comment") = std::string{});
    function.def("find_register_variable", [](
        ida::Address function_address, ida::Address address,
        std::string register_name) {
        return runtime_result("function.find_register_variable", [&] {
            return ida::function::find_register_variable(
                function_address, address, register_name);
        });
    }, py::arg("function_address"), py::arg("address"), py::arg("register_name"));
    function.def("remove_register_variable", [](
        ida::Address function_address, ida::Address range_start,
        ida::Address range_end, std::string register_name) {
        runtime_status("function.remove_register_variable", [&] {
            return ida::function::remove_register_variable(
                function_address, range_start, range_end, register_name);
        });
    }, py::arg("function_address"), py::arg("range_start"),
       py::arg("range_end"), py::arg("register_name"));
    function.def("rename_register_variable", [](
        ida::Address function_address, ida::Address address,
        std::string register_name, std::string new_user_name) {
        runtime_status("function.rename_register_variable", [&] {
            return ida::function::rename_register_variable(
                function_address, address, register_name, new_user_name);
        });
    }, py::arg("function_address"), py::arg("address"),
       py::arg("register_name"), py::arg("new_user_name"));
    function.def("has_register_variables", [](
        ida::Address function_address, ida::Address address) {
        return runtime_result("function.has_register_variables", [=] {
            return ida::function::has_register_variables(function_address, address);
        });
    }, py::arg("function_address"), py::arg("address"));
    function.def("all", [] {
        return runtime_call("function.all", ida::function::all);
    });
}

} // namespace idax::python
