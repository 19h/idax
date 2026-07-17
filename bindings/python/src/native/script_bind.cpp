#include "common.hpp"

namespace idax::python {

void bind_script(py::module_& module) {
    py::module_ script = module.def_submodule(
        "script", "Opaque IDC values and synchronous script execution.");

    py::native_enum<ida::script::ValueKind>(script, "ValueKind", "enum.Enum")
        .value("INTEGER", ida::script::ValueKind::Integer)
        .value("FLOATING_POINT", ida::script::ValueKind::FloatingPoint)
        .value("OBJECT", ida::script::ValueKind::Object)
        .value("FUNCTION", ida::script::ValueKind::Function)
        .value("STRING", ida::script::ValueKind::String)
        .value("OPAQUE_POINTER", ida::script::ValueKind::OpaquePointer)
        .value("REFERENCE", ida::script::ValueKind::Reference)
        .finalize();

    py::native_enum<ida::script::DereferenceMode>(
        script, "DereferenceMode", "enum.Enum")
        .value("ONCE", ida::script::DereferenceMode::Once)
        .value("RECURSIVE", ida::script::DereferenceMode::Recursive)
        .finalize();

    py::class_<ida::script::Value>(script, "Value")
        .def(py::init<>())
        .def(py::init<std::int64_t>(), py::arg("value"))
        .def(py::init([](const std::string& value) {
            return ida::script::Value(value);
        }), py::arg("value"))
        .def_static("floating", [](double value) {
            return runtime_result("script.Value.floating", [=] {
                return ida::script::Value::floating(value);
            });
        }, py::arg("value"))
        .def_static("object", [] {
            return runtime_result("script.Value.object", [] {
                return ida::script::Value::object();
            });
        })
        .def_property_readonly("kind", [](const ida::script::Value& self) {
            return runtime_result("script.Value.kind", [&] {
                return self.kind();
            });
        })
        .def("as_integer", [](const ida::script::Value& self) {
            return runtime_result("script.Value.as_integer", [&] {
                return self.as_integer();
            });
        })
        .def("as_floating", [](const ida::script::Value& self) {
            return runtime_result("script.Value.as_floating", [&] {
                return self.as_floating();
            });
        })
        .def("as_string", [](const ida::script::Value& self) {
            return runtime_result("script.Value.as_string", [&] {
                return self.as_string();
            });
        })
        .def("coerce_integer", [](const ida::script::Value& self) {
            return runtime_result("script.Value.coerce_integer", [&] {
                return self.coerce_integer();
            });
        })
        .def("coerce_floating", [](const ida::script::Value& self) {
            return runtime_result("script.Value.coerce_floating", [&] {
                return self.coerce_floating();
            });
        })
        .def("coerce_string", [](const ida::script::Value& self) {
            return runtime_result("script.Value.coerce_string", [&] {
                return self.coerce_string();
            });
        })
        .def("render", [](const ida::script::Value& self,
                           const std::optional<std::string>& name,
                           std::size_t indent) {
            std::optional<std::string_view> name_view;
            if (name) name_view = *name;
            return runtime_result("script.Value.render", [&] {
                return self.render(name_view, indent);
            });
        }, py::arg("name") = py::none(), py::arg("indent") = 0)
        .def("deep_copy", [](const ida::script::Value& self) {
            return runtime_result("script.Value.deep_copy", [&] {
                return self.deep_copy();
            });
        })
        .def_property_readonly("class_name", [](const ida::script::Value& self) {
            return runtime_result("script.Value.class_name", [&] {
                return self.class_name();
            });
        })
        .def("attribute", [](const ida::script::Value& self,
                              const std::string& name, bool use_handler) {
            return runtime_result("script.Value.attribute", [&] {
                return self.attribute(name, use_handler);
            });
        }, py::arg("name"), py::arg("use_handler") = false)
        .def("set_attribute", [](ida::script::Value& self,
                                  const std::string& name,
                                  const ida::script::Value& value,
                                  bool use_handler) {
            runtime_status("script.Value.set_attribute", [&] {
                return self.set_attribute(name, value, use_handler);
            });
        }, py::arg("name"), py::arg("value"),
           py::arg("use_handler") = false)
        .def("attribute_names", [](const ida::script::Value& self) {
            return runtime_result("script.Value.attribute_names", [&] {
                return self.attribute_names();
            });
        })
        .def("remove_attribute", [](ida::script::Value& self,
                                     const std::string& name) {
            return runtime_result("script.Value.remove_attribute", [&] {
                return self.remove_attribute(name);
            });
        }, py::arg("name"))
        .def("slice", [](const ida::script::Value& self,
                          std::size_t begin, std::size_t end) {
            return runtime_result("script.Value.slice", [&] {
                return self.slice(begin, end);
            });
        }, py::arg("begin"), py::arg("end"))
        .def("replace_slice", [](ida::script::Value& self,
                                  std::size_t begin, std::size_t end,
                                  const ida::script::Value& replacement) {
            runtime_status("script.Value.replace_slice", [&] {
                return self.replace_slice(begin, end, replacement);
            });
        }, py::arg("begin"), py::arg("end"), py::arg("replacement"))
        .def("dereference", [](const ida::script::Value& self,
                                ida::script::DereferenceMode mode) {
            return runtime_result("script.Value.dereference", [&] {
                return self.dereference(mode);
            });
        }, py::arg("mode") = ida::script::DereferenceMode::Recursive)
        .def("__copy__", [](const ida::script::Value& self) {
            return ida::script::Value(self);
        })
        .def("__deepcopy__", [](const ida::script::Value& self, py::dict) {
            return runtime_result("script.Value.__deepcopy__", [&] {
                return self.deep_copy();
            });
        }, py::arg("memo"))
        .def("__repr__", [](const ida::script::Value& self) {
            auto rendered = runtime_result("script.Value.__repr__", [&] {
                return self.render();
            });
            return "Value(" + rendered + ")";
        });

    py::class_<ida::script::ResolvedName>(script, "ResolvedName")
        .def(py::init<>())
        .def(py::init<std::string, std::uint64_t>(),
             py::arg("name"), py::arg("value"))
        .def_readwrite("name", &ida::script::ResolvedName::name)
        .def_readwrite("value", &ida::script::ResolvedName::value);

    py::class_<ida::script::CompileOptions>(script, "CompileOptions")
        .def(py::init<>())
        .def_readwrite("only_safe_functions",
                       &ida::script::CompileOptions::only_safe_functions)
        .def_readwrite("resolved_names",
                       &ida::script::CompileOptions::resolved_names);

    py::class_<ida::script::FileCompileOptions>(script, "FileCompileOptions")
        .def(py::init<>())
        .def_readwrite("delete_macros_after_compilation",
                       &ida::script::FileCompileOptions::delete_macros_after_compilation)
        .def_readwrite("allow_program_labels",
                       &ida::script::FileCompileOptions::allow_program_labels)
        .def_readwrite("only_safe_functions",
                       &ida::script::FileCompileOptions::only_safe_functions);

    py::class_<ida::script::CompilationResult>(script, "CompilationResult")
        .def_readonly("succeeded", &ida::script::CompilationResult::succeeded)
        .def_readonly("error", &ida::script::CompilationResult::error)
        .def("__bool__", [](const ida::script::CompilationResult& self) {
            return self.succeeded;
        });

    py::class_<ida::script::ExecutionResult>(script, "ExecutionResult")
        .def_readonly("succeeded", &ida::script::ExecutionResult::succeeded)
        .def_readonly("value", &ida::script::ExecutionResult::value)
        .def_readonly("error", &ida::script::ExecutionResult::error)
        .def("__bool__", [](const ida::script::ExecutionResult& self) {
            return self.succeeded;
        });

    py::class_<ida::script::IntegerExecutionResult>(
        script, "IntegerExecutionResult")
        .def_readonly("succeeded",
                      &ida::script::IntegerExecutionResult::succeeded)
        .def_readonly("value", &ida::script::IntegerExecutionResult::value)
        .def_readonly("error", &ida::script::IntegerExecutionResult::error)
        .def("__bool__", [](const ida::script::IntegerExecutionResult& self) {
            return self.succeeded;
        });

    script.def("evaluate", [](const std::string& expression, ida::Address where) {
        return runtime_result("script.evaluate", [&] {
            return ida::script::evaluate(expression, where);
        });
    }, py::arg("expression"), py::arg("where") = ida::BadAddress);

    script.def("evaluate_idc", [](const std::string& expression,
                                   ida::Address where) {
        return runtime_result("script.evaluate_idc", [&] {
            return ida::script::evaluate_idc(expression, where);
        });
    }, py::arg("expression"), py::arg("where") = ida::BadAddress);

    script.def("evaluate_integer", [](const std::string& expression,
                                       ida::Address where) {
        return runtime_result("script.evaluate_integer", [&] {
            return ida::script::evaluate_integer(expression, where);
        });
    }, py::arg("expression"), py::arg("where") = ida::BadAddress);

    script.def("compile_file", [](const std::string& path,
                                   const ida::script::FileCompileOptions& options) {
        return runtime_result("script.compile_file", [&] {
            return ida::script::compile_file(path, options);
        });
    }, py::arg("path"),
       py::arg("options") = ida::script::FileCompileOptions{});

    script.def("compile_text", [](const std::string& source,
                                   const ida::script::CompileOptions& options) {
        return runtime_result("script.compile_text", [&] {
            return ida::script::compile_text(source, options);
        });
    }, py::arg("source"), py::arg("options") = ida::script::CompileOptions{});

    script.def("compile_snippet", [](const std::string& function_name,
                                      const std::string& body,
                                      const ida::script::CompileOptions& options) {
        return runtime_result("script.compile_snippet", [&] {
            return ida::script::compile_snippet(function_name, body, options);
        });
    }, py::arg("function_name"), py::arg("body"),
       py::arg("options") = ida::script::CompileOptions{});

    script.def("call", [](const std::string& function_name,
                           const std::vector<ida::script::Value>& arguments,
                           const std::vector<ida::script::ResolvedName>& resolved_names) {
        return runtime_result("script.call", [&] {
            return ida::script::call(function_name, arguments, resolved_names);
        });
    }, py::arg("function_name"),
       py::arg("arguments") = std::vector<ida::script::Value>{},
       py::arg("resolved_names") = std::vector<ida::script::ResolvedName>{});

    script.def("execute_script", [](const std::string& path,
                                     const std::string& function_name,
                                     const std::vector<ida::script::Value>& arguments,
                                     const ida::script::FileCompileOptions& options) {
        return runtime_result("script.execute_script", [&] {
            return ida::script::execute_script(
                path, function_name, arguments, options);
        });
    }, py::arg("path"), py::arg("function_name"),
       py::arg("arguments") = std::vector<ida::script::Value>{},
       py::arg("options") = ida::script::FileCompileOptions{});

    script.def("evaluate_snippet", [](const std::string& source,
                                       const std::vector<ida::script::ResolvedName>& resolved_names) {
        return runtime_result("script.evaluate_snippet", [&] {
            return ida::script::evaluate_snippet(source, resolved_names);
        });
    }, py::arg("source"),
       py::arg("resolved_names") = std::vector<ida::script::ResolvedName>{});

    script.def("set_include_paths", [](const std::vector<std::string>& paths) {
        runtime_status("script.set_include_paths", [&] {
            return ida::script::set_include_paths(paths);
        });
    }, py::arg("paths"));

    script.def("append_include_paths", [](const std::vector<std::string>& paths) {
        runtime_status("script.append_include_paths", [&] {
            return ida::script::append_include_paths(paths);
        });
    }, py::arg("paths"));

    script.def("resolve_file", [](const std::string& file) {
        return runtime_result("script.resolve_file", [&] {
            return ida::script::resolve_file(file);
        });
    }, py::arg("file"));

    script.def("execute_system_script", [](const std::string& file,
                                            bool complain_if_missing) {
        runtime_status("script.execute_system_script", [&] {
            return ida::script::execute_system_script(
                file, complain_if_missing);
        });
    }, py::arg("file"), py::arg("complain_if_missing") = false);

    script.def("function_names", [](const std::string& prefix,
                                     std::size_t maximum) {
        return runtime_result("script.function_names", [&] {
            return ida::script::function_names(prefix, maximum);
        });
    }, py::arg("prefix") = "", py::arg("maximum") = 1024);

    script.def("global_value", [](const std::string& name) {
        return runtime_result("script.global_value", [&] {
            return ida::script::global(name);
        });
    }, py::arg("name"));

    script.def("set_global", [](const std::string& name,
                                 const ida::script::Value& value) {
        return runtime_result("script.set_global", [&] {
            return ida::script::set_global(name, value);
        });
    }, py::arg("name"), py::arg("value"));

    script.def("reference_global", [](const std::string& name) {
        return runtime_result("script.reference_global", [&] {
            return ida::script::reference_global(name);
        });
    }, py::arg("name"));
}

} // namespace idax::python
