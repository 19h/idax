#include "common.hpp"

namespace idax::python {

void bind_type(py::module_& module) {
    py::module_ type_module = module.def_submodule(
        "type", "Type construction, introspection, mutation, and rendering.");

    py::native_enum<ida::type::CallingConvention>(
        type_module, "CallingConvention", "enum.Enum")
        .value("UNKNOWN", ida::type::CallingConvention::Unknown)
        .value("CDECL", ida::type::CallingConvention::Cdecl)
        .value("STDCALL", ida::type::CallingConvention::Stdcall)
        .value("PASCAL", ida::type::CallingConvention::Pascal)
        .value("FASTCALL", ida::type::CallingConvention::Fastcall)
        .value("THISCALL", ida::type::CallingConvention::Thiscall)
        .value("SWIFT", ida::type::CallingConvention::Swift)
        .value("GOLANG", ida::type::CallingConvention::Golang)
        .value("USER_DEFINED", ida::type::CallingConvention::UserDefined)
        .finalize();
    py::native_enum<ida::type::TypeKind>(type_module, "TypeKind", "enum.Enum")
        .value("UNKNOWN", ida::type::TypeKind::Unknown)
        .value("VOID", ida::type::TypeKind::Void)
        .value("BOOL", ida::type::TypeKind::Bool)
        .value("CHARACTER", ida::type::TypeKind::Character)
        .value("SIGNED_INTEGER", ida::type::TypeKind::SignedInteger)
        .value("UNSIGNED_INTEGER", ida::type::TypeKind::UnsignedInteger)
        .value("FLOATING_POINT", ida::type::TypeKind::FloatingPoint)
        .value("POINTER", ida::type::TypeKind::Pointer)
        .value("ARRAY", ida::type::TypeKind::Array)
        .value("FUNCTION", ida::type::TypeKind::Function)
        .value("STRUCT", ida::type::TypeKind::Struct)
        .value("UNION", ida::type::TypeKind::Union)
        .value("ENUM", ida::type::TypeKind::Enum)
        .value("TYPEDEF", ida::type::TypeKind::Typedef)
        .finalize();
    py::native_enum<ida::type::EnumRadix>(type_module, "EnumRadix", "enum.Enum")
        .value("UNKNOWN", ida::type::EnumRadix::Unknown)
        .value("BINARY", ida::type::EnumRadix::Binary)
        .value("OCTAL", ida::type::EnumRadix::Octal)
        .value("DECIMAL", ida::type::EnumRadix::Decimal)
        .value("HEXADECIMAL", ida::type::EnumRadix::Hexadecimal)
        .finalize();

    py::class_<ida::type::EnumMember>(type_module, "EnumMember")
        .def(py::init<>())
        .def_readwrite("name", &ida::type::EnumMember::name)
        .def_readwrite("value", &ida::type::EnumMember::value)
        .def_readwrite("comment", &ida::type::EnumMember::comment);
    py::class_<ida::type::ParseDeclarationsOptions>(
        type_module, "ParseDeclarationsOptions")
        .def(py::init<>())
        .def_readwrite("suppress_warnings",
                       &ida::type::ParseDeclarationsOptions::suppress_warnings)
        .def_readwrite("relaxed_namespaces",
                       &ida::type::ParseDeclarationsOptions::relaxed_namespaces)
        .def_readwrite("raw_argument_names",
                       &ida::type::ParseDeclarationsOptions::raw_argument_names)
        .def_readwrite("no_mangle", &ida::type::ParseDeclarationsOptions::no_mangle)
        .def_readwrite("pack_alignment",
                       &ida::type::ParseDeclarationsOptions::pack_alignment);
    py::class_<ida::type::ParseDeclarationsReport>(
        type_module, "ParseDeclarationsReport")
        .def(py::init<>())
        .def_readwrite("error_count",
                       &ida::type::ParseDeclarationsReport::error_count)
        .def_property_readonly("ok", &ida::type::ParseDeclarationsReport::ok)
        .def("__bool__", &ida::type::ParseDeclarationsReport::ok);
    py::class_<ida::type::UsedMemberOffsets>(type_module, "UsedMemberOffsets")
        .def(py::init<>())
        .def_readwrite("type_name", &ida::type::UsedMemberOffsets::type_name)
        .def_readwrite("byte_offsets", &ida::type::UsedMemberOffsets::byte_offsets);
    py::class_<ida::type::TypeRenderOptions>(type_module, "TypeRenderOptions")
        .def(py::init<>())
        .def_readwrite("size_comments", &ida::type::TypeRenderOptions::size_comments)
        .def_readwrite("trim_unreferenced",
                       &ida::type::TypeRenderOptions::trim_unreferenced)
        .def_readwrite("used_offsets", &ida::type::TypeRenderOptions::used_offsets);

    auto graph_options = py::class_<ida::type::TypeGraphOptions>(
        type_module, "TypeGraphOptions");
    py::native_enum<ida::type::TypeGraphOptions::Mode>(
        graph_options, "Mode", "enum.Enum")
        .value("SIMPLE", ida::type::TypeGraphOptions::Mode::Simple)
        .value("TABLE", ida::type::TypeGraphOptions::Mode::Table)
        .finalize();
    graph_options
        .def(py::init<>())
        .def_readwrite("mode", &ida::type::TypeGraphOptions::mode)
        .def_readwrite("max_depth", &ida::type::TypeGraphOptions::max_depth)
        .def_readwrite("include_enums", &ida::type::TypeGraphOptions::include_enums)
        .def_readwrite("include_typedefs",
                       &ida::type::TypeGraphOptions::include_typedefs);

    py::class_<ida::type::TypeDeclaration>(type_module, "TypeDeclaration")
        .def(py::init<>())
        .def_readwrite("ordinal", &ida::type::TypeDeclaration::ordinal)
        .def_readwrite("name", &ida::type::TypeDeclaration::name)
        .def_readwrite("declaration", &ida::type::TypeDeclaration::declaration);

    auto type_info = py::class_<ida::type::TypeInfo>(type_module, "TypeInfo");
    type_info
        .def(py::init<>())
        .def_static("void_type", &ida::type::TypeInfo::void_type)
        .def_static("int8", &ida::type::TypeInfo::int8)
        .def_static("int16", &ida::type::TypeInfo::int16)
        .def_static("int32", &ida::type::TypeInfo::int32)
        .def_static("int64", &ida::type::TypeInfo::int64)
        .def_static("uint8", &ida::type::TypeInfo::uint8)
        .def_static("uint16", &ida::type::TypeInfo::uint16)
        .def_static("uint32", &ida::type::TypeInfo::uint32)
        .def_static("uint64", &ida::type::TypeInfo::uint64)
        .def_static("float32", &ida::type::TypeInfo::float32)
        .def_static("float64", &ida::type::TypeInfo::float64)
        .def_static("pointer_to", &ida::type::TypeInfo::pointer_to,
                    py::arg("target"))
        .def_static("array_of", &ida::type::TypeInfo::array_of,
                    py::arg("element"), py::arg("count"))
        .def_static("function_type", [](const ida::type::TypeInfo& return_type,
                                         const std::vector<ida::type::TypeInfo>& arguments,
                                         ida::type::CallingConvention convention,
                                         bool has_varargs) {
            return runtime_result("type.TypeInfo.function_type", [&] {
                return ida::type::TypeInfo::function_type(
                    return_type, arguments, convention, has_varargs);
            });
        }, py::arg("return_type"),
           py::arg("argument_types") = std::vector<ida::type::TypeInfo>{},
           py::arg("calling_convention") = ida::type::CallingConvention::Unknown,
           py::arg("has_varargs") = false)
        .def_static("enum_type", [](const std::vector<ida::type::EnumMember>& members,
                                     std::size_t byte_width, bool bitmask) {
            return runtime_result("type.TypeInfo.enum_type", [&] {
                return ida::type::TypeInfo::enum_type(members, byte_width, bitmask);
            });
        }, py::arg("members"), py::arg("byte_width") = 4,
           py::arg("bitmask") = false)
        .def_static("from_declaration", [](std::string declaration) {
            return runtime_result("type.TypeInfo.from_declaration", [&] {
                return ida::type::TypeInfo::from_declaration(declaration);
            });
        }, py::arg("c_declaration"))
        .def_static("create_struct", &ida::type::TypeInfo::create_struct)
        .def_static("create_union", &ida::type::TypeInfo::create_union)
        .def_static("by_name", [](std::string name) {
            return runtime_result("type.TypeInfo.by_name", [&] {
                return ida::type::TypeInfo::by_name(name);
            });
        }, py::arg("name"))
        .def_property_readonly("is_void", &ida::type::TypeInfo::is_void)
        .def_property_readonly("is_integer", &ida::type::TypeInfo::is_integer)
        .def_property_readonly("is_floating_point",
                               &ida::type::TypeInfo::is_floating_point)
        .def_property_readonly("is_pointer", &ida::type::TypeInfo::is_pointer)
        .def_property_readonly("is_array", &ida::type::TypeInfo::is_array)
        .def_property_readonly("is_function", &ida::type::TypeInfo::is_function)
        .def_property_readonly("is_struct", &ida::type::TypeInfo::is_struct)
        .def_property_readonly("is_union", &ida::type::TypeInfo::is_union)
        .def_property_readonly("is_enum", &ida::type::TypeInfo::is_enum)
        .def_property_readonly("is_typedef", &ida::type::TypeInfo::is_typedef)
        .def_property_readonly("is_bool", &ida::type::TypeInfo::is_bool)
        .def_property_readonly("is_char", &ida::type::TypeInfo::is_char)
        .def_property_readonly("is_unsigned_char",
                               &ida::type::TypeInfo::is_unsigned_char)
        .def_property_readonly("is_signed", &ida::type::TypeInfo::is_signed)
        .def_property_readonly("is_forward_declaration",
                               &ida::type::TypeInfo::is_forward_declaration)
        .def_property_readonly("forward_declaration_kind",
                               &ida::type::TypeInfo::forward_declaration_kind)
        .def_property_readonly("kind", &ida::type::TypeInfo::kind)
        .def_property_readonly("name", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.name", [&] { return self.name(); });
        })
        .def_property_readonly("size", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.size", [&] { return self.size(); });
        })
        .def("to_string", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.to_string", [&] {
                return self.to_string();
            });
        })
        .def("declaration", [](const ida::type::TypeInfo& self,
                                std::string declarator_name) {
            return runtime_result("type.TypeInfo.declaration", [&] {
                return self.declaration(declarator_name);
            });
        }, py::arg("declarator_name") = std::string{})
        .def("pointee_type", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.pointee_type", [&] {
                return self.pointee_type();
            });
        })
        .def("pointer_details", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.pointer_details", [&] {
                return self.pointer_details();
            });
        })
        .def("with_shifted_parent", [](const ida::type::TypeInfo& self,
                                        const ida::type::TypeInfo& parent,
                                        std::int64_t byte_delta) {
            return runtime_result("type.TypeInfo.with_shifted_parent", [&] {
                return self.with_shifted_parent(parent, byte_delta);
            });
        }, py::arg("parent"), py::arg("byte_delta"))
        .def("array_element_type", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.array_element_type", [&] {
                return self.array_element_type();
            });
        })
        .def("array_length", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.array_length", [&] {
                return self.array_length();
            });
        })
        .def("resolve_typedef", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.resolve_typedef", [&] {
                return self.resolve_typedef();
            });
        })
        .def("function_return_type", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.function_return_type", [&] {
                return self.function_return_type();
            });
        })
        .def("function_argument_types", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.function_argument_types", [&] {
                return self.function_argument_types();
            });
        })
        .def("function_details", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.function_details", [&] {
                return self.function_details();
            });
        })
        .def("with_function_argument_type", [](const ida::type::TypeInfo& self,
                                                 std::size_t index,
                                                 const ida::type::TypeInfo& replacement) {
            return runtime_result("type.TypeInfo.with_function_argument_type", [&] {
                return self.with_function_argument_type(index, replacement);
            });
        }, py::arg("index"), py::arg("replacement"))
        .def("with_function_argument_name", [](const ida::type::TypeInfo& self,
                                                 std::size_t index,
                                                 std::string name) {
            return runtime_result("type.TypeInfo.with_function_argument_name", [&] {
                return self.with_function_argument_name(index, name);
            });
        }, py::arg("index"), py::arg("name"))
        .def("with_function_return_type", [](const ida::type::TypeInfo& self,
                                               const ida::type::TypeInfo& replacement) {
            return runtime_result("type.TypeInfo.with_function_return_type", [&] {
                return self.with_function_return_type(replacement);
            });
        }, py::arg("replacement"))
        .def("calling_convention", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.calling_convention", [&] {
                return self.calling_convention();
            });
        })
        .def("is_variadic_function", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.is_variadic_function", [&] {
                return self.is_variadic_function();
            });
        })
        .def("enum_members", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.enum_members", [&] {
                return self.enum_members();
            });
        })
        .def("enum_details", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.enum_details", [&] {
                return self.enum_details();
            });
        })
        .def("member_count", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.member_count", [&] {
                return self.member_count();
            });
        })
        .def("members", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.members", [&] { return self.members(); });
        })
        .def("udt_details", [](const ida::type::TypeInfo& self) {
            return runtime_result("type.TypeInfo.udt_details", [&] {
                return self.udt_details();
            });
        })
        .def("set_udt_semantics", [](ida::type::TypeInfo& self,
                                      bool is_cpp_object, bool is_vftable) {
            runtime_status("type.TypeInfo.set_udt_semantics", [&] {
                return self.set_udt_semantics(is_cpp_object, is_vftable);
            });
        }, py::arg("is_cpp_object"), py::arg("is_vftable"))
        .def("member_by_name", [](const ida::type::TypeInfo& self,
                                   std::string name) {
            return runtime_result("type.TypeInfo.member_by_name", [&] {
                return self.member_by_name(name);
            });
        }, py::arg("name"))
        .def("member_by_offset", [](const ida::type::TypeInfo& self,
                                     std::size_t byte_offset) {
            return runtime_result("type.TypeInfo.member_by_offset", [&] {
                return self.member_by_offset(byte_offset);
            });
        }, py::arg("byte_offset"))
        .def("member_references", [](const ida::type::TypeInfo& self,
                                      std::size_t byte_offset) {
            return runtime_result("type.TypeInfo.member_references", [&] {
                return self.member_references(byte_offset);
            });
        }, py::arg("byte_offset"))
        .def("ensure_member_reference", [](const ida::type::TypeInfo& self,
                                            std::size_t byte_offset,
                                            ida::Address source_address) {
            return runtime_result("type.TypeInfo.ensure_member_reference", [&] {
                return self.ensure_member_reference(byte_offset, source_address);
            });
        }, py::arg("byte_offset"), py::arg("source_address"))
        .def("add_member", [](ida::type::TypeInfo& self, std::string name,
                               const ida::type::TypeInfo& member_type,
                               std::size_t byte_offset) {
            runtime_status("type.TypeInfo.add_member", [&] {
                return self.add_member(name, member_type, byte_offset);
            });
        }, py::arg("name"), py::arg("member_type"), py::arg("byte_offset") = 0)
        .def("apply", [](const ida::type::TypeInfo& self, ida::Address address) {
            runtime_status("type.TypeInfo.apply", [&] { return self.apply(address); });
        }, py::arg("address"))
        .def("save_as", [](const ida::type::TypeInfo& self, std::string name) {
            runtime_status("type.TypeInfo.save_as", [&] { return self.save_as(name); });
        }, py::arg("name"))
        .def("replace_forward_declaration", [](const ida::type::TypeInfo& self,
                                                 std::string name) {
            return runtime_result("type.TypeInfo.replace_forward_declaration", [&] {
                return self.replace_forward_declaration(name);
            });
        }, py::arg("name"));

    py::class_<ida::type::Member>(type_module, "Member")
        .def(py::init<>())
        .def_readwrite("name", &ida::type::Member::name)
        .def_readwrite("type", &ida::type::Member::type)
        .def_readwrite("byte_offset", &ida::type::Member::byte_offset)
        .def_readwrite("bit_size", &ida::type::Member::bit_size)
        .def_readwrite("bit_offset", &ida::type::Member::bit_offset)
        .def_readwrite("storage_byte_width", &ida::type::Member::storage_byte_width)
        .def_readwrite("is_baseclass", &ida::type::Member::is_baseclass)
        .def_readwrite("is_vftable", &ida::type::Member::is_vftable)
        .def_readwrite("is_gap", &ida::type::Member::is_gap)
        .def_readwrite("is_bitfield", &ida::type::Member::is_bitfield)
        .def_readwrite("comment", &ida::type::Member::comment);
    py::class_<ida::type::PointerDetails>(type_module, "PointerDetails")
        .def(py::init<>())
        .def_readwrite("pointee_type", &ida::type::PointerDetails::pointee_type)
        .def_readwrite("shifted_parent", &ida::type::PointerDetails::shifted_parent)
        .def_readwrite("shift_delta", &ida::type::PointerDetails::shift_delta)
        .def_readwrite("is_shifted", &ida::type::PointerDetails::is_shifted);
    py::class_<ida::type::FunctionArgument>(type_module, "FunctionArgument")
        .def(py::init<>())
        .def_readwrite("name", &ida::type::FunctionArgument::name)
        .def_readwrite("type", &ida::type::FunctionArgument::type);
    py::class_<ida::type::FunctionDetails>(type_module, "FunctionDetails")
        .def(py::init<>())
        .def_readwrite("return_type", &ida::type::FunctionDetails::return_type)
        .def_readwrite("arguments", &ida::type::FunctionDetails::arguments)
        .def_readwrite("calling_convention",
                       &ida::type::FunctionDetails::calling_convention)
        .def_readwrite("variadic", &ida::type::FunctionDetails::variadic);
    py::class_<ida::type::UdtDetails>(type_module, "UdtDetails")
        .def(py::init<>())
        .def_readwrite("total_size", &ida::type::UdtDetails::total_size)
        .def_readwrite("is_union", &ida::type::UdtDetails::is_union)
        .def_readwrite("is_cpp_object", &ida::type::UdtDetails::is_cpp_object)
        .def_readwrite("is_vftable", &ida::type::UdtDetails::is_vftable)
        .def_readwrite("members", &ida::type::UdtDetails::members);
    py::class_<ida::type::EnumDetails>(type_module, "EnumDetails")
        .def(py::init<>())
        .def_readwrite("byte_width", &ida::type::EnumDetails::byte_width)
        .def_readwrite("signed_values", &ida::type::EnumDetails::signed_values)
        .def_readwrite("radix", &ida::type::EnumDetails::radix)
        .def_readwrite("members", &ida::type::EnumDetails::members);

    type_module.def("retrieve", [](ida::Address address) {
        return runtime_result("type.retrieve", [=] { return ida::type::retrieve(address); });
    }, py::arg("address"));
    type_module.def("retrieve_operand", [](ida::Address address, int operand_index) {
        return runtime_result("type.retrieve_operand", [=] {
            return ida::type::retrieve_operand(address, operand_index);
        });
    }, py::arg("address"), py::arg("operand_index"));
    type_module.def("remove_type", [](ida::Address address) {
        runtime_status("type.remove_type", [=] { return ida::type::remove_type(address); });
    }, py::arg("address"));
    type_module.def("load_type_library", [](std::string name) {
        return runtime_result("type.load_type_library", [&] {
            return ida::type::load_type_library(name);
        });
    }, py::arg("name"));
    type_module.def("unload_type_library", [](std::string name) {
        runtime_status("type.unload_type_library", [&] {
            return ida::type::unload_type_library(name);
        });
    }, py::arg("name"));
    type_module.def("local_type_count", [] {
        return runtime_result("type.local_type_count", ida::type::local_type_count);
    });
    type_module.def("local_type_name", [](std::size_t ordinal) {
        return runtime_result("type.local_type_name", [=] {
            return ida::type::local_type_name(ordinal);
        });
    }, py::arg("ordinal"));
    type_module.def("import_type", [](std::string source_library,
                                       std::string type_name) {
        return runtime_result("type.import_type", [&] {
            return ida::type::import_type(source_library, type_name);
        });
    }, py::arg("source_library"), py::arg("type_name"));
    type_module.def("ensure_named_type", [](std::string type_name,
                                             std::string source_library) {
        return runtime_result("type.ensure_named_type", [&] {
            return ida::type::ensure_named_type(type_name, source_library);
        });
    }, py::arg("type_name"), py::arg("source_library") = std::string{});
    type_module.def("apply_named_type", [](ida::Address address,
                                            std::string type_name) {
        runtime_status("type.apply_named_type", [&] {
            return ida::type::apply_named_type(address, type_name);
        });
    }, py::arg("address"), py::arg("type_name"));
    type_module.def("parse_declarations", [](std::string declarations,
                                              const ida::type::ParseDeclarationsOptions& options) {
        return runtime_result("type.parse_declarations", [&] {
            return ida::type::parse_declarations(declarations, options);
        });
    }, py::arg("declarations"),
       py::arg("options") = ida::type::ParseDeclarationsOptions{});
    type_module.def("render_named_declarations", [](
        const std::vector<std::string>& names, int max_depth,
        const ida::type::TypeRenderOptions& options) {
        return runtime_result("type.render_named_declarations", [&] {
            return ida::type::render_named_declarations(names, max_depth, options);
        });
    }, py::arg("names"), py::arg("max_depth") = -1,
       py::arg("options") = ida::type::TypeRenderOptions{});
    type_module.def("render_ordinal_declarations", [](
        const std::vector<std::uint32_t>& ordinals,
        const ida::type::TypeRenderOptions& options) {
        return runtime_result("type.render_ordinal_declarations", [&] {
            return ida::type::render_ordinal_declarations(ordinals, options);
        });
    }, py::arg("ordinals"), py::arg("options") = ida::type::TypeRenderOptions{});
    type_module.def("render_type_graph", [](std::string root_name,
                                             const ida::type::TypeGraphOptions& options) {
        return runtime_result("type.render_type_graph", [&] {
            return ida::type::render_type_graph(root_name, options);
        });
    }, py::arg("root_name"), py::arg("options") = ida::type::TypeGraphOptions{});
    type_module.def("declarations_for_ordinals", [](
        const std::vector<std::uint32_t>& ordinals) {
        return runtime_result("type.declarations_for_ordinals", [&] {
            return ida::type::declarations_for_ordinals(ordinals);
        });
    }, py::arg("ordinals"));
}

} // namespace idax::python
