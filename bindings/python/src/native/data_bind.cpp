#include "common.hpp"

#include <limits>

namespace idax::python {

namespace {

struct PythonCustomDataTypeDefinition {
    ida::data::CustomDataTypeDefinition value;
    py::object may_create_at{py::none()};
    py::object calculate_size{py::none()};
};

struct PythonCustomDataFormatDefinition {
    ida::data::CustomDataFormatDefinition value;
    py::object render{py::none()};
    py::object scan{py::none()};
    py::object analyze{py::none()};
};

template <typename Result, typename Function>
Result callback_result(const py::function& callback, Function&& function,
                       Result fallback) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return std::forward<Function>(function)();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python custom data callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return fallback;
}

ida::data::CustomDataTypeDefinition materialize(
    const PythonCustomDataTypeDefinition& source) {
    auto result = source.value;
    if (!source.may_create_at.is_none()) {
        py::function callback = source.may_create_at.cast<py::function>();
        result.may_create_at = [callback = std::move(callback)](
            ida::Address address, ida::AddressSize byte_length) {
            return callback_result<bool>(callback, [&] {
                return callback(address, byte_length).cast<bool>();
            }, false);
        };
    }
    if (!source.calculate_size.is_none()) {
        py::function callback = source.calculate_size.cast<py::function>();
        result.calculate_size = [callback = std::move(callback)](
            ida::Address address, ida::AddressSize maximum_size) {
            return callback_result<ida::AddressSize>(callback, [&] {
                return callback(address, maximum_size).cast<ida::AddressSize>();
            }, 0);
        };
    }
    return result;
}

ida::data::CustomDataFormatDefinition materialize(
    const PythonCustomDataFormatDefinition& source) {
    auto result = source.value;
    if (!source.render.is_none()) {
        py::function callback = source.render.cast<py::function>();
        result.render = [callback = std::move(callback)](
            std::span<const std::uint8_t> bytes,
            const ida::data::CustomDataFormatContext& context)
            -> ida::Result<std::string> {
            py::gil_scoped_acquire acquire;
            try {
                py::bytes value(reinterpret_cast<const char*>(bytes.data()),
                                static_cast<py::ssize_t>(bytes.size()));
                return callback(value, context).cast<std::string>();
            } catch (py::error_already_set& error) {
                std::string message = error.what();
                error.discard_as_unraisable(callback);
                return std::unexpected(ida::Error::internal(
                    "Python custom data render callback failed", message));
            }
        };
    }
    if (!source.scan.is_none()) {
        py::function callback = source.scan.cast<py::function>();
        result.scan = [callback = std::move(callback)](
            std::string_view text,
            const ida::data::CustomDataFormatContext& context)
            -> ida::Result<std::vector<std::uint8_t>> {
            py::gil_scoped_acquire acquire;
            try {
                return buffer_bytes(callback(text, context));
            } catch (py::error_already_set& error) {
                std::string message = error.what();
                error.discard_as_unraisable(callback);
                return std::unexpected(ida::Error::internal(
                    "Python custom data scan callback failed", message));
            }
        };
    }
    if (!source.analyze.is_none()) {
        py::function callback = source.analyze.cast<py::function>();
        result.analyze = [callback = std::move(callback)](
            const ida::data::CustomDataFormatContext& context) {
            py::gil_scoped_acquire acquire;
            try {
                callback(context);
            } catch (py::error_already_set& error) {
                error.discard_as_unraisable(callback);
            }
        };
    }
    return result;
}

} // namespace

void bind_data(py::module_& module) {
    py::module_ data = module.def_submodule(
        "data", "Typed bytes, patches, items, strings, and custom data.");

    py::native_enum<ida::data::TypedValueKind>(
        data, "TypedValueKind", "enum.Enum")
        .value("UNSIGNED_INTEGER", ida::data::TypedValueKind::UnsignedInteger)
        .value("SIGNED_INTEGER", ida::data::TypedValueKind::SignedInteger)
        .value("FLOATING_POINT", ida::data::TypedValueKind::FloatingPoint)
        .value("POINTER", ida::data::TypedValueKind::Pointer)
        .value("STRING", ida::data::TypedValueKind::String)
        .value("BYTES", ida::data::TypedValueKind::Bytes)
        .value("ARRAY", ida::data::TypedValueKind::Array)
        .finalize();
    py::class_<ida::data::TypedValue>(data, "TypedValue")
        .def(py::init<>())
        .def_readwrite("kind", &ida::data::TypedValue::kind)
        .def_readwrite("unsigned_value", &ida::data::TypedValue::unsigned_value)
        .def_readwrite("signed_value", &ida::data::TypedValue::signed_value)
        .def_readwrite("floating_value", &ida::data::TypedValue::floating_value)
        .def_readwrite("pointer_value", &ida::data::TypedValue::pointer_value)
        .def_readwrite("string_value", &ida::data::TypedValue::string_value)
        .def_property("bytes", [](const ida::data::TypedValue& self) {
            return python_bytes(self.bytes);
        }, [](ida::data::TypedValue& self, py::handle value) {
            self.bytes = buffer_bytes(value);
        })
        .def_readwrite("elements", &ida::data::TypedValue::elements);
    py::class_<ida::data::StringListOptions>(data, "StringListOptions")
        .def(py::init<>())
        .def_readwrite("string_types", &ida::data::StringListOptions::string_types)
        .def_readwrite("minimum_length", &ida::data::StringListOptions::minimum_length)
        .def_readwrite("only_7bit", &ida::data::StringListOptions::only_7bit)
        .def_readwrite("ignore_instructions",
                       &ida::data::StringListOptions::ignore_instructions)
        .def_readwrite("display_only_existing_strings",
                       &ida::data::StringListOptions::display_only_existing_strings);
    py::class_<ida::data::StringLiteral>(data, "StringLiteral")
        .def(py::init<>())
        .def_readwrite("address", &ida::data::StringLiteral::address)
        .def_readwrite("byte_length", &ida::data::StringLiteral::byte_length)
        .def_readwrite("string_type", &ida::data::StringLiteral::string_type)
        .def_readwrite("text", &ida::data::StringLiteral::text);
    py::class_<ida::data::CustomDataTypeId>(data, "CustomDataTypeId")
        .def(py::init<>())
        .def(py::init<std::uint16_t>(), py::arg("value"))
        .def_readwrite("value", &ida::data::CustomDataTypeId::value)
        .def("__eq__", [](ida::data::CustomDataTypeId left,
                           ida::data::CustomDataTypeId right) {
            return left == right;
        });
    py::class_<ida::data::CustomDataFormatId>(data, "CustomDataFormatId")
        .def(py::init<>())
        .def(py::init<std::uint16_t>(), py::arg("value"))
        .def_readwrite("value", &ida::data::CustomDataFormatId::value)
        .def("__eq__", [](ida::data::CustomDataFormatId left,
                           ida::data::CustomDataFormatId right) {
            return left == right;
        });
    py::class_<ida::data::CustomDataFormatContext>(data, "CustomDataFormatContext")
        .def(py::init<>())
        .def_readwrite("address", &ida::data::CustomDataFormatContext::address)
        .def_readwrite("operand_index",
                       &ida::data::CustomDataFormatContext::operand_index)
        .def_readwrite("type_id", &ida::data::CustomDataFormatContext::type_id);

    py::class_<PythonCustomDataTypeDefinition>(data, "CustomDataTypeDefinition")
        .def(py::init<>())
        .def_property("name", [](const PythonCustomDataTypeDefinition& self) {
            return self.value.name;
        }, [](PythonCustomDataTypeDefinition& self, std::string value) {
            self.value.name = std::move(value);
        })
        .def_property("menu_name", [](const PythonCustomDataTypeDefinition& self) {
            return self.value.menu_name;
        }, [](PythonCustomDataTypeDefinition& self, std::string value) {
            self.value.menu_name = std::move(value);
        })
        .def_property("hotkey", [](const PythonCustomDataTypeDefinition& self) {
            return self.value.hotkey;
        }, [](PythonCustomDataTypeDefinition& self, std::string value) {
            self.value.hotkey = std::move(value);
        })
        .def_property("assembler_keyword",
                      [](const PythonCustomDataTypeDefinition& self) {
                          return self.value.assembler_keyword;
                      },
                      [](PythonCustomDataTypeDefinition& self, std::string value) {
                          self.value.assembler_keyword = std::move(value);
                      })
        .def_property("value_size", [](const PythonCustomDataTypeDefinition& self) {
            return self.value.value_size;
        }, [](PythonCustomDataTypeDefinition& self, ida::AddressSize value) {
            self.value.value_size = value;
        })
        .def_property("allow_duplicates",
                      [](const PythonCustomDataTypeDefinition& self) {
                          return self.value.allow_duplicates;
                      },
                      [](PythonCustomDataTypeDefinition& self, bool value) {
                          self.value.allow_duplicates = value;
                      })
        .def_readwrite("may_create_at", &PythonCustomDataTypeDefinition::may_create_at)
        .def_readwrite("calculate_size", &PythonCustomDataTypeDefinition::calculate_size);
    py::class_<ida::data::CustomDataTypeInfo>(data, "CustomDataTypeInfo")
        .def(py::init<>())
        .def_readwrite("id", &ida::data::CustomDataTypeInfo::id)
        .def_readwrite("name", &ida::data::CustomDataTypeInfo::name)
        .def_readwrite("menu_name", &ida::data::CustomDataTypeInfo::menu_name)
        .def_readwrite("hotkey", &ida::data::CustomDataTypeInfo::hotkey)
        .def_readwrite("assembler_keyword",
                       &ida::data::CustomDataTypeInfo::assembler_keyword)
        .def_readwrite("value_size", &ida::data::CustomDataTypeInfo::value_size)
        .def_readwrite("allow_duplicates",
                       &ida::data::CustomDataTypeInfo::allow_duplicates)
        .def_readwrite("visible_in_menu",
                       &ida::data::CustomDataTypeInfo::visible_in_menu)
        .def_readwrite("has_creation_filter",
                       &ida::data::CustomDataTypeInfo::has_creation_filter)
        .def_readwrite("variable_size", &ida::data::CustomDataTypeInfo::variable_size);
    py::class_<PythonCustomDataFormatDefinition>(data, "CustomDataFormatDefinition")
        .def(py::init<>())
        .def_property("name", [](const PythonCustomDataFormatDefinition& self) {
            return self.value.name;
        }, [](PythonCustomDataFormatDefinition& self, std::string value) {
            self.value.name = std::move(value);
        })
        .def_property("menu_name", [](const PythonCustomDataFormatDefinition& self) {
            return self.value.menu_name;
        }, [](PythonCustomDataFormatDefinition& self, std::string value) {
            self.value.menu_name = std::move(value);
        })
        .def_property("hotkey", [](const PythonCustomDataFormatDefinition& self) {
            return self.value.hotkey;
        }, [](PythonCustomDataFormatDefinition& self, std::string value) {
            self.value.hotkey = std::move(value);
        })
        .def_property("value_size", [](const PythonCustomDataFormatDefinition& self) {
            return self.value.value_size;
        }, [](PythonCustomDataFormatDefinition& self, ida::AddressSize value) {
            self.value.value_size = value;
        })
        .def_property("text_width", [](const PythonCustomDataFormatDefinition& self) {
            return self.value.text_width;
        }, [](PythonCustomDataFormatDefinition& self, std::int32_t value) {
            self.value.text_width = value;
        })
        .def_readwrite("render", &PythonCustomDataFormatDefinition::render)
        .def_readwrite("scan", &PythonCustomDataFormatDefinition::scan)
        .def_readwrite("analyze", &PythonCustomDataFormatDefinition::analyze);
    py::class_<ida::data::CustomDataFormatInfo>(data, "CustomDataFormatInfo")
        .def(py::init<>())
        .def_readwrite("id", &ida::data::CustomDataFormatInfo::id)
        .def_readwrite("name", &ida::data::CustomDataFormatInfo::name)
        .def_readwrite("menu_name", &ida::data::CustomDataFormatInfo::menu_name)
        .def_readwrite("hotkey", &ida::data::CustomDataFormatInfo::hotkey)
        .def_readwrite("value_size", &ida::data::CustomDataFormatInfo::value_size)
        .def_readwrite("text_width", &ida::data::CustomDataFormatInfo::text_width)
        .def_readwrite("visible_in_menu",
                       &ida::data::CustomDataFormatInfo::visible_in_menu)
        .def_readwrite("can_render", &ida::data::CustomDataFormatInfo::can_render)
        .def_readwrite("can_scan", &ida::data::CustomDataFormatInfo::can_scan)
        .def_readwrite("can_analyze", &ida::data::CustomDataFormatInfo::can_analyze);
    py::class_<ida::data::CustomDataItemInfo>(data, "CustomDataItemInfo")
        .def(py::init<>())
        .def_readwrite("type_id", &ida::data::CustomDataItemInfo::type_id)
        .def_readwrite("format_id", &ida::data::CustomDataItemInfo::format_id)
        .def_readwrite("byte_length", &ida::data::CustomDataItemInfo::byte_length);

#define IDAX_PY_DATA_ADDRESS_RESULT(fn)                                  \
    data.def(#fn, [](ida::Address address) {                             \
        return runtime_result("data." #fn, [=] { return ida::data::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_DATA_ADDRESS_RESULT(read_byte);
    IDAX_PY_DATA_ADDRESS_RESULT(read_word);
    IDAX_PY_DATA_ADDRESS_RESULT(read_dword);
    IDAX_PY_DATA_ADDRESS_RESULT(read_qword);
    IDAX_PY_DATA_ADDRESS_RESULT(original_byte);
    IDAX_PY_DATA_ADDRESS_RESULT(original_word);
    IDAX_PY_DATA_ADDRESS_RESULT(original_dword);
    IDAX_PY_DATA_ADDRESS_RESULT(original_qword);
    IDAX_PY_DATA_ADDRESS_RESULT(custom_data_at);
#undef IDAX_PY_DATA_ADDRESS_RESULT
    data.def("read_bytes", [](ida::Address address, ida::AddressSize count) {
        auto bytes = runtime_result("data.read_bytes", [=] {
            return ida::data::read_bytes(address, count);
        });
        return python_bytes(bytes);
    }, py::arg("address"), py::arg("count"));
    data.def("read_string", [](ida::Address address, ida::AddressSize max_length,
                                std::int32_t string_type, int conversion_flags) {
        return runtime_result("data.read_string", [=] {
            return ida::data::read_string(
                address, max_length, string_type, conversion_flags);
        });
    }, py::arg("address"), py::arg("max_length") = 0,
       py::arg("string_type") = 0, py::arg("conversion_flags") = 0);
    data.def("string_list_options", [] {
        return runtime_result("data.string_list_options",
                              ida::data::string_list_options);
    });
    data.def("configure_string_list", [](const ida::data::StringListOptions& options) {
        runtime_status("data.configure_string_list", [&] {
            return ida::data::configure_string_list(options);
        });
    }, py::arg("options"));
#define IDAX_PY_DATA_NOARG_STATUS(fn)                                    \
    data.def(#fn, [] { runtime_status("data." #fn, ida::data::fn); })
    IDAX_PY_DATA_NOARG_STATUS(rebuild_string_list);
    IDAX_PY_DATA_NOARG_STATUS(clear_string_list);
#undef IDAX_PY_DATA_NOARG_STATUS
    data.def("string_literals", [](bool rebuild) {
        return runtime_result("data.string_literals", [=] {
            return ida::data::string_literals(rebuild);
        });
    }, py::arg("rebuild") = true);
    data.def("read_typed", [](ida::Address address,
                               const ida::type::TypeInfo& type) {
        return runtime_result("data.read_typed", [&] {
            return ida::data::read_typed(address, type);
        });
    }, py::arg("address"), py::arg("type"));

#define IDAX_PY_DATA_WRITE_SCALAR(fn, value_type)                        \
    data.def(#fn, [](ida::Address address, value_type value) {           \
        runtime_status("data." #fn, [=] { return ida::data::fn(address, value); }); \
    }, py::arg("address"), py::arg("value"))
    IDAX_PY_DATA_WRITE_SCALAR(write_byte, std::uint8_t);
    IDAX_PY_DATA_WRITE_SCALAR(write_word, std::uint16_t);
    IDAX_PY_DATA_WRITE_SCALAR(write_dword, std::uint32_t);
    IDAX_PY_DATA_WRITE_SCALAR(write_qword, std::uint64_t);
    IDAX_PY_DATA_WRITE_SCALAR(patch_byte, std::uint8_t);
    IDAX_PY_DATA_WRITE_SCALAR(patch_word, std::uint16_t);
    IDAX_PY_DATA_WRITE_SCALAR(patch_dword, std::uint32_t);
    IDAX_PY_DATA_WRITE_SCALAR(patch_qword, std::uint64_t);
#undef IDAX_PY_DATA_WRITE_SCALAR
#define IDAX_PY_DATA_WRITE_BYTES(fn)                                     \
    data.def(#fn, [](ida::Address address, py::handle value) {           \
        auto bytes = buffer_bytes(value);                                \
        runtime_status("data." #fn, [&] { return ida::data::fn(address, bytes); }); \
    }, py::arg("address"), py::arg("data"))
    IDAX_PY_DATA_WRITE_BYTES(write_bytes);
    IDAX_PY_DATA_WRITE_BYTES(patch_bytes);
#undef IDAX_PY_DATA_WRITE_BYTES
    data.def("write_typed", [](ida::Address address,
                                const ida::type::TypeInfo& type,
                                const ida::data::TypedValue& value) {
        runtime_status("data.write_typed", [&] {
            return ida::data::write_typed(address, type, value);
        });
    }, py::arg("address"), py::arg("type"), py::arg("value"));
    data.def("revert_patch", [](ida::Address address) {
        runtime_status("data.revert_patch", [=] { return ida::data::revert_patch(address); });
    }, py::arg("address"));
    data.def("revert_patches", [](ida::Address address, ida::AddressSize count) {
        return runtime_result("data.revert_patches", [=] {
            return ida::data::revert_patches(address, count);
        });
    }, py::arg("address"), py::arg("count"));

#define IDAX_PY_DATA_DEFINE(fn)                                         \
    data.def(#fn, [](ida::Address address, ida::AddressSize count) {     \
        runtime_status("data." #fn, [=] { return ida::data::fn(address, count); }); \
    }, py::arg("address"), py::arg("count") = 1)
    IDAX_PY_DATA_DEFINE(define_byte);
    IDAX_PY_DATA_DEFINE(define_word);
    IDAX_PY_DATA_DEFINE(define_dword);
    IDAX_PY_DATA_DEFINE(define_qword);
    IDAX_PY_DATA_DEFINE(define_oword);
    IDAX_PY_DATA_DEFINE(define_yword);
    IDAX_PY_DATA_DEFINE(define_zword);
    IDAX_PY_DATA_DEFINE(define_tbyte);
    IDAX_PY_DATA_DEFINE(define_packed_real);
    IDAX_PY_DATA_DEFINE(define_float);
    IDAX_PY_DATA_DEFINE(define_double);
    IDAX_PY_DATA_DEFINE(undefine);
#undef IDAX_PY_DATA_DEFINE
#define IDAX_PY_DATA_SIZE_RESULT(fn)                                    \
    data.def(#fn, [] { return runtime_result("data." #fn, ida::data::fn); })
    IDAX_PY_DATA_SIZE_RESULT(tbyte_element_size);
    IDAX_PY_DATA_SIZE_RESULT(packed_real_element_size);
#undef IDAX_PY_DATA_SIZE_RESULT
    data.def("define_string", [](ida::Address address, ida::AddressSize length,
                                  std::int32_t string_type) {
        runtime_status("data.define_string", [=] {
            return ida::data::define_string(address, length, string_type);
        });
    }, py::arg("address"), py::arg("length"), py::arg("string_type") = 0);
    data.def("define_struct", [](ida::Address address, ida::AddressSize length,
                                  std::uint64_t structure_id) {
        runtime_status("data.define_struct", [=] {
            return ida::data::define_struct(address, length, structure_id);
        });
    }, py::arg("address"), py::arg("length"), py::arg("structure_id"));

    data.def("register_custom_data_type", [](
        const PythonCustomDataTypeDefinition& definition) {
        auto native = materialize(definition);
        return runtime_result("data.register_custom_data_type", [&] {
            return ida::data::register_custom_data_type(native);
        });
    }, py::arg("definition"));
    data.def("unregister_custom_data_type", [](ida::data::CustomDataTypeId id) {
        runtime_status("data.unregister_custom_data_type", [=] {
            return ida::data::unregister_custom_data_type(id);
        });
    }, py::arg("type_id"));
    data.def("custom_data_type", [](ida::data::CustomDataTypeId id) {
        return runtime_result("data.custom_data_type", [=] {
            return ida::data::custom_data_type(id);
        });
    }, py::arg("type_id"));
    data.def("find_custom_data_type", [](std::string name) {
        return runtime_result("data.find_custom_data_type", [&] {
            return ida::data::find_custom_data_type(name);
        });
    }, py::arg("name"));
    data.def("custom_data_types", [](ida::AddressSize minimum,
                                      ida::AddressSize maximum) {
        return runtime_result("data.custom_data_types", [=] {
            return ida::data::custom_data_types(minimum, maximum);
        });
    }, py::arg("minimum_size") = 0,
       py::arg("maximum_size") = std::numeric_limits<ida::AddressSize>::max());
    data.def("register_custom_data_format", [](
        const PythonCustomDataFormatDefinition& definition) {
        auto native = materialize(definition);
        return runtime_result("data.register_custom_data_format", [&] {
            return ida::data::register_custom_data_format(native);
        });
    }, py::arg("definition"));
    data.def("unregister_custom_data_format", [](ida::data::CustomDataFormatId id) {
        runtime_status("data.unregister_custom_data_format", [=] {
            return ida::data::unregister_custom_data_format(id);
        });
    }, py::arg("format_id"));
    data.def("custom_data_format", [](ida::data::CustomDataFormatId id) {
        return runtime_result("data.custom_data_format", [=] {
            return ida::data::custom_data_format(id);
        });
    }, py::arg("format_id"));
    data.def("find_custom_data_format", [](std::string name) {
        return runtime_result("data.find_custom_data_format", [&] {
            return ida::data::find_custom_data_format(name);
        });
    }, py::arg("name"));
    data.def("custom_data_formats", [](ida::data::CustomDataTypeId id) {
        return runtime_result("data.custom_data_formats", [=] {
            return ida::data::custom_data_formats(id);
        });
    }, py::arg("type_id"));
    data.def("standard_custom_data_formats", [] {
        return runtime_result("data.standard_custom_data_formats",
                              ida::data::standard_custom_data_formats);
    });

#define IDAX_PY_DATA_TYPE_FORMAT_STATUS(fn)                              \
    data.def(#fn, [](ida::data::CustomDataTypeId type_id,                \
                      ida::data::CustomDataFormatId format_id) {         \
        runtime_status("data." #fn, [=] { return ida::data::fn(type_id, format_id); }); \
    }, py::arg("type_id"), py::arg("format_id"))
    IDAX_PY_DATA_TYPE_FORMAT_STATUS(attach_custom_data_format);
    IDAX_PY_DATA_TYPE_FORMAT_STATUS(detach_custom_data_format);
#undef IDAX_PY_DATA_TYPE_FORMAT_STATUS
    data.def("is_custom_data_format_attached", [](
        ida::data::CustomDataTypeId type_id,
        ida::data::CustomDataFormatId format_id) {
        return runtime_result("data.is_custom_data_format_attached", [=] {
            return ida::data::is_custom_data_format_attached(type_id, format_id);
        });
    }, py::arg("type_id"), py::arg("format_id"));
#define IDAX_PY_DATA_FORMAT_STATUS(fn)                                   \
    data.def(#fn, [](ida::data::CustomDataFormatId format_id) {          \
        runtime_status("data." #fn, [=] { return ida::data::fn(format_id); }); \
    }, py::arg("format_id"))
    IDAX_PY_DATA_FORMAT_STATUS(attach_custom_data_format_to_standard_types);
    IDAX_PY_DATA_FORMAT_STATUS(detach_custom_data_format_from_standard_types);
#undef IDAX_PY_DATA_FORMAT_STATUS
    data.def("is_custom_data_format_attached_to_standard_types", [](
        ida::data::CustomDataFormatId format_id) {
        return runtime_result(
            "data.is_custom_data_format_attached_to_standard_types", [=] {
                return ida::data::is_custom_data_format_attached_to_standard_types(
                    format_id);
            });
    }, py::arg("format_id"));
    data.def("custom_data_item_size", [](ida::data::CustomDataTypeId type_id,
                                          ida::Address address,
                                          ida::AddressSize maximum_size) {
        return runtime_result("data.custom_data_item_size", [=] {
            return ida::data::custom_data_item_size(type_id, address, maximum_size);
        });
    }, py::arg("type_id"), py::arg("address"), py::arg("maximum_size"));
    data.def("define_custom", [](ida::Address address, ida::AddressSize length,
                                  ida::data::CustomDataTypeId type_id,
                                  ida::data::CustomDataFormatId format_id) {
        runtime_status("data.define_custom", [=] {
            return ida::data::define_custom(address, length, type_id, format_id);
        });
    }, py::arg("address"), py::arg("byte_length"), py::arg("type_id"),
       py::arg("format_id"));
    data.def("define_custom_inferred", [](
        ida::Address address, ida::data::CustomDataTypeId type_id,
        ida::data::CustomDataFormatId format_id, ida::AddressSize maximum_size) {
        runtime_status("data.define_custom_inferred", [=] {
            return ida::data::define_custom_inferred(
                address, type_id, format_id, maximum_size);
        });
    }, py::arg("address"), py::arg("type_id"), py::arg("format_id"),
       py::arg("maximum_size"));
    data.def("render_custom_data", [](
        ida::data::CustomDataFormatId format_id, py::handle value,
        const ida::data::CustomDataFormatContext& context) {
        auto bytes = buffer_bytes(value);
        return runtime_result("data.render_custom_data", [&] {
            return ida::data::render_custom_data(format_id, bytes, context);
        });
    }, py::arg("format_id"), py::arg("value"),
       py::arg("context") = ida::data::CustomDataFormatContext{});
    data.def("scan_custom_data", [](
        ida::data::CustomDataFormatId format_id, std::string text,
        const ida::data::CustomDataFormatContext& context) {
        auto bytes = runtime_result("data.scan_custom_data", [&] {
            return ida::data::scan_custom_data(format_id, text, context);
        });
        return python_bytes(bytes);
    }, py::arg("format_id"), py::arg("text"),
       py::arg("context") = ida::data::CustomDataFormatContext{});
    data.def("analyze_custom_data", [](
        ida::data::CustomDataFormatId format_id,
        const ida::data::CustomDataFormatContext& context) {
        runtime_status("data.analyze_custom_data", [&] {
            return ida::data::analyze_custom_data(format_id, context);
        });
    }, py::arg("format_id"),
       py::arg("context") = ida::data::CustomDataFormatContext{});
    data.def("find_binary_pattern", [](
        ida::Address start, ida::Address end, std::string pattern,
        bool forward, bool skip_start, bool case_sensitive, int radix,
        int string_literals_encoding) {
        return runtime_result("data.find_binary_pattern", [&] {
            return ida::data::find_binary_pattern(
                start, end, pattern, forward, skip_start, case_sensitive,
                radix, string_literals_encoding);
        });
    }, py::arg("start"), py::arg("end"), py::arg("pattern"),
       py::arg("forward") = true, py::arg("skip_start") = false,
       py::arg("case_sensitive") = true, py::arg("radix") = 16,
       py::arg("string_literals_encoding") = 0);
}

} // namespace idax::python
