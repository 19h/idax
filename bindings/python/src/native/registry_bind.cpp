#include "common.hpp"

namespace idax::python {

void bind_registry(py::module_& module) {
    py::module_ registry = module.def_submodule(
        "registry", "Opaque scoped persistent plugin configuration.");

    py::native_enum<ida::registry::ValueKind>(
        registry, "ValueKind", "enum.Enum")
        .value("STRING", ida::registry::ValueKind::String)
        .value("BINARY", ida::registry::ValueKind::Binary)
        .value("INTEGER", ida::registry::ValueKind::Integer)
        .finalize();

    py::class_<ida::registry::StringListUpdate>(registry, "StringListUpdate")
        .def(py::init<>())
        .def_readwrite("add", &ida::registry::StringListUpdate::add)
        .def_readwrite("remove", &ida::registry::StringListUpdate::remove)
        .def_readwrite("max_records", &ida::registry::StringListUpdate::max_records)
        .def_readwrite("ignore_case", &ida::registry::StringListUpdate::ignore_case);

    py::class_<ida::registry::Store>(registry, "Store")
        .def_static("open", [](const std::string& key) {
            return runtime_result("registry.Store.open", [=] {
                return ida::registry::Store::open(key);
            });
        }, py::arg("key"))
        .def_property_readonly("key", &ida::registry::Store::key)
        .def("child", [](const ida::registry::Store& store,
                           const std::string& name) {
            return runtime_result("registry.Store.child", [&] {
                return store.child(name);
            });
        }, py::arg("name"))
        .def_property_readonly("exists", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.exists", [&] {
                return store.exists();
            });
        })
        .def("child_keys", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.child_keys", [&] {
                return store.child_keys();
            });
        })
        .def("value_names", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.value_names", [&] {
                return store.value_names();
            });
        })
        .def("contains", [](const ida::registry::Store& store,
                              const std::string& name) {
            return runtime_result("registry.Store.contains", [&] {
                return store.contains(name);
            });
        }, py::arg("name"))
        .def("value_kind", [](const ida::registry::Store& store,
                                const std::string& name) {
            return runtime_result("registry.Store.value_kind", [&] {
                return store.value_kind(name);
            });
        }, py::arg("name"))
        .def("read_string", [](const ida::registry::Store& store,
                                 const std::string& name) {
            return runtime_result("registry.Store.read_string", [&] {
                return store.read_string(name);
            });
        }, py::arg("name"))
        .def("write_string", [](const ida::registry::Store& store,
                                  const std::string& name,
                                  const std::string& value) {
            runtime_status("registry.Store.write_string", [&] {
                return store.write_string(name, value);
            });
        }, py::arg("name"), py::arg("value"))
        .def("read_binary", [](const ida::registry::Store& store,
                                 const std::string& name) -> py::object {
            auto value = runtime_result("registry.Store.read_binary", [&] {
                return store.read_binary(name);
            });
            if (!value)
                return py::none();
            return python_bytes(*value);
        }, py::arg("name"))
        .def("write_binary", [](const ida::registry::Store& store,
                                  const std::string& name, py::handle value) {
            const auto bytes = buffer_bytes(value);
            runtime_status("registry.Store.write_binary", [&] {
                return store.write_binary(name, bytes);
            });
        }, py::arg("name"), py::arg("value"))
        .def("read_integer", [](const ida::registry::Store& store,
                                  const std::string& name) {
            return runtime_result("registry.Store.read_integer", [&] {
                return store.read_integer(name);
            });
        }, py::arg("name"))
        .def("write_integer", [](const ida::registry::Store& store,
                                   const std::string& name,
                                   std::int32_t value) {
            runtime_status("registry.Store.write_integer", [&] {
                return store.write_integer(name, value);
            });
        }, py::arg("name"), py::arg("value"))
        .def("read_boolean", [](const ida::registry::Store& store,
                                  const std::string& name) {
            return runtime_result("registry.Store.read_boolean", [&] {
                return store.read_boolean(name);
            });
        }, py::arg("name"))
        .def("write_boolean", [](const ida::registry::Store& store,
                                   const std::string& name, bool value) {
            runtime_status("registry.Store.write_boolean", [&] {
                return store.write_boolean(name, value);
            });
        }, py::arg("name"), py::arg("value"))
        .def("erase_value", [](const ida::registry::Store& store,
                                 const std::string& name) {
            return runtime_result("registry.Store.erase_value", [&] {
                return store.erase_value(name);
            });
        }, py::arg("name"))
        .def("erase_key", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.erase_key", [&] {
                return store.erase_key();
            });
        })
        .def("erase_tree", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.erase_tree", [&] {
                return store.erase_tree();
            });
        })
        .def("read_string_list", [](const ida::registry::Store& store) {
            return runtime_result("registry.Store.read_string_list", [&] {
                return store.read_string_list();
            });
        })
        .def("write_string_list", [](const ida::registry::Store& store,
                                       const std::vector<std::string>& values) {
            runtime_status("registry.Store.write_string_list", [&] {
                return store.write_string_list(values);
            });
        }, py::arg("values"))
        .def("update_string_list", [](const ida::registry::Store& store,
                                        const ida::registry::StringListUpdate& update) {
            runtime_status("registry.Store.update_string_list", [&] {
                return store.update_string_list(update);
            });
        }, py::arg("update"));
}

} // namespace idax::python
