#include "common.hpp"

namespace idax::python {

void bind_storage(py::module_& module) {
    py::module_ storage = module.def_submodule(
        "storage", "Opaque persistent database key-value nodes.");

    py::class_<ida::storage::Node>(storage, "Node")
        .def(py::init<>())
        .def_static("open", [](std::string name, bool create) {
            return runtime_result("storage.Node.open", [&] {
                return ida::storage::Node::open(name, create);
            });
        }, py::arg("name"), py::arg("create") = false)
        .def_static("open_by_id", [](std::uint64_t node_id) {
            return runtime_result("storage.Node.open_by_id", [=] {
                return ida::storage::Node::open_by_id(node_id);
            });
        }, py::arg("node_id"))
        .def_property_readonly("id", [](const ida::storage::Node& self) {
            return runtime_result("storage.Node.id", [&] { return self.id(); });
        })
        .def_property_readonly("name", [](const ida::storage::Node& self) {
            return runtime_result("storage.Node.name", [&] { return self.name(); });
        })
        .def("alt", [](const ida::storage::Node& self, ida::Address index,
                        std::uint8_t tag) {
            return runtime_result("storage.Node.alt", [=, &self] {
                return self.alt(index, tag);
            });
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('A'))
        .def("set_alt", [](ida::storage::Node& self, ida::Address index,
                            std::uint64_t value, std::uint8_t tag) {
            runtime_status("storage.Node.set_alt", [=, &self] {
                return self.set_alt(index, value, tag);
            });
        }, py::arg("index"), py::arg("value"),
           py::arg("tag") = static_cast<std::uint8_t>('A'))
        .def("remove_alt", [](ida::storage::Node& self, ida::Address index,
                               std::uint8_t tag) {
            runtime_status("storage.Node.remove_alt", [=, &self] {
                return self.remove_alt(index, tag);
            });
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('A'))
        .def("sup", [](const ida::storage::Node& self, ida::Address index,
                        std::uint8_t tag) {
            auto value = runtime_result("storage.Node.sup", [=, &self] {
                return self.sup(index, tag);
            });
            return python_bytes(value);
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('S'))
        .def("set_sup", [](ida::storage::Node& self, ida::Address index,
                            py::handle data, std::uint8_t tag) {
            auto bytes = buffer_bytes(data);
            runtime_status("storage.Node.set_sup", [=, &self] {
                return self.set_sup(index, bytes, tag);
            });
        }, py::arg("index"), py::arg("data"),
           py::arg("tag") = static_cast<std::uint8_t>('S'))
        .def("hash", [](const ida::storage::Node& self, std::string key,
                         std::uint8_t tag) {
            return runtime_result("storage.Node.hash", [&] {
                return self.hash(key, tag);
            });
        }, py::arg("key"), py::arg("tag") = static_cast<std::uint8_t>('H'))
        .def("set_hash", [](ida::storage::Node& self, std::string key,
                             std::string value, std::uint8_t tag) {
            runtime_status("storage.Node.set_hash", [&] {
                return self.set_hash(key, value, tag);
            });
        }, py::arg("key"), py::arg("value"),
           py::arg("tag") = static_cast<std::uint8_t>('H'))
        .def("blob_size", [](const ida::storage::Node& self, ida::Address index,
                              std::uint8_t tag) {
            return runtime_result("storage.Node.blob_size", [=, &self] {
                return self.blob_size(index, tag);
            });
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('B'))
        .def("blob", [](const ida::storage::Node& self, ida::Address index,
                         std::uint8_t tag) {
            auto value = runtime_result("storage.Node.blob", [=, &self] {
                return self.blob(index, tag);
            });
            return python_bytes(value);
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('B'))
        .def("set_blob", [](ida::storage::Node& self, ida::Address index,
                             py::handle data, std::uint8_t tag) {
            auto bytes = buffer_bytes(data);
            runtime_status("storage.Node.set_blob", [=, &self] {
                return self.set_blob(index, bytes, tag);
            });
        }, py::arg("index"), py::arg("data"),
           py::arg("tag") = static_cast<std::uint8_t>('B'))
        .def("remove_blob", [](ida::storage::Node& self, ida::Address index,
                                std::uint8_t tag) {
            runtime_status("storage.Node.remove_blob", [=, &self] {
                return self.remove_blob(index, tag);
            });
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('B'))
        .def("blob_string", [](const ida::storage::Node& self,
                                ida::Address index, std::uint8_t tag) {
            return runtime_result("storage.Node.blob_string", [=, &self] {
                return self.blob_string(index, tag);
            });
        }, py::arg("index"), py::arg("tag") = static_cast<std::uint8_t>('B'));
}

} // namespace idax::python
