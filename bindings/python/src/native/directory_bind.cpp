#include "common.hpp"

namespace idax::python {

void bind_directory(py::module_& module) {
    py::module_ directory = module.def_submodule(
        "directory", "Opaque standard database directory trees.");

    py::native_enum<ida::directory::Kind>(directory, "Kind", "enum.Enum")
        .value("LOCAL_TYPES", ida::directory::Kind::LocalTypes)
        .value("FUNCTIONS", ida::directory::Kind::Functions)
        .value("NAMES", ida::directory::Kind::Names)
        .value("IMPORTS", ida::directory::Kind::Imports)
        .value("IDA_PLACE_BOOKMARKS", ida::directory::Kind::IdaPlaceBookmarks)
        .value("BREAKPOINTS", ida::directory::Kind::Breakpoints)
        .value("LOCAL_TYPE_BOOKMARKS", ida::directory::Kind::LocalTypeBookmarks)
        .value("SNIPPETS", ida::directory::Kind::Snippets)
        .finalize();

    py::native_enum<ida::directory::EntryKind>(
        directory, "EntryKind", "enum.Enum")
        .value("DIRECTORY", ida::directory::EntryKind::Directory)
        .value("ITEM", ida::directory::EntryKind::Item)
        .finalize();

    py::native_enum<ida::directory::OperationError>(
        directory, "OperationError", "enum.Enum")
        .value("ALREADY_EXISTS", ida::directory::OperationError::AlreadyExists)
        .value("NOT_FOUND", ida::directory::OperationError::NotFound)
        .value("NOT_DIRECTORY", ida::directory::OperationError::NotDirectory)
        .value("NOT_EMPTY", ida::directory::OperationError::NotEmpty)
        .value("BAD_PATH", ida::directory::OperationError::BadPath)
        .value("CANNOT_RENAME", ida::directory::OperationError::CannotRename)
        .value("OWN_CHILD", ida::directory::OperationError::OwnChild)
        .value("DIRECTORY_LIMIT", ida::directory::OperationError::DirectoryLimit)
        .value("NOT_ORDERABLE", ida::directory::OperationError::NotOrderable)
        .value("SDK_FAILURE", ida::directory::OperationError::SdkFailure)
        .finalize();

    py::class_<ida::directory::Entry>(directory, "Entry")
        .def_readonly("path", &ida::directory::Entry::path)
        .def_readonly("name", &ida::directory::Entry::name)
        .def_readonly("display_name", &ida::directory::Entry::display_name)
        .def_readonly("attributes", &ida::directory::Entry::attributes)
        .def_readonly("kind", &ida::directory::Entry::kind)
        .def_property_readonly("is_directory",
                               &ida::directory::Entry::is_directory);

    py::class_<ida::directory::BulkFailure>(directory, "BulkFailure")
        .def_readonly("input_index", &ida::directory::BulkFailure::input_index)
        .def_readonly("path", &ida::directory::BulkFailure::path)
        .def_readonly("error", &ida::directory::BulkFailure::error)
        .def_readonly("message", &ida::directory::BulkFailure::message);

    py::class_<ida::directory::BulkReport>(directory, "BulkReport")
        .def_readonly("affected_paths", &ida::directory::BulkReport::affected_paths)
        .def_readonly("failures", &ida::directory::BulkReport::failures)
        .def_property_readonly("ok", &ida::directory::BulkReport::ok)
        .def("__bool__", &ida::directory::BulkReport::ok);

    py::class_<ida::directory::Tree>(directory, "Tree")
        .def_static("open", [](ida::directory::Kind kind) {
            return runtime_result("directory.Tree.open", [=] {
                return ida::directory::Tree::open(kind);
            });
        }, py::arg("kind"))
        .def_property_readonly("kind", &ida::directory::Tree::kind)
        .def_property_readonly("is_orderable", [](const ida::directory::Tree& tree) {
            return runtime_result("directory.Tree.is_orderable", [&] {
                return tree.is_orderable();
            });
        })
        .def_property_readonly("current_directory", [](const ida::directory::Tree& tree) {
            return runtime_result("directory.Tree.current_directory", [&] {
                return tree.current_directory();
            });
        })
        .def("change_directory", [](const ida::directory::Tree& tree,
                                     const std::string& path) {
            runtime_status("directory.Tree.change_directory", [&] {
                return tree.change_directory(path);
            });
        }, py::arg("path"))
        .def("absolute_path", [](const ida::directory::Tree& tree,
                                  const std::string& path) {
            return runtime_result("directory.Tree.absolute_path", [&] {
                return tree.absolute_path(path);
            });
        }, py::arg("relative_path"))
        .def("contains", [](const ida::directory::Tree& tree,
                             const std::string& path) {
            return runtime_result("directory.Tree.contains", [&] {
                return tree.contains(path);
            });
        }, py::arg("path"))
        .def("entry", [](const ida::directory::Tree& tree,
                          const std::string& path) {
            return runtime_result("directory.Tree.entry", [&] {
                return tree.entry(path);
            });
        }, py::arg("path"))
        .def("children", [](const ida::directory::Tree& tree,
                             const std::string& path) {
            return runtime_result("directory.Tree.children", [&] {
                return tree.children(path);
            });
        }, py::arg("path") = "/")
        .def("snapshot", [](const ida::directory::Tree& tree,
                             const std::string& path) {
            return runtime_result("directory.Tree.snapshot", [&] {
                return tree.snapshot(path);
            });
        }, py::arg("path") = "/")
        .def("find_items", [](const ida::directory::Tree& tree,
                               const std::string& pattern) {
            return runtime_result("directory.Tree.find_items", [&] {
                return tree.find_items(pattern);
            });
        }, py::arg("pattern"))
        .def("create_directory", [](const ida::directory::Tree& tree,
                                     const std::string& path) {
            runtime_status("directory.Tree.create_directory", [&] {
                return tree.create_directory(path);
            });
        }, py::arg("path"))
        .def("remove_directory", [](const ida::directory::Tree& tree,
                                     const std::string& path) {
            runtime_status("directory.Tree.remove_directory", [&] {
                return tree.remove_directory(path);
            });
        }, py::arg("path"))
        .def("link", [](const ida::directory::Tree& tree,
                          const std::string& path) {
            runtime_status("directory.Tree.link", [&] { return tree.link(path); });
        }, py::arg("path"))
        .def("unlink", [](const ida::directory::Tree& tree,
                            const std::string& path) {
            runtime_status("directory.Tree.unlink", [&] { return tree.unlink(path); });
        }, py::arg("path"))
        .def("rename", [](const ida::directory::Tree& tree,
                            const std::string& from, const std::string& to) {
            runtime_status("directory.Tree.rename", [&] {
                return tree.rename(from, to);
            });
        }, py::arg("from_path"), py::arg("to_path"))
        .def("fold_common_prefix", [](const ida::directory::Tree& tree,
                                       const std::string& path) {
            runtime_status("directory.Tree.fold_common_prefix", [&] {
                return tree.fold_common_prefix(path);
            });
        }, py::arg("path") = "/")
        .def("has_natural_order", [](const ida::directory::Tree& tree,
                                      const std::string& path) {
            return runtime_result("directory.Tree.has_natural_order", [&] {
                return tree.has_natural_order(path);
            });
        }, py::arg("directory_path"))
        .def("set_natural_order", [](const ida::directory::Tree& tree,
                                      const std::string& path, bool enable) {
            runtime_status("directory.Tree.set_natural_order", [&] {
                return tree.set_natural_order(path, enable);
            });
        }, py::arg("directory_path"), py::arg("enable"))
        .def("rank", [](const ida::directory::Tree& tree,
                         const std::string& path) {
            return runtime_result("directory.Tree.rank", [&] {
                return tree.rank(path);
            });
        }, py::arg("path"))
        .def("change_rank", [](const ida::directory::Tree& tree,
                                const std::string& path, std::ptrdiff_t delta) {
            runtime_status("directory.Tree.change_rank", [&] {
                return tree.change_rank(path, delta);
            });
        }, py::arg("path"), py::arg("delta"))
        .def("move", [](const ida::directory::Tree& tree,
                         const std::vector<std::string>& paths,
                         const std::string& destination,
                         std::optional<std::size_t> rank) {
            return runtime_result("directory.Tree.move", [&] {
                return tree.move(paths, destination, rank);
            });
        }, py::arg("paths"), py::arg("destination_directory"),
           py::arg("destination_rank") = std::nullopt)
        .def("remove", [](const ida::directory::Tree& tree,
                           const std::vector<std::string>& paths) {
            return runtime_result("directory.Tree.remove", [&] {
                return tree.remove(paths);
            });
        }, py::arg("paths"));
}

} // namespace idax::python
