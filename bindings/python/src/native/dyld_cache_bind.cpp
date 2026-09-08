#include "common.hpp"
namespace idax::python {
void bind_dyld_cache(py::module_& module) {
    auto dyld_cache = module.def_submodule("dyld_cache", "Dyld shared-cache inventory and incremental loading.");
    py::class_<ida::dyld_cache::ModuleInfo>(dyld_cache, "ModuleInfo")
        .def_readonly("path", &ida::dyld_cache::ModuleInfo::path)
        .def_readonly("load_address", &ida::dyld_cache::ModuleInfo::load_address);
    dyld_cache.def("is_available", [] { return runtime_call("dyld_cache.is_available", [] { return ida::dyld_cache::is_available(); }); });
    dyld_cache.def("list_modules", [](py::object path) {
        if (!path.is_none()) return unwrap(ida::dyld_cache::list_modules(filesystem_path(path)));
        return runtime_call("dyld_cache.list_modules", [] { return unwrap(ida::dyld_cache::list_modules()); });
    }, py::arg("cache_path") = py::none());
    dyld_cache.def("load_module", [](const std::string& path, bool wait) {
        runtime_call("dyld_cache.load_module", [&] { unwrap(ida::dyld_cache::load_module(path, wait)); });
    }, py::arg("module_path"), py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_section", [](ida::Address address, bool wait) {
        runtime_call("dyld_cache.load_section", [&] { unwrap(ida::dyld_cache::load_section(address, wait)); });
    }, py::arg("address"), py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_dyld_header", [](bool wait) {
        runtime_call("dyld_cache.load_dyld_header", [&] { unwrap(ida::dyld_cache::load_dyld_header(wait)); });
    }, py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_branch_islands", [](bool wait) {
        return runtime_call("dyld_cache.load_branch_islands", [&] { return unwrap(ida::dyld_cache::load_branch_islands(wait)); });
    }, py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_branch_mappings", [](bool wait) {
        return runtime_call("dyld_cache.load_branch_mappings", [&] { return unwrap(ida::dyld_cache::load_branch_mappings(wait)); });
    }, py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_global_offset_tables", [](bool wait) {
        return runtime_call("dyld_cache.load_global_offset_tables", [&] { return unwrap(ida::dyld_cache::load_global_offset_tables(wait)); });
    }, py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_gaps", [](bool wait) {
        return runtime_call("dyld_cache.load_gaps", [&] { return unwrap(ida::dyld_cache::load_gaps(wait)); });
    }, py::arg("wait_for_analysis") = false);
    dyld_cache.def("load_cache_data", [](bool wait) {
        return runtime_call("dyld_cache.load_cache_data", [&] { return unwrap(ida::dyld_cache::load_cache_data(wait)); });
    }, py::arg("wait_for_analysis") = false);
}
}
