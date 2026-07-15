#include "common.hpp"

#include <functional>
#include <unordered_map>

namespace idax::python {

namespace {

template <typename Result, typename... Args>
Result invoke_graph_override(ida::graph::GraphCallback* self,
                             const char* name,
                             Result fallback,
                             Args&&... args) {
    if (!Py_IsInitialized())
        return fallback;
    py::gil_scoped_acquire acquire;
    py::function override = py::get_override(self, name);
    if (!override)
        return fallback;
    try {
        return override(std::forward<Args>(args)...).template cast<Result>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(override);
    } catch (const std::exception& error) {
        PyErr_SetString(PyExc_RuntimeError, error.what());
        PyErr_WriteUnraisable(override.ptr());
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "unknown graph callback failure");
        PyErr_WriteUnraisable(override.ptr());
    }
    return fallback;
}

template <typename... Args>
void invoke_graph_override_void(ida::graph::GraphCallback* self,
                                const char* name,
                                Args&&... args) {
    if (!Py_IsInitialized())
        return;
    py::gil_scoped_acquire acquire;
    py::function override = py::get_override(self, name);
    if (!override)
        return;
    try {
        override(std::forward<Args>(args)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(override);
    } catch (const std::exception& error) {
        PyErr_SetString(PyExc_RuntimeError, error.what());
        PyErr_WriteUnraisable(override.ptr());
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "unknown graph callback failure");
        PyErr_WriteUnraisable(override.ptr());
    }
}

class PythonGraphCallback final : public ida::graph::GraphCallback {
public:
    using ida::graph::GraphCallback::GraphCallback;

    bool on_refresh(ida::graph::Graph& graph) override {
        return invoke_graph_override(this, "on_refresh", false, std::ref(graph));
    }
    std::string on_node_text(ida::graph::NodeId node) override {
        return invoke_graph_override(this, "on_node_text", std::string{}, node);
    }
    std::uint32_t on_node_color(ida::graph::NodeId node) override {
        return invoke_graph_override(
            this, "on_node_color", std::uint32_t{0xFFFFFFFF}, node);
    }
    bool on_clicked(ida::graph::NodeId node) override {
        return invoke_graph_override(this, "on_clicked", false, node);
    }
    bool on_double_clicked(ida::graph::NodeId node) override {
        return invoke_graph_override(this, "on_double_clicked", false, node);
    }
    std::string on_hint(ida::graph::NodeId node) override {
        return invoke_graph_override(this, "on_hint", std::string{}, node);
    }
    bool on_creating_group(const std::vector<ida::graph::NodeId>& nodes) override {
        return invoke_graph_override(this, "on_creating_group", false, nodes);
    }
    void on_destroyed() override {
        invoke_graph_override_void(this, "on_destroyed");
    }
};

std::unordered_map<std::string, py::tuple>& graph_roots() {
    static std::unordered_map<std::string, py::tuple> roots;
    return roots;
}

} // namespace

void bind_graph(py::module_& module) {
    py::module_ graph = module.def_submodule(
        "graph", "Custom graphs, viewers, flow charts, and switch tables.");

    py::native_enum<ida::graph::Layout>(graph, "Layout", "enum.Enum")
        .value("NONE", ida::graph::Layout::None)
        .value("DIGRAPH", ida::graph::Layout::Digraph)
        .value("TREE", ida::graph::Layout::Tree)
        .value("CIRCLE", ida::graph::Layout::Circle)
        .value("POLAR_TREE", ida::graph::Layout::PolarTree)
        .value("ORTHOGONAL", ida::graph::Layout::Orthogonal)
        .value("RADIAL_TREE", ida::graph::Layout::RadialTree)
        .finalize();
    py::native_enum<ida::graph::BlockType>(graph, "BlockType", "enum.Enum")
        .value("NORMAL", ida::graph::BlockType::Normal)
        .value("INDIRECT_JUMP", ida::graph::BlockType::IndirectJump)
        .value("RETURN", ida::graph::BlockType::Return)
        .value("CONDITIONAL_RETURN", ida::graph::BlockType::ConditionalReturn)
        .value("NO_RETURN", ida::graph::BlockType::NoReturn)
        .value("EXTERNAL_NO_RETURN", ida::graph::BlockType::ExternalNoReturn)
        .value("EXTERNAL", ida::graph::BlockType::External)
        .value("ERROR", ida::graph::BlockType::Error)
        .finalize();

#define IDAX_PY_GRAPH_VALUE(type_name)                                   \
    py::class_<ida::graph::type_name>(graph, #type_name).def(py::init<>())
    IDAX_PY_GRAPH_VALUE(Edge)
        .def_readwrite("source", &ida::graph::Edge::source)
        .def_readwrite("target", &ida::graph::Edge::target);
    IDAX_PY_GRAPH_VALUE(NodeInfo)
        .def_readwrite("background_color", &ida::graph::NodeInfo::background_color)
        .def_readwrite("frame_color", &ida::graph::NodeInfo::frame_color)
        .def_readwrite("address", &ida::graph::NodeInfo::address)
        .def_readwrite("text", &ida::graph::NodeInfo::text);
    IDAX_PY_GRAPH_VALUE(EdgeInfo)
        .def_readwrite("color", &ida::graph::EdgeInfo::color)
        .def_readwrite("width", &ida::graph::EdgeInfo::width)
        .def_readwrite("source_port", &ida::graph::EdgeInfo::source_port)
        .def_readwrite("target_port", &ida::graph::EdgeInfo::target_port);
    IDAX_PY_GRAPH_VALUE(BasicBlock)
        .def_readwrite("start", &ida::graph::BasicBlock::start)
        .def_readwrite("end", &ida::graph::BasicBlock::end)
        .def_readwrite("type", &ida::graph::BasicBlock::type)
        .def_readwrite("successors", &ida::graph::BasicBlock::successors)
        .def_readwrite("predecessors", &ida::graph::BasicBlock::predecessors);
    IDAX_PY_GRAPH_VALUE(SwitchTable)
        .def_readwrite("table_address", &ida::graph::SwitchTable::table_address)
        .def_readwrite("entry_count", &ida::graph::SwitchTable::entry_count)
        .def_readwrite("entry_size", &ida::graph::SwitchTable::entry_size);
#undef IDAX_PY_GRAPH_VALUE

    py::class_<ida::graph::Graph>(graph, "Graph")
        .def(py::init<>())
        .def("add_node", &ida::graph::Graph::add_node)
        .def("remove_node", [](ida::graph::Graph& self, int node) {
            unwrap(self.remove_node(node));
        }, py::arg("node"))
        .def_property_readonly("total_node_count", &ida::graph::Graph::total_node_count)
        .def_property_readonly("visible_node_count", &ida::graph::Graph::visible_node_count)
        .def("node_exists", &ida::graph::Graph::node_exists, py::arg("node"))
        .def("add_edge", [](ida::graph::Graph& self, int source, int target,
                              std::optional<ida::graph::EdgeInfo> info) {
            if (info)
                unwrap(self.add_edge(source, target, *info));
            else
                unwrap(self.add_edge(source, target));
        }, py::arg("source"), py::arg("target"), py::arg("info") = py::none())
        .def("remove_edge", [](ida::graph::Graph& self, int source, int target) {
            unwrap(self.remove_edge(source, target));
        }, py::arg("source"), py::arg("target"))
        .def("replace_edge", [](ida::graph::Graph& self, int source, int target,
                                  int new_source, int new_target) {
            unwrap(self.replace_edge(source, target, new_source, new_target));
        }, py::arg("source"), py::arg("target"), py::arg("new_source"),
           py::arg("new_target"))
        .def("successors", [](const ida::graph::Graph& self, int node) {
            return unwrap(self.successors(node));
        }, py::arg("node"))
        .def("predecessors", [](const ida::graph::Graph& self, int node) {
            return unwrap(self.predecessors(node));
        }, py::arg("node"))
        .def("visible_nodes", &ida::graph::Graph::visible_nodes)
        .def("edges", &ida::graph::Graph::edges)
        .def("path_exists", &ida::graph::Graph::path_exists,
             py::arg("source"), py::arg("target"))
        .def("create_group", [](ida::graph::Graph& self,
                                  const std::vector<int>& nodes) {
            return unwrap(self.create_group(nodes));
        }, py::arg("nodes"))
        .def("delete_group", [](ida::graph::Graph& self, int group) {
            unwrap(self.delete_group(group));
        }, py::arg("group"))
        .def("set_group_expanded", [](ida::graph::Graph& self, int group,
                                        bool expanded) {
            unwrap(self.set_group_expanded(group, expanded));
        }, py::arg("group"), py::arg("expanded"))
        .def("is_group", &ida::graph::Graph::is_group, py::arg("node"))
        .def("is_collapsed", &ida::graph::Graph::is_collapsed, py::arg("group"))
        .def("group_members", [](const ida::graph::Graph& self, int group) {
            return unwrap(self.group_members(group));
        }, py::arg("group"))
        .def("set_layout", [](ida::graph::Graph& self, ida::graph::Layout layout) {
            unwrap(self.set_layout(layout));
        }, py::arg("layout"))
        .def_property_readonly("current_layout", &ida::graph::Graph::current_layout)
        .def("redo_layout", [](ida::graph::Graph& self) {
            unwrap(self.redo_layout());
        })
        .def("clear", &ida::graph::Graph::clear);
    py::class_<ida::graph::GraphCallback, PythonGraphCallback,
               std::shared_ptr<ida::graph::GraphCallback>>(graph, "GraphCallback")
        .def(py::init<>())
        .def("on_refresh", &ida::graph::GraphCallback::on_refresh)
        .def("on_node_text", &ida::graph::GraphCallback::on_node_text)
        .def("on_node_color", &ida::graph::GraphCallback::on_node_color)
        .def("on_clicked", &ida::graph::GraphCallback::on_clicked)
        .def("on_double_clicked", &ida::graph::GraphCallback::on_double_clicked)
        .def("on_hint", &ida::graph::GraphCallback::on_hint)
        .def("on_creating_group", &ida::graph::GraphCallback::on_creating_group)
        .def("on_destroyed", &ida::graph::GraphCallback::on_destroyed);

    graph.def("show_graph", [](std::string title, py::object graph_object,
                                 py::object callback_object) {
        auto& native_graph = graph_object.cast<ida::graph::Graph&>();
        ida::graph::GraphCallback* callback = nullptr;
        if (!callback_object.is_none())
            callback = callback_object.cast<ida::graph::GraphCallback*>();
        runtime_status("graph.show_graph", [&] {
            return ida::graph::show_graph(title, native_graph, callback);
        });
        graph_roots().insert_or_assign(
            title, py::make_tuple(std::move(graph_object), std::move(callback_object)));
    }, py::arg("title"), py::arg("graph"), py::arg("callback") = py::none());
#define IDAX_PY_GRAPH_TITLE_STATUS(fn)                                   \
    graph.def(#fn, [](std::string title) {                               \
        runtime_status("graph." #fn, [&] { return ida::graph::fn(title); }); \
    }, py::arg("title"))
    IDAX_PY_GRAPH_TITLE_STATUS(refresh_graph);
    IDAX_PY_GRAPH_TITLE_STATUS(activate_graph_viewer);
#undef IDAX_PY_GRAPH_TITLE_STATUS
    graph.def("close_graph_viewer", [](std::string title) {
        runtime_status("graph.close_graph_viewer", [&] {
            return ida::graph::close_graph_viewer(title);
        });
        graph_roots().erase(title);
    }, py::arg("title"));
#define IDAX_PY_GRAPH_TITLE_RESULT(fn)                                   \
    graph.def(#fn, [](std::string title) {                               \
        return runtime_result("graph." #fn, [&] { return ida::graph::fn(title); }); \
    }, py::arg("title"))
    IDAX_PY_GRAPH_TITLE_RESULT(has_graph_viewer);
    IDAX_PY_GRAPH_TITLE_RESULT(is_graph_viewer_visible);
#undef IDAX_PY_GRAPH_TITLE_RESULT
    graph.def("switch_table", [](ida::Address address) {
        return runtime_result("graph.switch_table", [=] {
            return ida::graph::switch_table(address);
        });
    }, py::arg("jump_address"));
    graph.def("flowchart", [](ida::Address address) {
        return runtime_result("graph.flowchart", [=] {
            return ida::graph::flowchart(address);
        });
    }, py::arg("function_address"));
    graph.def("flowchart_for_ranges", [](
        const std::vector<ida::address::Range>& ranges) {
        return runtime_result("graph.flowchart_for_ranges", [&] {
            return ida::graph::flowchart_for_ranges(ranges);
        });
    }, py::arg("ranges"));
}

} // namespace idax::python
