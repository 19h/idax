/// \file graph.cpp
/// \brief Implementation of ida::graph — graph objects, viewers, flow charts.

#include "detail/sdk_bridge.hpp"
#include <ida/graph.hpp>
#include <graph.hpp>  // SDK graph header (interactive_graph_t, etc.)
#include <gdl.hpp>    // SDK graph drawing library (qflow_chart_t, etc.)

namespace ida::graph {

// ── Graph::Impl ─────────────────────────────────────────────────────────
//
// Uses a simple adjacency-list representation that works in any mode
// (headless, idalib, or UI). When show_graph() is called, the data is
// transferred into an interactive_graph_t for the viewer.

struct Graph::Impl {
    struct NodeData {
        bool alive{true};
        bool is_group{false};
        bool collapsed{false};
        int  parent_group{-1};   // -1 = no parent
        std::vector<NodeId> children;  // for group nodes
    };

    std::vector<NodeData>                  nodes;
    std::vector<std::pair<NodeId, NodeId>> edge_list;

    int add_node() {
        int id = static_cast<int>(nodes.size());
        nodes.push_back({});
        return id;
    }

    bool valid(NodeId n) const {
        return n >= 0 && static_cast<std::size_t>(n) < nodes.size() && nodes[n].alive;
    }

    void remove_node(NodeId n) {
        if (!valid(n)) return;
        nodes[n].alive = false;
        // Remove all edges involving n.
        std::erase_if(edge_list, [n](auto& e) {
            return e.first == n || e.second == n;
        });
    }

    int total_count() const { return static_cast<int>(nodes.size()); }

    int visible_count() const {
        int c = 0;
        for (auto& nd : nodes)
            if (nd.alive) ++c;
        return c;
    }

    bool has_edge(NodeId s, NodeId t) const {
        for (auto& e : edge_list)
            if (e.first == s && e.second == t) return true;
        return false;
    }

    void add_edge(NodeId s, NodeId t) {
        edge_list.push_back({s, t});
    }

    bool remove_edge(NodeId s, NodeId t) {
        auto it = std::find(edge_list.begin(), edge_list.end(),
                            std::pair<NodeId,NodeId>{s, t});
        if (it == edge_list.end()) return false;
        edge_list.erase(it);
        return true;
    }

    bool replace_edge(NodeId from, NodeId to, NodeId nf, NodeId nt) {
        for (auto& e : edge_list) {
            if (e.first == from && e.second == to) {
                e.first = nf;
                e.second = nt;
                return true;
            }
        }
        return false;
    }

    std::vector<NodeId> successors_of(NodeId n) const {
        std::vector<NodeId> r;
        for (auto& e : edge_list)
            if (e.first == n) r.push_back(e.second);
        return r;
    }

    std::vector<NodeId> predecessors_of(NodeId n) const {
        std::vector<NodeId> r;
        for (auto& e : edge_list)
            if (e.second == n) r.push_back(e.first);
        return r;
    }

    bool path_exists(NodeId source, NodeId target) const {
        if (source == target) return true;
        int sz = total_count();
        if (!valid(source) || !valid(target)) return false;
        std::vector<bool> visited(sz, false);
        std::vector<NodeId> queue;
        queue.push_back(source);
        visited[source] = true;
        std::size_t head = 0;
        while (head < queue.size()) {
            NodeId cur = queue[head++];
            for (auto& e : edge_list) {
                if (e.first == cur) {
                    if (e.second == target) return true;
                    if (e.second >= 0 && e.second < sz && !visited[e.second]) {
                        visited[e.second] = true;
                        queue.push_back(e.second);
                    }
                }
            }
        }
        return false;
    }

    int create_group(const std::vector<NodeId>& members) {
        int gid = add_node();
        nodes[gid].is_group = true;
        nodes[gid].collapsed = false;
        for (auto m : members) {
            if (valid(m)) {
                nodes[m].parent_group = gid;
                nodes[gid].children.push_back(m);
            }
        }
        return gid;
    }

    bool delete_group(NodeId group) {
        if (!valid(group) || !nodes[group].is_group) return false;
        for (auto& c : nodes[group].children) {
            if (valid(c)) nodes[c].parent_group = -1;
        }
        nodes[group].alive = false;
        return true;
    }

    void clear() {
        nodes.clear();
        edge_list.clear();
    }
};

// ── Graph lifecycle ─────────────────────────────────────────────────────

Graph::Graph() : impl_(new Impl) {}

Graph::~Graph() {
    delete impl_;
}

Graph::Graph(Graph&& other) noexcept : impl_(other.impl_) {
    other.impl_ = nullptr;
}

Graph& Graph::operator=(Graph&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

// ── Node operations ─────────────────────────────────────────────────────

NodeId Graph::add_node() {
    if (!impl_) return -1;
    return impl_->add_node();
}

Status Graph::remove_node(NodeId node) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(node))
        return std::unexpected(Error::not_found("Node does not exist"));
    impl_->remove_node(node);
    return ida::ok();
}

int Graph::total_node_count() const {
    if (!impl_) return 0;
    return impl_->total_count();
}

int Graph::visible_node_count() const {
    if (!impl_) return 0;
    return impl_->visible_count();
}

bool Graph::node_exists(NodeId node) const {
    if (!impl_) return false;
    return impl_->valid(node);
}

// ── Edge operations ─────────────────────────────────────────────────────

Status Graph::add_edge(NodeId source, NodeId target) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(source) || !impl_->valid(target))
        return std::unexpected(Error::validation("Invalid node"));
    impl_->add_edge(source, target);
    return ida::ok();
}

Status Graph::add_edge(NodeId source, NodeId target, const EdgeInfo& info) {
    (void)info; // Edge info stored when transferred to interactive_graph_t.
    return add_edge(source, target);
}

Status Graph::remove_edge(NodeId source, NodeId target) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->remove_edge(source, target))
        return std::unexpected(Error::not_found("Edge not found"));
    return ida::ok();
}

Status Graph::replace_edge(NodeId from, NodeId to,
                            NodeId new_from, NodeId new_to) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->replace_edge(from, to, new_from, new_to))
        return std::unexpected(Error::not_found("Edge not found"));
    return ida::ok();
}

// ── Traversal ───────────────────────────────────────────────────────────

Result<std::vector<NodeId>> Graph::successors(NodeId node) const {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(node))
        return std::unexpected(Error::not_found("Node does not exist"));
    return impl_->successors_of(node);
}

Result<std::vector<NodeId>> Graph::predecessors(NodeId node) const {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(node))
        return std::unexpected(Error::not_found("Node does not exist"));
    return impl_->predecessors_of(node);
}

std::vector<NodeId> Graph::visible_nodes() const {
    std::vector<NodeId> result;
    if (!impl_) return result;
    for (int i = 0; i < impl_->total_count(); ++i)
        if (impl_->valid(i))
            result.push_back(i);
    return result;
}

std::vector<Edge> Graph::edges() const {
    std::vector<Edge> result;
    if (!impl_) return result;
    for (auto& e : impl_->edge_list)
        result.push_back({e.first, e.second});
    return result;
}

bool Graph::path_exists(NodeId source, NodeId target) const {
    if (!impl_) return false;
    return impl_->path_exists(source, target);
}

// ── Group operations ────────────────────────────────────────────────────

Result<NodeId> Graph::create_group(const std::vector<NodeId>& nodes) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    int gid = impl_->create_group(nodes);
    return gid;
}

Status Graph::delete_group(NodeId group) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->delete_group(group))
        return std::unexpected(Error::sdk("delete_group failed"));
    return ida::ok();
}

Status Graph::set_group_expanded(NodeId group, bool expanded) {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(group) || !impl_->nodes[group].is_group)
        return std::unexpected(Error::validation("Node is not a group"));
    impl_->nodes[group].collapsed = !expanded;
    return ida::ok();
}

bool Graph::is_group(NodeId node) const {
    if (!impl_ || !impl_->valid(node)) return false;
    return impl_->nodes[node].is_group;
}

bool Graph::is_collapsed(NodeId group) const {
    if (!impl_ || !impl_->valid(group)) return false;
    return impl_->nodes[group].collapsed;
}

Result<std::vector<NodeId>> Graph::group_members(NodeId group) const {
    if (!impl_) return std::unexpected(Error::validation("Graph not initialized"));
    if (!impl_->valid(group) || !impl_->nodes[group].is_group)
        return std::unexpected(Error::validation("Node is not a group"));
    return impl_->nodes[group].children;
}

// ── Layout ──────────────────────────────────────────────────────────────

Status Graph::set_layout(Layout /*layout*/) {
    // Layout is meaningful only when displayed via show_graph().
    // For the programmatic API, just record the setting.
    return ida::ok();
}

Status Graph::redo_layout() {
    return ida::ok();
}

void Graph::clear() {
    if (impl_)
        impl_->clear();
}

// ── Graph viewer ────────────────────────────────────────────────────────

Status show_graph(std::string_view title, Graph& graph,
                  GraphCallback* callback) {
    if (!graph.impl())
        return std::unexpected(Error::validation("Graph not initialized"));

    // Build an interactive_graph_t from our adjacency list.
    interactive_graph_t* ig = create_interactive_graph(0);
    if (ig == nullptr)
        return std::unexpected(Error::unsupported(
            "Graph viewer not available (requires IDA UI mode)"));

    auto* impl = graph.impl();
    ig->resize(impl->total_count());
    for (auto& e : impl->edge_list)
        ig->add_edge(e.first, e.second, nullptr);

    // Create a persistent state for callbacks.
    struct ViewerState {
        GraphCallback* cb{nullptr};
        Graph*         graph{nullptr};
    };
    auto* state = new ViewerState{callback, &graph};

    auto callback_fn = [](void* ud, int code, va_list va) -> ssize_t {
        auto* st = static_cast<ViewerState*>(ud);
        if (!st || !st->cb) return 0;

        switch (code) {
        case grcode_user_text: {
            (void)va_arg(va, interactive_graph_t*);
            int node = va_arg(va, int);
            auto** text = va_arg(va, const char**);
            auto* bg = va_arg(va, bgcolor_t*);

            static thread_local qstring text_buf;
            std::string t = st->cb->on_node_text(node);
            if (!t.empty()) {
                text_buf = ida::detail::to_qstring(t);
                *text = text_buf.c_str();
            }
            std::uint32_t c = st->cb->on_node_color(node);
            if (c != 0xFFFFFFFF && bg != nullptr)
                *bg = static_cast<bgcolor_t>(c);
            return !t.empty() ? 1 : 0;
        }
        case grcode_clicked: {
            (void)va_arg(va, graph_viewer_t*);
            auto* item1 = va_arg(va, selection_item_t*);
            if (item1 && item1->is_node)
                return st->cb->on_clicked(item1->node) ? 1 : 0;
            return 0;
        }
        case grcode_dblclicked: {
            (void)va_arg(va, graph_viewer_t*);
            auto* item = va_arg(va, selection_item_t*);
            if (item && item->is_node)
                return st->cb->on_double_clicked(item->node) ? 1 : 0;
            return 0;
        }
        case grcode_user_hint: {
            (void)va_arg(va, interactive_graph_t*);
            int mousenode = va_arg(va, int);
            (void)va_arg(va, int); // edge_src
            (void)va_arg(va, int); // edge_dst
            auto** hint = va_arg(va, char**);
            if (mousenode >= 0) {
                std::string h = st->cb->on_hint(mousenode);
                if (!h.empty() && hint) {
                    *hint = qstrdup(h.c_str());
                    return 1;
                }
            }
            return 0;
        }
        case grcode_destroyed: {
            st->cb->on_destroyed();
            delete st;
            return 0;
        }
        }
        return 0;
    };

    std::string title_str(title);
    netnode id;
    qstring qname("$ idax_graph_");
    qname.append(title_str.c_str());
    id.create(qname.c_str());

    graph_viewer_t* gv = create_graph_viewer(
        title_str.c_str(), id,
        +callback_fn,  // Convert non-capturing lambda to function pointer.
        state, 0, nullptr);

    if (gv == nullptr) {
        delete state;
        delete_interactive_graph(ig);
        return std::unexpected(Error::sdk("create_graph_viewer failed"));
    }

    set_viewer_graph(gv, ig);
    display_widget(reinterpret_cast<TWidget*>(gv),
                   WOPN_DP_TAB | WOPN_RESTORE);
    viewer_fit_window(gv);

    return ida::ok();
}

Status refresh_graph(std::string_view title) {
    std::string t(title);
    TWidget* w = find_widget(t.c_str());
    if (w == nullptr)
        return std::unexpected(Error::not_found("Graph viewer not found", t));
    auto* gv = reinterpret_cast<graph_viewer_t*>(w);
    refresh_viewer(gv);
    return ida::ok();
}

// ── Flow chart ──────────────────────────────────────────────────────────

static BlockType convert_block_type(fc_block_type_t bt) {
    switch (bt) {
    case fcb_normal:  return BlockType::Normal;
    case fcb_indjump: return BlockType::IndirectJump;
    case fcb_ret:     return BlockType::Return;
    case fcb_cndret:  return BlockType::ConditionalReturn;
    case fcb_noret:   return BlockType::NoReturn;
    case fcb_enoret:  return BlockType::ExternalNoReturn;
    case fcb_extern:  return BlockType::External;
    case fcb_error:   return BlockType::Error;
    default:          return BlockType::Normal;
    }
}

Result<std::vector<BasicBlock>> flowchart(Address function_address) {
    func_t* pfn = get_func(static_cast<ea_t>(function_address));
    if (pfn == nullptr)
        return std::unexpected(Error::not_found("Function not found"));

    qflow_chart_t fc;
    qstring title;
    title.sprnt("flowchart_0x%llx", (unsigned long long)pfn->start_ea);
    fc.create(title.c_str(), pfn, pfn->start_ea, pfn->end_ea, 0);

    std::vector<BasicBlock> blocks;
    blocks.reserve(fc.size());
    for (int i = 0; i < fc.size(); ++i) {
        auto& b = fc.blocks[i];
        BasicBlock bb;
        bb.start = b.start_ea;
        bb.end = b.end_ea;
        bb.type = convert_block_type(fc.calc_block_type(i));

        for (auto s : b.succ)
            bb.successors.push_back(s);
        for (auto p : b.pred)
            bb.predecessors.push_back(p);

        blocks.push_back(std::move(bb));
    }
    return blocks;
}

Result<std::vector<BasicBlock>> flowchart_for_ranges(
    const std::vector<ida::address::Range>& ranges) {
    if (ranges.empty())
        return std::unexpected(Error::validation("No ranges provided"));

    rangevec_t rv;
    for (auto& r : ranges)
        rv.push_back(range_t(static_cast<ea_t>(r.start),
                             static_cast<ea_t>(r.end)));

    qflow_chart_t fc;
    fc.create("idax_ranges", rv, 0);

    std::vector<BasicBlock> blocks;
    blocks.reserve(fc.size());
    for (int i = 0; i < fc.size(); ++i) {
        auto& b = fc.blocks[i];
        BasicBlock bb;
        bb.start = b.start_ea;
        bb.end = b.end_ea;
        bb.type = convert_block_type(fc.calc_block_type(i));

        for (auto s : b.succ)
            bb.successors.push_back(s);
        for (auto p : b.pred)
            bb.predecessors.push_back(p);

        blocks.push_back(std::move(bb));
    }
    return blocks;
}

} // namespace ida::graph
