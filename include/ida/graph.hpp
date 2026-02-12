/// \file graph.hpp
/// \brief Graph API: custom graphs, flow charts, node/edge manipulation.
///
/// Provides opaque wrappers around IDA's interactive_graph_t and related
/// graph viewer APIs.

#ifndef IDAX_GRAPH_HPP
#define IDAX_GRAPH_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::graph {

// ── Node/edge primitives ────────────────────────────────────────────────

/// A node is identified by an integer index.
using NodeId = int;

/// An edge connects two nodes.
struct Edge {
    NodeId source;
    NodeId target;
};

/// Visual properties for a node.
struct NodeInfo {
    std::uint32_t background_color{0xFFFFFFFF};  ///< DEFCOLOR = no color override.
    std::uint32_t frame_color{0xFFFFFFFF};
    Address       address{BadAddress};            ///< Associated address (optional).
    std::string   text;                           ///< Custom text (optional).
};

/// Visual properties for an edge.
struct EdgeInfo {
    std::uint32_t color{0xFFFFFFFF};   ///< DEFCOLOR = no color override.
    int           width{1};
    int           source_port{-1};     ///< Source port offset from left (-1 = default).
    int           target_port{-1};     ///< Target port offset from left (-1 = default).
};

/// Layout algorithm choices.
enum class Layout {
    None,
    Digraph,       ///< Directed graph (default for flow charts).
    Tree,
    Circle,
    PolarTree,
    Orthogonal,
    RadialTree,
};

// Forward declaration for friend access.
class GraphCallback;

// ── Graph object ────────────────────────────────────────────────────────

/// Opaque handle to an interactive graph.
///
/// Create with create_graph(). The graph must be shown via a GraphViewer
/// or used programmatically. The graph lifetime is tied to the viewer if
/// attached, or managed by the caller if not.
class Graph {
public:
    /// Create a new empty graph.
    Graph();
    ~Graph();

    Graph(Graph&&) noexcept;
    Graph& operator=(Graph&&) noexcept;
    Graph(const Graph&) = delete;
    Graph& operator=(const Graph&) = delete;

    // ── Node operations ─────────────────────────────────────────────────

    /// Add a node to the graph. Returns the new node ID.
    NodeId add_node();

    /// Remove a node and all its incident edges.
    Status remove_node(NodeId node);

    /// Total number of nodes (including group/hidden nodes).
    [[nodiscard]] int total_node_count() const;

    /// Number of visible (non-hidden) nodes.
    [[nodiscard]] int visible_node_count() const;

    /// Check if a node exists and is visible.
    [[nodiscard]] bool node_exists(NodeId node) const;

    // ── Edge operations ─────────────────────────────────────────────────

    /// Add a directed edge from \p source to \p target.
    Status add_edge(NodeId source, NodeId target);

    /// Add a directed edge with visual properties.
    Status add_edge(NodeId source, NodeId target, const EdgeInfo& info);

    /// Remove an edge.
    Status remove_edge(NodeId source, NodeId target);

    /// Replace an edge (from,to) with (new_from,new_to).
    Status replace_edge(NodeId from, NodeId to, NodeId new_from, NodeId new_to);

    // ── Traversal ───────────────────────────────────────────────────────

    /// Get successor node IDs for a node.
    [[nodiscard]] Result<std::vector<NodeId>> successors(NodeId node) const;

    /// Get predecessor node IDs for a node.
    [[nodiscard]] Result<std::vector<NodeId>> predecessors(NodeId node) const;

    /// Get all visible node IDs.
    [[nodiscard]] std::vector<NodeId> visible_nodes() const;

    /// Get all edges.
    [[nodiscard]] std::vector<Edge> edges() const;

    /// Check if a path exists from \p source to \p target.
    [[nodiscard]] bool path_exists(NodeId source, NodeId target) const;

    // ── Group operations ────────────────────────────────────────────────

    /// Create a group containing the given nodes.
    /// @return The new group node ID, or error.
    Result<NodeId> create_group(const std::vector<NodeId>& nodes);

    /// Delete a group node but keep its member nodes.
    Status delete_group(NodeId group);

    /// Expand (show contents) or collapse (hide contents) a group.
    Status set_group_expanded(NodeId group, bool expanded);

    /// Check if a node is a group node.
    [[nodiscard]] bool is_group(NodeId node) const;

    /// Check if a group node is collapsed.
    [[nodiscard]] bool is_collapsed(NodeId group) const;

    /// Get the member nodes of a group.
    [[nodiscard]] Result<std::vector<NodeId>> group_members(NodeId group) const;

    // ── Layout ──────────────────────────────────────────────────────────

    /// Set the layout algorithm and recompute.
    Status set_layout(Layout layout);

    /// Recompute the current layout.
    Status redo_layout();

    /// Clear all nodes and edges.
    void clear();

    // ── Internal ────────────────────────────────────────────────────────
    struct Impl;

private:
    Impl* impl_{nullptr};
    Impl* impl() const { return impl_; }

    friend Status show_graph(std::string_view title, Graph& graph,
                             GraphCallback* callback);
};

// ── Graph viewer ────────────────────────────────────────────────────────

/// Callback interface for graph events.
///
/// Override the methods you care about and pass an instance when creating
/// a GraphViewer. Default implementations do nothing.
class GraphCallback {
public:
    virtual ~GraphCallback() = default;

    /// Called when the graph needs to be rebuilt (populate nodes/edges here).
    /// Return true if the graph was populated.
    virtual bool on_refresh(Graph& graph) { (void)graph; return false; }

    /// Called to get text content for a node.
    /// Return the text to display, or empty string for default.
    virtual std::string on_node_text(NodeId node) { (void)node; return {}; }

    /// Called to get background color for a node.
    /// Return 0xFFFFFFFF for default color.
    virtual std::uint32_t on_node_color(NodeId node) { (void)node; return 0xFFFFFFFF; }

    /// Called when a node is clicked.
    /// Return true to consume the event.
    virtual bool on_clicked(NodeId node) { (void)node; return false; }

    /// Called when a node is double-clicked.
    /// Return true to consume the event.
    virtual bool on_double_clicked(NodeId node) { (void)node; return false; }

    /// Called when hovering over a node. Return a tooltip string.
    virtual std::string on_hint(NodeId node) { (void)node; return {}; }

    /// Called when a group is about to be created.
    /// Return true to allow, false to prevent.
    virtual bool on_creating_group(const std::vector<NodeId>& nodes) {
        (void)nodes; return true;
    }

    /// Called when the graph is about to be destroyed.
    virtual void on_destroyed() {}
};

/// Create and display a graph viewer window.
/// @param title  Window title.
/// @param graph  The graph object (viewer takes ownership of its display).
/// @param callback  Event callback (optional, caller retains ownership).
/// @return Error on failure.
Status show_graph(std::string_view title, Graph& graph,
                  GraphCallback* callback = nullptr);

/// Refresh a graph viewer by title.
Status refresh_graph(std::string_view title);

// ── Flow chart convenience ──────────────────────────────────────────────

/// Block type in a flow chart.
enum class BlockType {
    Normal,
    IndirectJump,
    Return,
    ConditionalReturn,
    NoReturn,
    ExternalNoReturn,
    External,
    Error,
};

/// A basic block in a flow chart.
struct BasicBlock {
    Address   start;
    Address   end;
    BlockType type{BlockType::Normal};
    std::vector<int> successors;
    std::vector<int> predecessors;
};

/// Create a flow chart for the function at \p function_address.
/// Returns a list of basic blocks.
Result<std::vector<BasicBlock>> flowchart(Address function_address);

/// Create a flow chart for a set of address ranges.
Result<std::vector<BasicBlock>> flowchart_for_ranges(
    const std::vector<ida::address::Range>& ranges);

} // namespace ida::graph

#endif // IDAX_GRAPH_HPP
