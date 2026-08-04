internal import CIDAX
import Darwin

// MARK: - Value types

/// Graph edge descriptor.
public struct Edge: Sendable {
    public let source: Int32
    public let target: Int32
}

/// Graph edge visual properties.
public struct EdgeInfo: Sendable {
    public let color: UInt32
    public let width: Int32
    public let sourcePort: Int32
    public let targetPort: Int32

    public init(color: UInt32 = 0, width: Int32 = 1, sourcePort: Int32 = 0, targetPort: Int32 = 0) {
        self.color = color
        self.width = width
        self.sourcePort = sourcePort
        self.targetPort = targetPort
    }
}

/// Basic block descriptor from a flow chart.
public struct BasicBlock: Sendable {
    public let start: Address
    public let end: Address
    public let type: Int32
    public let successors: [Int32]
    public let predecessors: [Int32]
}

/// Graph layout algorithm.
///
/// Mirrors C++ `ida::graph::Layout`.
public enum GraphLayout: Int32, Sendable {
    case none = 0
    case digraph = 1
    case tree = 2
    case circle = 3
    case polarTree = 4
    case orthogonal = 5
    case radialTree = 6
}

// MARK: - Graph (mutable, ~Copyable handle)

/// Mutable directed graph with node/edge manipulation, grouping, and layout.
///
/// Move-only value — `deinit` frees the underlying handle.
/// Mirrors C++ `ida::graph`.
public struct Graph: ~Copyable, @unchecked Sendable {
    let handle: IdaxGraphHandle

    init(_ handle: IdaxGraphHandle) {
        self.handle = handle
    }

    deinit {
        idax_graph_free(handle)
    }

    /// Create a new empty graph.
    public init() throws(IDAError) {
        let h = idax_graph_create()
        guard let h else {
            throw IDAError(category: .internal, code: 0, message: "failed to create graph")
        }
        self.handle = h
    }

    // MARK: - Nodes

    /// Add a new node. Returns the node ID (0-based).
    public func addNode() throws(IDAError) -> Int32 {
        let ret = idax_graph_add_node(handle)
        if ret < 0 {
            throw consumeLastError(fallback: "graph.addNode")
        }
        return ret
    }

    /// Remove a node by ID.
    public func removeNode(_ node: Int32) throws(IDAError) {
        try checkStatus(idax_graph_remove_node(handle, node), "graph.removeNode")
    }

    /// Total number of nodes (including hidden/collapsed).
    public func totalNodeCount() throws(IDAError) -> Int32 {
        let ret = idax_graph_total_node_count(handle)
        if ret < 0 {
            throw consumeLastError(fallback: "graph.totalNodeCount")
        }
        return ret
    }

    /// Number of currently visible nodes.
    public func visibleNodeCount() throws(IDAError) -> Int32 {
        let ret = idax_graph_visible_node_count(handle)
        if ret < 0 {
            throw consumeLastError(fallback: "graph.visibleNodeCount")
        }
        return ret
    }

    /// Whether a node ID exists in the graph.
    public func nodeExists(_ node: Int32) -> Bool {
        idax_graph_node_exists(handle, node) != 0
    }

    // MARK: - Edges

    /// Add a directed edge from `source` to `target`.
    public func addEdge(source: Int32, target: Int32) throws(IDAError) {
        try checkStatus(idax_graph_add_edge(handle, source, target), "graph.addEdge")
    }

    /// Add a directed edge with visual properties.
    public func addEdge(source: Int32, target: Int32, info: EdgeInfo) throws(IDAError) {
        var raw = IdaxGraphEdgeInfo(
            color: info.color,
            width: info.width,
            source_port: info.sourcePort,
            target_port: info.targetPort
        )
        try checkStatus(
            idax_graph_add_edge_with_info(handle, source, target, &raw),
            "graph.addEdgeWithInfo"
        )
    }

    /// Remove the edge from `source` to `target`.
    public func removeEdge(source: Int32, target: Int32) throws(IDAError) {
        try checkStatus(idax_graph_remove_edge(handle, source, target), "graph.removeEdge")
    }

    /// Replace an edge (from, to) with (newFrom, newTo).
    public func replaceEdge(from: Int32, to: Int32, newFrom: Int32, newTo: Int32) throws(IDAError) {
        try checkStatus(
            idax_graph_replace_edge(handle, from, to, newFrom, newTo),
            "graph.replaceEdge"
        )
    }

    /// Remove all nodes and edges.
    public func clear() throws(IDAError) {
        try checkStatus(idax_graph_clear(handle), "graph.clear")
    }

    // MARK: - Traversal

    /// Successor node IDs of the given node.
    public func successors(of node: Int32) throws(IDAError) -> [Int32] {
        try nodeIdArray("graph.successors") { idax_graph_successors(handle, node, $0, $1) }
    }

    /// Predecessor node IDs of the given node.
    public func predecessors(of node: Int32) throws(IDAError) -> [Int32] {
        try nodeIdArray("graph.predecessors") { idax_graph_predecessors(handle, node, $0, $1) }
    }

    /// IDs of all currently visible nodes.
    public func visibleNodes() throws(IDAError) -> [Int32] {
        try nodeIdArray("graph.visibleNodes") { idax_graph_visible_nodes(handle, $0, $1) }
    }

    /// All edges in the graph.
    public func edges() throws(IDAError) -> [Edge] {
        var ptr: UnsafeMutablePointer<IdaxGraphEdge>? = nil
        var count: Int = 0
        try checkStatus(idax_graph_edges(handle, &ptr, &count), "graph.edges")
        defer { idax_graph_free_edges(ptr) }
        guard let ptr, count > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { Edge(source: $0.source, target: $0.target) }
    }

    /// Whether a directed path exists from `source` to `target`.
    public func pathExists(source: Int32, target: Int32) -> Bool {
        idax_graph_path_exists(handle, source, target) != 0
    }

    // MARK: - Groups

    /// Create a group containing the specified nodes. Returns the group node ID.
    public func createGroup(nodes: [Int32]) throws(IDAError) -> Int32 {
        var groupId: Int32 = 0
        let ret = nodes.withUnsafeBufferPointer { buf in
            idax_graph_create_group(handle, buf.baseAddress, buf.count, &groupId)
        }
        try checkStatus(ret, "graph.createGroup")
        return groupId
    }

    /// Delete a group node.
    public func deleteGroup(_ group: Int32) throws(IDAError) {
        try checkStatus(idax_graph_delete_group(handle, group), "graph.deleteGroup")
    }

    /// Set whether a group is expanded or collapsed.
    public func setGroupExpanded(_ group: Int32, expanded: Bool) throws(IDAError) {
        try checkStatus(
            idax_graph_set_group_expanded(handle, group, expanded ? 1 : 0),
            "graph.setGroupExpanded"
        )
    }

    /// Whether the given node is a group.
    public func isGroup(_ node: Int32) -> Bool {
        idax_graph_is_group(handle, node) != 0
    }

    /// Whether the given group is collapsed.
    public func isCollapsed(_ group: Int32) -> Bool {
        idax_graph_is_collapsed(handle, group) != 0
    }

    /// Member node IDs of the given group.
    public func groupMembers(_ group: Int32) throws(IDAError) -> [Int32] {
        try nodeIdArray("graph.groupMembers") { idax_graph_group_members(handle, group, $0, $1) }
    }

    // MARK: - Layout

    /// Set the layout algorithm.
    public func setLayout(_ layout: GraphLayout) throws(IDAError) {
        try checkStatus(idax_graph_set_layout(handle, layout.rawValue), "graph.setLayout")
    }

    /// The currently active layout algorithm.
    public func currentLayout() throws(IDAError) -> GraphLayout {
        let ret = idax_graph_current_layout(handle)
        if ret < 0 {
            throw consumeLastError(fallback: "graph.currentLayout")
        }
        return GraphLayout(rawValue: ret) ?? .none
    }

    /// Recalculate the current layout.
    public func redoLayout() throws(IDAError) {
        try checkStatus(idax_graph_redo_layout(handle), "graph.redoLayout")
    }

    // MARK: - Viewer

    /// Show the graph in an IDA graph viewer window.
    public func show(title: String, callbacks: GraphCallbackHandler? = nil) throws(IDAError) {
        if let callbacks {
            let box = GraphCallbackBox(handler: callbacks)
            let ctx = Unmanaged.passRetained(box).toOpaque()
            var cbs = IdaxGraphCallbacks(
                context: ctx,
                on_refresh: refreshTrampoline,
                on_node_text: nodeTextTrampoline,
                on_node_color: nodeColorTrampoline,
                on_clicked: clickedTrampoline,
                on_double_clicked: doubleClickedTrampoline,
                on_hint: hintTrampoline,
                on_creating_group: creatingGroupTrampoline,
                on_destroyed: destroyedTrampoline
            )
            do {
                try checkStatus(
                    title.withCString { idax_graph_show_graph($0, handle, &cbs) },
                    "graph.show"
                )
            } catch {
                Unmanaged<AnyObject>.fromOpaque(ctx).release()
                throw error
            }
        } else {
            try checkStatus(
                title.withCString { idax_graph_show_graph($0, handle, nil) },
                "graph.show"
            )
        }
    }

    // MARK: - Static viewer operations

    /// Request that the named graph viewer refresh its display.
    public static func refreshViewer(title: String) throws(IDAError) {
        try checkStatus(
            title.withCString { idax_graph_refresh_graph($0) },
            "graph.refreshViewer"
        )
    }

    /// Whether a graph viewer with the given title exists.
    public static func hasViewer(title: String) throws(IDAError) -> Bool {
        try withOutput("graph.hasViewer", Int32(0)) { out in
            title.withCString { idax_graph_has_graph_viewer($0, out) }
        } != 0
    }

    /// Whether the named graph viewer is currently visible.
    public static func isViewerVisible(title: String) throws(IDAError) -> Bool {
        try withOutput("graph.isViewerVisible", Int32(0)) { out in
            title.withCString { idax_graph_is_graph_viewer_visible($0, out) }
        } != 0
    }

    /// Bring the named graph viewer to the foreground.
    public static func activateViewer(title: String) throws(IDAError) {
        try checkStatus(
            title.withCString { idax_graph_activate_graph_viewer($0) },
            "graph.activateViewer"
        )
    }

    /// Close the named graph viewer window.
    public static func closeViewer(title: String) throws(IDAError) {
        try checkStatus(
            title.withCString { idax_graph_close_graph_viewer($0) },
            "graph.closeViewer"
        )
    }

    // MARK: - Flow chart

    /// Compute the flow chart (basic blocks) for the function at the given address.
    public static func flowchart(at functionAddress: Address) throws(IDAError) -> [BasicBlock] {
        var ptr: UnsafeMutablePointer<IdaxBasicBlock>? = nil
        var count: Int = 0
        try checkStatus(idax_graph_flowchart(functionAddress, &ptr, &count), "graph.flowchart")
        defer { idax_graph_flowchart_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return convertBasicBlocks(ptr, count: count)
    }

    /// Compute the flow chart for a set of address ranges.
    public static func flowchart(
        forRanges ranges: [(start: Address, end: Address)]
    ) throws(IDAError) -> [BasicBlock] {
        let cRanges = ranges.map { IdaxAddressRange(start: $0.start, end: $0.end) }
        var ptr: UnsafeMutablePointer<IdaxBasicBlock>? = nil
        var count: Int = 0
        let ret = cRanges.withUnsafeBufferPointer { buf in
            idax_graph_flowchart_for_ranges(buf.baseAddress, buf.count, &ptr, &count)
        }
        try checkStatus(ret, "graph.flowchartForRanges")
        defer { idax_graph_flowchart_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return convertBasicBlocks(ptr, count: count)
    }
}

// MARK: - GraphCallbackHandler protocol

/// Protocol for handling graph viewer callbacks.
///
/// All methods have default (no-op) implementations so conforming types
/// need only override the callbacks they care about.
public protocol GraphCallbackHandler: AnyObject {
    /// Called when the graph needs to refresh. Return `true` to proceed.
    func onRefresh() -> Bool
    /// Return the display text for a node.
    func onNodeText(node: Int32) -> String?
    /// Return the background colour for a node.
    func onNodeColor(node: Int32) -> UInt32
    /// Called when a node is clicked. Return `true` if handled.
    func onClicked(node: Int32) -> Bool
    /// Called when a node is double-clicked. Return `true` if handled.
    func onDoubleClicked(node: Int32) -> Bool
    /// Return tooltip text for a node.
    func onHint(node: Int32) -> String?
    /// Called before a group is created. Return `true` to allow.
    func onCreatingGroup(nodes: [Int32]) -> Bool
    /// Called when the graph viewer is destroyed.
    func onDestroyed()
}

// Default implementations
public extension GraphCallbackHandler {
    func onRefresh() -> Bool { true }
    func onNodeText(node: Int32) -> String? { nil }
    func onNodeColor(node: Int32) -> UInt32 { 0xFFFFFF }
    func onClicked(node: Int32) -> Bool { false }
    func onDoubleClicked(node: Int32) -> Bool { false }
    func onHint(node: Int32) -> String? { nil }
    func onCreatingGroup(nodes: [Int32]) -> Bool { true }
    func onDestroyed() {}
}

// MARK: - Callback box and trampolines

private final class GraphCallbackBox {
    let handler: GraphCallbackHandler
    init(handler: GraphCallbackHandler) { self.handler = handler }
}

private func refreshTrampoline(
    ctx: UnsafeMutableRawPointer?,
    graph: IdaxGraphHandle?
) -> Int32 {
    guard let ctx else { return 0 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.handler.onRefresh() ? 1 : 0
}

private func nodeTextTrampoline(
    ctx: UnsafeMutableRawPointer?,
    node: Int32,
    outText: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ctx, let outText else { return 0 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    guard let text = box.handler.onNodeText(node: node) else { return 0 }
    outText.pointee = strdup(text)
    return 1
}

private func nodeColorTrampoline(
    ctx: UnsafeMutableRawPointer?,
    node: Int32
) -> UInt32 {
    guard let ctx else { return 0xFFFFFF }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.handler.onNodeColor(node: node)
}

private func clickedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    node: Int32
) -> Int32 {
    guard let ctx else { return 0 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.handler.onClicked(node: node) ? 1 : 0
}

private func doubleClickedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    node: Int32
) -> Int32 {
    guard let ctx else { return 0 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.handler.onDoubleClicked(node: node) ? 1 : 0
}

private func hintTrampoline(
    ctx: UnsafeMutableRawPointer?,
    node: Int32,
    outHint: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ctx, let outHint else { return 0 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    guard let hint = box.handler.onHint(node: node) else { return 0 }
    outHint.pointee = strdup(hint)
    return 1
}

private func creatingGroupTrampoline(
    ctx: UnsafeMutableRawPointer?,
    nodes: UnsafePointer<Int32>?,
    count: Int
) -> Int32 {
    guard let ctx, let nodes, count > 0 else { return 1 }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    let arr = Array(UnsafeBufferPointer(start: nodes, count: count))
    return box.handler.onCreatingGroup(nodes: arr) ? 1 : 0
}

private func destroyedTrampoline(ctx: UnsafeMutableRawPointer?) {
    guard let ctx else { return }
    let box = Unmanaged<GraphCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler.onDestroyed()
    // Release the retained reference since the viewer is gone
    Unmanaged<AnyObject>.fromOpaque(ctx).release()
}

// MARK: - Private helpers

/// Read a node-ID array from a C shim call and free it.
private func nodeIdArray(
    _ fallback: String,
    _ body: (UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>, UnsafeMutablePointer<Int>) -> Int32
) throws(IDAError) -> [Int32] {
    var ptr: UnsafeMutablePointer<Int32>? = nil
    var count: Int = 0
    try checkStatus(body(&ptr, &count), fallback)
    defer { idax_graph_free_node_ids(ptr) }
    guard let ptr, count > 0 else { return [] }
    return Array(UnsafeBufferPointer(start: ptr, count: count))
}

/// Convert a C basic-block array to Swift value types.
private func convertBasicBlocks(
    _ ptr: UnsafeMutablePointer<IdaxBasicBlock>,
    count: Int
) -> [BasicBlock] {
    let buf = UnsafeBufferPointer(start: ptr, count: count)
    return buf.map { raw in
        var succs: [Int32] = []
        if let s = raw.successors, raw.successor_count > 0 {
            succs = Array(UnsafeBufferPointer(start: s, count: raw.successor_count))
        }
        var preds: [Int32] = []
        if let p = raw.predecessors, raw.predecessor_count > 0 {
            preds = Array(UnsafeBufferPointer(start: p, count: raw.predecessor_count))
        }
        return BasicBlock(
            start: raw.start,
            end: raw.end,
            type: raw.type,
            successors: succs,
            predecessors: preds
        )
    }
}
