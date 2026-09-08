internal import CIDAX

/// Mutable directed graph. Viewer callbacks retain its native graph even if
/// the originating Swift owner is released.
public final class Graph {
    public struct Node: Hashable, Sendable {
        internal let value: Int32
        public var index: Int32 { value }
        public init(index: Int32) { self.value = index }
    }
    public struct Edge: Sendable, Equatable {
        public var source: Node
        public var target: Node
        public init(source: Node, target: Node) {
            self.source = source
            self.target = target
        }
    }
    public struct EdgeStyle: Sendable {
        public var color: UInt32
        public var width: Int32
        public var sourcePort: Int32
        public var targetPort: Int32
        public init(color: UInt32 = .max, width: Int32 = 1, sourcePort: Int32 = -1, targetPort: Int32 = -1) {
            self.color = color
            self.width = width
            self.sourcePort = sourcePort
            self.targetPort = targetPort
        }
    }
    public struct NodeInfo: Sendable {
        public var text: String
        public var backgroundColor: UInt32
        public var frameColor: UInt32
        public var address: Address
        public init(text: String = "", backgroundColor: UInt32 = .max,
                    frameColor: UInt32 = .max, address: Address = .max) {
            self.text = text
            self.backgroundColor = backgroundColor
            self.frameColor = frameColor
            self.address = address
        }
    }
    public enum Layout: CaseIterable, Sendable {
        case none, digraph, tree, circle, polarTree, orthogonal, radialTree
        internal var native: Int32 { Int32(Self.allCases.firstIndex(of: self)!) }
    }
    private var handle: UnsafeMutableRawPointer?
    internal init(owning handle: UnsafeMutableRawPointer) { self.handle = handle }
    public init() throws(IDAError) {
        var result: UnsafeMutableRawPointer?
        try bridgeCall("graph.create") { idax_swift_graph_create(&result, $0) }
        handle = try requireLifecycleHandle(result, "graph.create")
    }
    deinit { if let handle { idax_swift_graph_release(handle) } }
    public func close() {
        if let handle {
            idax_swift_graph_release(handle)
            self.handle = nil
        }
    }
    private func checkedHandle() throws(IDAError) -> UnsafeMutableRawPointer {
        guard let handle else { throw IDAError(category: .conflict, message: "Graph is closed") }
        return handle
    }
    @discardableResult private func operation(
        _ op: Int32, _ a: Int32 = 0, _ b: Int32 = 0, _ c: Int32 = 0, _ d: Int32 = 0
    ) throws(IDAError) -> Int32 {
        let handle = try checkedHandle()
        var result: Int32 = 0
        try bridgeCall("graph.operation") { idax_swift_graph_operation(handle, op, a, b, c, d, &result, $0) }
        return result
    }
    public func addNode() throws(IDAError) -> Node { Node(index: try operation(0)) }
    public func removeNode(_ node: Node) throws(IDAError) { try operation(1, node.value) }
    public var totalNodeCount: Int32 { get throws(IDAError) { try operation(2) } }
    public var visibleNodeCount: Int32 { get throws(IDAError) { try operation(3) } }
    public func contains(_ node: Node) throws(IDAError) -> Bool { try operation(4, node.value) != 0 }
    public func addEdge(from source: Node, to target: Node, style: EdgeStyle? = nil) throws(IDAError) {
        if let style {
            let handle = try checkedHandle()
            var raw = IdaxSwiftGraphEdgeStyle(
                color: style.color, width: style.width, source_port: style.sourcePort,
                target_port: style.targetPort)
            try bridgeCall("graph.addEdge") {
                idax_swift_graph_add_styled_edge(handle, source.value, target.value, &raw, $0)
            }
        } else {
            try operation(5, source.value, target.value)
        }
    }
    public func removeEdge(from source: Node, to target: Node) throws(IDAError) {
        try operation(6, source.value, target.value)
    }
    public func replaceEdge(_ old: Edge, with replacement: Edge) throws(IDAError) {
        try operation(
            7, old.source.value, old.target.value, replacement.source.value, replacement.target.value)
    }
    public func pathExists(from source: Node, to target: Node) throws(IDAError) -> Bool {
        try operation(8, source.value, target.value) != 0
    }
    public func deleteGroup(_ group: Node) throws(IDAError) { try operation(9, group.value) }
    public func setGroupExpanded(_ group: Node, expanded: Bool) throws(IDAError) {
        try operation(10, group.value, expanded ? 1 : 0)
    }
    public func isGroup(_ node: Node) throws(IDAError) -> Bool { try operation(11, node.value) != 0 }
    public func isCollapsed(_ group: Node) throws(IDAError) -> Bool { try operation(12, group.value) != 0 }
    public func setLayout(_ layout: Layout) throws(IDAError) { try operation(13, layout.native) }
    public var layout: Layout {
        get throws(IDAError) {
            let value = try operation(14)
            guard value >= 0, Int(value) < Layout.allCases.count else {
                throw IDAError(category: .unsupported, message: "Unknown graph layout")
            }
            return Layout.allCases[Int(value)]
        }
    }
    public func redoLayout() throws(IDAError) { try operation(15) }
    public func clear() throws(IDAError) { try operation(16) }
    public func successors(of node: Node) throws(IDAError) -> [Node] { try nodes(0, node.value) }
    public func predecessors(of node: Node) throws(IDAError) -> [Node] { try nodes(1, node.value) }
    public var visibleNodes: [Node] { get throws(IDAError) { try nodes(2, 0) } }
    public func members(of group: Node) throws(IDAError) -> [Node] { try nodes(3, group.value) }
    private func nodes(_ operation: Int32, _ node: Int32) throws(IDAError) -> [Node] {
        try Self.readNodes(try checkedHandle(), operation, node)
    }
    private static func readNodes(_ handle: UnsafeMutableRawPointer, _ operation: Int32, _ node: Int32)
        throws(IDAError) -> [Node]
    {
        var pointer: UnsafeMutablePointer<Int32>?
        var count = 0
        try bridgeCall("graph.nodes") {
            idax_swift_graph_nodes(handle, operation, node, &pointer, &count, $0)
        }
        defer { idax_free_bytes(UnsafeMutableRawPointer(pointer)?.assumingMemoryBound(to: UInt8.self)) }
        return try checkedBuffer(pointer, count: count, "graph.nodes").map { Node(index: $0) }
    }
    public var edges: [Edge] {
        get throws(IDAError) {
            let handle = try checkedHandle()
            var pointer: UnsafeMutablePointer<IdaxSwiftGraphEdge>?
            var count = 0
            try bridgeCall("graph.edges") { idax_swift_graph_edges(handle, &pointer, &count, $0) }
            defer { idax_free_bytes(UnsafeMutableRawPointer(pointer)?.assumingMemoryBound(to: UInt8.self)) }
            return try checkedBuffer(pointer, count: count, "graph.edges").map {
                Edge(source: Node(index: $0.source), target: Node(index: $0.target))
            }
        }
    }
    public func createGroup(_ nodes: [Node]) throws(IDAError) -> Node {
        let handle = try checkedHandle()
        let indices = nodes.map(\.value)
        var result: Int32 = 0
        try bridgeCall("graph.createGroup") { error in
            indices.withUnsafeBufferPointer {
                idax_swift_graph_group(handle, $0.baseAddress, $0.count, &result, error)
            }
        }
        return Node(index: result)
    }
    public func show(title: String, callbacks: any GraphCallbacks) throws(IDAError) {
        let handle = try checkedHandle()
        let strings = try LifecycleStrings([title])
        let descriptor = callbackDescriptor { event, reply in
            let node = Node(index: event.number)
            switch event.kind {
            case 0:
                var graph: UnsafeMutableRawPointer?
                try bridgeCall("graph.refreshContext") {
                    idax_swift_graph_callback_copy(event.lease, &graph, $0)
                }
                let context = Graph(owning: try requireLifecycleHandle(graph, "graph.refreshContext"))
                reply.pointee.decision = try callbacks.refresh(context) ? 1 : 0
            case 1:
                let text = try callbacks.text(for: node)
                try checkedCString(text, "graph.callback.text") { idax_swift_reply_text(reply, $0) }
            case 2: reply.pointee.unsigned_integer = UInt64(try callbacks.color(for: node))
            case 3: reply.pointee.decision = try callbacks.clicked(node) ? 1 : 0
            case 4: reply.pointee.decision = try callbacks.doubleClicked(node) ? 1 : 0
            case 5:
                let text = try callbacks.hint(for: node)
                try checkedCString(text, "graph.callback.hint") { idax_swift_reply_text(reply, $0) }
            case 6:
                reply.pointee.decision =
                    try callbacks.creatingGroup(
                        Self.readNodes(try requireLifecycleHandle(event.lease, "graph.groupLease"), 4, 0))
                    ? 1 : 0
            case 7: callbacks.destroyed()
            default: throw IDAError(category: .unsupported, message: "Unknown graph callback")
            }
        }
        try bridgeCall("graph.show") { idax_swift_graph_show(handle, strings[0], descriptor, $0) }
    }
    private static func viewer(_ operation: Int32, _ title: String) throws(IDAError) -> Bool {
        let strings = try LifecycleStrings([title])
        var result: Int32 = 0
        try bridgeCall("graph.viewer") { idax_swift_graph_viewer(operation, strings[0], &result, $0) }
        return result != 0
    }
    public static func refreshViewer(title: String) throws(IDAError) { _ = try viewer(0, title) }
    public static func hasViewer(title: String) throws(IDAError) -> Bool { try viewer(1, title) }
    public static func isViewerVisible(title: String) throws(IDAError) -> Bool { try viewer(2, title) }
    public static func activateViewer(title: String) throws(IDAError) { _ = try viewer(3, title) }
    public static func closeViewer(title: String) throws(IDAError) { _ = try viewer(4, title) }
    public enum BlockType: Int32, Sendable {
        case normal, indirectJump, `return`, conditionalReturn, noReturn, externalNoReturn, external, error
    }
    public struct BasicBlock: Sendable {
        public var start, end: Address
        public var type: BlockType
        public var successors, predecessors: [Int32]
        public init(start: Address, end: Address, type: BlockType = .normal,
                    successors: [Int32] = [], predecessors: [Int32] = []) {
            self.start = start
            self.end = end
            self.type = type
            self.successors = successors
            self.predecessors = predecessors
        }
        internal init(_ value: IdaxBasicBlock) throws(IDAError) {
            guard let type = BlockType(rawValue: value.type) else {
                throw IDAError(category: .unsupported, message: "Unknown basic block type")
            }
            self.start = value.start
            self.end = value.end
            self.type = type
            self.successors = Array(
                try checkedBuffer(value.successors, count: value.successor_count, "graph.successors"))
            self.predecessors = Array(
                try checkedBuffer(value.predecessors, count: value.predecessor_count, "graph.predecessors"))
        }
    }
    public struct SwitchTable: Sendable {
        public var address: Address
        public var entryCount, entrySize: Int
        public init(address: Address = .max, entryCount: Int = 0, entrySize: Int = 0) {
            self.address = address
            self.entryCount = entryCount
            self.entrySize = entrySize
        }
    }
    public static func switchTable(at address: Address) throws(IDAError) -> SwitchTable {
        var table: UInt64 = 0
        var count = 0
        var size = 0
        try bridgeCall("graph.switchTable") { idax_swift_graph_switch(address, &table, &count, &size, $0) }
        return SwitchTable(address: table, entryCount: count, entrySize: size)
    }
    public static func flowchart(at functionAddress: Address) throws(IDAError) -> [BasicBlock] {
        try requireRuntimeThread("graph.flowchart")
        var pointer: UnsafeMutablePointer<IdaxBasicBlock>?
        var count = 0
        try checkStatus(idax_graph_flowchart(functionAddress, &pointer, &count), "graph.flowchart")
        defer { idax_graph_flowchart_free(pointer, count) }
        var result: [BasicBlock] = []
        for value in try checkedBuffer(pointer, count: count, "graph.flowchart") {
            result.append(try BasicBlock(value))
        }
        return result
    }
    public static func flowchart(for ranges: [Range<Address>]) throws(IDAError) -> [BasicBlock] {
        try requireRuntimeThread("graph.flowchartForRanges")
        let native = ranges.map { IdaxAddressRange(start: $0.lowerBound, end: $0.upperBound) }
        var pointer: UnsafeMutablePointer<IdaxBasicBlock>?
        var count = 0
        try checkStatus(
            native.withUnsafeBufferPointer {
                idax_graph_flowchart_for_ranges($0.baseAddress, $0.count, &pointer, &count)
            }, "graph.flowchartForRanges")
        defer { idax_graph_flowchart_free(pointer, count) }
        var result: [BasicBlock] = []
        for value in try checkedBuffer(pointer, count: count, "graph.flowchartForRanges") {
            result.append(try BasicBlock(value))
        }
        return result
    }
}

public protocol GraphCallbacks: AnyObject {
    /// The graph is an independently retained alias of the viewer's model.
    func refresh(_ graph: Graph) throws(IDAError) -> Bool
    func text(for node: Graph.Node) throws(IDAError) -> String
    func color(for node: Graph.Node) throws(IDAError) -> UInt32
    func clicked(_ node: Graph.Node) throws(IDAError) -> Bool
    func doubleClicked(_ node: Graph.Node) throws(IDAError) -> Bool
    func hint(for node: Graph.Node) throws(IDAError) -> String
    func creatingGroup(_ nodes: [Graph.Node]) throws(IDAError) -> Bool
    func destroyed()
}
extension GraphCallbacks {
    public func refresh(_ graph: Graph) throws(IDAError) -> Bool { false }
    public func text(for node: Graph.Node) throws(IDAError) -> String { "" }
    public func color(for node: Graph.Node) throws(IDAError) -> UInt32 { .max }
    public func clicked(_ node: Graph.Node) throws(IDAError) -> Bool { false }
    public func doubleClicked(_ node: Graph.Node) throws(IDAError) -> Bool { false }
    public func hint(for node: Graph.Node) throws(IDAError) -> String { "" }
    public func creatingGroup(_ nodes: [Graph.Node]) throws(IDAError) -> Bool { true }
    public func destroyed() {}
}
