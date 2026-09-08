internal import CIDAX

/// Every borrowed view is valid only for the current visitor invocation.
/// All four callbacks are protocol requirements and dynamically dispatch.
public protocol CtreeVisitor: AnyObject {
    func visitExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction
    func visitStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction
    func leaveExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction
    func leaveStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction
}
extension CtreeVisitor {
    public func visitExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction { .continue }
    public func visitStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction { .continue }
    public func leaveExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction { .continue }
    public func leaveStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction { .continue }
}

internal final class CtreeNode {
    internal let pointer: UnsafeMutableRawPointer
    internal init(owning pointer: UnsafeMutableRawPointer) { self.pointer = pointer }
    deinit { idax_swift_tree_node_free(pointer) }
    func snapshot() throws(IDAError) -> Decompiler.CtreeItem {
        var output = IdaxDecompilerCtreeItemInfo()
        try bridgeCall("Decompiler.CtreeItem.snapshot") { idax_swift_tree_info(pointer, &output, $0) }
        return try .init(copying: output, "Decompiler.CtreeItem.snapshot")
    }
    func scalar(_ property: Int32) throws(IDAError) -> UInt64 {
        var output: UInt64 = 0
        try bridgeCall("Decompiler.CtreeItem.scalar") { idax_swift_tree_scalar(pointer, property, 0, &output, $0) }
        return output
    }
    func string(_ property: Int32) throws(IDAError) -> String {
        var output: UnsafeMutablePointer<CChar>?
        defer { idax_free_string(output) }
        try bridgeCall("Decompiler.CtreeItem.string") { idax_swift_tree_string(pointer, property, &output, $0) }
        return try borrowCString(output.map { UnsafePointer($0) }, "Decompiler.CtreeItem.string")
    }
    func child(_ property: Int32, at index: Int = 0) throws(IDAError) -> CtreeNode {
        try requireNonnegative(index, "Decompiler.CtreeItem.child")
        var output: UnsafeMutableRawPointer?
        try bridgeCall("Decompiler.CtreeItem.child") { idax_swift_tree_child(pointer, property, index, &output, $0) }
        return CtreeNode(owning: try requireOwnedHandle(output, "Decompiler.CtreeItem.child"))
    }
    func parents() throws(IDAError) -> [Decompiler.CtreeItem] {
        let op = "Decompiler.CtreeItem.parents"
        var output: UnsafeMutablePointer<IdaxDecompilerCtreeItemInfo>?; var count = 0
        defer { idax_swift_free_array(output) }
        try bridgeCall(op) { idax_swift_tree_parents(pointer, &output, &count, $0) }
        return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> Decompiler.CtreeItem in try .init(copying: value, op) }
    }
}

extension Decompiler {
    public struct VisitOptions: Equatable, Sendable {
        public var postOrder: Bool
        public var trackParents: Bool
        public var expressionsOnly: Bool
        public init(postOrder: Bool = false, trackParents: Bool = false, expressionsOnly: Bool = false) {
            self.postOrder = postOrder; self.trackParents = trackParents; self.expressionsOnly = expressionsOnly
        }
    }
    public final class Expression {
        internal let node: CtreeNode
        internal init(_ node: CtreeNode) { self.node = node }
        public func snapshot() throws(IDAError) -> CtreeItem { try node.snapshot() }
        public func type() throws(IDAError) -> ItemType { try snapshot().type }
        public func address() throws(IDAError) -> Address { try snapshot().address }
        public func numberValue() throws(IDAError) -> UInt64 { try node.scalar(0) }
        public func objectAddress() throws(IDAError) -> Address { try node.scalar(1) }
        public func variableIndex() throws(IDAError) -> Int32 { Int32(truncatingIfNeeded: try node.scalar(2)) }
        public func typeByteWidth() throws(IDAError) -> Int32 { Int32(truncatingIfNeeded: try node.scalar(3)) }
        public func pointedTypeByteWidth() throws(IDAError) -> Int32 { Int32(truncatingIfNeeded: try node.scalar(4)) }
        public func callArgumentCount() throws(IDAError) -> Int { try checkedCtreeCount(node.scalar(5)) }
        public func memberOffset() throws(IDAError) -> UInt32 { UInt32(truncatingIfNeeded: try node.scalar(6)) }
        public func isAssignmentLHS() throws(IDAError) -> Bool { try node.scalar(7) != 0 }
        public func operandCount() throws(IDAError) -> Int32 { Int32(truncatingIfNeeded: try node.scalar(8)) }
        public func helperName() throws(IDAError) -> String { try node.string(0) }
        public func typeDeclaration() throws(IDAError) -> String { try node.string(1) }
        public func stringValue() throws(IDAError) -> String { try node.string(2) }
        public func memberName() throws(IDAError) -> String { try node.string(3) }
        public func text() throws(IDAError) -> String { try node.string(4) }
        public func left() throws(IDAError) -> Expression { try Expression(node.child(0)) }
        public func right() throws(IDAError) -> Expression { try Expression(node.child(1)) }
        public func third() throws(IDAError) -> Expression { try Expression(node.child(2)) }
        public func callCallee() throws(IDAError) -> Expression { try Expression(node.child(3)) }
        public func callArgument(at index: Int) throws(IDAError) -> Expression { try Expression(node.child(4, at: index)) }
        public func parent() throws(IDAError) -> CtreeItem? { try node.parents().last }
        public func parents() throws(IDAError) -> [CtreeItem] { try node.parents() }
    }
    public final class Statement {
        internal let node: CtreeNode
        internal init(_ node: CtreeNode) { self.node = node }
        public func snapshot() throws(IDAError) -> CtreeItem { try node.snapshot() }
        public func type() throws(IDAError) -> ItemType { try snapshot().type }
        public func address() throws(IDAError) -> Address { try snapshot().address }
        public func gotoTargetLabel() throws(IDAError) -> Int32 { Int32(truncatingIfNeeded: try node.scalar(9)) }
        public func hasElseBranch() throws(IDAError) -> Bool { try node.scalar(10) != 0 }
        public func blockSize() throws(IDAError) -> Int { try checkedCtreeCount(node.scalar(11)) }
        public func switchCaseCount() throws(IDAError) -> Int { try checkedCtreeCount(node.scalar(12)) }
        public func condition() throws(IDAError) -> Expression { try Expression(node.child(5)) }
        public func thenBranch() throws(IDAError) -> Statement { try Statement(node.child(6)) }
        public func elseBranch() throws(IDAError) -> Statement { try Statement(node.child(7)) }
        public func body() throws(IDAError) -> Statement { try Statement(node.child(8)) }
        public func initExpression() throws(IDAError) -> Expression { try Expression(node.child(9)) }
        public func stepExpression() throws(IDAError) -> Expression { try Expression(node.child(10)) }
        public func expression() throws(IDAError) -> Expression { try Expression(node.child(11)) }
        public func blockStatement(at index: Int) throws(IDAError) -> Statement { try Statement(node.child(12, at: index)) }
        public func switchCaseBody(at index: Int) throws(IDAError) -> Statement { try Statement(node.child(13, at: index)) }
        public func parent() throws(IDAError) -> CtreeItem? { try node.parents().last }
        public func parents() throws(IDAError) -> [CtreeItem] { try node.parents() }
        public func switchCaseValues(at index: Int) throws(IDAError) -> [UInt64] {
            let op = "Decompiler.Statement.switchCaseValues"; try requireNonnegative(index, op)
            var output: UnsafeMutablePointer<UInt64>?; var count = 0
            defer { idax_swift_free_array(output) }
            try bridgeCall(op) { idax_swift_tree_switch_values(node.pointer, index, &output, &count, $0) }
            return try copyNativeValues(output, count: count, op) { $0 }
        }
    }
}

private func checkedCtreeCount(_ value: UInt64) throws(IDAError) -> Int {
    guard let result = Int(exactly: value) else { throw IDAError(category: .internalError, message: "Ctree count exceeds Swift Int", context: "Decompiler") }
    return result
}
private final class CtreeVisitorBox {
    let visitor: any CtreeVisitor
    init(_ visitor: any CtreeVisitor) { self.visitor = visitor }
}
private func invokeCtreeVisitor(_ context: UnsafeMutableRawPointer?, _ phase: Int32, _ expression: Int32,
    _ pointer: UnsafeMutableRawPointer?, _ action: UnsafeMutablePointer<Int32>?, _ nativeError: UnsafeMutablePointer<IdaxSwiftError>?
) -> Int32 {
    // Native transfers one node allocation unconditionally on callback entry.
    guard let pointer else { return -1 }
    let node = CtreeNode(owning: pointer)
    guard let context, let action else { return -1 }
    let visitor = Unmanaged<CtreeVisitorBox>.fromOpaque(context).takeUnretainedValue().visitor
    do {
        let result: Decompiler.VisitAction
        if expression != 0 {
            let value = Decompiler.Expression(node)
            result = try phase == 0 ? visitor.visitExpression(value) : visitor.leaveExpression(value)
        } else {
            let value = Decompiler.Statement(node)
            result = try phase == 0 ? visitor.visitStatement(value) : visitor.leaveStatement(value)
        }
        action.pointee = result.rawValue; return 0
    } catch { writeCallbackError(error, to: nativeError); return -1 }
}

extension Decompiler.Function {
    public func visit(_ visitor: any CtreeVisitor, options: Decompiler.VisitOptions = .init()) throws(IDAError) -> Int32 {
        let op = "Decompiler.Function.visit"
        let box = Unmanaged.passRetained(CtreeVisitorBox(visitor))
        defer { box.release() }
        return try withHandle(op) { (h) throws(IDAError) -> Int32 in
            try withDecompilerActivity(op) { () throws(IDAError) -> Int32 in
                var output: Int32 = 0
                try bridgeCall(op) { idax_swift_decompiled_visit(h, options.postOrder ? 1 : 0, options.trackParents ? 1 : 0,
                    options.expressionsOnly ? 1 : 0, box.toOpaque(), invokeCtreeVisitor, &output, $0) }
                return output
            }
        }
    }
    public func visitExpressions(_ visitor: any CtreeVisitor, postOrder: Bool = false) throws(IDAError) -> Int32 {
        try visit(visitor, options: .init(postOrder: postOrder, expressionsOnly: true))
    }
    public func forEachExpression(_ callback: @escaping (Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction) throws(IDAError) -> Int32 {
        try visitExpressions(ClosureCtreeVisitor(expression: callback, statement: { _ in .continue }))
    }
    public func forEachItem(expression: @escaping (Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction,
        statement: @escaping (Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction
    ) throws(IDAError) -> Int32 { try visit(ClosureCtreeVisitor(expression: expression, statement: statement)) }
}
private final class ClosureCtreeVisitor: CtreeVisitor {
    let expression: (Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction
    let statement: (Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction
    init(expression: @escaping (Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction,
         statement: @escaping (Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction) {
        self.expression = expression; self.statement = statement
    }
    func visitExpression(_ value: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction { try expression(value) }
    func visitStatement(_ value: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction { try statement(value) }
}
