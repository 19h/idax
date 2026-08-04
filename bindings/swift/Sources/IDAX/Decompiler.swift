internal import CIDAX
import Darwin

/// Storage class for a decompiler local variable.
public enum VariableStorage: Int, Sendable {
    case unknown = 0
    case register = 1
    case stack = 2
}

/// Local variable from decompilation.
public struct LocalVariable: Sendable {
    public let name: String
    public let typeName: String
    public let isArgument: Bool
    public let width: Int
    public let hasUserName: Bool
    public let storage: VariableStorage
    public let comment: String
    /// Stack-frame offset for stack variables; `-1` for variables that do not
    /// live on the stack. Mirrors `lvar_t::get_stkoff()`.
    public let stackOffset: Int64
    /// Microcode register number (`mreg_t`) for register variables; `-1` for
    /// variables that do not live in a register. Mirrors `lvar_t::get_reg1()`.
    /// On ARM64 the mreg of `x<n>` is `8 + 8*n` (x0=8, x1=16, ..., x20=168),
    /// which lets consumers map argument lvars back to the ABI registers x0-x7.
    public let registerNumber: Int
}

/// Decompiled function handle.
///
/// Move-only value — `deinit` frees the underlying handle.
public struct DecompiledFunction: ~Copyable, @unchecked Sendable {
    let handle: IdaxDecompiledHandle

    init(_ handle: IdaxDecompiledHandle) {
        self.handle = handle
    }

    deinit {
        idax_decompiled_free(handle)
    }

    public var pseudocode: String {
        get throws(IDAError) {
            try withStringOutput("decompiled.pseudocode") { idax_decompiled_pseudocode(handle, $0) }
        }
    }

    public var declaration: String {
        get throws(IDAError) {
            try withStringOutput("decompiled.declaration") { idax_decompiled_declaration(handle, $0) }
        }
    }

    public var entryAddress: Address {
        get throws(IDAError) {
            try withOutput("decompiled.entryAddress", UInt64(0)) { idax_decompiled_entry_address(handle, $0) }
        }
    }

    public var lines: [String] {
        get throws(IDAError) {
            var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
            var count: Int = 0
            try checkStatus(idax_decompiled_lines(handle, &ptr, &count), "decompiled.lines")
            defer { idax_decompiled_lines_free(ptr, count) }
            guard let ptr, count > 0 else { return [] }
            return (0..<count).map { i in
                if let s = ptr[i] { String(cString: s) } else { "" }
            }
        }
    }

    public var variables: [LocalVariable] {
        get throws(IDAError) {
            var ptr: UnsafeMutablePointer<IdaxLocalVariable>? = nil
            var count: Int = 0
            try checkStatus(idax_decompiled_variables(handle, &ptr, &count), "decompiled.variables")
            defer { idax_decompiled_variables_free(ptr, count) }
            guard let ptr, count > 0 else { return [] }
            let buf = UnsafeBufferPointer(start: ptr, count: count)
            return buf.map { v in
                LocalVariable(
                    name: borrowCString(v.name),
                    typeName: borrowCString(v.type_name),
                    isArgument: v.is_argument != 0,
                    width: Int(v.width),
                    hasUserName: v.has_user_name != 0,
                    storage: VariableStorage(rawValue: Int(v.storage)) ?? .unknown,
                    comment: borrowCString(v.comment),
                    stackOffset: v.stack_offset,
                    registerNumber: Int(v.register_number)
                )
            }
        }
    }

    public func renameVariable(from oldName: String, to newName: String) throws(IDAError) {
        try checkStatus(
            oldName.withCString { o in
                newName.withCString { n in
                    idax_decompiled_rename_variable(handle, o, n)
                }
            },
            "decompiled.renameVariable"
        )
    }

    // MARK: - Additional properties

    public var microcode: String {
        get throws(IDAError) {
            try withStringOutput("decompiled.microcode") { idax_decompiled_microcode(handle, $0) }
        }
    }

    public var rawLines: [String] {
        get throws(IDAError) {
            var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
            var count: Int = 0
            try checkStatus(idax_decompiled_raw_lines(handle, &ptr, &count), "decompiled.rawLines")
            defer { idax_decompiled_lines_free(ptr, count) }
            guard let ptr, count > 0 else { return [] }
            return (0..<count).map { i in
                if let s = ptr[i] { String(cString: s) } else { "" }
            }
        }
    }

    public func setRawLine(at lineIndex: Int, text: String) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_decompiled_set_raw_line(handle, lineIndex, $0) },
            "decompiled.setRawLine"
        )
    }

    public var headerLineCount: Int {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(idax_decompiled_header_line_count(handle, &out), "decompiled.headerLineCount")
            return Int(out)
        }
    }

    public var variableCount: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_decompiled_variable_count(handle, &out), "decompiled.variableCount")
            return out
        }
    }

    // MARK: - Comments

    /// Semantic location of a persisted pseudocode comment.
    ///
    /// Replaces the raw integer position the C ABI used to take. `value`
    /// carries the argument index or switch-case value, and is ignored for
    /// every other kind.
    public struct CommentPosition: Sendable, Equatable {
        public enum Kind: Int32, Sendable {
            case `default` = 0
            case argument = 1
            case parenthesisOpen = 2
            case assembly = 3
            case elseLine = 4
            case doLine = 5
            case semicolon = 6
            case openBrace = 7
            case closeBrace = 8
            case parenthesisClose = 9
            case labelColon = 10
            case blockBefore = 11
            case blockAfter = 12
            case tryLine = 13
            case switchCase = 14
        }

        public var kind: Kind
        public var value: Int64

        public init(kind: Kind = .default, value: Int64 = 0) {
            self.kind = kind
            self.value = value
        }

        public static let `default` = CommentPosition()

        public static func argument(index: Int64) -> CommentPosition {
            CommentPosition(kind: .argument, value: index)
        }

        public static func switchCase(value: Int64) -> CommentPosition {
            CommentPosition(kind: .switchCase, value: value)
        }

        var cValue: IdaxDecompilerCommentPosition {
            IdaxDecompilerCommentPosition(kind: kind.rawValue, value: value)
        }
    }

    public func setComment(at address: Address,
                           text: String,
                           position: CommentPosition = .default) throws(IDAError) {
        var rawPosition = position.cValue
        try checkStatus(
            text.withCString { textPointer in
                withUnsafePointer(to: &rawPosition) { positionPointer in
                    idax_decompiled_set_comment(handle, address, textPointer, positionPointer)
                }
            },
            "decompiled.setComment"
        )
    }

    public func comment(at address: Address,
                        position: CommentPosition = .default) throws(IDAError) -> String {
        var rawPosition = position.cValue
        return try withStringOutput("decompiled.comment") { out in
            withUnsafePointer(to: &rawPosition) { positionPointer in
                idax_decompiled_get_comment(handle, address, positionPointer, out)
            }
        }
    }

    public func saveComments() throws(IDAError) {
        try checkStatus(idax_decompiled_save_comments(handle), "decompiled.saveComments")
    }

    // MARK: - Line / address mapping

    public func lineToAddress(_ lineNumber: Int) throws(IDAError) -> Address {
        try withOutput("decompiled.lineToAddress", UInt64(0)) {
            idax_decompiled_line_to_address(handle, Int32(lineNumber), $0)
        }
    }

    // MARK: - Visitors

    public func forEachExpression(_ visitor: @escaping (Int, Address) -> Bool) throws(IDAError) -> Int {
        final class VisitorBox {
            let visitor: (Int, Address) -> Bool
            init(_ visitor: @escaping (Int, Address) -> Bool) { self.visitor = visitor }
        }
        let box = VisitorBox(visitor)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<VisitorBox>.fromOpaque(ctx).release() }
        var visited: Int32 = 0
        let trampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerExpressionInfo>?) -> Int32 = { ctx, expr in
            guard let ctx, let expr else { return 0 }
            let box = Unmanaged<VisitorBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.visitor(Int(expr.pointee.type), expr.pointee.address) ? 1 : 0
        }
        try checkStatus(
            idax_decompiler_for_each_expression(handle, trampoline, ctx, &visited),
            "decompiled.forEachExpression"
        )
        return Int(visited)
    }

    public func forEachItem(
        expressionVisitor: @escaping (Int, Address) -> Bool,
        statementVisitor: @escaping (Int, Address) -> Bool
    ) throws(IDAError) -> Int {
        final class ItemVisitorBox {
            let exprVisitor: (Int, Address) -> Bool
            let stmtVisitor: (Int, Address) -> Bool
            init(
                _ exprVisitor: @escaping (Int, Address) -> Bool,
                _ stmtVisitor: @escaping (Int, Address) -> Bool
            ) {
                self.exprVisitor = exprVisitor
                self.stmtVisitor = stmtVisitor
            }
        }
        let box = ItemVisitorBox(expressionVisitor, statementVisitor)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<ItemVisitorBox>.fromOpaque(ctx).release() }
        var visited: Int32 = 0
        let exprTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerExpressionInfo>?) -> Int32 = { ctx, expr in
            guard let ctx, let expr else { return 0 }
            let box = Unmanaged<ItemVisitorBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.exprVisitor(Int(expr.pointee.type), expr.pointee.address) ? 1 : 0
        }
        let stmtTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerStatementInfo>?) -> Int32 = { ctx, stmt in
            guard let ctx, let stmt else { return 0 }
            let box = Unmanaged<ItemVisitorBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.stmtVisitor(Int(stmt.pointee.type), stmt.pointee.address) ? 1 : 0
        }
        try checkStatus(
            idax_decompiler_for_each_item(handle, exprTrampoline, stmtTrampoline, ctx, &visited),
            "decompiled.forEachItem"
        )
        return Int(visited)
    }

    // MARK: - Handle-based ctree visitor

    /// Visit the ctree with full handle access.
    ///
    /// The closures receive non-owning handles that are only valid during the callback.
    /// Return `.continue` to keep traversing, `.stop` to halt, `.skipChildren` to skip subtree.
    public func visitCtree(
        postOrder: Bool = false,
        expressionVisitor: ((CtreeExpression) -> CtreeVisitAction)? = nil,
        statementVisitor: ((CtreeStatement) -> CtreeVisitAction)? = nil
    ) throws(IDAError) -> Int {
        final class VisitorBox {
            let exprVisitor: ((CtreeExpression) -> CtreeVisitAction)?
            let stmtVisitor: ((CtreeStatement) -> CtreeVisitAction)?
            init(
                _ exprVisitor: ((CtreeExpression) -> CtreeVisitAction)?,
                _ stmtVisitor: ((CtreeStatement) -> CtreeVisitAction)?
            ) {
                self.exprVisitor = exprVisitor
                self.stmtVisitor = stmtVisitor
            }
        }
        let box = VisitorBox(expressionVisitor, statementVisitor)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<VisitorBox>.fromOpaque(ctx).release() }

        var visited: Int32 = 0

        let exprCb: IdaxCtreeExprVisitor? = expressionVisitor != nil ? { ctx, expr in
            guard let ctx, let expr else { return 0 }
            let box = Unmanaged<VisitorBox>.fromOpaque(ctx).takeUnretainedValue()
            let result = box.exprVisitor!(CtreeExpression(expr))
            return result.rawValue
        } : nil

        let stmtCb: IdaxCtreeStmtVisitor? = statementVisitor != nil ? { ctx, stmt in
            guard let ctx, let stmt else { return 0 }
            let box = Unmanaged<VisitorBox>.fromOpaque(ctx).takeUnretainedValue()
            let result = box.stmtVisitor!(CtreeStatement(stmt))
            return result.rawValue
        } : nil

        try checkStatus(
            idax_ctree_visit(handle, exprCb, stmtCb, ctx, postOrder ? 1 : 0, &visited),
            "decompiled.visitCtree"
        )
        return Int(visited)
    }

    // MARK: - Retype / refresh

    /// Retype a local variable by name using a C type declaration string.
    ///
    /// Call `refresh()` after success to update the pseudocode text.
    public func retypeVariable(name variableName: String, typeDeclaration: String) throws(IDAError) {
        try checkStatus(
            variableName.withCString { namePtr in
                typeDeclaration.withCString { declPtr in
                    idax_decompiled_retype_variable(handle, namePtr, declPtr)
                }
            },
            "decompiled.retypeVariable"
        )
    }

    /// Retype a local variable by index using an existing `TypeHandle`.
    ///
    /// Call `refresh()` after success to update the pseudocode text.
    public func retypeVariable(at variableIndex: Int, type typeHandle: borrowing TypeHandle) throws(IDAError) {
        try checkStatus(
            idax_decompiled_retype_variable_by_index(handle, variableIndex, typeHandle.handle),
            "decompiled.retypeVariableByIndex"
        )
    }

    /// Refresh the pseudocode view to reflect any changes made to the decompiled function.
    public func refresh() throws(IDAError) {
        try checkStatus(idax_decompiled_refresh(handle), "decompiled.refresh")
    }

    // MARK: - Orphan comments

    /// Returns `true` if the decompiled function has orphan comments (comments no longer
    /// attached to any address in the current pseudocode).
    public var hasOrphanComments: Bool {
        get throws(IDAError) {
            var outResult: Int32 = 0
            try checkStatus(idax_decompiled_has_orphan_comments(handle, &outResult),
                            "decompiled.hasOrphanComments")
            return outResult != 0
        }
    }

    /// Remove all orphan comments and return the number of comments removed.
    @discardableResult
    public func removeOrphanComments() throws(IDAError) -> Int {
        var outRemovedCount: Int32 = 0
        try checkStatus(idax_decompiled_remove_orphan_comments(handle, &outRemovedCount),
                        "decompiled.removeOrphanComments")
        return Int(outRemovedCount)
    }

    // MARK: - Address map / microcode lines

    /// Returns the mapping between pseudocode line numbers and binary addresses.
    public var addressMap: [AddressMapping] {
        get throws(IDAError) {
            var outLineNumbers: UnsafeMutablePointer<UInt64>? = nil
            var outAddresses: UnsafeMutablePointer<UInt64>? = nil
            var outCount: Int = 0
            try checkStatus(
                idax_decompiled_address_map(handle, &outLineNumbers, &outAddresses, &outCount),
                "decompiled.addressMap"
            )
            defer { idax_decompiled_address_map_free(outLineNumbers, outAddresses) }
            guard let lineNumbersPtr = outLineNumbers, let addressesPtr = outAddresses, outCount > 0 else {
                return []
            }
            return (0..<outCount).map { index in
                AddressMapping(
                    lineNumber: Int(lineNumbersPtr[index]),
                    address: addressesPtr[index]
                )
            }
        }
    }

    /// Returns the microcode lines for the decompiled function.
    ///
    /// Only available after a successful decompilation with the decompiler plugin loaded.
    public var microcodeLines: [String] {
        get throws(IDAError) {
            var outLines: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
            var outCount: Int = 0
            try checkStatus(
                idax_decompiled_microcode_lines(handle, &outLines, &outCount),
                "decompiled.microcodeLines"
            )
            guard let linesPtr = outLines, outCount > 0 else { return [] }
            defer {
                for lineIndex in 0..<outCount {
                    free(linesPtr[lineIndex])
                }
                free(linesPtr)
            }
            return (0..<outCount).map { lineIndex in
                if let linePtr = linesPtr[lineIndex] { String(cString: linePtr) } else { "" }
            }
        }
    }

    // MARK: - Extended ctree visitor with leave callbacks

    /// Visit the ctree with full handle access including leave (post-visit) callbacks.
    ///
    /// This is similar to `visitCtree` but also fires `expressionLeave` and `statementLeave`
    /// when leaving each node. If no leave closures are provided, this falls back to
    /// `idax_ctree_visit`.
    ///
    /// The closures receive non-owning handles valid only during the callback.
    /// Return `.continue` to keep traversing, `.stop` to halt, `.skipChildren` to skip subtree.
    public func visitCtreeEx(
        postOrder: Bool = false,
        expressionVisitor: ((CtreeExpression) -> CtreeVisitAction)? = nil,
        statementVisitor: ((CtreeStatement) -> CtreeVisitAction)? = nil,
        expressionLeave: ((CtreeExpression) -> CtreeVisitAction)? = nil,
        statementLeave: ((CtreeStatement) -> CtreeVisitAction)? = nil
    ) throws(IDAError) -> Int {
        // Fall back to the simpler visit when no leave callbacks are needed.
        if expressionLeave == nil && statementLeave == nil {
            return try visitCtree(
                postOrder: postOrder,
                expressionVisitor: expressionVisitor,
                statementVisitor: statementVisitor
            )
        }

        final class VisitorExBox {
            let exprVisitor: ((CtreeExpression) -> CtreeVisitAction)?
            let stmtVisitor: ((CtreeStatement) -> CtreeVisitAction)?
            let exprLeave: ((CtreeExpression) -> CtreeVisitAction)?
            let stmtLeave: ((CtreeStatement) -> CtreeVisitAction)?
            init(
                _ exprVisitor: ((CtreeExpression) -> CtreeVisitAction)?,
                _ stmtVisitor: ((CtreeStatement) -> CtreeVisitAction)?,
                _ exprLeave: ((CtreeExpression) -> CtreeVisitAction)?,
                _ stmtLeave: ((CtreeStatement) -> CtreeVisitAction)?
            ) {
                self.exprVisitor = exprVisitor
                self.stmtVisitor = stmtVisitor
                self.exprLeave = exprLeave
                self.stmtLeave = stmtLeave
            }
        }
        let box = VisitorExBox(expressionVisitor, statementVisitor, expressionLeave, statementLeave)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<VisitorExBox>.fromOpaque(ctx).release() }

        var visited: Int32 = 0

        let visitExprCb: IdaxCtreeExprVisitor? = expressionVisitor != nil ? { ctx, expr in
            guard let ctx, let expr else { return 0 }
            let box = Unmanaged<VisitorExBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.exprVisitor!(CtreeExpression(expr)).rawValue
        } : nil

        let visitStmtCb: IdaxCtreeStmtVisitor? = statementVisitor != nil ? { ctx, stmt in
            guard let ctx, let stmt else { return 0 }
            let box = Unmanaged<VisitorExBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.stmtVisitor!(CtreeStatement(stmt)).rawValue
        } : nil

        let leaveExprCb: IdaxCtreeExprLeaveVisitor? = expressionLeave != nil ? { ctx, expr in
            guard let ctx, let expr else { return 0 }
            let box = Unmanaged<VisitorExBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.exprLeave!(CtreeExpression(expr)).rawValue
        } : nil

        let leaveStmtCb: IdaxCtreeStmtLeaveVisitor? = statementLeave != nil ? { ctx, stmt in
            guard let ctx, let stmt else { return 0 }
            let box = Unmanaged<VisitorExBox>.fromOpaque(ctx).takeUnretainedValue()
            return box.stmtLeave!(CtreeStatement(stmt)).rawValue
        } : nil

        try checkStatus(
            idax_ctree_visit_ex(
                handle,
                visitExprCb, visitStmtCb,
                leaveExprCb, leaveStmtCb,
                ctx,
                postOrder ? 1 : 0,
                &visited
            ),
            "decompiled.visitCtreeEx"
        )
        return Int(visited)
    }
}

/// Mapping between a pseudocode line number and a database address.
public struct AddressMapping: Sendable {
    public let lineNumber: Int
    public let address: Address
}

// MARK: - Ctree types

/// Type of a ctree item (expression or statement).
public enum CtreeItemType: Int32, Sendable {
    // Expressions
    case exprEmpty = 0
    case exprComma = 1
    case exprAssign = 2
    case exprAssignBitOr = 3
    case exprAssignXor = 4
    case exprAssignBitAnd = 5
    case exprAssignAdd = 6
    case exprAssignSub = 7
    case exprAssignMul = 8
    case exprAssignShiftRightSigned = 9
    case exprAssignShiftRightUnsigned = 10
    case exprAssignShiftLeft = 11
    case exprAssignDivSigned = 12
    case exprAssignDivUnsigned = 13
    case exprAssignModSigned = 14
    case exprAssignModUnsigned = 15
    case exprTernary = 16
    case exprLogicalOr = 17
    case exprLogicalAnd = 18
    case exprBitOr = 19
    case exprXor = 20
    case exprBitAnd = 21
    case exprEqual = 22
    case exprNotEqual = 23
    case exprSignedGE = 24
    case exprUnsignedGE = 25
    case exprSignedLE = 26
    case exprUnsignedLE = 27
    case exprSignedGT = 28
    case exprUnsignedGT = 29
    case exprSignedLT = 30
    case exprUnsignedLT = 31
    case exprShiftRightSigned = 32
    case exprShiftRightUnsigned = 33
    case exprShiftLeft = 34
    case exprAdd = 35
    case exprSub = 36
    case exprMul = 37
    case exprDivSigned = 38
    case exprDivUnsigned = 39
    case exprModSigned = 40
    case exprModUnsigned = 41
    case exprFloatAdd = 42
    case exprFloatSub = 43
    case exprFloatMul = 44
    case exprFloatDiv = 45
    case exprFloatNeg = 46
    case exprNeg = 47
    case exprCast = 48
    case exprLogicalNot = 49
    case exprBitNot = 50
    case exprDeref = 51
    case exprRef = 52
    case exprPostInc = 53
    case exprPostDec = 54
    case exprPreInc = 55
    case exprPreDec = 56
    case exprCall = 57
    case exprIndex = 58
    case exprMemberRef = 59
    case exprMemberPtr = 60
    case exprNumber = 61
    case exprFloatNumber = 62
    case exprString = 63
    case exprObject = 64
    case exprVariable = 65
    case exprInsn = 66
    case exprSizeof = 67
    case exprHelper = 68
    case exprType = 69

    // Statements
    case stmtEmpty = 70
    case stmtBlock = 71
    case stmtExpr = 72
    case stmtIf = 73
    case stmtFor = 74
    case stmtWhile = 75
    case stmtDo = 76
    case stmtSwitch = 77
    case stmtBreak = 78
    case stmtContinue = 79
    case stmtReturn = 80
    case stmtGoto = 81
    case stmtAsm = 82
    case stmtTry = 83
    case stmtThrow = 84

    public var isExpression: Bool { rawValue <= 69 }
    public var isStatement: Bool { rawValue > 69 }
}

/// Result returned from ctree visitor callbacks.
public enum CtreeVisitAction: Int32, Sendable {
    case `continue` = 0
    case stop = 1
    case skipChildren = 2
}

/// Value snapshot of a parent ctree item.
///
/// Returned by ``CtreeExpression/parent`` and ``CtreeStatement/parent``
/// when the active visitor recorded a parent for the queried handle.
/// Suitable as the source for HIR structuring passes that need to walk
/// from a sub-expression back up to its enclosing statement.
public struct CtreeItemInfo: Sendable {
    /// The parent item's opcode classification.
    public let type: CtreeItemType
    /// The parent item's associated database address (may be `BadAddress`).
    public let address: Address
    /// `true` when the parent is an expression, `false` when statement.
    public let isExpression: Bool
}

/// Non-owning handle to a ctree expression. Valid only during visitor callback.
public struct CtreeExpression: @unchecked Sendable {
    let handle: IdaxCtreeExprHandle

    init(_ handle: IdaxCtreeExprHandle) { self.handle = handle }

    public var type: CtreeItemType {
        get throws(IDAError) {
            let raw = try withOutput("ctree.expr.type", Int32(0)) { idax_ctree_expr_type(handle, $0) }
            return CtreeItemType(rawValue: raw) ?? .exprEmpty
        }
    }

    public var address: Address {
        get throws(IDAError) {
            try withOutput("ctree.expr.address", UInt64(0)) { idax_ctree_expr_address(handle, $0) }
        }
    }

    public var numberValue: UInt64 {
        get throws(IDAError) {
            try withOutput("ctree.expr.numberValue", UInt64(0)) { idax_ctree_expr_number_value(handle, $0) }
        }
    }

    public var stringValue: String {
        get throws(IDAError) {
            try withStringOutput("ctree.expr.stringValue") { idax_ctree_expr_string_value(handle, $0) }
        }
    }

    public var objectAddress: Address {
        get throws(IDAError) {
            try withOutput("ctree.expr.objectAddress", UInt64(0)) { idax_ctree_expr_object_address(handle, $0) }
        }
    }

    public var variableIndex: Int {
        get throws(IDAError) {
            let raw = try withOutput("ctree.expr.variableIndex", Int32(0)) { idax_ctree_expr_variable_index(handle, $0) }
            return Int(raw)
        }
    }

    public var operandCount: Int {
        get throws(IDAError) {
            let raw = try withOutput("ctree.expr.operandCount", Int32(0)) { idax_ctree_expr_operand_count(handle, $0) }
            return Int(raw)
        }
    }

    public var memberOffset: UInt32 {
        get throws(IDAError) {
            try withOutput("ctree.expr.memberOffset", UInt32(0)) { idax_ctree_expr_member_offset(handle, $0) }
        }
    }

    public func toString() throws(IDAError) -> String {
        try withStringOutput("ctree.expr.toString") { idax_ctree_expr_to_string(handle, $0) }
    }

    public func withLeft<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_expr_left(handle, &raw), "ctree.expr.left")
        return try body(CtreeExpression(raw!))
    }

    public func withRight<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_expr_right(handle, &raw), "ctree.expr.right")
        return try body(CtreeExpression(raw!))
    }

    public var callArgumentCount: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_ctree_expr_call_argument_count(handle, &out), "ctree.expr.callArgumentCount")
            return out
        }
    }

    public func withCallCallee<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_expr_call_callee(handle, &raw), "ctree.expr.callCallee")
        return try body(CtreeExpression(raw!))
    }

    public func withCallArgument<T>(at index: Int, _ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_expr_call_argument(handle, index, &raw), "ctree.expr.callArgument")
        return try body(CtreeExpression(raw!))
    }

    /// Direct parent of this expression, or `nil` if it is the ctree root
    /// or no parent was recorded by the active visitor.
    ///
    /// Only valid while inside the visitor callback that produced this
    /// handle — the parent map is cleared when the visitor returns.
    public var parent: CtreeItemInfo? {
        get throws(IDAError) {
            var raw = IdaxCtreeItemInfo()
            try checkStatus(idax_ctree_expr_parent(handle, &raw), "ctree.expr.parent")
            return makeCtreeItemInfo(raw)
        }
    }
}

/// Non-owning handle to a ctree statement. Valid only during visitor callback.
public struct CtreeStatement: @unchecked Sendable {
    let handle: IdaxCtreeStmtHandle

    init(_ handle: IdaxCtreeStmtHandle) { self.handle = handle }

    public var type: CtreeItemType {
        get throws(IDAError) {
            let raw = try withOutput("ctree.stmt.type", Int32(0)) { idax_ctree_stmt_type(handle, $0) }
            return CtreeItemType(rawValue: raw) ?? .stmtEmpty
        }
    }

    public var address: Address {
        get throws(IDAError) {
            try withOutput("ctree.stmt.address", UInt64(0)) { idax_ctree_stmt_address(handle, $0) }
        }
    }

    public var gotoTargetLabel: Int {
        get throws(IDAError) {
            let raw = try withOutput("ctree.stmt.gotoTargetLabel", Int32(0)) { idax_ctree_stmt_goto_target_label(handle, $0) }
            return Int(raw)
        }
    }

    public func withCondition<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_stmt_condition(handle, &raw), "ctree.stmt.condition")
        return try body(CtreeExpression(raw!))
    }

    public func withThenBranch<T>(_ body: (CtreeStatement) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeStmtHandle?
        try checkStatus(idax_ctree_stmt_then_branch(handle, &raw), "ctree.stmt.thenBranch")
        return try body(CtreeStatement(raw!))
    }

    public func withElseBranch<T>(_ body: (CtreeStatement) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeStmtHandle?
        try checkStatus(idax_ctree_stmt_else_branch(handle, &raw), "ctree.stmt.elseBranch")
        return try body(CtreeStatement(raw!))
    }

    public var hasElseBranch: Bool {
        get throws(IDAError) {
            let raw = try withOutput("ctree.stmt.hasElseBranch", Int32(0)) { idax_ctree_stmt_has_else_branch(handle, $0) }
            return raw != 0
        }
    }

    public func withBody<T>(_ body: (CtreeStatement) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeStmtHandle?
        try checkStatus(idax_ctree_stmt_body(handle, &raw), "ctree.stmt.body")
        return try body(CtreeStatement(raw!))
    }

    public func withInitExpression<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_stmt_init_expression(handle, &raw), "ctree.stmt.initExpression")
        return try body(CtreeExpression(raw!))
    }

    public func withStepExpression<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_stmt_step_expression(handle, &raw), "ctree.stmt.stepExpression")
        return try body(CtreeExpression(raw!))
    }

    public func withExpression<T>(_ body: (CtreeExpression) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeExprHandle?
        try checkStatus(idax_ctree_stmt_expression(handle, &raw), "ctree.stmt.expression")
        return try body(CtreeExpression(raw!))
    }

    public var blockSize: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_ctree_stmt_block_size(handle, &out), "ctree.stmt.blockSize")
            return out
        }
    }

    public func withBlockStatement<T>(at index: Int, _ body: (CtreeStatement) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeStmtHandle?
        try checkStatus(idax_ctree_stmt_block_statement(handle, index, &raw), "ctree.stmt.blockStatement")
        return try body(CtreeStatement(raw!))
    }

    public var switchCaseCount: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(idax_ctree_stmt_switch_case_count(handle, &out), "ctree.stmt.switchCaseCount")
            return out
        }
    }

    public func switchCaseValues(at index: Int) throws(IDAError) -> [UInt64] {
        var ptr: UnsafeMutablePointer<UInt64>?
        var count: Int = 0
        try checkStatus(
            idax_ctree_stmt_switch_case_values(handle, index, &ptr, &count),
            "ctree.stmt.switchCaseValues"
        )
        defer { idax_ctree_switch_case_values_free(ptr) }
        guard let ptr, count > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: count))
    }

    public func withSwitchCaseBody<T>(at index: Int, _ body: (CtreeStatement) throws(IDAError) -> T) throws(IDAError) -> T {
        var raw: IdaxCtreeStmtHandle?
        try checkStatus(idax_ctree_stmt_switch_case_body(handle, index, &raw), "ctree.stmt.switchCaseBody")
        return try body(CtreeStatement(raw!))
    }

    /// Direct parent of this statement, or `nil` if it is the ctree root
    /// or no parent was recorded by the active visitor.
    ///
    /// Only valid while inside the visitor callback that produced this
    /// handle — the parent map is cleared when the visitor returns.
    public var parent: CtreeItemInfo? {
        get throws(IDAError) {
            var raw = IdaxCtreeItemInfo()
            try checkStatus(idax_ctree_stmt_parent(handle, &raw), "ctree.stmt.parent")
            return makeCtreeItemInfo(raw)
        }
    }
}

private func makeCtreeItemInfo(_ raw: IdaxCtreeItemInfo) -> CtreeItemInfo? {
    guard raw.has_value != 0 else { return nil }
    return CtreeItemInfo(
        type: CtreeItemType(rawValue: Int32(raw.type)) ?? .exprEmpty,
        address: raw.address,
        isExpression: raw.is_expression != 0
    )
}

// MARK: - Microcode types

/// Item at a position in decompiler output.
public struct DecompilerItemAtPosition: Sendable {
    public let type: Int32
    public let address: Address
    public let itemIndex: Int32
    public let isExpression: Bool
}

/// Microcode operand descriptor.
public struct MicrocodeOperand: Sendable {
    public let kind: Int32
    public let registerID: Int32
    public let localVariableIndex: Int32
    public let localVariableOffset: Int64
    public let secondRegisterID: Int32
    public let globalAddress: UInt64
    public let stackOffset: Int64
    public let helperName: String
    public let blockIndex: Int32
    public let unsignedImmediate: UInt64
    public let signedImmediate: Int64
    public let byteWidth: Int32
    public let markUserDefinedType: Int32
}

/// Microcode instruction descriptor.
public struct MicrocodeInstruction: Sendable {
    public let opcode: Int32
    public let left: MicrocodeOperand
    public let right: MicrocodeOperand
    public let destination: MicrocodeOperand
    public let floatingPointInstruction: Bool
}

/// Placement policy for emitted microcode instructions.
///
/// Maps to `ida::decompiler::MicrocodeInsertPolicy`.
public enum MicrocodeInsertPolicy: Int32, Sendable {
    /// Append at block tail (default behavior).
    case append  = 0
    /// Insert at block beginning.
    case prepend = 1
    /// Insert immediately before current block tail.
    case replace = 2
}

/// Simplified typed value for microcode helper-call argument construction.
///
/// The `data` field is interpreted according to `kind`:
/// - Register → register ID
/// - LocalVariable → local-variable index
/// - GlobalAddress → address
/// - StackVariable → stack offset
/// - UnsignedImmediate → unsigned integer value
/// - SignedImmediate → signed integer value
public struct MicrocodeValue: Sendable {
    public var kind: Int32
    public var locationKind: Int32
    public var data: Int64
    public var byteWidth: Int32

    public init(kind: Int32 = 0, locationKind: Int32 = 0, data: Int64 = 0, byteWidth: Int32 = 0) {
        self.kind = kind
        self.locationKind = locationKind
        self.data = data
        self.byteWidth = byteWidth
    }
}

/// Opaque mutable context passed to microcode filter callbacks during decompilation.
///
/// Wraps a `ida::decompiler::MicrocodeContext*` pointer that is only valid for the
/// duration of the filter callback. Do not store this value beyond the callback.
public struct MicrocodeContext: @unchecked Sendable {
    let pointer: UnsafeMutableRawPointer

    init(_ pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    // MARK: - Read properties

    /// Instruction address currently being lifted.
    public var address: Address {
        get throws(IDAError) {
            try withOutput("microcodeContext.address", UInt64(0)) {
                idax_decompiler_microcode_context_address(pointer, $0)
            }
        }
    }

    /// Processor-specific instruction type code.
    public var instructionType: Int {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(
                idax_decompiler_microcode_context_instruction_type(pointer, &out),
                "microcodeContext.instructionType"
            )
            return Int(out)
        }
    }

    /// Number of microcode instructions currently present in the active block.
    public var blockInstructionCount: Int {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(
                idax_decompiler_microcode_context_block_instruction_count(pointer, &out),
                "microcodeContext.blockInstructionCount"
            )
            return Int(out)
        }
    }

    /// Whether this context has tracked at least one emitted instruction.
    public var hasLastEmittedInstruction: Bool {
        get throws(IDAError) {
            var out: Int32 = 0
            try checkStatus(
                idax_decompiler_microcode_context_has_last_emitted_instruction(pointer, &out),
                "microcodeContext.hasLastEmittedInstruction"
            )
            return out != 0
        }
    }

    // MARK: - Read methods

    /// Return true when an instruction exists at the specified block index.
    public func hasInstruction(at instructionIndex: Int) throws(IDAError) -> Bool {
        var out: Int32 = 0
        try checkStatus(
            idax_decompiler_microcode_context_has_instruction_at_index(pointer, Int32(instructionIndex), &out),
            "microcodeContext.hasInstruction"
        )
        return out != 0
    }

    /// Return the instruction currently being processed by the microcode lifter.
    public func currentInstruction() throws(IDAError) -> Instruction {
        var raw = IdaxInstruction()
        try checkStatus(
            idax_decompiler_microcode_context_instruction(pointer, &raw),
            "microcodeContext.currentInstruction"
        )
        defer { idax_instruction_free(&raw) }
        return Instruction(raw: raw)
    }

    /// Return the microcode instruction at the specified index in the active block.
    public func instruction(at instructionIndex: Int) throws(IDAError) -> MicrocodeInstruction {
        var raw = IdaxMicrocodeInstruction()
        try checkStatus(
            idax_decompiler_microcode_context_instruction_at_index(pointer, Int32(instructionIndex), &raw),
            "microcodeContext.instructionAtIndex"
        )
        defer { idax_microcode_instruction_free(&raw) }
        return makeMicrocodeInstruction(raw)
    }

    /// Return the most recently emitted microcode instruction tracked by this context.
    public func lastEmittedInstruction() throws(IDAError) -> MicrocodeInstruction {
        var raw = IdaxMicrocodeInstruction()
        try checkStatus(
            idax_decompiler_microcode_context_last_emitted_instruction(pointer, &raw),
            "microcodeContext.lastEmittedInstruction"
        )
        defer { idax_microcode_instruction_free(&raw) }
        return makeMicrocodeInstruction(raw)
    }

    // MARK: - Mutation methods

    /// Remove the most recently emitted instruction tracked by this context.
    public func removeLastEmittedInstruction() throws(IDAError) {
        try checkStatus(
            idax_microcode_context_remove_last_emitted(pointer),
            "microcodeContext.removeLastEmittedInstruction"
        )
    }

    /// Remove an instruction by its current zero-based index in the active block.
    public func removeInstruction(at instructionIndex: Int) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_remove_at_index(pointer, Int32(instructionIndex)),
            "microcodeContext.removeInstruction"
        )
    }

    /// Emit a no-op microcode instruction with optional placement policy.
    ///
    /// Pass `nil` for `policy` to use the default placement.
    public func emitNoop(policy: MicrocodeInsertPolicy? = nil) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_emit_noop(pointer, policy.map { Int32($0.rawValue) } ?? -1),
            "microcodeContext.emitNoop"
        )
    }

    /// Emit one microcode instruction with optional placement policy.
    public func emitInstruction(_ instruction: MicrocodeInstruction, policy: MicrocodeInsertPolicy? = nil) throws(IDAError) {
        var rawInstruction = makeRawMicrocodeInstruction(instruction)
        defer { idax_microcode_instruction_free(&rawInstruction) }
        try checkStatus(
            idax_microcode_context_emit_instruction(
                pointer,
                &rawInstruction,
                policy.map { Int32($0.rawValue) } ?? -1
            ),
            "microcodeContext.emitInstruction"
        )
    }

    /// Load an instruction operand into a temporary register. Returns the register ID.
    public func loadOperandRegister(operandIndex: Int) throws(IDAError) -> Int {
        var outRegister: Int32 = 0
        try checkStatus(
            idax_microcode_context_load_operand_register(pointer, Int32(operandIndex), &outRegister),
            "microcodeContext.loadOperandRegister"
        )
        return Int(outRegister)
    }

    /// Load the effective address of a memory operand into a temporary register. Returns the register ID.
    public func loadEffectiveAddressRegister(operandIndex: Int) throws(IDAError) -> Int {
        var outRegister: Int32 = 0
        try checkStatus(
            idax_microcode_context_load_effective_address_register(pointer, Int32(operandIndex), &outRegister),
            "microcodeContext.loadEffectiveAddressRegister"
        )
        return Int(outRegister)
    }

    /// Allocate a temporary register in the current microcode context. Returns the register ID.
    public func allocateTemporaryRegister(byteWidth: Int) throws(IDAError) -> Int {
        var outRegister: Int32 = 0
        try checkStatus(
            idax_microcode_context_allocate_temporary_register(pointer, Int32(byteWidth), &outRegister),
            "microcodeContext.allocateTemporaryRegister"
        )
        return Int(outRegister)
    }

    /// Store a register value back to an instruction operand.
    public func storeOperandRegister(
        operandIndex: Int,
        source sourceRegister: Int,
        byteWidth: Int,
        markUserDefinedType: Bool = false
    ) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_store_operand_register(
                pointer,
                Int32(operandIndex),
                Int32(sourceRegister),
                Int32(byteWidth),
                markUserDefinedType ? 1 : 0
            ),
            "microcodeContext.storeOperandRegister"
        )
    }

    /// Emit register-to-register move with optional UDT marking and placement policy.
    public func emitMoveRegister(
        source sourceRegister: Int,
        destination destinationRegister: Int,
        byteWidth: Int,
        markUserDefinedType: Bool = false,
        policy: MicrocodeInsertPolicy? = nil
    ) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_emit_move_register(
                pointer,
                Int32(sourceRegister),
                Int32(destinationRegister),
                Int32(byteWidth),
                markUserDefinedType ? 1 : 0,
                policy.map { Int32($0.rawValue) } ?? -1
            ),
            "microcodeContext.emitMoveRegister"
        )
    }

    /// Emit memory load (`m_ldx`) from selector+offset into destination register.
    public func emitLoadMemoryRegister(
        selectorRegister: Int,
        offsetRegister: Int,
        destinationRegister: Int,
        byteWidth: Int,
        offsetByteWidth: Int,
        markUserDefinedType: Bool = false,
        policy: MicrocodeInsertPolicy? = nil
    ) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_emit_load_memory_register(
                pointer,
                Int32(selectorRegister),
                Int32(offsetRegister),
                Int32(destinationRegister),
                Int32(byteWidth),
                Int32(offsetByteWidth),
                markUserDefinedType ? 1 : 0,
                policy.map { Int32($0.rawValue) } ?? -1
            ),
            "microcodeContext.emitLoadMemoryRegister"
        )
    }

    /// Emit memory store (`m_stx`) from source register into selector+offset.
    public func emitStoreMemoryRegister(
        sourceRegister: Int,
        selectorRegister: Int,
        offsetRegister: Int,
        byteWidth: Int,
        offsetByteWidth: Int,
        markUserDefinedType: Bool = false,
        policy: MicrocodeInsertPolicy? = nil
    ) throws(IDAError) {
        try checkStatus(
            idax_microcode_context_emit_store_memory_register(
                pointer,
                Int32(sourceRegister),
                Int32(selectorRegister),
                Int32(offsetRegister),
                Int32(byteWidth),
                Int32(offsetByteWidth),
                markUserDefinedType ? 1 : 0,
                policy.map { Int32($0.rawValue) } ?? -1
            ),
            "microcodeContext.emitStoreMemoryRegister"
        )
    }

    /// Emit helper call with no explicit arguments.
    public func emitHelperCall(name helperName: String) throws(IDAError) {
        try checkStatus(
            helperName.withCString { idax_microcode_context_emit_helper_call(pointer, $0) },
            "microcodeContext.emitHelperCall"
        )
    }

    /// Emit helper call with typed arguments and no return value capture.
    public func emitHelperCall(name helperName: String, args: [MicrocodeValue]) throws(IDAError) {
        let rawArgs = ContiguousArray(args.map { makeRawMicrocodeValue($0) })
        var status: Int32 = 0
        rawArgs.withUnsafeBufferPointer { argsBuffer in
            helperName.withCString { namePtr in
                status = idax_microcode_context_emit_helper_call_with_args(
                    pointer, namePtr, argsBuffer.baseAddress, rawArgs.count
                )
            }
        }
        try checkStatus(status, "microcodeContext.emitHelperCallWithArgs")
    }

    /// Emit helper call with typed arguments and move the return value to a register.
    public func emitHelperCall(
        name helperName: String,
        args: [MicrocodeValue],
        destinationRegister: Int,
        destinationByteWidth: Int,
        destinationUnsigned: Bool = true
    ) throws(IDAError) {
        let rawArgs = ContiguousArray(args.map { makeRawMicrocodeValue($0) })
        var status: Int32 = 0
        rawArgs.withUnsafeBufferPointer { argsBuffer in
            helperName.withCString { namePtr in
                status = idax_microcode_context_emit_helper_call_to_register(
                    pointer, namePtr,
                    argsBuffer.baseAddress, rawArgs.count,
                    Int32(destinationRegister),
                    Int32(destinationByteWidth),
                    destinationUnsigned ? 1 : 0
                )
            }
        }
        try checkStatus(status, "microcodeContext.emitHelperCallToRegister")
    }

    /// Emit helper call with typed arguments and store the return into an instruction operand.
    public func emitHelperCall(
        name helperName: String,
        args: [MicrocodeValue],
        destinationOperandIndex: Int,
        destinationByteWidth: Int,
        destinationUnsigned: Bool = true
    ) throws(IDAError) {
        let rawArgs = ContiguousArray(args.map { makeRawMicrocodeValue($0) })
        var status: Int32 = 0
        rawArgs.withUnsafeBufferPointer { argsBuffer in
            helperName.withCString { namePtr in
                status = idax_microcode_context_emit_helper_call_to_operand(
                    pointer, namePtr,
                    argsBuffer.baseAddress, rawArgs.count,
                    Int32(destinationOperandIndex),
                    Int32(destinationByteWidth),
                    destinationUnsigned ? 1 : 0
                )
            }
        }
        try checkStatus(status, "microcodeContext.emitHelperCallToOperand")
    }
}

/// Convert a C IdaxMicrocodeOperand to the Swift MicrocodeOperand value type.
private func makeMicrocodeOperand(_ op: IdaxMicrocodeOperand) -> MicrocodeOperand {
    MicrocodeOperand(
        kind: op.kind,
        registerID: op.register_id,
        localVariableIndex: op.local_variable_index,
        localVariableOffset: op.local_variable_offset,
        secondRegisterID: op.second_register_id,
        globalAddress: op.global_address,
        stackOffset: op.stack_offset,
        helperName: borrowCString(op.helper_name),
        blockIndex: op.block_index,
        unsignedImmediate: op.unsigned_immediate,
        signedImmediate: op.signed_immediate,
        byteWidth: op.byte_width,
        markUserDefinedType: op.mark_user_defined_type
    )
}

/// Convert a C IdaxMicrocodeInstruction to the Swift MicrocodeInstruction value type.
private func makeMicrocodeInstruction(_ raw: IdaxMicrocodeInstruction) -> MicrocodeInstruction {
    MicrocodeInstruction(
        opcode: raw.opcode,
        left: makeMicrocodeOperand(raw.left),
        right: makeMicrocodeOperand(raw.right),
        destination: makeMicrocodeOperand(raw.destination),
        floatingPointInstruction: raw.floating_point_instruction != 0
    )
}

/// Convert a Swift MicrocodeOperand to a C IdaxMicrocodeOperand for mutation calls.
///
/// The returned struct does NOT own any heap memory (helper_name / nested_instruction
/// are left nil) because the mutation path in the shim does not need them.
private func makeRawMicrocodeOperand(_ operand: MicrocodeOperand) -> IdaxMicrocodeOperand {
    var raw = IdaxMicrocodeOperand()
    raw.kind                     = operand.kind
    raw.register_id               = operand.registerID
    raw.local_variable_index      = operand.localVariableIndex
    raw.local_variable_offset     = operand.localVariableOffset
    raw.second_register_id        = operand.secondRegisterID
    raw.global_address            = operand.globalAddress
    raw.stack_offset              = operand.stackOffset
    raw.helper_name               = nil   // not round-tripped via mutation path
    raw.block_index               = operand.blockIndex
    raw.nested_instruction        = nil   // not round-tripped via mutation path
    raw.unsigned_immediate        = operand.unsignedImmediate
    raw.signed_immediate          = operand.signedImmediate
    raw.byte_width                = operand.byteWidth
    raw.mark_user_defined_type    = operand.markUserDefinedType
    return raw
}

/// Convert a Swift MicrocodeInstruction to a C IdaxMicrocodeInstruction for mutation calls.
///
/// The returned struct does NOT own heap memory; the caller must NOT call
/// `idax_microcode_instruction_free` on it (helper_name/nested_instruction are nil).
private func makeRawMicrocodeInstruction(_ instruction: MicrocodeInstruction) -> IdaxMicrocodeInstruction {
    var raw = IdaxMicrocodeInstruction()
    raw.opcode                    = instruction.opcode
    raw.left                      = makeRawMicrocodeOperand(instruction.left)
    raw.right                     = makeRawMicrocodeOperand(instruction.right)
    raw.destination               = makeRawMicrocodeOperand(instruction.destination)
    raw.floating_point_instruction = instruction.floatingPointInstruction ? 1 : 0
    return raw
}

/// Convert a Swift MicrocodeValue to a C IdaxMicrocodeValue.
private func makeRawMicrocodeValue(_ value: MicrocodeValue) -> IdaxMicrocodeValue {
    var raw = IdaxMicrocodeValue()
    raw.kind          = value.kind
    raw.location_kind = value.locationKind
    raw.data          = value.data
    raw.byte_width    = value.byteWidth
    return raw
}

// MARK: - Decompiler subscription

/// RAII decompiler event subscription token. Unsubscribes on deinit.
public struct DecompilerSubscription: ~Copyable, @unchecked Sendable {
    private let token: UInt64
    private let context: UnsafeMutableRawPointer

    init(token: UInt64, context: UnsafeMutableRawPointer) {
        self.token = token
        self.context = context
    }

    deinit {
        idax_decompiler_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
    }

    public consuming func cancel() {
        idax_decompiler_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
        discard self
    }
}

/// RAII microcode filter subscription token. Unregisters on deinit.
public struct MicrocodeFilterSubscription: ~Copyable, @unchecked Sendable {
    private let token: UInt64
    private let context: UnsafeMutableRawPointer

    init(token: UInt64, context: UnsafeMutableRawPointer) {
        self.token = token
        self.context = context
    }

    deinit {
        idax_decompiler_unregister_microcode_filter(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
    }

    public consuming func cancel() {
        idax_decompiler_unregister_microcode_filter(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
        discard self
    }
}

// MARK: - Decompiler callback boxes and trampolines

private final class MaturityChangedBox {
    let handler: (Address, Int) -> Void
    init(handler: @escaping (Address, Int) -> Void) { self.handler = handler }
}

private final class PseudocodeEventBox {
    let handler: (Address) -> Void
    init(handler: @escaping (Address) -> Void) { self.handler = handler }
}

private final class CursorPositionBox {
    let handler: (Address, Address) -> Void
    init(handler: @escaping (Address, Address) -> Void) { self.handler = handler }
}

private final class CreateHintBox {
    let handler: (Address, Address) -> (String, Int)?
    init(handler: @escaping (Address, Address) -> (String, Int)?) { self.handler = handler }
}

private final class MicrocodeFilterBox {
    let match: (Address, Int) -> Bool
    let apply: (MicrocodeContext) -> Bool
    init(
        match: @escaping (Address, Int) -> Bool,
        apply: @escaping (MicrocodeContext) -> Bool
    ) {
        self.match = match
        self.apply = apply
    }
}

private let maturityChangedTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerMaturityEvent>?) -> Void = { ctx, event in
    guard let ctx, let event else { return }
    let box = Unmanaged<MaturityChangedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(event.pointee.function_address, Int(event.pointee.new_maturity))
}

private let funcPrintedTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerPseudocodeEvent>?) -> Void = { ctx, event in
    guard let ctx, let event else { return }
    let box = Unmanaged<PseudocodeEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(event.pointee.function_address)
}

private let refreshPseudocodeTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerPseudocodeEvent>?) -> Void = { ctx, event in
    guard let ctx, let event else { return }
    let box = Unmanaged<PseudocodeEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(event.pointee.function_address)
}

private let cursorPositionTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerCursorPositionEvent>?) -> Void = { ctx, event in
    guard let ctx, let event else { return }
    let box = Unmanaged<CursorPositionBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(event.pointee.function_address, event.pointee.cursor_address)
}

private let createHintTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<IdaxDecompilerHintRequestEvent>?, UnsafeMutablePointer<UnsafePointer<CChar>?>?, UnsafeMutablePointer<Int32>?) -> Int32 = { ctx, event, outText, outLines in
    guard let ctx, let event else { return 0 }
    let box = Unmanaged<CreateHintBox>.fromOpaque(ctx).takeUnretainedValue()
    guard let result = box.handler(event.pointee.function_address, event.pointee.item_address) else {
        return 0
    }
    outText?.pointee = UnsafePointer(strdup(result.0))
    outLines?.pointee = Int32(result.1)
    return 1
}

private let microcodeMatchTrampoline: @convention(c) (UnsafeMutableRawPointer?, UInt64, Int32) -> Int32 = { ctx, address, itype in
    guard let ctx else { return 0 }
    let box = Unmanaged<MicrocodeFilterBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.match(address, Int(itype)) ? 1 : 0
}

private let microcodeApplyTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Int32 = { ctx, mctx in
    guard let ctx, let mctx else { return 0 }
    let box = Unmanaged<MicrocodeFilterBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.apply(MicrocodeContext(mctx)) ? 1 : 0
}

/// Decompiler facade.
///
/// Mirrors C++ `ida::decompiler`.
public enum Decompiler {
    public static func isAvailable() throws(IDAError) -> Bool {
        var out: Int32 = 0
        try checkStatus(idax_decompiler_available(&out), "decompiler.available")
        return out != 0
    }

    public static func decompile(at address: Address) throws(IDAError) -> DecompiledFunction {
        var handle: IdaxDecompiledHandle?
        try checkStatus(idax_decompiler_decompile(address, &handle), "decompiler.decompile")
        guard let handle else {
            throw IDAError(category: .internal, code: 0, message: "nil handle after successful call")
        }
        return DecompiledFunction(handle)
    }

    // MARK: - Raw cfunc operations

    public static func rawPseudocodeLines(_ cfuncHandle: UnsafeMutableRawPointer) throws(IDAError) -> [String] {
        var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
        var count: Int = 0
        try checkStatus(idax_decompiler_raw_pseudocode_lines(cfuncHandle, &ptr, &count), "decompiler.rawPseudocodeLines")
        defer { idax_decompiler_pseudocode_lines_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return (0..<count).map { i in
            if let s = ptr[i] { String(cString: s) } else { "" }
        }
    }

    public static func setPseudocodeLine(_ cfuncHandle: UnsafeMutableRawPointer, at lineIndex: Int, text: String) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_decompiler_set_pseudocode_line(cfuncHandle, lineIndex, $0) },
            "decompiler.setPseudocodeLine"
        )
    }

    public static func pseudocodeHeaderLineCount(_ cfuncHandle: UnsafeMutableRawPointer) throws(IDAError) -> Int {
        var out: Int32 = 0
        try checkStatus(idax_decompiler_pseudocode_header_line_count(cfuncHandle, &out), "decompiler.pseudocodeHeaderLineCount")
        return Int(out)
    }

    public static func itemAtPosition(_ cfuncHandle: UnsafeMutableRawPointer, taggedLine: String, charIndex: Int) throws(IDAError) -> DecompilerItemAtPosition {
        var raw = IdaxDecompilerItemAtPosition()
        try checkStatus(
            taggedLine.withCString { idax_decompiler_item_at_position(cfuncHandle, $0, Int32(charIndex), &raw) },
            "decompiler.itemAtPosition"
        )
        return DecompilerItemAtPosition(
            type: raw.type,
            address: raw.address,
            itemIndex: raw.item_index,
            isExpression: raw.is_expression != 0
        )
    }

    // MARK: - Dirty / view management

    public static func markDirty(at address: Address, closeViews: Bool = false) throws(IDAError) {
        try checkStatus(
            idax_decompiler_mark_dirty(address, closeViews ? 1 : 0),
            "decompiler.markDirty"
        )
    }

    public static func markDirtyWithCallers(at address: Address, closeViews: Bool = false) throws(IDAError) {
        try checkStatus(
            idax_decompiler_mark_dirty_with_callers(address, closeViews ? 1 : 0),
            "decompiler.markDirtyWithCallers"
        )
    }

    // MARK: - Item inspection

    public static func itemTypeName(_ itemType: Int) throws(IDAError) -> String {
        try withStringOutput("decompiler.itemTypeName") {
            idax_decompiler_item_type_name(Int32(itemType), $0)
        }
    }

    // MARK: - Event subscriptions

    public static func onMaturityChanged(
        _ handler: @escaping (Address, Int) -> Void
    ) throws(IDAError) -> DecompilerSubscription {
        let box = MaturityChangedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_on_maturity_changed(maturityChangedTrampoline, ctx, &token),
                "decompiler.onMaturityChanged"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DecompilerSubscription(token: token, context: ctx)
    }

    public static func onFuncPrinted(
        _ handler: @escaping (Address) -> Void
    ) throws(IDAError) -> DecompilerSubscription {
        let box = PseudocodeEventBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_on_func_printed(funcPrintedTrampoline, ctx, &token),
                "decompiler.onFuncPrinted"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DecompilerSubscription(token: token, context: ctx)
    }

    public static func onRefreshPseudocode(
        _ handler: @escaping (Address) -> Void
    ) throws(IDAError) -> DecompilerSubscription {
        let box = PseudocodeEventBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_on_refresh_pseudocode(refreshPseudocodeTrampoline, ctx, &token),
                "decompiler.onRefreshPseudocode"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DecompilerSubscription(token: token, context: ctx)
    }

    public static func onCursorPositionChanged(
        _ handler: @escaping (Address, Address) -> Void
    ) throws(IDAError) -> DecompilerSubscription {
        let box = CursorPositionBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_on_curpos_changed(cursorPositionTrampoline, ctx, &token),
                "decompiler.onCursorPositionChanged"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DecompilerSubscription(token: token, context: ctx)
    }

    public static func onCreateHint(
        _ handler: @escaping (Address, Address) -> (String, Int)?
    ) throws(IDAError) -> DecompilerSubscription {
        let box = CreateHintBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_on_create_hint(createHintTrampoline, ctx, &token),
                "decompiler.onCreateHint"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DecompilerSubscription(token: token, context: ctx)
    }

    // MARK: - Microcode filter

    public static func registerMicrocodeFilter(
        match: @escaping (Address, Int) -> Bool,
        apply: @escaping (MicrocodeContext) -> Bool
    ) throws(IDAError) -> MicrocodeFilterSubscription {
        let box = MicrocodeFilterBox(match: match, apply: apply)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_decompiler_register_microcode_filter(
                    microcodeMatchTrampoline,
                    microcodeApplyTrampoline,
                    ctx,
                    &token
                ),
                "decompiler.registerMicrocodeFilter"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return MicrocodeFilterSubscription(token: token, context: ctx)
    }

}

/// Lightweight handle to a decompiler pseudocode view.
public struct DecompilerView: Sendable {
    /// Address of the function being displayed.
    public let functionAddress: Address

    /// Get the decompiler view currently active in the UI.
    public static var current: DecompilerView {
        get throws(IDAError) {
            let address = try withOutput("decompiler.currentView", UInt64(0)) {
                idax_decompiler_current_view($0)
            }
            return DecompilerView(functionAddress: address)
        }
    }

    /// Get a decompiler view from an opaque host pointer (e.g., from plugin context).
    public static func fromHost(_ viewHost: UnsafeMutableRawPointer) throws(IDAError) -> DecompilerView {
        let address = try withOutput("decompiler.viewFromHost", UInt64(0)) {
            idax_decompiler_view_from_host(viewHost, $0)
        }
        return DecompilerView(functionAddress: address)
    }

    /// Get or create a decompiler view for a function.
    public static func forFunction(at address: Address) throws(IDAError) -> DecompilerView {
        let functionAddress = try withOutput("decompiler.viewForFunction", UInt64(0)) {
            idax_decompiler_view_for_function(address, $0)
        }
        return DecompilerView(functionAddress: functionAddress)
    }
}
