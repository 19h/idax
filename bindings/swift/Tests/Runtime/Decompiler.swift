import Foundation
import IDAX

private func decompilerCheck(_ condition: @autoclosure () throws(IDAError) -> Bool, _ message: String)
    throws(IDAError)
{
    if try !condition() {
        throw IDAError(category: .internalError, message: message, context: "Swift decompiler runtime test")
    }
}
private func decompilerConflict(_ body: () throws(IDAError) -> Void) throws(IDAError) {
    do throws(IDAError) {
        try body()
        throw IDAError(category: .internalError, message: "Expected decompiler lifetime conflict")
    } catch { try decompilerCheck(error.category == .conflict, "Wrong lifetime error: \(error)") }
}

private final class DecompilerTreeProbe: CtreeVisitor {
    let function: Decompiler.Function
    let session: Decompiler.Session
    var expressions = 0, statements = 0, leftExpressions = 0, leftStatements = 0, children = 0
    var escapedExpression: Decompiler.Expression?
    var escapedStatement: Decompiler.Statement?
    var escapedChild: Decompiler.Expression?
    var copiedParents: [Decompiler.CtreeItem] = []
    var copiedItem: Decompiler.CtreeItem?
    init(function: Decompiler.Function, session: Decompiler.Session) {
        self.function = function
        self.session = session
    }
    private func check(_ child: Decompiler.Expression, parent: Decompiler.CtreeItem) throws(IDAError) {
        try decompilerCheck(try child.parent() == parent, "Navigated expression lost its direct parent")
        let parents = try child.parents()
        try decompilerCheck(parents.last == parent, "Navigated expression ancestor chain lost its parent")
        copiedParents = parents
        escapedChild = child
        children += 1
    }
    private func check(_ child: Decompiler.Statement, parent: Decompiler.CtreeItem) throws(IDAError) {
        try decompilerCheck(try child.parent() == parent, "Navigated statement lost its direct parent")
        try decompilerCheck(
            try child.parents().last == parent, "Navigated statement ancestor chain lost its parent")
        children += 1
    }
    func visitExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction {
        if let escapedExpression {
            try decompilerConflict { () throws(IDAError) in _ = try escapedExpression.address() }
        }
        if let escapedChild {
            try decompilerConflict { () throws(IDAError) in _ = try escapedChild.address() }
        }
        if expressions == 0 {
            try decompilerConflict { () throws(IDAError) in try function.close() }
            try decompilerConflict { () throws(IDAError) in try Database.close() }
            try decompilerConflict { () throws(IDAError) in try session.close() }
        }
        expressions += 1
        escapedExpression = expression
        let parent = try expression.snapshot()
        copiedItem = parent
        _ = try expression.typeDeclaration()
        _ = try expression.typeByteWidth()
        _ = try expression.text()
        for child in [try? expression.left(), try? expression.right(), try? expression.third()] {
            if let child { try check(child, parent: parent) }
        }
        if parent.type == .exprCall {
            try check(expression.callCallee(), parent: parent)
            for index in 0..<(try expression.callArgumentCount()) {
                try check(expression.callArgument(at: index), parent: parent)
            }
        }
        if try expression.operandCount() == 0 {
            try decompilerCheck(
                (try? expression.left()) == nil, "Leaf expression exposes an inactive operand")
        }
        return .continue
    }
    func visitStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction {
        if let escapedStatement {
            try decompilerConflict { () throws(IDAError) in _ = try escapedStatement.address() }
        }
        statements += 1
        escapedStatement = statement
        let parent = try statement.snapshot()
        for child in [
            try? statement.condition(), try? statement.initExpression(), try? statement.stepExpression(),
            try? statement.expression(),
        ] {
            if let child { try check(child, parent: parent) }
        }
        for child in [try? statement.thenBranch(), try? statement.elseBranch(), try? statement.body()] {
            if let child { try check(child, parent: parent) }
        }
        if parent.type == .stmtBlock {
            let count = try statement.blockSize()
            for index in 0..<count { try check(statement.blockStatement(at: index), parent: parent) }
            try decompilerCheck(
                (try? statement.blockStatement(at: count)) == nil, "Block accepted an out-of-range child")
        }
        if parent.type == .stmtSwitch {
            let count = try statement.switchCaseCount()
            for index in 0..<count {
                _ = try statement.switchCaseValues(at: index)
                try check(statement.switchCaseBody(at: index), parent: parent)
            }
        }
        return .continue
    }
    func leaveExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction {
        _ = try expression.address()
        leftExpressions += 1
        return .continue
    }
    func leaveStatement(_ statement: Decompiler.Statement) throws(IDAError) -> Decompiler.VisitAction {
        _ = try statement.address()
        leftStatements += 1
        return .continue
    }
}
private final class ThrowingDecompilerVisitor: CtreeVisitor {
    let failure: IDAError
    init(_ failure: IDAError) { self.failure = failure }
    func visitExpression(_ expression: Decompiler.Expression) throws(IDAError) -> Decompiler.VisitAction {
        throw failure
    }
}
private struct DecompilerGraphCounts {
    var floating = 0, stack = 0, calls = 0, switches = 0
    mutating func instruction(_ value: Decompiler.MicrocodeInstruction, indexes: Set<Int32>) throws {
        try operand(value.left, indexes: indexes)
        try operand(value.right, indexes: indexes)
        try operand(value.destination, indexes: indexes)
    }
    mutating func operand(_ value: Decompiler.MicrocodeOperand, indexes: Set<Int32>) throws {
        try expect(
            value.valueNumber == nil || value.valueNumber != 0, "Graph stored reserved zero value number")
        if value.kind == .floatingPointConstant && value.floatingPointConstant == 65536.0 { floating += 1 }
        if value.kind == .callArguments {
            calls += 1
            try expect(
                value.callArgumentProperties.count == value.callArguments.count,
                "Call argument properties are misaligned")
            for range in value.callReturnRegisters {
                try expect(
                    range.registerId >= 0 && range.byteWidth > 0, "Call return register range is invalid")
            }
        }
        if value.kind == .switchCases {
            switches += 1
            for item in value.switchCases {
                try expect(indexes.contains(item.targetBlock), "Switch case targets a missing block")
            }
            if let target = value.switchDefaultTarget {
                try expect(indexes.contains(target), "Switch default targets a missing block")
            }
        }
        if let nested = value.nestedInstruction { try instruction(nested, indexes: indexes) }
        if let referenced = value.referencedOperand { try operand(referenced, indexes: indexes) }
        for argument in value.callArguments { try operand(argument, indexes: indexes) }
        for result in value.callReturnOperands { try operand(result, indexes: indexes) }
    }
    mutating func graph(_ graph: Decompiler.MicrocodeFunction) throws {
        try expect(!graph.blocks.isEmpty, "Generated graph has no blocks")
        try expect(
            graph.stackFrameSize >= 0 && graph.localStackSize >= 0 && graph.savedRegisterSize >= 0,
            "Graph frame sizes have invalid signs")
        if let index = graph.returnVariableIndex {
            try expect(
                graph.localVariables.indices.contains(index), "Return variable index exceeds copied locals")
        }
        let indexes = Set(graph.blocks.map(\.index))
        try expect(indexes.count == graph.blocks.count, "Graph block indexes are not unique")
        for block in graph.blocks {
            for index in block.predecessors + block.successors {
                try expect(indexes.contains(index), "Graph edge targets a missing block")
            }
            for instruction in block.instructions { try self.instruction(instruction, indexes: indexes) }
        }
        for variable in graph.localVariables {
            if variable.storage == .stack {
                stack += 1
                try expect(variable.stackOffset >= 0, "Stack variable offset is absent")
                try expect(
                    variable.location?.kind == .stackOffset
                        && variable.location?.stackOffset == variable.stackOffset,
                    "Stack variable lost its location descriptor")
            } else {
                try expect(variable.stackOffset == -1, "Non-stack variable uses a fabricated stack offset")
            }
        }
    }
}
private final class DecompilerEventCapture {}
private final class DecompilerEventState {
    var selfClosing: Decompiler.Subscription?
    var dropping: Decompiler.Subscription?
    var escaped: Decompiler.PseudocodeEvent?
    var copiedLines: [String] = []
    var copiedItem: Decompiler.ItemAtPosition?
    var maturity: [Decompiler.MaturityEvent] = []
    var prints = 0, selfClosed = 0, dropped = 0
}
private func runDecompilerEventChecks(_ address: Address, session: Decompiler.Session) throws {
    let state = DecompilerEventState()
    let maturity = try Decompiler.onMaturityChanged { (event) throws(IDAError) in
        if event.functionAddress == address { state.maturity.append(event) }
    }
    let printed = try Decompiler.onFunctionPrinted { (event) throws(IDAError) in
        guard event.functionAddress == address else { return }
        state.prints += 1
        state.escaped = event
        state.copiedLines = try event.rawLines()
        try decompilerCheck(try event.headerLineCount() >= 0, "Printed event lost its header count")
        if let line = state.copiedLines.first { try event.setLine(at: 0, taggedText: line) }
        for line in state.copiedLines.prefix(12) where state.copiedItem == nil {
            for column in 0..<min(64, line.utf8.count) {
                if let item = try? event.item(inTaggedLine: line, atColumn: Int32(column)),
                    item.itemIndex >= 0
                {
                    state.copiedItem = item
                    break
                }
            }
        }
        try decompilerConflict { () throws(IDAError) in try Database.close() }
        try decompilerConflict { () throws(IDAError) in try session.close() }
    }
    let failure = IDAError(
        category: .validation, code: 197, message: "Observer β", context: "Decompiler.printed")
    let failing = try Decompiler.onFunctionPrinted { (event) throws(IDAError) in
        if event.functionAddress == address { throw failure }
    }
    var explicitCapture: DecompilerEventCapture? = DecompilerEventCapture()
    weak var weakExplicit = explicitCapture
    state.selfClosing = try Decompiler.onFunctionPrinted {
        [owned = explicitCapture!] (event) throws(IDAError) in
        guard event.functionAddress == address else { return }
        _ = owned
        state.selfClosed += 1
        try state.selfClosing?.close()
        state.selfClosing = nil
    }
    explicitCapture = nil
    var droppingCapture: DecompilerEventCapture? = DecompilerEventCapture()
    weak var weakDropping = droppingCapture
    state.dropping = try Decompiler.onFunctionPrinted { [owned = droppingCapture!] (event) throws(IDAError) in
        guard event.functionAddress == address else { return }
        _ = owned
        state.dropped += 1
        state.dropping = nil
    }
    droppingCapture = nil
    try Decompiler.markDirty(functionAddress: address, closeViews: false)
    let function = try Decompiler.decompile(address)
    _ = try function.pseudocode()
    try expect(
        state.prints > 0 && !state.maturity.isEmpty,
        "Decompiler printed or maturity callback did not dispatch")
    try expect(
        state.selfClosed == 1 && state.dropped == 1, "Decompiler callback close/ARC did not execute once")
    try expect(!state.copiedLines.isEmpty, "Printed pseudocode event did not copy lines")
    try expect(state.copiedItem != nil, "Printed event could not resolve a tagged ctree item")
    try expect(
        try printed.lastError() == nil && maturity.lastError() == nil,
        "Successful decompiler observer recorded a callback failure")
    try expect(try failing.lastError() == failure, "Observer diagnostic lost structured fields")
    try expect(
        try failing.lastError(clear: true) == failure, "Observer diagnostic clear returned the wrong value")
    try expect(try failing.lastError() == nil, "Observer diagnostic was not cleared")
    try expectConflict { _ = try state.escaped?.rawLines() }
    try function.close()
    try expectConflict { try session.close() }
    try maturity.close()
    try printed.close()
    try failing.close()
    try printed.close()
    _ = try Database.addressBitness()
    try expect(
        weakExplicit == nil && weakDropping == nil, "Decompiler observers retained captures after close/ARC")
    try expectConflict { _ = try printed.lastError() }
}

func runDecompilerChecks() throws {
    guard try Decompiler.available() else {
        if ProcessInfo.processInfo.environment["IDAX_SWIFT_REQUIRE_DECOMPILER"] == "1" {
            throw Failure(description: "Required decompiler runtime coverage has no available decompiler")
        }
        print("SKIP: Swift decompiler runtime checks require an available decompiler")
        return
    }
    let session = try Decompiler.initialize()
    try expect(try session.isValid(), "Explicit decompiler session is not valid")
    var selected: [Functions.Function] = []
    for index in 0..<(try Functions.count()) {
        let function = try Functions.byIndex(index: index)
        if function.name.contains("idax_metadata_") { selected.append(function) }
    }
    let semanticFixture = !selected.isEmpty
    if !semanticFixture {
        for index in 0..<min(32, try Functions.count()) {
            let candidate = try Functions.byIndex(index: index)
            if let function = try? Decompiler.decompile(candidate.start) {
                try function.close()
                selected = [candidate]
                break
            }
        }
    }
    try expect(!selected.isEmpty, "No function is available for the decompiler runtime test")
    var counts = DecompilerGraphCounts()
    var retainedGraphs: [Decompiler.MicrocodeFunction] = []
    var children = 0
    var settingsTested = false
    for source in selected {
        let function = try Decompiler.decompile(source.start)
        try expect(try function.entryAddress() == source.start, "Decompiled function entry changed")
        try expect(
            try !function.pseudocode().isEmpty && !function.lines().isEmpty, "Pseudocode value is empty")
        try expect(try !function.declaration().isEmpty, "Function declaration is empty")
        let rawLines = try function.rawLines()
        try expect(!rawLines.isEmpty, "Tagged pseudocode lines are empty")
        try function.setRawLine(at: 0, taggedText: rawLines[0])
        try expect(try function.rawLines()[0] == rawLines[0], "Tagged line round-trip changed its bytes")
        let mappings = try function.addressMap()
        let grouped = Dictionary(grouping: mappings, by: \.lineNumber)
        for (line, entries) in grouped {
            try expect(
                line >= 0 && Int(line) < rawLines.count, "Address map contains an invalid pseudocode line")
            try expect(entries.allSatisfy { $0.address != badAddress }, "Address map contains BadAddress")
            let resolved = try function.address(forLine: line)
            try expect(
                entries.contains(where: { $0.address == resolved }),
                "Resolved line address is absent from its address-map entries")
        }
        for line in rawLines.indices {
            let address = try function.address(forLine: Int32(line))
            if address != badAddress {
                try expect(
                    grouped[Int32(line)]?.contains(where: { $0.address == address }) == true,
                    "Line resolver returned an address outside its mapped set")
            }
        }
        _ = try function.microcodeLines()
        _ = try function.microcode()
        let variables = try function.variables()
        try expect(try function.variableCount() == variables.count, "Copied variable count is incorrect")
        for variable in variables {
            try expect(
                try function.variable(at: variable.index) == variable,
                "Single-variable snapshot differs from array snapshot")
        }
        try expectConflict { try session.close() }
        let visitor = DecompilerTreeProbe(function: function, session: session)
        _ = try function.visit(visitor, options: .init(postOrder: true, trackParents: true))
        try expect(
            visitor.expressions > 0 && visitor.statements > 0, "Pre-order visitor methods did not dispatch")
        try expect(
            visitor.leftExpressions > 0 && visitor.leftStatements > 0,
            "Post-order visitor methods did not dispatch")
        children += visitor.children
        try expectConflict { _ = try visitor.escapedExpression?.address() }
        try expectConflict { _ = try visitor.escapedStatement?.address() }
        if let child = visitor.escapedChild { try expectConflict { _ = try child.address() } }
        let summary = visitor.copiedItem
        let copiedParents = visitor.copiedParents
        let thrown = IDAError(category: .validation, code: 73, message: "Visitor β", context: "Swift.ctree")
        do {
            _ = try function.visitExpressions(ThrowingDecompilerVisitor(thrown))
            throw Failure(description: "Throwing ctree visitor did not fail")
        } catch let error as IDAError {
            try expect(error == thrown, "Visitor failure lost category/code/message/context")
        }
        var stopped = 0
        _ = try function.forEachExpression { (_) throws(IDAError) in
            stopped += 1
            return .stop
        }
        try expect(stopped == 1, "Stop action visited another expression")
        let snapshot = try function.captureUserLvarSettings()
        let copy = try snapshot.copy()
        try expect(
            try snapshot.savedVariableCount() == copy.savedVariableCount(), "Lvar snapshot copy lost entries")
        if !settingsTested, let variable = variables.first(where: { $0.width == 4 && !$0.name.isEmpty }) {
            let view = try Decompiler.view(forFunction: source.start)
            try expect(
                try view.functionAddress() == source.start && view.functionName() == source.name,
                "Decompiler view identity is incorrect")
            try view.setVariableComment(at: variable.index, comment: "Swift variable β")
            try view.retypeVariable(at: variable.index, type: TypeInfo.int32())
            try view.renameVariable(from: variable.name, to: "swift_test_variable")
            let settings = try Decompiler.savedUserLvarSettings(forFunction: source.start)
            try expect(
                settings.contains(where: { $0.name == "swift_test_variable" }),
                "Saved lvar setting lost its name")
            try expect(
                settings.contains(where: { $0.comment == "Swift variable β" }),
                "Saved lvar setting lost its comment")
            try Decompiler.applyUserLvarSettings(settings, toFunction: source.start)
            try view.restoreUserLvarSettings(copy)
            try view.refresh()
            try view.setComment(at: source.start, text: "Swift pseudocode β")
            try expect(
                try view.comment(at: source.start) == "Swift pseudocode β",
                "Pseudocode comment did not round-trip")
            try view.saveComments()
            try expect(
                try view.comments().contains(where: { $0.text == "Swift pseudocode β" }),
                "Pseudocode comment snapshot omitted its entry")
            try view.setComment(at: source.start, text: "")
            try view.saveComments()
            _ = try Decompiler.collectReferencedTypes(inFunction: source.start)
            try view.close()
            try view.close()
            try expectConflict { _ = try view.functionAddress() }
            settingsTested = true
        }
        try function.restoreUserLvarSettings(snapshot)
        try function.close()
        try function.close()
        try expectConflict { _ = try function.pseudocode() }
        try expect(
            visitor.copiedItem == summary && visitor.copiedParents == copiedParents,
            "Copied ctree summaries changed after function close")
        try expectConflict { try session.close() }
        try snapshot.close()
        try copy.close()
        for maturity in Decompiler.MicrocodeMaturity.allCases {
            let graph = try Decompiler.generateMicrocode(source.start, options: .init(maturity: maturity))
            try expect(
                graph.entryAddress == source.start && graph.maturity.rawValue >= maturity.rawValue,
                "Graph entry or maturity is incorrect")
            try counts.graph(graph)
            retainedGraphs.append(graph)
        }
    }
    if semanticFixture {
        try expect(
            selected.count >= 5 && children > 0 && settingsTested,
            "Semantic fixture navigation/settings coverage is absent")
        try expect(
            counts.floating > 0 && counts.stack > 0 && counts.calls > 0,
            "Semantic graph lacks populated floating/stack/call metadata")
        if try Database.processorName() == "metapc" {
            try expect(counts.switches > 0, "x86 semantic graph lacks switch descriptors")
        }
    }
    try runDecompilerEventChecks(selected[0].start, session: session)
    try session.close()
    try session.close()
    try expectConflict { _ = try session.isValid() }
    var arcSession: Decompiler.Session? = try Decompiler.initialize()
    let dependent = try Decompiler.decompile(selected[0].start)
    let dependentSnapshot = try dependent.captureUserLvarSettings()
    try expect(try arcSession?.isValid() == true, "ARC decompiler session was invalid")
    arcSession = nil
    try expect(try !dependent.pseudocode().isEmpty, "ARC session release invalidated a dependent function")
    _ = try dependentSnapshot.savedVariableCount()
    try dependent.close()
    _ = try dependentSnapshot.savedVariableCount()
    try dependentSnapshot.close()
    var copiedCounts = DecompilerGraphCounts()
    for graph in retainedGraphs { try copiedCounts.graph(graph) }
    try expect(
        copiedCounts.floating == counts.floating && copiedCounts.calls == counts.calls,
        "Copied graphs changed after native sessions were released")
    print(
        "PASS: Swift decompiler Function/View/settings, four ctree callbacks, navigation, structured errors, events, session dependencies, and \(retainedGraphs.count) graphs; metadata float=\(counts.floating), stack=\(counts.stack), calls=\(counts.calls), switch=\(counts.switches), children=\(children)"
    )
}
