import IDAX

private final class LifecycleBox {
    var registration: Registration?
    var filtered = 0
    var handled = 0
}
private final class LifecycleCapture {
    let marker: Int
    init(_ marker: Int) { self.marker = marker }
}
func runLifecycleChecks() throws {
    let address = try Database.minAddress()
    let original = try Data.readByte(address: address)
    defer { try? Data.patchByte(address: address, value: original) }
    let route = LifecycleBox()
    route.registration = try Event.subscribe(
        to: .bytePatched,
        filter: { (change) throws(IDAError) -> Bool in
            guard change.address == address else { return false }
            route.filtered += 1
            try route.registration?.close()
            route.registration = nil
            return true
        }, handler: { (_) throws(IDAError) -> Void in route.handled += 1 })
    try Data.patchByte(address: address, value: original ^ 1)
    try expect(route.filtered == 1, "Database event filter was not dispatched")
    try expect(route.handled == 0, "Self-unsubscribed filter still dispatched its handler")
    try Data.patchByte(address: address, value: original)
    try expect(route.filtered == 1, "Closed subscription dispatched a later event")

    var shortcutCalls = 0
    let shortcut = try Plugin.registerShortcut("Ctrl-Alt-F9") { () throws(IDAError) -> Void in
        shortcutCalls += 1
    }
    try expect(try shortcut.isActive, "Registered shortcut is inactive")
    try expect(shortcut.shortcut == "Ctrl-Alt-F9", "Shortcut metadata changed")
    var shortcutActivated = false
    do throws(IDAError) {
        try shortcut.activate()
        shortcutActivated = true
    } catch {
        guard error.category == .sdkFailure,
            error.code == 0,
            error.message == "process_ui_action failed",
            error.context.hasPrefix("idax:hotkey:"),
            shortcutCalls == 0
        else { throw error }
        print("UNAVAILABLE: shortcut dispatch in this IDAlib host (canonical process_ui_action failure)")
    }
    if shortcutActivated {
        try expect(shortcutCalls == 1, "Shortcut activation did not dispatch its Swift callback")
    }
    try shortcut.close()
    try shortcut.close()
    try expect(try !shortcut.isActive && shortcut.shortcut.isEmpty, "Closed shortcut retained active state")

    let functionType = try TypeInfo.function(returnType: TypeInfo.int32(), arguments: [TypeInfo.int64()])
    let executor = LifecycleBox()
    var capture: LifecycleCapture? = LifecycleCapture(42)
    weak var weakCapture = capture
    var capturedRequest: Debugger.AppcallRequest?
    var preventedClose = false
    var preventedTypeClose = false
    executor.registration = try Debugger.registerExecutor(
        name: "swift.lifecycle.executor",
        execute: { [owned = capture!] (request) throws(IDAError) -> Debugger.AppcallResult in
            capturedRequest = request
            do throws(IDAError) { try Database.close() } catch {
                preventedClose = error.category == .conflict
            }
            do throws(IDAError) { try functionType.close() } catch {
                preventedTypeClose = error.category == .conflict
            }
            try executor.registration?.close()
            executor.registration = nil
            guard owned.marker == 42 else {
                throw IDAError(category: .internalError, message: "Executor capture lifetime ended early")
            }
            return .init(returnValue: .unsignedInteger(.max), diagnostics: "UTF-8: β")
        })
    capture = nil
    try expect(weakCapture != nil, "Registered executor did not retain its Swift callback")
    var rejected: LifecycleCapture? = LifecycleCapture(7)
    weak var weakRejected = rejected
    do {
        _ = try Debugger.registerExecutor(
            name: "swift.lifecycle.executor",
            execute: { [owned = rejected!] (_) throws(IDAError) -> Debugger.AppcallResult in
                .init(returnValue: .signedInteger(Int64(owned.marker)))
            })
        throw Failure(description: "Duplicate executor registration succeeded")
    } catch let error as IDAError {
        try expect(error.category == .conflict, "Duplicate executor returned the wrong error")
    }
    rejected = nil
    try expect(weakRejected == nil, "Failed executor registration leaked its Swift callback")
    let arguments: [Debugger.AppcallValue] = [
        .signedInteger(.min), .unsignedInteger(.max), .floatingPoint(3.5), .string("βeta"), .address(address),
        .boolean(true),
    ]
    let options = Debugger.AppcallOptions(
        threadID: 123, manual: true, includeDebugEvent: true, timeoutMilliseconds: 250)
    let result = try Debugger.appcall(
        .init(functionAddress: address, functionType: functionType, arguments: arguments, options: options),
        executor: "swift.lifecycle.executor")
    try expect(
        result.returnValue == .unsignedInteger(.max) && result.diagnostics == "UTF-8: β",
        "Executor result lost value or diagnostics")
    try expect(capturedRequest?.arguments == arguments, "Appcall request did not copy every value kind")
    try expect(
        capturedRequest?.options.threadID == 123 && capturedRequest?.options.timeoutMilliseconds == 250
            && capturedRequest?.options.manual == true && capturedRequest?.options.includeDebugEvent == true,
        "Appcall options did not round-trip")
    try expect(preventedClose, "Executor callback permitted database close while native types were borrowed")
    try expect(preventedTypeClose, "Executor callback permitted close of its borrowed function type")
    try expect(weakCapture == nil, "Self-unregistered executor retained its callback after invocation")
    try expect(
        try capturedRequest?.functionType.copy() != nil,
        "Captured appcall function type expired after the native callback")

    let graph = try Graph()
    let first = try graph.addNode()
    let second = try graph.addNode()
    let third = try graph.addNode()
    try graph.addEdge(from: first, to: second)
    try graph.addEdge(from: second, to: third)
    try expect(try graph.pathExists(from: first, to: third), "Graph path traversal failed")
    try expect(try graph.successors(of: first) == [second], "Graph successor ownership is incorrect")
    try graph.replaceEdge(.init(source: second, target: third), with: .init(source: second, target: first))
    try expect(try !graph.pathExists(from: first, to: third), "Graph edge replacement retained the old edge")
    try expect(try graph.edges.count == 2, "Graph edge snapshot count is incorrect")
    graph.close()
    graph.close()
    try expectConflict { _ = try graph.addNode() }
    print(
        "PASS: Swift callback ownership, self-unsubscribe, appcall values, reentrant close guard, and graph lifecycle"
    )
}
