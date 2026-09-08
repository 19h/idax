import Foundation
import IDAX
import CIDAX
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

struct Failure: Error, CustomStringConvertible { let description: String }
func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    if try !condition() { throw Failure(description: message) }
}
func expectConflict(_ body: () throws -> Void) throws {
    do { try body(); throw Failure(description: "Expected a resource or thread conflict") }
    catch let error as IDAError { try expect(error.category == .conflict, "Unexpected error: \(error)") }
}

#if canImport(Darwin)
typealias WorkerFunction = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer?
#else
typealias WorkerFunction = @convention(c) (UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer?
#endif
func worker(_ body: @escaping WorkerFunction, context: UnsafeMutableRawPointer? = nil) throws {
    #if canImport(Darwin)
    var thread: pthread_t?
    #else
    var thread = pthread_t()
    #endif
    // The no-context callbacks do not dereference this non-null marker.
    try expect(pthread_create(&thread, nil, body, context ?? UnsafeMutableRawPointer(bitPattern: 1)) == 0, "Cannot create test worker")
    var result: UnsafeMutableRawPointer?
    #if canImport(Darwin)
    try expect(pthread_join(thread!, &result) == 0, "Cannot join test worker")
    #else
    try expect(pthread_join(thread, &result) == 0, "Cannot join test worker")
    #endif
    try expect(result == nil, "Runtime accepted an operation on the wrong thread")
}

struct ReleaseRecord {
    let index: Int
    let count: UnsafeMutablePointer<Int>
    let order: UnsafeMutablePointer<Int>
}
func recordRelease(_ raw: UnsafeMutableRawPointer?) {
    guard let raw else { return }
    let pointer = raw.assumingMemoryBound(to: ReleaseRecord.self)
    let value = pointer.pointee
    value.order[value.count.pointee] = value.index
    value.count.pointee += 1
    pointer.deinitialize(count: 1)
    pointer.deallocate()
}
func adoptRecord(index: Int, count: UnsafeMutablePointer<Int>, order: UnsafeMutablePointer<Int>) throws -> UnsafeMutableRawPointer {
    let pointer = UnsafeMutablePointer<ReleaseRecord>.allocate(capacity: 1)
    pointer.initialize(to: .init(index: index, count: count, order: order))
    var output: UnsafeMutableRawPointer?
    var error = IdaxSwiftError()
    defer { idax_swift_error_free(&error) }
    try expect(idax_swift_resource_adopt(pointer, recordRelease, 1, &output, &error) == 0, "Resource adoption failed")
    guard let output else { throw Failure(description: "Resource holder is null") }
    return output
}

func run() throws {
    try worker { _ in
        do { try Runtime.initialize(); return UnsafeMutableRawPointer(bitPattern: 1) }
        catch { return (error as? IDAError)?.category == .conflict ? nil : UnsafeMutableRawPointer(bitPattern: 2) }
    }
    try expect(!Runtime.isInitialized, "Rejected worker initialization changed runtime state")
    try Runtime.initialize(options: .init(quiet: true, pluginPolicy: .init(disableUserPlugins: true)))
    try expect(Runtime.isInitialized, "Runtime did not initialize")
    try expectConflict { try Runtime.initialize() }
    try worker { _ in
        do { _ = try Database.addressBitness(); return UnsafeMutableRawPointer(bitPattern: 1) }
        catch { return (error as? IDAError)?.category == .conflict ? nil : UnsafeMutableRawPointer(bitPattern: 2) }
    }

    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("idax-swift-runtime-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let source = CommandLine.arguments.dropFirst().first ?? "/usr/bin/true"
    let fixture = temporary.appendingPathComponent("fixture")
    try FileManager.default.copyItem(atPath: source, toPath: fixture.path)
    try Database.open(path: fixture.path)
    var databaseOpen = true
    defer { if databaseOpen { try? Database.close() } }
    try runLifecycleChecks()
    try runDataChecks()
    try runValueDomainChecks()
    try runTypeChecks()
    try runMicrocodeChecks()
    try runDecompilerChecks()
    try expect(try Database.addressBitness() > 0, "Database metadata is unavailable")
    try expectConflict { try Database.open(path: fixture.path) }

    let type = try TypeInfo.int32()
    let copy = try type.copy()
    try expect(try type.size() == 4 && copy.size() == 4, "Type values lost their native size")
    let scriptString = try Script.Value(string: "a\0β")
    try expect(try scriptString.asString() == "a\0β", "IDC string lost embedded NUL or UTF-8")
    let scriptObject = try Script.Value.object()
    try scriptObject.setAttribute("value", value: scriptString)
    try expect(try scriptObject.attribute("value").asString() == "a\0β", "IDC attribute copy is incorrect")
    let evaluation = try Script.evaluateIDC("6 * 7")
    try expect(evaluation.succeeded && (try evaluation.value.asInteger()) == 42, "IDC evaluation failed")
    let compilation = try Script.compileSnippet(functionName: "idax_swift_runtime_answer", body: "return 42;")
    try expect(compilation.succeeded, "IDC compilation failed: \(compilation.error)")
    try expect(try Script.call("idax_swift_runtime_answer").value.asInteger() == 42, "IDC call failed")

    let node = try Storage.Node.open("$ idax.swift.runtime", create: true)
    try node.setAlt(at: 1, value: .max)
    try expect(try node.alt(at: 1) == .max, "Storage unsigned value did not round-trip")
    let payload: [UInt8] = [0, 1, 127, 128, 255]
    try node.setBlob(at: 2, data: payload)
    try expect(try node.blob(at: 2) == payload, "Storage blob did not round-trip")
    let tree = try Directory.Tree.open(.functions)
    try expect(try tree.entry("/").isDirectory, "Directory root is not a directory")
    _ = try tree.snapshot()

    let history = try Navigation.History.open("swift-runtime", initial: .init(address: 0x1000, channel: "code", metadata: "initial"))
    try history.push(.init(address: 0x2000, channel: "code", metadata: "next"))
    try expect(try history.back()?.address == 0x1000, "Navigation back did not restore the prior entry")
    try expect(try history.forward()?.metadata == "next", "Navigation forward lost metadata")
    let historyCopy = try history.copy()
    try expect(historyCopy.created == history.created && (try historyCopy.current()) == history.current(), "Navigation copy lost open-time state")

    let customType = try IDAX.Data.registerCustomDataType(.init(name: "idax.swift.runtime.type", valueSize: 1))
    let customFormat = try IDAX.Data.registerCustomDataFormat(.init(name: "idax.swift.runtime.format", valueSize: 1,
        render: { (bytes, _) throws(IDAError) -> String in
            do throws(IDAError) { try Database.close(); throw IDAError(category: .internalError, message: "Database closed inside an active custom-data callback") }
            catch let error { if error.category != .conflict { throw error } }
            return "value:\(bytes[0])"
        }, scan: { (text, _) throws(IDAError) -> [UInt8] in
            if text == "reject" { throw IDAError(category: .validation, code: 77, message: "scan rejected", context: "custom scan") }
            return Array(text.utf8)
        }))
    try expect(try IDAX.Data.findCustomDataType("idax.swift.runtime.type") == customType.id, "Custom type identity lookup failed")
    try expect(try IDAX.Data.customDataFormat(customFormat.id).canRender, "Custom format metadata lost callback capability")
    try IDAX.Data.attachCustomDataFormat(customFormat.id, to: customType.id)
    try expect(try IDAX.Data.isCustomDataFormatAttached(customFormat.id, to: customType.id), "Custom format attachment failed")
    try expect(try IDAX.Data.renderCustomData(customFormat.id, value: [42]) == "value:42", "Custom render callback failed")
    try expect(try IDAX.Data.scanCustomData(customFormat.id, text: "aβ") == Array("aβ".utf8), "Custom scan lost UTF-8")
    do {
        _ = try IDAX.Data.scanCustomData(customFormat.id, text: "a\0β")
        throw Failure(description: "Custom scan accepted an embedded NUL")
    } catch let error as IDAError {
        try expect(error.category == .validation, "Custom scan did not preserve canonical NUL validation")
    }
    do {
        _ = try IDAX.Data.scanCustomData(customFormat.id, text: "reject")
        throw Failure(description: "Expected a structured callback error")
    } catch let error as IDAError {
        try expect(error == IDAError(category: .validation, code: 77, message: "scan rejected", context: "custom scan"), "Custom callback error fields changed")
    }
    try customFormat.close()
    try customFormat.close()
    try customType.close()

    var selfClosing: IDAX.Data.CustomDataFormatRegistration?
    selfClosing = try IDAX.Data.registerCustomDataFormat(.init(name: "idax.swift.runtime.self-close", valueSize: 1,
        render: { (_, _) throws(IDAError) -> String in try selfClosing?.close(); return "closed safely" }))
    try expect(try IDAX.Data.renderCustomData(selfClosing!.id, value: [0]) == "closed safely", "Custom callback self-unregistration failed")
    selfClosing = nil

    let store = try Registry.Store.open("idax.swift.runtime.\(UUID().uuidString)")
    defer { _ = try? store.eraseTree() }
    try expect(try store.readString("absent") == nil, "Registry absence was lost")
    try store.writeString("empty", value: "")
    try expect(try store.readString("empty") == "", "Registry empty value was lost")
    try store.writeInteger("integer", value: .min)
    try expect(try store.readInteger("integer") == .min, "Registry signed value did not round-trip")
    try store.writeBinary("bytes", value: payload)
    try expect(try store.readBinary("bytes") == payload, "Registry binary value did not round-trip")

    let count = UnsafeMutablePointer<Int>.allocate(capacity: 1)
    let order = UnsafeMutablePointer<Int>.allocate(capacity: 3)
    count.initialize(to: 0)
    order.initialize(repeating: -1, count: 3)
    defer { count.deinitialize(count: 1); count.deallocate(); order.deinitialize(count: 3); order.deallocate() }
    let first = try adoptRecord(index: 1, count: count, order: order)
    let second = try adoptRecord(index: 2, count: count, order: order)
    let deferred = try adoptRecord(index: 3, count: count, order: order)
    var pinnedValue: UnsafeMutableRawPointer?
    var pinError = IdaxSwiftError()
    defer { idax_swift_error_free(&pinError) }
    try expect(idax_swift_resource_pin(deferred, &pinnedValue, &pinError) == 0, "Cannot pin a native resource")
    try worker({ raw in idax_swift_resource_release(raw); return nil }, context: deferred)
    try expect(count.pointee == 0, "Off-thread finalizer destroyed a native resource")
    _ = try Database.addressBitness()
    try expect(count.pointee == 0, "Pinned native resource was destroyed by the deferred queue")
    try expect(idax_swift_resource_close(deferred, &pinError) != 0 && pinError.category == 3, "Pinned native resource accepted close")
    try expectConflict { try Database.close() }
    idax_swift_resource_unpin(deferred)
    try expect(count.pointee == 1 && order[0] == 3, "Final unpin did not drain deferred destruction")
    try expect(idax_swift_runtime_begin_activity(&pinError) == 0, "Cannot guard native callback activity")
    try expectConflict { try Database.close() }
    idax_swift_runtime_end_activity()

    let closingMicrocode = try Decompiler.available()
        ? Decompiler.registerMicrocodeFilter(DatabaseLifetimeMicrocodeFilter()) : nil
    if let closingMicrocode {
        try expect(try closingMicrocode.isValid(), "Database lifetime filter did not register")
    }
    try Database.close()
    databaseOpen = false
    try expect(count.pointee == 3 && order[1] == 2 && order[2] == 1, "Database resources were not released in reverse acquisition order")
    idax_swift_resource_release(second)
    idax_swift_resource_release(first)
    try expectConflict { _ = try type.size() }
    try expectConflict { _ = try scriptString.asString() }
    try expectConflict { _ = try node.id() }
    try expectConflict { _ = try history.current() }
    if let closingMicrocode {
        try expect(try !closingMicrocode.isValid(), "Database close did not invalidate its microcode filter")
    }
    try Database.open(path: fixture.path)
    databaseOpen = true
    try expectConflict { _ = try copy.size() }
    try expect(try TypeInfo.int32().size() == 4, "New database session cannot construct native types")
    if let closingMicrocode {
        try expect(try !closingMicrocode.isValid(), "Database reopen revived an old microcode filter")
        try closingMicrocode.close()
    }
    try Database.close()
    databaseOpen = false
    print("PASS: Swift runtime, thread confinement, structured values, owned resources, and database close/reopen")
}

do { try run() }
catch {
    FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
    exit(1)
}
