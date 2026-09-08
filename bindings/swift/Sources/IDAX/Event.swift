internal import CIDAX

/// Owns a native callback registration. Closing is idempotent; a failed close
/// preserves the registration so it can be retried. Native in-flight callbacks
/// retain their captures until the final invocation has returned.
public final class Registration {
    private var handle: UnsafeMutableRawPointer?
    internal init(owning handle: UnsafeMutableRawPointer) { self.handle = handle }
    deinit { if let handle { idax_swift_registration_release(handle) } }
    public func close() throws(IDAError) {
        guard let handle else { return }
        try bridgeCall("registration.close") { idax_swift_registration_close(handle, $0) }
        idax_swift_registration_release(handle)
        self.handle = nil
    }
    internal func activateShortcut() throws(IDAError) {
        guard let handle else { throw IDAError(category: .conflict, message: "Shortcut is closed") }
        try bridgeCall("shortcut.activate") { idax_swift_hotkey_activate(handle, $0) }
    }
    internal func isActive() throws(IDAError) -> Bool {
        guard let handle else { return false }
        var output: Int32 = 0
        try bridgeCall("registration.isActive") { idax_swift_registration_active(handle, &output, $0) }
        return output != 0
    }
}

internal final class CallbackLease {
    let handle: UnsafeMutableRawPointer
    init(_ handle: UnsafeMutableRawPointer) {
        self.handle = handle
        idax_swift_lease_retain(handle)
    }
    deinit { idax_swift_lease_release(handle) }
    func check(_ operation: String) throws(IDAError) {
        try bridgeCall(operation) { idax_swift_lease_check(handle, $0) }
    }
}

internal final class LifecycleStrings {
    private var storage: [UnsafeMutablePointer<CChar>] = []
    init(_ values: [String]) throws(IDAError) {
        for text in values {
            guard !text.utf8.contains(0) else {
                throw IDAError(category: .validation, message: "String contains an embedded NUL")
            }
            let bytes = text.utf8.map { CChar(bitPattern: $0) } + [0]
            let pointer = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count)
            bytes.withUnsafeBufferPointer { pointer.initialize(from: $0.baseAddress!, count: $0.count) }
            storage.append(pointer)
        }
    }
    deinit { for pointer in storage { pointer.deallocate() } }
    subscript(_ index: Int) -> UnsafePointer<CChar> { UnsafePointer(storage[index]) }
    var pointers: [UnsafePointer<CChar>?] { storage.map { UnsafePointer($0) } }
}

internal final class LifecycleCallback {
    let body: (IdaxSwiftNotification, UnsafeMutablePointer<IdaxSwiftReply>) throws -> Void
    init(_ body: @escaping (IdaxSwiftNotification, UnsafeMutablePointer<IdaxSwiftReply>) throws -> Void) {
        self.body = body
    }
}
internal func callbackDescriptor(
    _ body: @escaping (IdaxSwiftNotification, UnsafeMutablePointer<IdaxSwiftReply>) throws -> Void
) -> IdaxSwiftCallbacks {
    IdaxSwiftCallbacks(
        context: Unmanaged.passRetained(LifecycleCallback(body)).toOpaque(), invoke: lifecycleInvoke,
        destroy: lifecycleDestroy)
}
private func lifecycleDestroy(_ context: UnsafeMutableRawPointer?) {
    if let context { Unmanaged<LifecycleCallback>.fromOpaque(context).release() }
}
internal func writeCallbackError(_ error: IDAError, to output: UnsafeMutablePointer<IdaxSwiftError>?) {
    let category: Int32
    switch error.category {
    case .validation: category = 1
    case .notFound: category = 2
    case .conflict: category = 3
    case .unsupported: category = 4
    case .sdkFailure: category = 5
    case .internalError: category = 6
    }
    error.message.withCString { message in
        error.context.withCString { context in
            idax_swift_error_set(output, category, error.code, message, context)
        }
    }
}
private func lifecycleInvoke(
    _ context: UnsafeMutableRawPointer?, _ event: UnsafePointer<IdaxSwiftNotification>?,
    _ reply: UnsafeMutablePointer<IdaxSwiftReply>?, _ errorOutput: UnsafeMutablePointer<IdaxSwiftError>?
) -> Int32 {
    guard let context, let event, let reply else { return -1 }
    let owner = Unmanaged<LifecycleCallback>.fromOpaque(context).takeUnretainedValue()
    do {
        try owner.body(event.pointee, reply)
        return 0
    } catch {
        writeCallbackError(
            (error as? IDAError) ?? IDAError(category: .internalError, message: String(describing: error)),
            to: errorOutput)
        return -1
    }
}

internal func requireLifecycleHandle(_ handle: UnsafeMutableRawPointer?, _ operation: String) throws(IDAError)
    -> UnsafeMutableRawPointer
{
    guard let handle else {
        throw IDAError(
            category: .internalError, message: "Native operation returned no owned handle", context: operation
        )
    }
    return handle
}

/// Database changes represented as copied, independent values.
public enum Event {
    public enum Kind: CaseIterable, Sendable {
        case segmentAdded, segmentDeleted, functionAdded, functionDeleted, renamed, bytePatched,
            commentChanged
        case segmentMoved, functionUpdated, itemTypeChanged, operandTypeChanged, codeCreated, dataCreated,
            itemsDestroyed, extraCommentChanged, localTypesChanged
        internal var native: Int32 { Int32(Self.allCases.firstIndex(of: self)!) }
        internal init(native: Int32) throws(IDAError) {
            guard native >= 0, Int(native) < Self.allCases.count else {
                throw IDAError(category: .unsupported, message: "Unknown database event kind")
            }
            self = Self.allCases[Int(native)]
        }
    }
    public enum ExtraCommentPlacement: Sendable { case unknown, anterior, posterior }
    public enum LocalTypeChange: CaseIterable, Sendable {
        case none, added, deleted, edited, aliased, compilerChanged, libraryLoaded, libraryUnloaded,
            ordinalsCompacted
    }
    public struct Change: Sendable {
        public let kind: Kind
        public let address: Address
        public let secondaryAddress: Address
        public let size: UInt64
        public let newName: String
        public let oldName: String
        public let oldValue: UInt32
        public let repeatable: Bool
        public let operandIndex: Int32
        public let lineIndex: Int32
        public let text: String
        public let willDisableRange: Bool
        public let addressMappingChanged: Bool
        public let extraCommentPlacement: ExtraCommentPlacement
        public let localTypeChange: LocalTypeChange
        public let typeOrdinal: UInt32
        public let typeName: String
        internal init(_ raw: IdaxSwiftNotification) throws(IDAError) {
            kind = try Kind(native: raw.kind)
            address = raw.address
            secondaryAddress = raw.secondary_address
            size = raw.size
            newName = try borrowCString(raw.text, "event.newName")
            oldName = try borrowCString(raw.secondary_text, "event.oldName")
            oldValue = raw.value
            repeatable = raw.flag != 0
            operandIndex = raw.number
            lineIndex = raw.secondary_number
            text = kind == .extraCommentChanged ? newName : ""
            willDisableRange = raw.secondary_flag & 1 != 0
            addressMappingChanged = raw.secondary_flag & 2 != 0
            extraCommentPlacement = raw.number == 1 ? .anterior : raw.number == 2 ? .posterior : .unknown
            guard raw.previous_identity < UInt64(LocalTypeChange.allCases.count), raw.identity <= UInt32.max
            else { throw IDAError(category: .unsupported, message: "Unknown local type event metadata") }
            localTypeChange = LocalTypeChange.allCases[Int(raw.previous_identity)]
            typeOrdinal = UInt32(raw.identity)
            typeName = try borrowCString(raw.name, "event.typeName")
        }
    }
    /// Subscribe to all changes or one semantic kind. Filters and handlers run
    /// synchronously on IDA's owner thread; returned values may be retained.
    public static func subscribe(
        to kind: Kind? = nil, filter: ((Change) throws(IDAError) -> Bool)? = nil,
        handler: @escaping (Change) throws(IDAError) -> Void
    ) throws(IDAError) -> Registration {
        let descriptor = callbackDescriptor { raw, reply in
            let change = try Change(raw)
            if raw.phase == 1 {
                reply.pointee.decision = try (filter?(change) ?? true) ? 1 : 0
            } else {
                try handler(change)
            }
        }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("event.subscribe") {
            idax_swift_event_subscribe(kind?.native ?? -1, descriptor, &handle, $0)
        }
        return Registration(owning: try requireLifecycleHandle(handle, "event.subscribe"))
    }
}
