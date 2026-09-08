internal import CIDAX

extension Fixups {
    public struct HandlerProperties: OptionSet, Equatable, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let verify = Self(rawValue: 0x0001)
        public static let code = Self(rawValue: 0x0002)
        public static let forceCode = Self(rawValue: 0x0004)
        public static let absoluteOperand = Self(rawValue: 0x0008)
        public static let signedOperand = Self(rawValue: 0x0010)
    }
    public struct CustomHandler: Equatable, Sendable {
        public var name: String
        public var properties: HandlerProperties
        /// Storage size in bytes.
        public var size: UInt8
        /// Significant width in bits.
        public var width: UInt8
        public var shift: UInt8
        public var referenceType: UInt32
        public init(name: String, properties: HandlerProperties = [], size: UInt8 = 4, width: UInt8 = 32, shift: UInt8 = 0, referenceType: UInt32 = 0) {
            self.name = name; self.properties = properties; self.size = size; self.width = width
            self.shift = shift; self.referenceType = referenceType
        }
    }
    /// An opaque identity produced by registration or name lookup.
    public struct CustomTypeID: Hashable, Sendable {
        internal let value: UInt16
        internal let generation: UInt64
        internal init(_ value: UInt16, generation: UInt64) { self.value = value; self.generation = generation }
    }
    public final class CustomRegistration {
        public let id: CustomTypeID
        private let resource: NativeResource
        internal init(_ value: UInt16, name: String) throws(IDAError) {
            let state = SwiftFixupRegistration.create(id: value, name: name)
            id = state.id
            resource = try NativeResource(taking: Unmanaged.passRetained(state).toOpaque(), release: freeSwiftFixupRegistration,
                databaseBound: false, operation: "Fixups.registerCustom")
        }
        public func close() throws(IDAError) { try resource.close("Fixups.CustomRegistration.close", using: closeSwiftFixupRegistration) }
    }
    public static func registerCustom(_ handler: CustomHandler) throws(IDAError) -> CustomRegistration {
        let op = "Fixups.registerCustom"; try requireRuntimeThread(op); try validateCString(handler.name, op)
        var output: UInt16 = 0
        try checkStatus(handler.name.withCString { name in
            var value = IdaxFixupCustomHandler(name: name, properties: handler.properties.rawValue, size: handler.size,
                width: handler.width, shift: handler.shift, reference_type: handler.referenceType)
            return idax_fixup_register_custom(&value, &output)
        }, op)
        return try CustomRegistration(output, name: handler.name)
    }
    public static func findCustom(named name: String) throws(IDAError) -> CustomTypeID {
        let op = "Fixups.findCustom"; try validateCString(name, op)
        let value = try withOutput(op, initial: UInt16(0)) { output in name.withCString { idax_fixup_find_custom($0, output) } }
        if let state = SwiftFixupRegistration.states[value], state.active, state.name == name { return state.id }
        return SwiftFixupRegistration.create(id: value, name: name).id
    }
    public static func unregisterCustom(_ id: CustomTypeID) throws(IDAError) {
        try requireRuntimeThread("Fixups.unregisterCustom")
        guard let state = SwiftFixupRegistration.states[id.value], state.id == id else {
            throw IDAError(category: .conflict, message: "Custom fixup identity is no longer registered", context: "Fixups.unregisterCustom")
        }
        try state.close()
    }
    public static func set(at address: Address, descriptor: Descriptor) throws(IDAError) {
        try requireRuntimeThread("Fixups.set")
        var value = IdaxFixup(source: descriptor.source, type: descriptor.type.rawValue, flags: descriptor.flags,
            base: descriptor.base, target: descriptor.target, selector: descriptor.selector, offset: descriptor.offset,
            displacement: descriptor.displacement)
        try checkStatus(idax_fixup_set(address, &value), "Fixups.set")
    }
    /// A copied snapshot of the fixup sequence in ascending address order.
    public static func all() throws(IDAError) -> [Descriptor] {
        var result: [Descriptor] = []
        var address = try first()
        while address != badAddress {
            result.append(try at(source: address))
            let next = try next(address: address)
            guard next == badAddress || next > address else {
                throw IDAError(category: .internalError, message: "Fixup traversal did not advance", context: "Fixups.all")
            }
            address = next
        }
        return result
    }
}
/// Access is confined to the checked runtime thread, including deferred ARC callbacks.
private final class SwiftFixupRegistration {
    nonisolated(unsafe) static var states: [UInt16: SwiftFixupRegistration] = [:]
    nonisolated(unsafe) static var nextGeneration: UInt64 = 0
    let id: Fixups.CustomTypeID
    let name: String
    var active = true
    private init(id: UInt16, name: String, generation: UInt64) {
        self.id = .init(id, generation: generation); self.name = name
    }
    static func create(id: UInt16, name: String) -> SwiftFixupRegistration {
        nextGeneration += 1
        if let previous = states[id] { previous.active = false }
        let value = SwiftFixupRegistration(id: id, name: name, generation: nextGeneration)
        states[id] = value; return value
    }
    func close() throws(IDAError) {
        guard active else { return }
        guard Self.states[id.value] === self else {
            active = false; return
        }
        // A named check also detects native deletion or reuse outside this wrapper.
        var current: UInt16 = 0
        let status = name.withCString { idax_fixup_find_custom($0, &current) }
        if status != 0 || current != id.value {
            active = false; Self.states.removeValue(forKey: id.value)
            throw IDAError(category: .conflict, message: "Custom fixup identity changed in the host", context: "Fixups.CustomRegistration.close")
        }
        try checkStatus(idax_fixup_unregister_custom(id.value), "Fixups.CustomRegistration.close")
        active = false; Self.states.removeValue(forKey: id.value)
    }
}
private func closeSwiftFixupRegistration(_ raw: UnsafeMutableRawPointer?, _ output: UnsafeMutablePointer<IdaxSwiftError>?) -> Int32 {
    guard let raw else { return 0 }
    let state = Unmanaged<SwiftFixupRegistration>.fromOpaque(raw).takeUnretainedValue()
    do { try state.close(); return 0 }
    catch { writeCallbackError(error, to: output); return -1 }
}
private func freeSwiftFixupRegistration(_ raw: UnsafeMutableRawPointer?) {
    guard let raw else { return }
    let state = Unmanaged<SwiftFixupRegistration>.fromOpaque(raw).takeRetainedValue()
    try? state.close()
}
