internal import CIDAX
import Darwin

/// Fixup (relocation) type matching C++ `ida::fixup::Type`.
public enum FixupType: Int32, Sendable {
    case off8 = 0, off16, seg16, ptr16
    case off32, ptr32
    case hi8, hi16, low8, low16
    case off64
    case off8Signed, off16Signed, off32Signed
    case custom
}

/// Fixup/relocation descriptor.
public struct Fixup: Sendable {
    public let source: Address
    public let type: FixupType
    public let flags: UInt32
    public let base: Address
    public let target: Address
    public let selector: UInt16
    public let offset: UInt64
    public let displacement: Int64

    public static func at(_ source: Address) throws(IDAError) -> Fixup {
        var raw = IdaxFixup()
        try checkStatus(idax_fixup_at(source, &raw), "fixup.at")
        return Fixup(raw: raw)
    }

    public static func exists(at source: Address) -> Bool {
        idax_fixup_exists(source) != 0
    }

    public static func inRange(start: Address, end: Address) throws(IDAError) -> [Fixup] {
        var ptr: UnsafeMutablePointer<IdaxFixup>? = nil
        var count: Int = 0
        try checkStatus(idax_fixup_in_range(start, end, &ptr, &count), "fixup.inRange")
        defer { free(ptr) }
        guard let ptr, count > 0 else { return [] }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { Fixup(raw: $0) }
    }

    public static func remove(at source: Address) throws(IDAError) {
        try checkStatus(idax_fixup_remove(source), "fixup.remove")
    }

    public static func set(_ fixup: Fixup) throws(IDAError) {
        var raw = IdaxFixup()
        raw.source = fixup.source
        raw.type = fixup.type.rawValue
        raw.flags = fixup.flags
        raw.base = fixup.base
        raw.target = fixup.target
        raw.selector = fixup.selector
        raw.offset = fixup.offset
        raw.displacement = fixup.displacement
        try checkStatus(idax_fixup_set(fixup.source, &raw), "fixup.set")
    }

    public static func contains(start: Address, size: UInt64) -> Bool {
        idax_fixup_contains(start, size) != 0
    }

    public static func first() throws(IDAError) -> Address {
        try withOutput("fixup.first", UInt64(0)) { idax_fixup_first($0) }
    }

    public static func next(after address: Address) throws(IDAError) -> Address {
        try withOutput("fixup.next", UInt64(0)) { idax_fixup_next(address, $0) }
    }

    public static func prev(before address: Address) throws(IDAError) -> Address {
        try withOutput("fixup.prev", UInt64(0)) { idax_fixup_prev(address, $0) }
    }

    public static func registerCustom(
        name: String, properties: UInt32, size: UInt8,
        width: UInt8, shift: UInt8, referenceType: UInt32
    ) throws(IDAError) -> UInt16 {
        var out = UInt16(0)
        let ret = name.withCString { cName -> Int32 in
            var handler = IdaxFixupCustomHandler()
            handler.name = cName
            handler.properties = properties
            handler.size = size
            handler.width = width
            handler.shift = shift
            handler.reference_type = referenceType
            return idax_fixup_register_custom(&handler, &out)
        }
        try checkStatus(ret, "fixup.registerCustom")
        return out
    }

    public static func unregisterCustom(_ customType: UInt16) throws(IDAError) {
        try checkStatus(idax_fixup_unregister_custom(customType), "fixup.unregisterCustom")
    }

    public static func findCustom(_ name: String) throws(IDAError) -> UInt16 {
        try withOutput("fixup.findCustom", UInt16(0)) { out in
            name.withCString { idax_fixup_find_custom($0, out) }
        }
    }

    init(raw: IdaxFixup) {
        self.source = raw.source
        self.type = FixupType(rawValue: raw.type) ?? .off32
        self.flags = raw.flags
        self.base = raw.base
        self.target = raw.target
        self.selector = raw.selector
        self.offset = raw.offset
        self.displacement = raw.displacement
    }
}
