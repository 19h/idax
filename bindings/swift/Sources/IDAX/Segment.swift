internal import CIDAX

/// Segment type classification.
public enum SegmentType: Int32, Sendable {
    case normal = 0, external, code, data, bss
    case absoluteSymbols, common, null, undefined
    case `import`, internalMemory, group
}

/// Read/write/execute permission flags.
public struct Permissions: Sendable, Equatable {
    public let read: Bool
    public let write: Bool
    public let execute: Bool
}

/// Opaque snapshot of a segment.
public struct Segment: Sendable {
    public let start: Address
    public let end: Address
    public let name: String
    public let className: String
    public let bitness: Int
    public let segmentType: SegmentType
    public let permissions: Permissions
    public let isVisible: Bool

    public var size: AddressSize { end &- start }

    // MARK: - Queries

    public static func at(_ address: Address) throws(IDAError) -> Segment {
        var raw = IdaxSegment()
        try checkStatus(idax_segment_at(address, &raw), "segment.at")
        defer { idax_segment_free(&raw) }
        return Segment(raw: raw)
    }

    public static func byName(_ name: String) throws(IDAError) -> Segment {
        var raw = IdaxSegment()
        try checkStatus(
            name.withCString { idax_segment_by_name($0, &raw) },
            "segment.byName"
        )
        defer { idax_segment_free(&raw) }
        return Segment(raw: raw)
    }

    public static func byIndex(_ index: Int) throws(IDAError) -> Segment {
        var raw = IdaxSegment()
        try checkStatus(idax_segment_by_index(index, &raw), "segment.byIndex")
        defer { idax_segment_free(&raw) }
        return Segment(raw: raw)
    }

    public static func count() throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_segment_count(&out), "segment.count")
        return out
    }

    public static func all() throws(IDAError) -> [Segment] {
        let n = try count()
        var result: [Segment] = []
        result.reserveCapacity(n)
        for i in 0..<n { result.append(try byIndex(i)) }
        return result
    }

    /// First segment in database order.
    public static var first: Segment {
        get throws(IDAError) {
            try byIndex(0)
        }
    }

    /// Last segment in database order.
    public static var last: Segment {
        get throws(IDAError) {
            let totalCount = try count()
            guard totalCount > 0 else {
                throw IDAError(category: .notFound, code: 0, message: "no segments in database")
            }
            return try byIndex(totalCount - 1)
        }
    }

    // MARK: - Mutation

    public static func create(
        start: Address, end: Address,
        name: String, className: String = "",
        type: SegmentType = .normal
    ) throws(IDAError) {
        try checkStatus(
            name.withCString { n in
                className.withCString { c in
                    idax_segment_create(start, end, n, c, type.rawValue)
                }
            },
            "segment.create"
        )
    }

    public static func remove(at address: Address) throws(IDAError) {
        try checkStatus(idax_segment_remove(address), "segment.remove")
    }

    public static func setName(_ name: String, at address: Address) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_segment_set_name(address, $0) },
            "segment.setName"
        )
    }

    public static func setPermissions(
        at address: Address, read: Bool, write: Bool, execute: Bool
    ) throws(IDAError) {
        try checkStatus(
            idax_segment_set_permissions(
                address,
                read ? 1 : 0, write ? 1 : 0, execute ? 1 : 0
            ),
            "segment.setPermissions"
        )
    }

    public static func setType(_ type: SegmentType, at address: Address) throws(IDAError) {
        try checkStatus(idax_segment_set_type(address, type.rawValue), "segment.setType")
    }

    public static func setClass(_ className: String, at address: Address) throws(IDAError) {
        try checkStatus(
            className.withCString { idax_segment_set_class(address, $0) },
            "segment.setClass"
        )
    }

    public static func setBitness(_ bits: Int, at address: Address) throws(IDAError) {
        try checkStatus(idax_segment_set_bitness(address, Int32(bits)), "segment.setBitness")
    }

    public static func comment(at address: Address, repeatable: Bool = false) throws(IDAError) -> String {
        try withStringOutput("segment.comment") { idax_segment_comment(address, repeatable ? 1 : 0, $0) }
    }

    public static func setComment(_ text: String, at address: Address, repeatable: Bool = false) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_segment_set_comment(address, $0, repeatable ? 1 : 0) },
            "segment.setComment"
        )
    }

    public static func resize(at address: Address, newStart: Address, newEnd: Address) throws(IDAError) {
        try checkStatus(idax_segment_resize(address, newStart, newEnd), "segment.resize")
    }

    public static func move(at address: Address, to newStart: Address) throws(IDAError) {
        try checkStatus(idax_segment_move(address, newStart), "segment.move")
    }

    public static func next(after address: Address) throws(IDAError) -> Segment {
        var raw = IdaxSegment()
        try checkStatus(idax_segment_next(address, &raw), "segment.next")
        defer { idax_segment_free(&raw) }
        return Segment(raw: raw)
    }

    public static func prev(before address: Address) throws(IDAError) -> Segment {
        var raw = IdaxSegment()
        try checkStatus(idax_segment_prev(address, &raw), "segment.prev")
        defer { idax_segment_free(&raw) }
        return Segment(raw: raw)
    }

    public static func setDefaultSegmentRegister(at address: Address, registerIndex: Int, value: UInt64) throws(IDAError) {
        try checkStatus(
            idax_segment_set_default_segment_register(address, Int32(registerIndex), value),
            "segment.setDefaultSegmentRegister"
        )
    }

    public static func setDefaultSegmentRegisterForAll(registerIndex: Int, value: UInt64) throws(IDAError) {
        try checkStatus(
            idax_segment_set_default_segment_register_for_all(Int32(registerIndex), value),
            "segment.setDefaultSegmentRegisterForAll"
        )
    }

    // MARK: - Internal

    init(raw: IdaxSegment) {
        self.start = raw.start
        self.end = raw.end
        self.bitness = Int(raw.bitness)
        self.segmentType = SegmentType(rawValue: Int32(raw.type)) ?? .undefined
        self.permissions = Permissions(
            read: raw.perm_read != 0,
            write: raw.perm_write != 0,
            execute: raw.perm_exec != 0
        )
        self.name = borrowCString(raw.name)
        self.className = borrowCString(raw.class_name)
        self.isVisible = raw.visible != 0
    }
}
