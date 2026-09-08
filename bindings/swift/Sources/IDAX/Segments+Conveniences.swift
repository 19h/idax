internal import CIDAX

extension Segments {
    public struct Permissions: Equatable, Sendable {
        public var read: Bool
        public var write: Bool
        public var execute: Bool

        public init(read: Bool = false, write: Bool = false, execute: Bool = false) {
            self.read = read
            self.write = write
            self.execute = execute
        }
    }

    @discardableResult
    public static func create(start: Address, end: Address, name: String,
        className: String = "", type: Kind = .normal
    ) throws(IDAError) -> Segment {
        let operation = "Segments.create"
        try requireRuntimeThread(operation)
        try validateCString(name, operation)
        try validateCString(className, operation)
        try checkStatus(name.withCString { name in className.withCString { className in
            idax_segment_create(start, end, name, className, type.rawValue)
        } }, operation)
        return try at(address: start)
    }

    public static func setPermissions(address: Address, permissions: Permissions) throws(IDAError) {
        try setPermissions(address: address, read: permissions.read,
            write: permissions.write, exec: permissions.execute)
    }

    public static func all() throws(IDAError) -> [Segment] {
        let total = try count()
        var result: [Segment] = []
        result.reserveCapacity(total)
        for index in 0..<total { result.append(try byIndex(index: index)) }
        return result
    }

    public static func first() throws(IDAError) -> Segment {
        guard try count() > 0 else {
            throw IDAError(category: .notFound, message: "No segments")
        }
        return try byIndex(index: 0)
    }

    public static func last() throws(IDAError) -> Segment {
        let total = try count()
        guard total > 0 else {
            throw IDAError(category: .notFound, message: "No segments")
        }
        return try byIndex(index: total - 1)
    }

    public static func splitRegisterRange(address: Address, registerName: String,
        value: UInt64?, source: SegmentRegisterSource = .user
    ) throws(IDAError) {
        let operation = "Segments.splitRegisterRange"
        try requireRuntimeThread(operation)
        try validateCString(registerName, operation)
        try checkStatus(registerName.withCString {
            idax_segment_split_register_range(address, $0, value == nil ? 0 : 1, value ?? 0, source.rawValue)
        }, operation)
    }

    public static func setDefaultSegmentRegister(address: Address, registerName: String,
        value: UInt64?
    ) throws(IDAError) {
        let operation = "Segments.setDefaultSegmentRegister"
        try requireRuntimeThread(operation)
        try validateCString(registerName, operation)
        try checkStatus(registerName.withCString {
            idax_segment_set_default_segment_register_named(address, $0, value == nil ? 0 : 1, value ?? 0)
        }, operation)
    }

    public static func setDefaultSegmentRegisterForAll(registerName: String,
        value: UInt64?
    ) throws(IDAError) {
        let operation = "Segments.setDefaultSegmentRegisterForAll"
        try requireRuntimeThread(operation)
        try validateCString(registerName, operation)
        try checkStatus(registerName.withCString {
            idax_segment_set_default_segment_register_for_all_named($0, value == nil ? 0 : 1, value ?? 0)
        }, operation)
    }

    public static func setDefaultDataSegment(value: UInt64?) throws(IDAError) {
        try requireRuntimeThread("Segments.setDefaultDataSegment")
        try checkStatus(idax_segment_set_default_data_segment(value == nil ? 0 : 1, value ?? 0),
            "Segments.setDefaultDataSegment")
    }

    public static func setRegisterAtNextCode(searchStart: Address, maximum: Address,
        registerName: String, value: UInt64?
    ) throws(IDAError) {
        let operation = "Segments.setRegisterAtNextCode"
        try requireRuntimeThread(operation)
        try validateCString(registerName, operation)
        try checkStatus(registerName.withCString {
            idax_segment_set_register_at_next_code(searchStart, maximum, $0, value == nil ? 0 : 1, value ?? 0)
        }, operation)
    }

    public typealias SegmentRegisterDescriptor = RegisterDescriptor
    public typealias SegmentRegisterRange = RegisterRange

    public static func segmentRegisters() throws(IDAError) -> [RegisterDescriptor] { try registers() }
    public static func segmentRegisterValue(address: Address, registerName: String) throws(IDAError) -> UInt64? {
        try registerValue(address: address, registerName: registerName)
    }
    public static func defaultSegmentRegisterValue(address: Address, registerName: String) throws(IDAError) -> UInt64? {
        try defaultRegisterValue(address: address, registerName: registerName)
    }
    public static func segmentRegisterRange(address: Address, registerName: String) throws(IDAError) -> RegisterRange {
        try registerRange(address: address, registerName: registerName)
    }
    public static func previousSegmentRegisterRange(address: Address, registerName: String) throws(IDAError) -> RegisterRange? {
        try previousRegisterRange(address: address, registerName: registerName)
    }
    public static func segmentRegisterRanges(registerName: String) throws(IDAError) -> [RegisterRange] {
        try registerRanges(registerName: registerName)
    }
    public static func segmentRegisterRangeIndex(address: Address, registerName: String) throws(IDAError) -> Int? {
        try registerRangeIndex(address: address, registerName: registerName)
    }
    public static func splitSegmentRegisterRange(address: Address, registerName: String,
        value: UInt64?, source: SegmentRegisterSource = .user
    ) throws(IDAError) {
        try splitRegisterRange(address: address, registerName: registerName, value: value, source: source)
    }
    public static func removeSegmentRegisterRange(rangeStart: Address, registerName: String) throws(IDAError) {
        try removeRegisterRange(address: rangeStart, registerName: registerName)
    }
    public static func setSegmentRegisterAtNextCode(searchStart: Address, maximum: Address,
        registerName: String, value: UInt64?
    ) throws(IDAError) {
        try setRegisterAtNextCode(searchStart: searchStart, maximum: maximum,
            registerName: registerName, value: value)
    }
    public static func copySegmentRegisterRanges(destinationRegister: String,
        sourceRegister: String, mapSelectorsToAddresses: Bool = false
    ) throws(IDAError) {
        try copyRegisterRanges(destinationRegister: destinationRegister,
            sourceRegister: sourceRegister, mapSelectorsToAddresses: mapSelectorsToAddresses)
    }
}

extension Segments.Segment {
    public var size: UInt64 { end &- start }
    public var permissions: Segments.Permissions {
        .init(read: permRead, write: permWrite, execute: permExec)
    }
    public var isVisible: Bool { visible }
    public mutating func refresh() throws(IDAError) { self = try Segments.at(address: start) }
}
