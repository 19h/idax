internal import CIDAX

extension Addresses.Range {
    public var size: UInt64 { end > start ? end - start : 0 }
    public var isEmpty: Bool { start >= end }
    public func contains(_ address: Address) -> Bool { address >= start && address < end }
}

extension Addresses {
    public static func nextDefined(address: Address, limit: Address = badAddress) throws(IDAError) -> Address {
        try nextHead(address: address, limit: limit)
    }
    public static func prevDefined(address: Address, limit: Address = 0) throws(IDAError) -> Address {
        try prevHead(address: address, limit: limit)
    }

    /// Copy matching addresses in ascending order. Time and space are linear in the visited range and returned count respectively.
    public static func matching(_ predicate: Predicate, start: Address, end: Address) throws(IDAError) -> [Address] {
        try collect(predicate: predicate.rawValue, start: start, end: end)
    }
    private static func collect(predicate: Int32, start: Address, end: Address) throws(IDAError) -> [Address] {
        let operation = "Addresses.matching"
        var output: UnsafeMutablePointer<UInt64>?
        var count = 0
        defer { idax_swift_free_array(output) }
        try bridgeCall(operation) {
            idax_swift_address_collect(start, end, predicate, &output, &count, $0)
        }
        return Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
    }
    public static func items(start: Address, end: Address) throws(IDAError) -> [Address] {
        try collect(predicate: 7, start: start, end: end)
    }
    public static func codeItems(start: Address, end: Address) throws(IDAError) -> [Address] {
        try matching(.code, start: start, end: end)
    }
    public static func dataItems(start: Address, end: Address) throws(IDAError) -> [Address] {
        try matching(.data, start: start, end: end)
    }
    public static func unknownBytes(start: Address, end: Address) throws(IDAError) -> [Address] {
        try matching(.unknown, start: start, end: end)
    }
}
