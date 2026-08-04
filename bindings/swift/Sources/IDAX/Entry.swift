internal import CIDAX

/// Program entry point descriptor.
public struct EntryPoint: Sendable {
    public let ordinal: UInt64
    public let address: Address
    public let name: String
    public let forwarder: String

    public static func count() throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_entry_count(&out), "entry.count")
        return out
    }

    public static func byIndex(_ index: Int) throws(IDAError) -> EntryPoint {
        var raw = IdaxEntryPoint()
        try checkStatus(idax_entry_by_index(index, &raw), "entry.byIndex")
        defer { idax_entry_free(&raw) }
        return EntryPoint(
            ordinal: raw.ordinal, address: raw.address,
            name: borrowCString(raw.name),
            forwarder: borrowCString(raw.forwarder)
        )
    }

    public static func all() throws(IDAError) -> [EntryPoint] {
        let n = try count()
        var result: [EntryPoint] = []
        result.reserveCapacity(n)
        for i in 0..<n { result.append(try byIndex(i)) }
        return result
    }

    public static func add(ordinal: UInt64, address: Address, name: String, makeCode: Bool = true) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_entry_add(ordinal, address, $0, makeCode ? 1 : 0) },
            "entry.add"
        )
    }

    public static func rename(ordinal: UInt64, name: String) throws(IDAError) {
        try checkStatus(name.withCString { idax_entry_rename(ordinal, $0) }, "entry.rename")
    }

    public static func byOrdinal(_ ordinal: UInt64) throws(IDAError) -> EntryPoint {
        var raw = IdaxEntryPoint()
        try checkStatus(idax_entry_by_ordinal(ordinal, &raw), "entry.byOrdinal")
        defer { idax_entry_free(&raw) }
        return EntryPoint(
            ordinal: raw.ordinal, address: raw.address,
            name: borrowCString(raw.name),
            forwarder: borrowCString(raw.forwarder)
        )
    }

    public static func forwarder(ordinal: UInt64) throws(IDAError) -> String {
        try withStringOutput("entry.forwarder") { idax_entry_forwarder(ordinal, $0) }
    }

    public static func setForwarder(ordinal: UInt64, target: String) throws(IDAError) {
        try checkStatus(
            target.withCString { idax_entry_set_forwarder(ordinal, $0) },
            "entry.setForwarder"
        )
    }

    public static func clearForwarder(ordinal: UInt64) throws(IDAError) {
        try checkStatus(idax_entry_clear_forwarder(ordinal), "entry.clearForwarder")
    }
}
