internal import CIDAX

/// Text, binary, and immediate value search.
///
/// Mirrors C++ `ida::search`.
public enum Search {
    public static func text(
        _ query: String, start: Address,
        forward: Bool = true, caseSensitive: Bool = true
    ) throws(IDAError) -> Address {
        try withOutput("search.text", UInt64(0)) { out in
            query.withCString { idax_search_text($0, start, forward ? 1 : 0, caseSensitive ? 1 : 0, out) }
        }
    }

    public static func binaryPattern(_ hex: String, start: Address, forward: Bool = true) throws(IDAError) -> Address {
        try withOutput("search.binaryPattern", UInt64(0)) { out in
            hex.withCString { idax_search_binary_pattern($0, start, forward ? 1 : 0, out) }
        }
    }

    public static func immediate(_ value: UInt64, start: Address, forward: Bool = true) throws(IDAError) -> Address {
        try withOutput("search.immediate", UInt64(0)) { idax_search_immediate(value, start, forward ? 1 : 0, $0) }
    }

    public static func nextCode(after address: Address) throws(IDAError) -> Address {
        try withOutput("search.nextCode", UInt64(0)) { idax_search_next_code(address, $0) }
    }

    public static func nextData(after address: Address) throws(IDAError) -> Address {
        try withOutput("search.nextData", UInt64(0)) { idax_search_next_data(address, $0) }
    }

    public static func nextUnknown(after address: Address) throws(IDAError) -> Address {
        try withOutput("search.nextUnknown", UInt64(0)) { idax_search_next_unknown(address, $0) }
    }

    public static func nextError(after address: Address) throws(IDAError) -> Address {
        try withOutput("search.nextError", UInt64(0)) { idax_search_next_error(address, $0) }
    }

    public static func nextDefined(after address: Address) throws(IDAError) -> Address {
        try withOutput("search.nextDefined", UInt64(0)) { idax_search_next_defined(address, $0) }
    }
}
