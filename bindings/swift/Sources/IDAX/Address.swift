internal import CIDAX

/// IDA address type (64-bit unsigned).
public typealias Address = UInt64

/// Unsigned size difference between two addresses.
public typealias AddressSize = UInt64

/// Signed offset between two addresses.
public typealias AddressDelta = Int64

/// Sentinel value representing an invalid address.
public let badAddress: Address = .max

/// Address predicates and navigation.
///
/// Mirrors C++ `ida::address`.
public enum AddressAPI {

    // MARK: - Predicates (pure bool, never throw)

    public static func isMapped(_ address: Address) -> Bool {
        idax_address_is_mapped(address) != 0
    }

    public static func isLoaded(_ address: Address) -> Bool {
        idax_address_is_loaded(address) != 0
    }

    public static func isCode(_ address: Address) -> Bool {
        idax_address_is_code(address) != 0
    }

    public static func isData(_ address: Address) -> Bool {
        idax_address_is_data(address) != 0
    }

    public static func isUnknown(_ address: Address) -> Bool {
        idax_address_is_unknown(address) != 0
    }

    public static func isHead(_ address: Address) -> Bool {
        idax_address_is_head(address) != 0
    }

    public static func isTail(_ address: Address) -> Bool {
        idax_address_is_tail(address) != 0
    }

    // MARK: - Navigation

    public static func itemStart(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.itemStart", UInt64(0)) { idax_address_item_start(address, $0) }
    }

    public static func itemEnd(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.itemEnd", UInt64(0)) { idax_address_item_end(address, $0) }
    }

    public static func itemSize(_ address: Address) throws(IDAError) -> AddressSize {
        try withOutput("address.itemSize", UInt64(0)) { idax_address_item_size(address, $0) }
    }

    public static func nextHead(_ address: Address, limit: Address = badAddress) throws(IDAError) -> Address {
        try withOutput("address.nextHead", UInt64(0)) { idax_address_next_head(address, limit, $0) }
    }

    public static func prevHead(_ address: Address, limit: Address = 0) throws(IDAError) -> Address {
        try withOutput("address.prevHead", UInt64(0)) { idax_address_prev_head(address, limit, $0) }
    }

    public static func nextNotTail(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.nextNotTail", UInt64(0)) { idax_address_next_not_tail(address, $0) }
    }

    public static func prevNotTail(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.prevNotTail", UInt64(0)) { idax_address_prev_not_tail(address, $0) }
    }

    public static func nextMapped(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.nextMapped", UInt64(0)) { idax_address_next_mapped(address, $0) }
    }

    public static func prevMapped(_ address: Address) throws(IDAError) -> Address {
        try withOutput("address.prevMapped", UInt64(0)) { idax_address_prev_mapped(address, $0) }
    }

    // MARK: - Search

    public static func findFirst(start: Address, end: Address, predicate: Int) throws(IDAError) -> Address {
        try withOutput("address.findFirst", UInt64(0)) {
            idax_address_find_first(start, end, Int32(predicate), $0)
        }
    }

    public static func findNext(_ address: Address, predicate: Int, end: Address) throws(IDAError) -> Address {
        try withOutput("address.findNext", UInt64(0)) {
            idax_address_find_next(address, Int32(predicate), end, $0)
        }
    }
}
