internal import CIDAX

internal func checkedNativeEnum<E: RawRepresentable, I: BinaryInteger>(_ type: E.Type, _ value: I, _ operation: String) throws(IDAError) -> E where E.RawValue == Int32 {
    guard let raw = Int32(exactly: value), let result = E(rawValue: raw) else {
        throw IDAError(category: .unsupported, message: "Native enumeration discriminant is unknown: \(value)", context: operation)
    }
    return result
}

internal func requireOwnedHandle(_ pointer: UnsafeMutableRawPointer?, _ operation: String) throws(IDAError) -> UnsafeMutableRawPointer {
    guard let pointer else { throw IDAError(category: .internalError, message: "Native operation returned no owned handle", context: operation) }
    return pointer
}

internal func copyNativeOptional<C, V>(_ pointer: UnsafeMutablePointer<C>?, _ operation: String,
    _ transform: (C) throws(IDAError) -> V
) throws(IDAError) -> V? {
    guard let pointer else { return nil }
    return try transform(pointer.pointee)
}

internal func validateCString(_ value: String, _ operation: String) throws(IDAError) {
    guard !value.utf8.contains(0) else {
        throw IDAError(category: .validation, message: "String contains an embedded NUL byte", context: operation)
    }
}

extension Database {
    public static func open(path: String, autoAnalysis: Bool = true, intent: LoadIntent = .autoDetect) throws(IDAError) {
        let operation = "Database.open"
        try validateCString(path, operation)
        try bridgeCall(operation) { error in
            path.withCString { idax_swift_database_open($0, autoAnalysis ? 1 : 0, intent.rawValue, error) }
        }
    }

    public static func close(save: Bool = false) throws(IDAError) {
        try bridgeCall("Database.close") { idax_swift_database_close(save ? 1 : 0, $0) }
    }
}

internal func copyNativeValues<Element, Value>(
    _ pointer: UnsafeMutablePointer<Element>?, count: Int, _ operation: String,
    _ transform: (Element) throws(IDAError) -> Value
) throws(IDAError) -> [Value] {
    let buffer = try checkedBuffer(pointer.map { UnsafePointer($0) }, count: count, operation)
    var result: [Value] = []
    result.reserveCapacity(count)
    for element in buffer { result.append(try transform(element)) }
    return result
}
