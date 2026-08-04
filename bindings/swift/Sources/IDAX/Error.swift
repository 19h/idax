internal import CIDAX

/// Error classification matching C++ `ida::ErrorCategory`.
public enum IDAErrorCategory: Int32, Sendable, CustomStringConvertible {
    case validation  = 1
    case notFound    = 2
    case conflict    = 3
    case unsupported = 4
    case sdkFailure  = 5
    case `internal`  = 6

    public var description: String {
        switch self {
        case .validation:  "Validation"
        case .notFound:    "NotFound"
        case .conflict:    "Conflict"
        case .unsupported: "Unsupported"
        case .sdkFailure:  "SdkFailure"
        case .internal:    "Internal"
        }
    }
}

/// Structured error carried through every throwing IDA operation.
///
/// Maps directly to C++ `ida::Error`.
public struct IDAError: Error, Sendable, CustomStringConvertible {
    public let category: IDAErrorCategory
    public let code: Int32
    public let message: String

    public var description: String {
        "[\(category)] \(message)"
    }
}

// MARK: - Internal FFI helpers

/// Read the last error from the C shim's thread-local state.
func consumeLastError(fallback: String) -> IDAError {
    let cat = idax_last_error_category()
    let code = idax_last_error_code()
    let msgPtr = idax_last_error_message()

    let message: String
    if let msgPtr {
        message = String(cString: msgPtr)
    } else {
        message = fallback
    }

    let category = IDAErrorCategory(rawValue: cat) ?? .internal
    return IDAError(category: category, code: code, message: message)
}

/// Check a C shim return code (0 = success) and throw on failure.
func checkStatus(_ ret: Int32, _ fallback: String) throws(IDAError) {
    if ret != 0 {
        throw consumeLastError(fallback: fallback)
    }
}

/// Call a C shim function that writes to a scalar output pointer.
func withOutput<T>(
    _ fallback: String,
    _ initial: T,
    _ body: (UnsafeMutablePointer<T>) -> Int32
) throws(IDAError) -> T {
    var out = initial
    let ret = body(&out)
    if ret != 0 {
        throw consumeLastError(fallback: fallback)
    }
    return out
}

/// Call a C shim function that returns a malloc'd string via `char**` out param.
func withStringOutput(
    _ fallback: String,
    _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
) throws(IDAError) -> String {
    var ptr: UnsafeMutablePointer<CChar>? = nil
    let ret = body(&ptr)
    if ret != 0 {
        throw consumeLastError(fallback: fallback)
    }
    return takeCString(ptr)
}

/// Consume a malloc'd C string into a Swift String and free it.
/// Returns empty string for nil.
func takeCString(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
    guard let ptr else { return "" }
    defer { idax_free_string(ptr) }
    return String(cString: ptr)
}

/// Read a C string without freeing it. Used when a separate `_free` function
/// owns the lifecycle of the containing struct.
func borrowCString(_ ptr: UnsafePointer<CChar>?) -> String {
    guard let ptr else { return "" }
    return String(cString: ptr)
}

/// Read an address array output from a C shim call.
func withAddressArrayOutput(
    _ fallback: String,
    _ body: (UnsafeMutablePointer<UnsafeMutablePointer<UInt64>?>, UnsafeMutablePointer<Int>) -> Int32
) throws(IDAError) -> [Address] {
    var ptr: UnsafeMutablePointer<UInt64>? = nil
    var count: Int = 0
    let ret = body(&ptr, &count)
    if ret != 0 {
        throw consumeLastError(fallback: fallback)
    }
    defer { idax_free_addresses(ptr) }
    guard let ptr, count > 0 else { return [] }
    return Array(UnsafeBufferPointer(start: ptr, count: count))
}
