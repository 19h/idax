internal import CIDAX

/// A private holder whose native value expires at the end of its database
/// session. The holder itself remains valid until ARC releases it.
internal final class NativeResource {
  private let holder: UnsafeMutableRawPointer

  internal init(
    taking value: UnsafeMutableRawPointer,
    release: @convention(c) (UnsafeMutableRawPointer?) -> Void,
    databaseBound: Bool = true,
    operation: String
  ) throws(IDAError) {
    var output: UnsafeMutableRawPointer?
    try bridgeCall(operation) {
      idax_swift_resource_adopt(value, release, databaseBound ? 1 : 0, &output, $0)
    }
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Native resource adoption returned no holder",
        context: operation)
    }
    holder = output
  }

  internal func pointer(_ operation: String) throws(IDAError) -> UnsafeMutableRawPointer {
    var output: UnsafeMutableRawPointer?
    try bridgeCall(operation) { idax_swift_resource_get(holder, &output, $0) }
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Native resource holder returned no value",
        context: operation)
    }
    return output
  }

  internal func close(_ operation: String) throws(IDAError) {
    try bridgeCall(operation) { idax_swift_resource_close(holder, $0) }
  }

  internal func isOpen(_ operation: String) throws(IDAError) -> Bool {
    var output: Int32 = 0
    try bridgeCall(operation) { idax_swift_resource_is_open(holder, &output, $0) }
    return output != 0
  }

  internal func withPinned<Value>(
    _ operation: String,
    _ body: (UnsafeMutableRawPointer) throws(IDAError) -> Value
  ) throws(IDAError) -> Value {
    var output: UnsafeMutableRawPointer?
    try bridgeCall(operation) { idax_swift_resource_pin(holder, &output, $0) }
    defer { idax_swift_resource_unpin(holder) }
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Pinned native resource has no value", context: operation
      )
    }
    return try body(output)
  }

  internal func close(
    _ operation: String,
    using body:
      @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<IdaxSwiftError>?) -> Int32
  ) throws(IDAError) {
    try bridgeCall(operation) { idax_swift_resource_close_with(holder, body, $0) }
  }

  deinit { idax_swift_resource_release(holder) }
}
