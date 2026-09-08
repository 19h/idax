internal import CIDAX

/// Structured failure reported by IDAX or by its Swift boundary.
public struct IDAError: Error, Equatable, Sendable, CustomStringConvertible {
  public enum Category: String, Sendable, CaseIterable {
    case validation, notFound, conflict, unsupported, sdkFailure, internalError
  }

  public let category: Category
  public let code: Int32
  public let message: String
  public let context: String

  public init(category: Category, code: Int32 = 0, message: String, context: String = "") {
    self.category = category
    self.code = code
    self.message = message
    self.context = context
  }

  public var description: String {
    context.isEmpty
      ? "[\(category.rawValue)] \(message)" : "[\(category.rawValue)] \(message) [\(context)]"
  }

  internal static func category(fromNative value: Int32) -> Category {
    switch value {
    case Int32(IDAX_ERROR_VALIDATION): .validation
    case Int32(IDAX_ERROR_NOT_FOUND): .notFound
    case Int32(IDAX_ERROR_CONFLICT): .conflict
    case Int32(IDAX_ERROR_UNSUPPORTED): .unsupported
    case Int32(IDAX_ERROR_SDK_FAILURE): .sdkFailure
    default: .internalError
    }
  }
}

internal func checkStatus(_ status: Int32, _ operation: String) throws(IDAError) {
  guard status != 0 else { return }
  let category = idax_last_error_category()
  let code = idax_last_error_code()
  let message = idax_last_error_message_only().flatMap { String(validatingCString: $0) }
  let context = idax_last_error_context().flatMap { String(validatingCString: $0) }
  throw IDAError(
    category: category == Int32(IDAX_ERROR_NONE)
      ? .sdkFailure : IDAError.category(fromNative: category),
    code: code,
    message: message ?? "Native operation failed without a valid UTF-8 diagnostic",
    context: category == Int32(IDAX_ERROR_NONE) ? operation : context ?? operation
  )
}

internal func bridgeCall(
  _ operation: String,
  _ body: (UnsafeMutablePointer<IdaxSwiftError>) -> Int32
) throws(IDAError) {
  var error = IdaxSwiftError()
  defer { idax_swift_error_free(&error) }
  let status = body(&error)
  try checkBridgeStatus(status, error, operation)
}

internal func checkBridgeStatus(
  _ status: Int32, _ error: IdaxSwiftError, _ operation: String
) throws(IDAError) {
  guard status != 0 else { return }
  let message = error.message.flatMap { String(validatingCString: $0) }
  let context = error.context.flatMap { String(validatingCString: $0) }
  throw IDAError(
    category: IDAError.category(fromNative: error.category),
    code: error.code,
    message: message ?? "Native bridge failed without a valid UTF-8 diagnostic",
    context: (1...6).contains(error.category) ? context ?? operation : operation
  )
}
