internal import CIDAX
internal import Foundation

extension Data {
  public static func configureStringList(_ options: StringListOptions) throws(IDAError) {
    try configureStringList(stringTypes: options.stringTypes, minimumLength: options.minimumLength,
                            only7bit: options.only7bit, ignoreInstructions: options.ignoreInstructions,
                            displayOnlyExistingStrings: options.displayOnlyExistingStrings)
  }
  /// Semantic values materialized using an IDA type. String reads also retain
  /// the full source byte array, including its terminator and trailing bytes.
  public indirect enum TypedValue: Equatable, Sendable {
    case unsignedInteger(UInt64)
    case signedInteger(Int64)
    case floatingPoint(Double)
    case pointer(Address)
    case string(String, originalBytes: [UInt8] = [])
    case bytes([UInt8])
    case array([TypedValue])

    public var kind: TypedValueKind {
      switch self {
      case .unsignedInteger: return .unsignedInteger
      case .signedInteger: return .signedInteger
      case .floatingPoint: return .floatingPoint
      case .pointer: return .pointer
      case .string: return .string
      case .bytes: return .bytes
      case .array: return .array
      }
    }

    internal init(copying value: IdaxSwiftDataValue, _ operation: String, depth: Int = 0)
      throws(IDAError)
    {
      guard depth <= 64 else {
        throw IDAError(
          category: .internalError, message: "Native typed-value depth exceeds the supported limit",
          context: operation)
      }
      let kind = try checkedEnum(TypedValueKind.self, value.kind, operation)
      switch kind {
      case .unsignedInteger: self = .unsignedInteger(value.unsigned_value)
      case .signedInteger: self = .signedInteger(value.signed_value)
      case .floatingPoint: self = .floatingPoint(value.floating_value)
      case .pointer: self = .pointer(value.pointer_value)
      case .string:
        let text = Array(try checkedBuffer(value.text, count: value.text_count, operation))
        guard let string = String(bytes: text, encoding: .utf8) else {
          throw IDAError(
            category: .internalError, message: "Typed string is not valid UTF-8", context: operation
          )
        }
        self = .string(
          string,
          originalBytes: Array(try checkedBuffer(value.bytes, count: value.byte_count, operation)))
      case .bytes:
        self = .bytes(Array(try checkedBuffer(value.bytes, count: value.byte_count, operation)))
      case .array:
        let values = try checkedBuffer(value.elements, count: value.element_count, operation)
        var elements: [TypedValue] = []
        elements.reserveCapacity(values.count)
        for element in values {
          elements.append(try TypedValue(copying: element, operation, depth: depth + 1))
        }
        self = .array(elements)
      }
    }

    internal func native(in arena: InputArena, _ operation: String, depth: Int = 0) throws(IDAError)
      -> IdaxSwiftDataValue
    {
      guard depth <= 64 else {
        throw IDAError(
          category: .validation, message: "Maximum typed-value recursion depth exceeded",
          context: operation)
      }
      var value = IdaxSwiftDataValue()
      value.kind = kind.rawValue
      switch self {
      case .unsignedInteger(let number): value.unsigned_value = number
      case .signedInteger(let number): value.signed_value = number
      case .floatingPoint(let number): value.floating_value = number
      case .pointer(let address): value.pointer_value = address
      case .string(let string, let bytes):
        let text = Array(string.utf8)
        value.text = arena.array(text)
        value.text_count = text.count
        value.bytes = arena.array(bytes)
        value.byte_count = bytes.count
      case .bytes(let bytes):
        value.bytes = arena.array(bytes)
        value.byte_count = bytes.count
      case .array(let elements):
        var values: [IdaxSwiftDataValue] = []
        values.reserveCapacity(elements.count)
        for element in elements {
          values.append(try element.native(in: arena, operation, depth: depth + 1))
        }
        value.elements = arena.array(values)
        value.element_count = values.count
      }
      return value
    }
  }

  public static func readTyped(address: Address, type: TypeInfo) throws(IDAError) -> TypedValue {
    let operation = "Data.readTyped"
    return try type.withHandle(operation) { (handle) throws(IDAError) -> TypedValue in
      var output = IdaxSwiftDataValue()
      defer { idax_swift_data_value_free(&output) }
      try bridgeCall(operation) { idax_swift_data_read_typed(address, handle, &output, $0) }
      return try TypedValue(copying: output, operation)
    }
  }

  public static func writeTyped(address: Address, type: TypeInfo, value: TypedValue)
    throws(IDAError)
  {
    let operation = "Data.writeTyped"
    let arena = InputArena()
    defer { withExtendedLifetime(arena) {} }
    var native = try value.native(in: arena, operation)
    try type.withHandle(operation) { (handle) throws(IDAError) in
      try bridgeCall(operation) { idax_swift_data_write_typed(address, handle, &native, $0) }
    }
  }

  /// Reads converted string text; zero maximum length lets IDA infer its size.
  public static func readString(
    address: Address, maxLength: AddressSize = 0,
    stringType: Int32 = 0, conversionFlags: Int32 = 0
  ) throws(IDAError) -> String {
    let operation = "Data.readString"
    var output: UnsafeMutablePointer<UInt8>?
    var count = 0
    defer { idax_free_bytes(output) }
    try bridgeCall(operation) {
      idax_swift_data_read_string(
        address, maxLength, stringType, conversionFlags, &output, &count, $0)
    }
    let bytes = Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
    guard let result = String(bytes: bytes, encoding: .utf8) else {
      throw IDAError(
        category: .internalError, message: "Native string output is not valid UTF-8",
        context: operation)
    }
    return result
  }

  public static func findBinaryPattern(
    start: Address, end: Address, pattern: String,
    forward: Bool = true, skipStart: Bool = false,
    caseSensitive: Bool = true, radix: Int32 = 16,
    stringLiteralEncoding: Int32 = 0
  ) throws(IDAError) -> Address {
    let operation = "Data.findBinaryPattern"
    var output = badAddress
    try validateCString(pattern, operation)
    try bridgeCall(operation) { error in
      pattern.withCString {
        idax_swift_data_find_binary_pattern(
          start, end, $0, forward ? 1 : 0,
          skipStart ? 1 : 0, caseSensitive ? 1 : 0, radix, stringLiteralEncoding, &output, error)
      }
    }
    return output
  }

  /// Reads a value using its explicit byte codec. Built-in scalar codecs use
  /// native host memory order, matching C++ read_value<T>().
  public static func readValue<Value: BinaryValue>(
    address: Address, as type: Value.Type = Value.self
  ) throws(IDAError) -> Value {
    let operation = "Data.readValue"
    let count = Value.byteCount
    guard count > 0 else {
      throw IDAError(
        category: .validation, message: "Binary value byte count must be positive",
        context: operation)
    }
    return try Value.decodeNativeBytes(readBytes(address: address, count: UInt64(count)))
  }

  /// Writes a value using its explicit byte codec; native scalar codecs do
  /// not change endianness to match the database processor.
  public static func writeValue<Value: BinaryValue>(address: Address, value: Value) throws(IDAError)
  {
    let operation = "Data.writeValue"
    let bytes = value.nativeBytes()
    let count = Value.byteCount
    guard count > 0, bytes.count == count else {
      throw IDAError(
        category: .validation, message: "Binary value codec returned an invalid byte count",
        context: operation)
    }
    try writeBytes(address: address, data: bytes)
  }
}

/// An owned-byte representation for scalar or application-defined values.
/// Custom codecs can validate layouts without exposing unsafe memory pointers.
public protocol BinaryValue {
  static var byteCount: Int { get }
  static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self
  func nativeBytes() -> [UInt8]
}

// These helpers are instantiated only for the built-in scalar conformances
// below; application-defined codecs provide their own decoding implementation.
private func decodeScalar<Value>(_ bytes: [UInt8], initial: Value) throws(IDAError) -> Value {
  guard bytes.count == MemoryLayout<Value>.size else {
    throw IDAError(
      category: .validation, message: "Scalar byte count does not match its native size",
      context: "BinaryValue.decodeNativeBytes")
  }
  var value = initial
  bytes.withUnsafeBytes { input in withUnsafeMutableBytes(of: &value) { $0.copyMemory(from: input) }
  }
  return value
}
private func scalarBytes<Value>(_ value: Value) -> [UInt8] {
  withUnsafeBytes(of: value) { Array($0) }
}

extension UInt8: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension UInt16: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension UInt32: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension UInt64: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension UInt: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Int8: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Int16: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Int32: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Int64: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Int: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Float: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Double: BinaryValue {
  public static var byteCount: Int { MemoryLayout<Self>.size }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    try decodeScalar(bytes, initial: Self.zero)
  }
  public func nativeBytes() -> [UInt8] { scalarBytes(self) }
}
extension Bool: BinaryValue {
  public static var byteCount: Int { 1 }
  public static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    guard bytes.count == 1, bytes[0] <= 1 else {
      throw IDAError(
        category: .validation, message: "Boolean byte representation must be 0 or 1",
        context: "BinaryValue.decodeNativeBytes")
    }
    return bytes[0] != 0
  }
  public func nativeBytes() -> [UInt8] { [self ? 1 : 0] }
}
