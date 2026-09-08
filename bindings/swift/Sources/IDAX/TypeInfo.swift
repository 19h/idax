internal import CIDAX

public typealias Address = UInt64
public typealias AddressDelta = Int64
public typealias AddressSize = UInt64
public let badAddress: Address = .max

/// An owned type value. SDK access is confined to the runtime thread.
/// Copy explicitly before independently mutating a second type value.
public final class TypeInfo {
  private let holder: UnsafeMutableRawPointer

  /// Constructs the canonical unspecified type value.
  public convenience init() throws(IDAError) {
    var output: UnsafeMutableRawPointer?
    try bridgeCall("TypeInfo.init") { idax_swift_type_default(&output, $0) }
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Default type output is null", context: "TypeInfo.init")
    }
    try self.init(owning: output)
  }

  internal init(owning handle: UnsafeMutableRawPointer) throws(IDAError) {
    var output: UnsafeMutableRawPointer?
    try bridgeCall("TypeInfo.init") {
      idax_swift_resource_adopt(handle, idax_type_free, 1, &output, $0)
    }
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Native resource holder is null",
        context: "TypeInfo.init")
    }
    holder = output
  }

  internal func checkedHandle(_ operation: String) throws(IDAError) -> UnsafeMutableRawPointer {
    var handle: UnsafeMutableRawPointer?
    try bridgeCall(operation) { idax_swift_resource_get(holder, &handle, $0) }
    guard let handle else {
      throw IDAError(
        category: .internalError, message: "Native type handle is null", context: operation)
    }
    return handle
  }

  internal func withHandle<Value>(
    _ operation: String,
    _ body: (UnsafeMutableRawPointer) throws(IDAError) -> Value
  ) throws(IDAError) -> Value {
    try Self.withHandles([self], operation) { (handles) throws(IDAError) -> Value in
      try body(handles[0])
    }
  }

  internal static func withHandles<Value>(
    _ types: [TypeInfo], _ operation: String,
    _ body: ([UnsafeMutableRawPointer]) throws(IDAError) -> Value
  ) throws(IDAError) -> Value {
    var holders: [UnsafeMutableRawPointer] = []
    var handles: [UnsafeMutableRawPointer] = []
    defer {
      for holder in holders.reversed() { idax_swift_resource_unpin(holder) }
      withExtendedLifetime(types) {}
    }
    for type in types {
      var pointer: UnsafeMutableRawPointer?
      try bridgeCall(operation) { idax_swift_resource_pin(type.holder, &pointer, $0) }
      holders.append(type.holder)
      guard let pointer else {
        throw IDAError(
          category: .internalError, message: "Pinned type output is null", context: operation)
      }
      handles.append(pointer)
    }
    return try body(handles)
  }

  public func close() throws(IDAError) {
    try bridgeCall("TypeInfo.close") { idax_swift_resource_close(holder, $0) }
  }

  deinit { idax_swift_resource_release(holder) }

  internal static func taking(_ handle: UnsafeMutableRawPointer?, _ operation: String)
    throws(IDAError) -> TypeInfo
  {
    guard let handle else {
      throw IDAError(
        category: .internalError, message: "Native type output is null", context: operation)
    }
    return try TypeInfo(owning: handle)
  }

  internal static func output(
    _ operation: String, _ body: (UnsafeMutablePointer<UnsafeMutableRawPointer?>) -> Int32
  ) throws(IDAError) -> TypeInfo {
    let handle = try withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none, body)
    return try taking(handle, operation)
  }

  public static func voidType() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.voidType")
    return try taking(idax_type_void(), "TypeInfo.voidType")
  }

  public static func int8() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.int8")
    return try taking(idax_type_int8(), "TypeInfo.int8")
  }

  public static func int16() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.int16")
    return try taking(idax_type_int16(), "TypeInfo.int16")
  }

  public static func int32() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.int32")
    return try taking(idax_type_int32(), "TypeInfo.int32")
  }

  public static func int64() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.int64")
    return try taking(idax_type_int64(), "TypeInfo.int64")
  }

  public static func uint8() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.uint8")
    return try taking(idax_type_uint8(), "TypeInfo.uint8")
  }

  public static func uint16() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.uint16")
    return try taking(idax_type_uint16(), "TypeInfo.uint16")
  }

  public static func uint32() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.uint32")
    return try taking(idax_type_uint32(), "TypeInfo.uint32")
  }

  public static func uint64() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.uint64")
    return try taking(idax_type_uint64(), "TypeInfo.uint64")
  }

  public static func float32() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.float32")
    return try taking(idax_type_float32(), "TypeInfo.float32")
  }

  public static func float64() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.float64")
    return try taking(idax_type_float64(), "TypeInfo.float64")
  }

  public static func structure() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.structure")
    return try taking(idax_type_create_struct(), "TypeInfo.structure")
  }

  public static func unionType() throws(IDAError) -> TypeInfo {
    try requireRuntimeThread("TypeInfo.unionType")
    return try taking(idax_type_create_union(), "TypeInfo.unionType")
  }

  public static func named(_ value: String) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.named"
    var result: UnsafeMutableRawPointer?
    try requireRuntimeThread(operation)
    let status = try checkedCString(value, operation) { idax_type_by_name($0, &result) }
    try checkStatus(status, operation)
    return try taking(result, operation)
  }

  public static func parse(_ value: String) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.parse"
    var result: UnsafeMutableRawPointer?
    try requireRuntimeThread(operation)
    let status = try checkedCString(value, operation) { idax_type_from_declaration($0, &result) }
    try checkStatus(status, operation)
    return try taking(result, operation)
  }

  public func isVoid() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isVoid") { (handle) throws(IDAError) -> Bool in
      idax_type_is_void(handle) != 0
    }
  }

  public func isInteger() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isInteger") { (handle) throws(IDAError) -> Bool in
      idax_type_is_integer(handle) != 0
    }
  }

  public func isFloatingPoint() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isFloatingPoint") { (handle) throws(IDAError) -> Bool in
      idax_type_is_floating_point(handle) != 0
    }
  }

  public func isPointer() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isPointer") { (handle) throws(IDAError) -> Bool in
      idax_type_is_pointer(handle) != 0
    }
  }

  public func isArray() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isArray") { (handle) throws(IDAError) -> Bool in
      idax_type_is_array(handle) != 0
    }
  }

  public func isFunction() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isFunction") { (handle) throws(IDAError) -> Bool in
      idax_type_is_function(handle) != 0
    }
  }

  public func isStruct() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isStruct") { (handle) throws(IDAError) -> Bool in
      idax_type_is_struct(handle) != 0
    }
  }

  public func isUnion() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isUnion") { (handle) throws(IDAError) -> Bool in
      idax_type_is_union(handle) != 0
    }
  }

  public func isEnum() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isEnum") { (handle) throws(IDAError) -> Bool in
      idax_type_is_enum(handle) != 0
    }
  }

  public func isTypedef() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isTypedef") { (handle) throws(IDAError) -> Bool in
      idax_type_is_typedef(handle) != 0
    }
  }

  public func isBool() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isBool") { (handle) throws(IDAError) -> Bool in
      idax_type_is_bool(handle) != 0
    }
  }

  public func isChar() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isChar") { (handle) throws(IDAError) -> Bool in
      idax_type_is_char(handle) != 0
    }
  }

  public func isUnsignedChar() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isUnsignedChar") { (handle) throws(IDAError) -> Bool in
      idax_type_is_unsigned_char(handle) != 0
    }
  }

  public func isSigned() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isSigned") { (handle) throws(IDAError) -> Bool in
      idax_type_is_signed(handle) != 0
    }
  }

  public func isForwardDeclaration() throws(IDAError) -> Bool {
    try withHandle("TypeInfo.isForwardDeclaration") { (handle) throws(IDAError) -> Bool in
      idax_type_is_forward_declaration(handle) != 0
    }
  }

  public func copy() throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.copy"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      return try TypeInfo.output(operation) { idax_type_clone(handle, $0) }
    }
  }

  public func pointeeType() throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.pointeeType"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      return try TypeInfo.output(operation) { idax_type_pointee_type(handle, $0) }
    }
  }

  public func arrayElementType() throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.arrayElementType"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      return try TypeInfo.output(operation) { idax_type_array_element_type(handle, $0) }
    }
  }

  public func resolvingTypedef() throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.resolvingTypedef"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      return try TypeInfo.output(operation) { idax_type_resolve_typedef(handle, $0) }
    }
  }

  public func functionReturnType() throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.functionReturnType"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      return try TypeInfo.output(operation) { idax_type_function_return_type(handle, $0) }
    }
  }

  public func name() throws(IDAError) -> String {
    let operation = "TypeInfo.name"
    return try withHandle(operation) { (handle) throws(IDAError) -> String in
      return try withStringOutput(operation) { idax_type_name(handle, $0) }
    }
  }

  public func render() throws(IDAError) -> String {
    let operation = "TypeInfo.render"
    return try withHandle(operation) { (handle) throws(IDAError) -> String in
      return try withStringOutput(operation) { idax_type_to_string(handle, $0) }
    }
  }

  public func size() throws(IDAError) -> Int {
    let operation = "TypeInfo.size"
    return try withHandle(operation) { (handle) throws(IDAError) -> Int in
      return try withOutput(operation, initial: 0) { idax_type_size(handle, $0) }
    }
  }

  public func arrayLength() throws(IDAError) -> Int {
    let operation = "TypeInfo.arrayLength"
    return try withHandle(operation) { (handle) throws(IDAError) -> Int in
      return try withOutput(operation, initial: 0) { idax_type_array_length(handle, $0) }
    }
  }

  public func memberCount() throws(IDAError) -> Int {
    let operation = "TypeInfo.memberCount"
    return try withHandle(operation) { (handle) throws(IDAError) -> Int in
      return try withOutput(operation, initial: 0) { idax_type_member_count(handle, $0) }
    }
  }

  public func kind() throws(IDAError) -> TypeKind {
    let operation = "TypeInfo.kind"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeKind in
      let value = try withOutput(operation, initial: Int32(0)) { idax_type_kind(handle, $0) }
      return try checkedEnum(TypeKind.self, value, operation)
    }
  }

  public func forwardDeclarationKind() throws(IDAError) -> TypeKind {
    let operation = "TypeInfo.forwardDeclarationKind"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeKind in
      let value = try withOutput(operation, initial: Int32(0)) {
        idax_type_forward_declaration_kind(handle, $0)
      }
      return try checkedEnum(TypeKind.self, value, operation)
    }
  }

  public func callingConvention() throws(IDAError) -> CallingConvention {
    let operation = "TypeInfo.callingConvention"
    return try withHandle(operation) { (handle) throws(IDAError) -> CallingConvention in
      let value = try withOutput(operation, initial: Int32(0)) {
        idax_type_calling_convention(handle, $0)
      }
      return try checkedEnum(CallingConvention.self, value, operation)
    }
  }

  public static func pointer(to target: TypeInfo) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.pointer"
    return try target.withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      try taking(idax_type_pointer_to(handle), operation)
    }
  }

  public static func array(of element: TypeInfo, count: Int) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.array"
    try requireNonnegative(count, operation)
    return try element.withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      try taking(idax_type_array_of(handle, count), operation)
    }
  }

  public static func function(
    returnType: TypeInfo, arguments: [TypeInfo] = [], convention: CallingConvention = .unknown,
    variadic: Bool = false
  ) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.function"
    return try withHandles([returnType] + arguments, operation) {
      (handles) throws(IDAError) -> TypeInfo in
      let argumentHandles = handles.dropFirst().map { Optional($0) }
      return try output(operation) { output in
        argumentHandles.withUnsafeBufferPointer {
          idax_type_function_type(
            handles[0], $0.baseAddress, $0.count, convention.rawValue, variadic ? 1 : 0, output)
        }
      }
    }
  }

  public func declaration(named name: String = "") throws(IDAError) -> String {
    let operation = "TypeInfo.declaration"
    return try withHandle(operation) { (handle) throws(IDAError) -> String in
      var output: UnsafeMutablePointer<CChar>?
      defer { idax_free_string(output) }
      try checkStatus(
        checkedCString(name, operation) { idax_type_declaration(handle, $0, &output) }, operation)
      return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
  }

  public func apply(at address: Address) throws(IDAError) {
    try withHandle("TypeInfo.apply") { (handle) throws(IDAError) in
      try checkStatus(idax_type_apply(handle, address), "TypeInfo.apply")
    }
  }

  public func save(as name: String) throws(IDAError) {
    let operation = "TypeInfo.save"
    return try withHandle(operation) { (handle) throws(IDAError) -> Void in
      try checkStatus(checkedCString(name, operation) { idax_type_save_as(handle, $0) }, operation)
    }
  }

  public func addMember(named name: String, type: TypeInfo, byteOffset: Int = 0) throws(IDAError) {
    let operation = "TypeInfo.addMember"
    try requireNonnegative(byteOffset, operation)
    try Self.withHandles([self, type], operation) { (handles) throws(IDAError) in
      try checkStatus(
        checkedCString(name, operation) {
          idax_type_add_member(handles[0], $0, handles[1], byteOffset)
        }, operation)
    }
  }

  public func withShiftedParent(_ parent: TypeInfo, byteDelta: Int64) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.withShiftedParent"
    return try Self.withHandles([self, parent], operation) {
      (handles) throws(IDAError) -> TypeInfo in
      try TypeInfo.output(operation) {
        idax_type_with_shifted_parent(handles[0], handles[1], byteDelta, $0)
      }
    }
  }

  public func withFunctionArgumentType(at index: Int, replacement: TypeInfo) throws(IDAError)
    -> TypeInfo
  {
    let operation = "TypeInfo.withFunctionArgumentType"
    try requireNonnegative(index, operation)
    return try Self.withHandles([self, replacement], operation) {
      (handles) throws(IDAError) -> TypeInfo in
      try TypeInfo.output(operation) {
        idax_type_with_function_argument_type(handles[0], index, handles[1], $0)
      }
    }
  }

  public func withFunctionArgumentName(at index: Int, name: String) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.withFunctionArgumentName"
    try requireNonnegative(index, operation)
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      var output: UnsafeMutableRawPointer?
      try checkStatus(
        checkedCString(name, operation) {
          idax_type_with_function_argument_name(handle, index, $0, &output)
        }, operation)
      return try TypeInfo.taking(output, operation)
    }
  }

  public func withFunctionReturnType(_ replacement: TypeInfo) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.withFunctionReturnType"
    return try Self.withHandles([self, replacement], operation) {
      (handles) throws(IDAError) -> TypeInfo in
      try TypeInfo.output(operation) {
        idax_type_with_function_return_type(handles[0], handles[1], $0)
      }
    }
  }

  public func replacingForwardDeclaration(named name: String) throws(IDAError) -> TypeInfo {
    let operation = "TypeInfo.replacingForwardDeclaration"
    return try withHandle(operation) { (handle) throws(IDAError) -> TypeInfo in
      var output: UnsafeMutableRawPointer?
      try checkStatus(
        checkedCString(name, operation) {
          idax_type_replace_forward_declaration(handle, $0, &output)
        }, operation)
      return try TypeInfo.taking(output, operation)
    }
  }

  public func isVariadicFunction() throws(IDAError) -> Bool {
    let operation = "TypeInfo.isVariadicFunction"
    return try withHandle(operation) { (handle) throws(IDAError) -> Bool in
      return try withOutput(operation, initial: Int32(0)) {
        idax_type_is_variadic_function(handle, $0)
      } != 0
    }
  }

  public func setUDTSemantics(isCPPObject: Bool, isVFTable: Bool) throws(IDAError) {
    let operation = "TypeInfo.setUDTSemantics"
    try withHandle(operation) { (handle) throws(IDAError) in
      try checkStatus(
        idax_type_set_udt_semantics(handle, isCPPObject ? 1 : 0, isVFTable ? 1 : 0), operation)
    }
  }
}

public enum CallingConvention: Int32, CaseIterable, Sendable {
  case unknown, cdecl, stdcall, pascal, fastcall, thiscall, swift, golang, userDefined
}
public enum TypeKind: Int32, CaseIterable, Sendable {
  case unknown, void, bool, character, signedInteger, unsignedInteger, floatingPoint
  case pointer, array, function, `struct`, union, `enum`, typedef
}
public enum EnumRadix: Int32, CaseIterable, Sendable {
  case unknown, binary, octal, decimal, hexadecimal
}

internal func checkedEnum<T: RawRepresentable>(_ type: T.Type, _ value: Int32, _ operation: String)
  throws(IDAError) -> T where T.RawValue == Int32
{
  guard let result = T(rawValue: value) else {
    throw IDAError(
      category: .internalError, message: "Unknown native enum value: \(value)", context: operation)
  }
  return result
}

internal func requireNonnegative(_ value: Int, _ operation: String) throws(IDAError) {
  guard value >= 0 else {
    throw IDAError(category: .validation, message: "Size or index is negative", context: operation)
  }
}
