internal import CIDAX

internal func requireRuntimeThread(_ operation: String) throws(IDAError) {
  try bridgeCall(operation) { idax_swift_require_runtime_thread($0) }
}

internal func withOutput<Value>(
  _ operation: String,
  initial: Value,
  _ body: (UnsafeMutablePointer<Value>) -> Int32
) throws(IDAError) -> Value {
  try requireRuntimeThread(operation)
  var output = initial
  try checkStatus(body(&output), operation)
  return output
}

internal func withStringOutput(
  _ operation: String,
  _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
) throws(IDAError) -> String {
  try requireRuntimeThread(operation)
  var output: UnsafeMutablePointer<CChar>?
  defer { idax_free_string(output) }
  try checkStatus(body(&output), operation)
  return try borrowCString(output.map { UnsafePointer($0) }, operation)
}

internal func borrowCString(
  _ pointer: UnsafePointer<CChar>?,
  _ operation: String
) throws(IDAError) -> String {
  guard let pointer else {
    throw IDAError(
      category: .internalError, message: "Native string output is null", context: operation)
  }
  guard let result = String(validatingCString: pointer) else {
    throw IDAError(
      category: .internalError, message: "Native string is not valid UTF-8", context: operation)
  }
  return result
}

internal func takeCString(
  _ pointer: UnsafeMutablePointer<CChar>?,
  _ operation: String
) throws(IDAError) -> String {
  defer { idax_free_string(pointer) }
  return try borrowCString(pointer.map { UnsafePointer($0) }, operation)
}

internal func checkedCString<Value>(
  _ value: String,
  _ operation: String,
  _ body: (UnsafePointer<CChar>) -> Value
) throws(IDAError) -> Value {
  guard !value.utf8.contains(0) else {
    throw IDAError(
      category: .validation, message: "String contains an embedded NUL byte", context: operation)
  }
  return value.withCString(body)
}

internal func checkedCStringArray<Value>(
  _ values: [String], _ operation: String,
  _ body: (UnsafePointer<UnsafePointer<CChar>?>?, Int) -> Value
) throws(IDAError) -> Value {
  guard !values.contains(where: { $0.utf8.contains(0) }) else {
    throw IDAError(
      category: .validation, message: "String contains an embedded NUL byte", context: operation)
  }
  let storage: [UnsafeMutablePointer<CChar>] = values.map { value in
    let bytes = Array(value.utf8CString)
    let pointer = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count)
    pointer.initialize(from: bytes, count: bytes.count)
    return pointer
  }
  defer { storage.forEach { $0.deallocate() } }
  let pointers: [UnsafePointer<CChar>?] = storage.map { UnsafePointer($0) }
  return pointers.withUnsafeBufferPointer { body($0.baseAddress, $0.count) }
}

internal func checkedBuffer<Element>(
  _ pointer: UnsafePointer<Element>?, count: Int, _ operation: String
) throws(IDAError) -> UnsafeBufferPointer<Element> {
  guard count >= 0, count <= Int.max / max(1, MemoryLayout<Element>.stride) else {
    throw IDAError(
      category: .internalError, message: "Native array extent is invalid", context: operation)
  }
  guard count == 0 || pointer != nil else {
    throw IDAError(
      category: .internalError, message: "Native array is null with a nonzero count",
      context: operation)
  }
  return UnsafeBufferPointer(start: pointer, count: count)
}

internal func withByteOutput(
  _ operation: String,
  _ body: (UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, UnsafeMutablePointer<Int>) -> Int32
) throws(IDAError) -> [UInt8] {
  try requireRuntimeThread(operation)
  var output: UnsafeMutablePointer<UInt8>?
  var count = 0
  defer { idax_free_bytes(output) }
  try checkStatus(body(&output, &count), operation)
  return Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
}

internal func copyNativeStrings(
  _ pointer: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, count: Int,
  _ operation: String
) throws(IDAError) -> [String] {
  let buffer = try checkedBuffer(pointer.map { UnsafePointer($0) }, count: count, operation)
  var result: [String] = []
  result.reserveCapacity(count)
  for value in buffer {
    result.append(try borrowCString(value.map { UnsafePointer($0) }, operation))
  }
  return result
}
