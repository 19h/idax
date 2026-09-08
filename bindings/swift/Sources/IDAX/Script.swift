internal import CIDAX
internal import Foundation

/// Owned IDC values, compilation, and synchronous script execution.
public enum Script {
  public enum ValueKind: Int32, Sendable {
    case integer = 0, floatingPoint, object, function, string, opaquePointer, reference
  }
  public enum DereferenceMode: Int32, Sendable { case once = 0, recursive = 1 }

  public struct ResolvedName: Equatable, Sendable {
    public var name: String
    public var value: UInt64
    public init(name: String, value: UInt64) {
      self.name = name
      self.value = value
    }
  }
  public struct CompileOptions: Equatable, Sendable {
    public var onlySafeFunctions: Bool
    public var resolvedNames: [ResolvedName]
    public init(onlySafeFunctions: Bool = false, resolvedNames: [ResolvedName] = []) {
      self.onlySafeFunctions = onlySafeFunctions
      self.resolvedNames = resolvedNames
    }
  }
  public struct FileCompileOptions: Equatable, Sendable {
    public var deleteMacrosAfterCompilation: Bool
    public var allowProgramLabels: Bool
    public var onlySafeFunctions: Bool
    public init(
      deleteMacrosAfterCompilation: Bool = true, allowProgramLabels: Bool = true,
      onlySafeFunctions: Bool = false
    ) {
      self.deleteMacrosAfterCompilation = deleteMacrosAfterCompilation
      self.allowProgramLabels = allowProgramLabels
      self.onlySafeFunctions = onlySafeFunctions
    }
    internal var native: IdaxScriptFileCompileOptions {
      .init(
        delete_macros_after_compilation: deleteMacrosAfterCompilation ? 1 : 0,
        allow_program_labels: allowProgramLabels ? 1 : 0,
        only_safe_functions: onlySafeFunctions ? 1 : 0)
    }
  }
  public struct CompilationResult: Equatable, Sendable {
    public let succeeded: Bool
    public let error: String
    public init(succeeded: Bool = false, error: String = "") {
      self.succeeded = succeeded; self.error = error
    }
  }
  /// An unsuccessful execution retains the native exception value.
  public struct ExecutionResult {
    public let succeeded: Bool
    public let value: Value
    public let error: String
    public init(succeeded: Bool = false, value: Value, error: String = "") {
      self.succeeded = succeeded; self.value = value; self.error = error
    }
    public init() throws(IDAError) {
      self.init(value: try Value())
    }
  }
  public struct IntegerExecutionResult: Equatable, Sendable {
    public let succeeded: Bool
    public let value: Int64
    public let error: String
    public init(succeeded: Bool = false, value: Int64 = 0, error: String = "") {
      self.succeeded = succeeded; self.value = value; self.error = error
    }
  }

  public final class Value {
    fileprivate let resource: NativeResource

    fileprivate init(taking pointer: UnsafeMutableRawPointer?, _ operation: String) throws(IDAError)
    {
      guard let pointer else {
        throw IDAError(
          category: .internalError, message: "Native script value is null", context: operation)
      }
      resource = try NativeResource(
        taking: pointer, release: idax_script_value_free, operation: operation)
    }

    public convenience init(integer: Int64 = 0) throws(IDAError) {
      let operation = "Script.Value.init(integer:)"
      let pointer = try withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
        idax_script_value_integer(integer, $0)
      }
      try self.init(taking: pointer, operation)
    }

    /// Preserves embedded NUL bytes through the native length-bearing API.
    public convenience init(string: String) throws(IDAError) {
      let operation = "Script.Value.init(string:)"
      let bytes = Array(string.utf8)
      let pointer = try withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
        output in
        bytes.withUnsafeBufferPointer { idax_script_value_string($0.baseAddress, $0.count, output) }
      }
      try self.init(taking: pointer, operation)
    }

    public static func floating(_ value: Double) throws(IDAError) -> Value {
      let operation = "Script.Value.floating"
      return try Value(
        taking: withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
          idax_script_value_floating(value, $0)
        }, operation)
    }
    public static func object() throws(IDAError) -> Value {
      let operation = "Script.Value.object"
      return try Value(
        taking: withOutput(
          operation, initial: Optional<UnsafeMutableRawPointer>.none, idax_script_value_object),
        operation)
    }
    public func close() throws(IDAError) { try resource.close("Script.Value.close") }
    public func copy() throws(IDAError) -> Value {
      let operation = "Script.Value.copy"
      let pointer = try resource.pointer(operation)
      return try Value(
        taking: withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
          idax_script_value_clone(pointer, $0)
        }, operation)
    }
    public func deepCopy() throws(IDAError) -> Value {
      let operation = "Script.Value.deepCopy"
      let pointer = try resource.pointer(operation)
      return try Value(
        taking: withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
          idax_script_value_deep_copy(pointer, $0)
        }, operation)
    }
    public func kind() throws(IDAError) -> ValueKind {
      let operation = "Script.Value.kind"
      let pointer = try resource.pointer(operation)
      let output = try withOutput(operation, initial: Int32(0)) {
        idax_script_value_kind(pointer, $0)
      }
      guard let result = ValueKind(rawValue: output) else {
        throw IDAError(
          category: .internalError, message: "Unknown IDC value kind", context: operation)
      }
      return result
    }
    public func asInteger() throws(IDAError) -> Int64 {
      let pointer = try resource.pointer("Script.Value.asInteger")
      return try withOutput("Script.Value.asInteger", initial: Int64(0)) {
        idax_script_value_as_integer(pointer, $0)
      }
    }
    public func asFloating() throws(IDAError) -> Double {
      let pointer = try resource.pointer("Script.Value.asFloating")
      return try withOutput("Script.Value.asFloating", initial: 0.0) {
        idax_script_value_as_floating(pointer, $0)
      }
    }
    private func string(
      _ operation: String,
      _ body: (
        UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
        UnsafeMutablePointer<Int>
      ) -> Int32
    ) throws(IDAError) -> String {
      let pointer = try resource.pointer(operation)
      let bytes = try withByteOutput(operation) { body(pointer, $0, $1) }
      guard let result = String(bytes: bytes, encoding: .utf8) else {
        throw IDAError(
          category: .internalError, message: "IDC string is not valid UTF-8", context: operation)
      }
      return result
    }
    public func asString() throws(IDAError) -> String {
      try string("Script.Value.asString", idax_script_value_as_string)
    }
    public func coerceInteger() throws(IDAError) -> Int64 {
      let pointer = try resource.pointer("Script.Value.coerceInteger")
      return try withOutput("Script.Value.coerceInteger", initial: Int64(0)) {
        idax_script_value_coerce_integer(pointer, $0)
      }
    }
    public func coerceFloating() throws(IDAError) -> Double {
      let pointer = try resource.pointer("Script.Value.coerceFloating")
      return try withOutput("Script.Value.coerceFloating", initial: 0.0) {
        idax_script_value_coerce_floating(pointer, $0)
      }
    }
    public func coerceString() throws(IDAError) -> String {
      try string("Script.Value.coerceString", idax_script_value_coerce_string)
    }
    public func render(name: String? = nil, indent: Int = 0) throws(IDAError) -> String {
      let operation = "Script.Value.render"
      guard indent >= 0 else {
        throw IDAError(
          category: .validation, message: "Indent cannot be negative", context: operation)
      }
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutablePointer<CChar>?
      defer { idax_free_string(output) }
      try checkStatus(
        checkedCString(name ?? "", operation) {
          idax_script_value_render(pointer, name == nil ? nil : $0, indent, &output)
        }, operation)
      return try borrowCString(output.map { UnsafePointer($0) }, operation)
    }
    public func className() throws(IDAError) -> String {
      let pointer = try resource.pointer("Script.Value.className")
      return try withStringOutput("Script.Value.className") {
        idax_script_value_class_name(pointer, $0)
      }
    }
    public func attribute(_ name: String, useHandler: Bool = false) throws(IDAError) -> Value {
      let operation = "Script.Value.attribute"
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutableRawPointer?
      try checkStatus(
        checkedCString(name, operation) {
          idax_script_value_attribute(pointer, $0, useHandler ? 1 : 0, &output)
        }, operation)
      return try Value(taking: output, operation)
    }
    public func setAttribute(_ name: String, value: Value, useHandler: Bool = false)
      throws(IDAError)
    {
      let operation = "Script.Value.setAttribute"
      let pointer = try resource.pointer(operation)
      let replacement = try value.resource.pointer(operation)
      try checkStatus(
        checkedCString(name, operation) {
          idax_script_value_set_attribute(pointer, $0, replacement, useHandler ? 1 : 0)
        }, operation)
    }
    public func attributeNames() throws(IDAError) -> [String] {
      let operation = "Script.Value.attributeNames"
      let pointer = try resource.pointer(operation)
      var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
      var count = 0
      defer { idax_script_string_array_free(output, count) }
      try checkStatus(idax_script_value_attribute_names(pointer, &output, &count), operation)
      return try copyNativeStrings(output, count: count, operation)
    }
    @discardableResult public func removeAttribute(_ name: String) throws(IDAError) -> Bool {
      let operation = "Script.Value.removeAttribute"
      let pointer = try resource.pointer(operation)
      var output: Int32 = 0
      try checkStatus(
        checkedCString(name, operation) {
          idax_script_value_remove_attribute(pointer, $0, &output)
        }, operation)
      return output != 0
    }
    public func slice(_ range: Range<Int>) throws(IDAError) -> Value {
      let operation = "Script.Value.slice"
      guard range.lowerBound >= 0 else {
        throw IDAError(
          category: .validation, message: "Slice bounds cannot be negative", context: operation)
      }
      let pointer = try resource.pointer(operation)
      return try Value(
        taking: withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
          idax_script_value_slice(pointer, range.lowerBound, range.upperBound, $0)
        }, operation)
    }
    public func replaceSlice(_ range: Range<Int>, with value: Value) throws(IDAError) {
      let operation = "Script.Value.replaceSlice"
      guard range.lowerBound >= 0 else {
        throw IDAError(
          category: .validation, message: "Slice bounds cannot be negative", context: operation)
      }
      let pointer = try resource.pointer(operation)
      let replacement = try value.resource.pointer(operation)
      try checkStatus(
        idax_script_value_replace_slice(pointer, range.lowerBound, range.upperBound, replacement),
        operation)
    }
    public func dereference(_ mode: DereferenceMode = .recursive) throws(IDAError) -> Value {
      let operation = "Script.Value.dereference"
      let pointer = try resource.pointer(operation)
      return try Value(
        taking: withOutput(operation, initial: Optional<UnsafeMutableRawPointer>.none) {
          idax_script_value_dereference(pointer, mode.rawValue, $0)
        }, operation)
    }
  }

  private static func withNames<Result>(
    _ names: [ResolvedName], strings: [String], _ operation: String,
    _ body: (UnsafePointer<UnsafePointer<CChar>?>?, UnsafePointer<IdaxScriptResolvedName>?, Int) ->
      Result
  ) throws(IDAError) -> Result {
    try checkedCStringArray(strings + names.map(\.name), operation) { pointers, _ in
      let native = names.enumerated().map { index, name in
        IdaxScriptResolvedName(name: pointers![strings.count + index], value: name.value)
      }
      return native.withUnsafeBufferPointer { body(pointers, $0.baseAddress, $0.count) }
    }
  }
  private static func execution(_ output: inout IdaxScriptExecutionResult, _ operation: String)
    throws(IDAError) -> ExecutionResult
  {
    let diagnostic = try borrowCString(output.error.map { UnsafePointer($0) }, operation)
    let pointer = output.value
    output.value = nil
    let value = try Value(taking: pointer, operation)
    return ExecutionResult(succeeded: output.succeeded != 0, value: value, error: diagnostic)
  }
  private static func evaluate(
    _ expression: String, at address: Address, _ operation: String,
    _ body: (UnsafePointer<CChar>?, UInt64, UnsafeMutablePointer<IdaxScriptExecutionResult>) ->
      Int32
  ) throws(IDAError) -> ExecutionResult {
    try requireRuntimeThread(operation)
    var output = IdaxScriptExecutionResult()
    defer { idax_script_execution_result_free(&output) }
    try checkStatus(checkedCString(expression, operation) { body($0, address, &output) }, operation)
    return try execution(&output, operation)
  }
  public static func evaluate(_ expression: String, at address: Address = badAddress)
    throws(IDAError) -> ExecutionResult
  {
    try evaluate(expression, at: address, "Script.evaluate", idax_script_evaluate)
  }
  public static func evaluateIDC(_ expression: String, at address: Address = badAddress)
    throws(IDAError) -> ExecutionResult
  {
    try evaluate(expression, at: address, "Script.evaluateIDC", idax_script_evaluate_idc)
  }
  public static func evaluateInteger(_ expression: String, at address: Address = badAddress)
    throws(IDAError) -> IntegerExecutionResult
  {
    let operation = "Script.evaluateInteger"
    try requireRuntimeThread(operation)
    var output = IdaxScriptIntegerExecutionResult()
    defer { idax_script_integer_execution_result_free(&output) }
    try checkStatus(
      checkedCString(expression, operation) { idax_script_evaluate_integer($0, address, &output) },
      operation)
    return try IntegerExecutionResult(
      succeeded: output.succeeded != 0, value: output.value,
      error: borrowCString(output.error.map { UnsafePointer($0) }, operation))
  }
  public static func compileFile(_ path: String, options: FileCompileOptions = .init())
    throws(IDAError) -> CompilationResult
  {
    let operation = "Script.compileFile"
    try requireRuntimeThread(operation)
    var output = IdaxScriptCompilationResult()
    var native = options.native
    defer { idax_script_compilation_result_free(&output) }
    try checkStatus(
      checkedCString(path, operation) { idax_script_compile_file($0, &native, &output) }, operation)
    return try CompilationResult(
      succeeded: output.succeeded != 0,
      error: borrowCString(output.error.map { UnsafePointer($0) }, operation))
  }
  public static func compileText(_ source: String, options: CompileOptions = .init())
    throws(IDAError) -> CompilationResult
  {
    let operation = "Script.compileText"
    try requireRuntimeThread(operation)
    var output = IdaxScriptCompilationResult()
    defer { idax_script_compilation_result_free(&output) }
    try checkStatus(
      withNames(options.resolvedNames, strings: [source], operation) { strings, names, count in
        var native = IdaxScriptCompileOptions(
          only_safe_functions: options.onlySafeFunctions ? 1 : 0, resolved_names: names,
          resolved_name_count: count)
        return idax_script_compile_text(strings![0], &native, &output)
      }, operation)
    return try CompilationResult(
      succeeded: output.succeeded != 0,
      error: borrowCString(output.error.map { UnsafePointer($0) }, operation))
  }
  public static func compileSnippet(
    functionName: String, body: String, options: CompileOptions = .init()
  ) throws(IDAError) -> CompilationResult {
    let operation = "Script.compileSnippet"
    try requireRuntimeThread(operation)
    var output = IdaxScriptCompilationResult()
    defer { idax_script_compilation_result_free(&output) }
    try checkStatus(
      withNames(options.resolvedNames, strings: [functionName, body], operation) {
        strings, names, count in
        var native = IdaxScriptCompileOptions(
          only_safe_functions: options.onlySafeFunctions ? 1 : 0, resolved_names: names,
          resolved_name_count: count)
        return idax_script_compile_snippet(strings![0], strings![1], &native, &output)
      }, operation)
    return try CompilationResult(
      succeeded: output.succeeded != 0,
      error: borrowCString(output.error.map { UnsafePointer($0) }, operation))
  }
  public static func call(
    _ functionName: String, arguments: [Value] = [], resolvedNames: [ResolvedName] = []
  ) throws(IDAError) -> ExecutionResult {
    let operation = "Script.call"
    try requireRuntimeThread(operation)
    var handles: [UnsafeMutableRawPointer?] = []
    for argument in arguments { handles.append(try argument.resource.pointer(operation)) }
    var output = IdaxScriptExecutionResult()
    defer { idax_script_execution_result_free(&output) }
    try checkStatus(
      withNames(resolvedNames, strings: [functionName], operation) { strings, names, count in
        handles.withUnsafeBufferPointer {
          idax_script_call(strings![0], $0.baseAddress, $0.count, names, count, &output)
        }
      }, operation)
    return try execution(&output, operation)
  }
  public static func executeScript(
    _ path: String, functionName: String, arguments: [Value] = [],
    options: FileCompileOptions = .init()
  ) throws(IDAError) -> ExecutionResult {
    let operation = "Script.executeScript"
    try requireRuntimeThread(operation)
    var handles: [UnsafeMutableRawPointer?] = []
    for argument in arguments { handles.append(try argument.resource.pointer(operation)) }
    var native = options.native
    var output = IdaxScriptExecutionResult()
    defer { idax_script_execution_result_free(&output) }
    try checkStatus(
      checkedCStringArray([path, functionName], operation) { strings, _ in
        handles.withUnsafeBufferPointer {
          idax_script_execute_script(
            strings![0], strings![1], $0.baseAddress, $0.count, &native, &output)
        }
      }, operation)
    return try execution(&output, operation)
  }
  public static func evaluateSnippet(_ source: String, resolvedNames: [ResolvedName] = [])
    throws(IDAError) -> ExecutionResult
  {
    let operation = "Script.evaluateSnippet"
    try requireRuntimeThread(operation)
    var output = IdaxScriptExecutionResult()
    defer { idax_script_execution_result_free(&output) }
    try checkStatus(
      withNames(resolvedNames, strings: [source], operation) { strings, names, count in
        idax_script_evaluate_snippet(strings![0], names, count, &output)
      }, operation)
    return try execution(&output, operation)
  }
  public static func setIncludePaths(_ paths: [String]) throws(IDAError) {
    try requireRuntimeThread("Script.setIncludePaths")
    try checkStatus(
      checkedCStringArray(paths, "Script.setIncludePaths", idax_script_set_include_paths),
      "Script.setIncludePaths")
  }
  public static func appendIncludePaths(_ paths: [String]) throws(IDAError) {
    try requireRuntimeThread("Script.appendIncludePaths")
    try checkStatus(
      checkedCStringArray(paths, "Script.appendIncludePaths", idax_script_append_include_paths),
      "Script.appendIncludePaths")
  }
  public static func resolveFile(_ file: String) throws(IDAError) -> String? {
    let operation = "Script.resolveFile"
    try requireRuntimeThread(operation)
    var output: UnsafeMutablePointer<CChar>?
    var present: Int32 = 0
    defer { idax_free_string(output) }
    try checkStatus(
      checkedCString(file, operation) { idax_script_resolve_file($0, &output, &present) }, operation
    )
    return present == 0 ? nil : try borrowCString(output.map { UnsafePointer($0) }, operation)
  }
  public static func executeSystemScript(_ file: String, complainIfMissing: Bool = false)
    throws(IDAError)
  {
    try requireRuntimeThread("Script.executeSystemScript")
    try checkStatus(
      checkedCString(file, "Script.executeSystemScript") {
        idax_script_execute_system_script($0, complainIfMissing ? 1 : 0)
      }, "Script.executeSystemScript")
  }
  public static func functionNames(prefix: String = "", maximum: Int = 1024) throws(IDAError)
    -> [String]
  {
    let operation = "Script.functionNames"
    guard maximum >= 0 else {
      throw IDAError(
        category: .validation, message: "Maximum cannot be negative", context: operation)
    }
    try requireRuntimeThread(operation)
    var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    var count = 0
    defer { idax_script_string_array_free(output, count) }
    try checkStatus(
      checkedCString(prefix, operation) {
        idax_script_function_names($0, maximum, &output, &count)
      }, operation)
    return try copyNativeStrings(output, count: count, operation)
  }
  public static func global(_ name: String) throws(IDAError) -> Value? {
    let operation = "Script.global"
    try requireRuntimeThread(operation)
    var output: UnsafeMutableRawPointer?
    var present: Int32 = 0
    try checkStatus(
      checkedCString(name, operation) { idax_script_global($0, &output, &present) }, operation)
    if present == 0 {
      idax_script_value_free(output)
      return nil
    }
    return try Value(taking: output, operation)
  }
  @discardableResult public static func setGlobal(_ name: String, value: Value) throws(IDAError)
    -> Bool
  {
    let operation = "Script.setGlobal"
    let pointer = try value.resource.pointer(operation)
    var output: Int32 = 0
    try checkStatus(
      checkedCString(name, operation) { idax_script_set_global($0, pointer, &output) }, operation)
    return output != 0
  }
  public static func referenceGlobal(_ name: String) throws(IDAError) -> Value {
    let operation = "Script.referenceGlobal"
    try requireRuntimeThread(operation)
    var output: UnsafeMutableRawPointer?
    try checkStatus(
      checkedCString(name, operation) { idax_script_reference_global($0, &output) }, operation)
    return try Value(taking: output, operation)
  }
}
