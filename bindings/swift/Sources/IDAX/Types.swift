internal import CIDAX

public enum Types {
  public struct ParseDeclarationsOptions: Equatable, Sendable {
    public var suppressWarnings: Bool
    public var relaxedNamespaces: Bool
    public var rawArgumentNames: Bool
    public var noMangle: Bool
    public var packAlignment: Int
    public init(
      suppressWarnings: Bool = false, relaxedNamespaces: Bool = false,
      rawArgumentNames: Bool = false, noMangle: Bool = false, packAlignment: Int = 0
    ) {
      self.suppressWarnings = suppressWarnings
      self.relaxedNamespaces = relaxedNamespaces
      self.rawArgumentNames = rawArgumentNames
      self.noMangle = noMangle
      self.packAlignment = packAlignment
    }
  }
  public struct ParseDeclarationsReport: Equatable, Sendable {
    public var errorCount: Int
    public var ok: Bool { errorCount == 0 }
    public init(errorCount: Int = 0) { self.errorCount = errorCount }
  }
  public struct UsedMemberOffsets: Equatable, Sendable {
    public var typeName: String
    public var byteOffsets: [Int32]
    public init(typeName: String, byteOffsets: [Int32]) {
      self.typeName = typeName
      self.byteOffsets = byteOffsets
    }
  }
  public struct RenderOptions: Equatable, Sendable {
    public var sizeComments: Bool
    public var trimUnreferenced: Bool
    public var usedOffsets: [UsedMemberOffsets]
    public init(
      sizeComments: Bool = false, trimUnreferenced: Bool = false,
      usedOffsets: [UsedMemberOffsets] = []
    ) {
      self.sizeComments = sizeComments
      self.trimUnreferenced = trimUnreferenced
      self.usedOffsets = usedOffsets
    }
  }
  public struct GraphOptions: Equatable, Sendable {
    public enum Mode: Int32, CaseIterable, Sendable { case simple, table }
    public var mode: Mode
    public var maxDepth: Int32
    public var includeEnums: Bool
    public var includeTypedefs: Bool
    public init(
      mode: Mode = .simple, maxDepth: Int32 = -1, includeEnums: Bool = true,
      includeTypedefs: Bool = true
    ) {
      self.mode = mode
      self.maxDepth = maxDepth
      self.includeEnums = includeEnums
      self.includeTypedefs = includeTypedefs
    }
  }
  public struct Declaration: Equatable, Sendable {
    public var ordinal: UInt32
    public var name: String
    public var declaration: String
    public init(ordinal: UInt32, name: String, declaration: String) {
      self.ordinal = ordinal
      self.name = name
      self.declaration = declaration
    }
  }

  public static func retrieve(at address: Address) throws(IDAError) -> TypeInfo {
    try TypeInfo.output("Types.retrieve") { idax_type_retrieve(address, $0) }
  }
  public static func retrieveOperand(at address: Address, operandIndex: Int32) throws(IDAError)
    -> TypeInfo
  {
    try TypeInfo.output("Types.retrieveOperand") {
      idax_type_retrieve_operand(address, operandIndex, $0)
    }
  }
  public static func remove(at address: Address) throws(IDAError) {
    try requireRuntimeThread("Types.remove")
    try checkStatus(idax_type_remove(address), "Types.remove")
  }
  public static func loadLibrary(named name: String) throws(IDAError) -> Bool {
    let operation = "Types.loadLibrary"
    try requireRuntimeThread(operation)
    var output: Int32 = 0
    try checkStatus(
      checkedCString(name, operation) { idax_type_load_library($0, &output) }, operation)
    return output != 0
  }
  public static func unloadLibrary(named name: String) throws(IDAError) {
    let operation = "Types.unloadLibrary"
    try requireRuntimeThread(operation)
    try checkStatus(checkedCString(name, operation) { idax_type_unload_library($0) }, operation)
  }
  public static func localTypeCount() throws(IDAError) -> Int {
    try withOutput("Types.localTypeCount", initial: 0) { idax_type_local_type_count($0) }
  }
  public static func localTypeName(ordinal: Int) throws(IDAError) -> String {
    try requireNonnegative(ordinal, "Types.localTypeName")
    return try withStringOutput("Types.localTypeName") { idax_type_local_type_name(ordinal, $0) }
  }
  public static func importType(named name: String, fromLibrary library: String = "")
    throws(IDAError) -> Int
  {
    let operation = "Types.importType"
    try requireRuntimeThread(operation)
    try validateCString(name, operation)
    try validateCString(library, operation)
    var output = 0
    let status = name.withCString { name in
      library.withCString { idax_type_import($0, name, &output) }
    }
    try checkStatus(status, operation)
    return output
  }
  public static func ensureNamedType(_ name: String, fromLibrary library: String = "")
    throws(IDAError) -> TypeInfo
  {
    let operation = "Types.ensureNamedType"
    try validateCString(name, operation)
    try validateCString(library, operation)
    var output: UnsafeMutableRawPointer?
    try bridgeCall(operation) { error in
      name.withCString { name in
        library.withCString { idax_swift_type_ensure_named(name, $0, &output, error) }
      }
    }
    return try TypeInfo.taking(output, operation)
  }
  public static func applyNamedType(_ name: String, at address: Address) throws(IDAError) {
    let operation = "Types.applyNamedType"
    try requireRuntimeThread(operation)
    try checkStatus(
      checkedCString(name, operation) { idax_type_apply_named(address, $0) }, operation)
  }
  public static func parseDeclarations(
    _ declarations: String, options: ParseDeclarationsOptions = .init()
  ) throws(IDAError) -> ParseDeclarationsReport {
    let operation = "Types.parseDeclarations"
    try requireRuntimeThread(operation)
    try requireNonnegative(options.packAlignment, operation)
    var count = 0
    try checkStatus(
      checkedCString(declarations, operation) {
        idax_type_parse_declarations(
          $0, options.suppressWarnings ? 1 : 0, options.relaxedNamespaces ? 1 : 0,
          options.rawArgumentNames ? 1 : 0, options.noMangle ? 1 : 0, options.packAlignment, &count)
      }, operation)
    return ParseDeclarationsReport(errorCount: count)
  }
}

public struct OperationOptions: Equatable, Sendable {
  public var strictValidation: Bool
  public var allowPartialResults: Bool
  public var cancelOnUserBreak: Bool
  public var quiet: Bool
  public init(
    strictValidation: Bool = true, allowPartialResults: Bool = false,
    cancelOnUserBreak: Bool = true, quiet: Bool = true
  ) {
    self.strictValidation = strictValidation
    self.allowPartialResults = allowPartialResults
    self.cancelOnUserBreak = cancelOnUserBreak
    self.quiet = quiet
  }
}
public struct RangeOptions: Equatable, Sendable {
  public var start: Address
  public var end: Address
  public var inclusiveEnd: Bool
  public init(start: Address = badAddress, end: Address = badAddress, inclusiveEnd: Bool = false) {
    self.start = start
    self.end = end
    self.inclusiveEnd = inclusiveEnd
  }
}
public struct WaitOptions: Equatable, Sendable {
  public var timeoutMilliseconds: UInt32
  public var pollIntervalMilliseconds: UInt32
  public init(timeoutMilliseconds: UInt32 = 0, pollIntervalMilliseconds: UInt32 = 10) {
    self.timeoutMilliseconds = timeoutMilliseconds
    self.pollIntervalMilliseconds = pollIntervalMilliseconds
  }
}
