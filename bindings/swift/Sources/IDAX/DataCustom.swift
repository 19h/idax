internal import CIDAX
internal import Foundation

private final class CustomDataCallback {
  let body: (IdaxSwiftCustomRequest, UnsafeMutablePointer<IdaxSwiftCustomReply>) throws -> Void
  init(
    _ body:
      @escaping (IdaxSwiftCustomRequest, UnsafeMutablePointer<IdaxSwiftCustomReply>) throws -> Void
  ) { self.body = body }
}
private func customDataDestroy(_ context: UnsafeMutableRawPointer?) {
  if let context { Unmanaged<CustomDataCallback>.fromOpaque(context).release() }
}
private func customDataInvoke(
  _ context: UnsafeMutableRawPointer?, _ request: UnsafePointer<IdaxSwiftCustomRequest>?,
  _ reply: UnsafeMutablePointer<IdaxSwiftCustomReply>?,
  _ errorOutput: UnsafeMutablePointer<IdaxSwiftError>?
) -> Int32 {
  guard let context, let request, let reply else {
    writeCallbackError(
      IDAError(category: .internalError, message: "Missing custom-data callback state"),
      to: errorOutput)
    return -1
  }
  let owner = Unmanaged<CustomDataCallback>.fromOpaque(context).takeUnretainedValue()
  do {
    try owner.body(request.pointee, reply)
    return 0
  } catch {
    writeCallbackError(
      (error as? IDAError)
        ?? IDAError(category: .internalError, message: String(describing: error)), to: errorOutput)
    return -1
  }
}
private func customDataDescriptor(
  _ body:
    @escaping (IdaxSwiftCustomRequest, UnsafeMutablePointer<IdaxSwiftCustomReply>) throws -> Void
) -> IdaxSwiftCustomCallbacks {
  .init(
    context: Unmanaged.passRetained(CustomDataCallback(body)).toOpaque(), invoke: customDataInvoke,
    destroy: customDataDestroy)
}
private func customDataReply(_ bytes: [UInt8], _ reply: UnsafeMutablePointer<IdaxSwiftCustomReply>)
  throws(IDAError)
{
  try bridgeCall("Data.customDataReply") { error in
    bytes.withUnsafeBufferPointer {
      idax_swift_custom_reply_bytes(reply, $0.baseAddress, $0.count, error)
    }
  }
}

extension Data {
  /// An opaque identity tied to a registration generation.
  public struct CustomDataTypeID: Equatable, Hashable, Sendable {
    internal let value: UInt64
    internal init(_ value: UInt64) { self.value = value }
    public static let standard = CustomDataTypeID(0)
  }
  /// An opaque identity tied to a registration generation.
  public struct CustomDataFormatID: Equatable, Hashable, Sendable {
    internal let value: UInt64
    internal init(_ value: UInt64) { self.value = value }
  }
  public struct CustomDataFormatContext: Equatable, Sendable {
    public var address: Address
    public var operandIndex: Int32
    public var typeID: CustomDataTypeID
    public init(
      address: Address = badAddress, operandIndex: Int32 = -1, typeID: CustomDataTypeID = .standard
    ) {
      self.address = address
      self.operandIndex = operandIndex
      self.typeID = typeID
    }
    internal init(_ native: IdaxSwiftCustomContext) {
      self.init(
        address: native.address, operandIndex: native.operand_index, typeID: .init(native.type_id))
    }
    internal var native: IdaxSwiftCustomContext {
      .init(address: address, operand_index: operandIndex, type_id: typeID.value)
    }
  }
  public struct CustomDataTypeDefinition {
    public var name: String
    public var menuName: String
    public var hotkey: String
    public var assemblerKeyword: String
    public var valueSize: AddressSize
    public var allowDuplicates: Bool
    public var mayCreateAt: ((Address, AddressSize) throws(IDAError) -> Bool)?
    public var calculateSize: ((Address, AddressSize) throws(IDAError) -> AddressSize)?
    public init(
      name: String, valueSize: AddressSize, menuName: String = "", hotkey: String = "",
      assemblerKeyword: String = "", allowDuplicates: Bool = true,
      mayCreateAt: ((Address, AddressSize) throws(IDAError) -> Bool)? = nil,
      calculateSize: ((Address, AddressSize) throws(IDAError) -> AddressSize)? = nil
    ) {
      self.name = name
      self.valueSize = valueSize
      self.menuName = menuName
      self.hotkey = hotkey
      self.assemblerKeyword = assemblerKeyword
      self.allowDuplicates = allowDuplicates
      self.mayCreateAt = mayCreateAt
      self.calculateSize = calculateSize
    }
  }
  public struct CustomDataFormatDefinition {
    public var name: String
    public var menuName: String
    public var hotkey: String
    public var valueSize: AddressSize
    public var textWidth: Int32
    public var render: (([UInt8], CustomDataFormatContext) throws(IDAError) -> String)?
    public var scan: ((String, CustomDataFormatContext) throws(IDAError) -> [UInt8])?
    public var analyze: ((CustomDataFormatContext) throws(IDAError) -> Void)?
    public init(
      name: String, valueSize: AddressSize = 0, menuName: String = "", hotkey: String = "",
      textWidth: Int32 = 0,
      render: (([UInt8], CustomDataFormatContext) throws(IDAError) -> String)? = nil,
      scan: ((String, CustomDataFormatContext) throws(IDAError) -> [UInt8])? = nil,
      analyze: ((CustomDataFormatContext) throws(IDAError) -> Void)? = nil
    ) {
      self.name = name
      self.valueSize = valueSize
      self.menuName = menuName
      self.hotkey = hotkey
      self.textWidth = textWidth
      self.render = render
      self.scan = scan
      self.analyze = analyze
    }
  }
  public struct CustomDataTypeInfo: Equatable, Sendable {
    public let id: CustomDataTypeID
    public let name: String
    public let menuName: String
    public let hotkey: String
    public let assemblerKeyword: String
    public let valueSize: AddressSize
    public let allowDuplicates: Bool
    public let visibleInMenu: Bool
    public let hasCreationFilter: Bool
    public let variableSize: Bool
    public init(id: CustomDataTypeID = .standard, name: String = "", menuName: String = "",
                hotkey: String = "", assemblerKeyword: String = "", valueSize: AddressSize = 0,
                allowDuplicates: Bool = true, visibleInMenu: Bool = false,
                hasCreationFilter: Bool = false, variableSize: Bool = false) {
      self.id = id; self.name = name; self.menuName = menuName; self.hotkey = hotkey
      self.assemblerKeyword = assemblerKeyword; self.valueSize = valueSize
      self.allowDuplicates = allowDuplicates; self.visibleInMenu = visibleInMenu
      self.hasCreationFilter = hasCreationFilter; self.variableSize = variableSize
    }
    internal init(_ value: IdaxSwiftCustomInfo, _ operation: String) throws(IDAError) {
      id = .init(value.id)
      name = try borrowCString(value.name.map { UnsafePointer($0) }, operation)
      menuName = try borrowCString(value.menu_name.map { UnsafePointer($0) }, operation)
      hotkey = try borrowCString(value.hotkey.map { UnsafePointer($0) }, operation)
      assemblerKeyword = try borrowCString(
        value.assembler_keyword.map { UnsafePointer($0) }, operation)
      valueSize = value.value_size
      allowDuplicates = value.flags & 1 != 0
      visibleInMenu = value.flags & 2 != 0
      hasCreationFilter = value.flags & 4 != 0
      variableSize = value.flags & 8 != 0
    }
  }
  public struct CustomDataFormatInfo: Equatable, Sendable {
    public let id: CustomDataFormatID
    public let name: String
    public let menuName: String
    public let hotkey: String
    public let valueSize: AddressSize
    public let textWidth: Int32
    public let visibleInMenu: Bool
    public let canRender: Bool
    public let canScan: Bool
    public let canAnalyze: Bool
    public init(id: CustomDataFormatID, name: String = "", menuName: String = "",
                hotkey: String = "", valueSize: AddressSize = 0, textWidth: Int32 = 0,
                visibleInMenu: Bool = false, canRender: Bool = false,
                canScan: Bool = false, canAnalyze: Bool = false) {
      self.id = id; self.name = name; self.menuName = menuName; self.hotkey = hotkey
      self.valueSize = valueSize; self.textWidth = textWidth; self.visibleInMenu = visibleInMenu
      self.canRender = canRender; self.canScan = canScan; self.canAnalyze = canAnalyze
    }
    internal init(_ value: IdaxSwiftCustomInfo, _ operation: String) throws(IDAError) {
      id = .init(value.id)
      name = try borrowCString(value.name.map { UnsafePointer($0) }, operation)
      menuName = try borrowCString(value.menu_name.map { UnsafePointer($0) }, operation)
      hotkey = try borrowCString(value.hotkey.map { UnsafePointer($0) }, operation)
      valueSize = value.value_size
      textWidth = value.text_width
      visibleInMenu = value.flags & 2 != 0
      canRender = value.flags & 16 != 0
      canScan = value.flags & 32 != 0
      canAnalyze = value.flags & 64 != 0
    }
  }
  public struct CustomDataItemInfo: Equatable, Sendable {
    public let typeID: CustomDataTypeID
    public let formatID: CustomDataFormatID
    public let byteLength: AddressSize
    public init(typeID: CustomDataTypeID = .standard, formatID: CustomDataFormatID,
                byteLength: AddressSize = 0) {
      self.typeID = typeID; self.formatID = formatID; self.byteLength = byteLength
    }
  }
  public final class CustomDataTypeRegistration {
    public let id: CustomDataTypeID
    private let resource: NativeResource
    internal init(_ pointer: UnsafeMutableRawPointer, id: UInt64) throws(IDAError) {
      self.id = .init(id)
      resource = try NativeResource(
        taking: pointer, release: idax_swift_custom_registration_free,
        operation: "Data.registerCustomDataType")
    }
    public func close() throws(IDAError) {
      try resource.close(
        "Data.CustomDataTypeRegistration.close", using: idax_swift_custom_registration_close)
    }
  }
  public final class CustomDataFormatRegistration {
    public let id: CustomDataFormatID
    private let resource: NativeResource
    internal init(_ pointer: UnsafeMutableRawPointer, id: UInt64) throws(IDAError) {
      self.id = .init(id)
      resource = try NativeResource(
        taking: pointer, release: idax_swift_custom_registration_free,
        operation: "Data.registerCustomDataFormat")
    }
    public func close() throws(IDAError) {
      try resource.close(
        "Data.CustomDataFormatRegistration.close", using: idax_swift_custom_registration_close)
    }
  }

  public static func registerCustomDataType(_ definition: CustomDataTypeDefinition) throws(IDAError)
    -> CustomDataTypeRegistration
  {
    let operation = "Data.registerCustomDataType"
    var error = IdaxSwiftError()
    var output: UnsafeMutableRawPointer?
    var id: UInt64 = 0
    defer { idax_swift_error_free(&error) }
    let status = try checkedCStringArray(
      [definition.name, definition.menuName, definition.hotkey, definition.assemblerKeyword],
      operation
    ) { strings, _ in
      var callbackFlags: UInt32 = 0
      if case .some = definition.mayCreateAt { callbackFlags |= 1 }
      if case .some = definition.calculateSize { callbackFlags |= 2 }
      var native = IdaxSwiftCustomDefinition(
        name: strings![0], menu_name: strings![1], hotkey: strings![2],
        assembler_keyword: strings![3],
        value_size: definition.valueSize, text_width: 0,
        allow_duplicates: definition.allowDuplicates ? 1 : 0,
        callback_flags: callbackFlags)
      let callbacks = customDataDescriptor { request, reply in
        if request.kind == 0, let callback = definition.mayCreateAt {
          reply.pointee.value = try callback(request.context.address, request.size) ? 1 : 0
        } else if request.kind == 1, let callback = definition.calculateSize {
          reply.pointee.value = try callback(request.context.address, request.size)
        } else {
          throw IDAError(category: .internalError, message: "Unexpected custom type callback kind")
        }
      }
      return idax_swift_custom_register(0, &native, callbacks, &output, &id, &error)
    }
    try checkBridgeStatus(status, error, operation)
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Native custom type registration is null",
        context: operation)
    }
    return try CustomDataTypeRegistration(output, id: id)
  }
  public static func registerCustomDataFormat(_ definition: CustomDataFormatDefinition)
    throws(IDAError) -> CustomDataFormatRegistration
  {
    let operation = "Data.registerCustomDataFormat"
    var error = IdaxSwiftError()
    var output: UnsafeMutableRawPointer?
    var id: UInt64 = 0
    defer { idax_swift_error_free(&error) }
    let status = try checkedCStringArray(
      [definition.name, definition.menuName, definition.hotkey], operation
    ) { strings, _ in
      var callbackFlags: UInt32 = 0
      if case .some = definition.render { callbackFlags |= 4 }
      if case .some = definition.scan { callbackFlags |= 8 }
      if case .some = definition.analyze { callbackFlags |= 16 }
      var native = IdaxSwiftCustomDefinition(
        name: strings![0], menu_name: strings![1], hotkey: strings![2], assembler_keyword: nil,
        value_size: definition.valueSize, text_width: definition.textWidth, allow_duplicates: 0,
        callback_flags: callbackFlags)
      let callbacks = customDataDescriptor { request, reply in
        let context = CustomDataFormatContext(request.context)
        let bytes = Array(try checkedBuffer(request.bytes, count: request.count, operation))
        if request.kind == 2, let callback = definition.render {
          try customDataReply(Array(callback(bytes, context).utf8), reply)
        } else if request.kind == 3, let callback = definition.scan {
          guard let input = String(bytes: bytes, encoding: .utf8) else {
            throw IDAError(
              category: .internalError, message: "Custom scan input is not valid UTF-8")
          }
          try customDataReply(callback(input, context), reply)
        } else if request.kind == 4, let callback = definition.analyze {
          try callback(context)
        } else {
          throw IDAError(
            category: .internalError, message: "Unexpected custom format callback kind")
        }
      }
      return idax_swift_custom_register(1, &native, callbacks, &output, &id, &error)
    }
    try checkBridgeStatus(status, error, operation)
    guard let output else {
      throw IDAError(
        category: .internalError, message: "Native custom format registration is null",
        context: operation)
    }
    return try CustomDataFormatRegistration(output, id: id)
  }
  public static func unregisterCustomDataType(_ id: CustomDataTypeID) throws(IDAError) {
    try bridgeCall("Data.unregisterCustomDataType") {
      idax_swift_custom_unregister(0, id.value, $0)
    }
  }
  public static func unregisterCustomDataFormat(_ id: CustomDataFormatID) throws(IDAError) {
    try bridgeCall("Data.unregisterCustomDataFormat") {
      idax_swift_custom_unregister(1, id.value, $0)
    }
  }
  private static func findCustom(_ name: String, format: Bool, _ operation: String) throws(IDAError)
    -> UInt64
  {
    var output: UInt64 = 0
    var error = IdaxSwiftError()
    defer { idax_swift_error_free(&error) }
    let status = try checkedCString(name, operation) {
      idax_swift_custom_find(format ? 1 : 0, $0, &output, &error)
    }
    try checkBridgeStatus(status, error, operation)
    return output
  }
  public static func findCustomDataType(_ name: String) throws(IDAError) -> CustomDataTypeID {
    try .init(findCustom(name, format: false, "Data.findCustomDataType"))
  }
  public static func findCustomDataFormat(_ name: String) throws(IDAError) -> CustomDataFormatID {
    try .init(findCustom(name, format: true, "Data.findCustomDataFormat"))
  }
  public static func customDataType(_ id: CustomDataTypeID) throws(IDAError) -> CustomDataTypeInfo {
    let operation = "Data.customDataType"
    var output = IdaxSwiftCustomInfo()
    defer { idax_swift_custom_info_free(&output) }
    try bridgeCall(operation) { idax_swift_custom_info(0, id.value, &output, $0) }
    return try CustomDataTypeInfo(output, operation)
  }
  public static func customDataFormat(_ id: CustomDataFormatID) throws(IDAError)
    -> CustomDataFormatInfo
  {
    let operation = "Data.customDataFormat"
    var output = IdaxSwiftCustomInfo()
    defer { idax_swift_custom_info_free(&output) }
    try bridgeCall(operation) { idax_swift_custom_info(1, id.value, &output, $0) }
    return try CustomDataFormatInfo(output, operation)
  }
  private static func customList<Value>(
    _ selector: Int32, type: UInt64 = 0, minimum: AddressSize = 0, maximum: AddressSize = .max,
    _ operation: String, _ transform: (IdaxSwiftCustomInfo, String) throws(IDAError) -> Value
  ) throws(IDAError) -> [Value] {
    var output: UnsafeMutablePointer<IdaxSwiftCustomInfo>?
    var count = 0
    defer { idax_swift_custom_infos_free(output, count) }
    try bridgeCall(operation) {
      idax_swift_custom_list(selector, type, minimum, maximum, &output, &count, $0)
    }
    let buffer = try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation)
    var result: [Value] = []
    result.reserveCapacity(count)
    for value in buffer { result.append(try transform(value, operation)) }
    return result
  }
  public static func customDataTypes(minimumSize: AddressSize = 0, maximumSize: AddressSize = .max)
    throws(IDAError) -> [CustomDataTypeInfo]
  {
    try customList(
      0, minimum: minimumSize, maximum: maximumSize, "Data.customDataTypes", CustomDataTypeInfo.init
    )
  }
  public static func customDataFormats(for type: CustomDataTypeID) throws(IDAError)
    -> [CustomDataFormatInfo]
  {
    try customList(1, type: type.value, "Data.customDataFormats", CustomDataFormatInfo.init)
  }
  public static func standardCustomDataFormats() throws(IDAError) -> [CustomDataFormatInfo] {
    try customList(2, "Data.standardCustomDataFormats", CustomDataFormatInfo.init)
  }
  private static func customRelation(
    _ operation: Int32, type: UInt64 = 0, format: CustomDataFormatID, _ context: String
  ) throws(IDAError) -> Bool {
    var output: Int32 = 0
    try bridgeCall(context) {
      idax_swift_custom_relation(operation, type, format.value, &output, $0)
    }
    return output != 0
  }
  public static func attachCustomDataFormat(_ format: CustomDataFormatID, to type: CustomDataTypeID)
    throws(IDAError)
  { _ = try customRelation(0, type: type.value, format: format, "Data.attachCustomDataFormat") }
  public static func detachCustomDataFormat(
    _ format: CustomDataFormatID, from type: CustomDataTypeID
  ) throws(IDAError) {
    _ = try customRelation(1, type: type.value, format: format, "Data.detachCustomDataFormat")
  }
  public static func isCustomDataFormatAttached(
    _ format: CustomDataFormatID, to type: CustomDataTypeID
  ) throws(IDAError) -> Bool {
    try customRelation(2, type: type.value, format: format, "Data.isCustomDataFormatAttached")
  }
  public static func attachCustomDataFormatToStandardTypes(_ format: CustomDataFormatID)
    throws(IDAError)
  { _ = try customRelation(3, format: format, "Data.attachCustomDataFormatToStandardTypes") }
  public static func detachCustomDataFormatFromStandardTypes(_ format: CustomDataFormatID)
    throws(IDAError)
  { _ = try customRelation(4, format: format, "Data.detachCustomDataFormatFromStandardTypes") }
  public static func isCustomDataFormatAttachedToStandardTypes(_ format: CustomDataFormatID)
    throws(IDAError) -> Bool
  { try customRelation(5, format: format, "Data.isCustomDataFormatAttachedToStandardTypes") }
  public static func customDataItemSize(
    _ type: CustomDataTypeID, at address: Address, maximumSize: AddressSize
  ) throws(IDAError) -> AddressSize {
    var output: AddressSize = 0
    try bridgeCall("Data.customDataItemSize") {
      idax_swift_custom_item_size(type.value, address, maximumSize, &output, $0)
    }
    return output
  }
  public static func defineCustom(
    at address: Address, byteLength: AddressSize, type: CustomDataTypeID, format: CustomDataFormatID
  ) throws(IDAError) {
    try bridgeCall("Data.defineCustom") {
      idax_swift_custom_define(0, address, byteLength, type.value, format.value, $0)
    }
  }
  public static func defineCustomInferred(
    at address: Address, type: CustomDataTypeID, format: CustomDataFormatID,
    maximumSize: AddressSize
  ) throws(IDAError) {
    try bridgeCall("Data.defineCustomInferred") {
      idax_swift_custom_define(1, address, maximumSize, type.value, format.value, $0)
    }
  }
  public static func customData(at address: Address) throws(IDAError) -> CustomDataItemInfo {
    var type: UInt64 = 0
    var format: UInt64 = 0
    var byteLength: UInt64 = 0
    try bridgeCall("Data.customData") {
      idax_swift_custom_at(address, &type, &format, &byteLength, $0)
    }
    return .init(typeID: .init(type), formatID: .init(format), byteLength: byteLength)
  }
  public static func renderCustomData(
    _ format: CustomDataFormatID, value: [UInt8], context: CustomDataFormatContext = .init()
  ) throws(IDAError) -> String {
    let operation = "Data.renderCustomData"
    var native = context.native
    var output: UnsafeMutablePointer<UInt8>?
    var count = 0
    defer { idax_free_bytes(output) }
    try bridgeCall(operation) { error in
      value.withUnsafeBufferPointer {
        idax_swift_custom_render(
          format.value, $0.baseAddress, $0.count, &native, &output, &count, error)
      }
    }
    let bytes = Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
    guard let result = String(bytes: bytes, encoding: .utf8) else {
      throw IDAError(
        category: .internalError, message: "Custom render output is not valid UTF-8",
        context: operation)
    }
    return result
  }
  public static func scanCustomData(
    _ format: CustomDataFormatID, text: String, context: CustomDataFormatContext = .init()
  ) throws(IDAError) -> [UInt8] {
    let operation = "Data.scanCustomData"
    var native = context.native
    var output: UnsafeMutablePointer<UInt8>?
    var count = 0
    let input = Array(text.utf8)
    defer { idax_free_bytes(output) }
    try bridgeCall(operation) { error in
      input.withUnsafeBufferPointer {
        idax_swift_custom_scan(
          format.value, $0.baseAddress, $0.count, &native, &output, &count, error)
      }
    }
    return Array(try checkedBuffer(output.map { UnsafePointer($0) }, count: count, operation))
  }
  public static func analyzeCustomData(
    _ format: CustomDataFormatID, context: CustomDataFormatContext = .init()
  ) throws(IDAError) {
    var native = context.native
    try bridgeCall("Data.analyzeCustomData") {
      idax_swift_custom_analyze(format.value, &native, $0)
    }
  }
}
