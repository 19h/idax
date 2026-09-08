import IDAX
import CIDAX

private final class CustomCallbackLifetime {}

private func nativeCustomToken(_ name: String, format: Bool) throws -> UInt64 {
  var token: UInt64 = 0
  var error = IdaxSwiftError()
  defer { idax_swift_error_free(&error) }
  let status = name.withCString {
    idax_swift_custom_find(format ? 1 : 0, $0, &token, &error)
  }
  try expect(status == 0, "Private custom-data identity lookup failed")
  return token
}

private func staleCustomIdentity(_ body: () throws -> Void) throws {
  do {
    try body()
    throw Failure(description: "Stale custom-data identity remained usable")
  } catch let error as IDAError {
    try expect(error.category == .conflict, "Stale custom-data identity lost its conflict diagnostic")
  }
}

func runCustomDataGenerationChecks(at address: Address) throws {
  let typeName = "idax.swift.generation.type"
  let formatName = "idax.swift.generation.format"
  var typeLifetime: CustomCallbackLifetime? = CustomCallbackLifetime()
  weak var weakTypeLifetime = typeLifetime
  var oldType: IDAX.Data.CustomDataTypeRegistration? = try IDAX.Data.registerCustomDataType(
    .init(name: typeName, valueSize: 1,
      calculateSize: { [lifetime = typeLifetime!] (_, maximum) throws(IDAError) -> AddressSize in
        withExtendedLifetime(lifetime) { min(1, maximum) }
      }))
  typeLifetime = nil
  let oldTypeID = try IDAX.Data.findCustomDataType(typeName)
  let oldTypeToken = try nativeCustomToken(typeName, format: false)
  try expect(oldTypeID == oldType!.id && weakTypeLifetime != nil, "Type alias or callback retention failed")
  try IDAX.Data.unregisterCustomDataType(oldTypeID)
  try expect(weakTypeLifetime == nil, "Explicit type removal retained its callback")

  let replacementType = try IDAX.Data.registerCustomDataType(
    .init(name: typeName, valueSize: 1,
      calculateSize: { (_, maximum) throws(IDAError) -> AddressSize in min(1, maximum) }))
  defer { try? replacementType.close() }
  let replacementTypeID = replacementType.id
  let replacementTypeToken = try nativeCustomToken(typeName, format: false)
  try expect(oldTypeToken & 0xffff == replacementTypeToken & 0xffff,
    "Type regression did not exercise SDK slot reuse")
  try expect(replacementTypeID != oldTypeID, "Reused type slot did not receive a new generation")
  try oldType?.close()
  try oldType?.close()
  oldType = nil
  try staleCustomIdentity { try IDAX.Data.unregisterCustomDataType(oldTypeID) }
  try staleCustomIdentity { _ = try IDAX.Data.customDataType(oldTypeID) }
  try staleCustomIdentity { _ = try IDAX.Data.customDataFormats(for: oldTypeID) }
  try staleCustomIdentity { _ = try IDAX.Data.customDataItemSize(oldTypeID, at: address, maximumSize: 1) }
  try expect(try IDAX.Data.findCustomDataType(typeName) == replacementTypeID,
    "Old type owner close or ARC removed its replacement")
  try expect(try IDAX.Data.customDataTypes().contains { $0.id == replacementTypeID },
    "Type metadata list lost its registration generation")

  var formatLifetime: CustomCallbackLifetime? = CustomCallbackLifetime()
  weak var weakFormatLifetime = formatLifetime
  var oldFormat: IDAX.Data.CustomDataFormatRegistration? = try IDAX.Data.registerCustomDataFormat(
    .init(name: formatName, valueSize: 1,
      render: { [lifetime = formatLifetime!] (_, _) throws(IDAError) -> String in
        withExtendedLifetime(lifetime) { "old" }
      }))
  formatLifetime = nil
  let oldFormatID = try IDAX.Data.findCustomDataFormat(formatName)
  let oldFormatToken = try nativeCustomToken(formatName, format: true)
  try expect(oldFormatID == oldFormat!.id && weakFormatLifetime != nil,
    "Format alias or callback retention failed")
  try IDAX.Data.unregisterCustomDataFormat(oldFormatID)
  try expect(weakFormatLifetime == nil, "Explicit format removal retained its callback")

  let replacementFormat = try IDAX.Data.registerCustomDataFormat(
    .init(name: formatName, valueSize: 1,
      render: { (_, context) throws(IDAError) -> String in
        context.typeID == replacementTypeID ? "replacement" : "wrong type generation"
      }))
  defer { try? replacementFormat.close() }
  let replacementFormatID = replacementFormat.id
  let replacementFormatToken = try nativeCustomToken(formatName, format: true)
  try expect(oldFormatToken & 0xffff == replacementFormatToken & 0xffff,
    "Format regression did not exercise SDK slot reuse")
  try expect(replacementFormatID != oldFormatID, "Reused format slot did not receive a new generation")
  oldFormat = nil
  try staleCustomIdentity { try IDAX.Data.unregisterCustomDataFormat(oldFormatID) }
  try staleCustomIdentity { _ = try IDAX.Data.customDataFormat(oldFormatID) }
  try staleCustomIdentity { _ = try IDAX.Data.renderCustomData(oldFormatID, value: [0]) }
  try staleCustomIdentity { _ = try IDAX.Data.scanCustomData(oldFormatID, text: "0") }
  try staleCustomIdentity { try IDAX.Data.analyzeCustomData(oldFormatID) }
  try staleCustomIdentity { try IDAX.Data.attachCustomDataFormat(oldFormatID, to: replacementTypeID) }
  try staleCustomIdentity { try IDAX.Data.attachCustomDataFormat(replacementFormatID, to: oldTypeID) }
  try staleCustomIdentity {
    _ = try IDAX.Data.renderCustomData(replacementFormatID, value: [0], context: .init(typeID: oldTypeID))
  }
  try staleCustomIdentity {
    try IDAX.Data.defineCustom(at: address, byteLength: 1, type: oldTypeID, format: replacementFormatID)
  }
  try staleCustomIdentity {
    try IDAX.Data.defineCustom(at: address, byteLength: 1, type: replacementTypeID, format: oldFormatID)
  }
  try expect(try IDAX.Data.findCustomDataFormat(formatName) == replacementFormatID,
    "Old format owner ARC removed its replacement")
  try IDAX.Data.attachCustomDataFormat(replacementFormatID, to: replacementTypeID)
  try expect(try IDAX.Data.customDataFormats(for: replacementTypeID).contains { $0.id == replacementFormatID },
    "Format metadata list lost its registration generation")
  try expect(try IDAX.Data.customDataItemSize(replacementTypeID, at: address, maximumSize: 1) == 1,
    "Replacement type callback was removed by a stale owner")
  try expect(try IDAX.Data.renderCustomData(replacementFormatID, value: [0],
    context: .init(address: address, typeID: replacementTypeID)) == "replacement",
    "Replacement callback or context type generation was lost")
  try IDAX.Data.defineCustomInferred(at: address, type: replacementTypeID,
    format: replacementFormatID, maximumSize: 1)
  let item = try IDAX.Data.customData(at: address)
  try expect(item.typeID == replacementTypeID && item.formatID == replacementFormatID && item.byteLength == 1,
    "Custom item metadata lost its identity generations")
  print("PASS: custom-data SDK slot reuse, stale identities, owner close/ARC, callback release, and context generations")
}
