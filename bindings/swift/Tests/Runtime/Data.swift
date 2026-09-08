import IDAX

private struct NetworkPair: BinaryValue, Equatable {
  let first: UInt16
  let second: UInt16
  static let byteCount = 4
  static func decodeNativeBytes(_ bytes: [UInt8]) throws(IDAError) -> Self {
    guard bytes.count == byteCount else {
      throw IDAError(category: .validation, message: "Pair byte count is invalid")
    }
    return .init(
      first: UInt16(bytes[0]) << 8 | UInt16(bytes[1]),
      second: UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
  }
  func nativeBytes() -> [UInt8] {
    [
      UInt8(first >> 8), UInt8(truncatingIfNeeded: first), UInt8(second >> 8),
      UInt8(truncatingIfNeeded: second),
    ]
  }
}

func runDataChecks() throws {
  let originalStringOptions = try Data.stringListOptions()
  defer { try? Data.configureStringList(originalStringOptions) }
  let stringOptions = Data.StringListOptions(
    minimumLength: 3, only7bit: false, ignoreInstructions: true,
    displayOnlyExistingStrings: true)
  try Data.configureStringList(stringOptions)
  try expect(Data.stringListOptions() == stringOptions,
             "String-list Boolean options lost their native meanings")
  _ = try Data.stringLiterals(rebuild: false)
  let maximum = try Database.maxAddress()
  try expect(maximum < badAddress - 0x2000, "Cannot allocate the data test segment")
  let start = (maximum + 0xfff) & ~Address(0xfff)
  try Segments.create(
    start: start, end: start + 0x1000, name: "SWIFT_DATA_TEST", className: "DATA", type: .data)
  defer { try? Segments.remove(address: start) }
  try IDAX.Data.writeBytes(address: start, data: Array(repeating: 0, count: 128))
  try runCustomDataGenerationChecks(at: start + 96)

  let unsigned = try TypeInfo.uint64()
  try IDAX.Data.writeTyped(address: start, type: unsigned, value: .unsignedInteger(.max))
  try expect(
    try IDAX.Data.readTyped(address: start, type: unsigned) == .unsignedInteger(.max),
    "Unsigned typed scalar lost its upper bits")
  let signed = try TypeInfo.int64()
  try IDAX.Data.writeTyped(address: start, type: signed, value: .signedInteger(.min))
  try expect(
    try IDAX.Data.readTyped(address: start, type: signed) == .signedInteger(.min),
    "Signed typed scalar lost its sign")
  let floating = try TypeInfo.float64()
  try IDAX.Data.writeTyped(address: start, type: floating, value: .floatingPoint(-1.25))
  try expect(
    try IDAX.Data.readTyped(address: start, type: floating) == .floatingPoint(-1.25),
    "Floating typed scalar did not round-trip")
  let row = try TypeInfo.array(of: TypeInfo.int32(), count: 2)
  let matrix = try TypeInfo.array(of: row, count: 2)
  let expected: IDAX.Data.TypedValue = .array([
    .array([.signedInteger(-1), .signedInteger(2)]),
    .array([.signedInteger(3), .signedInteger(-4)]),
  ])
  try IDAX.Data.writeTyped(address: start, type: matrix, value: expected)
  try expect(
    try IDAX.Data.readTyped(address: start, type: matrix) == expected,
    "Recursive typed arrays did not round-trip")

  let byteArray = try TypeInfo.array(of: TypeInfo.uint8(), count: 8)
  try IDAX.Data.writeTyped(address: start, type: byteArray, value: .string("a\0β"))
  try expect(
    try IDAX.Data.readBytes(address: start, count: 8) == [97, 0, 206, 178, 0, 0, 0, 0],
    "Typed string input lost embedded NUL or UTF-8")
  try expect(
    try IDAX.Data.readTyped(address: start, type: byteArray)
      == .string("a", originalBytes: [97, 0, 206, 178, 0, 0, 0, 0]),
    "Typed string snapshot lost original bytes")
  try IDAX.Data.writeBytes(address: start, data: [65, 0, 66, 0, 0, 0, 0, 0])
  try expect(
    try IDAX.Data.readString(address: start, maxLength: 6, stringType: 1) == "AB",
    "String type or maximum length was not forwarded")
  try IDAX.Data.writeBytes(address: start, data: [0x12, 0x34, 0x12, 0x34])
  try expect(
    try IDAX.Data.findBinaryPattern(start: start, end: start + 4, pattern: "12 34") == start,
    "Binary pattern lookup missed its first match")
  try expect(
    try IDAX.Data.findBinaryPattern(start: start, end: start + 4, pattern: "12 34", skipStart: true)
      == start + 2, "Binary pattern skipStart was not forwarded")

  let pair = NetworkPair(first: 0xabcd, second: 0x0123)
  try IDAX.Data.writeValue(address: start, value: pair)
  try expect(
    try IDAX.Data.readValue(address: start, as: NetworkPair.self) == pair,
    "Application-defined binary codec failed")
  try IDAX.Data.writeValue(address: start, value: Int64.min)
  try expect(
    try IDAX.Data.readValue(address: start, as: Int64.self) == .min,
    "Native scalar binary codec failed")
  print(
    "PASS: typed data, recursive arrays, length-bearing strings, search options, and native/custom binary codecs"
  )
}
