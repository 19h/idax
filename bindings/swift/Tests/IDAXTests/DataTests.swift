import CIDAX
import XCTest

@testable import IDAX

final class DataTests: XCTestCase {
  func testSemanticValuesPreserveRecursivePayloadsAndLengthBearingStrings() throws {
    let original: IDAX.Data.TypedValue = .array([
      .unsignedInteger(.max), .signedInteger(.min), .floatingPoint(-1.25),
      .pointer(0x1234), .string("a\0β", originalBytes: [97, 0, 206, 178, 0, 7]),
      .bytes([0, 255]), .array([]),
    ])
    let arena = InputArena()
    let native = try original.native(in: arena, "test")
    XCTAssertEqual(try IDAX.Data.TypedValue(copying: native, "test"), original)
    withExtendedLifetime(arena) {}
  }

  func testSemanticValuesRejectMalformedNativeExtentsAndExcessiveDepth() throws {
    var native = IdaxSwiftDataValue()
    native.kind = IDAX.Data.TypedValueKind.bytes.rawValue
    native.byte_count = 1
    XCTAssertThrowsError(try IDAX.Data.TypedValue(copying: native, "test"))
    native.kind = 999
    XCTAssertThrowsError(try IDAX.Data.TypedValue(copying: native, "test"))
    var deep: IDAX.Data.TypedValue = .bytes([])
    for _ in 0..<66 { deep = .array([deep]) }
    XCTAssertThrowsError(try deep.native(in: InputArena(), "test"))
  }

  func testNativeScalarCodecsPreserveBitPatternsAndRejectInvalidExtents() throws {
    XCTAssertEqual(try UInt64.decodeNativeBytes(UInt64.max.nativeBytes()), .max)
    XCTAssertEqual(try Int64.decodeNativeBytes(Int64.min.nativeBytes()), .min)
    let nan = Double(bitPattern: 0x7ff8_0000_0000_1234)
    XCTAssertEqual(try Double.decodeNativeBytes(nan.nativeBytes()).bitPattern, nan.bitPattern)
    XCTAssertEqual(
      try Float.decodeNativeBytes((-0.0 as Float).nativeBytes()).bitPattern, Float(-0.0).bitPattern)
    XCTAssertThrowsError(try UInt32.decodeNativeBytes([1, 2, 3]))
    XCTAssertThrowsError(try Bool.decodeNativeBytes([2]))
    XCTAssertEqual(try Bool.decodeNativeBytes([1]), true)
  }
}
