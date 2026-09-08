import CIDAX
import XCTest

@testable import IDAX

final class FoundationTests: XCTestCase {
  func testErrorCategoriesUseExplicitNativeValues() {
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_VALIDATION)), .validation)
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_NOT_FOUND)), .notFound)
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_CONFLICT)), .conflict)
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_UNSUPPORTED)), .unsupported)
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_SDK_FAILURE)), .sdkFailure)
    XCTAssertEqual(IDAError.category(fromNative: Int32(IDAX_ERROR_INTERNAL)), .internalError)
    XCTAssertEqual(IDAError.category(fromNative: -77), .internalError)
  }

  func testBridgePreservesOwnedErrorFieldsAndReplacement() throws {
    var error = IdaxSwiftError()
    defer { idax_swift_error_free(&error) }
    idax_swift_error_set(&error, Int32(IDAX_ERROR_UNSUPPORTED), 94, "diagnostic", "native context")
    idax_swift_error_set(&error, error.category, error.code, error.message, error.context)
    do {
      try checkBridgeStatus(-1, error, "fallback")
      XCTFail("Expected structured native error")
    } catch let failure {
      XCTAssertEqual(
        failure,
        IDAError(category: .unsupported, code: 94, message: "diagnostic", context: "native context")
      )
    }
    idax_swift_error_free(&error)
    XCTAssertEqual(error.category, 0)
    XCTAssertNil(error.message)
    XCTAssertNil(error.context)
  }

  func testCStringRejectsNULBeforeNativeCall() {
    var called = false
    XCTAssertThrowsError(try checkedCString("a\0b", "input") { _ in called = true })
    XCTAssertFalse(called)
    XCTAssertThrowsError(
      try checkedCStringArray(["valid", "a\0b"], "input") { _, _ in called = true })
    XCTAssertFalse(called)
  }

  func testNativeErrorKeepsEmptyContextAndUnformattedMessage() {
    var output: Int64 = 0
    let status = idax_script_value_as_integer(nil, &output)
    XCTAssertNotEqual(status, 0)
    XCTAssertThrowsError(try checkStatus(status, "fallback operation")) { error in
      let actual = error as? IDAError
      XCTAssertEqual(actual?.category, .validation)
      XCTAssertEqual(actual?.message, "Script value handle or output pointer is null")
      XCTAssertEqual(actual?.context, "")
    }
  }

  func testCStringArrayOwnsAllPointersForCall() throws {
    let result = try checkedCStringArray(["alpha", "βeta", ""], "input") { pointers, count in
      (0..<count).map { String(cString: pointers![$0]!) }
    }
    XCTAssertEqual(result, ["alpha", "βeta", ""])
    XCTAssertEqual(try checkedCStringArray([], "input") { _, count in count }, 0)
  }

  func testInvalidStringAndArrayOutputsThrow() throws {
    XCTAssertThrowsError(try borrowCString(nil, "output"))
    let invalid: [CChar] = [-1, 0]
    try invalid.withUnsafeBufferPointer { pointer in
      XCTAssertThrowsError(try borrowCString(pointer.baseAddress, "output"))
    }
    let absent: UnsafePointer<UInt64>? = nil
    XCTAssertThrowsError(try checkedBuffer(absent, count: 1, "array"))
    XCTAssertThrowsError(try checkedBuffer(absent, count: -1, "array"))
    XCTAssertThrowsError(try checkedBuffer(absent, count: Int.max, "array"))
    XCTAssertEqual(try checkedBuffer(absent, count: 0, "array").count, 0)
  }

  func testUninitializedRuntimeRejectsSDKOperation() {
    XCTAssertFalse(Runtime.isInitialized)
    XCTAssertThrowsError(try requireRuntimeThread("test")) { error in
      XCTAssertEqual((error as? IDAError)?.category, .conflict)
    }
  }

  func testParserSemanticOptionsValidateBeforeNativeTransport() throws {
    let languages: Parser.Language = [.c, .cpp, .objectiveC]
    XCTAssertEqual(languages.rawValue, 7)
    XCTAssertTrue(languages.contains(.cpp))
    XCTAssertFalse(languages.contains(.swift))
    let options = Parser.ParseOptions(
      inputKind: .filePath, suppressWarnings: true, packAlignment: 8)
    let native = try options.native("options")
    XCTAssertEqual(native.input_kind, Parser.InputKind.filePath.rawValue)
    XCTAssertEqual(native.suppress_warnings, 1)
    XCTAssertEqual(native.discard_result, 0)
    XCTAssertEqual(native.pack_alignment, 8)
    XCTAssertThrowsError(try Parser.ParseOptions(packAlignment: -1).native("options"))
    XCTAssertThrowsError(try Parser.ParseOptions(packAlignment: 3).native("options"))
    XCTAssertThrowsError(
      try Parser.ParseOptions(assumeHighLevel: true, lowerPrototypes: true).native("options"))
    XCTAssertTrue(Parser.ParseReport(errorCount: 0).isOK)
    XCTAssertFalse(Parser.ParseReport(errorCount: 1).isOK)
  }
}
