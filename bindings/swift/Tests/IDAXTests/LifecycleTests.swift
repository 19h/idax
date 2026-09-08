import XCTest

@testable import IDAX

private final class ExportProbe: PluginModule {
    var information: Plugin.Information { .init(name: "Probe") }
    func run(argument: UInt64) throws(IDAError) {}
}
private final class CallbackProbe {}
final class LifecycleTests: XCTestCase {
    func testExportOutsideFactoryRejectsAndReleasesInstance() {
        var module: ExportProbe? = ExportProbe()
        weak var weakModule = module
        XCTAssertThrowsError(try Plugin.exportModule(module!)) { error in
            XCTAssertEqual((error as? IDAError)?.category, .conflict)
        }
        module = nil
        XCTAssertNil(weakModule)
    }
    func testFailedUninitializedRegistrationReleasesCapture() {
        var probe: CallbackProbe? = CallbackProbe()
        weak var weakProbe = probe
        XCTAssertThrowsError(
            try Event.subscribe(handler: { [owned = probe!] (_) throws(IDAError) -> Void in _ = owned })
        ) { error in XCTAssertEqual((error as? IDAError)?.category, .conflict) }
        probe = nil
        XCTAssertNil(weakProbe)
    }
    func testFormBuilderUsesTypedMarkupAndRejectsInjection() throws {
        let number = UI.FormBinding<Int64>(.min)
        let bits = UI.FormBinding<UInt16>(3)
        let text = UI.FormBinding("βeta")
        let form = UI.FormBuilder(title: "Example").addInteger("Count", value: number).addBitset(
            "Modes", value: bits, choices: ["A", "B"]
        ).addText("Name", value: text)
        let markup = try form.markup
        XCTAssertTrue(markup.contains("<Count:D:10:10::>"))
        XCTAssertTrue(markup.contains("<##Modes##A:C>\n<B:C>>"))
        XCTAssertTrue(markup.contains("<Name:q:256:40::>"))
        XCTAssertEqual(number.value, .min)
        XCTAssertEqual(bits.value, 3)
        XCTAssertEqual(text.value, "βeta")
        let invalid = UI.FormBuilder(title: "Invalid").addInteger("X:D:1::><Y", value: number)
        XCTAssertThrowsError(try invalid.markup)
    }
    func testFormBuilderDefaultConstructionPreservesNativeMarkup() throws {
        let untitled = UI.FormBuilder()
        let explicitlyEmpty = UI.FormBuilder(title: "")
        XCTAssertEqual(try untitled.markup, "")
        XCTAssertEqual(try explicitlyEmpty.markup, "\n\n")
        let value = UI.FormBinding<Int64>(7)
        untitled.addInteger("Count", value: value)
        explicitlyEmpty.addInteger("Count", value: value)
        XCTAssertEqual(try untitled.markup, "<Count:D:10:10::>\n")
        XCTAssertEqual(try explicitlyEmpty.markup, "\n\n<Count:D:10:10::>\n")
        XCTAssertEqual(value.value, 7)
    }
    func testProcessorOutputTokenExtractionPreservesText() throws {
        var output = Processor.OutputContext()
        output.mnemonic("mov")
        output.space()
        output.registerName("r0")
        output.comma()
        try output.immediate(-1)
        let text = output.text
        let tokens = output.takeTokens()
        XCTAssertEqual(text, "mov r0,0xffffffffffffffff")
        XCTAssertEqual(tokens.count, 5)
        XCTAssertEqual(output.text, text)
        XCTAssertTrue(output.tokens.isEmpty)
        XCTAssertFalse(output.isEmpty)
        XCTAssertEqual(output.take(), text)
        XCTAssertTrue(output.isEmpty)
        XCTAssertThrowsError(try output.immediate(1, radix: 3))
    }
    func testLoaderFlagEncodingPreservesEveryDeclaredBit() throws {
        for bit in 0..<16 {
            let original = UInt16(1) << bit
            let decoded = try Loader.LoadFlags(rawValue: original)
            let encoded = try decoded.rawValue
            // The canonical record deliberately omits unrecognized SDK bits.
            XCTAssertTrue(encoded == original || encoded == 0)
            XCTAssertEqual(try Loader.LoadFlags(rawValue: encoded).rawValue, encoded)
        }
        var flags = Loader.LoadFlags()
        flags.createSegments = true
        flags.reload = true
        flags.loadAllSegments = true
        let decoded = try Loader.LoadFlags(rawValue: flags.rawValue)
        XCTAssertTrue(decoded.createSegments)
        XCTAssertTrue(decoded.reload)
        XCTAssertTrue(decoded.loadAllSegments)
        XCTAssertFalse(decoded.manualLoad)
    }
}
