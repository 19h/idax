import XCTest

@testable import IDAX

final class CustomFormTests: XCTestCase {
    func testCustomLayoutPreservesNativeArgumentOrder() throws {
        let text = UI.FormBinding("βeta")
        let address = UI.FormBinding<Address>(.max)
        let integer = UI.FormBinding<Int64>(.min)
        let firstBits = UI.FormBinding<UInt16>(3)
        let secondBits = UI.FormBinding<UInt16>(1)
        let firstRadio = UI.FormBinding<UInt16>(0)
        let secondRadio = UI.FormBinding<UInt16>(1)
        let path = UI.FormBinding("input.idb")
        let markup = """
            STARTITEM 2
            AUTOSYNC
            BUTTON YES ~A~pply
            BUTTON CANCEL Cancel
            HELP
            Literal help: <not a control> and %q are explanatory text.
            ENDHELP
            Custom layout

            Current name: %10q at %11$
            <#item: hint#Flags: title#group: hint#First:C1> <Other:c2>
            <Count:D3:+10:10::>
            <Second:C4>20> <Another:c5>21>
            <No:R6> <On:r7>
            <Yes:R8>22> <Off:r9>23>
            <|><->
            <File:f10:0:64::>
            <=:Advanced>30>
            Literal progress: 100%%
            """
        try UI.validateForm(markup: markup, bindings: [
            .text(text), .address(address), .integer(integer), .bitset(firstBits),
            .bitset(secondBits), .radio(firstRadio), .radio(secondRadio), .path(path),
        ])
        XCTAssertEqual(text.value, "βeta")
        XCTAssertEqual(address.value, .max)
        XCTAssertEqual(integer.value, .min)
        XCTAssertEqual(firstBits.value, 3)
        XCTAssertEqual(secondBits.value, 1)
        XCTAssertEqual(firstRadio.value, 0)
        XCTAssertEqual(secondRadio.value, 1)
        XCTAssertEqual(path.value, "input.idb")
        // Group arguments occur at their closing marker, after Count.
        assertValidation(markup, [
            .text(text), .address(address), .bitset(firstBits), .integer(integer),
            .bitset(secondBits), .radio(firstRadio), .radio(secondRadio), .path(path),
        ])
    }

    func testCompatibleScalarTextAndDynamicLabelStorage() throws {
        let signed = UI.FormBinding<Int64>(.min)
        let unsigned = UI.FormBinding<Address>(.max)
        for type in "SNnLlMmuDOoYsH$" {
            let markup = "Numeric\n\n<Value:\(type)42::18::>\n"
            try UI.validateForm(markup: markup, bindings: [.integer(signed)])
            try UI.validateForm(markup: markup, bindings: [.address(unsigned)])
        }
        let text = UI.FormBinding("日本語 α")
        for type in "qiIyp" {
            try UI.validateForm(markup: "Text\n\n<Value:\(type)7:256:40::>\n", bindings: [.text(text)])
            try UI.validateForm(markup: "Label\n\n%19\(type)\n", bindings: [.text(text)])
        }
        try UI.validateForm(markup: "Labels\n\n%12n %13$\n", bindings: [.integer(signed), .address(unsigned)])
        XCTAssertEqual(signed.value, .min)
        XCTAssertEqual(unsigned.value, .max)
        XCTAssertEqual(text.value, "日本語 α")
    }

    func testCharacterBuffersFollowNativeControlCapacity() throws {
        let longText = UI.FormBinding(String(repeating: "x", count: 8192))
        for markup in [
            "Command\n\n<Command:X::40::>\n", // MAXSTR can exceed QMAXPATH on Windows.
            "Command\n\n<Command:X:16384:40::>\n",
            "Label\n\n%3A\n",
            "HTML\n\n%4h\n",
            "Folder\n\n<Folder:F::40::>\n",
        ] {
            try UI.validateForm(markup: markup, bindings: [.path(longText)])
        }
        assertValidation("Command\n\n<Command:X:0:40::>", [.path(longText)])
        assertValidation("HTML\n\n%h", [.text(longText)])
        XCTAssertEqual(longText.value.count, 8192)
    }

    func testCountTypeAndGroupValidationPrecedesNativeDispatch() {
        let integer = UI.FormBinding<Int64>(7)
        let text = UI.FormBinding("original")
        let bits = UI.FormBinding<UInt16>(1)
        assertValidation("Title\n\n<Value:D:10:10::>", [])
        assertValidation("Title\n\nNo placeholders", [.integer(integer)])
        assertValidation("Title\n\n<Value:q:10:10::>", [.integer(integer)])
        assertValidation("Title\n\n<Yes:R>>", [.bitset(bits)])
        assertValidation("Title\n\n<Flag:C>", [.bitset(bits)])
        assertValidation("Title\n\n<Value:Dx:10:10::>", [.integer(integer)])
        assertValidation("Title\n\n<Value:D:10:10::", [.integer(integer)])
        assertValidation("Title\n\n<%q:D:10:10::>", [.text(text), .integer(integer)])
        assertValidation("Title\n\n%999", [.integer(integer)])
        assertValidation("", [])
        assertValidation("Title\n\nValue\0trailing", [])
        let tooManyFlags = "Title\n\n" + String(repeating: "<Flag:C>\n", count: 17) + ">"
        assertValidation(tooManyFlags, [.bitset(bits)])
        XCTAssertThrowsError(try UI.askForm(markup: "Title\n\n<Value:q:10:10::>", bindings: [.integer(integer)])) {
            XCTAssertEqual(($0 as? IDAError)?.category, .validation)
        }
        XCTAssertEqual(integer.value, 7)
        XCTAssertEqual(text.value, "original")
        XCTAssertEqual(bits.value, 1)
    }

    func testCallbacksAndMultiArgumentPointerControlsAreRejected() {
        let number = UI.FormBinding<Int64>(0)
        for markup in [
            "Title\n\n%/", "Title\n\n%*", "Title\n\n%12/",
            "HELP\nDo not bind %/ here\nENDHELP\nTitle\n\n",
            "Title\n\n<Chooser:E:0:40::>", "Title\n\n<List:b:0:40::>",
            "Title\n\n<Button:B:0:::>", "Title\n\n<Color:K:0:::>",
            "Title\n\n<Text:t:0:40::>",
        ] {
            assertValidation(markup, [.integer(number)])
        }
    }

    func testArgumentCeilingAndPlainLayouts() throws {
        let value = UI.FormBinding<Int64>(3)
        let field = "<Value:D:10:10::>\n"
        try UI.validateForm(markup: "Title\n\n" + String(repeating: field, count: 64),
                            bindings: Array(repeating: .integer(value), count: 64))
        assertValidation("Title\n\n" + String(repeating: field, count: 65),
                         Array(repeating: .integer(value), count: 65))
        try UI.validateForm(markup: "BUTTON YES Continue\nTitle\n\nLiteral 100%%\n<|><->\n<=:Tab>9>\n",
                            bindings: [])
        try UI.validateForm(markup: "Title\n\n<#Confidence 100%%#Progress 100%%:D:10:10::>\n<=:Tab 100%%>9>\n",
                            bindings: [.integer(value)])
    }

    private func assertValidation(_ markup: String, _ bindings: [UI.FormArgument],
                                  file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try UI.validateForm(markup: markup, bindings: bindings), file: file, line: line) {
            XCTAssertEqual(($0 as? IDAError)?.category, .validation, file: file, line: line)
        }
    }
}
