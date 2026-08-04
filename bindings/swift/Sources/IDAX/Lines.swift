internal import CIDAX

/// Syntax-highlight color codes for IDA listing output.
///
/// Mirrors the color tag constants in C++ `ida::lines`.
public enum Color: UInt8, Sendable {
    case `default` = 0x01
    case regularComment = 0x02
    case repeatableComment = 0x03
    case autoComment = 0x04
    case instruction = 0x05
    case dataName = 0x06
    case regularDataName = 0x07
    case demangledName = 0x08
    case symbol = 0x09
    case charLiteral = 0x0A
    case string = 0x0B
    case number = 0x0C
    case void_ = 0x0D
    case codeReference = 0x0E
    case dataReference = 0x0F
    case codeReferenceTail = 0x10
    case dataReferenceTail = 0x11
    case error = 0x12
    case prefix = 0x13
    case binaryPrefix = 0x14
    case extra = 0x15
    case altOperand = 0x16
    case hiddenName = 0x17
    case libraryName = 0x18
    case localName = 0x19
    case dummyCodeName = 0x1A
    case asmDirective = 0x1B
    case macro = 0x1C
    case dataString = 0x1D
    case dataChar = 0x1E
    case dataNumber = 0x1F
    case keyword = 0x20
    case register = 0x21
    case importedName = 0x22
    case segmentName = 0x23
    case unknownName = 0x24
    case codeName = 0x25
    case userName = 0x26
    case collapsed = 0x27

    public static let tagOn: UInt8 = 0x01
    public static let tagOff: UInt8 = 0x02
    public static let tagEscape: UInt8 = 0x03
    public static let tagInverse: UInt8 = 0x04
    public static let addressTag: UInt8 = 0x28
    public static let addressTagSize: Int = 16
}

/// Color tag manipulation for pseudocode and listing output.
///
/// Mirrors C++ `ida::lines`.
public enum Lines {
    public static func colorString(_ text: String, color: Color) throws(IDAError) -> String {
        try withStringOutput("lines.colstr") { out in
            text.withCString { idax_lines_colstr($0, color.rawValue, out) }
        }
    }

    public static func tagRemove(_ taggedText: String) throws(IDAError) -> String {
        try withStringOutput("lines.tagRemove") { out in
            taggedText.withCString { idax_lines_tag_remove($0, out) }
        }
    }

    public static func tagLength(_ taggedText: String) -> Int {
        taggedText.withCString { Int(idax_lines_tag_strlen($0)) }
    }

    public static func tagAdvance(_ taggedText: String, position: Int) -> Int {
        taggedText.withCString { Int(idax_lines_tag_advance($0, Int32(position))) }
    }

    public static func makeAddressTag(itemIndex: Int) throws(IDAError) -> String {
        try withStringOutput("lines.makeAddressTag") { idax_lines_make_addr_tag(Int32(itemIndex), $0) }
    }

    public static func decodeAddressTag(_ taggedText: String, position: Int) -> Int {
        taggedText.withCString { Int(idax_lines_decode_addr_tag($0, position)) }
    }
}
