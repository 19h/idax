import Foundation
import IDAX

@main
struct MemberConsumers {
    static func validation(_ body: () throws(IDAError) -> UInt64) {
        do { _ = try body(); preconditionFailure("Expected Validation") }
        catch { precondition(error.category == .validation) }
    }

    static func main() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("idax-sdk95-swift-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = directory.appendingPathComponent("fixture.i64")
        try FileManager.default.copyItem(atPath: CommandLine.arguments[1], toPath: fixture.path)
        try Runtime.initialize(options: .init(quiet: true))
        try Database.open(path: fixture.path, autoAnalysis: false)
        defer { try? Database.close() }
        let cases: [(String, String, String, UInt64, Bool, Bool)] = [
            ("read_wide", "IDAXHuge950", "wide", 2147483664, false, false),
            ("read_bits", "IDAXSmallBits950", "target", 3, true, false),
            ("read_big_bits", "IDAXBigBits950", "target", 4294967299, true, false),
            ("read_union", "IDAXChoice950", "real", 1, false, true),
        ]
        for (function, typeName, field, value, bitfield, union) in cases {
            let address: Address
            do { address = try Names.resolve(name: function) }
            catch { address = try Names.resolve(name: "_" + function) }
            var matches = 0
            _ = try Decompiler.decompile(address).forEachExpression { expression throws(IDAError) in
                let kind = try expression.type()
                guard kind == .exprMemberRef || kind == .exprMemberPtr else { return .continue }
                let actualName = try expression.memberName()
                let actualFlag = try expression.memberIsBitfield()
                precondition(actualName == field && actualFlag == bitfield)
                if union {
                    let index = try expression.memberIndex()
                    precondition(index == value)
                    validation { () throws(IDAError) in try expression.memberOffset() }
                    validation { () throws(IDAError) in try expression.memberBitOffset() }
                } else {
                    let bytes = try expression.memberOffset()
                    let bits = try expression.memberBitOffset()
                    precondition(bytes == (bitfield ? value / 8 : value))
                    precondition(bits == (bitfield ? value : value * 8))
                    validation { () throws(IDAError) in try expression.memberIndex() }
                }
                if function == "read_wide" {
                    let width = try expression.left().pointedTypeByteWidth()
                    precondition(width == 2147483668)
                }
                matches += 1
                return .continue
            }
            precondition(matches > 0)
            let collection = try Decompiler.collectReferencedTypes(inFunction: address)
            let used = collection.usedOffsets.first { $0.typeName == typeName }!
            precondition(used.byteOffsets == (bitfield || union ? [] : [value]))
            precondition(used.bitOffsets == (bitfield ? [value] : []))
            precondition(used.memberIndices == (union ? [value] : []))
            let rendered = try Types.renderNamedDeclarations([typeName], options: .init(trimUnreferenced: true, usedOffsets: collection.usedOffsets))
            precondition(rendered.contains(field))
            if !union { precondition(!rendered.contains("before") && !rendered.contains("padding[")) }
            let parsed = try TypeInfo.parse(rendered.replacingOccurrences(of: typeName, with: typeName + "SwiftTrimmed"))
            let expectedSize = typeName == "IDAXHuge950" ? 2147483668 : typeName == "IDAXBigBits950" ? 536870916 : 4
            let parsedSize = try parsed.size()
            precondition(parsedSize == expectedSize)
            if !union {
                let member = try parsed.member(named: field)
                precondition(UInt64(member.bitOffset) == (bitfield ? value : value * 8))
            }
            print("PASS: Swift \(function) exact UInt64/name/unit/collection/render")
        }
    }
}
