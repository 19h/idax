import Testing
import Foundation
@testable import IDAX

// MARK: - Error Model

@Suite("IDA Error Model")
struct ErrorModelTests {
    @Test func errorCategoryDescription() {
        #expect(IDAErrorCategory.validation.description == "Validation")
        #expect(IDAErrorCategory.notFound.description == "NotFound")
        #expect(IDAErrorCategory.conflict.description == "Conflict")
        #expect(IDAErrorCategory.unsupported.description == "Unsupported")
        #expect(IDAErrorCategory.sdkFailure.description == "SdkFailure")
        #expect(IDAErrorCategory.internal.description == "Internal")
    }

    @Test func errorDescription() {
        let err = IDAError(category: .notFound, code: 42, message: "symbol missing")
        #expect(err.description == "[NotFound] symbol missing")
    }

    @Test func errorCategoryRawValues() {
        #expect(IDAErrorCategory.validation.rawValue == 1)
        #expect(IDAErrorCategory.notFound.rawValue == 2)
        #expect(IDAErrorCategory.conflict.rawValue == 3)
        #expect(IDAErrorCategory.unsupported.rawValue == 4)
        #expect(IDAErrorCategory.sdkFailure.rawValue == 5)
        #expect(IDAErrorCategory.internal.rawValue == 6)
    }

    @Test func unknownCategoryRawValueReturnsNil() {
        #expect(IDAErrorCategory(rawValue: 0) == nil)
        #expect(IDAErrorCategory(rawValue: 99) == nil)
    }
}

@Suite("IDA Error Helpers")
struct ErrorHelperTests {
    @Test func consumeLastErrorUsesFallbackCategory() {
        let err = consumeLastError(fallback: "test fallback")
        #expect(err.category == .internal)
    }

    @Test func checkStatusSuccessDoesNotThrow() throws {
        try checkStatus(0, "should not throw")
    }

    @Test func checkStatusFailureThrows() {
        #expect(throws: IDAError.self) {
            try checkStatus(-1, "expected failure")
        }
    }
}

// MARK: - Address Types

@Suite("IDA Address Types")
struct AddressTypeTests {
    @Test func badAddressIsSentinel() {
        #expect(badAddress == UInt64.max)
    }

    @Test func addressTypealiasesAreCorrectWidth() {
        let addr: Address = 0x00400000
        #expect(addr == 4194304)

        let delta: AddressDelta = -128
        #expect(delta < 0)

        let size: AddressSize = 0x1000
        #expect(size == 4096)
    }
}

// MARK: - Segment Types

@Suite("IDA SegmentType")
struct SegmentTypeTests {
    @Test func allRawValues() {
        #expect(SegmentType.normal.rawValue == 0)
        #expect(SegmentType.external.rawValue == 1)
        #expect(SegmentType.code.rawValue == 2)
        #expect(SegmentType.data.rawValue == 3)
        #expect(SegmentType.bss.rawValue == 4)
        #expect(SegmentType.absoluteSymbols.rawValue == 5)
        #expect(SegmentType.common.rawValue == 6)
        #expect(SegmentType.null.rawValue == 7)
        #expect(SegmentType.undefined.rawValue == 8)
        #expect(SegmentType.import.rawValue == 9)
        #expect(SegmentType.internalMemory.rawValue == 10)
        #expect(SegmentType.group.rawValue == 11)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(SegmentType(rawValue: 99) == nil)
    }
}

@Suite("IDA Permissions")
struct PermissionsTests {
    @Test func equality() {
        let a = Permissions(read: true, write: false, execute: true)
        let b = Permissions(read: true, write: false, execute: true)
        let c = Permissions(read: false, write: true, execute: false)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func allFalse() {
        let p = Permissions(read: false, write: false, execute: false)
        #expect(!p.read)
        #expect(!p.write)
        #expect(!p.execute)
    }

    @Test func allTrue() {
        let p = Permissions(read: true, write: true, execute: true)
        #expect(p.read)
        #expect(p.write)
        #expect(p.execute)
    }
}

// MARK: - Operand Types

@Suite("IDA OperandType")
struct OperandTypeTests {
    @Test func allRawValues() {
        #expect(OperandType.void_.rawValue == 0)
        #expect(OperandType.register.rawValue == 1)
        #expect(OperandType.memory.rawValue == 2)
        #expect(OperandType.phrase.rawValue == 3)
        #expect(OperandType.displacement.rawValue == 4)
        #expect(OperandType.immediate.rawValue == 5)
        #expect(OperandType.far.rawValue == 6)
        #expect(OperandType.near.rawValue == 7)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(OperandType(rawValue: 99) == nil)
    }
}

@Suite("IDA Operand predicates")
struct OperandPredicateTests {
    @Test func isImmediateWhenTypeIsImmediate() {
        let op = Operand(
            index: 0, operandType: .immediate, registerID: 0,
            registerName: "", registerCategory: 0, value: 42,
            targetAddress: 0, byteWidth: 4,
            isRead: true, isWritten: false
        )
        #expect(op.isImmediate)
        #expect(!op.isRegister)
        #expect(!op.isMemory)
    }

    @Test func isRegisterWhenTypeIsRegister() {
        let op = Operand(
            index: 0, operandType: .register, registerID: 1,
            registerName: "rax", registerCategory: 0, value: 0,
            targetAddress: 0, byteWidth: 8,
            isRead: true, isWritten: true
        )
        #expect(op.isRegister)
        #expect(!op.isImmediate)
    }
}

// MARK: - Xref Types

@Suite("IDA ReferenceType")
struct ReferenceTypeTests {
    @Test func rawValues() {
        #expect(ReferenceType.unknown.rawValue == 0)
        #expect(ReferenceType.flow.rawValue == 1)
        #expect(ReferenceType.callNear.rawValue == 2)
        #expect(ReferenceType.callFar.rawValue == 3)
        #expect(ReferenceType.jumpNear.rawValue == 4)
        #expect(ReferenceType.jumpFar.rawValue == 5)
        #expect(ReferenceType.offset.rawValue == 6)
        #expect(ReferenceType.read.rawValue == 7)
        #expect(ReferenceType.write.rawValue == 8)
        #expect(ReferenceType.text.rawValue == 9)
        #expect(ReferenceType.informational.rawValue == 10)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(ReferenceType(rawValue: 99) == nil)
    }
}

@Suite("IDA CodeXrefType")
struct CodeXrefTypeTests {
    @Test func rawValues() {
        #expect(CodeXrefType.callFar.rawValue == 0)
        #expect(CodeXrefType.callNear.rawValue == 1)
        #expect(CodeXrefType.jumpFar.rawValue == 2)
        #expect(CodeXrefType.jumpNear.rawValue == 3)
        #expect(CodeXrefType.flow.rawValue == 4)
    }
}

@Suite("IDA DataXrefType")
struct DataXrefTypeTests {
    @Test func rawValues() {
        #expect(DataXrefType.offset.rawValue == 0)
        #expect(DataXrefType.write.rawValue == 1)
        #expect(DataXrefType.read.rawValue == 2)
        #expect(DataXrefType.text.rawValue == 3)
        #expect(DataXrefType.informational.rawValue == 4)
    }
}

// MARK: - Fixup Types

@Suite("IDA FixupType")
struct FixupTypeTests {
    @Test func basicRawValues() {
        #expect(FixupType.off8.rawValue == 0)
        #expect(FixupType.off16.rawValue == 1)
        #expect(FixupType.seg16.rawValue == 2)
        #expect(FixupType.ptr16.rawValue == 3)
        #expect(FixupType.off32.rawValue == 4)
        #expect(FixupType.ptr32.rawValue == 5)
        #expect(FixupType.off64.rawValue == 10)
        #expect(FixupType.custom.rawValue == 14)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(FixupType(rawValue: 99) == nil)
    }
}

// MARK: - Name Types

@Suite("IDA DemangledForm")
struct DemangledFormTests {
    @Test func rawValues() {
        #expect(DemangledForm.short.rawValue == 0)
        #expect(DemangledForm.long.rawValue == 1)
        #expect(DemangledForm.typeOnly.rawValue == 2)
    }
}

// MARK: - Decompiler Types

@Suite("IDA VariableStorage")
struct VariableStorageTests {
    @Test func rawValues() {
        #expect(VariableStorage.unknown.rawValue == 0)
        #expect(VariableStorage.register.rawValue == 1)
        #expect(VariableStorage.stack.rawValue == 2)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(VariableStorage(rawValue: 99) == nil)
    }
}

@Suite("IDA CtreeItemType")
struct CtreeItemTypeTests {
    @Test func expressionRawValues() {
        #expect(CtreeItemType.exprEmpty.rawValue == 0)
        #expect(CtreeItemType.exprCall.rawValue == 57)
        #expect(CtreeItemType.exprType.rawValue == 69)
    }

    @Test func statementRawValues() {
        #expect(CtreeItemType.stmtEmpty.rawValue == 70)
        #expect(CtreeItemType.stmtBlock.rawValue == 71)
        #expect(CtreeItemType.stmtIf.rawValue == 73)
        #expect(CtreeItemType.stmtFor.rawValue == 74)
        #expect(CtreeItemType.stmtSwitch.rawValue == 77)
        #expect(CtreeItemType.stmtReturn.rawValue == 80)
        #expect(CtreeItemType.stmtThrow.rawValue == 84)
    }

    @Test func isExpressionAndStatement() {
        #expect(CtreeItemType.exprCall.isExpression)
        #expect(!CtreeItemType.exprCall.isStatement)
        #expect(CtreeItemType.stmtIf.isStatement)
        #expect(!CtreeItemType.stmtIf.isExpression)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(CtreeItemType(rawValue: 999) == nil)
    }
}

@Suite("IDA CtreeVisitAction")
struct CtreeVisitActionTests {
    @Test func rawValues() {
        #expect(CtreeVisitAction.continue.rawValue == 0)
        #expect(CtreeVisitAction.stop.rawValue == 1)
        #expect(CtreeVisitAction.skipChildren.rawValue == 2)
    }
}

// MARK: - Value Type Construction

@Suite("IDA Chunk")
struct ChunkTests {
    @Test func basicConstruction() {
        let c = Chunk(start: 0x1000, end: 0x2000, isTail: false, owner: 0x1000)
        #expect(c.start == 0x1000)
        #expect(c.end == 0x2000)
        #expect(!c.isTail)
        #expect(c.owner == 0x1000)
    }

    @Test func tailChunk() {
        let c = Chunk(start: 0x3000, end: 0x3100, isTail: true, owner: 0x1000)
        #expect(c.isTail)
        #expect(c.owner == 0x1000)
    }
}

@Suite("IDA FrameVariable")
struct FrameVariableTests {
    @Test func basicConstruction() {
        let fv = FrameVariable(
            name: "local_0", byteOffset: 0, byteSize: 8,
            comment: "", isSpecial: false
        )
        #expect(fv.name == "local_0")
        #expect(fv.byteSize == 8)
        #expect(!fv.isSpecial)
    }

    @Test func specialVariable() {
        let fv = FrameVariable(
            name: "__return_address", byteOffset: 16, byteSize: 8,
            comment: "return addr", isSpecial: true
        )
        #expect(fv.isSpecial)
        #expect(fv.comment == "return addr")
    }
}

@Suite("IDA LocalVariable")
struct LocalVariableTests {
    @Test func basicConstruction() {
        let lv = LocalVariable(
            name: "result", typeName: "int", isArgument: false,
            width: 4, hasUserName: true, storage: .stack, comment: "",
            stackOffset: 0x8, registerNumber: -1
        )
        #expect(lv.name == "result")
        #expect(lv.storage == .stack)
        #expect(!lv.isArgument)
        #expect(lv.hasUserName)
        #expect(lv.stackOffset == 0x8)
        #expect(lv.registerNumber == -1)
    }

    @Test func argumentVariable() {
        let lv = LocalVariable(
            name: "argc", typeName: "int", isArgument: true,
            width: 4, hasUserName: false, storage: .register, comment: "",
            stackOffset: -1, registerNumber: 8
        )
        #expect(lv.isArgument)
        #expect(lv.storage == .register)
        #expect(lv.stackOffset == -1)
        #expect(lv.registerNumber == 8)
    }
}

// MARK: - CallingConvention

@Suite("IDA CallingConvention")
struct CallingConventionTests {
    @Test func rawValues() {
        #expect(CallingConvention.unknown.rawValue == 0)
        #expect(CallingConvention.cdecl.rawValue == 1)
        #expect(CallingConvention.stdcall.rawValue == 2)
        #expect(CallingConvention.pascal.rawValue == 3)
        #expect(CallingConvention.fastcall.rawValue == 4)
        #expect(CallingConvention.thiscall.rawValue == 5)
        #expect(CallingConvention.swift.rawValue == 6)
        #expect(CallingConvention.golang.rawValue == 7)
        #expect(CallingConvention.userDefined.rawValue == 8)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(CallingConvention(rawValue: -1) == nil)
        #expect(CallingConvention(rawValue: 9) == nil)
    }
}

// MARK: - Color

@Suite("IDA Color")
struct ColorTests {
    @Test func representativeRawValues() {
        #expect(Color.default.rawValue == 0x01)
        #expect(Color.instruction.rawValue == 0x05)
        #expect(Color.number.rawValue == 0x0C)
        #expect(Color.keyword.rawValue == 0x20)
        #expect(Color.collapsed.rawValue == 0x27)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(Color(rawValue: 0x00) == nil)
        #expect(Color(rawValue: 0x28) == nil)
    }

    @Test func tagConstants() {
        #expect(Color.tagOn == 0x01)
        #expect(Color.tagOff == 0x02)
        #expect(Color.tagEscape == 0x03)
        #expect(Color.tagInverse == 0x04)
        #expect(Color.addressTag == 0x28)
        #expect(Color.addressTagSize == 16)
    }
}

// MARK: - ProcessorID

@Suite("IDA ProcessorID")
struct ProcessorIDTests {
    @Test func representativeRawValues() {
        #expect(ProcessorID.intelX86.rawValue == 0)
        #expect(ProcessorID.arm.rawValue == 13)
        #expect(ProcessorID.mips.rawValue == 12)
        #expect(ProcessorID.riscV.rawValue == 72)
        #expect(ProcessorID.wasm.rawValue == 75)
        #expect(ProcessorID.mcore.rawValue == 77)
    }

    @Test func unknownRawValueReturnsNil() {
        #expect(ProcessorID(rawValue: -1) == nil)
        #expect(ProcessorID(rawValue: 78) == nil)
    }
}

// MARK: - GraphLayout

@Suite("IDA GraphLayout")
struct GraphLayoutTests {
    @Test func allRawValues() {
        #expect(GraphLayout.none.rawValue == 0)
        #expect(GraphLayout.digraph.rawValue == 1)
        #expect(GraphLayout.tree.rawValue == 2)
        #expect(GraphLayout.circle.rawValue == 3)
        #expect(GraphLayout.polarTree.rawValue == 4)
        #expect(GraphLayout.orthogonal.rawValue == 5)
        #expect(GraphLayout.radialTree.rawValue == 6)
    }
}

// MARK: - CrossReference Predicates

@Suite("IDA CrossReference Predicates")
struct CrossReferencePredicateTests {
    @Test func isCall() {
        let callNear = CrossReference(from: 0, to: 1, isCode: true,
                                      type: .callNear, isUserDefined: false)
        let callFar = CrossReference(from: 0, to: 1, isCode: true,
                                     type: .callFar, isUserDefined: false)
        let jump = CrossReference(from: 0, to: 1, isCode: true,
                                  type: .jumpNear, isUserDefined: false)
        #expect(callNear.isCall)
        #expect(callFar.isCall)
        #expect(!jump.isCall)
    }

    @Test func isJump() {
        let jumpNear = CrossReference(from: 0, to: 1, isCode: true,
                                      type: .jumpNear, isUserDefined: false)
        let jumpFar = CrossReference(from: 0, to: 1, isCode: true,
                                     type: .jumpFar, isUserDefined: false)
        #expect(jumpNear.isJump)
        #expect(jumpFar.isJump)
    }

    @Test func isFlow() {
        let flow = CrossReference(from: 0, to: 1, isCode: true,
                                  type: .flow, isUserDefined: false)
        #expect(flow.isFlow)
    }

    @Test func dataPredicates() {
        let read = CrossReference(from: 0, to: 1, isCode: false,
                                  type: .read, isUserDefined: false)
        let write = CrossReference(from: 0, to: 1, isCode: false,
                                   type: .write, isUserDefined: false)
        #expect(read.isDataReference)
        #expect(read.isDataRead)
        #expect(!read.isDataWrite)
        #expect(write.isDataWrite)
        #expect(!write.isDataRead)
    }
}

// MARK: - Diagnostics Convenience

@Suite("IDA Diagnostics Convenience")
struct DiagnosticsConvenienceTests {
    @Test func enrichAppendsContext() {
        let original = IDAError(category: .notFound, code: 1, message: "symbol missing")
        let enriched = Diagnostics.enrich(original, context: "in function foo")
        #expect(enriched.message == "symbol missing; in function foo")
        #expect(enriched.category == .notFound)
        #expect(enriched.code == 1)
    }

    @Test func enrichEmptyMessage() {
        let original = IDAError(category: .internal, code: 0, message: "")
        let enriched = Diagnostics.enrich(original, context: "context only")
        #expect(enriched.message == "context only")
    }

    @Test func assertInvariantPasses() throws {
        try Diagnostics.assertInvariant(true, "should pass")
    }

    @Test func assertInvariantFails() {
        #expect(throws: IDAError.self) {
            try Diagnostics.assertInvariant(false, "expected failure")
        }
    }
}

// MARK: - DecompilerView

@Suite("IDA DecompilerView")
struct DecompilerViewTests {
    @Test func construction() {
        let view = DecompilerView(functionAddress: 0x401000)
        #expect(view.functionAddress == 0x401000)
    }
}

// MARK: - OpenMode

@Suite("IDA OpenMode")
struct OpenModeTests {
    @Test func rawValues() {
        #expect(OpenMode.analyze.rawValue == 0)
        #expect(OpenMode.skipAnalysis.rawValue == 1)
    }
}

// MARK: - LoadIntent

@Suite("IDA LoadIntent")
struct LoadIntentTests {
    @Test func rawValues() {
        #expect(LoadIntent.autoDetect.rawValue == 0)
        #expect(LoadIntent.binary.rawValue == 1)
        #expect(LoadIntent.nonBinary.rawValue == 2)
    }
}

// MARK: - RuntimeOptions

@Suite("IDA RuntimeOptions")
struct RuntimeOptionsTests {
    @Test func defaults() {
        let options = RuntimeOptions()
        #expect(!options.quiet)
        #expect(!options.disableUserPlugins)
    }
}

// MARK: - OperationOptions

@Suite("IDA OperationOptions")
struct OperationOptionsTests {
    @Test func defaults() {
        let options = OperationOptions()
        #expect(options.strictValidation)
        #expect(!options.allowPartialResults)
        #expect(options.cancelOnUserBreak)
        #expect(options.quiet)
    }
}

// MARK: - WaitOptions

@Suite("IDA WaitOptions")
struct WaitOptionsTests {
    @Test func defaults() {
        let options = WaitOptions()
        #expect(options.timeoutMilliseconds == 0)
        #expect(options.pollIntervalMilliseconds == 10)
    }
}

// MARK: - Runtime Availability

@Suite("IDA Runtime")
struct RuntimeTests {
    @Test func isAvailableDoesNotCrash() {
        // Must return a Bool without crashing, regardless of whether IDA is installed.
        let result = IDARuntime.isAvailable
        #expect(result == true || result == false)
    }

    @Test func isAvailableIsConsistent() {
        // Repeated calls must return the same value.
        let first = IDARuntime.isAvailable
        let second = IDARuntime.isAvailable
        #expect(first == second)
    }

    @Test func test() async throws {
        guard let databasePath = ProcessInfo.processInfo.environment["IDAX_TEST_DATABASE"] else {
            print("IDAX_TEST_DATABASE not set, skipping integration test")
            return
        }

        print("=== IDAX Swift Example ===")
        print("Runtime available: \(IDARuntime.isAvailable)")

        guard IDARuntime.isAvailable else {
            print("ERROR: IDA Pro runtime not found.")
            return
        }

        do {
            print("Initializing IDA...")
            try Database.initialize()

            print("Opening: \(databasePath)")
            try Database.open(databasePath, autoAnalysis: false)

            print("--- Database Info ---")
            try print("  Input file:  \(Database.inputFilePath())")
            try print("  File type:   \(Database.fileTypeName())")
            try print("  Processor:   \(Database.processorName())")
            try print("  Image base:  0x\(String(Database.imageBase(), radix: 16))")
            try print("  Address bits: \(Database.addressBitness())")

            print("--- Segments ---")
            let segments = try Segment.all()
            for seg in segments {
                let start = String(seg.start, radix: 16)
                let end = String(seg.end, radix: 16)
                print("  \(seg.name): 0x\(start) - 0x\(end) (\(seg.size) bytes)")
            }

            print("--- Functions (first 20) ---")
            let functions = try Function.all()
            print("  Total: \(functions.count)")
            for fn in functions.prefix(20) {
                let addr = String(fn.start, radix: 16)
                print("  0x\(addr): \(fn.name)")
            }

            print("--- Closing ---")
            try Database.close()
            print("Done.")
        } catch {
            print("ERROR: \(error)")
        }
    }
}
