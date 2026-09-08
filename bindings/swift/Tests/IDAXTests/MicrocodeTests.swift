import XCTest

@testable import IDAX

private final class RejectedFilter: Decompiler.MicrocodeFilter {
    func match(context: Decompiler.MicrocodeContext) throws(IDAError) -> Bool { false }
    func apply(context: Decompiler.MicrocodeContext) throws(IDAError) -> Decompiler.MicrocodeApplyResult {
        .notHandled
    }
}
final class MicrocodeTests: XCTestCase {
    func testRejectedRegistrationConsumesCallbackOwner() {
        var filter: RejectedFilter? = RejectedFilter()
        weak var retained = filter
        XCTAssertThrowsError(try Decompiler.registerMicrocodeFilter(filter!)) { error in
            XCTAssertEqual((error as? IDAError)?.category, .conflict)
        }
        filter = nil
        XCTAssertNil(retained)
    }
    func testRecursiveValueBoundaryPreservesOwnedFields() throws {
        let child = Decompiler.MicrocodeInstruction(
            opcode: .add,
            left: .init(kind: .unsignedImmediate, unsignedImmediate: .max, byteWidth: 8),
            right: .init(kind: .signedImmediate, signedImmediate: .min, byteWidth: 8), text: "nested β")
        let operand = Decompiler.MicrocodeOperand(
            kind: .callArguments, registerId: 91,
            localVariableIndex: 4, localVariableOffset: -7, secondRegisterId: 92,
            globalAddress: .max - 1, stackOffset: .min, helperName: "helper_β", blockIndex: 5,
            processorRegisterId: 11, nestedInstruction: child, unsignedImmediate: .max, signedImmediate: .min,
            byteWidth: 8, markUserDefinedType: true,
            referencedOperand: .init(kind: .blockReference, blockIndex: 7),
            callArguments: [.init(kind: .register, registerId: 15, byteWidth: 4)], callTarget: 0x1234,
            text: "display β", stringConstant: "literal β", floatingPointConstant: -0.0,
            globalName: "global_β",
            valueNumber: 0,
            callArgumentProperties: [
                .init(
                    hidden: true, returnValuePointer: true,
                    structureArgument: true, arrayArgument: true, unused: true, swiftSelf: true)
            ],
            callReturnOperands: [
                .init(kind: .registerPair, registerId: 3, secondRegisterId: 4, byteWidth: 8)
            ],
            callReturnRegisters: [.init(registerId: 7, byteWidth: 8)],
            switchCases: [.init(value: .min, targetBlock: 12)], switchDefaultTarget: 0)
        let expected = Decompiler.MicrocodeInstruction(
            opcode: .call, left: operand, right: .init(),
            destination: operand, floatingPointInstruction: true, modifiesDestination: true,
            address: .max - 1, text: "instruction β")
        let copied: Decompiler.MicrocodeInstruction = try {
            let arena = InputArena()
            defer { withExtendedLifetime(arena) {} }
            let native = try expected.native(in: arena, "test recursive input")
            return try Decompiler.MicrocodeInstruction(copying: native, "test recursive copy")
        }()
        XCTAssertEqual(copied, expected)
    }
    func testDeepInputRejectsBeforeUnboundedRecursion() throws {
        var value = Decompiler.MicrocodeOperand(kind: .register, byteWidth: 4)
        for _ in 0..<130 { value = .init(kind: .addressReference, referencedOperand: value) }
        let arena = InputArena()
        XCTAssertThrowsError(try value.native(in: arena, "test depth bound")) { error in
            XCTAssertEqual((error as? IDAError)?.category, .validation)
        }
        XCTAssertThrowsError(try Decompiler.MicrocodeValue(helperName: "a\0b").native(in: arena, "test NUL"))
    }
    func testCallOptionsPreserveZeroOptionalValuesAndLocationArrays() throws {
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        let location = Decompiler.MicrocodeValueLocation(
            kind: .scattered,
            scatteredParts: [
                .init(kind: .registerWithOffset, registerId: 7, registerOffset: 1, byteOffset: 0, byteSize: 4)
            ])
        let options = Decompiler.MicrocodeCallOptions(
            insertPolicy: .beginning, calleeAddress: 0,
            solidArgumentCount: 0, callStackPointerDelta: 0, stackArgumentsTop: 0, functionRole: .memcpy,
            returnLocation: location, returnTypeDeclaration: "unsigned int", callingConvention: .fastcall,
            markFinal: true, markPropagated: true, markDeadReturnRegisters: true, markNoReturn: true,
            markPure: true, markNoSideEffects: true, markSpoiledListsOptimized: true,
            markSyntheticHasCall: true,
            markHasFormatString: true, autoStackStartOffset: 0, autoStackAlignment: 0,
            autoStackArgumentLocations: true, markExplicitLocations: true,
            returnRegisters: [.init(registerId: 1, byteWidth: 4)],
            spoiledRegisters: [.init(registerId: 2, byteWidth: 8)],
            passthroughRegisters: [.init(registerId: 3, byteWidth: 16)],
            deadRegisters: [.init(registerId: 4, byteWidth: 32)],
            visibleMemoryRanges: [.init(address: 0x8000, byteSize: .max)], visibleMemoryAll: true)
        let native = try options.native(in: arena, "test call options")
        XCTAssertEqual(native.has_callee_address, 1)
        XCTAssertEqual(native.callee_address, 0)
        XCTAssertEqual(native.has_solid_argument_count, 1)
        XCTAssertEqual(native.has_auto_stack_start_offset, 1)
        XCTAssertEqual(native.has_auto_stack_alignment, 1)
        XCTAssertEqual(
            try Decompiler.MicrocodeValueLocation(copying: native.return_location, "test location"), location)
        XCTAssertEqual(native.return_registers?.pointee.register_id, 1)
        XCTAssertEqual(native.spoiled_registers?.pointee.register_id, 2)
        XCTAssertEqual(native.passthrough_registers?.pointee.byte_width, 16)
        XCTAssertEqual(native.dead_registers?.pointee.byte_width, 32)
        XCTAssertEqual(native.visible_memory_ranges?.pointee.byte_size, .max)
        XCTAssertEqual(native.visible_memory_all, 1)
        let argument = Decompiler.MicrocodeValue(
            kind: .vector, unsignedImmediate: .max, signedImmediate: .min,
            floatingImmediate: 1.25, byteWidth: 16, unsignedInteger: false, vectorElementByteWidth: 4,
            vectorElementCount: 4, vectorElementsUnsigned: false, vectorElementsFloating: true,
            typeDeclaration: "float", argumentName: "β", argumentFlags: 31, location: location)
        let value = try argument.native(in: arena, "test argument")
        XCTAssertEqual(value.unsigned_immediate, .max)
        XCTAssertEqual(value.signed_immediate, .min)
        XCTAssertEqual(value.argument_flags, 31)
        XCTAssertEqual(value.vector_element_count, 4)
        XCTAssertEqual(value.vector_elements_floating, 1)
        XCTAssertEqual(
            try Decompiler.MicrocodeValueLocation(copying: value.location, "test argument location"), location
        )
    }
}
