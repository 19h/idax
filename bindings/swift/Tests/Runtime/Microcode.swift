import Foundation
import IDAX

private final class MicrocodeState {
    var registration: Decompiler.MicrocodeFilterRegistration?
    var matchContext: Decompiler.MicrocodeContext?
    var applyContext: Decompiler.MicrocodeContext?
    var copiedInstruction: Instructions.Instruction?
    var matches = 0
    var applies = 0
    var invalidWidths = 0
    var closePrevented = false
    var mutationPrevented = false
    var databaseClosePrevented = false
    var failure: IDAError?
    var step = "start"
    var emitted: Decompiler.MicrocodeInstruction?
}
private final class ProbingMicrocodeFilter: Decompiler.MicrocodeFilter {
    let state: MicrocodeState
    init(_ state: MicrocodeState) { self.state = state }
    func match(context: Decompiler.MicrocodeContext) throws(IDAError) -> Bool {
        state.matches += 1
        guard state.applies == 0 else { return false }
        state.matchContext = context
        state.copiedInstruction = try context.instruction()
        do throws(IDAError) { try context.emitNoop() } catch {
            state.mutationPrevented = error.category == .conflict
        }
        do throws(IDAError) { try state.registration?.close() } catch {
            state.closePrevented = error.category == .conflict
        }
        do throws(IDAError) { try Database.close() } catch {
            state.databaseClosePrevented = error.category == .conflict
        }
        return true
    }
    func apply(context: Decompiler.MicrocodeContext) throws(IDAError) -> Decompiler.MicrocodeApplyResult {
        state.applies += 1
        state.applyContext = context
        do throws(IDAError) {
            state.step = "queries"
            _ = try context.address
            _ = try context.instructionType
            _ = try context.hasOpmask
            _ = try context.isZeroMasking
            _ = try context.opmaskRegisterNumber
            _ = try context.localVariableCount
            let before = try context.blockInstructionCount
            if try context.hasInstruction(at: 0) { _ = try context.instruction(at: 0) }
            state.step = "noop"
            do throws(IDAError) {
                try context.emitNoop(policy: .tail)
                guard try context.hasLastEmittedInstruction else {
                    throw IDAError(category: .internalError, message: "No-op emission was not tracked")
                }
                try context.removeLastEmittedInstruction()
            } catch {
                guard error.category == .sdkFailure && error.message == "emit(m_nop) failed" else {
                    throw error
                }
            }
            state.step = "allocate temporary"
            let temporary = try context.allocateTemporaryRegister(byteWidth: 4)
            let inner = Decompiler.MicrocodeInstruction(
                opcode: .add,
                left: .init(kind: .register, registerId: temporary, byteWidth: 4),
                right: .init(kind: .unsignedImmediate, unsignedImmediate: 9, byteWidth: 4),
                destination: .init())
            let instruction = Decompiler.MicrocodeInstruction(
                opcode: .move,
                left: .init(kind: .nestedInstruction, nestedInstruction: inner, byteWidth: 4),
                destination: .init(kind: .register, registerId: temporary, byteWidth: 4))
            state.step = "nested instruction"
            try context.emitInstruction(instruction)
            state.step = "snapshot nested instruction"
            state.emitted = try context.lastEmittedInstruction()
            try context.removeLastEmittedInstruction()
            state.step = "invalid nested widths"
            var missingWidth = instruction
            missingWidth.left.byteWidth = 0
            var negativeWidth = instruction
            negativeWidth.left.byteWidth = -1
            var mismatchedWidth = instruction
            mismatchedWidth.left.nestedInstruction?.destination = .init(
                kind: .register, registerId: temporary, byteWidth: 8)
            var unsupportedNested = instruction
            unsupportedNested.left.nestedInstruction?.opcode = .noOperation
            for malformed in [missingWidth, negativeWidth, mismatchedWidth, unsupportedNested] {
                do throws(IDAError) {
                    try context.emitInstruction(malformed)
                    throw IDAError(
                        category: .internalError, message: "Malformed nested instruction unexpectedly emitted"
                    )
                } catch {
                    guard error.category == .validation else { throw error }
                    state.invalidWidths += 1
                }
            }
            guard try context.blockInstructionCount == before else {
                throw IDAError(
                    category: .internalError, message: "Rejected nested instruction changed the block")
            }
            state.step = "move registers"
            try context.emitMoveRegister(
                sourceRegister: temporary,
                destinationRegister: try context.allocateTemporaryRegister(byteWidth: 4),
                byteWidth: 4, policy: .tail, markUserDefinedType: false)
            try context.removeLastEmittedInstruction()
            state.step = "emit instruction vector"
            try context.emitInstructions(
                [instruction, instruction], policy: .tail)
            while try context.blockInstructionCount > before { try context.removeInstruction(at: before) }
            state.step = "emit helper"
            try context.emitHelperCall(
                "swift_microcode_probe",
                arguments: [
                    .init(
                        kind: .unsignedImmediate, unsignedImmediate: .max, byteWidth: 8,
                        argumentName: "value", location: .init()),
                    .init(
                        kind: .nestedInstruction, nestedInstruction: inner, byteWidth: 4,
                        argumentName: "nested"),
                ], options: .init(markNoSideEffects: true))
            while try context.blockInstructionCount > before { try context.removeInstruction(at: before) }
        } catch { state.failure = error }
        return .notHandled
    }
}
private final class DroppingMicrocodeFilter: Decompiler.MicrocodeFilter {
    let state: MicrocodeState
    init(_ state: MicrocodeState) { self.state = state }
    func match(context: Decompiler.MicrocodeContext) throws(IDAError) -> Bool {
        state.matches += 1
        state.matchContext = context
        state.registration = nil
        return false
    }
    func apply(context: Decompiler.MicrocodeContext) throws(IDAError) -> Decompiler.MicrocodeApplyResult {
        .notHandled
    }
}

func runMicrocodeChecks() throws {
    guard try Decompiler.available() else {
        if ProcessInfo.processInfo.environment["IDAX_SWIFT_REQUIRE_DECOMPILER"] == "1" {
            throw Failure(description: "Required microcode runtime coverage has no available decompiler")
        }
        print("SKIP: Swift microcode runtime checks require an available decompiler")
        return
    }
    let functions = try Functions.count()
    try expect(functions > 0, "Microcode runtime fixture contains no analyzed functions")
    var address: Address?
    for index in 0..<min(functions, 32) {
        let candidate = try Functions.byIndex(index: index).start
        if (try? Decompiler.generateMicrocode(candidate)) != nil {
            address = candidate
            break
        }
    }
    guard let address else { throw Failure(description: "No fixture function could generate microcode") }
    let state = MicrocodeState()
    var filter: ProbingMicrocodeFilter? = ProbingMicrocodeFilter(state)
    weak var weakFilter = filter
    state.registration = try Decompiler.registerMicrocodeFilter(filter!)
    try expect(try state.registration?.isValid() == true, "Installed microcode filter is invalid")
    filter = nil
    try expect(weakFilter != nil, "Installed microcode filter released its Swift callback")
    _ = try Decompiler.generateMicrocode(address)
    if let failure = state.failure {
        throw Failure(description: "Microcode step \(state.step): \(failure)")
    }
    try expect(state.matches > 0 && state.applies == 1, "Microcode callbacks did not execute")
    try expect(state.invalidWidths == 4, "Nested instruction width/opcode validation did not execute")
    try expect(
        state.closePrevented && state.mutationPrevented && state.databaseClosePrevented,
        "Microcode callback permitted self-close, match mutation, or database close")
    try expect(state.copiedInstruction != nil, "Microcode native instruction snapshot was not copied")
    // The SDK can lift the nested addition directly into the block instruction.
    let arithmetic = state.emitted?.opcode == .add ? state.emitted : state.emitted?.left.nestedInstruction
    try expect(
        arithmetic?.opcode == .add,
        "Nested generic microcode emission lost its instruction")
    try expect(
        arithmetic?.right.unsignedImmediate == 9,
        "Nested generic microcode emission lost an immediate")
    try expectConflict { _ = try state.matchContext?.address }
    try expectConflict { try state.applyContext?.emitNoop() }
    try state.registration?.close()
    try expect(try state.registration?.isValid() == false, "Closed microcode filter stayed valid")
    try state.registration?.close()
    state.registration = nil
    _ = try Database.addressBitness()
    try expect(weakFilter == nil, "Closed microcode registration retained callback captures")

    let droppingState = MicrocodeState()
    var droppingFilter: DroppingMicrocodeFilter? = DroppingMicrocodeFilter(droppingState)
    weak var weakDroppingFilter = droppingFilter
    droppingState.registration = try Decompiler.registerMicrocodeFilter(droppingFilter!)
    droppingFilter = nil
    _ = try Decompiler.generateMicrocode(address)
    try expect(droppingState.matches > 0, "Dropping filter did not run")
    try expectConflict { _ = try droppingState.matchContext?.address }
    _ = try Database.addressBitness()
    try expect(
        weakDroppingFilter == nil, "Deferred filter finalization did not release captures after lifting")
    print(
        "PASS: Swift microcode callback leases, read-only match, self-close guards, recursive emission, helper arguments, and deferred ARC"
    )
}

final class DatabaseLifetimeMicrocodeFilter: Decompiler.MicrocodeFilter {
    func match(context: Decompiler.MicrocodeContext) throws(IDAError) -> Bool { false }
    func apply(context: Decompiler.MicrocodeContext) throws(IDAError) -> Decompiler.MicrocodeApplyResult {
        .notHandled
    }
}
