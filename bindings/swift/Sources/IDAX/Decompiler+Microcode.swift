internal import CIDAX

extension Decompiler {
    /// Runs during native microcode generation. Contexts expire when each
    /// callback returns. Mutating operations are available only during apply.
    public protocol MicrocodeFilter: AnyObject {
        func match(context: MicrocodeContext) throws(IDAError) -> Bool
        func apply(context: MicrocodeContext) throws(IDAError) -> MicrocodeApplyResult
    }

    /// Owns a filter registration. Explicit close from a filter callback throws
    /// Conflict; releasing the last owner there schedules removal after lifting.
    public final class MicrocodeFilterRegistration {
        private var handle: UnsafeMutableRawPointer?
        private var closing = false
        internal init(owning handle: UnsafeMutableRawPointer) { self.handle = handle }
        deinit { if let handle { idax_swift_microcode_registration_release(handle) } }
        /// False after close or database teardown; a later database does not
        /// reactivate this registration.
        public func isValid() throws(IDAError) -> Bool {
            guard let handle else { return false }
            var output: Int32 = 0
            try bridgeCall("Decompiler.MicrocodeFilterRegistration.isValid") {
                idax_swift_microcode_registration_valid(handle, &output, $0)
            }
            return output != 0
        }
        public func close() throws(IDAError) {
            guard let handle else { return }
            guard !closing else {
                throw IDAError(category: .conflict, message: "Microcode filter close is already in progress")
            }
            closing = true
            defer { closing = false }
            try bridgeCall("Decompiler.MicrocodeFilterRegistration.close") {
                idax_swift_microcode_registration_close(handle, $0)
            }
            idax_swift_microcode_registration_release(handle)
            self.handle = nil
        }
    }

    public static func registerMicrocodeFilter(_ filter: any MicrocodeFilter) throws(IDAError)
        -> MicrocodeFilterRegistration
    {
        let callbacks = callbackDescriptor { event, reply in
            let context = MicrocodeContext(
                borrowing: try requireLifecycleHandle(event.lease, "MicrocodeFilter.callback"),
                mutable: event.phase != 0)
            if event.phase == 0 {
                reply.pointee.decision = try filter.match(context: context) ? 1 : 0
            } else {
                reply.pointee.decision = try filter.apply(context: context).rawValue
            }
        }
        var output: UnsafeMutableRawPointer?
        try bridgeCall("Decompiler.registerMicrocodeFilter") {
            idax_swift_microcode_register(callbacks, &output, $0)
        }
        return MicrocodeFilterRegistration(
            owning: try requireLifecycleHandle(output, "Decompiler.registerMicrocodeFilter"))
    }

    /// A checked borrow of the current lifting context. Copy returned values to
    /// retain them; operations on a retained context throw after callback return.
    public final class MicrocodeContext {
        private let handle: UnsafeMutableRawPointer
        /// True for apply callbacks and false for match callbacks.
        public let isMutable: Bool
        internal init(borrowing handle: UnsafeMutableRawPointer, mutable: Bool) {
            self.handle = handle
            self.isMutable = mutable
            idax_swift_microcode_lease_retain(handle)
        }
        deinit { idax_swift_microcode_lease_release(handle) }

        private func query(_ kind: Int32, index: Int32 = 0) throws(IDAError) -> UInt64 {
            var output: UInt64 = 0
            try bridgeCall("Decompiler.MicrocodeContext.query") {
                idax_swift_microcode_query(handle, kind, index, &output, $0)
            }
            return output
        }
        public var address: Address { get throws(IDAError) { try query(0) } }
        public var instructionType: Int32 { get throws(IDAError) { Int32(truncatingIfNeeded: try query(1)) } }
        public var hasOpmask: Bool { get throws(IDAError) { try query(2) != 0 } }
        public var isZeroMasking: Bool { get throws(IDAError) { try query(3) != 0 } }
        public var opmaskRegisterNumber: Int32 {
            get throws(IDAError) { Int32(truncatingIfNeeded: try query(4)) }
        }
        public var localVariableCount: Int32 {
            get throws(IDAError) { Int32(truncatingIfNeeded: try query(5)) }
        }
        public var blockInstructionCount: Int32 {
            get throws(IDAError) { Int32(truncatingIfNeeded: try query(6)) }
        }
        public var hasLastEmittedInstruction: Bool { get throws(IDAError) { try query(8) != 0 } }
        public func hasInstruction(at index: Int32) throws(IDAError) -> Bool {
            try query(7, index: index) != 0
        }

        public func instruction() throws(IDAError) -> Instructions.Instruction {
            let operation = "Decompiler.MicrocodeContext.instruction"
            var output = IdaxInstruction()
            defer { idax_instruction_free(&output) }
            try bridgeCall(operation) { idax_swift_microcode_instruction(handle, &output, $0) }
            return try Instructions.Instruction(copying: output, operation)
        }
        public func instruction(at index: Int32) throws(IDAError) -> MicrocodeInstruction {
            try blockInstruction(index: index, last: false)
        }
        public func lastEmittedInstruction() throws(IDAError) -> MicrocodeInstruction {
            try blockInstruction(index: 0, last: true)
        }
        private func blockInstruction(index: Int32, last: Bool) throws(IDAError) -> MicrocodeInstruction {
            let operation = "Decompiler.MicrocodeContext.blockInstruction"
            var output = IdaxMicrocodeInstruction()
            defer { idax_microcode_instruction_free(&output) }
            try bridgeCall(operation) {
                idax_swift_microcode_block_instruction(handle, index, last ? 1 : 0, &output, $0)
            }
            return try MicrocodeInstruction(copying: output, operation)
        }

        @discardableResult
        private func perform(
            _ operation: Int32, _ a: Int32 = 0, _ b: Int32 = 0, _ c: Int32 = 0,
            _ d: Int32 = 0, _ e: Int32 = 0, policy: MicrocodeInsertPolicy? = nil,
            markUserDefinedType: Bool = false
        ) throws(IDAError) -> Int32 {
            var output: Int32 = 0
            try bridgeCall("Decompiler.MicrocodeContext.operation") {
                idax_swift_microcode_operation(
                    handle, operation, a, b, c, d, e, policy?.rawValue ?? -1,
                    markUserDefinedType ? 1 : 0, &output, $0)
            }
            return output
        }
        public func removeLastEmittedInstruction() throws(IDAError) { try perform(0) }
        public func removeInstruction(at index: Int32) throws(IDAError) { try perform(1, index) }
        public func emitNoop(policy: MicrocodeInsertPolicy? = nil) throws(IDAError) {
            try perform(2, policy: policy)
        }
        public func loadOperandRegister(operandIndex: Int32) throws(IDAError) -> Int32 {
            try perform(3, operandIndex)
        }
        public func loadEffectiveAddressRegister(operandIndex: Int32) throws(IDAError) -> Int32 {
            try perform(4, operandIndex)
        }
        public func allocateTemporaryRegister(byteWidth: Int32) throws(IDAError) -> Int32 {
            try perform(5, byteWidth)
        }
        public func storeOperandRegister(
            operandIndex: Int32, sourceRegister: Int32, byteWidth: Int32,
            markUserDefinedType: Bool = false
        ) throws(IDAError) {
            try perform(6, operandIndex, sourceRegister, byteWidth, markUserDefinedType: markUserDefinedType)
        }
        public func emitMoveRegister(
            sourceRegister: Int32, destinationRegister: Int32, byteWidth: Int32,
            policy: MicrocodeInsertPolicy? = nil, markUserDefinedType: Bool = false
        ) throws(IDAError) {
            try perform(
                7, sourceRegister, destinationRegister, byteWidth, policy: policy,
                markUserDefinedType: markUserDefinedType)
        }
        public func emitLoadMemoryRegister(
            selectorRegister: Int32, offsetRegister: Int32,
            destinationRegister: Int32, byteWidth: Int32, offsetByteWidth: Int32,
            policy: MicrocodeInsertPolicy? = nil, markUserDefinedType: Bool = false
        ) throws(IDAError) {
            try perform(
                8, selectorRegister, offsetRegister, destinationRegister, byteWidth, offsetByteWidth,
                policy: policy, markUserDefinedType: markUserDefinedType)
        }
        public func emitStoreMemoryRegister(
            sourceRegister: Int32, selectorRegister: Int32,
            offsetRegister: Int32, byteWidth: Int32, offsetByteWidth: Int32,
            policy: MicrocodeInsertPolicy? = nil, markUserDefinedType: Bool = false
        ) throws(IDAError) {
            try perform(
                9, sourceRegister, selectorRegister, offsetRegister, byteWidth, offsetByteWidth,
                policy: policy, markUserDefinedType: markUserDefinedType)
        }
        public func emitInstruction(
            _ instruction: MicrocodeInstruction,
            policy: MicrocodeInsertPolicy? = nil
        ) throws(IDAError) {
            try emit([instruction], single: true, policy: policy)
        }
        public func emitInstructions(
            _ instructions: [MicrocodeInstruction],
            policy: MicrocodeInsertPolicy? = nil
        ) throws(IDAError) {
            try emit(instructions, single: false, policy: policy)
        }
        private func emit(
            _ instructions: [MicrocodeInstruction], single: Bool, policy: MicrocodeInsertPolicy?
        ) throws(IDAError) {
            let operation =
                single
                ? "Decompiler.MicrocodeContext.emitInstruction"
                : "Decompiler.MicrocodeContext.emitInstructions"
            guard instructions.count <= 65536 else {
                throw IDAError(
                    category: .validation, message: "Microcode input exceeds 65536 instructions",
                    context: operation)
            }
            let arena = InputArena()
            defer { withExtendedLifetime(arena) {} }
            let budget = MicrocodeInputBudget()
            var values: [IdaxMicrocodeInstruction] = []
            for instruction in instructions {
                values.append(try instruction.native(in: arena, operation, budget: budget))
            }
            try bridgeCall(operation) {
                idax_swift_microcode_emit(
                    handle, arena.array(values), values.count, single ? 1 : 0, policy?.rawValue ?? -1, $0)
            }
        }
        public func emitHelperCall(_ helperName: String) throws(IDAError) {
            try helper(helperName, arguments: [], options: .init(), destinationKind: 4)
        }
        public func emitHelperCall(
            _ helperName: String, arguments: [MicrocodeValue],
            options: MicrocodeCallOptions = .init()
        ) throws(IDAError) {
            try helper(helperName, arguments: arguments, options: options, destinationKind: 0)
        }
        public func emitHelperCall(
            _ helperName: String, arguments: [MicrocodeValue] = [],
            toRegister destinationRegister: Int32, byteWidth: Int32,
            unsigned: Bool = true, options: MicrocodeCallOptions = .init()
        ) throws(IDAError) {
            try helper(
                helperName, arguments: arguments, options: options, destinationKind: 1,
                destination: destinationRegister, byteWidth: byteWidth, unsigned: unsigned)
        }
        public func emitHelperCall(
            _ helperName: String, arguments: [MicrocodeValue] = [],
            toMicroOperand destination: MicrocodeOperand, unsigned: Bool = true,
            options: MicrocodeCallOptions = .init()
        ) throws(IDAError) {
            try helper(
                helperName, arguments: arguments, options: options, destinationKind: 2,
                unsigned: unsigned, operand: destination)
        }
        public func emitHelperCall(
            _ helperName: String, arguments: [MicrocodeValue] = [],
            toOperand destinationOperandIndex: Int32, byteWidth: Int32,
            unsigned: Bool = true, options: MicrocodeCallOptions = .init()
        ) throws(IDAError) {
            try helper(
                helperName, arguments: arguments, options: options, destinationKind: 3,
                destination: destinationOperandIndex, byteWidth: byteWidth, unsigned: unsigned)
        }
        private func helper(
            _ name: String, arguments: [MicrocodeValue], options: MicrocodeCallOptions,
            destinationKind: Int32, destination: Int32 = 0, byteWidth: Int32 = 0,
            unsigned: Bool = true, operand: MicrocodeOperand? = nil
        ) throws(IDAError) {
            let operation = "Decompiler.MicrocodeContext.emitHelperCall"
            guard arguments.count <= 65536 else {
                throw IDAError(
                    category: .validation, message: "Microcode input exceeds 65536 arguments",
                    context: operation)
            }
            let arena = InputArena()
            defer { withExtendedLifetime(arena) {} }
            let budget = MicrocodeInputBudget()
            let helperName = try arena.string(name, operation)
            var values: [IdaxSwiftMicrocodeValue] = []
            for argument in arguments {
                values.append(try argument.native(in: arena, operation, budget: budget))
            }
            var nativeOptions = try options.native(in: arena, operation, budget: budget)
            var nativeOperand: UnsafePointer<IdaxMicrocodeOperand>?
            if let operand {
                nativeOperand = arena.array([try operand.native(in: arena, operation, budget: budget)])
            }
            try bridgeCall(operation) {
                idax_swift_microcode_helper(
                    handle, helperName, arena.array(values), values.count, &nativeOptions,
                    destinationKind, destination, byteWidth, unsigned ? 1 : 0, nativeOperand, $0)
            }
        }
    }
}
