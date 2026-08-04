internal import CIDAX

/// Post-hoc microcode snapshot API.
///
/// `Microcode` is the value-typed counterpart of the live `MicrocodeContext`
/// filter API exposed in ``Decompiler``: rather than intercepting
/// instructions while Hex-Rays lifts them, it produces a deep-copied view of
/// the entire `mba_t` once lifting finishes. Snapshots are self-contained
/// and outlive any SDK state.
///
/// Typical use is driving an external IR consumer (e.g. an MIR-style SSA
/// importer for the Swift decompiler project) that wants a stable, off-line
/// view of the decompiler's microcode.
public enum Microcode {

    /// Maturity at which to snapshot the microcode.
    ///
    /// Mirrors `ida::microcode::Maturity` / SDK `mba_maturity_t`.
    /// ``lvars`` is closest to ctree input and the recommended choice for
    /// MIR-style consumers.
    public enum Maturity: Int32, Sendable, CaseIterable {
        case generated       = 1
        case preoptimized    = 2
        case locopt          = 3
        case calledArguments = 4
        case glbopt1         = 5
        case glbopt2         = 6
        case glbopt3         = 7
        case lvars           = 8
    }

    /// Basic-block kind, mirroring SDK `mblock_type_t`.
    public enum BlockKind: Int32, Sendable {
        case none     = 0
        case stop     = 1
        case noWay    = 2
        case oneWay   = 3
        case twoWay   = 4
        case nWay     = 5
        case external = 6
    }

    /// Microcode operand kind, mirroring SDK `mopt_t`.
    public enum OperandKind: Int32, Sendable {
        case none              = 0
        case register          = 1
        case numericConstant   = 2
        case stringLiteral     = 3
        case nestedInstruction = 4
        case stackVariable     = 5
        case globalAddress     = 6
        case blockReference    = 7
        case callInfo          = 8
        case localVariable     = 9
        case addressOf         = 10
        case helper            = 11
        case cases             = 12
        case floatConstant     = 13
        case registerPair      = 14
        case scattered         = 15
    }

    /// Deep-copied microcode operand snapshot.
    public struct Operand: Sendable {
        public let kind: OperandKind
        public let byteWidth: Int
        public let registerID: Int
        public let secondRegisterID: Int
        public let numericValue: Int64
        public let floatValue: Double
        public let stackOffset: Int64
        public let globalAddress: Address
        /// Name at `globalAddress` (`get_name`), empty if none — lets a consumer
        /// render a call/global by name instead of a raw address.
        public let globalName: String
        public let localVariableIndex: Int
        public let localVariableOffset: Int64
        public let helperName: String
        public let stringLiteral: String
        /// For a `.callInfo` operand (`mop_f`), the call's argument operands in
        /// order. Empty for every other kind.
        public let callArguments: [Operand]
        /// For a `.callInfo` operand (`mop_f`), the `FAI_*` flag bitmask of each
        /// argument, index-aligned with `callArguments`. `FAI_RETPTR` (0x0002)
        /// marks a hidden `sret` pointer argument — the real output location for
        /// a large/existential return value that never lands in a register. Use
        /// `argumentIsReturnPointer(at:)` for the common check. Empty for every
        /// other kind.
        public let argumentFlags: [UInt32]
        /// For a `.callInfo` operand (`mop_f`), the call's return register
        /// operands (`mcallinfo_t::retregs`) — the locations the call writes its
        /// result to, so a consumer can wire `v5 = <call>` instead of treating
        /// the call as `void`. Each is usually a `.register` operand. Cleared by
        /// Hex-Rays once the call is propagated; prefer `returnRegisterIDs` when
        /// this is unexpectedly empty. Empty for every other kind.
        public let returnRegisters: [Operand]
        /// For a `.callInfo` operand (`mop_f`), the micro-register numbers
        /// (`mreg_t`) the call returns into (`mcallinfo_t::return_regs` register
        /// part). Unlike `returnRegisters` this survives propagation. Empty for
        /// every other kind.
        public let returnRegisterIDs: [Int]
        /// For a `.cases` operand (`mop_c`), the switch's case values, flattened
        /// and index-aligned with `switchCaseTargetBlocks`. Each value selects
        /// the target micro-block at the same index. The default case is not in
        /// this list — see `switchDefaultTargetBlock`. Empty for every other
        /// kind.
        public let switchCaseValues: [Int64]
        /// For a `.cases` operand (`mop_c`), the target micro-block serial for
        /// each entry in `switchCaseValues` (parallel, same length). Empty for
        /// every other kind.
        public let switchCaseTargetBlocks: [Int]
        /// For a `.cases` operand (`mop_c`), the default target micro-block
        /// serial (the group with no case values), or `-1` when there is no
        /// default case. `-1` for every other kind.
        public let switchDefaultTargetBlock: Int
        public let blockIndex: Int
        public let nestedInstructionID: Int
        public let ssaVersion: Int?
        public let operandProperties: UInt8

        /// `FAI_RETPTR` — argument is a hidden pointer to the return value
        /// (`sret`), implies hidden. From IDA SDK `typeinf.hpp`.
        public static let argumentFlagReturnPointer: UInt32 = 0x0002

        /// Whether the argument at `index` is a hidden `sret` return pointer
        /// (`FAI_RETPTR`). For such a call the result is written through this
        /// argument rather than into `returnRegisters`. Returns `false` for an
        /// out-of-range index.
        public func argumentIsReturnPointer(at index: Int) -> Bool {
            guard index >= 0, index < argumentFlags.count else { return false }
            return argumentFlags[index] & Self.argumentFlagReturnPointer != 0
        }
    }

    /// Deep-copied microcode instruction snapshot.
    public struct Instruction: Sendable {
        public let id: Int
        public let sourceAddress: Address
        public let opcode: Int
        public let opcodeName: String
        public let left: Operand
        public let right: Operand
        public let destination: Operand
        public let flags: UInt32
    }

    /// Deep-copied microcode basic block snapshot.
    public struct Block: Sendable {
        public let index: Int
        public let startAddress: Address
        public let endAddress: Address
        public let kind: BlockKind
        public let flags: UInt32
        public let predecessorIndices: [Int]
        public let successorIndices: [Int]
        public let instructions: [Instruction]
    }

    /// Move-only handle to a microcode snapshot.
    ///
    /// `deinit` releases the underlying C++ snapshot. Once decoded into the
    /// value types above, the result is fully `Sendable` and can be passed
    /// across actors freely; the handle itself is not.
    public struct FunctionSnapshot: ~Copyable, @unchecked Sendable {
        let handle: IdaxMicrocodeSnapshotHandle

        init(_ handle: IdaxMicrocodeSnapshotHandle) {
            self.handle = handle
        }

        deinit {
            idax_microcode_snapshot_free(handle)
        }

        public var functionAddress: Address {
            get throws(IDAError) {
                try withOutput("microcode.functionAddress", UInt64(0)) {
                    idax_microcode_snapshot_function_address(handle, $0)
                }
            }
        }

        public var maturity: Maturity {
            get throws(IDAError) {
                var raw: Int32 = 0
                try checkStatus(
                    idax_microcode_snapshot_maturity(handle, &raw),
                    "microcode.maturity"
                )
                return Maturity(rawValue: raw) ?? .lvars
            }
        }

        public var localVariablesSize: Int64 {
            get throws(IDAError) {
                try withOutput("microcode.localVariablesSize", Int64(0)) {
                    idax_microcode_snapshot_local_variables_size(handle, $0)
                }
            }
        }

        public var savedRegistersSize: Int64 {
            get throws(IDAError) {
                try withOutput("microcode.savedRegistersSize", Int64(0)) {
                    idax_microcode_snapshot_saved_registers_size(handle, $0)
                }
            }
        }

        public var stackSize: Int64 {
            get throws(IDAError) {
                try withOutput("microcode.stackSize", Int64(0)) {
                    idax_microcode_snapshot_stack_size(handle, $0)
                }
            }
        }

        /// Index into `localVariables` of the lvar holding the function's
        /// return value (`mba_t::retvaridx`), or `-1` for a `void` / undefined
        /// return. At `.lvars` maturity the returned value lives in this lvar
        /// (not on `m_ret`'s operands), so a MIR consumer wires `return <expr>`
        /// from this lvar's reaching definition at each `m_ret`.
        public var returnValueVariableIndex: Int {
            get throws(IDAError) {
                var out: Int32 = -1
                try checkStatus(
                    idax_microcode_snapshot_return_value_variable_index(handle, &out),
                    "microcode.returnValueVariableIndex"
                )
                return Int(out)
            }
        }

        public var blockCount: Int {
            get throws(IDAError) {
                var out: Int = 0
                try checkStatus(
                    idax_microcode_snapshot_block_count(handle, &out),
                    "microcode.blockCount"
                )
                return out
            }
        }

        /// Materialise all basic blocks in `mba->natural` order.
        ///
        /// Each block is decoded into Swift value types; the underlying
        /// snapshot continues to be owned by this handle.
        public var blocks: [Block] {
            get throws(IDAError) {
                let count = try blockCount
                var result: [Block] = []
                result.reserveCapacity(count)
                for index in 0..<count {
                    result.append(try block(at: index))
                }
                return result
            }
        }

        /// Materialise the block at the given zero-based index.
        public func block(at index: Int) throws(IDAError) -> Block {
            var raw = IdaxMicrocodeSnapshotBlock()
            try checkStatus(
                idax_microcode_snapshot_block(handle, index, &raw),
                "microcode.block"
            )
            defer { idax_microcode_snapshot_block_free(&raw) }
            return Block(raw: raw)
        }

        /// Resolve a nested microinstruction referenced from an operand.
        ///
        /// `id` is the value of ``Microcode/Operand/nestedInstructionID``
        /// (which is `-1` when the operand does not refer to a nested
        /// instruction). Negative ids return a `notFound` error.
        public func nestedInstruction(id: Int) throws(IDAError) -> Instruction {
            var raw = IdaxMicrocodeSnapshotInstruction()
            try checkStatus(
                idax_microcode_snapshot_nested_instruction(handle, Int32(id), &raw),
                "microcode.nestedInstruction"
            )
            defer { idax_microcode_snapshot_instruction_free(&raw) }
            return Instruction(raw: raw)
        }

        /// Materialise the local-variable table visible at this maturity.
        ///
        /// Fully populated from `.lvars`; lower maturities expose whatever
        /// the SDK has so far.
        public var localVariables: [LocalVariable] {
            get throws(IDAError) {
                var pointer: UnsafeMutablePointer<IdaxLocalVariable>? = nil
                var count: Int = 0
                try checkStatus(
                    idax_microcode_snapshot_local_variables(handle, &pointer, &count),
                    "microcode.localVariables"
                )
                defer { idax_decompiled_variables_free(pointer, count) }
                guard let pointer, count > 0 else { return [] }
                let buffer = UnsafeBufferPointer(start: pointer, count: count)
                return buffer.map { v in
                    LocalVariable(
                        name: borrowCString(v.name),
                        typeName: borrowCString(v.type_name),
                        isArgument: v.is_argument != 0,
                        width: Int(v.width),
                        hasUserName: v.has_user_name != 0,
                        storage: VariableStorage(rawValue: Int(v.storage)) ?? .unknown,
                        comment: borrowCString(v.comment),
                        stackOffset: v.stack_offset,
                        registerNumber: Int(v.register_number)
                    )
                }
            }
        }
    }

    /// Build a microcode snapshot of the function at `address`.
    ///
    /// - Parameters:
    ///   - address: Entry address of the function to lift.
    ///   - maturity: Microcode maturity at which to snapshot.
    ///     Defaults to ``Maturity/lvars`` — the recommended choice for
    ///     MIR-style consumers.
    public static func snapshot(
        of address: Address,
        at maturity: Maturity = .lvars
    ) throws(IDAError) -> FunctionSnapshot {
        var raw: IdaxMicrocodeSnapshotHandle? = nil
        try checkStatus(
            idax_microcode_snapshot_create(address, maturity.rawValue, &raw),
            "microcode.snapshot"
        )
        guard let raw else {
            throw IDAError(category: .internal,
                           code: 0,
                           message: "microcode.snapshot returned null handle")
        }
        return FunctionSnapshot(raw)
    }
}

// MARK: - Internal conversions

private extension Microcode.Operand {
    init(raw: IdaxMicrocodeSnapshotOperand) {
        self.kind                = Microcode.OperandKind(rawValue: Int32(raw.kind)) ?? .none
        self.byteWidth           = Int(raw.byte_width)
        self.registerID          = Int(raw.register_id)
        self.secondRegisterID    = Int(raw.second_register_id)
        self.numericValue        = raw.numeric_value
        self.floatValue          = raw.float_value
        self.stackOffset         = raw.stack_offset
        self.globalAddress       = raw.global_address
        self.globalName          = borrowCString(raw.global_name)
        self.localVariableIndex  = Int(raw.local_variable_index)
        self.localVariableOffset = raw.local_variable_offset
        self.helperName          = borrowCString(raw.helper_name)
        self.stringLiteral       = borrowCString(raw.string_literal)
        if raw.call_argument_count > 0, let argumentsPointer = raw.call_arguments {
            self.callArguments = (0 ..< Int(raw.call_argument_count)).map {
                Microcode.Operand(raw: argumentsPointer[$0])
            }
        } else {
            self.callArguments = []
        }
        if raw.argument_flags_count > 0, let flagsPointer = raw.argument_flags {
            self.argumentFlags = (0 ..< Int(raw.argument_flags_count)).map {
                flagsPointer[$0]
            }
        } else {
            self.argumentFlags = []
        }
        if raw.return_register_count > 0, let returnRegistersPointer = raw.return_registers {
            self.returnRegisters = (0 ..< Int(raw.return_register_count)).map {
                Microcode.Operand(raw: returnRegistersPointer[$0])
            }
        } else {
            self.returnRegisters = []
        }
        if raw.return_register_id_count > 0, let idsPointer = raw.return_register_ids {
            self.returnRegisterIDs = (0 ..< Int(raw.return_register_id_count)).map {
                Int(idsPointer[$0])
            }
        } else {
            self.returnRegisterIDs = []
        }
        if raw.switch_case_value_count > 0, let valuesPointer = raw.switch_case_values {
            self.switchCaseValues = (0 ..< Int(raw.switch_case_value_count)).map {
                valuesPointer[$0]
            }
        } else {
            self.switchCaseValues = []
        }
        if raw.switch_case_value_count > 0, let targetBlocksPointer = raw.switch_case_target_blocks {
            self.switchCaseTargetBlocks = (0 ..< Int(raw.switch_case_value_count)).map {
                Int(targetBlocksPointer[$0])
            }
        } else {
            self.switchCaseTargetBlocks = []
        }
        self.switchDefaultTargetBlock = Int(raw.switch_default_target_block)
        self.blockIndex          = Int(raw.block_index)
        self.nestedInstructionID = Int(raw.nested_instruction_id)
        self.ssaVersion          = raw.has_ssa_version != 0 ? Int(raw.ssa_version) : nil
        self.operandProperties   = raw.operand_properties
    }
}

private extension Microcode.Instruction {
    init(raw: IdaxMicrocodeSnapshotInstruction) {
        self.id            = Int(raw.id)
        self.sourceAddress = raw.source_address
        self.opcode        = Int(raw.opcode)
        self.opcodeName    = borrowCString(raw.opcode_name)
        self.left          = Microcode.Operand(raw: raw.left)
        self.right         = Microcode.Operand(raw: raw.right)
        self.destination   = Microcode.Operand(raw: raw.destination)
        self.flags         = raw.flags
    }
}

private extension Microcode.Block {
    init(raw: IdaxMicrocodeSnapshotBlock) {
        self.index         = Int(raw.index)
        self.startAddress  = raw.start_address
        self.endAddress    = raw.end_address
        self.kind          = Microcode.BlockKind(rawValue: Int32(raw.kind)) ?? .none
        self.flags         = raw.flags

        if let pointer = raw.predecessor_indices, raw.predecessor_count > 0 {
            self.predecessorIndices = UnsafeBufferPointer(start: pointer,
                                                          count: raw.predecessor_count).map { Int($0) }
        } else {
            self.predecessorIndices = []
        }

        if let pointer = raw.successor_indices, raw.successor_count > 0 {
            self.successorIndices = UnsafeBufferPointer(start: pointer,
                                                       count: raw.successor_count).map { Int($0) }
        } else {
            self.successorIndices = []
        }

        if let pointer = raw.instructions, raw.instruction_count > 0 {
            self.instructions = UnsafeBufferPointer(start: pointer,
                                                    count: raw.instruction_count)
                .map { Microcode.Instruction(raw: $0) }
        } else {
            self.instructions = []
        }
    }
}
