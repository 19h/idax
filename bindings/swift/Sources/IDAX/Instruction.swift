internal import CIDAX

/// Operand type classification.
public enum OperandType: Int32, Sendable {
    case void_ = 0, register, memory, phrase
    case displacement, immediate, far, near
}

/// Semantic branch-condition classifier for conditional control-transfer
/// instructions.
///
/// Mirrors C++ `ida::instruction::BranchCondition`. The raw value matches
/// the C++ enum so the C ABI can ferry it as `int`.
///
/// Implementation is mnemonic-based on the C++ side, so the same vocabulary
/// applies across ARM64, x86, ARM32, and any other processor whose
/// conditional-branch mnemonics follow the standard `B<cc>` / `B.<cc>` /
/// `J<cc>` / `CB[N]Z` / `TB[N]Z` patterns.
public enum BranchCondition: Int32, Sendable {
    /// Not a conditional control-transfer, or could not be classified.
    case none = 0
    /// Unconditional jump or branch (e.g. ARM64 `B`, x86 `JMP`).
    case always
    case equal
    case notEqual
    case lessThanSigned
    case lessThanOrEqualSigned
    case greaterThanSigned
    case greaterThanOrEqualSigned
    case lessThanUnsigned
    case lessThanOrEqualUnsigned
    case greaterThanUnsigned
    case greaterThanOrEqualUnsigned
    /// Direct register-is-zero test (ARM64 `CBZ`, `TBZ`).
    case zero
    /// Direct register-is-not-zero test (ARM64 `CBNZ`, `TBNZ`).
    case notZero
    /// Negative / N flag set (ARM64 `B.MI`, x86 `JS`).
    case negative
    /// Non-negative / N flag clear (ARM64 `B.PL`, x86 `JNS`).
    case notNegative
    /// Overflow flag set (ARM64 `B.VS`, x86 `JO`).
    case overflow
    /// Overflow flag clear (ARM64 `B.VC`, x86 `JNO`).
    case noOverflow
    /// Parity flag set (x86 `JP` / `JPE`).
    case parity
    /// Parity flag clear (x86 `JNP` / `JPO`).
    case noParity
    /// Counter register is zero (x86 `JCXZ` / `JECXZ` / `JRCXZ`, `LOOP*`).
    case countZero
}

/// Decoded instruction operand.
public struct Operand: Sendable {
    public let index: Int
    public let operandType: OperandType
    public let registerID: UInt16
    public let registerName: String
    public let registerCategory: Int32
    public let value: UInt64
    public let targetAddress: Address
    public let byteWidth: Int
    /// Processor-marked semantic read (SDK `CF_USE<n>` feature bit).
    ///
    /// True when the processor module reports that this operand index is
    /// read by the instruction. Suitable as the LIR `registersRead` source
    /// for register / memory-phrase / memory-displacement operands.
    public let isRead: Bool
    /// Processor-marked semantic write (SDK `CF_CHG<n>` feature bit).
    ///
    /// True when the processor module reports that this operand index is
    /// changed by the instruction. Suitable as the LIR `registersWritten`
    /// source for register operands.
    public let isWritten: Bool

    public var isImmediate: Bool { operandType == .immediate }
    public var isRegister: Bool { operandType == .register }
    public var isMemory: Bool { operandType == .memory }
}

/// Decoded instruction snapshot.
public struct Instruction: Sendable {
    public let address: Address
    public let size: AddressSize
    public let opcode: UInt16
    public let mnemonic: String
    public let operands: [Operand]
    /// Semantic branch-condition classification of the instruction.
    ///
    /// `.none` for non-branch instructions, `.always` for unconditional
    /// branches/jumps, and a specific `BranchCondition` case otherwise.
    /// Suitable as the LIR `branchCondition` source on terminator
    /// instructions.
    public let branchCondition: BranchCondition

    public var operandCount: Int { operands.count }

    // MARK: - Queries

    public static func decode(at address: Address) throws(IDAError) -> Instruction {
        var raw = IdaxInstruction()
        try checkStatus(idax_instruction_decode(address, &raw), "instruction.decode")
        defer { idax_instruction_free(&raw) }
        return Instruction(raw: raw)
    }

    public static func text(at address: Address) throws(IDAError) -> String {
        try withStringOutput("instruction.text") { idax_instruction_text(address, $0) }
    }

    // MARK: - Predicates

    public static func isCall(_ address: Address) -> Bool {
        idax_instruction_is_call(address) != 0
    }

    public static func isReturn(_ address: Address) -> Bool {
        idax_instruction_is_return(address) != 0
    }

    public static func isJump(_ address: Address) -> Bool {
        idax_instruction_is_jump(address) != 0
    }

    public static func isConditionalJump(_ address: Address) -> Bool {
        idax_instruction_is_conditional_jump(address) != 0
    }

    /// Classify the branch condition of the instruction at `address`.
    ///
    /// Returns `.none` for non-branch instructions / decode failures,
    /// `.always` for unconditional branches, and the specific condition
    /// otherwise. Mirrors C++ `ida::instruction::branch_condition`.
    public static func branchCondition(at address: Address) throws(IDAError) -> BranchCondition {
        var raw: Int32 = 0
        try checkStatus(
            idax_instruction_branch_condition(address, &raw),
            "instruction.branchCondition"
        )
        return BranchCondition(rawValue: raw) ?? .none
    }

    public static func hasFallThrough(_ address: Address) -> Bool {
        idax_instruction_has_fall_through(address) != 0
    }

    // MARK: - Xref conveniences

    public static func codeRefsFrom(_ address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("instruction.codeRefsFrom") { idax_instruction_code_refs_from(address, $0, $1) }
    }

    public static func dataRefsFrom(_ address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("instruction.dataRefsFrom") { idax_instruction_data_refs_from(address, $0, $1) }
    }

    public static func callTargets(_ address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("instruction.callTargets") { idax_instruction_call_targets(address, $0, $1) }
    }

    public static func jumpTargets(_ address: Address) throws(IDAError) -> [Address] {
        try withAddressArrayOutput("instruction.jumpTargets") { idax_instruction_jump_targets(address, $0, $1) }
    }

    // MARK: - Operand display

    public static func setOperandHex(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_hex(address, Int32(n)), "instruction.setOperandHex")
    }

    public static func setOperandDecimal(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_decimal(address, Int32(n)), "instruction.setOperandDecimal")
    }

    // MARK: - Create / Navigate

    public static func create(at address: Address) throws(IDAError) -> Instruction {
        var raw = IdaxInstruction()
        try checkStatus(idax_instruction_create(address, &raw), "instruction.create")
        defer { idax_instruction_free(&raw) }
        return Instruction(raw: raw)
    }

    public static func next(after address: Address) throws(IDAError) -> Instruction {
        var raw = IdaxInstruction()
        try checkStatus(idax_instruction_next(address, &raw), "instruction.next")
        defer { idax_instruction_free(&raw) }
        return Instruction(raw: raw)
    }

    public static func prev(before address: Address) throws(IDAError) -> Instruction {
        var raw = IdaxInstruction()
        try checkStatus(idax_instruction_prev(address, &raw), "instruction.prev")
        defer { idax_instruction_free(&raw) }
        return Instruction(raw: raw)
    }

    // MARK: - Operand queries

    public static func operandText(at address: Address, operand n: Int) throws(IDAError) -> String {
        try withStringOutput("instruction.operandText") { idax_instruction_operand_text(address, Int32(n), $0) }
    }

    public static func operandByteWidth(at address: Address, operand n: Int) throws(IDAError) -> Int {
        var out: Int32 = 0
        try checkStatus(idax_instruction_operand_byte_width(address, Int32(n), &out), "instruction.operandByteWidth")
        return Int(out)
    }

    public static func operandRegisterName(at address: Address, operand n: Int) throws(IDAError) -> String {
        try withStringOutput("instruction.operandRegisterName") { idax_instruction_operand_register_name(address, Int32(n), $0) }
    }

    public static func operandRegisterCategory(at address: Address, operand n: Int) throws(IDAError) -> Int {
        var out: Int32 = 0
        try checkStatus(idax_instruction_operand_register_category(address, Int32(n), &out), "instruction.operandRegisterCategory")
        return Int(out)
    }

    // MARK: - Operand representation

    public static func setOperandOctal(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_octal(address, Int32(n)), "instruction.setOperandOctal")
    }

    public static func setOperandBinary(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_binary(address, Int32(n)), "instruction.setOperandBinary")
    }

    public static func setOperandCharacter(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_character(address, Int32(n)), "instruction.setOperandCharacter")
    }

    public static func setOperandFloat(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_float(address, Int32(n)), "instruction.setOperandFloat")
    }

    public static func setOperandFormat(_ address: Address, operand n: Int, format: Int, base: UInt64) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_format(address, Int32(n), Int32(format), base), "instruction.setOperandFormat")
    }

    public static func setOperandOffset(_ address: Address, operand n: Int, base: UInt64) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_offset(address, Int32(n), base), "instruction.setOperandOffset")
    }

    public static func setOperandStructOffsetByName(_ address: Address, operand n: Int, structureName: String, delta: Int64) throws(IDAError) {
        try checkStatus(
            structureName.withCString { idax_instruction_set_operand_struct_offset_by_name(address, Int32(n), $0, delta) },
            "instruction.setOperandStructOffsetByName"
        )
    }

    public static func setOperandStructOffsetByID(_ address: Address, operand n: Int, structureID: UInt64, delta: Int64) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_struct_offset_by_id(address, Int32(n), structureID, delta), "instruction.setOperandStructOffsetByID")
    }

    public static func setOperandBasedStructOffset(_ address: Address, operand n: Int, operandValue: UInt64, base: UInt64) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_based_struct_offset(address, Int32(n), operandValue, base), "instruction.setOperandBasedStructOffset")
    }

    public static func setOperandStackVariable(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_set_operand_stack_variable(address, Int32(n)), "instruction.setOperandStackVariable")
    }

    public static func setForcedOperand(_ address: Address, operand n: Int, text: String) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_instruction_set_forced_operand(address, Int32(n), $0) },
            "instruction.setForcedOperand"
        )
    }

    public static func forcedOperand(at address: Address, operand n: Int) throws(IDAError) -> String {
        try withStringOutput("instruction.forcedOperand") { idax_instruction_get_forced_operand(address, Int32(n), $0) }
    }

    public static func clearOperandRepresentation(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_clear_operand_representation(address, Int32(n)), "instruction.clearOperandRepresentation")
    }

    public static func toggleOperandSign(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_toggle_operand_sign(address, Int32(n)), "instruction.toggleOperandSign")
    }

    public static func toggleOperandNegate(_ address: Address, operand n: Int) throws(IDAError) {
        try checkStatus(idax_instruction_toggle_operand_negate(address, Int32(n)), "instruction.toggleOperandNegate")
    }

    // MARK: - Struct offset paths

    /// Structure-offset path applied to an operand, plus its delta.
    ///
    /// The C ABI used to hand back raw SDK structure ids here; upstream made
    /// the path opaque and now returns structure *names*, so this returns
    /// names too.
    public static func operandStructOffsetPath(at address: Address, operand n: Int) throws(IDAError) -> (names: [String], delta: Int64) {
        var namesPtr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
        var count: Int = 0
        var delta: Int64 = 0
        try checkStatus(
            idax_instruction_operand_struct_offset_path(address, Int32(n), &namesPtr, &count, &delta),
            "instruction.operandStructOffsetPath"
        )
        defer { idax_instruction_string_array_free(namesPtr, count) }
        var names: [String] = []
        if let namesPtr, count > 0 {
            names.reserveCapacity(count)
            for index in 0..<count {
                if let element = namesPtr[index] {
                    names.append(String(cString: element))
                }
            }
        }
        return (names: names, delta: delta)
    }

    public static func operandStructOffsetPathNames(at address: Address, operand n: Int) throws(IDAError) -> [String] {
        var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
        var count: Int = 0
        try checkStatus(
            idax_instruction_operand_struct_offset_path_names(address, Int32(n), &ptr, &count),
            "instruction.operandStructOffsetPathNames"
        )
        defer { idax_instruction_string_array_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return (0..<count).map { i in
            if let s = ptr[i] { String(cString: s) } else { "" }
        }
    }

    // MARK: - Internal

    init(raw: IdaxInstruction) {
        self.address = raw.address
        self.size = raw.size
        self.opcode = raw.opcode
        self.mnemonic = borrowCString(raw.mnemonic)
        self.branchCondition = BranchCondition(rawValue: Int32(raw.branch_condition)) ?? .none

        var ops: [Operand] = []
        if let ptr = raw.operands, raw.operand_count > 0 {
            let buf = UnsafeBufferPointer(start: ptr, count: raw.operand_count)
            ops = buf.map { o in
                Operand(
                    index: Int(o.index),
                    operandType: OperandType(rawValue: Int32(o.type)) ?? .void_,
                    registerID: o.register_id,
                    registerName: borrowCString(o.register_name),
                    registerCategory: o.register_category,
                    value: o.value,
                    targetAddress: o.target_address,
                    byteWidth: Int(o.byte_width),
                    isRead: o.is_read != 0,
                    isWritten: o.is_written != 0
                )
            }
        }
        self.operands = ops
    }
}
