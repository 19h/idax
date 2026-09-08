internal import CIDAX

extension Instructions.Operand {
    public var displacement: Int64 { Int64(bitPattern: value) }
    public var isRegister: Bool { type == .register }
    public var isImmediate: Bool { type == .immediate }
    public var isMemory: Bool {
        type == .memoryDirect || type == .memoryPhrase || type == .memoryDisplacement
    }
    public var isVectorRegister: Bool { registerCategory == .vector }
    public var isMaskRegister: Bool { registerCategory == .mask }
}
extension Instructions.Instruction {
    public var operandCount: Int { operands.count }
    public func operand(index: Int) throws(IDAError) -> Instructions.Operand {
        guard operands.indices.contains(index) else {
            throw IDAError(category: .validation, message: "Operand index out of range", context: String(index))
        }
        return operands[index]
    }
}
extension Instructions {
    public struct OperandEnum: Equatable, Sendable {
        public var name: String
        public var serial: UInt8
        public init(name: String = "", serial: UInt8 = 0) {
            self.name = name
            self.serial = serial
        }
    }

    public static func operandEnum(address: Address, operandIndex: Int32) throws(IDAError) -> OperandEnum {
        let operation = "Instructions.operandEnum"
        try requireRuntimeThread(operation)
        var name: UnsafeMutablePointer<CChar>?
        var serial: UInt8 = 0
        defer { idax_free_string(name) }
        try checkStatus(idax_instruction_operand_enum(address, operandIndex, &name, &serial), operation)
        return .init(name: try borrowCString(name.map { UnsafePointer($0) }, operation), serial: serial)
    }

    public struct StructOffsetPath: Equatable, Sendable {
        public var structureName: String
        public var memberNames: [String]
        public var delta: Int64
        public init(structureName: String = "", memberNames: [String] = [], delta: Int64 = 0) {
            self.structureName = structureName
            self.memberNames = memberNames
            self.delta = delta
        }
    }

    public static func setOperandStructOffset(address: Address, operandIndex: Int32,
        structureName: String, delta: Int64 = 0
    ) throws(IDAError) {
        try setOperandStructOffsetByName(address: address, operandIndex: operandIndex,
            structureName: structureName, delta: delta)
    }

    public static func operandStructOffsetPath(address: Address, operandIndex: Int32) throws(IDAError) -> StructOffsetPath {
        let operation = "Instructions.operandStructOffsetPath"
        try requireRuntimeThread(operation)
        var names: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
        var count = 0
        var delta: Int64 = 0
        defer { idax_instruction_string_array_free(names, count) }
        try checkStatus(idax_instruction_operand_struct_offset_path(address, operandIndex, &names, &count, &delta), operation)
        let copied = try copyNativeStrings(names, count: count, operation)
        guard let structure = copied.first else {
            throw IDAError(category: .internalError, message: "Structure offset path has no root", context: operation)
        }
        return .init(structureName: structure, memberNames: Array(copied.dropFirst()), delta: delta)
    }
}
