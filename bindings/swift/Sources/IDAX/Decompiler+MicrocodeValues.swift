internal import CIDAX

internal final class MicrocodeInputBudget {
    var count = 0
    func enter(_ depth: Int, _ operation: String) throws(IDAError) {
        count += 1
        guard depth <= 128 && count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input exceeds depth 128 or 65536 nodes",
                context: operation)
        }
    }
}

extension Decompiler {
    public struct MicrocodeValue: Equatable, Sendable {
        public var kind: Decompiler.MicrocodeValueKind
        public var registerId: Int32
        public var localVariableIndex: Int32
        public var localVariableOffset: Int64
        public var secondRegisterId: Int32
        public var globalAddress: Address
        public var stackOffset: Int64
        public var helperName: String
        public var blockIndex: Int32
        public var nestedInstruction: Decompiler.MicrocodeInstruction?
        public var unsignedImmediate: UInt64
        public var signedImmediate: Int64
        public var floatingImmediate: Double
        public var byteWidth: Int32
        public var unsignedInteger: Bool
        public var vectorElementByteWidth: Int32
        public var vectorElementCount: Int32
        public var vectorElementsUnsigned: Bool
        public var vectorElementsFloating: Bool
        public var typeDeclaration: String
        public var argumentName: String
        public var argumentFlags: UInt32
        public var location: Decompiler.MicrocodeValueLocation
        public init(
            kind: Decompiler.MicrocodeValueKind = .register, registerId: Int32 = 0,
            localVariableIndex: Int32 = 0, localVariableOffset: Int64 = 0, secondRegisterId: Int32 = 0,
            globalAddress: Address = badAddress, stackOffset: Int64 = 0, helperName: String = "",
            blockIndex: Int32 = 0, nestedInstruction: Decompiler.MicrocodeInstruction? = nil,
            unsignedImmediate: UInt64 = 0, signedImmediate: Int64 = 0, floatingImmediate: Double = 0.0,
            byteWidth: Int32 = 0, unsignedInteger: Bool = true, vectorElementByteWidth: Int32 = 0,
            vectorElementCount: Int32 = 0, vectorElementsUnsigned: Bool = true,
            vectorElementsFloating: Bool = false, typeDeclaration: String = "", argumentName: String = "",
            argumentFlags: UInt32 = 0, location: Decompiler.MicrocodeValueLocation = .init()
        ) {
            self.kind = kind
            self.registerId = registerId
            self.localVariableIndex = localVariableIndex
            self.localVariableOffset = localVariableOffset
            self.secondRegisterId = secondRegisterId
            self.globalAddress = globalAddress
            self.stackOffset = stackOffset
            self.helperName = helperName
            self.blockIndex = blockIndex
            self.nestedInstruction = nestedInstruction
            self.unsignedImmediate = unsignedImmediate
            self.signedImmediate = signedImmediate
            self.floatingImmediate = floatingImmediate
            self.byteWidth = byteWidth
            self.unsignedInteger = unsignedInteger
            self.vectorElementByteWidth = vectorElementByteWidth
            self.vectorElementCount = vectorElementCount
            self.vectorElementsUnsigned = vectorElementsUnsigned
            self.vectorElementsFloating = vectorElementsFloating
            self.typeDeclaration = typeDeclaration
            self.argumentName = argumentName
            self.argumentFlags = argumentFlags
            self.location = location
        }
    }
}

extension Decompiler {
    public struct MicrocodeMemoryRange: Equatable, Sendable {
        public var address: Address
        public var byteSize: UInt64
        public init(address: Address = badAddress, byteSize: UInt64 = 0) {
            self.address = address
            self.byteSize = byteSize
        }
    }
}

extension Decompiler {
    public struct MicrocodeCallOptions: Equatable, Sendable {
        public var insertPolicy: Decompiler.MicrocodeInsertPolicy?
        public var calleeAddress: Address?
        public var solidArgumentCount: Int32?
        public var callStackPointerDelta: Int32?
        public var stackArgumentsTop: Int32?
        public var functionRole: Decompiler.MicrocodeFunctionRole?
        public var returnLocation: Decompiler.MicrocodeValueLocation?
        public var returnTypeDeclaration: String
        public var callingConvention: Decompiler.MicrocodeCallingConvention
        public var markFinal: Bool
        public var markPropagated: Bool
        public var markDeadReturnRegisters: Bool
        public var markNoReturn: Bool
        public var markPure: Bool
        public var markNoSideEffects: Bool
        public var markSpoiledListsOptimized: Bool
        public var markSyntheticHasCall: Bool
        public var markHasFormatString: Bool
        public var autoStackStartOffset: Int64?
        public var autoStackAlignment: Int32?
        public var autoStackArgumentLocations: Bool
        public var markExplicitLocations: Bool
        public var returnRegisters: [Decompiler.MicrocodeRegisterRange]
        public var spoiledRegisters: [Decompiler.MicrocodeRegisterRange]
        public var passthroughRegisters: [Decompiler.MicrocodeRegisterRange]
        public var deadRegisters: [Decompiler.MicrocodeRegisterRange]
        public var visibleMemoryRanges: [Decompiler.MicrocodeMemoryRange]
        public var visibleMemoryAll: Bool
        public init(
            insertPolicy: Decompiler.MicrocodeInsertPolicy? = nil, calleeAddress: Address? = nil,
            solidArgumentCount: Int32? = nil, callStackPointerDelta: Int32? = nil,
            stackArgumentsTop: Int32? = nil, functionRole: Decompiler.MicrocodeFunctionRole? = nil,
            returnLocation: Decompiler.MicrocodeValueLocation? = nil, returnTypeDeclaration: String = "",
            callingConvention: Decompiler.MicrocodeCallingConvention = .unspecified, markFinal: Bool = false,
            markPropagated: Bool = false, markDeadReturnRegisters: Bool = false, markNoReturn: Bool = false,
            markPure: Bool = false, markNoSideEffects: Bool = false, markSpoiledListsOptimized: Bool = false,
            markSyntheticHasCall: Bool = false, markHasFormatString: Bool = false,
            autoStackStartOffset: Int64? = nil, autoStackAlignment: Int32? = nil,
            autoStackArgumentLocations: Bool = false, markExplicitLocations: Bool = false,
            returnRegisters: [Decompiler.MicrocodeRegisterRange] = [],
            spoiledRegisters: [Decompiler.MicrocodeRegisterRange] = [],
            passthroughRegisters: [Decompiler.MicrocodeRegisterRange] = [],
            deadRegisters: [Decompiler.MicrocodeRegisterRange] = [],
            visibleMemoryRanges: [Decompiler.MicrocodeMemoryRange] = [], visibleMemoryAll: Bool = false
        ) {
            self.insertPolicy = insertPolicy
            self.calleeAddress = calleeAddress
            self.solidArgumentCount = solidArgumentCount
            self.callStackPointerDelta = callStackPointerDelta
            self.stackArgumentsTop = stackArgumentsTop
            self.functionRole = functionRole
            self.returnLocation = returnLocation
            self.returnTypeDeclaration = returnTypeDeclaration
            self.callingConvention = callingConvention
            self.markFinal = markFinal
            self.markPropagated = markPropagated
            self.markDeadReturnRegisters = markDeadReturnRegisters
            self.markNoReturn = markNoReturn
            self.markPure = markPure
            self.markNoSideEffects = markNoSideEffects
            self.markSpoiledListsOptimized = markSpoiledListsOptimized
            self.markSyntheticHasCall = markSyntheticHasCall
            self.markHasFormatString = markHasFormatString
            self.autoStackStartOffset = autoStackStartOffset
            self.autoStackAlignment = autoStackAlignment
            self.autoStackArgumentLocations = autoStackArgumentLocations
            self.markExplicitLocations = markExplicitLocations
            self.returnRegisters = returnRegisters
            self.spoiledRegisters = spoiledRegisters
            self.passthroughRegisters = passthroughRegisters
            self.deadRegisters = deadRegisters
            self.visibleMemoryRanges = visibleMemoryRanges
            self.visibleMemoryAll = visibleMemoryAll
        }
    }
}

extension Decompiler.MicrocodeRegisterRange {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeRegisterRange {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeRegisterRange()
        native.register_id = registerId
        native.byte_width = byteWidth
        return native
    }
}

extension Decompiler.MicrocodeSwitchCase {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeSwitchCase {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeSwitchCase()
        native.value = value
        native.target_block = targetBlock
        return native
    }
}

extension Decompiler.MicrocodeCallArgumentProperties {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeCallArgumentProperties {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeCallArgumentProperties()
        native.hidden = hidden ? 1 : 0
        native.return_value_pointer = returnValuePointer ? 1 : 0
        native.structure_argument = structureArgument ? 1 : 0
        native.array_argument = arrayArgument ? 1 : 0
        native.unused = unused ? 1 : 0
        native.swift_self = swiftSelf ? 1 : 0
        return native
    }
}

extension Decompiler.MicrocodeLocationPart {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeLocationPart {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeLocationPart()
        native.kind = kind.rawValue
        native.register_id = registerId
        native.second_register_id = secondRegisterId
        native.register_offset = registerOffset
        native.register_relative_offset = registerRelativeOffset
        native.stack_offset = stackOffset
        native.static_address = staticAddress
        native.byte_offset = byteOffset
        native.byte_size = byteSize
        return native
    }
}

extension Decompiler.MicrocodeValueLocation {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeValueLocation {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeValueLocation()
        native.kind = kind.rawValue
        native.register_id = registerId
        native.second_register_id = secondRegisterId
        native.register_offset = registerOffset
        native.register_relative_offset = registerRelativeOffset
        native.stack_offset = stackOffset
        native.static_address = staticAddress
        var scatteredPartsValues: [IdaxMicrocodeLocationPart] = []
        guard scatteredParts.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in scatteredParts {
            scatteredPartsValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.scattered_parts = UnsafeMutablePointer(mutating: arena.array(scatteredPartsValues))
        native.scattered_part_count = scatteredParts.count
        return native
    }
}

extension Decompiler.MicrocodeOperand {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeOperand {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeOperand()
        native.kind = kind.rawValue
        native.register_id = registerId
        native.processor_register_id = processorRegisterId
        native.local_variable_index = localVariableIndex
        native.local_variable_offset = localVariableOffset
        native.second_register_id = secondRegisterId
        native.global_address = globalAddress
        native.stack_offset = stackOffset
        native.helper_name = UnsafeMutablePointer(mutating: try arena.string(helperName, operation))
        native.block_index = blockIndex
        if let value = nestedInstruction {
            let pointer = arena.array([
                try value.native(in: arena, operation, budget: budget, depth: depth + 1)
            ])
            native.nested_instruction = UnsafeMutablePointer(mutating: pointer)
        }
        native.unsigned_immediate = unsignedImmediate
        native.signed_immediate = signedImmediate
        native.byte_width = byteWidth
        native.mark_user_defined_type = markUserDefinedType ? 1 : 0
        if let value = referencedOperand {
            let pointer = arena.array([
                try value.native(in: arena, operation, budget: budget, depth: depth + 1)
            ])
            native.referenced_operand = UnsafeMutablePointer(mutating: pointer)
        }
        var callArgumentsValues: [IdaxMicrocodeOperand] = []
        guard callArguments.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in callArguments {
            callArgumentsValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.call_arguments = UnsafeMutablePointer(mutating: arena.array(callArgumentsValues))
        native.call_argument_count = callArguments.count
        native.call_target = callTarget
        native.text = UnsafeMutablePointer(mutating: try arena.string(text, operation))
        native.string_constant = UnsafeMutablePointer(mutating: try arena.string(stringConstant, operation))
        native.has_floating_point_constant = floatingPointConstant == nil ? 0 : 1
        if let value = floatingPointConstant {
            native.floating_point_constant = value
        }
        native.global_name = UnsafeMutablePointer(mutating: try arena.string(globalName, operation))
        native.has_value_number = valueNumber == nil ? 0 : 1
        if let value = valueNumber {
            native.value_number = value
        }
        var callArgumentPropertiesValues: [IdaxMicrocodeCallArgumentProperties] = []
        guard callArgumentProperties.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in callArgumentProperties {
            callArgumentPropertiesValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.call_argument_properties = UnsafeMutablePointer(
            mutating: arena.array(callArgumentPropertiesValues))
        native.call_argument_property_count = callArgumentProperties.count
        var callReturnOperandsValues: [IdaxMicrocodeOperand] = []
        guard callReturnOperands.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in callReturnOperands {
            callReturnOperandsValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.call_return_operands = UnsafeMutablePointer(mutating: arena.array(callReturnOperandsValues))
        native.call_return_operand_count = callReturnOperands.count
        var callReturnRegistersValues: [IdaxMicrocodeRegisterRange] = []
        guard callReturnRegisters.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in callReturnRegisters {
            callReturnRegistersValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.call_return_registers = UnsafeMutablePointer(mutating: arena.array(callReturnRegistersValues))
        native.call_return_register_count = callReturnRegisters.count
        var switchCasesValues: [IdaxMicrocodeSwitchCase] = []
        guard switchCases.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in switchCases {
            switchCasesValues.append(try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.switch_cases = UnsafeMutablePointer(mutating: arena.array(switchCasesValues))
        native.switch_case_count = switchCases.count
        native.has_switch_default_target = switchDefaultTarget == nil ? 0 : 1
        if let value = switchDefaultTarget {
            native.switch_default_target = value
        }
        return native
    }
}

extension Decompiler.MicrocodeInstruction {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxMicrocodeInstruction {
        try budget.enter(depth, operation)
        var native = IdaxMicrocodeInstruction()
        native.opcode = opcode.rawValue
        native.left = try left.native(in: arena, operation, budget: budget, depth: depth + 1)
        native.right = try right.native(in: arena, operation, budget: budget, depth: depth + 1)
        native.destination = try destination.native(in: arena, operation, budget: budget, depth: depth + 1)
        native.floating_point_instruction = floatingPointInstruction ? 1 : 0
        native.modifies_destination = modifiesDestination ? 1 : 0
        native.address = address
        native.text = UnsafeMutablePointer(mutating: try arena.string(text, operation))
        return native
    }
}

extension Decompiler.MicrocodeValue {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxSwiftMicrocodeValue {
        try budget.enter(depth, operation)
        var native = IdaxSwiftMicrocodeValue()
        native.kind = kind.rawValue
        native.register_id = registerId
        native.local_variable_index = localVariableIndex
        native.local_variable_offset = localVariableOffset
        native.second_register_id = secondRegisterId
        native.global_address = globalAddress
        native.stack_offset = stackOffset
        native.helper_name = try arena.string(helperName, operation)
        native.block_index = blockIndex
        if let value = nestedInstruction {
            let pointer = arena.array([
                try value.native(in: arena, operation, budget: budget, depth: depth + 1)
            ])
            native.nested_instruction = pointer
        }
        native.unsigned_immediate = unsignedImmediate
        native.signed_immediate = signedImmediate
        native.floating_immediate = floatingImmediate
        native.byte_width = byteWidth
        native.unsigned_integer = unsignedInteger ? 1 : 0
        native.vector_element_byte_width = vectorElementByteWidth
        native.vector_element_count = vectorElementCount
        native.vector_elements_unsigned = vectorElementsUnsigned ? 1 : 0
        native.vector_elements_floating = vectorElementsFloating ? 1 : 0
        native.type_declaration = try arena.string(typeDeclaration, operation)
        native.argument_name = try arena.string(argumentName, operation)
        native.argument_flags = argumentFlags
        native.location = try location.native(in: arena, operation, budget: budget, depth: depth + 1)
        return native
    }
}

extension Decompiler.MicrocodeMemoryRange {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxSwiftMicrocodeMemoryRange {
        try budget.enter(depth, operation)
        var native = IdaxSwiftMicrocodeMemoryRange()
        native.address = address
        native.byte_size = byteSize
        return native
    }
}

extension Decompiler.MicrocodeCallOptions {
    internal func native(
        in arena: InputArena, _ operation: String, budget: MicrocodeInputBudget = MicrocodeInputBudget(),
        depth: Int = 0
    ) throws(IDAError) -> IdaxSwiftMicrocodeCallOptions {
        try budget.enter(depth, operation)
        var native = IdaxSwiftMicrocodeCallOptions()
        native.has_insert_policy = insertPolicy == nil ? 0 : 1
        if let value = insertPolicy {
            native.insert_policy = value.rawValue
        }
        native.has_callee_address = calleeAddress == nil ? 0 : 1
        if let value = calleeAddress {
            native.callee_address = value
        }
        native.has_solid_argument_count = solidArgumentCount == nil ? 0 : 1
        if let value = solidArgumentCount {
            native.solid_argument_count = value
        }
        native.has_call_stack_pointer_delta = callStackPointerDelta == nil ? 0 : 1
        if let value = callStackPointerDelta {
            native.call_stack_pointer_delta = value
        }
        native.has_stack_arguments_top = stackArgumentsTop == nil ? 0 : 1
        if let value = stackArgumentsTop {
            native.stack_arguments_top = value
        }
        native.has_function_role = functionRole == nil ? 0 : 1
        if let value = functionRole {
            native.function_role = value.rawValue
        }
        native.has_return_location = returnLocation == nil ? 0 : 1
        if let value = returnLocation {
            native.return_location = try value.native(in: arena, operation, budget: budget, depth: depth + 1)
        }
        native.return_type_declaration = try arena.string(returnTypeDeclaration, operation)
        native.calling_convention = callingConvention.rawValue
        native.mark_final = markFinal ? 1 : 0
        native.mark_propagated = markPropagated ? 1 : 0
        native.mark_dead_return_registers = markDeadReturnRegisters ? 1 : 0
        native.mark_no_return = markNoReturn ? 1 : 0
        native.mark_pure = markPure ? 1 : 0
        native.mark_no_side_effects = markNoSideEffects ? 1 : 0
        native.mark_spoiled_lists_optimized = markSpoiledListsOptimized ? 1 : 0
        native.mark_synthetic_has_call = markSyntheticHasCall ? 1 : 0
        native.mark_has_format_string = markHasFormatString ? 1 : 0
        native.has_auto_stack_start_offset = autoStackStartOffset == nil ? 0 : 1
        if let value = autoStackStartOffset {
            native.auto_stack_start_offset = value
        }
        native.has_auto_stack_alignment = autoStackAlignment == nil ? 0 : 1
        if let value = autoStackAlignment {
            native.auto_stack_alignment = value
        }
        native.auto_stack_argument_locations = autoStackArgumentLocations ? 1 : 0
        native.mark_explicit_locations = markExplicitLocations ? 1 : 0
        var returnRegistersValues: [IdaxMicrocodeRegisterRange] = []
        guard returnRegisters.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in returnRegisters {
            returnRegistersValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.return_registers = arena.array(returnRegistersValues)
        native.return_registers_count = returnRegisters.count
        var spoiledRegistersValues: [IdaxMicrocodeRegisterRange] = []
        guard spoiledRegisters.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in spoiledRegisters {
            spoiledRegistersValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.spoiled_registers = arena.array(spoiledRegistersValues)
        native.spoiled_registers_count = spoiledRegisters.count
        var passthroughRegistersValues: [IdaxMicrocodeRegisterRange] = []
        guard passthroughRegisters.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in passthroughRegisters {
            passthroughRegistersValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.passthrough_registers = arena.array(passthroughRegistersValues)
        native.passthrough_registers_count = passthroughRegisters.count
        var deadRegistersValues: [IdaxMicrocodeRegisterRange] = []
        guard deadRegisters.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in deadRegisters {
            deadRegistersValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.dead_registers = arena.array(deadRegistersValues)
        native.dead_registers_count = deadRegisters.count
        var visibleMemoryRangesValues: [IdaxSwiftMicrocodeMemoryRange] = []
        guard visibleMemoryRanges.count <= 65536 else {
            throw IDAError(
                category: .validation, message: "Microcode input array exceeds 65536 elements",
                context: operation)
        }
        for item in visibleMemoryRanges {
            visibleMemoryRangesValues.append(
                try item.native(in: arena, operation, budget: budget, depth: depth + 1))
        }
        native.visible_memory_ranges = arena.array(visibleMemoryRangesValues)
        native.visible_memory_ranges_count = visibleMemoryRanges.count
        native.visible_memory_all = visibleMemoryAll ? 1 : 0
        return native
    }
}
