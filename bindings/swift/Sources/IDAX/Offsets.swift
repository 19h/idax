internal import CIDAX

extension Offsets {
    public struct ReferenceType: Equatable, Sendable {
        public var kind: ReferenceKind
        public var customName: String
        public init(kind: ReferenceKind = .offset32, customName: String = "") { self.kind = kind; self.customName = customName }
        internal init(copying value: IdaxOffsetReferenceType, _ operation: String) throws(IDAError) {
            kind = try checkedEnum(ReferenceKind.self, value.kind, operation)
            customName = try borrowCString(value.custom_name.map { UnsafePointer($0) }, operation)
        }
    }
    public struct ReferenceTypeDescriptor: Equatable, Sendable {
        public var type: ReferenceType
        public var name: String
        public var description: String
        public var targetOptional: Bool
        public init(type: ReferenceType, name: String, description: String, targetOptional: Bool = false) {
            self.type = type; self.name = name; self.description = description; self.targetOptional = targetOptional
        }
    }
    public struct OperandLocation: Equatable, Sendable {
        public var index: Int
        public var outer: Bool
        public init(index: Int = 0, outer: Bool = false) { self.index = index; self.outer = outer }
    }
    public struct ReferenceOptions: Equatable, Sendable {
        public var relativeVirtualAddress: Bool
        public var allowPastEnd: Bool
        public var suppressBaseReference: Bool
        public var subtractOperand: Bool
        public var signExtendOperand: Bool
        public var acceptZero: Bool
        public var rejectAllOnes: Bool
        public var selfRelative: Bool
        public var ignoreFixup: Bool
        public init(relativeVirtualAddress: Bool = false, allowPastEnd: Bool = false, suppressBaseReference: Bool = false,
                    subtractOperand: Bool = false, signExtendOperand: Bool = false, acceptZero: Bool = false,
                    rejectAllOnes: Bool = false, selfRelative: Bool = false, ignoreFixup: Bool = false) {
            self.relativeVirtualAddress = relativeVirtualAddress; self.allowPastEnd = allowPastEnd
            self.suppressBaseReference = suppressBaseReference; self.subtractOperand = subtractOperand
            self.signExtendOperand = signExtendOperand; self.acceptZero = acceptZero; self.rejectAllOnes = rejectAllOnes
            self.selfRelative = selfRelative; self.ignoreFixup = ignoreFixup
        }
    }
    public struct ReferenceInfo: Equatable, Sendable {
        public var type: ReferenceType
        public var target: Address?
        public var base: Address?
        public var targetDelta: AddressDelta
        public var options: ReferenceOptions
        public init(type: ReferenceType = .init(), target: Address? = nil, base: Address? = nil,
                    targetDelta: AddressDelta = 0, options: ReferenceOptions = .init()) {
            self.type = type; self.target = target; self.base = base; self.targetDelta = targetDelta; self.options = options
        }
        internal init(copying value: IdaxOffsetReferenceInfo, _ operation: String) throws(IDAError) {
            type = ReferenceType(kind: try checkedEnum(ReferenceKind.self, value.kind, operation),
                                 customName: try borrowCString(value.custom_name.map { UnsafePointer($0) }, operation))
            target = value.has_target != 0 ? value.target : nil
            base = value.has_base != 0 ? value.base : nil
            targetDelta = value.target_delta
            options = ReferenceOptions(relativeVirtualAddress: value.relative_virtual_address != 0, allowPastEnd: value.allow_past_end != 0,
                                       suppressBaseReference: value.suppress_base_reference != 0, subtractOperand: value.subtract_operand != 0,
                                       signExtendOperand: value.sign_extend_operand != 0, acceptZero: value.accept_zero != 0,
                                       rejectAllOnes: value.reject_all_ones != 0, selfRelative: value.self_relative != 0, ignoreFixup: value.ignore_fixup != 0)
        }
        internal func native(_ arena: InputArena, _ operation: String) throws(IDAError) -> IdaxOffsetReferenceInfoInput {
            IdaxOffsetReferenceInfoInput(kind: type.kind.rawValue, custom_name: try arena.string(type.customName, operation),
                                        has_target: target == nil ? 0 : 1, target: target ?? 0, has_base: base == nil ? 0 : 1,
                                        base: base ?? 0, target_delta: targetDelta, relative_virtual_address: options.relativeVirtualAddress ? 1 : 0,
                                        allow_past_end: options.allowPastEnd ? 1 : 0, suppress_base_reference: options.suppressBaseReference ? 1 : 0,
                                        subtract_operand: options.subtractOperand ? 1 : 0, sign_extend_operand: options.signExtendOperand ? 1 : 0,
                                        accept_zero: options.acceptZero ? 1 : 0, reject_all_ones: options.rejectAllOnes ? 1 : 0,
                                        self_relative: options.selfRelative ? 1 : 0, ignore_fixup: options.ignoreFixup ? 1 : 0)
        }
    }
    public struct RenderOptions: Equatable, Sendable {
        public var appendZeroField: Bool
        public var avoidDummyNames: Bool
        public init(appendZeroField: Bool = false, avoidDummyNames: Bool = false) {
            self.appendZeroField = appendZeroField; self.avoidDummyNames = avoidDummyNames
        }
    }
    public struct RenderedExpression: Equatable, Sendable {
        public var text: String
        public var complexity: ExpressionComplexity
        public init(text: String, complexity: ExpressionComplexity = .simple) { self.text = text; self.complexity = complexity }
        internal init(copying value: IdaxOffsetRenderedExpression, _ operation: String) throws(IDAError) {
            text = try borrowCString(value.text.map { UnsafePointer($0) }, operation)
            complexity = try checkedEnum(ExpressionComplexity.self, value.complexity, operation)
        }
    }
    public struct ReferenceCalculation: Equatable, Sendable {
        public var target: Address?
        public var base: Address?
        public init(target: Address? = nil, base: Address? = nil) { self.target = target; self.base = base }
    }
    public static func referenceTypes() throws(IDAError) -> [ReferenceTypeDescriptor] {
        let operation = "Offsets.referenceTypes"
        try requireRuntimeThread(operation)
        var output: UnsafeMutablePointer<IdaxOffsetReferenceTypeDescriptor>?
        var count = 0
        defer { idax_offset_reference_types_free(output, count) }
        try checkStatus(idax_offset_reference_types(&output, &count), operation)
        return try copyNativeValues(output, count: count, operation) { (value) throws(IDAError) -> ReferenceTypeDescriptor in
            ReferenceTypeDescriptor(type: try ReferenceType(copying: value.type, operation),
                                    name: try borrowCString(value.name.map { UnsafePointer($0) }, operation),
                                    description: try borrowCString(value.description.map { UnsafePointer($0) }, operation),
                                    targetOptional: value.target_optional != 0)
        }
    }
    public static func defaultReferenceType(at address: Address) throws(IDAError) -> ReferenceType {
        let operation = "Offsets.defaultReferenceType"
        try requireRuntimeThread(operation)
        var output = IdaxOffsetReferenceType()
        defer { idax_offset_reference_type_free(&output) }
        try checkStatus(idax_offset_default_reference_type(address, &output), operation)
        return try ReferenceType(copying: output, operation)
    }
    public static func referenceInfo(at address: Address, location: OperandLocation) throws(IDAError) -> ReferenceInfo? {
        let operation = "Offsets.referenceInfo"
        try requireRuntimeThread(operation); try requireNonnegative(location.index, operation)
        var output = IdaxOffsetReferenceInfo()
        var present: Int32 = 0
        defer { idax_offset_reference_info_free(&output) }
        try checkStatus(idax_offset_reference_info(address, location.index, location.outer ? 1 : 0, &output, &present), operation)
        return present != 0 ? try ReferenceInfo(copying: output, operation) : nil
    }
    public static func applyReference(at address: Address, location: OperandLocation, info: ReferenceInfo) throws(IDAError) {
        let operation = "Offsets.applyReference"
        try requireRuntimeThread(operation); try requireNonnegative(location.index, operation)
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var native = try info.native(arena, operation)
        try checkStatus(idax_offset_apply_reference(address, location.index, location.outer ? 1 : 0, &native), operation)
    }
    public static func removeReference(at address: Address, location: OperandLocation) throws(IDAError) -> Bool {
        let operation = "Offsets.removeReference"
        try requireNonnegative(location.index, operation)
        return try withOutput(operation, initial: Int32(0)) { idax_offset_remove_reference(address, location.index, location.outer ? 1 : 0, $0) } != 0
    }
    public static func renderStoredExpression(at address: Address, location: OperandLocation, from: Address,
                                              operandValue: AddressDelta, options: RenderOptions = .init()) throws(IDAError) -> RenderedExpression {
        let operation = "Offsets.renderStoredExpression"
        try requireRuntimeThread(operation); try requireNonnegative(location.index, operation)
        var output = IdaxOffsetRenderedExpression()
        defer { idax_offset_rendered_expression_free(&output) }
        try checkStatus(idax_offset_render_stored_expression(address, location.index, location.outer ? 1 : 0, from, operandValue,
                                                             options.appendZeroField ? 1 : 0, options.avoidDummyNames ? 1 : 0, &output), operation)
        return try RenderedExpression(copying: output, operation)
    }
    public static func renderExpression(at address: Address, location: OperandLocation, info: ReferenceInfo, from: Address,
                                       operandValue: AddressDelta, options: RenderOptions = .init()) throws(IDAError) -> RenderedExpression {
        let operation = "Offsets.renderExpression"
        try requireRuntimeThread(operation); try requireNonnegative(location.index, operation)
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var native = try info.native(arena, operation)
        var output = IdaxOffsetRenderedExpression()
        defer { idax_offset_rendered_expression_free(&output) }
        try checkStatus(idax_offset_render_expression(address, location.index, location.outer ? 1 : 0, &native, from, operandValue,
                                                      options.appendZeroField ? 1 : 0, options.avoidDummyNames ? 1 : 0, &output), operation)
        return try RenderedExpression(copying: output, operation)
    }
    public static func calculateOffsetBase(at address: Address, location: OperandLocation) throws(IDAError) -> Address? {
        let operation = "Offsets.calculateOffsetBase"
        try requireRuntimeThread(operation); try requireNonnegative(location.index, operation)
        var output: UInt64 = 0
        var present: Int32 = 0
        try checkStatus(idax_offset_calculate_offset_base(address, location.index, location.outer ? 1 : 0, &output, &present), operation)
        return present != 0 ? output : nil
    }
    public static func calculateReference(from: Address, info: ReferenceInfo, operandValue: AddressDelta) throws(IDAError) -> ReferenceCalculation {
        let operation = "Offsets.calculateReference"
        try requireRuntimeThread(operation)
        let arena = InputArena()
        defer { withExtendedLifetime(arena) {} }
        var native = try info.native(arena, operation)
        var output = IdaxOffsetReferenceCalculation()
        try checkStatus(idax_offset_calculate_reference(from, &native, operandValue, &output), operation)
        return ReferenceCalculation(target: output.has_target != 0 ? output.target : nil, base: output.has_base != 0 ? output.base : nil)
    }
    public static func addOperandDataReferences(at address: Address, location: OperandLocation, type: CrossReferences.DataType = .offset) throws(IDAError) -> Address {
        let operation = "Offsets.addOperandDataReferences"
        try requireNonnegative(location.index, operation)
        return try withOutput(operation, initial: UInt64(0)) { idax_offset_add_operand_data_references(address, location.index, location.outer ? 1 : 0, type.rawValue, $0) }
    }
}
