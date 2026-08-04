internal import CIDAX
import Darwin

// MARK: - Bitmask option sets

/// Instruction feature flags (mirrors C++ `InstructionFeature`).
public struct InstructionFeature: OptionSet, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let stop     = InstructionFeature(rawValue: 0x00001)
    public static let call     = InstructionFeature(rawValue: 0x00002)
    public static let change1  = InstructionFeature(rawValue: 0x00004)
    public static let change2  = InstructionFeature(rawValue: 0x00008)
    public static let change3  = InstructionFeature(rawValue: 0x00010)
    public static let change4  = InstructionFeature(rawValue: 0x00020)
    public static let change5  = InstructionFeature(rawValue: 0x00040)
    public static let change6  = InstructionFeature(rawValue: 0x00080)
    public static let use1     = InstructionFeature(rawValue: 0x00100)
    public static let use2     = InstructionFeature(rawValue: 0x00200)
    public static let use3     = InstructionFeature(rawValue: 0x00400)
    public static let use4     = InstructionFeature(rawValue: 0x00800)
    public static let use5     = InstructionFeature(rawValue: 0x01000)
    public static let use6     = InstructionFeature(rawValue: 0x02000)
    public static let jump     = InstructionFeature(rawValue: 0x04000)
    public static let shift    = InstructionFeature(rawValue: 0x08000)
    public static let highLevel = InstructionFeature(rawValue: 0x10000)
}

/// Processor feature flags (mirrors C++ `ProcessorFlag`).
public struct ProcessorFlag: OptionSet, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let segments          = ProcessorFlag(rawValue: 0x000001)
    public static let use32             = ProcessorFlag(rawValue: 0x000002)
    public static let use64             = ProcessorFlag(rawValue: 0x000004)
    public static let defaultSeg32      = ProcessorFlag(rawValue: 0x000008)
    public static let defaultSeg64      = ProcessorFlag(rawValue: 0x000010)
    public static let typeInfo          = ProcessorFlag(rawValue: 0x000020)
    public static let useArgTypes       = ProcessorFlag(rawValue: 0x000040)
    public static let conditionalInsns  = ProcessorFlag(rawValue: 0x000080)
    public static let noSegMove         = ProcessorFlag(rawValue: 0x000100)
    public static let hexNumbers        = ProcessorFlag(rawValue: 0x000200)
    public static let decimalNumbers    = ProcessorFlag(rawValue: 0x000400)
    public static let octalNumbers      = ProcessorFlag(rawValue: 0x000800)
}

// MARK: - Result enums

/// Result of `emulate()` callback (mirrors C++ `EmulateResult`).
public enum EmulateResult: Int32, Sendable {
    case notImplemented    =  0
    case success           =  1
    case deleteInstruction = -1
}

/// Result of `outputOperand()` callback (mirrors C++ `OutputOperandResult`).
public enum OutputOperandResult: Int32, Sendable {
    case notImplemented =  0
    case success        =  1
    case hidden         = -1
}

/// Result of context-driven instruction formatting (mirrors C++ `OutputInstructionResult`).
public enum OutputInstructionResult: Int32, Sendable {
    case notImplemented = 0
    case success        = 1
}

/// Kind of switch table (mirrors C++ `SwitchTableKind`).
public enum SwitchTableKind: Int32, Sendable {
    case dense    = 0
    case sparse   = 1
    case indirect = 2
    case custom   = 3
}

// MARK: - Data structs

/// Describes a single processor register.
public struct ProcessorRegisterInfo: Sendable {
    public var name: String
    public var readOnly: Bool

    public init(name: String, readOnly: Bool = false) {
        self.name = name
        self.readOnly = readOnly
    }
}

/// Describes a single instruction in the processor's instruction set.
public struct InstructionDescriptor: Sendable {
    public var mnemonic: String
    public var featureFlags: InstructionFeature
    public var operandCount: UInt8
    public var description: String
    public var privileged: Bool

    public init(
        mnemonic: String,
        featureFlags: InstructionFeature = [],
        operandCount: UInt8 = 0,
        description: String = "",
        privileged: Bool = false
    ) {
        self.mnemonic = mnemonic
        self.featureFlags = featureFlags
        self.operandCount = operandCount
        self.description = description
        self.privileged = privileged
    }
}

/// Describes assembler syntax preferences.
public struct AssemblerInfo: Sendable {
    public var name: String
    public var commentPrefix: String
    public var origin: String
    public var endDirective: String
    public var stringDelimiter: CChar
    public var characterDelimiter: CChar

    public var byteDirective: String
    public var wordDirective: String
    public var dwordDirective: String
    public var qwordDirective: String
    public var owordDirective: String
    public var floatDirective: String
    public var doubleDirective: String
    public var tbyteDirective: String
    public var alignDirective: String
    public var includeDirective: String
    public var publicDirective: String
    public var weakDirective: String
    public var externalDirective: String
    public var currentIPSymbol: String

    public var uppercaseMnemonics: Bool
    public var uppercaseRegisters: Bool
    public var requiresColonAfterLabels: Bool
    public var supportsQuotedNames: Bool

    public init(
        name: String = "",
        commentPrefix: String = ";",
        origin: String = "org",
        endDirective: String = "end",
        stringDelimiter: CChar = 0x22,  // '"'
        characterDelimiter: CChar = 0x27,  // '\''
        byteDirective: String = "db",
        wordDirective: String = "dw",
        dwordDirective: String = "dd",
        qwordDirective: String = "dq",
        owordDirective: String = "",
        floatDirective: String = "",
        doubleDirective: String = "",
        tbyteDirective: String = "",
        alignDirective: String = "",
        includeDirective: String = "",
        publicDirective: String = "",
        weakDirective: String = "",
        externalDirective: String = "",
        currentIPSymbol: String = "",
        uppercaseMnemonics: Bool = false,
        uppercaseRegisters: Bool = false,
        requiresColonAfterLabels: Bool = false,
        supportsQuotedNames: Bool = true
    ) {
        self.name = name
        self.commentPrefix = commentPrefix
        self.origin = origin
        self.endDirective = endDirective
        self.stringDelimiter = stringDelimiter
        self.characterDelimiter = characterDelimiter
        self.byteDirective = byteDirective
        self.wordDirective = wordDirective
        self.dwordDirective = dwordDirective
        self.qwordDirective = qwordDirective
        self.owordDirective = owordDirective
        self.floatDirective = floatDirective
        self.doubleDirective = doubleDirective
        self.tbyteDirective = tbyteDirective
        self.alignDirective = alignDirective
        self.includeDirective = includeDirective
        self.publicDirective = publicDirective
        self.weakDirective = weakDirective
        self.externalDirective = externalDirective
        self.currentIPSymbol = currentIPSymbol
        self.uppercaseMnemonics = uppercaseMnemonics
        self.uppercaseRegisters = uppercaseRegisters
        self.requiresColonAfterLabels = requiresColonAfterLabels
        self.supportsQuotedNames = supportsQuotedNames
    }
}

/// Processor metadata provided by a `ProcessorModule` implementation.
public struct ProcessorInfo: Sendable {
    public var id: Int32
    public var shortNames: [String]
    public var longNames: [String]
    public var flags: ProcessorFlag
    public var flags2: UInt32

    public var codeBitsPerByte: Int32
    public var dataBitsPerByte: Int32

    public var registers: [ProcessorRegisterInfo]
    public var codeSegmentRegister: Int32
    public var dataSegmentRegister: Int32
    public var firstSegmentRegister: Int32
    public var lastSegmentRegister: Int32
    public var segmentRegisterSize: Int32

    public var instructions: [InstructionDescriptor]
    public var returnIcode: Int32

    public var assemblers: [AssemblerInfo]

    public var defaultBitness: Int32

    public init(
        id: Int32 = 0,
        shortNames: [String] = [],
        longNames: [String] = [],
        flags: ProcessorFlag = [],
        flags2: UInt32 = 0,
        codeBitsPerByte: Int32 = 8,
        dataBitsPerByte: Int32 = 8,
        registers: [ProcessorRegisterInfo] = [],
        codeSegmentRegister: Int32 = 0,
        dataSegmentRegister: Int32 = 1,
        firstSegmentRegister: Int32 = 0,
        lastSegmentRegister: Int32 = 1,
        segmentRegisterSize: Int32 = 0,
        instructions: [InstructionDescriptor] = [],
        returnIcode: Int32 = 0,
        assemblers: [AssemblerInfo] = [],
        defaultBitness: Int32 = 32
    ) {
        self.id = id
        self.shortNames = shortNames
        self.longNames = longNames
        self.flags = flags
        self.flags2 = flags2
        self.codeBitsPerByte = codeBitsPerByte
        self.dataBitsPerByte = dataBitsPerByte
        self.registers = registers
        self.codeSegmentRegister = codeSegmentRegister
        self.dataSegmentRegister = dataSegmentRegister
        self.firstSegmentRegister = firstSegmentRegister
        self.lastSegmentRegister = lastSegmentRegister
        self.segmentRegisterSize = segmentRegisterSize
        self.instructions = instructions
        self.returnIcode = returnIcode
        self.assemblers = assemblers
        self.defaultBitness = defaultBitness
    }
}

/// One switch destination and all case values mapping to it.
public struct SwitchCase: Sendable {
    public var values: [Int64]
    public var target: Address

    public init(values: [Int64] = [], target: Address = .max) {
        self.values = values
        self.target = target
    }
}

/// Opaque, SDK-free description of a detected switch idiom.
public struct SwitchDescription: Sendable {
    public var kind: SwitchTableKind
    public var jumpTable: Address
    public var valuesTable: Address
    public var defaultTarget: Address
    public var idiomStart: Address
    public var elementBase: Address

    public var lowCaseValue: Int64
    public var indirectLowCaseValue: Int64

    public var caseCount: UInt32
    public var jumpTableEntryCount: UInt32

    public var jumpElementSize: UInt8
    public var valueElementSize: UInt8
    public var shift: UInt8

    public var expressionRegister: Int32
    public var expressionDataType: UInt8

    public var hasDefault: Bool
    public var defaultInTable: Bool
    public var valuesSigned: Bool
    public var subtractValues: Bool
    public var selfRelative: Bool
    public var inverted: Bool
    public var userDefined: Bool

    public init(
        kind: SwitchTableKind = .dense,
        jumpTable: Address = .max,
        valuesTable: Address = .max,
        defaultTarget: Address = .max,
        idiomStart: Address = .max,
        elementBase: Address = 0,
        lowCaseValue: Int64 = 0,
        indirectLowCaseValue: Int64 = 0,
        caseCount: UInt32 = 0,
        jumpTableEntryCount: UInt32 = 0,
        jumpElementSize: UInt8 = 0,
        valueElementSize: UInt8 = 0,
        shift: UInt8 = 0,
        expressionRegister: Int32 = -1,
        expressionDataType: UInt8 = 0,
        hasDefault: Bool = false,
        defaultInTable: Bool = false,
        valuesSigned: Bool = false,
        subtractValues: Bool = false,
        selfRelative: Bool = false,
        inverted: Bool = false,
        userDefined: Bool = false
    ) {
        self.kind = kind
        self.jumpTable = jumpTable
        self.valuesTable = valuesTable
        self.defaultTarget = defaultTarget
        self.idiomStart = idiomStart
        self.elementBase = elementBase
        self.lowCaseValue = lowCaseValue
        self.indirectLowCaseValue = indirectLowCaseValue
        self.caseCount = caseCount
        self.jumpTableEntryCount = jumpTableEntryCount
        self.jumpElementSize = jumpElementSize
        self.valueElementSize = valueElementSize
        self.shift = shift
        self.expressionRegister = expressionRegister
        self.expressionDataType = expressionDataType
        self.hasDefault = hasDefault
        self.defaultInTable = defaultInTable
        self.valuesSigned = valuesSigned
        self.subtractValues = subtractValues
        self.selfRelative = selfRelative
        self.inverted = inverted
        self.userDefined = userDefined
    }
}

// MARK: - OutputContext

/// SDK-opaque output builder for processor text rendering callbacks.
///
/// Borrowed (not owned) -- passed by the C++ framework to callback methods.
/// Move-only to prevent accidental copies of the raw pointer.
public struct OutputContext: ~Copyable {
    let pointer: UnsafeMutableRawPointer

    init(_ pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    /// Emit a mnemonic token.
    public func mnemonic(_ text: String) {
        text.withCString { idax_output_context_mnemonic(pointer, $0) }
    }

    /// Emit a register name token.
    public func registerName(_ text: String) {
        text.withCString { idax_output_context_register_name(pointer, $0) }
    }

    /// Emit a symbol token.
    public func symbol(_ text: String) {
        text.withCString { idax_output_context_symbol(pointer, $0) }
    }

    /// Emit a keyword token.
    public func keyword(_ text: String) {
        text.withCString { idax_output_context_keyword(pointer, $0) }
    }

    /// Emit a comment token.
    public func comment(_ text: String) {
        text.withCString { idax_output_context_comment(pointer, $0) }
    }

    /// Emit a number token.
    public func number(_ text: String) {
        text.withCString { idax_output_context_number(pointer, $0) }
    }

    /// Emit an operator symbol token.
    public func operatorSymbol(_ text: String) {
        text.withCString { idax_output_context_operator_symbol(pointer, $0) }
    }

    /// Emit a punctuation token.
    public func punctuation(_ text: String) {
        text.withCString { idax_output_context_punctuation(pointer, $0) }
    }

    /// Emit a whitespace token.
    public func whitespace(_ text: String = " ") {
        text.withCString { idax_output_context_whitespace(pointer, $0) }
    }

    /// Emit a string literal token (including quote characters).
    public func stringLiteral(_ text: String, quote: CChar = 0x22) {
        text.withCString { idax_output_context_string_literal(pointer, $0, quote) }
    }

    /// Emit a formatted immediate value token.
    public func immediate(_ value: Int64, radix: Int32 = 16) {
        idax_output_context_immediate(pointer, value, radix)
    }

    /// Emit a formatted address token.
    public func address(_ address: Address) {
        idax_output_context_address(pointer, address)
    }

    /// Emit a single character token (auto-classified by kind).
    public func character(_ character: CChar) {
        idax_output_context_character(pointer, character)
    }

    /// Emit a single space.
    public func space() {
        idax_output_context_space(pointer)
    }

    /// Emit a comma punctuation token.
    public func comma() {
        idax_output_context_comma(pointer)
    }

    /// Clear all accumulated output.
    public func clear() {
        idax_output_context_clear(pointer)
    }

    /// Whether the output buffer is empty.
    public var isEmpty: Bool {
        idax_output_context_is_empty(pointer) != 0
    }

    /// The accumulated plain-text output.
    public var text: String {
        var textPointer: UnsafeMutablePointer<CChar>? = nil
        if idax_output_context_text(pointer, &textPointer) == 0 {
            return takeCString(textPointer)
        }
        return ""
    }

    /// Append plain text.
    public func append(_ text: String) {
        text.withCString { idax_output_context_append(pointer, $0) }
    }

    /// Emit a token with an explicit kind.
    public func token(kind: Int32, text: String) {
        text.withCString { idax_output_context_token(pointer, kind, $0) }
    }
}

// MARK: - ProcessorModule protocol

/// Protocol for implementing a custom IDA processor module.
///
/// Subclass this to define how your processor analyzes, emulates,
/// and renders instructions. Required methods must be implemented;
/// optional methods have sensible default implementations.
public protocol ProcessorModule: AnyObject {
    // ── Required ───────────────────────────────────────────────────────

    /// Return processor metadata (registers, instructions, assembler, etc.).
    var info: ProcessorInfo { get }

    /// Analyze one instruction at the given address.
    /// Returns instruction size in bytes (0 on decode failure).
    func analyze(at address: Address) throws(IDAError) -> Int

    /// Emulate an instruction (create xrefs, plan analysis, etc.).
    func emulate(at address: Address) -> EmulateResult

    /// Generate text output for an instruction.
    func outputInstruction(at address: Address)

    /// Generate text for a single operand.
    func outputOperand(at address: Address, operand: Int, to context: borrowing OutputContext) -> OutputOperandResult
}

// Default implementations for optional methods.
public extension ProcessorModule {

    /// Called when a new file is loaded.
    func onNewFile(filename: String) {}

    /// Called when an old file is loaded.
    func onOldFile(filename: String) {}

    /// Check if an instruction is a call. 1=yes, -1=no, 0=default.
    func isCall(at address: Address) -> Int32 { 0 }

    /// Check if an instruction is a return. 1=yes, -1=no, 0=default.
    func isReturn(at address: Address) -> Int32 { 0 }

    /// Probability that a function starts at this address (0..100, or -1).
    func mayBeFunction(at address: Address) -> Int32 { 0 }

    /// Whether this instruction is sane for this file type. >=0=sane, <0=invalid.
    func isSaneInstruction(at address: Address, noCodeReferences: Bool) -> Int32 { 0 }

    /// Whether this instruction is an indirect jump. 0=default, 1=no, 2=yes.
    func isIndirectJump(at address: Address) -> Int32 { 0 }

    /// Whether this instruction is a basic-block terminator. 0=unknown, -1=no, 1=yes.
    func isBasicBlockEnd(at address: Address, callStopsBlock: Bool) -> Int32 { 0 }

    /// Create a function frame. Returns true if frame was created.
    func createFunctionFrame(at functionStart: Address) -> Bool { false }

    /// Adjust function-boundary analysis result.
    func adjustFunctionBounds(
        functionStart: Address,
        maxFunctionEnd: Address,
        suggestedResult: Int32
    ) -> Int32 { suggestedResult }

    /// Analyze function prolog/epilog. 1=handled, 0=not implemented.
    func analyzeFunctionProlog(at functionStart: Address) -> Int32 { 0 }

    /// Compute stack-pointer delta for one instruction.
    /// Returns (handled: 1/0, delta).
    func calculateStackPointerDelta(at address: Address) -> (handled: Int32, delta: Int64) {
        (0, 0)
    }

    /// Get the return address size for a function (bytes), 0=not implemented.
    func getReturnAddressSize(at functionStart: Address) -> Int32 { 0 }

    /// Detect and describe a switch/jump-table idiom.
    /// Returns (1=found, -1=not a switch, 0=not implemented).
    func detectSwitch(at address: Address) -> (result: Int32, switchDescription: SwitchDescription) {
        (0, SwitchDescription())
    }

    /// Calculate switch case values and targets for custom switches.
    /// Returns (1=handled, 0=not implemented).
    func calculateSwitchCases(
        at address: Address,
        switchDescription: SwitchDescription
    ) -> (result: Int32, cases: [SwitchCase]) {
        (0, [])
    }

    /// Create xrefs for a custom switch table. 1=handled, 0=not implemented.
    func createSwitchReferences(
        at address: Address,
        switchDescription: SwitchDescription
    ) -> Int32 { 0 }

    /// Optional context-driven mnemonic formatter.
    func outputMnemonicWithContext(
        at address: Address,
        to context: borrowing OutputContext
    ) -> OutputInstructionResult { .notImplemented }

    /// Optional context-driven full instruction formatter.
    func outputInstructionWithContext(
        at address: Address,
        to context: borrowing OutputContext
    ) -> OutputInstructionResult { .notImplemented }

    /// Optional context-driven operand formatter.
    func outputOperandWithContext(
        at address: Address,
        operand: Int,
        to context: borrowing OutputContext
    ) -> OutputOperandResult { .notImplemented }
}

// MARK: - ProcessorRegistration (RAII token)

/// RAII registration token for a processor module.
///
/// Unregisters the processor on `deinit`. Call `unregister()` to
/// explicitly unregister and consume the token.
public struct ProcessorRegistration: ~Copyable, @unchecked Sendable {
    private let handle: IdaxProcessorHandle
    private let contextPointer: UnsafeMutableRawPointer

    init(handle: IdaxProcessorHandle, contextPointer: UnsafeMutableRawPointer) {
        self.handle = handle
        self.contextPointer = contextPointer
    }

    deinit {
        idax_processor_unregister(handle)
        Unmanaged<AnyObject>.fromOpaque(contextPointer).release()
    }

    /// Explicitly unregister the processor module.
    public consuming func unregister() {
        idax_processor_unregister(handle)
        Unmanaged<AnyObject>.fromOpaque(contextPointer).release()
        discard self
    }
}

// MARK: - Registration function

/// Register a processor module and return an RAII registration token.
///
/// The token must be kept alive for the processor to remain active.
/// Dropping or consuming the token unregisters the processor.
public func registerProcessor(_ module: some ProcessorModule) throws(IDAError) -> ProcessorRegistration {
    let box = ProcessorBox(module: module)
    let context = Unmanaged.passRetained(box).toOpaque()

    var callbacks = IdaxProcessorCallbacks()
    callbacks.context = context

    // Required
    callbacks.info = processorInfoTrampoline
    callbacks.analyze = processorAnalyzeTrampoline
    callbacks.emulate = processorEmulateTrampoline
    callbacks.output_instruction = processorOutputInstructionTrampoline
    callbacks.output_operand = processorOutputOperandTrampoline

    // Optional
    callbacks.on_new_file = processorOnNewFileTrampoline
    callbacks.on_old_file = processorOnOldFileTrampoline
    callbacks.is_call = processorIsCallTrampoline
    callbacks.is_return = processorIsReturnTrampoline
    callbacks.may_be_function = processorMayBeFunctionTrampoline
    callbacks.is_sane_instruction = processorIsSaneInstructionTrampoline
    callbacks.is_indirect_jump = processorIsIndirectJumpTrampoline
    callbacks.is_basic_block_end = processorIsBasicBlockEndTrampoline
    callbacks.create_function_frame = processorCreateFunctionFrameTrampoline
    callbacks.adjust_function_bounds = processorAdjustFunctionBoundsTrampoline
    callbacks.analyze_function_prolog = processorAnalyzeFunctionPrologTrampoline
    callbacks.calculate_stack_pointer_delta = processorStackDeltaTrampoline
    callbacks.get_return_address_size = processorReturnAddressSizeTrampoline
    callbacks.detect_switch = processorDetectSwitchTrampoline
    callbacks.calculate_switch_cases = processorCalculateSwitchCasesTrampoline
    callbacks.create_switch_references = processorCreateSwitchReferencesTrampoline
    callbacks.output_mnemonic_with_context = processorOutputMnemonicWithContextTrampoline
    callbacks.output_instruction_with_context = processorOutputInstructionWithContextTrampoline
    callbacks.output_operand_with_context = processorOutputOperandWithContextTrampoline

    var handle: IdaxProcessorHandle? = nil
    do {
        try checkStatus(
            idax_processor_register(&callbacks, &handle),
            "processor.register"
        )
    } catch {
        Unmanaged<AnyObject>.fromOpaque(context).release()
        throw error
    }

    return ProcessorRegistration(handle: handle!, contextPointer: context)
}

// MARK: - Private callback box

private final class ProcessorBox {
    let module: any ProcessorModule
    init(module: any ProcessorModule) { self.module = module }
}

// MARK: - C trampoline functions

// Helper to extract box from opaque context.
private func extractModule(_ context: UnsafeMutableRawPointer?) -> (any ProcessorModule)? {
    guard let context else { return nil }
    return Unmanaged<ProcessorBox>.fromOpaque(context).takeUnretainedValue().module
}

// ── Required trampolines ───────────────────────────────────────────────

private func processorInfoTrampoline(
    context: UnsafeMutableRawPointer?,
    out: UnsafeMutablePointer<IdaxProcessorInfo>?
) {
    guard let module = extractModule(context), let out else { return }

    let processorInfo = module.info

    // Zero-initialize the output.
    out.pointee = IdaxProcessorInfo()

    out.pointee.id = processorInfo.id
    out.pointee.flags = processorInfo.flags.rawValue
    out.pointee.flags2 = processorInfo.flags2
    out.pointee.code_bits_per_byte = processorInfo.codeBitsPerByte
    out.pointee.data_bits_per_byte = processorInfo.dataBitsPerByte
    out.pointee.code_segment_register = processorInfo.codeSegmentRegister
    out.pointee.data_segment_register = processorInfo.dataSegmentRegister
    out.pointee.first_segment_register = processorInfo.firstSegmentRegister
    out.pointee.last_segment_register = processorInfo.lastSegmentRegister
    out.pointee.segment_register_size = processorInfo.segmentRegisterSize
    out.pointee.return_icode = processorInfo.returnIcode
    out.pointee.default_bitness = processorInfo.defaultBitness

    // Short names
    if !processorInfo.shortNames.isEmpty {
        let count = processorInfo.shortNames.count
        let array = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: count)
        for (index, name) in processorInfo.shortNames.enumerated() {
            array[index] = strdup(name)
        }
        out.pointee.short_names = array
        out.pointee.short_name_count = count
    }

    // Long names
    if !processorInfo.longNames.isEmpty {
        let count = processorInfo.longNames.count
        let array = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: count)
        for (index, name) in processorInfo.longNames.enumerated() {
            array[index] = strdup(name)
        }
        out.pointee.long_names = array
        out.pointee.long_name_count = count
    }

    // Registers
    if !processorInfo.registers.isEmpty {
        let count = processorInfo.registers.count
        let array = UnsafeMutablePointer<IdaxRegisterInfo>.allocate(capacity: count)
        for (index, register) in processorInfo.registers.enumerated() {
            array[index] = IdaxRegisterInfo(
                name: strdup(register.name),
                read_only: register.readOnly ? 1 : 0
            )
        }
        out.pointee.registers = array
        out.pointee.register_count = count
    }

    // Instructions
    if !processorInfo.instructions.isEmpty {
        let count = processorInfo.instructions.count
        let array = UnsafeMutablePointer<IdaxInstructionDescriptor>.allocate(capacity: count)
        for (index, instruction) in processorInfo.instructions.enumerated() {
            array[index] = IdaxInstructionDescriptor(
                mnemonic: strdup(instruction.mnemonic),
                feature_flags: instruction.featureFlags.rawValue,
                operand_count: instruction.operandCount,
                description: strdup(instruction.description),
                privileged: instruction.privileged ? 1 : 0
            )
        }
        out.pointee.instructions = array
        out.pointee.instruction_count = count
    }

    // Assemblers
    if !processorInfo.assemblers.isEmpty {
        let count = processorInfo.assemblers.count
        let array = UnsafeMutablePointer<IdaxAssemblerInfo>.allocate(capacity: count)
        for (index, assembler) in processorInfo.assemblers.enumerated() {
            array[index] = IdaxAssemblerInfo(
                name: strdup(assembler.name),
                comment_prefix: strdup(assembler.commentPrefix),
                origin: strdup(assembler.origin),
                end_directive: strdup(assembler.endDirective),
                string_delim: assembler.stringDelimiter,
                char_delim: assembler.characterDelimiter,
                byte_directive: strdup(assembler.byteDirective),
                word_directive: strdup(assembler.wordDirective),
                dword_directive: strdup(assembler.dwordDirective),
                qword_directive: strdup(assembler.qwordDirective),
                oword_directive: strdup(assembler.owordDirective),
                float_directive: strdup(assembler.floatDirective),
                double_directive: strdup(assembler.doubleDirective),
                tbyte_directive: strdup(assembler.tbyteDirective),
                align_directive: strdup(assembler.alignDirective),
                include_directive: strdup(assembler.includeDirective),
                public_directive: strdup(assembler.publicDirective),
                weak_directive: strdup(assembler.weakDirective),
                external_directive: strdup(assembler.externalDirective),
                current_ip_symbol: strdup(assembler.currentIPSymbol),
                uppercase_mnemonics: assembler.uppercaseMnemonics ? 1 : 0,
                uppercase_registers: assembler.uppercaseRegisters ? 1 : 0,
                requires_colon_after_labels: assembler.requiresColonAfterLabels ? 1 : 0,
                supports_quoted_names: assembler.supportsQuotedNames ? 1 : 0
            )
        }
        out.pointee.assemblers = array
        out.pointee.assembler_count = count
    }
}

private func processorAnalyzeTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    outSize: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let module = extractModule(context), let outSize else { return -1 }
    do {
        let size = try module.analyze(at: address)
        outSize.pointee = Int32(size)
        return 0
    } catch {
        return -1
    }
}

private func processorEmulateTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) -> Int32 {
    guard let module = extractModule(context) else {
        return EmulateResult.notImplemented.rawValue
    }
    return module.emulate(at: address).rawValue
}

private func processorOutputInstructionTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) {
    guard let module = extractModule(context) else { return }
    module.outputInstruction(at: address)
}

private func processorOutputOperandTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    operandIndex: Int32
) -> Int32 {
    guard let module = extractModule(context) else {
        return OutputOperandResult.notImplemented.rawValue
    }
    // Create a temporary OutputContext; the C shim will provide the real pointer
    // in with-context variants. For the bare variant, we pass a dummy.
    // The bare output_operand in C++ doesn't receive an OutputContext.
    // We need the context pointer here - but the bare callback doesn't get one.
    // Actually, looking at the C callback signature, there is no output context
    // for the bare output_operand - it just returns the result code.
    return module.outputOperand(
        at: address,
        operand: Int(operandIndex),
        to: OutputContext(UnsafeMutableRawPointer(bitPattern: 1)!)  // Placeholder - bare variant
    ).rawValue
}

// ── Optional trampolines ───────────────────────────────────────────────

private func processorOnNewFileTrampoline(
    context: UnsafeMutableRawPointer?,
    filename: UnsafePointer<CChar>?
) {
    guard let module = extractModule(context) else { return }
    let name = filename.map { String(cString: $0) } ?? ""
    module.onNewFile(filename: name)
}

private func processorOnOldFileTrampoline(
    context: UnsafeMutableRawPointer?,
    filename: UnsafePointer<CChar>?
) {
    guard let module = extractModule(context) else { return }
    let name = filename.map { String(cString: $0) } ?? ""
    module.onOldFile(filename: name)
}

private func processorIsCallTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.isCall(at: address)
}

private func processorIsReturnTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.isReturn(at: address)
}

private func processorMayBeFunctionTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.mayBeFunction(at: address)
}

private func processorIsSaneInstructionTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    noCodeReferences: Int32
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.isSaneInstruction(at: address, noCodeReferences: noCodeReferences != 0)
}

private func processorIsIndirectJumpTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.isIndirectJump(at: address)
}

private func processorIsBasicBlockEndTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    callStopsBlock: Int32
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.isBasicBlockEnd(at: address, callStopsBlock: callStopsBlock != 0)
}

private func processorCreateFunctionFrameTrampoline(
    context: UnsafeMutableRawPointer?,
    functionStart: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.createFunctionFrame(at: functionStart) ? 1 : 0
}

private func processorAdjustFunctionBoundsTrampoline(
    context: UnsafeMutableRawPointer?,
    functionStart: UInt64,
    maxFunctionEnd: UInt64,
    suggestedResult: Int32
) -> Int32 {
    guard let module = extractModule(context) else { return suggestedResult }
    return module.adjustFunctionBounds(
        functionStart: functionStart,
        maxFunctionEnd: maxFunctionEnd,
        suggestedResult: suggestedResult
    )
}

private func processorAnalyzeFunctionPrologTrampoline(
    context: UnsafeMutableRawPointer?,
    functionStart: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.analyzeFunctionProlog(at: functionStart)
}

private func processorStackDeltaTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    outDelta: UnsafeMutablePointer<Int64>?
) -> Int32 {
    guard let module = extractModule(context), let outDelta else { return 0 }
    let (handled, delta) = module.calculateStackPointerDelta(at: address)
    outDelta.pointee = delta
    return handled
}

private func processorReturnAddressSizeTrampoline(
    context: UnsafeMutableRawPointer?,
    functionStart: UInt64
) -> Int32 {
    guard let module = extractModule(context) else { return 0 }
    return module.getReturnAddressSize(at: functionStart)
}

private func processorDetectSwitchTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    outSwitch: UnsafeMutablePointer<IdaxSwitchDescription>?
) -> Int32 {
    guard let module = extractModule(context), let outSwitch else { return 0 }
    let (result, switchDescription) = module.detectSwitch(at: address)
    if result > 0 {
        fillCSwitch(outSwitch, from: switchDescription)
    }
    return result
}

private func processorCalculateSwitchCasesTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    switchDescription: UnsafePointer<IdaxSwitchDescription>?,
    outCases: UnsafeMutablePointer<UnsafeMutablePointer<IdaxSwitchCase>?>?,
    outCaseCount: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let module = extractModule(context),
          let switchDescription,
          let outCases,
          let outCaseCount else { return 0 }

    let swiftSwitch = toSwiftSwitch(switchDescription.pointee)
    let (result, cases) = module.calculateSwitchCases(
        at: address,
        switchDescription: swiftSwitch
    )

    if result > 0 && !cases.isEmpty {
        let count = cases.count
        let array = UnsafeMutablePointer<IdaxSwitchCase>.allocate(capacity: count)
        for (index, switchCase) in cases.enumerated() {
            let valuesPointer = UnsafeMutablePointer<Int64>.allocate(capacity: switchCase.values.count)
            for (valueIndex, value) in switchCase.values.enumerated() {
                valuesPointer[valueIndex] = value
            }
            array[index] = IdaxSwitchCase(
                values: valuesPointer,
                value_count: switchCase.values.count,
                target: switchCase.target
            )
        }
        outCases.pointee = array
        outCaseCount.pointee = count
    } else {
        outCases.pointee = nil
        outCaseCount.pointee = 0
    }

    return result
}

private func processorCreateSwitchReferencesTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    switchDescription: UnsafePointer<IdaxSwitchDescription>?
) -> Int32 {
    guard let module = extractModule(context), let switchDescription else { return 0 }
    let swiftSwitch = toSwiftSwitch(switchDescription.pointee)
    return module.createSwitchReferences(at: address, switchDescription: swiftSwitch)
}

private func processorOutputMnemonicWithContextTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    outputContext: UnsafeMutableRawPointer?
) -> Int32 {
    guard let module = extractModule(context), let outputContext else {
        return OutputInstructionResult.notImplemented.rawValue
    }
    return module.outputMnemonicWithContext(
        at: address,
        to: OutputContext(outputContext)
    ).rawValue
}

private func processorOutputInstructionWithContextTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    outputContext: UnsafeMutableRawPointer?
) -> Int32 {
    guard let module = extractModule(context), let outputContext else {
        return OutputInstructionResult.notImplemented.rawValue
    }
    return module.outputInstructionWithContext(
        at: address,
        to: OutputContext(outputContext)
    ).rawValue
}

private func processorOutputOperandWithContextTrampoline(
    context: UnsafeMutableRawPointer?,
    address: UInt64,
    operandIndex: Int32,
    outputContext: UnsafeMutableRawPointer?
) -> Int32 {
    guard let module = extractModule(context), let outputContext else {
        return OutputOperandResult.notImplemented.rawValue
    }
    return module.outputOperandWithContext(
        at: address,
        operand: Int(operandIndex),
        to: OutputContext(outputContext)
    ).rawValue
}

// MARK: - Private conversion helpers

/// Fill a C IdaxSwitchDescription from a Swift SwitchDescription.
private func fillCSwitch(
    _ out: UnsafeMutablePointer<IdaxSwitchDescription>,
    from description: SwitchDescription
) {
    out.pointee.kind = description.kind.rawValue
    out.pointee.jump_table = description.jumpTable
    out.pointee.values_table = description.valuesTable
    out.pointee.default_target = description.defaultTarget
    out.pointee.idiom_start = description.idiomStart
    out.pointee.element_base = description.elementBase
    out.pointee.low_case_value = description.lowCaseValue
    out.pointee.indirect_low_case_value = description.indirectLowCaseValue
    out.pointee.case_count = description.caseCount
    out.pointee.jump_table_entry_count = description.jumpTableEntryCount
    out.pointee.jump_element_size = description.jumpElementSize
    out.pointee.value_element_size = description.valueElementSize
    out.pointee.shift = description.shift
    out.pointee.expression_register = description.expressionRegister
    out.pointee.expression_data_type = description.expressionDataType
    out.pointee.has_default = description.hasDefault ? 1 : 0
    out.pointee.default_in_table = description.defaultInTable ? 1 : 0
    out.pointee.values_signed = description.valuesSigned ? 1 : 0
    out.pointee.subtract_values = description.subtractValues ? 1 : 0
    out.pointee.self_relative = description.selfRelative ? 1 : 0
    out.pointee.inverted = description.inverted ? 1 : 0
    out.pointee.user_defined = description.userDefined ? 1 : 0
}

/// Convert a C IdaxSwitchDescription to a Swift SwitchDescription.
private func toSwiftSwitch(_ raw: IdaxSwitchDescription) -> SwitchDescription {
    SwitchDescription(
        kind: SwitchTableKind(rawValue: raw.kind) ?? .dense,
        jumpTable: raw.jump_table,
        valuesTable: raw.values_table,
        defaultTarget: raw.default_target,
        idiomStart: raw.idiom_start,
        elementBase: raw.element_base,
        lowCaseValue: raw.low_case_value,
        indirectLowCaseValue: raw.indirect_low_case_value,
        caseCount: raw.case_count,
        jumpTableEntryCount: raw.jump_table_entry_count,
        jumpElementSize: raw.jump_element_size,
        valueElementSize: raw.value_element_size,
        shift: raw.shift,
        expressionRegister: raw.expression_register,
        expressionDataType: raw.expression_data_type,
        hasDefault: raw.has_default != 0,
        defaultInTable: raw.default_in_table != 0,
        valuesSigned: raw.values_signed != 0,
        subtractValues: raw.subtract_values != 0,
        selfRelative: raw.self_relative != 0,
        inverted: raw.inverted != 0,
        userDefined: raw.user_defined != 0
    )
}
