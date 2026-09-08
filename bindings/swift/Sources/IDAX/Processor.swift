internal import CIDAX

/// Typed processor module descriptors and callback protocols.
public enum Processor {
    public struct InstructionFeatures: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let stop = Self(rawValue: 0x00001)
        public static let call = Self(rawValue: 0x00002)
        public static let change1 = Self(rawValue: 0x00004)
        public static let change2 = Self(rawValue: 0x00008)
        public static let change3 = Self(rawValue: 0x00010)
        public static let change4 = Self(rawValue: 0x00020)
        public static let change5 = Self(rawValue: 0x00040)
        public static let change6 = Self(rawValue: 0x00080)
        public static let use1 = Self(rawValue: 0x00100)
        public static let use2 = Self(rawValue: 0x00200)
        public static let use3 = Self(rawValue: 0x00400)
        public static let use4 = Self(rawValue: 0x00800)
        public static let use5 = Self(rawValue: 0x01000)
        public static let use6 = Self(rawValue: 0x02000)
        public static let jump = Self(rawValue: 0x04000)
        public static let shift = Self(rawValue: 0x08000)
        public static let highLevel = Self(rawValue: 0x10000)
        public static let change7 = Self(rawValue: 0x020000)
        public static let change8 = Self(rawValue: 0x040000)
        public static let use7 = Self(rawValue: 0x080000)
        public static let use8 = Self(rawValue: 0x100000)
    }
    public struct Flags: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let hexNumbers: Self = []
        public static let segments = Self(rawValue: 0x000001)
        public static let use32 = Self(rawValue: 0x000002)
        public static let defaultSeg32 = Self(rawValue: 0x000004)
        public static let registerNames = Self(rawValue: 0x000008)
        public static let adjustSegments = Self(rawValue: 0x000020)
        public static let octalNumbers = Self(rawValue: 0x000040)
        public static let decimalNumbers = Self(rawValue: 0x000080)
        public static let binaryNumbers = Self(rawValue: 0x0000C0)
        public static let wordInstructions = Self(rawValue: 0x000100)
        public static let noChange = Self(rawValue: 0x000200)
        public static let assemble = Self(rawValue: 0x000400)
        public static let alignData = Self(rawValue: 0x000800)
        public static let typeInfo = Self(rawValue: 0x001000)
        public static let use64 = Self(rawValue: 0x002000)
        public static let segmentRegistersOther = Self(rawValue: 0x004000)
        public static let stackGrowsUp = Self(rawValue: 0x008000)
        public static let binaryMemory = Self(rawValue: 0x010000)
        public static let segmentTranslation = Self(rawValue: 0x020000)
        public static let checkCrossReferences = Self(rawValue: 0x040000)
        public static let noSegMove = Self(rawValue: 0x080000)
        public static let useArgTypes = Self(rawValue: 0x200000)
        public static let scaleStackVariables = Self(rawValue: 0x400000)
        public static let delayedBranches = Self(rawValue: 0x800000)
        public static let alignInstructions = Self(rawValue: 0x1000000)
        public static let purging = Self(rawValue: 0x2000000)
        public static let conditionalInsns = Self(rawValue: 0x4000000)
        public static let useTbyte = Self(rawValue: 0x8000000)
        public static let defaultSeg64 = Self(rawValue: 0x1000_0000)
        public static let outerOperands = Self(rawValue: 0x2000_0000)
    }
    public struct Flags2: OptionSet, Sendable {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        public static let mappings = Self(rawValue: 0x000001)
        public static let idpOptions = Self(rawValue: 0x000002)
        public static let code16Bit = Self(rawValue: 0x000008)
        public static let macro = Self(rawValue: 0x000010)
        public static let useCalcRel = Self(rawValue: 0x000020)
        public static let relativeBits = Self(rawValue: 0x000040)
        public static let force16BitTypes = Self(rawValue: 0x000080)
        public static let ignoreIdaGuess = Self(rawValue: 0x000100)
    }
    public struct Register: Sendable {
        public var name: String
        public var readOnly: Bool
        public init(name: String, readOnly: Bool = false) {
            self.name = name
            self.readOnly = readOnly
        }
    }
    public struct InstructionDescriptor: Sendable {
        public var mnemonic: String
        public var features: InstructionFeatures
        public var operandCount: UInt8
        public var description: String
        public var privileged: Bool
        public init(
            mnemonic: String, features: InstructionFeatures = [], operandCount: UInt8 = 0,
            description: String = "", privileged: Bool = false
        ) {
            self.mnemonic = mnemonic
            self.features = features
            self.operandCount = operandCount
            self.description = description
            self.privileged = privileged
        }
    }
    public struct Assembler: Sendable {
        public var name: String = ""
        public var commentPrefix: String = ""
        public var origin: String = ""
        public var endDirective: String = ""
        public var byteDirective: String = ""
        public var wordDirective: String = ""
        public var dwordDirective: String = ""
        public var qwordDirective: String = ""
        public var owordDirective: String = ""
        public var floatDirective: String = ""
        public var doubleDirective: String = ""
        public var tbyteDirective: String = ""
        public var alignDirective: String = ""
        public var includeDirective: String = ""
        public var publicDirective: String = ""
        public var weakDirective: String = ""
        public var externalDirective: String = ""
        public var currentIpSymbol: String = ""
        public var stringDelimiter: UInt8 = 34
        public var characterDelimiter: UInt8 = 39
        public var uppercaseMnemonics = false
        public var uppercaseRegisters = false
        public var requiresColonAfterLabels = false
        public var supportsQuotedNames = true
        public init(name: String) { self.name = name }
    }
    public struct Information: Sendable {
        public var identifier: Int32
        public var shortNames, longNames: [String]
        public var flags: Flags = []
        public var flags2: Flags2 = []
        public var codeBitsPerByte: Int32 = 8
        public var dataBitsPerByte: Int32 = 8
        public var registers: [Register] = []
        public var codeSegmentRegister: Int32 = 0
        public var dataSegmentRegister: Int32 = 1
        public var firstSegmentRegister: Int32 = 0
        public var lastSegmentRegister: Int32 = 1
        public var segmentRegisterSize: Int32 = 0
        public var instructions: [InstructionDescriptor] = []
        public var returnInstructionCode: Int32 = 0
        public var assemblers: [Assembler] = []
        public var defaultBitness: Int32 = 32
        public init(identifier: Int32, shortNames: [String], longNames: [String]) {
            self.identifier = identifier
            self.shortNames = shortNames
            self.longNames = longNames
        }
        internal func write(to lease: UnsafeMutableRawPointer) throws(IDAError) {
            guard identifier > 0x8000, !shortNames.isEmpty, shortNames.count == longNames.count,
                shortNames.allSatisfy({ !$0.isEmpty && $0.utf8.count < 9 }),
                [16, 32, 64].contains(defaultBitness), codeBitsPerByte > 0, dataBitsPerByte > 0
            else {
                throw IDAError(
                    category: .validation,
                    message: "Invalid processor identifier, names, bitness, or addressable unit size")
            }
            try moduleStrings(lease, 200, shortNames)
            try moduleStrings(lease, 201, longNames)
            try moduleNumbers(
                lease, 200,
                [
                    Int64(identifier), Int64(flags.rawValue), Int64(flags2.rawValue), Int64(codeBitsPerByte),
                    Int64(dataBitsPerByte), Int64(codeSegmentRegister), Int64(dataSegmentRegister),
                    Int64(firstSegmentRegister), Int64(lastSegmentRegister), Int64(segmentRegisterSize),
                    Int64(returnInstructionCode), Int64(defaultBitness),
                ])
            try moduleStrings(lease, 202, registers.map(\.name))
            try moduleNumbers(lease, 202, registers.map { $0.readOnly ? 1 : 0 })
            for instruction in instructions {
                try moduleStrings(lease, 203, [instruction.mnemonic, instruction.description])
                try moduleNumbers(
                    lease, 203,
                    [
                        Int64(instruction.features.rawValue), Int64(instruction.operandCount),
                        instruction.privileged ? 1 : 0,
                    ])
            }
            for assembler in assemblers {
                try moduleStrings(
                    lease, 204,
                    [
                        assembler.name, assembler.commentPrefix, assembler.origin, assembler.endDirective,
                        assembler.byteDirective, assembler.wordDirective, assembler.dwordDirective,
                        assembler.qwordDirective, assembler.owordDirective, assembler.floatDirective,
                        assembler.doubleDirective, assembler.tbyteDirective, assembler.alignDirective,
                        assembler.includeDirective, assembler.publicDirective, assembler.weakDirective,
                        assembler.externalDirective, assembler.currentIpSymbol,
                    ])
                try moduleNumbers(
                    lease, 204,
                    [
                        Int64(assembler.stringDelimiter), Int64(assembler.characterDelimiter),
                        assembler.uppercaseMnemonics ? 1 : 0, assembler.uppercaseRegisters ? 1 : 0,
                        assembler.requiresColonAfterLabels ? 1 : 0, assembler.supportsQuotedNames ? 1 : 0,
                    ])
            }
        }
    }
    public enum EmulateResult: Int32, Sendable {
        case deleteInstruction = -1, notImplemented = 0, success = 1
    }
    public enum OutputOperandResult: Int32, Sendable { case hidden = -1, notImplemented = 0, success = 1 }
    public enum OutputInstructionResult: Int32, Sendable { case notImplemented = 0, success = 1 }
    public enum OperandKind: Int32, Sendable {
        case none, register, immediate, nearAddress, farAddress, directMemory, indirectMemory, displacement,
            processorSpecific0, processorSpecific1, processorSpecific2, processorSpecific3,
            processorSpecific4, processorSpecific5
    }
    public struct AnalyzeOperand: Sendable {
        public var index: Int
        public var kind: OperandKind
        public var registerIndex: Int32?
        public var immediateValue: UInt64?
        public var targetAddress: Address?
        public var displacement: Int64?
        public var dataTypeCode, processorFlags: UInt32
        public init(
            index: Int, kind: OperandKind, registerIndex: Int32? = nil, immediateValue: UInt64? = nil,
            targetAddress: Address? = nil, displacement: Int64? = nil, dataTypeCode: UInt32 = 0,
            processorFlags: UInt32 = 0
        ) {
            self.index = index
            self.kind = kind
            self.registerIndex = registerIndex
            self.immediateValue = immediateValue
            self.targetAddress = targetAddress
            self.displacement = displacement
            self.dataTypeCode = dataTypeCode
            self.processorFlags = processorFlags
        }
        internal func write(to lease: UnsafeMutableRawPointer) throws(IDAError) {
            guard (0..<8).contains(index) else {
                throw IDAError(category: .validation, message: "Processor operand index must be 0 through 7")
            }
            var value = IdaxSwiftAnalyzeOperand(
                index: index, kind: kind.rawValue, has_register: registerIndex == nil ? 0 : 1,
                register_index: registerIndex ?? -1, has_immediate: immediateValue == nil ? 0 : 1,
                immediate_value: immediateValue ?? 0, has_target_address: targetAddress == nil ? 0 : 1,
                target_address: targetAddress ?? .max, has_displacement: displacement == nil ? 0 : 1,
                displacement: displacement ?? 0, data_type_code: dataTypeCode, processor_flags: processorFlags
            )
            try bridgeCall("processor.analyze.operand") { idax_swift_module_operand(lease, &value, $0) }
        }
    }
    public struct AnalyzeDetails: Sendable {
        public var instructionCode: UInt16
        public var size: Int32
        public var operands: [AnalyzeOperand]
        public init(instructionCode: UInt16 = 0, size: Int32, operands: [AnalyzeOperand] = []) {
            self.instructionCode = instructionCode
            self.size = size
            self.operands = operands
        }
        internal func write(to lease: UnsafeMutableRawPointer) throws(IDAError) {
            guard size >= 0, Set(operands.map(\.index)).count == operands.count else {
                throw IDAError(
                    category: .validation, message: "Invalid instruction size or duplicate operand index")
            }
            try moduleNumbers(lease, 201, [Int64(instructionCode), Int64(size)])
            for operand in operands { try operand.write(to: lease) }
        }
    }
    public enum OutputTokenKind: Int32, Sendable {
        case plainText, mnemonic, register, immediate, address, symbol, comment, keyword, stringLiteral,
            number, operatorSymbol, punctuation, whitespace
    }
    public struct OutputToken: Sendable, Equatable {
        public var kind: OutputTokenKind
        public var text: String
        public init(kind: OutputTokenKind, text: String) {
            self.kind = kind
            self.text = text
        }
    }
    public struct OutputContext: Sendable {
        public private(set) var tokens: [OutputToken] = []
        private var buffer: String = ""
        public init() {}
        public var text: String { buffer }
        public var isEmpty: Bool { buffer.isEmpty }
        public mutating func token(_ kind: OutputTokenKind, _ text: String) {
            if !text.isEmpty {
                buffer.append(text)
                tokens.append(.init(kind: kind, text: text))
            }
        }
        public mutating func append(_ text: String) { token(.plainText, text) }
        public mutating func mnemonic(_ text: String) { token(.mnemonic, text) }
        public mutating func registerName(_ text: String) { token(.register, text) }
        public mutating func symbol(_ text: String) { token(.symbol, text) }
        public mutating func keyword(_ text: String) { token(.keyword, text) }
        public mutating func comment(_ text: String) { token(.comment, text) }
        public mutating func number(_ text: String) { token(.number, text) }
        public mutating func operatorSymbol(_ text: String) { token(.operatorSymbol, text) }
        public mutating func punctuation(_ text: String) { token(.punctuation, text) }
        public mutating func whitespace(_ text: String = " ") { token(.whitespace, text) }
        public mutating func stringLiteral(_ text: String, quote: Character = "\"") {
            punctuation(String(quote))
            token(.stringLiteral, text)
            punctuation(String(quote))
        }
        public mutating func immediate(_ value: Int64, radix: Int = 16) throws(IDAError) {
            guard [2, 8, 10, 16].contains(radix) else {
                throw IDAError(category: .validation, message: "Immediate radix must be 2, 8, 10, or 16")
            }
            let prefix = radix == 16 ? "0x" : radix == 8 ? "0" : radix == 2 ? "0b" : ""
            token(
                .immediate,
                prefix + (radix == 10 ? String(value) : String(UInt64(bitPattern: value), radix: radix)))
        }
        public mutating func address(_ address: Address) {
            token(.address, "0x" + String(address, radix: 16))
        }
        public mutating func character(_ character: Character) {
            let text = String(character)
            token(
                " \t\n\r".contains(character)
                    ? .whitespace : ",:;()[]{}".contains(character) ? .punctuation : .plainText, text)
        }
        public mutating func space() { whitespace() }
        public mutating func comma() { punctuation(",") }
        public mutating func clear() {
            tokens.removeAll()
            buffer.removeAll()
        }
        public mutating func take() -> String {
            let value = text
            clear()
            return value
        }
        public mutating func takeTokens() -> [OutputToken] {
            let value = tokens
            tokens.removeAll()
            return value
        }
        internal func write(to lease: UnsafeMutableRawPointer) throws(IDAError) {
            for token in tokens {
                let text = try LifecycleStrings([token.text])
                try bridgeCall("processor.output.token") {
                    idax_swift_module_output_token(lease, token.kind.rawValue, text[0], $0)
                }
            }
        }
    }
    public enum SwitchTableKind: Int32, Sendable { case dense, sparse, indirect, custom }
    public struct SwitchDescription: Sendable {
        public var kind: SwitchTableKind = .dense
        public var jumpTable: Address = .max
        public var valuesTable: Address = .max
        public var defaultTarget: Address = .max
        public var idiomStart: Address = .max
        public var elementBase: Address = 0
        public var lowCaseValue: Int64 = 0
        public var indirectLowCaseValue: Int64 = 0
        public var caseCount: UInt32 = 0
        public var jumpTableEntryCount: UInt32 = 0
        public var jumpElementSize: UInt8 = 0
        public var valueElementSize: UInt8 = 0
        public var shift: UInt8 = 0
        public var expressionRegister: Int32 = -1
        public var expressionDataType: UInt8 = 0
        public var hasDefault: Bool = false
        public var defaultInTable: Bool = false
        public var valuesSigned: Bool = false
        public var subtractValues: Bool = false
        public var selfRelative: Bool = false
        public var inverted: Bool = false
        public var userDefined: Bool = false
        public init() {}
        internal var native: IdaxSwiftSwitch {
            var value = IdaxSwiftSwitch()
            value.kind = kind.rawValue
            value.jump_table = jumpTable
            value.values_table = valuesTable
            value.default_target = defaultTarget
            value.idiom_start = idiomStart
            value.element_base = elementBase
            value.low_case_value = lowCaseValue
            value.indirect_low_case_value = indirectLowCaseValue
            value.case_count = caseCount
            value.jump_table_entry_count = jumpTableEntryCount
            value.jump_element_size = jumpElementSize
            value.value_element_size = valueElementSize
            value.shift = shift
            value.expression_register = expressionRegister
            value.expression_data_type = expressionDataType
            value.has_default = hasDefault ? 1 : 0
            value.default_in_table = defaultInTable ? 1 : 0
            value.values_signed = valuesSigned ? 1 : 0
            value.subtract_values = subtractValues ? 1 : 0
            value.self_relative = selfRelative ? 1 : 0
            value.inverted = inverted ? 1 : 0
            value.user_defined = userDefined ? 1 : 0
            return value
        }
        internal init(_ value: IdaxSwiftSwitch) throws(IDAError) {
            guard let kind = SwitchTableKind(rawValue: value.kind) else {
                throw IDAError(category: .unsupported, message: "Unknown switch table kind")
            }
            self.kind = kind
            jumpTable = value.jump_table
            valuesTable = value.values_table
            defaultTarget = value.default_target
            idiomStart = value.idiom_start
            elementBase = value.element_base
            lowCaseValue = value.low_case_value
            indirectLowCaseValue = value.indirect_low_case_value
            caseCount = value.case_count
            jumpTableEntryCount = value.jump_table_entry_count
            jumpElementSize = value.jump_element_size
            valueElementSize = value.value_element_size
            shift = value.shift
            expressionRegister = value.expression_register
            expressionDataType = value.expression_data_type
            hasDefault = value.has_default != 0
            defaultInTable = value.default_in_table != 0
            valuesSigned = value.values_signed != 0
            subtractValues = value.subtract_values != 0
            selfRelative = value.self_relative != 0
            inverted = value.inverted != 0
            userDefined = value.user_defined != 0
        }
    }
    public enum SwitchDetection: Sendable { case notImplemented, notSwitch, found(SwitchDescription) }
    public struct SwitchCase: Sendable {
        public var values: [Int64]
        public var target: Address
        public init(values: [Int64], target: Address) {
            self.values = values
            self.target = target
        }
    }
    public static func exportModule(_ module: any ProcessorModule) throws(IDAError) {
        let callbacks = callbackDescriptor { event, reply in
            func lease() throws(IDAError) -> UnsafeMutableRawPointer {
                try requireLifecycleHandle(event.lease, "processor.callback")
            }
            switch event.kind {
            case 200: try module.information.write(to: lease())
            case 201: try module.analyzeWithDetails(at: event.address).write(to: lease())
            case 202: reply.pointee.decision = try module.emulate(at: event.address).rawValue
            case 203: try module.outputInstruction(at: event.address)
            case 204:
                reply.pointee.decision = try module.outputOperand(at: event.address, index: event.number)
                    .rawValue
            case 205, 206, 207:
                var output = OutputContext()
                if event.kind == 205 {
                    reply.pointee.decision = try module.outputMnemonic(at: event.address, output: &output)
                        .rawValue
                } else if event.kind == 206 {
                    reply.pointee.decision = try module.outputInstruction(at: event.address, output: &output)
                        .rawValue
                } else {
                    reply.pointee.decision = try module.outputOperand(
                        at: event.address, index: event.number, output: &output
                    ).rawValue
                }
                try output.write(to: lease())
            case 208: try module.newFile(try borrowCString(event.text, "processor.filename"))
            case 209: try module.oldFile(try borrowCString(event.text, "processor.filename"))
            case 210: reply.pointee.decision = try module.isCall(at: event.address)
            case 211: reply.pointee.decision = try module.isReturn(at: event.address)
            case 212: reply.pointee.decision = try module.mayBeFunction(at: event.address)
            case 213:
                reply.pointee.decision = try module.isSaneInstruction(
                    at: event.address, noCodeReferences: event.flag != 0)
            case 214: reply.pointee.decision = try module.isIndirectJump(at: event.address)
            case 215:
                reply.pointee.decision = try module.isBasicBlockEnd(
                    at: event.address, callInstructionStopsBlock: event.flag != 0)
            case 216: reply.pointee.decision = try module.createFunctionFrame(at: event.address) ? 1 : 0
            case 217:
                reply.pointee.decision = try module.adjustFunctionBounds(
                    start: event.address, maximumEnd: event.secondary_address, suggestedResult: event.number)
            case 218: reply.pointee.decision = try module.analyzeFunctionProlog(at: event.address) ? 1 : 0
            case 219:
                if let delta = try module.stackPointerDelta(at: event.address) {
                    reply.pointee.decision = 1
                    reply.pointee.integer = delta
                }
            case 220: reply.pointee.decision = try module.returnAddressSize(at: event.address)
            case 221:
                switch try module.detectSwitch(at: event.address) {
                case .notImplemented: break
                case .notSwitch: reply.pointee.decision = -1
                case .found(let description):
                    var value = description.native
                    let context = try lease()
                    try bridgeCall("processor.switch") { idax_swift_module_switch(context, 1, &value, $0) }
                    reply.pointee.decision = 1
                }
            case 222, 223:
                let context = try lease()
                var value = IdaxSwiftSwitch()
                try bridgeCall("processor.switch") { idax_swift_module_switch(context, 0, &value, $0) }
                let description = try SwitchDescription(value)
                if event.kind == 222 {
                    if let cases = try module.calculateSwitchCases(
                        at: event.address, description: description)
                    {
                        for item in cases {
                            try bridgeCall("processor.switchCase") { error in
                                item.values.withUnsafeBufferPointer {
                                    idax_swift_module_switch_case(
                                        context, $0.baseAddress, $0.count, item.target, error)
                                }
                            }
                        }
                        reply.pointee.decision = 1
                    }
                } else {
                    reply.pointee.decision =
                        try module.createSwitchReferences(at: event.address, description: description) ? 1 : 0
                }
            default: throw IDAError(category: .unsupported, message: "Unknown processor callback")
            }
        }
        try bridgeCall("module.exportProcessor") { idax_swift_module_publish(2, callbacks, $0) }
    }
}
public protocol ProcessorModule: AnyObject {
    var information: Processor.Information { get }
    func analyze(at address: Address) throws(IDAError) -> Int32
    func analyzeWithDetails(at address: Address) throws(IDAError) -> Processor.AnalyzeDetails
    func emulate(at address: Address) throws(IDAError) -> Processor.EmulateResult
    func outputInstruction(at address: Address) throws(IDAError)
    func outputOperand(at address: Address, index: Int32) throws(IDAError) -> Processor.OutputOperandResult
    func outputMnemonic(at address: Address, output: inout Processor.OutputContext) throws(IDAError)
        -> Processor.OutputInstructionResult
    func outputInstruction(at address: Address, output: inout Processor.OutputContext) throws(IDAError)
        -> Processor.OutputInstructionResult
    func outputOperand(at address: Address, index: Int32, output: inout Processor.OutputContext)
        throws(IDAError) -> Processor.OutputOperandResult
    func newFile(_ filename: String) throws(IDAError)
    func oldFile(_ filename: String) throws(IDAError)
    func isCall(at address: Address) throws(IDAError) -> Int32
    func isReturn(at address: Address) throws(IDAError) -> Int32
    func mayBeFunction(at address: Address) throws(IDAError) -> Int32
    func isSaneInstruction(at address: Address, noCodeReferences: Bool) throws(IDAError) -> Int32
    func isIndirectJump(at address: Address) throws(IDAError) -> Int32
    func isBasicBlockEnd(at address: Address, callInstructionStopsBlock: Bool) throws(IDAError) -> Int32
    func createFunctionFrame(at address: Address) throws(IDAError) -> Bool
    func adjustFunctionBounds(start: Address, maximumEnd: Address, suggestedResult: Int32) throws(IDAError)
        -> Int32
    func analyzeFunctionProlog(at address: Address) throws(IDAError) -> Bool
    func stackPointerDelta(at address: Address) throws(IDAError) -> Int64?
    func returnAddressSize(at address: Address) throws(IDAError) -> Int32
    func detectSwitch(at address: Address) throws(IDAError) -> Processor.SwitchDetection
    func calculateSwitchCases(at address: Address, description: Processor.SwitchDescription) throws(IDAError)
        -> [Processor.SwitchCase]?
    func createSwitchReferences(at address: Address, description: Processor.SwitchDescription)
        throws(IDAError) -> Bool
}
extension ProcessorModule {
    public func analyzeWithDetails(at address: Address) throws(IDAError) -> Processor.AnalyzeDetails {
        .init(size: try analyze(at: address))
    }
    public func outputInstruction(at address: Address) throws(IDAError) {}
    public func outputOperand(at address: Address, index: Int32) throws(IDAError)
        -> Processor.OutputOperandResult
    { .notImplemented }
    public func outputMnemonic(at address: Address, output: inout Processor.OutputContext) throws(IDAError)
        -> Processor.OutputInstructionResult
    { .notImplemented }
    public func outputInstruction(at address: Address, output: inout Processor.OutputContext) throws(IDAError)
        -> Processor.OutputInstructionResult
    {
        try outputInstruction(at: address)
        return .notImplemented
    }
    public func outputOperand(at address: Address, index: Int32, output: inout Processor.OutputContext)
        throws(IDAError) -> Processor.OutputOperandResult
    { try outputOperand(at: address, index: index) }
    public func newFile(_ filename: String) throws(IDAError) {}
    public func oldFile(_ filename: String) throws(IDAError) {}
    public func isCall(at address: Address) throws(IDAError) -> Int32 { 0 }
    public func isReturn(at address: Address) throws(IDAError) -> Int32 { 0 }
    public func mayBeFunction(at address: Address) throws(IDAError) -> Int32 { 0 }
    public func isSaneInstruction(at address: Address, noCodeReferences: Bool) throws(IDAError) -> Int32 { 0 }
    public func isIndirectJump(at address: Address) throws(IDAError) -> Int32 { 0 }
    public func isBasicBlockEnd(at address: Address, callInstructionStopsBlock: Bool) throws(IDAError)
        -> Int32
    { 0 }
    public func createFunctionFrame(at address: Address) throws(IDAError) -> Bool { false }
    public func adjustFunctionBounds(start: Address, maximumEnd: Address, suggestedResult: Int32)
        throws(IDAError) -> Int32
    { suggestedResult }
    public func analyzeFunctionProlog(at address: Address) throws(IDAError) -> Bool { false }
    public func stackPointerDelta(at address: Address) throws(IDAError) -> Int64? { nil }
    public func returnAddressSize(at address: Address) throws(IDAError) -> Int32 { 0 }
    public func detectSwitch(at address: Address) throws(IDAError) -> Processor.SwitchDetection {
        .notImplemented
    }
    public func calculateSwitchCases(at address: Address, description: Processor.SwitchDescription)
        throws(IDAError) -> [Processor.SwitchCase]?
    { nil }
    public func createSwitchReferences(at address: Address, description: Processor.SwitchDescription)
        throws(IDAError) -> Bool
    { false }
}
