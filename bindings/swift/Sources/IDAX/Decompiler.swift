internal import CIDAX

internal func withDecompilerActivity<T>(_ operation: String, _ body: () throws(IDAError) -> T) throws(IDAError) -> T {
    try bridgeCall(operation) { idax_swift_runtime_begin_activity($0) }
    defer { idax_swift_runtime_end_activity() }
    return try body()
}

extension Decompiler {
    public struct GenerationOptions: Equatable, Sendable {
        public var maturity: MicrocodeMaturity
        public var analyzeCalls: Bool
        public init(maturity: MicrocodeMaturity = .preoptimized, analyzeCalls: Bool = false) {
            self.maturity = maturity; self.analyzeCalls = analyzeCalls
        }
    }
    public struct DecompileFailure: Equatable, Sendable {
        public var requestAddress: Address
        public var failureAddress: Address
        public var description: String
        public init(requestAddress: Address = badAddress, failureAddress: Address = badAddress, description: String = "") {
            self.requestAddress = requestAddress; self.failureAddress = failureAddress; self.description = description
        }
    }
    public struct CommentPosition: Equatable, Sendable {
        public let kind: CommentPositionKind
        private let value: Int64
        private init(kind: CommentPositionKind, value: Int64 = 0) { self.kind = kind; self.value = value }
        public init() { self.init(kind: .default) }
        public static let `default` = Self(kind: .default)
        public static let parenthesisOpen = Self(kind: .parenthesisOpen)
        public static let assembly = Self(kind: .assembly)
        public static let elseLine = Self(kind: .elseLine)
        public static let doLine = Self(kind: .doLine)
        public static let semicolon = Self(kind: .semicolon)
        public static let openBrace = Self(kind: .openBrace)
        public static let closeBrace = Self(kind: .closeBrace)
        public static let parenthesisClose = Self(kind: .parenthesisClose)
        public static let labelColon = Self(kind: .labelColon)
        public static let blockBefore = Self(kind: .blockBefore)
        public static let blockAfter = Self(kind: .blockAfter)
        public static let tryLine = Self(kind: .tryLine)
        public static func argument(_ index: Int) throws(IDAError) -> Self {
            guard (0...63).contains(index) else {
                throw IDAError(category: .validation, message: "Pseudocode comment argument index must be in [0, 63]")
            }
            return Self(kind: .argument, value: Int64(index))
        }
        public static func switchCase(_ value: Int64) throws(IDAError) -> Self {
            guard (-0x1fffffff...0x1fffffff).contains(value) else {
                throw IDAError(category: .validation, message: "Pseudocode switch-case comment value exceeds the supported range")
            }
            return Self(kind: .switchCase, value: value)
        }
        public var argumentIndex: Int? { kind == .argument ? Int(value) : nil }
        public var switchCaseValue: Int64? { kind == .switchCase ? value : nil }
        internal func native(_ operation: String) throws(IDAError) -> IdaxDecompilerCommentPosition {
            IdaxDecompilerCommentPosition(kind: kind.rawValue, value: value)
        }
        internal init(copying native: IdaxDecompilerCommentPosition, _ operation: String) throws(IDAError) {
            let kind = try checkedEnum(CommentPositionKind.self, native.kind, operation)
            switch kind {
            case .argument:
                guard let index = Int(exactly: native.value) else {
                    throw IDAError(category: .internalError, message: "Native comment argument index exceeds Swift Int", context: operation)
                }
                self = try Self.argument(index)
            case .switchCase: self = try Self.switchCase(native.value)
            default:
                guard native.value == 0 else { throw IDAError(category: .internalError, message: "Native comment position has an unexpected detail", context: operation) }
                self.init(kind: kind)
            }
        }
    }
    public struct AddressMapping: Equatable, Sendable {
        public var address: Address
        public var lineNumber: Int32
        public init(address: Address, lineNumber: Int32) { self.address = address; self.lineNumber = lineNumber }
    }
    /// Owns one explicit Hex-Rays plugin session on the runtime thread.
    public final class Session {
        internal let resource: NativeResource
        internal init(owning pointer: UnsafeMutableRawPointer) throws(IDAError) {
            resource = try NativeResource(taking: pointer, release: idax_swift_decompiler_session_free, operation: "Decompiler.initialize")
        }
        public func isValid() throws(IDAError) -> Bool {
            let pointer = try resource.pointer("Decompiler.Session.isValid")
            var output: Int32 = 0
            try bridgeCall("Decompiler.Session.isValid") { idax_swift_decompiler_session_valid(pointer, &output, $0) }
            return output != 0
        }
        public func close() throws(IDAError) {
            try bridgeCall("Decompiler.Session.close") { idax_swift_runtime_require_idle($0) }
            try resource.close("Decompiler.Session.close", using: idax_swift_decompiler_session_close)
        }
    }
    public static func initialize() throws(IDAError) -> Session {
        var output: UnsafeMutableRawPointer?
        try bridgeCall("Decompiler.initialize") { idax_swift_decompiler_initialize(&output, $0) }
        return try Session(owning: requireOwnedHandle(output, "Decompiler.initialize"))
    }
    public static func decompile(_ address: Address) throws(IDAError) -> Function {
        var failure: DecompileFailure?
        return try decompile(address, failure: &failure)
    }
    public static func decompile(_ address: Address, failure: inout DecompileFailure?) throws(IDAError) -> Function {
        try withDecompilerActivity("Decompiler.decompile") { () throws(IDAError) -> Function in
            var output: UnsafeMutableRawPointer?
            var details = IdaxSwiftDecompileFailure()
            var error = IdaxSwiftError()
            defer { idax_swift_decompile_failure_free(&details); idax_swift_error_free(&error); if let output { idax_decompiled_free(output) } }
            let status = idax_swift_decompile(address, &output, &details, &error)
            if status != 0 {
                failure = DecompileFailure(requestAddress: details.request_address, failureAddress: details.failure_address,
                    description: try borrowCString(details.description.map { UnsafePointer($0) }, "Decompiler.decompile"))
                try checkBridgeStatus(status, error, "Decompiler.decompile")
            }
            failure = nil
            let pointer = try requireOwnedHandle(output, "Decompiler.decompile")
            output = nil // NativeResource adoption consumes unconditionally.
            return try Function(owning: pointer)
        }
    }
    public static func generateMicrocode(_ functionAddress: Address, options: GenerationOptions = .init()) throws(IDAError) -> MicrocodeFunction {
        try withDecompilerActivity("Decompiler.generateMicrocode") { () throws(IDAError) -> MicrocodeFunction in
            var output: UnsafeMutablePointer<IdaxMicrocodeFunction>?
            defer { idax_decompiler_microcode_function_free(output) }
            try checkStatus(idax_decompiler_generate_microcode(functionAddress, options.maturity.rawValue, options.analyzeCalls ? 1 : 0, &output), "Decompiler.generateMicrocode")
            return try MicrocodeFunction(copying: requirePointee(output, "Decompiler.generateMicrocode"), "Decompiler.generateMicrocode")
        }
    }
    /// Owns a decompiled function; all native use is pinned against reentrant closure.
    public final class Function {
        internal let resource: DecompilerOwnedResource
        internal init(owning pointer: UnsafeMutableRawPointer) throws(IDAError) {
            resource = try DecompilerOwnedResource(taking: pointer, release: idax_decompiled_free, operation: "Decompiler.Function")
        }
        internal func withHandle<T>(_ operation: String, _ body: (UnsafeMutableRawPointer) throws(IDAError) -> T) throws(IDAError) -> T {
            try resource.withPinned(operation, body)
        }
        public func close() throws(IDAError) { try resource.close("Decompiler.Function.close") }
        public func retypeVariable(named name: String, type: TypeInfo) throws(IDAError) {
            let op = "Decompiler.Function.retypeVariable"; try validateCString(name, op)
            try type.withHandle(op) { (t) throws(IDAError) in
                try withHandle(op) { (h) throws(IDAError) in try bridgeCall(op) { error in name.withCString { idax_swift_decompiled_retype(h, $0, 0, t, error) } } }
            }
        }
        public func retypeVariable(at index: Int, type: TypeInfo) throws(IDAError) {
            let op = "Decompiler.Function.retypeVariable"; try requireNonnegative(index, op)
            try type.withHandle(op) { (t) throws(IDAError) in
                try withHandle(op) { (h) throws(IDAError) in try bridgeCall(op) { idax_swift_decompiled_retype(h, nil, index, t, $0) } }
            }
        }
        public func refresh() throws(IDAError) {
            try withHandle("Decompiler.Function.refresh") { (h) throws(IDAError) in
                try withDecompilerActivity("Decompiler.Function.refresh") { () throws(IDAError) in
                    try bridgeCall("Decompiler.Function.refresh") { idax_swift_decompiled_refresh(h, $0) }
                }
            }
        }
        public func microcodeLines() throws(IDAError) -> [String] {
            let op = "Decompiler.Function.microcodeLines"
            return try withHandle(op) { (h) throws(IDAError) -> [String] in
                var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?; var count = 0
                defer { idax_decompiled_lines_free(output, count) }
                try bridgeCall(op) { idax_swift_decompiled_microcode_lines(h, &output, &count, $0) }
                return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> String in try borrowCString(value.map { UnsafePointer($0) }, op) }
            }
        }
        public func addressMap() throws(IDAError) -> [AddressMapping] {
            let op = "Decompiler.Function.addressMap"
            return try withHandle(op) { (h) throws(IDAError) -> [AddressMapping] in
                var output: UnsafeMutablePointer<IdaxSwiftAddressMapping>?; var count = 0
                defer { idax_swift_free_array(output) }
                try bridgeCall(op) { idax_swift_decompiled_address_map(h, &output, &count, $0) }
                return try copyNativeValues(output, count: count, op) { AddressMapping(address: $0.address, lineNumber: $0.line_number) }
            }
        }
    }
    public final class LvarSnapshot {
        internal let resource: DecompilerOwnedResource
        public convenience init() throws(IDAError) {
            var output: UnsafeMutableRawPointer?
            try bridgeCall("Decompiler.LvarSnapshot.init") { idax_swift_lvar_snapshot_new(&output, $0) }
            try self.init(owning: requireOwnedHandle(output, "Decompiler.LvarSnapshot.init"))
        }
        internal init(owning pointer: UnsafeMutableRawPointer) throws(IDAError) {
            resource = try DecompilerOwnedResource(taking: pointer, release: idax_lvar_snapshot_free, operation: "Decompiler.LvarSnapshot")
        }
        public func copy() throws(IDAError) -> LvarSnapshot {
            let op = "Decompiler.LvarSnapshot.copy"; var output: UnsafeMutableRawPointer?
            let h = try resource.pointer(op); try bridgeCall(op) { idax_swift_lvar_snapshot_copy(h, &output, $0) }
            return try LvarSnapshot(owning: requireOwnedHandle(output, op))
        }
        public func isEmpty() throws(IDAError) -> Bool {
            let op = "Decompiler.LvarSnapshot.isEmpty"; let h = try resource.pointer(op)
            return try withOutput(op, initial: Int32(0)) { idax_lvar_snapshot_empty(h, $0) } != 0
        }
        public func savedVariableCount() throws(IDAError) -> Int {
            let op = "Decompiler.LvarSnapshot.savedVariableCount"; let h = try resource.pointer(op)
            return try withOutput(op, initial: Int(0)) { idax_lvar_snapshot_saved_variable_count(h, $0) }
        }
        public func close() throws(IDAError) { try resource.close("Decompiler.LvarSnapshot.close") }
    }
    public final class View {
        internal let resource: NativeResource
        internal init(owning pointer: UnsafeMutableRawPointer) throws(IDAError) {
            resource = try NativeResource(taking: pointer, release: idax_swift_decompiler_view_free, operation: "Decompiler.View")
        }
        public func functionAddress() throws(IDAError) -> Address {
            let op = "Decompiler.View.functionAddress"; let h = try resource.pointer(op); var output: Address = 0
            try bridgeCall(op) { idax_swift_decompiler_view_address(h, &output, $0) }; return output
        }
        public func functionName() throws(IDAError) -> String { try Names.get(address: functionAddress()) }
        public func decompiledFunction() throws(IDAError) -> Function { try Decompiler.decompile(functionAddress()) }
        public func close() throws(IDAError) { try resource.close("Decompiler.View.close") }
    }
    public static func view(forFunction address: Address) throws(IDAError) -> View {
        var output: UnsafeMutableRawPointer?; try bridgeCall("Decompiler.view") { idax_swift_decompiler_view(address, 0, &output, $0) }
        return try View(owning: requireOwnedHandle(output, "Decompiler.view"))
    }
    public static func currentView() throws(IDAError) -> View {
        var output: UnsafeMutableRawPointer?; try bridgeCall("Decompiler.currentView") { idax_swift_decompiler_view(0, 1, &output, $0) }
        return try View(owning: requireOwnedHandle(output, "Decompiler.currentView"))
    }
}

extension Decompiler {
    public static func isExpressionType(_ type: ItemType) -> Bool {
        type.rawValue >= ItemType.exprEmpty.rawValue && type.rawValue <= ItemType.exprLast.rawValue
    }
    public static func isStatementType(_ type: ItemType) -> Bool {
        type.rawValue > ItemType.exprLast.rawValue
    }
}
