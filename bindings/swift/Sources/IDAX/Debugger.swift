internal import CIDAX

/// Debugger control, copied runtime metadata, and owned callback registrations.
public enum Debugger {
    public enum ProcessState: Sendable { case noProcess, running, suspended }
    public struct Backend: Sendable {
        public var name, displayName: String
        public var remote, supportsAppcall, supportsAttach, loaded: Bool
        public init(name: String = "", displayName: String = "", remote: Bool = false,
                    supportsAppcall: Bool = false, supportsAttach: Bool = false, loaded: Bool = false) {
            self.name = name
            self.displayName = displayName
            self.remote = remote
            self.supportsAppcall = supportsAppcall
            self.supportsAttach = supportsAttach
            self.loaded = loaded
        }
        internal init(_ raw: IdaxBackendInfo) throws(IDAError) {
            name = try borrowCString(raw.name, "debugger.backend.name")
            displayName = try borrowCString(raw.display_name, "debugger.backend.displayName")
            remote = raw.remote != 0
            supportsAppcall = raw.supports_appcall != 0
            supportsAttach = raw.supports_attach != 0
            loaded = raw.loaded != 0
        }
    }
    public struct Thread: Sendable {
        public var identifier: Int32
        public var name: String
        public var isCurrent: Bool
        public init(identifier: Int32 = 0, name: String = "", isCurrent: Bool = false) {
            self.identifier = identifier
            self.name = name
            self.isCurrent = isCurrent
        }
    }
    public struct Register: Sendable {
        public var name: String
        public var readOnly, instructionPointer, stackPointer, framePointer, mayContainAddress,
            customFormat: Bool
        public init(name: String = "", readOnly: Bool = false, instructionPointer: Bool = false,
                    stackPointer: Bool = false, framePointer: Bool = false,
                    mayContainAddress: Bool = false, customFormat: Bool = false) {
            self.name = name
            self.readOnly = readOnly
            self.instructionPointer = instructionPointer
            self.stackPointer = stackPointer
            self.framePointer = framePointer
            self.mayContainAddress = mayContainAddress
            self.customFormat = customFormat
        }
    }
    public static func availableBackends() throws(IDAError) -> [Backend] {
        try requireRuntimeThread("debugger.availableBackends")
        var pointer: UnsafeMutablePointer<IdaxBackendInfo>?
        var count = 0
        try checkStatus(idax_debugger_available_backends(&pointer, &count), "debugger.availableBackends")
        defer {
            if let pointer {
                for index in 0..<count { idax_backend_info_free(pointer.advanced(by: index)) }
                idax_free_bytes(UnsafeMutableRawPointer(pointer).assumingMemoryBound(to: UInt8.self))
            }
        }
        var result: [Backend] = []
        for value in try checkedBuffer(pointer, count: count, "debugger.availableBackends") {
            result.append(try Backend(value))
        }
        return result
    }
    public static func currentBackend() throws(IDAError) -> Backend {
        try requireRuntimeThread("debugger.currentBackend")
        var value = IdaxBackendInfo()
        defer { idax_backend_info_free(&value) }
        try checkStatus(idax_debugger_current_backend(&value), "debugger.currentBackend")
        return try Backend(value)
    }
    public static func loadBackend(_ name: String, remote: Bool = false) throws(IDAError) {
        try requireRuntimeThread("debugger.loadBackend")
        let text = try LifecycleStrings([name])
        try checkStatus(idax_debugger_load_backend(text[0], remote ? 1 : 0), "debugger.loadBackend")
    }
    public static func start(path: String = "", arguments: String = "", workingDirectory: String = "")
        throws(IDAError)
    {
        try requireRuntimeThread("debugger.start")
        let text = try LifecycleStrings([path, arguments, workingDirectory])
        try checkStatus(idax_debugger_start(text[0], text[1], text[2]), "debugger.start")
    }
    public static func requestStart(path: String = "", arguments: String = "", workingDirectory: String = "")
        throws(IDAError)
    {
        try requireRuntimeThread("debugger.requestStart")
        let text = try LifecycleStrings([path, arguments, workingDirectory])
        try checkStatus(idax_debugger_request_start(text[0], text[1], text[2]), "debugger.requestStart")
    }
    public static func state() throws(IDAError) -> ProcessState {
        let state = try withOutput("debugger.state", initial: Int32(0)) { idax_debugger_state($0) }
        switch state {
        case 0: return .noProcess
        case 1: return .running
        case 2: return .suspended
        default: throw IDAError(category: .unsupported, message: "Unknown process state")
        }
    }
    public static func registerValue(_ name: String) throws(IDAError) -> UInt64 {
        let text = try LifecycleStrings([name])
        return try withOutput("debugger.registerValue", initial: UInt64(0)) {
            idax_debugger_register_value(text[0], $0)
        }
    }
    public static func setRegister(_ name: String, value: UInt64) throws(IDAError) {
        try requireRuntimeThread("debugger.setRegister")
        let text = try LifecycleStrings([name])
        try checkStatus(idax_debugger_set_register(text[0], value), "debugger.setRegister")
    }
    public static func readMemory(at address: Address, size: UInt64) throws(IDAError) -> [UInt8] {
        try requireRuntimeThread("debugger.readMemory")
        var bytes: UnsafeMutablePointer<UInt8>?
        var count = 0
        try checkStatus(idax_debugger_read_memory(address, size, &bytes, &count), "debugger.readMemory")
        defer { idax_free_bytes(bytes) }
        return Array(try checkedBuffer(bytes, count: count, "debugger.readMemory"))
    }
    public static func writeMemory(at address: Address, bytes: [UInt8]) throws(IDAError) {
        try requireRuntimeThread("debugger.writeMemory")
        try checkStatus(
            bytes.withUnsafeBufferPointer { idax_debugger_write_memory(address, $0.baseAddress, $0.count) },
            "debugger.writeMemory")
    }
    public static func threads() throws(IDAError) -> [Thread] {
        try requireRuntimeThread("debugger.threads")
        var pointer: UnsafeMutablePointer<IdaxThreadInfo>?
        var count = 0
        try checkStatus(idax_debugger_threads(&pointer, &count), "debugger.threads")
        defer {
            if let pointer {
                for i in 0..<count { idax_thread_info_free(pointer.advanced(by: i)) }
                idax_free_bytes(UnsafeMutableRawPointer(pointer).assumingMemoryBound(to: UInt8.self))
            }
        }
        var result: [Thread] = []
        for value in try checkedBuffer(pointer, count: count, "debugger.threads") {
            result.append(
                Thread(
                    identifier: value.id, name: try borrowCString(value.name, "debugger.thread.name"),
                    isCurrent: value.is_current != 0))
        }
        return result
    }
    public static func registerInformation(_ name: String) throws(IDAError) -> Register {
        try requireRuntimeThread("debugger.registerInformation")
        let text = try LifecycleStrings([name])
        var raw = IdaxDebuggerRegisterInfo()
        defer { idax_debugger_register_info_free(&raw) }
        try checkStatus(idax_debugger_register_info(text[0], &raw), "debugger.registerInformation")
        return Register(
            name: try borrowCString(raw.name, "debugger.register.name"), readOnly: raw.read_only != 0,
            instructionPointer: raw.instruction_pointer != 0, stackPointer: raw.stack_pointer != 0,
            framePointer: raw.frame_pointer != 0, mayContainAddress: raw.may_contain_address != 0,
            customFormat: raw.custom_format != 0)
    }
    public static func isRequestRunning() throws(IDAError) -> Bool {
        try requireRuntimeThread("debugger.isRequestRunning")
        return idax_debugger_is_request_running() != 0
    }
    public static func detach() throws(IDAError) {
        try requireRuntimeThread("debugger.detach")
        try checkStatus(idax_debugger_detach(), "debugger.detach")
    }
    public static func terminate() throws(IDAError) {
        try requireRuntimeThread("debugger.terminate")
        try checkStatus(idax_debugger_terminate(), "debugger.terminate")
    }
    public static func suspend() throws(IDAError) {
        try requireRuntimeThread("debugger.suspend")
        try checkStatus(idax_debugger_suspend(), "debugger.suspend")
    }
    public static func resume() throws(IDAError) {
        try requireRuntimeThread("debugger.resume")
        try checkStatus(idax_debugger_resume(), "debugger.resume")
    }
    public static func stepInto() throws(IDAError) {
        try requireRuntimeThread("debugger.stepInto")
        try checkStatus(idax_debugger_step_into(), "debugger.stepInto")
    }
    public static func stepOver() throws(IDAError) {
        try requireRuntimeThread("debugger.stepOver")
        try checkStatus(idax_debugger_step_over(), "debugger.stepOver")
    }
    public static func stepOut() throws(IDAError) {
        try requireRuntimeThread("debugger.stepOut")
        try checkStatus(idax_debugger_step_out(), "debugger.stepOut")
    }
    public static func runRequests() throws(IDAError) {
        try requireRuntimeThread("debugger.runRequests")
        try checkStatus(idax_debugger_run_requests(), "debugger.runRequests")
    }
    public static func requestSuspend() throws(IDAError) {
        try requireRuntimeThread("debugger.requestSuspend")
        try checkStatus(idax_debugger_request_suspend(), "debugger.requestSuspend")
    }
    public static func requestResume() throws(IDAError) {
        try requireRuntimeThread("debugger.requestResume")
        try checkStatus(idax_debugger_request_resume(), "debugger.requestResume")
    }
    public static func requestStepInto() throws(IDAError) {
        try requireRuntimeThread("debugger.requestStepInto")
        try checkStatus(idax_debugger_request_step_into(), "debugger.requestStepInto")
    }
    public static func requestStepOver() throws(IDAError) {
        try requireRuntimeThread("debugger.requestStepOver")
        try checkStatus(idax_debugger_request_step_over(), "debugger.requestStepOver")
    }
    public static func requestStepOut() throws(IDAError) {
        try requireRuntimeThread("debugger.requestStepOut")
        try checkStatus(idax_debugger_request_step_out(), "debugger.requestStepOut")
    }
    public static func attach(_ processID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.attach")
        try checkStatus(idax_debugger_attach(processID), "debugger.attach")
    }
    public static func runTo(_ address: Address) throws(IDAError) {
        try requireRuntimeThread("debugger.runTo")
        try checkStatus(idax_debugger_run_to(address), "debugger.runTo")
    }
    public static func requestRunTo(_ address: Address) throws(IDAError) {
        try requireRuntimeThread("debugger.requestRunTo")
        try checkStatus(idax_debugger_request_run_to(address), "debugger.requestRunTo")
    }
    public static func addBreakpoint(_ address: Address) throws(IDAError) {
        try requireRuntimeThread("debugger.addBreakpoint")
        try checkStatus(idax_debugger_add_breakpoint(address), "debugger.addBreakpoint")
    }
    public static func removeBreakpoint(_ address: Address) throws(IDAError) {
        try requireRuntimeThread("debugger.removeBreakpoint")
        try checkStatus(idax_debugger_remove_breakpoint(address), "debugger.removeBreakpoint")
    }
    public static func selectThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.selectThread")
        try checkStatus(idax_debugger_select_thread(threadID), "debugger.selectThread")
    }
    public static func requestSelectThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.requestSelectThread")
        try checkStatus(idax_debugger_request_select_thread(threadID), "debugger.requestSelectThread")
    }
    public static func suspendThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.suspendThread")
        try checkStatus(idax_debugger_suspend_thread(threadID), "debugger.suspendThread")
    }
    public static func requestSuspendThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.requestSuspendThread")
        try checkStatus(idax_debugger_request_suspend_thread(threadID), "debugger.requestSuspendThread")
    }
    public static func resumeThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.resumeThread")
        try checkStatus(idax_debugger_resume_thread(threadID), "debugger.resumeThread")
    }
    public static func requestResumeThread(_ threadID: Int32) throws(IDAError) {
        try requireRuntimeThread("debugger.requestResumeThread")
        try checkStatus(idax_debugger_request_resume_thread(threadID), "debugger.requestResumeThread")
    }
    public static func instructionPointer() throws(IDAError) -> Address {
        try withOutput("debugger.instructionPointer", initial: UInt64(0)) {
            idax_debugger_instruction_pointer($0)
        }
    }
    public static func stackPointer() throws(IDAError) -> Address {
        try withOutput("debugger.stackPointer", initial: UInt64(0)) { idax_debugger_stack_pointer($0) }
    }
    public static func threadCount() throws(IDAError) -> Int {
        try withOutput("debugger.threadCount", initial: Int(0)) { idax_debugger_thread_count($0) }
    }
    public static func currentThreadId() throws(IDAError) -> Int32 {
        try withOutput("debugger.currentThreadId", initial: Int32(0)) { idax_debugger_current_thread_id($0) }
    }
    public static func isIntegerRegister(_ name: String) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([name])
        return try withOutput("debugger.isIntegerRegister", initial: Int32(0)) {
            idax_debugger_is_integer_register(text[0], $0)
        } != 0
    }
    public static func isFloatingRegister(_ name: String) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([name])
        return try withOutput("debugger.isFloatingRegister", initial: Int32(0)) {
            idax_debugger_is_floating_register(text[0], $0)
        } != 0
    }
    public static func isCustomRegister(_ name: String) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([name])
        return try withOutput("debugger.isCustomRegister", initial: Int32(0)) {
            idax_debugger_is_custom_register(text[0], $0)
        } != 0
    }
    public static func requestAttach(_ processID: Int32, eventID: Int32 = -1) throws(IDAError) {
        try requireRuntimeThread("debugger.requestAttach")
        try checkStatus(idax_debugger_request_attach(processID, eventID), "debugger.requestAttach")
    }
    public static func hasBreakpoint(at address: Address) throws(IDAError) -> Bool {
        try withOutput("debugger.hasBreakpoint", initial: Int32(0)) {
            idax_debugger_has_breakpoint(address, $0)
        } != 0
    }
    public static func threadID(at index: Int) throws(IDAError) -> Int32 {
        guard index >= 0 else { throw IDAError(category: .validation, message: "Negative thread index") }
        return try withOutput("debugger.threadID", initial: Int32(0)) {
            idax_debugger_thread_id_at(index, $0)
        }
    }
    public static func threadName(at index: Int) throws(IDAError) -> String {
        guard index >= 0 else { throw IDAError(category: .validation, message: "Negative thread index") }
        return try withStringOutput("debugger.threadName") { idax_debugger_thread_name_at(index, $0) }
    }
    public enum AppcallValue: Sendable, Equatable {
        case signedInteger(Int64), unsignedInteger(UInt64), floatingPoint(Double), string(String), address(
            Address), boolean(Bool)
    }
    public struct AppcallOptions: Sendable {
        public var threadID: Int32?
        public var manual, includeDebugEvent: Bool
        public var timeoutMilliseconds: UInt32?
        public init(
            threadID: Int32? = nil, manual: Bool = false, includeDebugEvent: Bool = false,
            timeoutMilliseconds: UInt32? = nil
        ) {
            self.threadID = threadID
            self.manual = manual
            self.includeDebugEvent = includeDebugEvent
            self.timeoutMilliseconds = timeoutMilliseconds
        }
        internal var native: IdaxDebuggerAppcallOptions {
            IdaxDebuggerAppcallOptions(
                has_thread_id: threadID == nil ? 0 : 1, thread_id: threadID ?? 0, manual: manual ? 1 : 0,
                include_debug_event: includeDebugEvent ? 1 : 0,
                has_timeout_milliseconds: timeoutMilliseconds == nil ? 0 : 1,
                timeout_milliseconds: timeoutMilliseconds ?? 0)
        }
    }
    public struct AppcallRequest {
        public var functionAddress: Address
        public var functionType: TypeInfo
        public var arguments: [AppcallValue]
        public var options: AppcallOptions
        public init(
            functionAddress: Address, functionType: TypeInfo, arguments: [AppcallValue] = [],
            options: AppcallOptions = .init()
        ) {
            self.functionAddress = functionAddress
            self.functionType = functionType
            self.arguments = arguments
            self.options = options
        }
    }
    public struct AppcallResult: Sendable {
        public var returnValue: AppcallValue
        public var diagnostics: String
        public init(returnValue: AppcallValue, diagnostics: String = "") {
            self.returnValue = returnValue
            self.diagnostics = diagnostics
        }
    }
    public static func appcall(_ request: AppcallRequest, executor: String? = nil) throws(IDAError)
        -> AppcallResult
    {
        return try request.functionType.withHandle("debugger.appcall") {
            (type) throws(IDAError) -> AppcallResult in
            let text = try LifecycleStrings(executor.map { [$0] } ?? [])
            var arguments: [IdaxDebuggerAppcallValue] = []
            defer { for i in arguments.indices { idax_debugger_appcall_value_free(&arguments[i]) } }
            for value in request.arguments { arguments.append(try nativeAppcallValue(value)) }
            var raw = IdaxDebuggerAppcallRequest(
                function_address: request.functionAddress, function_type: type, arguments: nil,
                argument_count: arguments.count, options: request.options.native)
            var result = IdaxDebuggerAppcallResult()
            defer { idax_debugger_appcall_result_free(&result) }
            try bridgeCall("debugger.appcall") { error in
                arguments.withUnsafeMutableBufferPointer { buffer in
                    raw.arguments = buffer.baseAddress
                    return idax_swift_debugger_appcall(executor == nil ? nil : text[0], &raw, &result, error)
                }
            }
            return AppcallResult(
                returnValue: try swiftAppcallValue(result.return_value),
                diagnostics: try borrowCString(result.diagnostics, "debugger.appcall.diagnostics"))
        }
    }
    public static func cleanupAppcall(threadID: Int32? = nil) throws(IDAError) {
        try requireRuntimeThread("debugger.cleanupAppcall")
        try checkStatus(
            idax_debugger_cleanup_appcall(threadID == nil ? 0 : 1, threadID ?? 0), "debugger.cleanupAppcall")
    }
    public static func registerExecutor(
        name: String, execute: @escaping (AppcallRequest) throws(IDAError) -> AppcallResult
    ) throws(IDAError) -> Registration {
        let text = try LifecycleStrings([name])
        let context = Unmanaged.passRetained(ExecutorCallback(execute)).toOpaque()
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("debugger.registerExecutor") {
            idax_swift_executor_register(text[0], context, executorInvoke, executorDestroy, &handle, $0)
        }
        return Registration(owning: try requireLifecycleHandle(handle, "debugger.registerExecutor"))
    }
    public enum EventKind: CaseIterable, Sendable {
        case processStarted, processExited, processSuspended, breakpointHit, trace, exception, threadStarted,
            threadExited, libraryLoaded, libraryUnloaded, breakpointChanged
    }
    public struct Change: Sendable {
        public let kind: EventKind
        public let address: Address
        public let size: UInt64
        public let name: String
        public let threadID: Int32
        public let exitCode: Int32
        public let exceptionCode: UInt32
        public let canContinue: Bool
        public let breakpointChange: BreakpointChange?
    }
    public enum BreakpointChange: Sendable { case added, removed, changed }
    /// Return true from trace callbacks to suppress the native trace log entry.
    public static func subscribe(to kind: EventKind, handler: @escaping (Change) throws(IDAError) -> Bool)
        throws(IDAError) -> Registration
    {
        let callbacks = callbackDescriptor { raw, reply in
            let change = Change(
                kind: kind, address: raw.address, size: raw.size,
                name: try borrowCString(raw.text, "debugger.event.name"), threadID: raw.number,
                exitCode: kind == .processExited ? raw.number : raw.secondary_number,
                exceptionCode: raw.value, canContinue: raw.flag != 0,
                breakpointChange: kind == .breakpointChanged
                    ? (raw.number == 0 ? .added : raw.number == 1 ? .removed : .changed) : nil)
            reply.pointee.decision = try handler(change) ? 1 : 0
        }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("debugger.subscribe") {
            idax_swift_debugger_subscribe(
                Int32(EventKind.allCases.firstIndex(of: kind)!), callbacks, &handle, $0)
        }
        return Registration(owning: try requireLifecycleHandle(handle, "debugger.subscribe"))
    }
}
private func swiftAppcallValue(_ raw: IdaxDebuggerAppcallValue) throws(IDAError) -> Debugger.AppcallValue {
    switch raw.kind {
    case 0: return .signedInteger(raw.signed_value)
    case 1: return .unsignedInteger(raw.unsigned_value)
    case 2: return .floatingPoint(raw.floating_value)
    case 3: return .string(try borrowCString(raw.string_value, "appcall.string"))
    case 4: return .address(raw.address_value)
    case 5: return .boolean(raw.boolean_value != 0)
    default: throw IDAError(category: .unsupported, message: "Unknown appcall value kind")
    }
}
private func nativeAppcallValue(_ value: Debugger.AppcallValue) throws(IDAError) -> IdaxDebuggerAppcallValue {
    var raw = IdaxDebuggerAppcallValue()
    switch value {
    case .signedInteger(let value):
        raw.kind = 0
        raw.signed_value = value
    case .unsignedInteger(let value):
        raw.kind = 1
        raw.unsigned_value = value
    case .floatingPoint(let value):
        raw.kind = 2
        raw.floating_value = value
    case .string(let value):
        raw.kind = 3
        let text = try LifecycleStrings([value])
        try bridgeCall("appcall.string") { idax_swift_appcall_string(&raw, text[0], $0) }
    case .address(let value):
        raw.kind = 4
        raw.address_value = value
    case .boolean(let value):
        raw.kind = 5
        raw.boolean_value = value ? 1 : 0
    }
    return raw
}
private final class ExecutorCallback {
    let execute: (Debugger.AppcallRequest) throws(IDAError) -> Debugger.AppcallResult
    init(_ execute: @escaping (Debugger.AppcallRequest) throws(IDAError) -> Debugger.AppcallResult) {
        self.execute = execute
    }
}
private func executorDestroy(_ context: UnsafeMutableRawPointer?) {
    if let context { Unmanaged<ExecutorCallback>.fromOpaque(context).release() }
}
private func executorInvoke(
    _ context: UnsafeMutableRawPointer?, _ request: UnsafePointer<IdaxDebuggerAppcallRequest>?,
    _ output: UnsafeMutablePointer<IdaxDebuggerAppcallResult>?,
    _ failure: UnsafeMutablePointer<IdaxSwiftError>?
) -> Int32 {
    guard let context, let request, let output else { return -1 }
    do {
        let native = request.pointee
        var copy: UnsafeMutableRawPointer?
        try checkStatus(idax_type_clone(native.function_type, &copy), "appcall.functionType.copy")
        let type = try TypeInfo(owning: requireLifecycleHandle(copy, "appcall.functionType.copy"))
        let arguments = try checkedBuffer(native.arguments, count: native.argument_count, "appcall.arguments")
            .map { try swiftAppcallValue($0) }
        let options = Debugger.AppcallOptions(
            threadID: native.options.has_thread_id != 0 ? native.options.thread_id : nil,
            manual: native.options.manual != 0, includeDebugEvent: native.options.include_debug_event != 0,
            timeoutMilliseconds: native.options.has_timeout_milliseconds != 0
                ? native.options.timeout_milliseconds : nil)
        let result = try Unmanaged<ExecutorCallback>.fromOpaque(context).takeUnretainedValue().execute(
            Debugger.AppcallRequest(
                functionAddress: native.function_address, functionType: type, arguments: arguments,
                options: options))
        output.pointee.return_value = try nativeAppcallValue(result.returnValue)
        let diagnostics = try nativeAppcallValue(.string(result.diagnostics))
        output.pointee.diagnostics = diagnostics.string_value
        return 0
    } catch {
        writeCallbackError(
            (error as? IDAError) ?? IDAError(category: .internalError, message: String(describing: error)),
            to: failure)
        return -1
    }
}
