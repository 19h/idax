internal import CIDAX
import Darwin

// MARK: - Value types

/// Thread information snapshot.
public struct ThreadInfo: Sendable {
    public let id: Int32
    public let name: String
    public let isCurrent: Bool
}

/// Debugger backend descriptor.
public struct BackendInfo: Sendable {
    public let name: String
    public let displayName: String
    public let remote: Bool
    public let supportsAppcall: Bool
    public let supportsAttach: Bool
    public let loaded: Bool
}

/// Debugger register descriptor.
public struct RegisterInfo: Sendable {
    public let name: String
    public let readOnly: Bool
    public let instructionPointer: Bool
    public let stackPointer: Bool
    public let framePointer: Bool
    public let mayContainAddress: Bool
    public let customFormat: Bool
}

/// Loaded module information from the debugger.
public struct ModuleInfo: Sendable {
    public let name: String
    public let base: Address
    public let size: UInt64
}

/// Exception information from the debugger.
public struct ExceptionInfo: Sendable {
    public let address: Address
    public let code: UInt32
    public let canContinue: Bool
    public let message: String
}

/// Debugger state value.
public struct DebuggerState: Sendable, Equatable {
    public let rawValue: Int32

    public init(rawValue: Int32) { self.rawValue = rawValue }
}

/// Breakpoint change kind.
public enum BreakpointChange: Int32, Sendable {
    case added = 0
    case removed = 1
    case changed = 2
}

// MARK: - Appcall types

/// Appcall value kind matching the C enum.
public enum AppcallValueKind: Int32, Sendable {
    case signedInteger = 0
    case unsignedInteger = 1
    case floatingPoint = 2
    case string = 3
    case address = 4
    case boolean = 5
}

/// Tagged union for appcall argument/return values.
public enum AppcallValue: Sendable {
    case signedInteger(Int64)
    case unsignedInteger(UInt64)
    case floatingPoint(Double)
    case string(String)
    case address(Address)
    case boolean(Bool)
}

/// Options for an appcall invocation.
public struct AppcallOptions: Sendable {
    public var threadId: Int32?
    public var manual: Bool
    public var includeDebugEvent: Bool
    public var timeoutMilliseconds: UInt32?

    public init(
        threadId: Int32? = nil,
        manual: Bool = false,
        includeDebugEvent: Bool = false,
        timeoutMilliseconds: UInt32? = nil
    ) {
        self.threadId = threadId
        self.manual = manual
        self.includeDebugEvent = includeDebugEvent
        self.timeoutMilliseconds = timeoutMilliseconds
    }
}

/// Result of an appcall invocation.
public struct AppcallResult: Sendable {
    public let returnValue: AppcallValue
    public let diagnostics: String
}

// MARK: - Appcall conversion helpers

/// Convert a Swift `AppcallValue` to the C struct representation.
private func makeCAppcallValue(_ value: AppcallValue) -> IdaxDebuggerAppcallValue {
    var c = IdaxDebuggerAppcallValue()
    switch value {
    case .signedInteger(let v):
        c.kind = AppcallValueKind.signedInteger.rawValue
        c.signed_value = v
    case .unsignedInteger(let v):
        c.kind = AppcallValueKind.unsignedInteger.rawValue
        c.unsigned_value = v
    case .floatingPoint(let v):
        c.kind = AppcallValueKind.floatingPoint.rawValue
        c.floating_value = v
    case .string(let v):
        c.kind = AppcallValueKind.string.rawValue
        c.string_value = strdup(v)
    case .address(let v):
        c.kind = AppcallValueKind.address.rawValue
        c.address_value = v
    case .boolean(let v):
        c.kind = AppcallValueKind.boolean.rawValue
        c.boolean_value = v ? 1 : 0
    }
    return c
}

/// Convert a C `IdaxDebuggerAppcallValue` to the Swift enum. Does not free the C value.
private func makeSwiftAppcallValue(_ c: IdaxDebuggerAppcallValue) -> AppcallValue {
    switch AppcallValueKind(rawValue: c.kind) {
    case .signedInteger:
        return .signedInteger(c.signed_value)
    case .unsignedInteger:
        return .unsignedInteger(c.unsigned_value)
    case .floatingPoint:
        return .floatingPoint(c.floating_value)
    case .string:
        let s = c.string_value.map { String(cString: $0) } ?? ""
        return .string(s)
    case .address:
        return .address(c.address_value)
    case .boolean:
        return .boolean(c.boolean_value != 0)
    case .none:
        return .signedInteger(c.signed_value)
    }
}

/// Convert `AppcallOptions` to the C struct.
private func makeCAppcallOptions(_ opts: AppcallOptions) -> IdaxDebuggerAppcallOptions {
    var c = IdaxDebuggerAppcallOptions()
    if let tid = opts.threadId {
        c.has_thread_id = 1
        c.thread_id = tid
    } else {
        c.has_thread_id = 0
    }
    c.manual = opts.manual ? 1 : 0
    c.include_debug_event = opts.includeDebugEvent ? 1 : 0
    if let timeout = opts.timeoutMilliseconds {
        c.has_timeout_milliseconds = 1
        c.timeout_milliseconds = timeout
    } else {
        c.has_timeout_milliseconds = 0
    }
    return c
}

// MARK: - DebuggerSubscription

/// RAII debugger event subscription token. Unsubscribes on deinit.
public struct DebuggerSubscription: ~Copyable, @unchecked Sendable {
    private let token: UInt64
    private let context: UnsafeMutableRawPointer

    init(token: UInt64, context: UnsafeMutableRawPointer) {
        self.token = token
        self.context = context
    }

    deinit {
        idax_debugger_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
    }

    public consuming func cancel() {
        idax_debugger_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
        discard self
    }
}

// MARK: - Callback boxes

private final class ProcessStartedBox {
    let handler: (ModuleInfo) -> Void
    init(handler: @escaping (ModuleInfo) -> Void) { self.handler = handler }
}

private final class ProcessExitedBox {
    let handler: (Int32) -> Void
    init(handler: @escaping (Int32) -> Void) { self.handler = handler }
}

private final class ProcessSuspendedBox {
    let handler: (Address) -> Void
    init(handler: @escaping (Address) -> Void) { self.handler = handler }
}

private final class BreakpointHitBox {
    let handler: (Int32, Address) -> Void
    init(handler: @escaping (Int32, Address) -> Void) { self.handler = handler }
}

private final class TraceBox {
    let handler: (Int32, Address) -> Bool
    init(handler: @escaping (Int32, Address) -> Bool) { self.handler = handler }
}

private final class ExceptionBox {
    let handler: (ExceptionInfo) -> Void
    init(handler: @escaping (ExceptionInfo) -> Void) { self.handler = handler }
}

private final class ThreadStartedBox {
    let handler: (Int32, String) -> Void
    init(handler: @escaping (Int32, String) -> Void) { self.handler = handler }
}

private final class ThreadExitedBox {
    let handler: (Int32, Int32) -> Void
    init(handler: @escaping (Int32, Int32) -> Void) { self.handler = handler }
}

private final class LibraryLoadedBox {
    let handler: (ModuleInfo) -> Void
    init(handler: @escaping (ModuleInfo) -> Void) { self.handler = handler }
}

private final class LibraryUnloadedBox {
    let handler: (String) -> Void
    init(handler: @escaping (String) -> Void) { self.handler = handler }
}

private final class BreakpointChangedBox {
    let handler: (BreakpointChange, Address) -> Void
    init(handler: @escaping (BreakpointChange, Address) -> Void) { self.handler = handler }
}

private final class AppcallExecutorBox {
    let callback: (Address, UnsafeMutableRawPointer?, [AppcallValue], AppcallOptions) -> AppcallResult?
    let cleanup: () -> Void
    init(
        callback: @escaping (Address, UnsafeMutableRawPointer?, [AppcallValue], AppcallOptions) -> AppcallResult?,
        cleanup: @escaping () -> Void
    ) {
        self.callback = callback
        self.cleanup = cleanup
    }
}

// MARK: - Trampolines

private func processStartedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    info: UnsafePointer<IdaxDebuggerModuleInfo>?
) {
    guard let ctx, let info else { return }
    let box = Unmanaged<ProcessStartedBox>.fromOpaque(ctx).takeUnretainedValue()
    let mi = ModuleInfo(
        name: borrowCString(info.pointee.name),
        base: info.pointee.base,
        size: info.pointee.size
    )
    box.handler(mi)
}

private func processExitedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    exitCode: Int32
) {
    guard let ctx else { return }
    let box = Unmanaged<ProcessExitedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(exitCode)
}

private func processSuspendedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    address: UInt64
) {
    guard let ctx else { return }
    let box = Unmanaged<ProcessSuspendedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(address)
}

private func breakpointHitTrampoline(
    ctx: UnsafeMutableRawPointer?,
    threadId: Int32,
    address: UInt64
) {
    guard let ctx else { return }
    let box = Unmanaged<BreakpointHitBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(threadId, address)
}

private func traceTrampoline(
    ctx: UnsafeMutableRawPointer?,
    threadId: Int32,
    ip: UInt64
) -> Int32 {
    guard let ctx else { return 0 }
    let box = Unmanaged<TraceBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.handler(threadId, ip) ? 1 : 0
}

private func exceptionTrampoline(
    ctx: UnsafeMutableRawPointer?,
    info: UnsafePointer<IdaxDebuggerExceptionInfo>?
) {
    guard let ctx, let info else { return }
    let box = Unmanaged<ExceptionBox>.fromOpaque(ctx).takeUnretainedValue()
    let ei = ExceptionInfo(
        address: info.pointee.ea,
        code: info.pointee.code,
        canContinue: info.pointee.can_continue != 0,
        message: borrowCString(info.pointee.message)
    )
    box.handler(ei)
}

private func threadStartedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    threadId: Int32,
    name: UnsafePointer<CChar>?
) {
    guard let ctx else { return }
    let box = Unmanaged<ThreadStartedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(threadId, borrowCString(name))
}

private func threadExitedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    threadId: Int32,
    exitCode: Int32
) {
    guard let ctx else { return }
    let box = Unmanaged<ThreadExitedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(threadId, exitCode)
}

private func libraryLoadedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    info: UnsafePointer<IdaxDebuggerModuleInfo>?
) {
    guard let ctx, let info else { return }
    let box = Unmanaged<LibraryLoadedBox>.fromOpaque(ctx).takeUnretainedValue()
    let mi = ModuleInfo(
        name: borrowCString(info.pointee.name),
        base: info.pointee.base,
        size: info.pointee.size
    )
    box.handler(mi)
}

private func libraryUnloadedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    name: UnsafePointer<CChar>?
) {
    guard let ctx else { return }
    let box = Unmanaged<LibraryUnloadedBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(borrowCString(name))
}

private func breakpointChangedTrampoline(
    ctx: UnsafeMutableRawPointer?,
    change: Int32,
    address: UInt64
) {
    guard let ctx else { return }
    let box = Unmanaged<BreakpointChangedBox>.fromOpaque(ctx).takeUnretainedValue()
    let kind = BreakpointChange(rawValue: change) ?? .changed
    box.handler(kind, address)
}

private func appcallExecutorTrampoline(
    ctx: UnsafeMutableRawPointer?,
    request: UnsafePointer<IdaxDebuggerAppcallRequest>?,
    outResult: UnsafeMutablePointer<IdaxDebuggerAppcallResult>?
) -> Int32 {
    guard let ctx, let request, let outResult else { return 0 }
    let box = Unmanaged<AppcallExecutorBox>.fromOpaque(ctx).takeUnretainedValue()

    // Convert arguments
    var args: [AppcallValue] = []
    if let argPtr = request.pointee.arguments, request.pointee.argument_count > 0 {
        let buf = UnsafeBufferPointer(start: argPtr, count: request.pointee.argument_count)
        args = buf.map { makeSwiftAppcallValue($0) }
    }

    // Convert options
    var opts = AppcallOptions()
    let cOpts = request.pointee.options
    if cOpts.has_thread_id != 0 { opts.threadId = cOpts.thread_id }
    opts.manual = cOpts.manual != 0
    opts.includeDebugEvent = cOpts.include_debug_event != 0
    if cOpts.has_timeout_milliseconds != 0 { opts.timeoutMilliseconds = cOpts.timeout_milliseconds }

    guard let result = box.callback(
        request.pointee.function_address,
        request.pointee.function_type,
        args,
        opts
    ) else {
        return 0
    }

    outResult.pointee.return_value = makeCAppcallValue(result.returnValue)
    outResult.pointee.diagnostics = result.diagnostics.isEmpty ? nil : strdup(result.diagnostics)
    return 1
}

private func appcallExecutorCleanupTrampoline(ctx: UnsafeMutableRawPointer?) {
    guard let ctx else { return }
    let box = Unmanaged<AppcallExecutorBox>.fromOpaque(ctx).takeUnretainedValue()
    box.cleanup()
}

// MARK: - Debugger namespace

/// Debugger control and inspection.
///
/// Mirrors C++ `ida::debugger`.
public enum Debugger {

    // MARK: - Backend

    /// List all available debugger backends.
    public static func availableBackends() throws(IDAError) -> [BackendInfo] {
        var ptr: UnsafeMutablePointer<IdaxBackendInfo>? = nil
        var count: Int = 0
        try checkStatus(idax_debugger_available_backends(&ptr, &count), "debugger.availableBackends")
        guard let ptr, count > 0 else { return [] }
        defer {
            for i in 0..<count {
                var item = ptr[i]
                idax_backend_info_free(&item)
            }
            free(ptr)
        }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { raw in
            BackendInfo(
                name: borrowCString(raw.name),
                displayName: borrowCString(raw.display_name),
                remote: raw.remote != 0,
                supportsAppcall: raw.supports_appcall != 0,
                supportsAttach: raw.supports_attach != 0,
                loaded: raw.loaded != 0
            )
        }
    }

    /// Get the currently loaded debugger backend.
    public static func currentBackend() throws(IDAError) -> BackendInfo {
        var raw = IdaxBackendInfo()
        try checkStatus(idax_debugger_current_backend(&raw), "debugger.currentBackend")
        defer { idax_backend_info_free(&raw) }
        return BackendInfo(
            name: borrowCString(raw.name),
            displayName: borrowCString(raw.display_name),
            remote: raw.remote != 0,
            supportsAppcall: raw.supports_appcall != 0,
            supportsAttach: raw.supports_attach != 0,
            loaded: raw.loaded != 0
        )
    }

    /// Load a debugger backend by name.
    public static func loadBackend(_ name: String, remote: Bool = false) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_debugger_load_backend($0, remote ? 1 : 0) },
            "debugger.loadBackend"
        )
    }

    // MARK: - Process control

    /// Start a process under the debugger.
    public static func start(
        path: String, args: String = "", workingDirectory: String = ""
    ) throws(IDAError) {
        try checkStatus(
            path.withCString { p in
                args.withCString { a in
                    workingDirectory.withCString { w in
                        idax_debugger_start(p, a, w)
                    }
                }
            },
            "debugger.start"
        )
    }

    /// Request asynchronous process start.
    public static func requestStart(
        path: String, args: String = "", workingDirectory: String = ""
    ) throws(IDAError) {
        try checkStatus(
            path.withCString { p in
                args.withCString { a in
                    workingDirectory.withCString { w in
                        idax_debugger_request_start(p, a, w)
                    }
                }
            },
            "debugger.requestStart"
        )
    }

    /// Attach to a running process by PID.
    public static func attach(pid: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_attach(pid), "debugger.attach")
    }

    /// Request asynchronous attach to a process.
    public static func requestAttach(pid: Int32, eventId: Int32 = -1) throws(IDAError) {
        try checkStatus(idax_debugger_request_attach(pid, eventId), "debugger.requestAttach")
    }

    /// Detach from the debugged process.
    public static func detach() throws(IDAError) {
        try checkStatus(idax_debugger_detach(), "debugger.detach")
    }

    /// Terminate the debugged process.
    public static func terminate() throws(IDAError) {
        try checkStatus(idax_debugger_terminate(), "debugger.terminate")
    }

    // MARK: - Execution control

    /// Suspend all threads.
    public static func suspend() throws(IDAError) {
        try checkStatus(idax_debugger_suspend(), "debugger.suspend")
    }

    /// Resume execution.
    public static func resume() throws(IDAError) {
        try checkStatus(idax_debugger_resume(), "debugger.resume")
    }

    /// Step into the next instruction.
    public static func stepInto() throws(IDAError) {
        try checkStatus(idax_debugger_step_into(), "debugger.stepInto")
    }

    /// Step over the next instruction.
    public static func stepOver() throws(IDAError) {
        try checkStatus(idax_debugger_step_over(), "debugger.stepOver")
    }

    /// Step out of the current function.
    public static func stepOut() throws(IDAError) {
        try checkStatus(idax_debugger_step_out(), "debugger.stepOut")
    }

    /// Run until a specific address.
    public static func runTo(_ address: Address) throws(IDAError) {
        try checkStatus(idax_debugger_run_to(address), "debugger.runTo")
    }

    // MARK: - State queries

    /// Get the current debugger state.
    public static func state() throws(IDAError) -> DebuggerState {
        let raw = try withOutput("debugger.state", Int32(0)) { idax_debugger_state($0) }
        return DebuggerState(rawValue: raw)
    }

    /// Get the current instruction pointer.
    public static func instructionPointer() throws(IDAError) -> Address {
        try withOutput("debugger.instructionPointer", UInt64(0)) { idax_debugger_instruction_pointer($0) }
    }

    /// Get the current stack pointer.
    public static func stackPointer() throws(IDAError) -> Address {
        try withOutput("debugger.stackPointer", UInt64(0)) { idax_debugger_stack_pointer($0) }
    }

    /// Read a register value by name.
    public static func registerValue(_ regName: String) throws(IDAError) -> UInt64 {
        try withOutput("debugger.registerValue", UInt64(0)) { out in
            regName.withCString { idax_debugger_register_value($0, out) }
        }
    }

    /// Set a register value by name.
    public static func setRegister(_ regName: String, value: UInt64) throws(IDAError) {
        try checkStatus(
            regName.withCString { idax_debugger_set_register($0, value) },
            "debugger.setRegister"
        )
    }

    // MARK: - Breakpoints

    /// Add a breakpoint at the given address.
    public static func addBreakpoint(at address: Address) throws(IDAError) {
        try checkStatus(idax_debugger_add_breakpoint(address), "debugger.addBreakpoint")
    }

    /// Remove a breakpoint at the given address.
    public static func removeBreakpoint(at address: Address) throws(IDAError) {
        try checkStatus(idax_debugger_remove_breakpoint(address), "debugger.removeBreakpoint")
    }

    /// Check whether a breakpoint exists at the given address.
    public static func hasBreakpoint(at address: Address) throws(IDAError) -> Bool {
        let out = try withOutput("debugger.hasBreakpoint", Int32(0)) { idax_debugger_has_breakpoint(address, $0) }
        return out != 0
    }

    // MARK: - Memory

    /// Read bytes from debuggee memory.
    public static func readMemory(at address: Address, size: UInt64) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(idax_debugger_read_memory(address, size, &ptr, &len), "debugger.readMemory")
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    /// Write bytes to debuggee memory.
    public static func writeMemory(at address: Address, data: [UInt8]) throws(IDAError) {
        let ret = data.withUnsafeBufferPointer { buf in
            idax_debugger_write_memory(address, buf.baseAddress, buf.count)
        }
        try checkStatus(ret, "debugger.writeMemory")
    }

    // MARK: - Async requests

    /// Check whether an asynchronous request is currently running.
    public static func isRequestRunning() -> Bool {
        idax_debugger_is_request_running() != 0
    }

    /// Run pending asynchronous requests.
    public static func runRequests() throws(IDAError) {
        try checkStatus(idax_debugger_run_requests(), "debugger.runRequests")
    }

    /// Request asynchronous suspend.
    public static func requestSuspend() throws(IDAError) {
        try checkStatus(idax_debugger_request_suspend(), "debugger.requestSuspend")
    }

    /// Request asynchronous resume.
    public static func requestResume() throws(IDAError) {
        try checkStatus(idax_debugger_request_resume(), "debugger.requestResume")
    }

    /// Request asynchronous step-into.
    public static func requestStepInto() throws(IDAError) {
        try checkStatus(idax_debugger_request_step_into(), "debugger.requestStepInto")
    }

    /// Request asynchronous step-over.
    public static func requestStepOver() throws(IDAError) {
        try checkStatus(idax_debugger_request_step_over(), "debugger.requestStepOver")
    }

    /// Request asynchronous step-out.
    public static func requestStepOut() throws(IDAError) {
        try checkStatus(idax_debugger_request_step_out(), "debugger.requestStepOut")
    }

    /// Request asynchronous run-to.
    public static func requestRunTo(_ address: Address) throws(IDAError) {
        try checkStatus(idax_debugger_request_run_to(address), "debugger.requestRunTo")
    }

    // MARK: - Threads

    /// Get the number of threads.
    public static func threadCount() throws(IDAError) -> Int {
        var out: Int = 0
        try checkStatus(idax_debugger_thread_count(&out), "debugger.threadCount")
        return out
    }

    /// Get the thread ID at the given index.
    public static func threadId(at index: Int) throws(IDAError) -> Int32 {
        try withOutput("debugger.threadIdAt", Int32(0)) { idax_debugger_thread_id_at(index, $0) }
    }

    /// Get the thread name at the given index.
    public static func threadName(at index: Int) throws(IDAError) -> String {
        try withStringOutput("debugger.threadNameAt") { idax_debugger_thread_name_at(index, $0) }
    }

    /// Get the current thread ID.
    public static func currentThreadId() throws(IDAError) -> Int32 {
        try withOutput("debugger.currentThreadId", Int32(0)) { idax_debugger_current_thread_id($0) }
    }

    /// List all threads.
    public static func threads() throws(IDAError) -> [ThreadInfo] {
        var ptr: UnsafeMutablePointer<IdaxThreadInfo>? = nil
        var count: Int = 0
        try checkStatus(idax_debugger_threads(&ptr, &count), "debugger.threads")
        guard let ptr, count > 0 else { return [] }
        defer {
            for i in 0..<count {
                var item = ptr[i]
                idax_thread_info_free(&item)
            }
            free(ptr)
        }
        let buf = UnsafeBufferPointer(start: ptr, count: count)
        return buf.map { raw in
            ThreadInfo(
                id: raw.id,
                name: borrowCString(raw.name),
                isCurrent: raw.is_current != 0
            )
        }
    }

    /// Select a thread by ID.
    public static func selectThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_select_thread(threadId), "debugger.selectThread")
    }

    /// Request asynchronous thread selection.
    public static func requestSelectThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_request_select_thread(threadId), "debugger.requestSelectThread")
    }

    /// Suspend a specific thread.
    public static func suspendThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_suspend_thread(threadId), "debugger.suspendThread")
    }

    /// Request asynchronous thread suspend.
    public static func requestSuspendThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_request_suspend_thread(threadId), "debugger.requestSuspendThread")
    }

    /// Resume a specific thread.
    public static func resumeThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_resume_thread(threadId), "debugger.resumeThread")
    }

    /// Request asynchronous thread resume.
    public static func requestResumeThread(_ threadId: Int32) throws(IDAError) {
        try checkStatus(idax_debugger_request_resume_thread(threadId), "debugger.requestResumeThread")
    }

    // MARK: - Register info

    /// Get detailed register information by name.
    public static func registerInfo(_ registerName: String) throws(IDAError) -> RegisterInfo {
        var raw = IdaxDebuggerRegisterInfo()
        try checkStatus(
            registerName.withCString { idax_debugger_register_info($0, &raw) },
            "debugger.registerInfo"
        )
        defer { idax_debugger_register_info_free(&raw) }
        return RegisterInfo(
            name: borrowCString(raw.name),
            readOnly: raw.read_only != 0,
            instructionPointer: raw.instruction_pointer != 0,
            stackPointer: raw.stack_pointer != 0,
            framePointer: raw.frame_pointer != 0,
            mayContainAddress: raw.may_contain_address != 0,
            customFormat: raw.custom_format != 0
        )
    }

    /// Check whether a register is an integer register.
    public static func isIntegerRegister(_ registerName: String) throws(IDAError) -> Bool {
        let out = try withOutput("debugger.isIntegerRegister", Int32(0)) { out in
            registerName.withCString { idax_debugger_is_integer_register($0, out) }
        }
        return out != 0
    }

    /// Check whether a register is a floating-point register.
    public static func isFloatingRegister(_ registerName: String) throws(IDAError) -> Bool {
        let out = try withOutput("debugger.isFloatingRegister", Int32(0)) { out in
            registerName.withCString { idax_debugger_is_floating_register($0, out) }
        }
        return out != 0
    }

    /// Check whether a register is a custom register.
    public static func isCustomRegister(_ registerName: String) throws(IDAError) -> Bool {
        let out = try withOutput("debugger.isCustomRegister", Int32(0)) { out in
            registerName.withCString { idax_debugger_is_custom_register($0, out) }
        }
        return out != 0
    }

    // MARK: - Appcall

    /// Invoke an appcall.
    public static func appcall(
        functionAddress: Address,
        functionType: borrowing TypeHandle,
        arguments: [AppcallValue],
        options: AppcallOptions = AppcallOptions()
    ) throws(IDAError) -> AppcallResult {
        var cArgs = arguments.map { makeCAppcallValue($0) }
        defer {
            for i in 0..<cArgs.count {
                idax_debugger_appcall_value_free(&cArgs[i])
            }
        }
        let cOpts = makeCAppcallOptions(options)

        var request = IdaxDebuggerAppcallRequest()
        request.function_address = functionAddress
        request.function_type = UnsafeMutableRawPointer(functionType.handle)
        request.argument_count = cArgs.count
        request.options = cOpts

        var result = IdaxDebuggerAppcallResult()
        let ret: Int32 = cArgs.withUnsafeMutableBufferPointer { buf in
            request.arguments = buf.baseAddress
            return idax_debugger_appcall(&request, &result)
        }
        defer { idax_debugger_appcall_result_free(&result) }
        try checkStatus(ret, "debugger.appcall")

        let returnValue = makeSwiftAppcallValue(result.return_value)
        let diagnostics = result.diagnostics.map { String(cString: $0) } ?? ""
        return AppcallResult(returnValue: returnValue, diagnostics: diagnostics)
    }

    /// Clean up after an appcall.
    public static func cleanupAppcall(threadId: Int32? = nil) throws(IDAError) {
        if let tid = threadId {
            try checkStatus(idax_debugger_cleanup_appcall(1, tid), "debugger.cleanupAppcall")
        } else {
            try checkStatus(idax_debugger_cleanup_appcall(0, 0), "debugger.cleanupAppcall")
        }
    }

    /// Register an appcall executor with the given name.
    public static func registerExecutor(
        name: String,
        callback: @escaping (Address, UnsafeMutableRawPointer?, [AppcallValue], AppcallOptions) -> AppcallResult?,
        cleanup: @escaping () -> Void = {}
    ) throws(IDAError) {
        let box = AppcallExecutorBox(callback: callback, cleanup: cleanup)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        do {
            try checkStatus(
                name.withCString { n in
                    idax_debugger_register_executor(
                        n,
                        appcallExecutorTrampoline,
                        appcallExecutorCleanupTrampoline,
                        ctx
                    )
                },
                "debugger.registerExecutor"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
    }

    /// Unregister a named appcall executor.
    public static func unregisterExecutor(_ name: String) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_debugger_unregister_executor($0) },
            "debugger.unregisterExecutor"
        )
    }

    /// Invoke an appcall through a named executor.
    public static func appcallWithExecutor(
        name: String,
        functionAddress: Address,
        functionType: borrowing TypeHandle,
        arguments: [AppcallValue],
        options: AppcallOptions = AppcallOptions()
    ) throws(IDAError) -> AppcallResult {
        var cArgs = arguments.map { makeCAppcallValue($0) }
        defer {
            for i in 0..<cArgs.count {
                idax_debugger_appcall_value_free(&cArgs[i])
            }
        }
        let cOpts = makeCAppcallOptions(options)

        var request = IdaxDebuggerAppcallRequest()
        request.function_address = functionAddress
        request.function_type = UnsafeMutableRawPointer(functionType.handle)
        request.argument_count = cArgs.count
        request.options = cOpts

        var result = IdaxDebuggerAppcallResult()
        let ret: Int32 = cArgs.withUnsafeMutableBufferPointer { buf in
            request.arguments = buf.baseAddress
            return name.withCString { n in
                idax_debugger_appcall_with_executor(n, &request, &result)
            }
        }
        defer { idax_debugger_appcall_result_free(&result) }
        try checkStatus(ret, "debugger.appcallWithExecutor")

        let returnValue = makeSwiftAppcallValue(result.return_value)
        let diagnostics = result.diagnostics.map { String(cString: $0) } ?? ""
        return AppcallResult(returnValue: returnValue, diagnostics: diagnostics)
    }

    // MARK: - Event subscriptions

    /// Subscribe to process-started events.
    public static func onProcessStarted(
        _ handler: @escaping (ModuleInfo) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ProcessStartedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_process_started(processStartedTrampoline, ctx, &token),
                "debugger.onProcessStarted"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to process-exited events.
    public static func onProcessExited(
        _ handler: @escaping (Int32) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ProcessExitedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_process_exited(processExitedTrampoline, ctx, &token),
                "debugger.onProcessExited"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to process-suspended events.
    public static func onProcessSuspended(
        _ handler: @escaping (Address) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ProcessSuspendedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_process_suspended(processSuspendedTrampoline, ctx, &token),
                "debugger.onProcessSuspended"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to breakpoint-hit events.
    public static func onBreakpointHit(
        _ handler: @escaping (Int32, Address) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = BreakpointHitBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_breakpoint_hit(breakpointHitTrampoline, ctx, &token),
                "debugger.onBreakpointHit"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to trace events. Return `true` from the handler to continue tracing.
    public static func onTrace(
        _ handler: @escaping (Int32, Address) -> Bool
    ) throws(IDAError) -> DebuggerSubscription {
        let box = TraceBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_trace(traceTrampoline, ctx, &token),
                "debugger.onTrace"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to exception events.
    public static func onException(
        _ handler: @escaping (ExceptionInfo) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ExceptionBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_exception(exceptionTrampoline, ctx, &token),
                "debugger.onException"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to thread-started events.
    public static func onThreadStarted(
        _ handler: @escaping (Int32, String) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ThreadStartedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_thread_started(threadStartedTrampoline, ctx, &token),
                "debugger.onThreadStarted"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to thread-exited events.
    public static func onThreadExited(
        _ handler: @escaping (Int32, Int32) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = ThreadExitedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_thread_exited(threadExitedTrampoline, ctx, &token),
                "debugger.onThreadExited"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to library-loaded events.
    public static func onLibraryLoaded(
        _ handler: @escaping (ModuleInfo) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = LibraryLoadedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_library_loaded(libraryLoadedTrampoline, ctx, &token),
                "debugger.onLibraryLoaded"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to library-unloaded events.
    public static func onLibraryUnloaded(
        _ handler: @escaping (String) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = LibraryUnloadedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_library_unloaded(libraryUnloadedTrampoline, ctx, &token),
                "debugger.onLibraryUnloaded"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }

    /// Subscribe to breakpoint-changed events.
    public static func onBreakpointChanged(
        _ handler: @escaping (BreakpointChange, Address) -> Void
    ) throws(IDAError) -> DebuggerSubscription {
        let box = BreakpointChangedBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_debugger_on_breakpoint_changed(breakpointChangedTrampoline, ctx, &token),
                "debugger.onBreakpointChanged"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return DebuggerSubscription(token: token, context: ctx)
    }
}
