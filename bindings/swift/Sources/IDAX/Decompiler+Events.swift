internal import CIDAX

internal final class DecompilerEventLease {
    let handle: UnsafeMutableRawPointer
    init(_ handle: UnsafeMutableRawPointer) { self.handle = handle; idax_swift_decompiler_event_retain(handle) }
    deinit { idax_swift_decompiler_event_release(handle) }
    func view() throws(IDAError) -> Decompiler.View {
        let op = "Decompiler.Event.view"; var output: UnsafeMutableRawPointer?
        try bridgeCall(op) { idax_swift_decompiler_event_view(handle, &output, $0) }
        return try .init(owning: requireOwnedHandle(output, op))
    }
}
extension Decompiler {
    /// Registration errors throw. Later observer failures are retained by the
    /// subscription and can be read with lastError(clear:).
    public final class Subscription {
        private let resource: NativeResource
        internal init(owning pointer: UnsafeMutableRawPointer) throws(IDAError) {
            resource = try NativeResource(taking: pointer, release: idax_swift_decompiler_subscription_free, operation: "Decompiler.subscribe")
        }
        public func close() throws(IDAError) {
            try resource.close("Decompiler.Subscription.close", using: idax_swift_decompiler_subscription_close)
        }
        public func isValid() throws(IDAError) -> Bool {
            try resource.isOpen("Decompiler.Subscription.isValid")
        }
        public func lastError(clear: Bool = false) throws(IDAError) -> IDAError? {
            let op = "Decompiler.Subscription.lastError"; let h = try resource.pointer(op)
            var result = IdaxSwiftError(); var present: Int32 = 0
            defer { idax_swift_error_free(&result) }
            try bridgeCall(op) { idax_swift_decompiler_subscription_error(h, &result, &present, clear ? 1 : 0, $0) }
            guard present != 0 else { return nil }
            return IDAError(category: IDAError.category(fromNative: result.category), code: result.code,
                message: try borrowCString(result.message.map { UnsafePointer($0) }, op),
                context: try borrowCString(result.context.map { UnsafePointer($0) }, op))
        }
    }
    public struct MaturityEvent: Equatable, Sendable {
        public let functionAddress: Address
        public let newMaturity: Maturity
        public init(functionAddress: Address, newMaturity: Maturity) { self.functionAddress = functionAddress; self.newMaturity = newMaturity }
    }
    /// A callback-scoped pseudocode editor. Copied addresses remain plain values.
    public struct PseudocodeEvent {
        public let functionAddress: Address
        internal let lease: DecompilerEventLease
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            functionAddress = event.address
            lease = DecompilerEventLease(try requireOwnedHandle(event.lease, "Decompiler.PseudocodeEvent"))
        }
        public func rawLines() throws(IDAError) -> [String] {
            let op = "Decompiler.PseudocodeEvent.rawLines"
            var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?; var count = 0
            defer { idax_decompiled_lines_free(output, count) }
            try bridgeCall(op) { idax_swift_decompiler_event_lines(lease.handle, &output, &count, $0) }
            return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> String in try borrowCString(value.map { UnsafePointer($0) }, op) }
        }
        public func setLine(at index: Int, taggedText: String) throws(IDAError) {
            let op = "Decompiler.PseudocodeEvent.setLine"; try requireNonnegative(index, op); try validateCString(taggedText, op)
            try bridgeCall(op) { error in taggedText.withCString { idax_swift_decompiler_event_set_line(lease.handle, index, $0, error) } }
        }
        public func headerLineCount() throws(IDAError) -> Int32 {
            let op = "Decompiler.PseudocodeEvent.headerLineCount"; var output: Int32 = 0
            try bridgeCall(op) { idax_swift_decompiler_event_header_lines(lease.handle, &output, $0) }; return output
        }
        public func item(inTaggedLine line: String, atColumn column: Int32) throws(IDAError) -> ItemAtPosition {
            let op = "Decompiler.PseudocodeEvent.item"; try validateCString(line, op)
            var output = IdaxDecompilerItemAtPosition()
            try bridgeCall(op) { error in line.withCString { idax_swift_decompiler_event_item(lease.handle, $0, column, &output, error) } }
            return try .init(copying: output, op)
        }
    }
    public struct CursorPositionEvent {
        public let functionAddress: Address
        public let cursorAddress: Address
        internal let lease: DecompilerEventLease
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            functionAddress = event.address; cursorAddress = event.secondary_address
            lease = DecompilerEventLease(try requireOwnedHandle(event.lease, "Decompiler.CursorPositionEvent"))
        }
        public func view() throws(IDAError) -> View { try lease.view() }
    }
    public struct HintRequestEvent {
        public let functionAddress: Address
        public let itemAddress: Address
        internal let lease: DecompilerEventLease
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            functionAddress = event.address; itemAddress = event.secondary_address
            lease = DecompilerEventLease(try requireOwnedHandle(event.lease, "Decompiler.HintRequestEvent"))
        }
        public func view() throws(IDAError) -> View { try lease.view() }
    }
    public struct PopulatingPopupEvent {
        public let functionAddress: Address
        internal let lease: DecompilerEventLease
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            functionAddress = event.address
            lease = DecompilerEventLease(try requireOwnedHandle(event.lease, "Decompiler.PopulatingPopupEvent"))
        }
        public func view() throws(IDAError) -> View { try lease.view() }
        public func popup() throws(IDAError) -> UI.Popup {
            var output = IdaxSwiftNotification()
            try bridgeCall("Decompiler.PopulatingPopupEvent.popup") { idax_swift_decompiler_event_popup(lease.handle, &output, $0) }
            return try UI.Popup(output)
        }
    }
    public struct HintResult: Equatable, Sendable {
        public var text: String
        public var lines: Int32
        public init(text: String = "", lines: Int32 = 0) { self.text = text; self.lines = lines }
    }
    private static func subscribe(_ kind: Int32, callbacks: IdaxSwiftCallbacks) throws(IDAError) -> Subscription {
        var output: UnsafeMutableRawPointer?
        try bridgeCall("Decompiler.subscribe") { idax_swift_decompiler_subscribe(kind, callbacks, &output, $0) }
        return try Subscription(owning: requireOwnedHandle(output, "Decompiler.subscribe"))
    }
    public static func onMaturityChanged(_ callback: @escaping (MaturityEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(0, callbacks: callbackDescriptor { event, _ in
            try callback(MaturityEvent(functionAddress: event.address, newMaturity: checkedEnum(Maturity.self, event.number, "Decompiler.MaturityEvent")))
        })
    }
    public static func onFunctionPrinted(_ callback: @escaping (PseudocodeEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(1, callbacks: callbackDescriptor { event, _ in try callback(PseudocodeEvent(event)) })
    }
    public static func onRefreshPseudocode(_ callback: @escaping (PseudocodeEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(2, callbacks: callbackDescriptor { event, _ in try callback(PseudocodeEvent(event)) })
    }
    public static func onSwitchPseudocode(_ callback: @escaping (PseudocodeEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(3, callbacks: callbackDescriptor { event, _ in try callback(PseudocodeEvent(event)) })
    }
    public static func onCursorPositionChanged(_ callback: @escaping (CursorPositionEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(4, callbacks: callbackDescriptor { event, _ in try callback(CursorPositionEvent(event)) })
    }
    public static func onCreateHint(_ callback: @escaping (HintRequestEvent) throws(IDAError) -> HintResult) throws(IDAError) -> Subscription {
        try subscribe(5, callbacks: callbackDescriptor { event, reply in
            let result = try callback(HintRequestEvent(event)); try validateCString(result.text, "Decompiler.HintResult")
            guard result.lines >= 0 else { throw IDAError(category: .validation, message: "Hint line count is negative", context: "Decompiler.HintResult") }
            reply.pointee.integer = Int64(result.lines)
            result.text.withCString { idax_swift_reply_text(reply, $0) }
        })
    }
    public static func onPopulatingPopup(_ callback: @escaping (PopulatingPopupEvent) throws(IDAError) -> Void) throws(IDAError) -> Subscription {
        try subscribe(6, callbacks: callbackDescriptor { event, _ in try callback(PopulatingPopupEvent(event)) })
    }
}
