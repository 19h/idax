internal import CIDAX

/// IDA's user interface. Operations execute synchronously on the runtime's
/// owning thread. UI handles and callback contexts are not transferable.
public enum UI {
    public enum WidgetType: Sendable {
        case unknown, exports, imports, names, functions, strings, segments, segmentRegisters, selectors,
            signatures, typeLibraries, localTypes, problems, breakpoints, threads, modules, traceLog,
            callStack, crossReferences, searchResults, stackFrame, navigationBand, disassembly, hexView,
            notepad, output, commandLine, chooser, pseudocode, microcode
        internal init(native: Int32) {
            switch native {
            case 0: self = .exports
            case 1: self = .imports
            case 2: self = .names
            case 3: self = .functions
            case 4: self = .strings
            case 5: self = .segments
            case 6: self = .segmentRegisters
            case 7: self = .selectors
            case 8: self = .signatures
            case 9: self = .typeLibraries
            case 10: self = .localTypes
            case 12: self = .problems
            case 13: self = .breakpoints
            case 14: self = .threads
            case 15: self = .modules
            case 16: self = .traceLog
            case 17: self = .callStack
            case 18: self = .crossReferences
            case 19: self = .searchResults
            case 25: self = .stackFrame
            case 26: self = .navigationBand
            case 27: self = .disassembly
            case 28: self = .hexView
            case 29: self = .notepad
            case 30: self = .output
            case 31: self = .commandLine
            case 35: self = .chooser
            case 46: self = .pseudocode
            case 61: self = .microcode
            default: self = .unknown
            }
        }
    }
    public enum DockPosition: CaseIterable, Sendable {
        case left, right, top, bottom, floating, tab
        internal var native: Int64 { Int64(Self.allCases.firstIndex(of: self)!) }
    }
    public struct WidgetIdentity: Equatable, Hashable, Sendable { internal let value: UInt64 }
    public struct ShowOptions: Sendable {
        public var position: DockPosition
        public var restorePrevious: Bool
        public init(position: DockPosition = .right, restorePrevious: Bool = true) {
            self.position = position
            self.restorePrevious = restorePrevious
        }
    }
    public final class Widget {
        internal let handle: UnsafeMutableRawPointer
        internal init(owning handle: UnsafeMutableRawPointer) { self.handle = handle }
        deinit { idax_swift_widget_release(handle) }
        public func show(options: ShowOptions = .init()) throws(IDAError) {
            try operation(0, options.position.native, options.restorePrevious ? 1 : 0)
        }
        public func activate() throws(IDAError) { try operation(1) }
        public func close() throws(IDAError) { try operation(2) }
        public var isVisible: Bool { get throws(IDAError) { try query(0) != 0 } }
        public var isValid: Bool { get throws(IDAError) { try query(4) != 0 } }
        public var type: WidgetType {
            get throws(IDAError) { WidgetType(native: Int32(truncatingIfNeeded: try query(1))) }
        }
        public var identity: WidgetIdentity { get throws(IDAError) { WidgetIdentity(value: try query(2)) } }
        public var title: String { get throws(IDAError) { try text(currentLine: false) } }
        internal func operation(_ op: Int32, _ arg: Int64 = 0, _ auxiliary: Int32 = 0, _ extra: Int32 = 0)
            throws(IDAError)
        {
            try bridgeCall("widget.operation") {
                idax_swift_widget_operation(handle, op, arg, auxiliary, extra, $0)
            }
        }
        internal func query(_ query: Int32) throws(IDAError) -> UInt64 {
            var value: UInt64 = 0
            try bridgeCall("widget.query") { idax_swift_widget_query(handle, query, &value, $0) }
            return value
        }
        internal func text(currentLine: Bool, mouse: Bool = false) throws(IDAError) -> String {
            var value: UnsafeMutablePointer<CChar>?
            try bridgeCall("widget.text") {
                idax_swift_widget_text(handle, currentLine ? 1 : 0, mouse ? 1 : 0, &value, $0)
            }
            return try takeCString(value, "widget.text")
        }
    }
    public final class CustomViewer {
        public let widget: Widget
        internal init(_ widget: Widget) { self.widget = widget }
        public func setLines(_ lines: [String]) throws(IDAError) {
            let text = try LifecycleStrings(lines)
            let pointers = text.pointers
            var nativeError = IdaxSwiftError()
            defer { idax_swift_error_free(&nativeError) }
            let result = pointers.withUnsafeBufferPointer {
                idax_swift_widget_lines(widget.handle, $0.baseAddress, $0.count, &nativeError)
            }
            try bridgeCall("viewer.setLines") { error in
                error.pointee = nativeError
                nativeError = IdaxSwiftError()
                return result
            }
        }
        public var lineCount: UInt64 { get throws(IDAError) { try widget.query(3) } }
        public func jump(toLine line: Int64, x: Int32 = 0, y: Int32 = 0) throws(IDAError) {
            try widget.operation(4, line, x, y)
        }
        public func currentLine(atMouse: Bool = false) throws(IDAError) -> String {
            try widget.text(currentLine: true, mouse: atMouse)
        }
        public func refresh() throws(IDAError) { try widget.operation(3) }
        public func close() throws(IDAError) { try widget.operation(5) }
    }
    public static func createWidget(title: String) throws(IDAError) -> Widget {
        let text = try LifecycleStrings([title])
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.createWidget") { idax_swift_widget_create(text[0], nil, 0, 0, &handle, $0) }
        return Widget(owning: try requireLifecycleHandle(handle, "ui.createWidget"))
    }
    public static func findWidget(title: String) throws(IDAError) -> Widget {
        let text = try LifecycleStrings([title])
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.findWidget") { idax_swift_widget_find(text[0], &handle, $0) }
        return Widget(owning: try requireLifecycleHandle(handle, "ui.findWidget"))
    }
    public static func createCustomViewer(title: String, lines: [String] = []) throws(IDAError)
        -> CustomViewer
    {
        let text = try LifecycleStrings([title] + lines)
        let pointers = Array(text.pointers.dropFirst())
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.createCustomViewer") { error in
            pointers.withUnsafeBufferPointer {
                idax_swift_widget_create(text[0], $0.baseAddress, $0.count, 1, &handle, error)
            }
        }
        return CustomViewer(Widget(owning: try requireLifecycleHandle(handle, "ui.createCustomViewer")))
    }
    public static func message(_ text: String) throws(IDAError) {
        try requireRuntimeThread("ui.message")
        let value = try LifecycleStrings([text])
        idax_ui_message(value[0])
    }
    public static func warning(_ text: String) throws(IDAError) {
        try requireRuntimeThread("ui.warning")
        let value = try LifecycleStrings([text])
        idax_ui_warning(value[0])
    }
    public static func information(_ text: String) throws(IDAError) {
        try requireRuntimeThread("ui.information")
        let value = try LifecycleStrings([text])
        idax_ui_info(value[0])
    }
    public static func askYesNo(_ question: String, defaultYes: Bool = true) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([question])
        return try withOutput("ui.askYesNo", initial: Int32(0)) {
            idax_ui_ask_yn(text[0], defaultYes ? 1 : 0, $0)
        } != 0
    }
    public static func askString(_ prompt: String, defaultValue: String = "") throws(IDAError) -> String {
        let text = try LifecycleStrings([prompt, defaultValue])
        return try withStringOutput("ui.askString") { idax_ui_ask_string(text[0], text[1], $0) }
    }
    public static func askFile(_ prompt: String, defaultPath: String = "", forSaving: Bool = false)
        throws(IDAError) -> String
    {
        let text = try LifecycleStrings([prompt, defaultPath])
        return try withStringOutput("ui.askFile") {
            idax_ui_ask_file(forSaving ? 1 : 0, text[1], text[0], $0)
        }
    }
    public static func askAddress(_ prompt: String, defaultValue: Address = .max) throws(IDAError) -> Address
    {
        let text = try LifecycleStrings([prompt])
        return try withOutput("ui.askAddress", initial: UInt64(0)) {
            idax_ui_ask_address(text[0], defaultValue, $0)
        }
    }
    public static func askInteger(_ prompt: String, defaultValue: Int64 = 0) throws(IDAError) -> Int64 {
        let text = try LifecycleStrings([prompt])
        return try withOutput("ui.askInteger", initial: Int64(0)) {
            idax_ui_ask_long(text[0], defaultValue, $0)
        }
    }
    public static func askText(
        _ prompt: String, defaultValue: String = "", maximumBytes: Int = 0, acceptTabs: Bool = false,
        normalFont: Bool = false
    ) throws(IDAError) -> String {
        guard maximumBytes >= 0 else {
            throw IDAError(category: .validation, message: "Text capacity must not be negative")
        }
        let text = try LifecycleStrings([prompt, defaultValue])
        return try withStringOutput("ui.askText") {
            idax_ui_ask_text(text[0], text[1], maximumBytes, acceptTabs ? 1 : 0, normalFont ? 1 : 0, $0)
        }
    }
    public static func copyToClipboard(_ text: String) throws(IDAError) {
        try requireRuntimeThread("ui.copyToClipboard")
        let value = try LifecycleStrings([text])
        try checkStatus(idax_ui_copy_to_clipboard(value[0]), "ui.copyToClipboard")
    }
    public static func clipboard() throws(IDAError) -> String {
        try withStringOutput("ui.clipboard") { idax_ui_read_clipboard($0) }
    }
    public static func jump(to address: Address) throws(IDAError) {
        try requireRuntimeThread("ui.jump")
        try checkStatus(idax_ui_jump_to(address), "ui.jump")
    }
    public static var screenAddress: Address {
        get throws(IDAError) {
            try withOutput("ui.screenAddress", initial: UInt64(0)) { idax_ui_screen_address($0) }
        }
    }
    public static func selection() throws(IDAError) -> Range<Address> {
        try requireRuntimeThread("ui.selection")
        var start: UInt64 = 0
        var end: UInt64 = 0
        try checkStatus(idax_ui_selection(&start, &end), "ui.selection")
        guard start <= end else {
            throw IDAError(category: .internalError, message: "Invalid native selection range")
        }
        return start..<end
    }
    public static func refreshAllViews() throws(IDAError) {
        try requireRuntimeThread("ui.refreshAllViews")
        idax_ui_refresh_all_views()
    }
    public static func userDirectory() throws(IDAError) -> String {
        try withStringOutput("ui.userDirectory") { idax_ui_user_directory($0) }
    }

    public enum EventKind: CaseIterable, Sendable {
        case databaseInitialized, databaseClosed, readyToRun, currentWidgetChanged, screenAddressChanged,
            widgetVisible, widgetInvisible, widgetClosing, viewActivated, viewDeactivated, viewCreated,
            viewClosed, cursorChanged
        internal var native: Int32 { Int32(Self.allCases.firstIndex(of: self)!) }
    }
    public struct Change {
        internal let lease: CallbackLease
        public func resolveWidget() throws(IDAError) -> Widget? { try contextWidget(lease, 0) }
        public func resolvePreviousWidget() throws(IDAError) -> Widget? { try contextWidget(lease, 1) }
        public let kind: EventKind
        public let address: Address
        public let previousAddress: Address
        public let widget: WidgetIdentity
        public let previousWidget: WidgetIdentity
        public let isNewDatabase: Bool
        public let startupScript: String
        public let widgetTitle: String
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            guard event.kind >= 0, Int(event.kind) < EventKind.allCases.count else {
                throw IDAError(category: .unsupported, message: "Unknown UI event")
            }
            lease = CallbackLease(try requireLifecycleHandle(event.lease, "ui.event.context"))
            kind = EventKind.allCases[Int(event.kind)]
            address = event.address
            previousAddress = event.secondary_address
            widget = WidgetIdentity(value: event.identity)
            previousWidget = WidgetIdentity(value: event.previous_identity)
            isNewDatabase = event.flag != 0
            startupScript = try borrowCString(event.secondary_text, "ui.event.startupScript")
            widgetTitle = try borrowCString(event.text, "ui.event.widgetTitle")
        }
    }
    public static func subscribe(
        to kind: EventKind? = nil, filter: @escaping (Change) throws(IDAError) -> Bool = { _ in true },
        handler: @escaping (Change) throws(IDAError) -> Void
    ) throws(IDAError) -> Registration {
        let callbacks = callbackDescriptor { raw, reply in
            let change = try Change(raw)
            if raw.phase == 1 {
                reply.pointee.decision = try filter(change) ? 1 : 0
            } else {
                try handler(change)
            }
        }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.subscribe") { idax_swift_ui_subscribe(kind?.native ?? -1, callbacks, &handle, $0) }
        return Registration(owning: try requireLifecycleHandle(handle, "ui.subscribe"))
    }
    public enum TimerDecision: Sendable { case stop, reschedule(milliseconds: Int32) }
    public static func registerTimer(
        intervalMilliseconds: Int32, callback: @escaping () throws(IDAError) -> TimerDecision
    ) throws(IDAError) -> Registration {
        let callbacks = callbackDescriptor { _, reply in
            switch try callback() {
            case .stop: reply.pointee.decision = -1
            case .reschedule(let interval):
                guard interval > 0 else {
                    throw IDAError(category: .validation, message: "Timer interval must be positive")
                }
                reply.pointee.decision = interval
            }
        }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.registerTimer") {
            idax_swift_timer_register(intervalMilliseconds, callbacks, &handle, $0)
        }
        return Registration(owning: try requireLifecycleHandle(handle, "ui.registerTimer"))
    }
    public final class Popup {
        internal let lease: CallbackLease
        public let widgetTitle: String
        public let widgetType: WidgetType
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            lease = CallbackLease(try requireLifecycleHandle(event.lease, "popup.context"))
            widgetTitle = try borrowCString(event.text, "popup.title")
            widgetType = WidgetType(native: event.number)
        }
        public func widget() throws(IDAError) -> Widget? { try contextWidget(lease, 0) }
        public func attachAction(
            identifier: String, label: String, path: String = "", icon: Int32 = -1,
            handler: @escaping () throws(IDAError) -> Void
        ) throws(IDAError) {
            let text = try LifecycleStrings([identifier, label, path])
            let callbacks = callbackDescriptor { _, _ in try handler() }
            try bridgeCall("popup.attachAction") {
                idax_swift_popup_attach(lease.handle, text[0], text[1], text[2], icon, callbacks, $0)
            }
        }
        public func attachRegisteredAction(_ identifier: String, path: String = "") throws(IDAError) {
            let text = try LifecycleStrings([identifier, path])
            try bridgeCall("popup.attachRegisteredAction") {
                idax_swift_popup_attach_registered(lease.handle, text[0], text[1], $0)
            }
        }
    }
    public struct LineRenderEntry: Sendable {
        public var lineNumber: Int32
        public var backgroundColor: UInt32
        public var startColumn: Int32
        public var length: Int32
        public var characterRange: Bool
        public init(
            lineNumber: Int32, backgroundColor: UInt32, startColumn: Int32 = 0, length: Int32 = 0,
            characterRange: Bool = false
        ) {
            self.lineNumber = lineNumber
            self.backgroundColor = backgroundColor
            self.startColumn = startColumn
            self.length = length
            self.characterRange = characterRange
        }
    }
    public final class RenderingContext {
        internal let lease: CallbackLease
        public let widgetTitle: String
        public let widgetType: WidgetType
        internal init(_ event: IdaxSwiftNotification) throws(IDAError) {
            lease = CallbackLease(try requireLifecycleHandle(event.lease, "rendering.context"))
            widgetTitle = try borrowCString(event.text, "rendering.widgetTitle")
            widgetType = WidgetType(native: event.number)
        }
        public func widget() throws(IDAError) -> Widget? { try contextWidget(lease, 0) }
        public func add(_ entry: LineRenderEntry) throws(IDAError) {
            try bridgeCall("rendering.add") {
                idax_swift_rendering_add(
                    lease.handle, entry.lineNumber, entry.backgroundColor, entry.startColumn, entry.length,
                    entry.characterRange ? 1 : 0, $0)
            }
        }
        public var entries: [LineRenderEntry] {
            get throws(IDAError) {
                var values: UnsafeMutablePointer<IdaxLineRenderEntry>?
                var count = 0
                try bridgeCall("rendering.entries") {
                    idax_swift_rendering_entries(lease.handle, &values, &count, $0)
                }
                defer { idax_free_bytes(UnsafeMutableRawPointer(values)?.assumingMemoryBound(to: UInt8.self)) }
                return try checkedBuffer(values, count: count, "rendering.entries").map {
                    LineRenderEntry(lineNumber: $0.line_number, backgroundColor: $0.bg_color,
                                    startColumn: $0.start_column, length: $0.length,
                                    characterRange: $0.character_range != 0)
                }
            }
        }
        public func setEntries(_ entries: [LineRenderEntry]) throws(IDAError) {
            let values = entries.map {
                IdaxLineRenderEntry(line_number: $0.lineNumber, bg_color: $0.backgroundColor,
                                   start_column: $0.startColumn, length: $0.length,
                                   character_range: $0.characterRange ? 1 : 0)
            }
            try bridgeCall("rendering.setEntries") { error in
                values.withUnsafeBufferPointer {
                    idax_swift_rendering_replace(lease.handle, $0.baseAddress, $0.count, error)
                }
            }
        }
    }
    public static func onPopupReady(_ handler: @escaping (Popup) throws(IDAError) -> Void) throws(IDAError)
        -> Registration
    {
        try subscribeContext(13) { event, _ in try handler(Popup(event)) }
    }
    public static func onRenderingInfo(_ handler: @escaping (RenderingContext) throws(IDAError) -> Void)
        throws(IDAError) -> Registration
    {
        try subscribeContext(14) { event, _ in try handler(RenderingContext(event)) }
    }
    private static func subscribeContext(
        _ kind: Int32,
        _ body: @escaping (IdaxSwiftNotification, UnsafeMutablePointer<IdaxSwiftReply>) throws -> Void
    ) throws(IDAError) -> Registration {
        let callbacks = callbackDescriptor(body)
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("ui.subscribeContext") { idax_swift_ui_subscribe(kind, callbacks, &handle, $0) }
        return Registration(owning: try requireLifecycleHandle(handle, "ui.subscribeContext"))
    }
}

internal func contextWidget(_ lease: CallbackLease, _ which: Int32) throws(IDAError) -> UI.Widget? {
    var result: UnsafeMutableRawPointer?
    try bridgeCall("context.widget") { idax_swift_context_widget(lease.handle, which, &result, $0) }
    return result.map { UI.Widget(owning: $0) }
}
extension UI {
    public static func currentWidget() throws(IDAError) -> Widget? {
        var result: UnsafeMutableRawPointer?
        try bridgeCall("ui.currentWidget") { idax_swift_widget_current(&result, $0) }
        return result.map { Widget(owning: $0) }
    }
    public static func clipboardBackend() throws(IDAError) -> String {
        try requireRuntimeThread("ui.clipboardBackend")
        return try borrowCString(idax_ui_clipboard_backend(), "ui.clipboardBackend")
    }
    public struct Progress: Sendable {
        public var phase: String
        public var processed, total: Int
        public var currentItem: String
        public init(phase: String, processed: Int = 0, total: Int = 0, currentItem: String = "") {
            self.phase = phase
            self.processed = processed
            self.total = total
            self.currentItem = currentItem
        }
    }
    public typealias ProgressHandler = (Progress) throws(IDAError) -> Bool
    public final class WaitBox {
        private let holder: UnsafeMutableRawPointer
        public init(_ message: String) throws(IDAError) {
            try requireRuntimeThread("ui.waitBox")
            let text = try LifecycleStrings([message])
            var native: UnsafeMutableRawPointer?
            try checkStatus(idax_ui_wait_box_create(text[0], &native), "ui.waitBox")
            let handle = try requireLifecycleHandle(native, "ui.waitBox")
            var resource: UnsafeMutableRawPointer?
            try bridgeCall("ui.waitBox.adopt") {
                idax_swift_resource_adopt(handle, idax_ui_wait_box_free, 0, &resource, $0)
            }
            holder = try requireLifecycleHandle(resource, "ui.waitBox.adopt")
        }
        deinit { idax_swift_resource_release(holder) }
        private func checkedHandle() throws(IDAError) -> UnsafeMutableRawPointer {
            var raw: UnsafeMutableRawPointer?
            try bridgeCall("ui.waitBox") { idax_swift_resource_get(holder, &raw, $0) }
            return try requireLifecycleHandle(raw, "ui.waitBox")
        }
        public func update(_ message: String) throws(IDAError) {
            let handle = try checkedHandle()
            let text = try LifecycleStrings([message])
            try checkStatus(idax_ui_wait_box_update(handle, text[0]), "ui.waitBox.update")
        }
        public var isCancelled: Bool {
            get throws(IDAError) {
                let handle = try checkedHandle()
                return try withOutput("ui.waitBox.cancelled", initial: Int32(0)) {
                    idax_ui_wait_box_cancelled(handle, $0)
                } != 0
            }
        }
        public var isActive: Bool {
            get throws(IDAError) {
                let handle = try checkedHandle()
                return try withOutput("ui.waitBox.active", initial: Int32(0)) {
                    idax_ui_wait_box_active(handle, $0)
                } != 0
            }
        }
        public func dismiss() throws(IDAError) { idax_ui_wait_box_dismiss(try checkedHandle()) }
        public func close() throws(IDAError) {
            try bridgeCall("ui.waitBox.close") { idax_swift_resource_close(holder, $0) }
        }
    }
}
