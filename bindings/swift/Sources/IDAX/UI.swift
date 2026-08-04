internal import CIDAX
import Darwin

// MARK: - Value types

/// UI event snapshot from the IDA kernel.
///
/// Maps directly to C `IdaxUIEvent`. Raw widget/previous_widget void
/// pointers are omitted — use `widgetID` / `previousWidgetID` instead.
public struct UIEvent: Sendable {
    public let kind: Int32
    public let address: Address
    public let previousAddress: Address
    public let widgetID: UInt64
    public let previousWidgetID: UInt64
    public let isNewDatabase: Bool
    public let startupScript: String
    public let widgetTitle: String
}

/// Options for `UI.showWidgetEx`.
public struct ShowWidgetOptions: Sendable {
    public var position: Int32
    public var restorePrevious: Bool

    public init(position: Int32 = 0, restorePrevious: Bool = false) {
        self.position = position
        self.restorePrevious = restorePrevious
    }
}

/// Popup event snapshot from the IDA kernel.
public struct PopupEvent: @unchecked Sendable {
    public let widgetID: UInt64
    public let widgetTitle: String
    public let widgetType: Int32
    // Raw widget/popup void pointers kept as opaque for attachDynamicAction use.
    let rawWidget: UnsafeMutableRawPointer?
    let rawPopup: UnsafeMutableRawPointer?
}

/// Line rendering entry for custom rendering callbacks.
public struct LineRenderEntry: Sendable {
    public var lineNumber: Int32
    public var backgroundColor: UInt32
    public var startColumn: Int32
    public var length: Int32
    public var characterRange: Int32

    public init(
        lineNumber: Int32 = 0,
        backgroundColor: UInt32 = 0,
        startColumn: Int32 = 0,
        length: Int32 = 0,
        characterRange: Int32 = 0
    ) {
        self.lineNumber = lineNumber
        self.backgroundColor = backgroundColor
        self.startColumn = startColumn
        self.length = length
        self.characterRange = characterRange
    }
}

// MARK: - Widget (borrowed handle)

/// Lightweight wrapper around an IDA widget handle.
///
/// Widget handles are borrowed from IDA — they are NOT owned by this struct,
/// so `Widget` is freely copyable and does NOT free the handle on deinit.
public struct Widget: @unchecked Sendable {
    let handle: IdaxWidgetHandle

    init(_ handle: IdaxWidgetHandle) {
        self.handle = handle
    }

    /// Show the widget at the given position.
    public func show(position: Int32 = 0) throws(IDAError) {
        try checkStatus(idax_ui_show_widget(handle, position), "ui.showWidget")
    }

    /// Show the widget with extended options.
    public func showEx(options: ShowWidgetOptions) throws(IDAError) {
        var raw = IdaxShowWidgetOptions(
            position: options.position,
            restore_previous: options.restorePrevious ? 1 : 0
        )
        try checkStatus(idax_ui_show_widget_ex(handle, &raw), "ui.showWidgetEx")
    }

    /// Activate (bring to front) the widget.
    public func activate() throws(IDAError) {
        try checkStatus(idax_ui_activate_widget(handle), "ui.activateWidget")
    }

    /// Close the widget.
    public func close() throws(IDAError) {
        try checkStatus(idax_ui_close_widget(handle), "ui.closeWidget")
    }

    /// Whether the widget is currently visible.
    public var isVisible: Bool {
        idax_ui_is_widget_visible(handle) != 0
    }

    /// The widget type identifier.
    public var type: Int32 {
        idax_ui_widget_type(handle)
    }

    /// The widget title.
    public var title: String {
        get throws(IDAError) {
            try withStringOutput("ui.widgetTitle") { idax_ui_widget_title(handle, $0) }
        }
    }

    /// The widget's unique identifier.
    public var widgetID: UInt64 {
        get throws(IDAError) {
            try withOutput("ui.widgetID", UInt64(0)) { idax_ui_widget_id(handle, $0) }
        }
    }

    /// Get the raw host pointer for the widget.
    public var host: UnsafeMutableRawPointer? {
        get throws(IDAError) {
            try withOutput("ui.widgetHost", nil as UnsafeMutableRawPointer?) {
                idax_ui_widget_host(handle, $0)
            }
        }
    }

    /// Access the widget host through a scoped closure.
    ///
    /// The host pointer is valid only for the duration of the closure.
    public func withHost(
        _ body: @escaping (UnsafeMutableRawPointer) -> Void
    ) throws(IDAError) {
        let box = WidgetHostBox(callback: body)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<AnyObject>.fromOpaque(ctx).release() }
        try checkStatus(
            idax_ui_with_widget_host(handle, widgetHostTrampoline, ctx),
            "ui.withWidgetHost"
        )
    }
}

// MARK: - CustomViewer (~Copyable handle)

/// A custom text viewer widget.
///
/// Wraps an `IdaxWidgetHandle` specifically for custom viewer operations.
/// NOT ~Copyable because closing is explicit (the handle is owned by IDA).
public struct CustomViewer: @unchecked Sendable {
    let handle: IdaxWidgetHandle

    init(_ handle: IdaxWidgetHandle) {
        self.handle = handle
    }

    /// Replace all lines in the viewer.
    public func setLines(_ lines: [String]) throws(IDAError) {
        let ret = lines.withCStringArray { ptrs, count in
            idax_ui_set_custom_viewer_lines(handle, ptrs, count)
        }
        try checkStatus(ret, "ui.setCustomViewerLines")
    }

    /// The number of lines currently displayed.
    public var lineCount: Int {
        get throws(IDAError) {
            var out: Int = 0
            try checkStatus(
                idax_ui_custom_viewer_line_count(handle, &out),
                "ui.customViewerLineCount"
            )
            return out
        }
    }

    /// Jump to a specific line in the viewer.
    public func jumpToLine(_ lineIndex: Int, x: Int32 = 0, y: Int32 = 0) throws(IDAError) {
        try checkStatus(
            idax_ui_custom_viewer_jump_to_line(handle, lineIndex, x, y),
            "ui.customViewerJumpToLine"
        )
    }

    /// Get the current line text.
    ///
    /// - Parameter mouse: If `true`, returns the line under the mouse cursor.
    public func currentLine(mouse: Bool = false) throws(IDAError) -> String {
        try withStringOutput("ui.customViewerCurrentLine") {
            idax_ui_custom_viewer_current_line(handle, mouse ? 1 : 0, $0)
        }
    }

    /// Refresh the viewer display.
    public func refresh() throws(IDAError) {
        try checkStatus(idax_ui_refresh_custom_viewer(handle), "ui.refreshCustomViewer")
    }

    /// Close the custom viewer.
    public func close() throws(IDAError) {
        try checkStatus(idax_ui_close_custom_viewer(handle), "ui.closeCustomViewer")
    }

    /// Get a `Widget` view of this custom viewer for generic widget operations.
    public var asWidget: Widget {
        Widget(handle)
    }
}

// MARK: - UITimer (~Copyable RAII)

/// RAII timer registration token. Unregisters the timer on deinit.
public struct UITimer: ~Copyable, @unchecked Sendable {
    private let token: UInt64
    private let context: UnsafeMutableRawPointer?

    init(token: UInt64, context: UnsafeMutableRawPointer? = nil) {
        self.token = token
        self.context = context
    }

    deinit {
        idax_ui_unregister_timer(token)
        if let context {
            Unmanaged<AnyObject>.fromOpaque(context).release()
        }
    }

    /// Explicitly cancel and unregister the timer.
    public consuming func cancel() {
        idax_ui_unregister_timer(token)
        if let context {
            Unmanaged<AnyObject>.fromOpaque(context).release()
        }
        discard self
    }
}

// MARK: - UISubscription (~Copyable RAII)

/// RAII UI event subscription token. Unsubscribes on deinit.
public struct UISubscription: ~Copyable, @unchecked Sendable {
    private let token: UInt64
    private let context: UnsafeMutableRawPointer

    init(token: UInt64, context: UnsafeMutableRawPointer) {
        self.token = token
        self.context = context
    }

    deinit {
        idax_ui_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
    }

    /// Explicitly cancel and unsubscribe.
    public consuming func cancel() {
        idax_ui_unsubscribe(token)
        Unmanaged<AnyObject>.fromOpaque(context).release()
        discard self
    }
}

// MARK: - UI namespace

/// IDA user interface operations.
///
/// Mirrors C++ `ida::ui`.
public enum UI {

    // MARK: - Messages

    /// Output a message to the IDA output window.
    public static func message(_ text: String) {
        text.withCString { idax_ui_message($0) }
    }

    /// Show a warning dialog.
    public static func warning(_ text: String) {
        text.withCString { idax_ui_warning($0) }
    }

    /// Show an informational dialog.
    public static func info(_ text: String) {
        text.withCString { idax_ui_info($0) }
    }

    // MARK: - Dialogs

    /// Show a Yes/No dialog. Returns `true` for Yes, `false` for No.
    public static func askYesNo(
        question: String, default defaultYes: Bool = true
    ) throws(IDAError) -> Bool {
        let out = try withOutput("ui.askYesNo", Int32(0)) { out in
            question.withCString { idax_ui_ask_yn($0, defaultYes ? 1 : 0, out) }
        }
        return out != 0
    }

    /// Show a string input dialog.
    public static func askString(
        prompt: String, default defaultValue: String = ""
    ) throws(IDAError) -> String {
        try withStringOutput("ui.askString") { out in
            prompt.withCString { p in
                defaultValue.withCString { d in
                    idax_ui_ask_string(p, d, out)
                }
            }
        }
    }

    /// Show a file chooser dialog.
    ///
    /// - Parameters:
    ///   - forSaving: `true` for a save dialog, `false` for an open dialog.
    ///   - defaultPath: Default file path shown in the dialog.
    ///   - prompt: Dialog title / prompt text.
    public static func askFile(
        forSaving: Bool, defaultPath: String = "", prompt: String = ""
    ) throws(IDAError) -> String {
        try withStringOutput("ui.askFile") { out in
            defaultPath.withCString { dp in
                prompt.withCString { p in
                    idax_ui_ask_file(forSaving ? 1 : 0, dp, p, out)
                }
            }
        }
    }

    /// Show an address input dialog.
    public static func askAddress(
        prompt: String, default defaultValue: Address = 0
    ) throws(IDAError) -> Address {
        try withOutput("ui.askAddress", UInt64(0)) { out in
            prompt.withCString { idax_ui_ask_address($0, defaultValue, out) }
        }
    }

    /// Show a long integer input dialog.
    public static func askLong(
        prompt: String, default defaultValue: Int64 = 0
    ) throws(IDAError) -> Int64 {
        try withOutput("ui.askLong", Int64(0)) { out in
            prompt.withCString { idax_ui_ask_long($0, defaultValue, out) }
        }
    }

    /// Show a form dialog from markup.
    public static func askForm(markup: String) throws(IDAError) -> Int32 {
        try withOutput("ui.askForm", Int32(0)) { out in
            markup.withCString { idax_ui_ask_form($0, out) }
        }
    }

    // MARK: - Navigation

    /// Jump to the given address in the disassembly view.
    public static func jumpTo(_ address: Address) throws(IDAError) {
        try checkStatus(idax_ui_jump_to(address), "ui.jumpTo")
    }

    /// Get the current screen (cursor) address.
    public static func screenAddress() throws(IDAError) -> Address {
        try withOutput("ui.screenAddress", UInt64(0)) { idax_ui_screen_address($0) }
    }

    /// Get the current selection range.
    ///
    /// Returns `(start, end)` or throws if no selection exists.
    public static func selection() throws(IDAError) -> (start: Address, end: Address) {
        var start: UInt64 = 0
        var end: UInt64 = 0
        try checkStatus(idax_ui_selection(&start, &end), "ui.selection")
        return (start, end)
    }

    // MARK: - Views

    /// Refresh all IDA views.
    public static func refreshAllViews() {
        idax_ui_refresh_all_views()
    }

    /// Get the IDA user directory path.
    public static func userDirectory() throws(IDAError) -> String {
        try withStringOutput("ui.userDirectory") { idax_ui_user_directory($0) }
    }

    // MARK: - Widget management

    /// Create a new widget with the given title.
    public static func createWidget(title: String) throws(IDAError) -> Widget {
        let handle = try withOutput("ui.createWidget", nil as IdaxWidgetHandle?) { out in
            title.withCString { idax_ui_create_widget($0, out) }
        }
        guard let handle else {
            throw IDAError(category: .internal, code: 0, message: "ui.createWidget returned nil handle")
        }
        return Widget(handle)
    }

    /// Find an existing widget by title.
    public static func findWidget(title: String) throws(IDAError) -> Widget {
        let handle = try withOutput("ui.findWidget", nil as IdaxWidgetHandle?) { out in
            title.withCString { idax_ui_find_widget($0, out) }
        }
        guard let handle else {
            throw IDAError(category: .notFound, code: 0, message: "widget not found: \(title)")
        }
        return Widget(handle)
    }

    // MARK: - Custom viewer

    /// Create a custom text viewer with initial lines.
    public static func createCustomViewer(
        title: String, lines: [String]
    ) throws(IDAError) -> CustomViewer {
        var handle: IdaxWidgetHandle? = nil
        let ret = lines.withCStringArray { ptrs, count in
            title.withCString { cTitle in
                idax_ui_create_custom_viewer(cTitle, ptrs, count, &handle)
            }
        }
        try checkStatus(ret, "ui.createCustomViewer")
        guard let handle else {
            throw IDAError(category: .internal, code: 0, message: "ui.createCustomViewer returned nil handle")
        }
        return CustomViewer(handle)
    }

    // MARK: - Timers

    /// Register a periodic timer.
    ///
    /// Returns a `UITimer` token that unregisters the timer on deinit.
    public static func registerTimer(intervalMs: Int32) throws(IDAError) -> UITimer {
        let token = try withOutput("ui.registerTimer", UInt64(0)) {
            idax_ui_register_timer(intervalMs, $0)
        }
        return UITimer(token: token)
    }

    /// Register a periodic timer with a callback.
    ///
    /// The callback returns a nonzero value to continue firing, or zero to stop.
    /// Returns a `UITimer` token that unregisters the timer on deinit.
    public static func registerTimer(
        intervalMs: Int32,
        callback: @escaping () -> Int32
    ) throws(IDAError) -> UITimer {
        let box = TimerCallbackBox(callback: callback)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_ui_register_timer_with_callback(intervalMs, timerTrampoline, ctx, &token),
                "ui.registerTimerWithCallback"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return UITimer(token: token, context: ctx)
    }

    // MARK: - Legacy event subscription

    /// Subscribe to a UI event by kind (legacy generic callback).
    public static func subscribe(
        kind: Int32,
        handler: @escaping (Int32, UInt64) -> Void
    ) throws(IDAError) -> UISubscription {
        let box = LegacyUIEventBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_ui_subscribe(kind, legacyUIEventTrampoline, ctx, &token),
                "ui.subscribe"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return UISubscription(token: token, context: ctx)
    }

    // MARK: - Typed event subscriptions

    /// Subscribe to database-closed events.
    public static func onDatabaseClosed(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onDatabaseClosed", handler) {
            idax_ui_on_database_closed($0, $1, $2)
        }
    }

    /// Subscribe to database-initialized events.
    public static func onDatabaseInited(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onDatabaseInited", handler) {
            idax_ui_on_database_inited($0, $1, $2)
        }
    }

    /// Subscribe to ready-to-run events.
    public static func onReadyToRun(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onReadyToRun", handler) {
            idax_ui_on_ready_to_run($0, $1, $2)
        }
    }

    /// Subscribe to screen-address-changed events.
    public static func onScreenAddressChanged(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onScreenAddressChanged", handler) {
            idax_ui_on_screen_ea_changed($0, $1, $2)
        }
    }

    /// Subscribe to current-widget-changed events.
    public static func onCurrentWidgetChanged(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onCurrentWidgetChanged", handler) {
            idax_ui_on_current_widget_changed($0, $1, $2)
        }
    }

    /// Subscribe to widget-visible events (any widget).
    public static func onWidgetVisible(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetVisible", handler) {
            idax_ui_on_widget_visible($0, $1, $2)
        }
    }

    /// Subscribe to widget-invisible events (any widget).
    public static func onWidgetInvisible(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetInvisible", handler) {
            idax_ui_on_widget_invisible($0, $1, $2)
        }
    }

    /// Subscribe to widget-closing events (any widget).
    public static func onWidgetClosing(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetClosing", handler) {
            idax_ui_on_widget_closing($0, $1, $2)
        }
    }

    /// Subscribe to widget-visible events for a specific widget.
    public static func onWidgetVisibleForWidget(
        _ widget: Widget,
        handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetVisibleForWidget", handler) {
            idax_ui_on_widget_visible_for_widget(widget.handle, $0, $1, $2)
        }
    }

    /// Subscribe to widget-invisible events for a specific widget.
    public static func onWidgetInvisibleForWidget(
        _ widget: Widget,
        handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetInvisibleForWidget", handler) {
            idax_ui_on_widget_invisible_for_widget(widget.handle, $0, $1, $2)
        }
    }

    /// Subscribe to widget-closing events for a specific widget.
    public static func onWidgetClosingForWidget(
        _ widget: Widget,
        handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onWidgetClosingForWidget", handler) {
            idax_ui_on_widget_closing_for_widget(widget.handle, $0, $1, $2)
        }
    }

    /// Subscribe to cursor-changed events.
    public static func onCursorChanged(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onCursorChanged", handler) {
            idax_ui_on_cursor_changed($0, $1, $2)
        }
    }

    /// Subscribe to view-activated events.
    public static func onViewActivated(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onViewActivated", handler) {
            idax_ui_on_view_activated($0, $1, $2)
        }
    }

    /// Subscribe to view-deactivated events.
    public static func onViewDeactivated(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onViewDeactivated", handler) {
            idax_ui_on_view_deactivated($0, $1, $2)
        }
    }

    /// Subscribe to view-created events.
    public static func onViewCreated(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onViewCreated", handler) {
            idax_ui_on_view_created($0, $1, $2)
        }
    }

    /// Subscribe to view-closed events.
    public static func onViewClosed(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onViewClosed", handler) {
            idax_ui_on_view_closed($0, $1, $2)
        }
    }

    /// Subscribe to all UI events.
    public static func onEvent(
        _ handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        try subscribeUIEvent("ui.onEvent", handler) {
            idax_ui_on_event($0, $1, $2)
        }
    }

    /// Subscribe to UI events with a filter.
    ///
    /// Only events accepted by `filter` (returning `true`) are delivered
    /// to `handler`.
    public static func onEventFiltered(
        filter: @escaping (UIEvent) -> Bool,
        handler: @escaping (UIEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        let box = UIEventFilteredBox(filter: filter, handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_ui_on_event_filtered(uiEventFilterTrampoline, uiEventFilteredHandlerTrampoline, ctx, &token),
                "ui.onEventFiltered"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return UISubscription(token: token, context: ctx)
    }

    // MARK: - Popup events

    /// Subscribe to popup-ready events.
    ///
    /// The handler receives a `PopupEvent` whose raw pointers can be passed
    /// to `attachDynamicAction`.
    public static func onPopupReady(
        _ handler: @escaping (PopupEvent) -> Void
    ) throws(IDAError) -> UISubscription {
        let box = PopupEventBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_ui_on_popup_ready(popupEventTrampoline, ctx, &token),
                "ui.onPopupReady"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return UISubscription(token: token, context: ctx)
    }

    /// Attach a dynamic action to a popup menu.
    ///
    /// Typically called from within an `onPopupReady` handler.
    ///
    /// - Parameters:
    ///   - popup: The raw popup pointer from `PopupEvent.rawPopup`.
    ///   - widget: The widget associated with the popup.
    ///   - actionId: Unique action identifier.
    ///   - label: Human-readable action label.
    ///   - callback: Closure invoked when the action is triggered.
    ///   - menuPath: Path in the menu hierarchy, or empty string.
    ///   - icon: Icon resource ID, or -1 for no icon.
    public static func attachDynamicAction(
        popup: UnsafeMutableRawPointer,
        widget: Widget,
        actionId: String,
        label: String,
        callback: @escaping () -> Void,
        menuPath: String = "",
        icon: Int32 = -1
    ) throws(IDAError) {
        let box = ActionCallbackBox(callback: callback)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        do {
            try checkStatus(
                actionId.withCString { cId in
                    label.withCString { cLabel in
                        menuPath.withCString { cMenu in
                            idax_ui_attach_dynamic_action(
                                popup, widget.handle,
                                cId, cLabel,
                                actionCallbackTrampoline, ctx,
                                cMenu, icon
                            )
                        }
                    }
                },
                "ui.attachDynamicAction"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
    }

    // MARK: - Rendering events

    /// Subscribe to rendering-info events.
    ///
    /// The handler receives a `RenderingContext` to which entries can be added.
    public static func onRenderingInfo(
        _ handler: @escaping (RenderingContext) -> Void
    ) throws(IDAError) -> UISubscription {
        let box = RenderingEventBox(handler: handler)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var token: UInt64 = 0
        do {
            try checkStatus(
                idax_ui_on_rendering_info(renderingEventTrampoline, ctx, &token),
                "ui.onRenderingInfo"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(ctx).release()
            throw error
        }
        return UISubscription(token: token, context: ctx)
    }

    /// Explicitly unsubscribe a UI event by token.
    ///
    /// Prefer letting `UISubscription` handle cleanup via RAII.
    public static func unsubscribe(token: UInt64) {
        idax_ui_unsubscribe(token)
    }
}

// MARK: - RenderingContext

/// Opaque rendering event context.
///
/// Passed to `onRenderingInfo` handlers. Use ``addEntry(_:)`` to add
/// line rendering entries.
public struct RenderingContext: @unchecked Sendable {
    private let ptr: UnsafeMutableRawPointer

    init(_ ptr: UnsafeMutableRawPointer) { self.ptr = ptr }

    /// Add a line render entry to this rendering event.
    public func addEntry(_ entry: LineRenderEntry) {
        var raw = IdaxLineRenderEntry(
            line_number: entry.lineNumber,
            bg_color: entry.backgroundColor,
            start_column: entry.startColumn,
            length: entry.length,
            character_range: entry.characterRange
        )
        ptr.withMemoryRebound(to: IdaxRenderingEvent.self, capacity: 1) {
            idax_ui_rendering_event_add_entry($0, &raw)
        }
    }
}

// MARK: - Callback boxes

private final class TimerCallbackBox {
    let callback: () -> Int32
    init(callback: @escaping () -> Int32) { self.callback = callback }
}

private final class LegacyUIEventBox {
    let handler: (Int32, UInt64) -> Void
    init(handler: @escaping (Int32, UInt64) -> Void) { self.handler = handler }
}

private final class UIEventBox {
    let handler: (UIEvent) -> Void
    init(handler: @escaping (UIEvent) -> Void) { self.handler = handler }
}

private final class UIEventFilteredBox {
    let filter: (UIEvent) -> Bool
    let handler: (UIEvent) -> Void
    init(filter: @escaping (UIEvent) -> Bool, handler: @escaping (UIEvent) -> Void) {
        self.filter = filter
        self.handler = handler
    }
}

private final class PopupEventBox {
    let handler: (PopupEvent) -> Void
    init(handler: @escaping (PopupEvent) -> Void) { self.handler = handler }
}

private final class ActionCallbackBox {
    let callback: () -> Void
    init(callback: @escaping () -> Void) { self.callback = callback }
}

private final class RenderingEventBox {
    let handler: (RenderingContext) -> Void
    init(handler: @escaping (RenderingContext) -> Void) {
        self.handler = handler
    }
}

private final class WidgetHostBox {
    let callback: (UnsafeMutableRawPointer) -> Void
    init(callback: @escaping (UnsafeMutableRawPointer) -> Void) {
        self.callback = callback
    }
}

// MARK: - Trampolines

private func timerTrampoline(ctx: UnsafeMutableRawPointer?) -> Int32 {
    guard let ctx else { return 0 }
    let box = Unmanaged<TimerCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.callback()
}

private func legacyUIEventTrampoline(
    ctx: UnsafeMutableRawPointer?,
    eventKind: Int32,
    address: UInt64
) {
    guard let ctx else { return }
    let box = Unmanaged<LegacyUIEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(eventKind, address)
}

private func uiEventExTrampoline(
    ctx: UnsafeMutableRawPointer?,
    event: UnsafePointer<IdaxUIEvent>?
) {
    guard let ctx, let event else { return }
    let box = Unmanaged<UIEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(makeUIEvent(event))
}

private func uiEventFilterTrampoline(
    ctx: UnsafeMutableRawPointer?,
    event: UnsafePointer<IdaxUIEvent>?
) -> Int32 {
    guard let ctx, let event else { return 0 }
    let box = Unmanaged<UIEventFilteredBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.filter(makeUIEvent(event)) ? 1 : 0
}

private func uiEventFilteredHandlerTrampoline(
    ctx: UnsafeMutableRawPointer?,
    event: UnsafePointer<IdaxUIEvent>?
) {
    guard let ctx, let event else { return }
    let box = Unmanaged<UIEventFilteredBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(makeUIEvent(event))
}

private func popupEventTrampoline(
    ctx: UnsafeMutableRawPointer?,
    event: UnsafePointer<IdaxPopupEvent>?
) {
    guard let ctx, let event else { return }
    let box = Unmanaged<PopupEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(makePopupEvent(event))
}

private func actionCallbackTrampoline(ctx: UnsafeMutableRawPointer?) {
    guard let ctx else { return }
    let box = Unmanaged<ActionCallbackBox>.fromOpaque(ctx).takeUnretainedValue()
    box.callback()
}

private func renderingEventTrampoline(
    ctx: UnsafeMutableRawPointer?,
    event: UnsafeMutablePointer<IdaxRenderingEvent>?
) {
    guard let ctx, let event else { return }
    let box = Unmanaged<RenderingEventBox>.fromOpaque(ctx).takeUnretainedValue()
    box.handler(RenderingContext(event))
}

private func widgetHostTrampoline(
    ctx: UnsafeMutableRawPointer?,
    host: UnsafeMutableRawPointer?
) -> Int32 {
    guard let ctx, let host else { return 1 }
    let box = Unmanaged<WidgetHostBox>.fromOpaque(ctx).takeUnretainedValue()
    box.callback(host)
    return 0
}

// MARK: - Conversion helpers

private func makeUIEvent(_ raw: UnsafePointer<IdaxUIEvent>) -> UIEvent {
    UIEvent(
        kind: raw.pointee.kind,
        address: raw.pointee.address,
        previousAddress: raw.pointee.previous_address,
        widgetID: raw.pointee.widget_id,
        previousWidgetID: raw.pointee.previous_widget_id,
        isNewDatabase: raw.pointee.is_new_database != 0,
        startupScript: borrowCString(raw.pointee.startup_script),
        widgetTitle: borrowCString(raw.pointee.widget_title)
    )
}

private func makePopupEvent(_ raw: UnsafePointer<IdaxPopupEvent>) -> PopupEvent {
    PopupEvent(
        widgetID: raw.pointee.widget_id,
        widgetTitle: borrowCString(raw.pointee.widget_title),
        widgetType: raw.pointee.widget_type,
        rawWidget: raw.pointee.widget,
        rawPopup: raw.pointee.popup
    )
}

// MARK: - Private subscription helper

/// Shared helper for typed UI event subscriptions to reduce boilerplate.
///
/// Boxes the handler, retains it, calls the C shim, and wraps the result
/// in a `UISubscription`.
private func subscribeUIEvent(
    _ fallback: String,
    _ handler: @escaping (UIEvent) -> Void,
    _ shimCall: (IdaxUIEventExCallback?, UnsafeMutableRawPointer?, UnsafeMutablePointer<UInt64>) -> Int32
) throws(IDAError) -> UISubscription {
    let box = UIEventBox(handler: handler)
    let ctx = Unmanaged.passRetained(box).toOpaque()
    var token: UInt64 = 0
    do {
        try checkStatus(shimCall(uiEventExTrampoline, ctx, &token), fallback)
    } catch {
        Unmanaged<AnyObject>.fromOpaque(ctx).release()
        throw error
    }
    return UISubscription(token: token, context: ctx)
}

// MARK: - String array helper

/// Execute a closure with an array of C strings (`const char* const*`)
/// backed by the given Swift strings. The C pointers are only valid
/// for the duration of the closure.
private extension Array where Element == String {
    func withCStringArray<R>(
        _ body: (UnsafePointer<UnsafePointer<CChar>?>?, Int) -> R
    ) -> R {
        let cStrings = map { strdup($0) }
        defer { cStrings.forEach { free($0) } }

        return cStrings.withUnsafeBufferPointer { buf in
            buf.baseAddress!.withMemoryRebound(
                to: UnsafePointer<CChar>?.self,
                capacity: cStrings.count
            ) { ptr in
                body(ptr, cStrings.count)
            }
        }
    }
}
