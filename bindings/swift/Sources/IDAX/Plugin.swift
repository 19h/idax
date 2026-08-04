internal import CIDAX
import Darwin

/// Snapshot of the action invocation context.
///
/// Maps directly to C `IdaxPluginActionContext`.
public struct ActionContext: @unchecked Sendable {
    public let actionId: String
    public let widgetTitle: String
    public let widgetType: Int32
    public let currentAddress: Address
    public let currentValue: Address
    public let hasSelection: Bool
    public let isExternalAddress: Bool
    public let registerName: String
    public let widgetHandle: UnsafeMutableRawPointer?
    public let focusedWidgetHandle: UnsafeMutableRawPointer?
    public let decompilerViewHandle: UnsafeMutableRawPointer?

    init(raw: IdaxPluginActionContext) {
        self.actionId = borrowCString(raw.action_id)
        self.widgetTitle = borrowCString(raw.widget_title)
        self.widgetType = raw.widget_type
        self.currentAddress = raw.current_address
        self.currentValue = raw.current_value
        self.hasSelection = raw.has_selection != 0
        self.isExternalAddress = raw.is_external_address != 0
        self.registerName = borrowCString(raw.register_name)
        self.widgetHandle = raw.widget_handle
        self.focusedWidgetHandle = raw.focused_widget_handle
        self.decompilerViewHandle = raw.decompiler_view_handle
    }
}

/// RAII action registration token. Unregisters the action on deinit.
public struct ActionRegistration: ~Copyable, @unchecked Sendable {
    private let cActionId: UnsafeMutablePointer<CChar>
    private let handlerContext: UnsafeMutableRawPointer
    private let enabledContext: UnsafeMutableRawPointer?

    init(actionId: String,
         handlerContext: UnsafeMutableRawPointer,
         enabledContext: UnsafeMutableRawPointer?) {
        self.cActionId = strdup(actionId)!
        self.handlerContext = handlerContext
        self.enabledContext = enabledContext
    }

    deinit {
        idax_plugin_unregister_action(cActionId)
        free(cActionId)
        Unmanaged<AnyObject>.fromOpaque(handlerContext).release()
        if let enabledContext {
            Unmanaged<AnyObject>.fromOpaque(enabledContext).release()
        }
    }

    /// Explicitly unregister the action and release resources.
    public consuming func unregister() {
        idax_plugin_unregister_action(cActionId)
        free(cActionId)
        Unmanaged<AnyObject>.fromOpaque(handlerContext).release()
        if let enabledContext {
            Unmanaged<AnyObject>.fromOpaque(enabledContext).release()
        }
        discard self
    }
}

/// Plugin action management.
///
/// Mirrors C++ `ida::plugin`.
public enum Plugin {

    // MARK: - Action Registration

    /// Register a plugin action with a simple handler.
    ///
    /// Returns an `ActionRegistration` that automatically unregisters
    /// the action when it goes out of scope.
    ///
    /// - Parameters:
    ///   - id: Unique action identifier (e.g. "myPlugin:doSomething").
    ///   - label: Human-readable label shown in menus.
    ///   - hotkey: Keyboard shortcut (e.g. "Ctrl+Shift+X"), or empty string for none.
    ///   - tooltip: Tooltip text, or empty string for none.
    ///   - icon: Icon resource ID, or -1 for no icon.
    ///   - handler: Closure invoked when the action is triggered.
    ///   - enabledCheck: Optional closure that returns whether the action is enabled.
    public static func registerAction(
        id: String,
        label: String,
        hotkey: String = "",
        tooltip: String = "",
        icon: Int32 = -1,
        handler: @escaping () -> Void,
        enabledCheck: (() -> Bool)? = nil
    ) throws(IDAError) -> ActionRegistration {
        let handlerBox = ActionHandlerBox(handler: handler)
        let handlerCtx = Unmanaged.passRetained(handlerBox).toOpaque()

        let enabledBox: ActionEnabledCheckBox?
        let enabledCtx: UnsafeMutableRawPointer?
        let enabledFn: IdaxActionEnabledCheck?
        if let enabledCheck {
            let box = ActionEnabledCheckBox(check: enabledCheck)
            enabledBox = box
            enabledCtx = Unmanaged.passRetained(box).toOpaque()
            enabledFn = actionEnabledCheckTrampoline
        } else {
            enabledBox = nil
            enabledCtx = nil
            enabledFn = nil
        }

        do {
            try checkStatus(
                id.withCString { cId in
                    label.withCString { cLabel in
                        hotkey.withCString { cHotkey in
                            tooltip.withCString { cTooltip in
                                idax_plugin_register_action(
                                    cId, cLabel, cHotkey, cTooltip, icon,
                                    actionHandlerTrampoline, handlerCtx,
                                    enabledFn, enabledCtx
                                )
                            }
                        }
                    }
                },
                "plugin.registerAction"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(handlerCtx).release()
            if let enabledCtx {
                Unmanaged<AnyObject>.fromOpaque(enabledCtx).release()
            }
            throw error
        }

        return ActionRegistration(
            actionId: id,
            handlerContext: handlerCtx,
            enabledContext: enabledCtx
        )
    }

    /// Register a plugin action with an extended handler that receives
    /// the action context.
    ///
    /// The `handlerEx` closure receives an `ActionContext` snapshot
    /// describing the UI state at invocation time.
    ///
    /// - Parameters:
    ///   - id: Unique action identifier.
    ///   - label: Human-readable label shown in menus.
    ///   - hotkey: Keyboard shortcut, or empty string for none.
    ///   - tooltip: Tooltip text, or empty string for none.
    ///   - icon: Icon resource ID, or -1 for no icon.
    ///   - handler: Simple handler (called when no context is available).
    ///   - handlerEx: Extended handler receiving `ActionContext`.
    ///   - enabledCheck: Optional simple enabled check.
    ///   - enabledCheckEx: Optional extended enabled check receiving `ActionContext`.
    public static func registerActionEx(
        id: String,
        label: String,
        hotkey: String = "",
        tooltip: String = "",
        icon: Int32 = -1,
        handler: @escaping () -> Void,
        handlerEx: @escaping (ActionContext) -> Void,
        enabledCheck: (() -> Bool)? = nil,
        enabledCheckEx: ((ActionContext) -> Bool)? = nil
    ) throws(IDAError) -> ActionRegistration {
        let handlerBox = ActionHandlerExBox(handler: handler, handlerEx: handlerEx)
        let handlerCtx = Unmanaged.passRetained(handlerBox).toOpaque()

        let enabledBox: ActionEnabledCheckExBox?
        let enabledCtx: UnsafeMutableRawPointer?
        let enabledFn: IdaxActionEnabledCheck?
        let enabledFnEx: IdaxActionEnabledCheckEx?
        if let enabledCheck {
            let box = ActionEnabledCheckExBox(
                check: enabledCheck,
                checkEx: enabledCheckEx
            )
            enabledBox = box
            enabledCtx = Unmanaged.passRetained(box).toOpaque()
            enabledFn = actionEnabledCheckExSimpleTrampoline
            enabledFnEx = enabledCheckEx != nil ? actionEnabledCheckExTrampoline : nil
        } else if let enabledCheckEx {
            let box = ActionEnabledCheckExBox(
                check: nil,
                checkEx: enabledCheckEx
            )
            enabledBox = box
            enabledCtx = Unmanaged.passRetained(box).toOpaque()
            enabledFn = nil
            enabledFnEx = actionEnabledCheckExTrampoline
        } else {
            enabledBox = nil
            enabledCtx = nil
            enabledFn = nil
            enabledFnEx = nil
        }

        do {
            try checkStatus(
                id.withCString { cId in
                    label.withCString { cLabel in
                        hotkey.withCString { cHotkey in
                            tooltip.withCString { cTooltip in
                                idax_plugin_register_action_ex(
                                    cId, cLabel, cHotkey, cTooltip, icon,
                                    actionHandlerExSimpleTrampoline,
                                    actionHandlerExTrampoline,
                                    handlerCtx,
                                    enabledFn, enabledFnEx, enabledCtx
                                )
                            }
                        }
                    }
                },
                "plugin.registerActionEx"
            )
        } catch {
            Unmanaged<AnyObject>.fromOpaque(handlerCtx).release()
            if let enabledCtx {
                Unmanaged<AnyObject>.fromOpaque(enabledCtx).release()
            }
            throw error
        }

        return ActionRegistration(
            actionId: id,
            handlerContext: handlerCtx,
            enabledContext: enabledCtx
        )
    }

    /// Unregister an action by its identifier.
    ///
    /// Prefer letting `ActionRegistration` handle cleanup via RAII.
    /// Use this only for actions registered outside this wrapper.
    public static func unregisterAction(_ actionId: String) throws(IDAError) {
        try checkStatus(
            actionId.withCString { idax_plugin_unregister_action($0) },
            "plugin.unregisterAction"
        )
    }

    // MARK: - Menu / Toolbar / Popup Attachment

    /// Attach an action to a menu path.
    public static func attachToMenu(
        _ menuPath: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            menuPath.withCString { cMenu in
                actionId.withCString { cAction in
                    idax_plugin_attach_to_menu(cMenu, cAction)
                }
            },
            "plugin.attachToMenu"
        )
    }

    /// Attach an action to a toolbar.
    public static func attachToToolbar(
        _ toolbar: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            toolbar.withCString { cToolbar in
                actionId.withCString { cAction in
                    idax_plugin_attach_to_toolbar(cToolbar, cAction)
                }
            },
            "plugin.attachToToolbar"
        )
    }

    /// Attach an action to a widget popup menu.
    public static func attachToPopup(
        _ widgetTitle: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            widgetTitle.withCString { cWidget in
                actionId.withCString { cAction in
                    idax_plugin_attach_to_popup(cWidget, cAction)
                }
            },
            "plugin.attachToPopup"
        )
    }

    /// Detach an action from a menu path.
    public static func detachFromMenu(
        _ menuPath: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            menuPath.withCString { cMenu in
                actionId.withCString { cAction in
                    idax_plugin_detach_from_menu(cMenu, cAction)
                }
            },
            "plugin.detachFromMenu"
        )
    }

    /// Detach an action from a toolbar.
    public static func detachFromToolbar(
        _ toolbar: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            toolbar.withCString { cToolbar in
                actionId.withCString { cAction in
                    idax_plugin_detach_from_toolbar(cToolbar, cAction)
                }
            },
            "plugin.detachFromToolbar"
        )
    }

    /// Detach an action from a widget popup menu.
    public static func detachFromPopup(
        _ widgetTitle: String, actionId: String
    ) throws(IDAError) {
        try checkStatus(
            widgetTitle.withCString { cWidget in
                actionId.withCString { cAction in
                    idax_plugin_detach_from_popup(cWidget, cAction)
                }
            },
            "plugin.detachFromPopup"
        )
    }

    // MARK: - Action Context Host Access

    /// Retrieve the raw widget host pointer from an action context.
    public static func widgetHost(
        from context: ActionContext
    ) throws(IDAError) -> UnsafeMutableRawPointer {
        var raw = makeRawContext(context)
        defer { freeRawContext(&raw) }
        var out: UnsafeMutableRawPointer? = nil
        try checkStatus(
            idax_plugin_action_context_widget_host(&raw, &out),
            "plugin.widgetHost"
        )
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil widget host")
        }
        return out
    }

    /// Access the widget host through a scoped closure.
    ///
    /// The host pointer is valid only for the duration of the closure.
    public static func withWidgetHost(
        from context: ActionContext,
        _ body: @escaping (UnsafeMutableRawPointer) -> Void
    ) throws(IDAError) {
        var raw = makeRawContext(context)
        defer { freeRawContext(&raw) }
        let box = HostCallbackBox(callback: body)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<AnyObject>.fromOpaque(ctx).release() }
        try checkStatus(
            idax_plugin_action_context_with_widget_host(
                &raw, hostCallbackTrampoline, ctx
            ),
            "plugin.withWidgetHost"
        )
    }

    /// Retrieve the raw decompiler view host pointer from an action context.
    public static func decompilerViewHost(
        from context: ActionContext
    ) throws(IDAError) -> UnsafeMutableRawPointer {
        var raw = makeRawContext(context)
        defer { freeRawContext(&raw) }
        var out: UnsafeMutableRawPointer? = nil
        try checkStatus(
            idax_plugin_action_context_decompiler_view_host(&raw, &out),
            "plugin.decompilerViewHost"
        )
        guard let out else {
            throw IDAError(category: .internal, code: 0, message: "nil decompiler view host")
        }
        return out
    }

    /// Access the decompiler view host through a scoped closure.
    ///
    /// The host pointer is valid only for the duration of the closure.
    public static func withDecompilerViewHost(
        from context: ActionContext,
        _ body: @escaping (UnsafeMutableRawPointer) -> Void
    ) throws(IDAError) {
        var raw = makeRawContext(context)
        defer { freeRawContext(&raw) }
        let box = HostCallbackBox(callback: body)
        let ctx = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<AnyObject>.fromOpaque(ctx).release() }
        try checkStatus(
            idax_plugin_action_context_with_decompiler_view_host(
                &raw, hostCallbackTrampoline, ctx
            ),
            "plugin.withDecompilerViewHost"
        )
    }

    // MARK: - Plugin Invocation

    /// Whether a plugin can be located by its name.
    ///
    /// - Parameter name: The plugin's short name (e.g. "dscu") — the base
    ///   name of the plugin module, not a file path.
    /// - Returns: `true` when the plugin is registered and available to run.
    public static func isPluginAvailable(_ name: String) -> Bool {
        name.withCString { idax_plugin_is_plugin_available($0) } != 0
    }

    /// Load (if needed) and run a plugin by name.
    ///
    /// Invokes one of IDA's bundled plugins (such as "dscu") or any
    /// third-party plugin. The meaning of `argument` is defined entirely by
    /// the target plugin. For dyld shared cache utilities, prefer the typed
    /// `DyldCache` API over calling this directly.
    ///
    /// - Parameters:
    ///   - name: The plugin's short name.
    ///   - argument: Plugin-specific argument (0 by default).
    public static func runPlugin(
        _ name: String, argument: Int = 0
    ) throws(IDAError) {
        try checkStatus(
            name.withCString { idax_plugin_run_plugin($0, argument) },
            "plugin.runPlugin"
        )
    }
}

// MARK: - Callback Boxes

private final class ActionHandlerBox {
    let handler: () -> Void
    init(handler: @escaping () -> Void) { self.handler = handler }
}

private final class ActionEnabledCheckBox {
    let check: () -> Bool
    init(check: @escaping () -> Bool) { self.check = check }
}

private final class ActionHandlerExBox {
    let handler: () -> Void
    let handlerEx: (ActionContext) -> Void
    init(handler: @escaping () -> Void,
         handlerEx: @escaping (ActionContext) -> Void) {
        self.handler = handler
        self.handlerEx = handlerEx
    }
}

private final class ActionEnabledCheckExBox {
    let check: (() -> Bool)?
    let checkEx: ((ActionContext) -> Bool)?
    init(check: (() -> Bool)?,
         checkEx: ((ActionContext) -> Bool)?) {
        self.check = check
        self.checkEx = checkEx
    }
}

private final class HostCallbackBox {
    let callback: (UnsafeMutableRawPointer) -> Void
    init(callback: @escaping (UnsafeMutableRawPointer) -> Void) {
        self.callback = callback
    }
}

// MARK: - Trampolines

private func actionHandlerTrampoline(context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let box = Unmanaged<ActionHandlerBox>.fromOpaque(context).takeUnretainedValue()
    box.handler()
}

private func actionEnabledCheckTrampoline(context: UnsafeMutableRawPointer?) -> Int32 {
    guard let context else { return 0 }
    let box = Unmanaged<ActionEnabledCheckBox>.fromOpaque(context).takeUnretainedValue()
    return box.check() ? 1 : 0
}

private func actionHandlerExSimpleTrampoline(context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let box = Unmanaged<ActionHandlerExBox>.fromOpaque(context).takeUnretainedValue()
    box.handler()
}

private func actionHandlerExTrampoline(
    context: UnsafeMutableRawPointer?,
    actionContext: UnsafePointer<IdaxPluginActionContext>?
) {
    guard let context, let actionContext else { return }
    let box = Unmanaged<ActionHandlerExBox>.fromOpaque(context).takeUnretainedValue()
    box.handlerEx(ActionContext(raw: actionContext.pointee))
}

private func actionEnabledCheckExSimpleTrampoline(
    context: UnsafeMutableRawPointer?
) -> Int32 {
    guard let context else { return 0 }
    let box = Unmanaged<ActionEnabledCheckExBox>.fromOpaque(context).takeUnretainedValue()
    return (box.check?() ?? true) ? 1 : 0
}

private func actionEnabledCheckExTrampoline(
    context: UnsafeMutableRawPointer?,
    actionContext: UnsafePointer<IdaxPluginActionContext>?
) -> Int32 {
    guard let context, let actionContext else { return 0 }
    let box = Unmanaged<ActionEnabledCheckExBox>.fromOpaque(context).takeUnretainedValue()
    return (box.checkEx?(ActionContext(raw: actionContext.pointee)) ?? true) ? 1 : 0
}

private func hostCallbackTrampoline(
    context: UnsafeMutableRawPointer?,
    host: UnsafeMutableRawPointer?
) -> Int32 {
    guard let context, let host else { return 1 }
    let box = Unmanaged<HostCallbackBox>.fromOpaque(context).takeUnretainedValue()
    box.callback(host)
    return 0
}

// MARK: - Internal Helpers

/// Create an `IdaxPluginActionContext` with strdup'd C strings.
/// Must be paired with `freeRawContext` to avoid leaks.
private func makeRawContext(_ ctx: ActionContext) -> IdaxPluginActionContext {
    // `type_ref_name` / `type_ref_type` are Rust-binding-specific extensions
    // on the shared C ABI for routing IDA Local-Types selections through
    // action contexts; Swift consumers do not currently surface them and
    // leave the slots empty.
    IdaxPluginActionContext(
        action_id: strdup(ctx.actionId),
        widget_title: strdup(ctx.widgetTitle),
        widget_type: ctx.widgetType,
        current_address: ctx.currentAddress,
        current_value: ctx.currentValue,
        has_selection: ctx.hasSelection ? 1 : 0,
        is_external_address: ctx.isExternalAddress ? 1 : 0,
        register_name: strdup(ctx.registerName),
        widget_handle: ctx.widgetHandle,
        focused_widget_handle: ctx.focusedWidgetHandle,
        decompiler_view_handle: ctx.decompilerViewHandle,
        type_ref_name: nil,
        type_ref_type: nil
    )
}

/// Free the strdup'd strings in a raw action context.
private func freeRawContext(_ raw: inout IdaxPluginActionContext) {
    free(UnsafeMutablePointer(mutating: raw.action_id))
    free(UnsafeMutablePointer(mutating: raw.widget_title))
    free(UnsafeMutablePointer(mutating: raw.register_name))
}
