internal import CIDAX

/// Plugin actions, shortcuts, and module authoring.
public enum Plugin {
    /// Canonical SDK plugin export flags, sampled when the addon is loaded.
    /// The native bridge always includes the multi-database lifecycle flag.
    public struct ExportFlags: Sendable {
        public var modifiesDatabase = false
        public var requestsRedraw = false
        public var segmentScoped = false
        public var unloadAfterRun = false
        public var hidden = false
        public var debuggerOnly = false
        public var processorSpecific = false
        public var loadAtStartup = false
        public var extraRawFlags: Int32 = 0
        public init() {}
        internal var encoded: UInt64 {
            let choices = [modifiesDatabase, requestsRedraw, segmentScoped, unloadAfterRun,
                           hidden, debuggerOnly, processorSpecific, loadAtStartup]
            return choices.enumerated().reduce(UInt64(0)) { $0 | ($1.element ? 1 << $1.offset : 0) }
        }
    }
    public struct Information: Sendable {
        public var name: String
        public var shortcut: String
        public var comment: String
        public var help: String
        public var icon: Int32
        public init(
            name: String, shortcut: String = "", comment: String = "", help: String = "", icon: Int32 = -1
        ) {
            self.name = name
            self.shortcut = shortcut
            self.comment = comment
            self.help = help
            self.icon = icon
        }
    }
    public struct ActionContext {
        public let identifier: String
        public let widgetTitle: String
        public let widgetType: UI.WidgetType
        public let currentAddress: Address
        public let currentValue: UInt64
        public let hasSelection: Bool
        public let isExternalAddress: Bool
        public let registerName: String
        internal let lease: CallbackLease?
        internal init(_ raw: IdaxSwiftNotification) throws(IDAError) {
            identifier = try borrowCString(raw.name, "action.identifier")
            widgetTitle = try borrowCString(raw.text, "action.widgetTitle")
            widgetType = UI.WidgetType(native: raw.number)
            currentAddress = raw.address
            currentValue = raw.secondary_address
            hasSelection = raw.flag != 0
            isExternalAddress = raw.secondary_flag != 0
            registerName = try borrowCString(raw.secondary_text, "action.registerName")
            lease = raw.lease.map(CallbackLease.init)
        }
    }
    public struct Action {
        public var identifier: String
        public var label: String
        public var shortcut: String
        public var tooltip: String
        public var icon: Int32
        public var handler: (ActionContext) throws(IDAError) -> Void
        public var isEnabled: (ActionContext) throws(IDAError) -> Bool
        public init(
            identifier: String, label: String, shortcut: String = "", tooltip: String = "", icon: Int32 = -1,
            isEnabled: @escaping (ActionContext) throws(IDAError) -> Bool = { _ in true },
            handler: @escaping (ActionContext) throws(IDAError) -> Void
        ) {
            self.identifier = identifier
            self.label = label
            self.shortcut = shortcut
            self.tooltip = tooltip
            self.icon = icon
            self.isEnabled = isEnabled
            self.handler = handler
        }
    }
    public static func register(_ action: Action) throws(IDAError) -> Registration {
        let text = try LifecycleStrings([action.identifier, action.label, action.shortcut, action.tooltip])
        var native = IdaxSwiftAction(
            identifier: text[0], label: text[1], shortcut: text[2], tooltip: text[3], icon: action.icon)
        let callbacks = callbackDescriptor { event, reply in
            let context = try ActionContext(event)
            if event.kind == 1 {
                reply.pointee.decision = try action.isEnabled(context) ? 1 : 0
            } else {
                try action.handler(context)
            }
        }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("plugin.registerAction") {
            idax_swift_action_register(&native, callbacks, &handle, $0)
        }
        return Registration(owning: try requireLifecycleHandle(handle, "plugin.registerAction"))
    }
    public final class Shortcut {
        private let registration: Registration
        public private(set) var shortcut: String
        internal init(_ registration: Registration, shortcut: String) {
            self.registration = registration
            self.shortcut = shortcut
        }
        public var isActive: Bool { get throws(IDAError) { try registration.isActive() } }
        public func activate() throws(IDAError) { try registration.activateShortcut() }
        public func close() throws(IDAError) {
            try registration.close()
            shortcut = ""
        }
    }
    public static func registerShortcut(_ shortcut: String, handler: @escaping () throws(IDAError) -> Void)
        throws(IDAError) -> Shortcut
    {
        let text = try LifecycleStrings([shortcut])
        let callbacks = callbackDescriptor { _, _ in try handler() }
        var handle: UnsafeMutableRawPointer?
        try bridgeCall("plugin.registerShortcut") {
            idax_swift_hotkey_register(text[0], callbacks, &handle, $0)
        }
        return Shortcut(Registration(owning: try requireLifecycleHandle(handle, "plugin.registerShortcut")),
                        shortcut: shortcut)
    }
    public static func activateAction(_ identifier: String) throws(IDAError) {
        let text = try LifecycleStrings([identifier])
        try bridgeCall("plugin.activateAction") { idax_swift_action_activate(text[0], $0) }
    }
    public enum Attachment { case menu(String), toolbar(String), popup(String) }
    public static func attach(_ identifier: String, to attachment: Attachment) throws(IDAError) {
        try changeAttachment(identifier, attachment, false)
    }
    public static func detach(_ identifier: String, from attachment: Attachment) throws(IDAError) {
        try changeAttachment(identifier, attachment, true)
    }
    private static func changeAttachment(_ identifier: String, _ attachment: Attachment, _ detach: Bool)
        throws(IDAError)
    {
        let location: Int32
        let path: String
        switch attachment {
        case .menu(let value):
            location = 0
            path = value
        case .toolbar(let value):
            location = 1
            path = value
        case .popup(let value):
            location = 2
            path = value
        }
        let text = try LifecycleStrings([path, identifier])
        try bridgeCall("plugin.attachment") {
            idax_swift_action_attach(location, detach ? 1 : 0, text[0], text[1], $0)
        }
    }
}

/// Every customization is a protocol requirement, including methods with a
/// default implementation. Module factories are materialized by the native
/// export target so IDA receives its actual PLUGIN descriptor.
public protocol PluginModule: AnyObject {
    var information: Plugin.Information { get }
    var exportFlags: Plugin.ExportFlags { get }
    func initialize() throws(IDAError) -> Bool
    func run(argument: UInt64) throws(IDAError)
    func terminate()
}
extension PluginModule {
    public var exportFlags: Plugin.ExportFlags { .init() }
    public func initialize() throws(IDAError) -> Bool { true }
    public func terminate() {}
}

/// Used by the generated native module bootstrap to report a typed failure.
/// Module export is valid only while its native factory is invoking bootstrap.
public enum ModuleExport {
    public static func fail(_ error: IDAError) {
        var native = IdaxSwiftError()
        writeCallbackError(error, to: &native)
        idax_swift_module_fail(&native)
        idax_swift_error_free(&native)
    }
}
internal func moduleStrings(_ lease: UnsafeMutableRawPointer, _ field: Int32, _ values: [String])
    throws(IDAError)
{
    let strings = try LifecycleStrings(values)
    let pointers = strings.pointers
    try bridgeCall("module.metadata.strings") { error in
        pointers.withUnsafeBufferPointer {
            idax_swift_module_strings(lease, field, $0.baseAddress, $0.count, error)
        }
    }
}
internal func moduleNumbers(_ lease: UnsafeMutableRawPointer, _ field: Int32, _ values: [Int64])
    throws(IDAError)
{
    try bridgeCall("module.metadata.numbers") { error in
        values.withUnsafeBufferPointer {
            idax_swift_module_numbers(lease, field, $0.baseAddress, $0.count, error)
        }
    }
}
extension Plugin {
    public static func exportModule(_ module: any PluginModule) throws(IDAError) {
        let descriptor = callbackDescriptor { event, reply in
            switch event.kind {
            case 0:
                let lease = try requireLifecycleHandle(event.lease, "module.plugin.information")
                let info = module.information
                try moduleStrings(lease, 0, [info.name, info.shortcut, info.comment, info.help])
                try moduleNumbers(lease, 0, [Int64(info.icon)])
            case 1: reply.pointee.decision = try module.initialize() ? 1 : 0
            case 2: try module.run(argument: event.identity)
            case 3: module.terminate()
            case 4:
                let flags = module.exportFlags
                reply.pointee.unsigned_integer = flags.encoded
                reply.pointee.integer = Int64(flags.extraRawFlags)
            default: throw IDAError(category: .unsupported, message: "Unknown plugin callback")
            }
        }
        try bridgeCall("module.exportPlugin") { idax_swift_module_publish(0, descriptor, $0) }
    }
    public static func isAvailable(_ name: String) throws(IDAError) -> Bool {
        let text = try LifecycleStrings([name])
        return try withOutput("plugin.isAvailable", initial: Int32(0)) {
            idax_plugin_is_plugin_available(text[0], $0)
        } != 0
    }
    public static func run(_ name: String, argument: Int = 0) throws(IDAError) {
        guard argument >= 0 else {
            throw IDAError(category: .validation, message: "Negative plugin argument")
        }
        try requireRuntimeThread("plugin.run")
        let text = try LifecycleStrings([name])
        try checkStatus(idax_plugin_run_plugin(text[0], argument), "plugin.run")
    }
}

extension Plugin {
    public struct TypeReference {
        public var name: String
        public var type: TypeInfo
        public init(name: String = "", type: TypeInfo) {
            self.name = name
            self.type = type
        }
    }
}
extension Plugin.ActionContext {
    public func decompilerView() throws(IDAError) -> Decompiler.View {
        guard let lease else { throw IDAError(category: .conflict, message: "Action context expired") }
        var result: UnsafeMutableRawPointer?
        try bridgeCall("action.decompilerView") {
            idax_swift_action_decompiler_view(lease.handle, &result, $0)
        }
        return try Decompiler.View(owning: requireLifecycleHandle(result, "action.decompilerView"))
    }
    public func widget() throws(IDAError) -> UI.Widget? {
        guard let lease else { throw IDAError(category: .conflict, message: "Action context expired") }
        return try contextWidget(lease, 0)
    }
    public func focusedWidget() throws(IDAError) -> UI.Widget? {
        guard let lease else { throw IDAError(category: .conflict, message: "Action context expired") }
        return try contextWidget(lease, 1)
    }
    public func typeReference() throws(IDAError) -> Plugin.TypeReference? {
        guard let lease else { throw IDAError(category: .conflict, message: "Action context expired") }
        var name: UnsafeMutablePointer<CChar>?
        var type: UnsafeMutableRawPointer?
        var present: Int32 = 0
        try bridgeCall("action.typeReference") {
            idax_swift_action_type_reference(lease.handle, &name, &type, &present, $0)
        }
        guard present != 0 else { return nil }
        defer { idax_free_string(name) }
        let owned = try TypeInfo(owning: requireLifecycleHandle(type, "action.typeReference"))
        return Plugin.TypeReference(name: try borrowCString(name, "action.typeReference.name"), type: owned)
    }
}
