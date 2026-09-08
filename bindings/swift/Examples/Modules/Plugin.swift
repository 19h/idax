import IDAX

final class ExamplePlugin: PluginModule {
    var information: Plugin.Information {
        .init(name: "Swift IDAX example", comment: "Owned Swift module callbacks")
    }
    private var shortcut: Plugin.Shortcut?
    func initialize() throws(IDAError) -> Bool {
        shortcut = try Plugin.registerShortcut("Ctrl-Alt-F8") { () throws(IDAError) -> Void in
            try UI.message("Swift IDAX action\n")
        }
        return true
    }
    func run(argument: UInt64) throws(IDAError) { try UI.message("Swift IDAX argument: \(argument)\n") }
    func terminate() {
        try? shortcut?.close()
        shortcut = nil
    }
}
@_cdecl("idax_swift_example_plugin")
public func exportExamplePlugin() {
    do { try Plugin.exportModule(ExamplePlugin()) } catch { ModuleExport.fail(error) }
}
