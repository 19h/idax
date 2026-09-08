import IDAX

final class SecondPlugin: PluginModule {
    var information: Plugin.Information { .init(name: "Swift IDAX second plugin") }
    var exportFlags: Plugin.ExportFlags {
        var flags = Plugin.ExportFlags()
        flags.modifiesDatabase = true
        flags.hidden = true
        return flags
    }
    func run(argument: UInt64) throws(IDAError) {
        try UI.message("Swift IDAX second argument: \(argument)\n")
    }
}

@_cdecl("idax_swift_second_plugin")
public func exportSecondPlugin() {
    do { try Plugin.exportModule(SecondPlugin()) }
    catch { ModuleExport.fail(error) }
}
