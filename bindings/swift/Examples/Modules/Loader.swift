import IDAX

final class ExampleLoader: LoaderModule {
    func accept(_ file: Loader.InputFile) throws(IDAError) -> Loader.AcceptResult? {
        let magic = try file.read(at: 0, count: 4)
        return magic == [0x49, 0x44, 0x41, 0x58]
            ? .init(formatName: "IDAX example container", processorName: "metapc") : nil
    }
    func load(_ file: Loader.InputFile, formatName: String) throws(IDAError) {
        try Loader.setProcessor("metapc")
        try Loader.createFilenameComment()
    }
}
@_cdecl("idax_swift_example_loader")
public func exportExampleLoader() {
    do { try Loader.exportModule(ExampleLoader()) } catch { ModuleExport.fail(error) }
}
