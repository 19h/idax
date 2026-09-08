extension Database {
    public static func initialize(arguments: [String] = [], options: RuntimeOptions = .init()) throws(IDAError) {
        try Runtime.initialize(arguments: arguments, options: options)
    }
    public static func open(path: String, mode: OpenMode, intent: LoadIntent = .autoDetect) throws(IDAError) {
        try open(path: path, autoAnalysis: mode == .analyze, intent: intent)
    }
    public static func openBinary(path: String, mode: OpenMode = .analyze) throws(IDAError) {
        try open(path: path, mode: mode, intent: .binary)
    }
    public static func openNonBinary(path: String, mode: OpenMode = .analyze) throws(IDAError) {
        try open(path: path, mode: mode, intent: .nonBinary)
    }
    public static func addressBounds() throws(IDAError) -> Addresses.Range {
        try .init(start: minAddress(), end: maxAddress())
    }
    public static func processorIdFromRaw(_ value: Int32) -> ProcessorId? {
        ProcessorId(rawValue: value)
    }
    public static func processor() throws(IDAError) -> ProcessorId {
        let raw = try processorId()
        guard let result = processorIdFromRaw(raw) else {
            throw IDAError(category: .unsupported,
                message: "Processor ID is not a verified public SDK value", context: String(raw))
        }
        return result
    }
}
