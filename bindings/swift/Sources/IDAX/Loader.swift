internal import CIDAX

/// Native loader authoring and callback-scoped input/output files.
public enum Loader {
    public struct Options: Sendable {
        public var supportsReload, requiresProcessor: Bool
        public init(supportsReload: Bool = false, requiresProcessor: Bool = false) {
            self.supportsReload = supportsReload
            self.requiresProcessor = requiresProcessor
        }
    }
    public struct LoadFlags: Sendable {
        public var createSegments: Bool = false
        public var loadResources: Bool = false
        public var renameEntries: Bool = false
        public var manualLoad: Bool = false
        public var fillGaps: Bool = false
        public var createImportSegment: Bool = false
        public var firstFile: Bool = false
        public var binaryCodeSegment: Bool = false
        public var reload: Bool = false
        public var autoFlatGroup: Bool = false
        public var miniDatabase: Bool = false
        public var loaderOptionsDialog: Bool = false
        public var loadAllSegments: Bool = false
        public init() {}
        public init(rawValue: UInt16) throws(IDAError) { try self.init(bits: rawValue) }
        public var rawValue: UInt16 { get throws(IDAError) { try encoded() } }
        internal init(bits: UInt16) throws(IDAError) {
            var value = IdaxLoaderLoadFlags()
            try checkStatus(idax_loader_decode_load_flags(bits, &value), "loader.decodeFlags")
            createSegments = value.create_segments != 0
            loadResources = value.load_resources != 0
            renameEntries = value.rename_entries != 0
            manualLoad = value.manual_load != 0
            fillGaps = value.fill_gaps != 0
            createImportSegment = value.create_import_segment != 0
            firstFile = value.first_file != 0
            binaryCodeSegment = value.binary_code_segment != 0
            reload = value.reload != 0
            autoFlatGroup = value.auto_flat_group != 0
            miniDatabase = value.mini_database != 0
            loaderOptionsDialog = value.loader_options_dialog != 0
            loadAllSegments = value.load_all_segments != 0
        }
        internal func encoded() throws(IDAError) -> UInt16 {
            var value = IdaxLoaderLoadFlags()
            value.create_segments = createSegments ? 1 : 0
            value.load_resources = loadResources ? 1 : 0
            value.rename_entries = renameEntries ? 1 : 0
            value.manual_load = manualLoad ? 1 : 0
            value.fill_gaps = fillGaps ? 1 : 0
            value.create_import_segment = createImportSegment ? 1 : 0
            value.first_file = firstFile ? 1 : 0
            value.binary_code_segment = binaryCodeSegment ? 1 : 0
            value.reload = reload ? 1 : 0
            value.auto_flat_group = autoFlatGroup ? 1 : 0
            value.mini_database = miniDatabase ? 1 : 0
            value.loader_options_dialog = loaderOptionsDialog ? 1 : 0
            value.load_all_segments = loadAllSegments ? 1 : 0
            var bits: UInt16 = 0
            try checkStatus(idax_loader_encode_load_flags(&value, &bits), "loader.encodeFlags")
            return bits
        }
    }
    public struct AcceptResult: Sendable {
        public var formatName, processorName: String
        public var priority: Int32
        public var archiveLoader, continueProbe, preferFirst: Bool
        public init(
            formatName: String, processorName: String = "", priority: Int32 = 0, archiveLoader: Bool = false,
            continueProbe: Bool = false, preferFirst: Bool = false
        ) {
            self.formatName = formatName
            self.processorName = processorName
            self.priority = priority
            self.archiveLoader = archiveLoader
            self.continueProbe = continueProbe
            self.preferFirst = preferFirst
        }
    }
    public struct LoadRequest: Sendable {
        public var formatName, inputName, archiveName, archiveMemberName: String
        public var flags: LoadFlags
        public var isRemote: Bool
        public init(formatName: String = "", inputName: String = "", archiveName: String = "",
                    archiveMemberName: String = "", flags: LoadFlags = .init(), isRemote: Bool = false) {
            self.formatName = formatName
            self.inputName = inputName
            self.archiveName = archiveName
            self.archiveMemberName = archiveMemberName
            self.flags = flags
            self.isRemote = isRemote
        }
    }
    public struct SaveRequest: Sendable {
        public var formatName: String
        public var capabilityQuery, isRemote: Bool
        public init(formatName: String = "", capabilityQuery: Bool = false, isRemote: Bool = false) {
            self.formatName = formatName
            self.capabilityQuery = capabilityQuery
            self.isRemote = isRemote
        }
    }
    public struct MoveSegmentRequest: Sendable {
        public var formatName: String
        public var wholeProgramRebase, reload: Bool
        public init(formatName: String = "", wholeProgramRebase: Bool = false, reload: Bool = false) {
            self.formatName = formatName
            self.wholeProgramRebase = wholeProgramRebase
            self.reload = reload
        }
    }
    public struct ArchiveMemberRequest: Sendable {
        public var archiveName, defaultMember: String
        public var flags: LoadFlags
        public init(archiveName: String = "", defaultMember: String = "", flags: LoadFlags = .init()) {
            self.archiveName = archiveName
            self.defaultMember = defaultMember
            self.flags = flags
        }
    }
    public struct ArchiveMemberResult: Sendable {
        public var extractedFile, memberName: String
        public var flags: LoadFlags
        public init(extractedFile: String, memberName: String, flags: LoadFlags = .init()) {
            self.extractedFile = extractedFile
            self.memberName = memberName
            self.flags = flags
        }
    }
    public final class InputFile {
        private let lease: CallbackLease
        internal init(_ raw: UnsafeMutableRawPointer) { lease = CallbackLease(raw) }
        private func position(_ op: Int32, _ offset: Int64 = 0) throws(IDAError) -> Int64 {
            var value: Int64 = 0
            try bridgeCall("loader.input.position") {
                idax_swift_module_input(lease.handle, op, offset, 0, nil, nil, &value, nil, $0)
            }
            return value
        }
        public var size: Int64 { get throws(IDAError) { try position(0) } }
        public var position: Int64 { get throws(IDAError) { try position(1) } }
        @discardableResult public func seek(to offset: Int64) throws(IDAError) -> Int64 {
            guard offset >= 0 else { throw IDAError(category: .validation, message: "Negative input offset") }
            return try position(2, offset)
        }
        public func read(count: Int) throws(IDAError) -> [UInt8] { try readBytes(3, offset: 0, count: count) }
        public func read(at offset: Int64, count: Int) throws(IDAError) -> [UInt8] {
            try readBytes(4, offset: offset, count: count)
        }
        private func readBytes(_ op: Int32, offset: Int64, count: Int) throws(IDAError) -> [UInt8] {
            guard count >= 0, offset >= 0 else {
                throw IDAError(category: .validation, message: "Negative input offset or size")
            }
            var pointer: UnsafeMutablePointer<UInt8>?
            var size = 0
            try bridgeCall("loader.input.read") {
                idax_swift_module_input(lease.handle, op, offset, count, &pointer, &size, nil, nil, $0)
            }
            defer { idax_free_bytes(pointer) }
            return Array(try checkedBuffer(pointer, count: size, "loader.input.read"))
        }
        public var filename: String { get throws(IDAError) { try inputString(5, offset: 0, count: 0) } }
        public func readString(at offset: Int64, maximumLength: Int = 1024) throws(IDAError) -> String {
            guard offset >= 0, maximumLength >= 0, maximumLength < Int.max else {
                throw IDAError(category: .validation, message: "Invalid string offset or maximum length")
            }
            return try inputString(7, offset: offset, count: maximumLength)
        }
        private func inputString(_ op: Int32, offset: Int64, count: Int) throws(IDAError) -> String {
            var text: UnsafeMutablePointer<CChar>?
            try bridgeCall("loader.input.string") {
                idax_swift_module_input(lease.handle, op, offset, count, nil, nil, nil, &text, $0)
            }
            return try takeCString(text, "loader.input.string")
        }
        public func copyToDatabase(fileOffset: Int64, address: Address, size: UInt64, patchable: Bool = true)
            throws(IDAError)
        {
            guard fileOffset >= 0 else {
                throw IDAError(category: .validation, message: "Negative file offset")
            }
            try bridgeCall("loader.copyToDatabase") {
                idax_swift_module_file_to_database(
                    lease.handle, fileOffset, address, size, patchable ? 1 : 0, $0)
            }
        }
    }
    public final class OutputFile {
        private let lease: CallbackLease
        internal init(_ raw: UnsafeMutableRawPointer) { lease = CallbackLease(raw) }
        public func write(_ bytes: [UInt8]) throws(IDAError) {
            try bridgeCall("loader.output.write") { error in
                bytes.withUnsafeBufferPointer {
                    idax_swift_module_output_file(lease.handle, $0.baseAddress, $0.count, error)
                }
            }
        }
    }
    public static func memoryToDatabase(_ bytes: [UInt8], at address: Address) throws(IDAError) {
        try requireRuntimeThread("loader.memoryToDatabase")
        try checkStatus(
            bytes.withUnsafeBufferPointer {
                idax_loader_memory_to_database($0.baseAddress, address, UInt64($0.count))
            }, "loader.memoryToDatabase")
    }
    public static func setProcessor(_ name: String) throws(IDAError) {
        try requireRuntimeThread("loader.setProcessor")
        let text = try LifecycleStrings([name])
        try checkStatus(idax_loader_set_processor(text[0]), "loader.setProcessor")
    }
    public static func createFilenameComment() throws(IDAError) {
        try requireRuntimeThread("loader.createFilenameComment")
        try checkStatus(idax_loader_create_filename_comment(), "loader.createFilenameComment")
    }
    /// Throw from load() to abort. This lets Swift unwind owned captures before
    /// the native loader adapter reports the failure to IDA.
    public static func abortLoad(_ message: String) throws(IDAError) -> Never {
        throw IDAError(category: .sdkFailure, message: message, context: "loader.load")
    }
    public static func exportModule(_ module: any LoaderModule) throws(IDAError) {
        let callbacks = callbackDescriptor { event, reply in
            switch event.kind {
            case 100:
                let value = module.options
                reply.pointee.decision = (value.supportsReload ? 1 : 0) | (value.requiresProcessor ? 2 : 0)
            case 101:
                let lease = try requireLifecycleHandle(event.lease, "loader.accept")
                if let result = try module.accept(InputFile(lease)) {
                    try moduleStrings(lease, 100, [result.formatName, result.processorName])
                    try moduleNumbers(
                        lease, 100,
                        [
                            Int64(result.priority), result.archiveLoader ? 1 : 0,
                            result.continueProbe ? 1 : 0, result.preferFirst ? 1 : 0,
                        ])
                    reply.pointee.decision = 1
                }
            case 102:
                let lease = try requireLifecycleHandle(event.lease, "loader.load")
                var text: UnsafeMutablePointer<CChar>?
                try bridgeCall("loader.archiveMemberName") {
                    idax_swift_module_input(lease, 6, 0, 0, nil, nil, nil, &text, $0)
                }
                let member = try takeCString(text, "loader.archiveMemberName")
                let request = LoadRequest(
                    formatName: try borrowCString(event.text, "loader.format"),
                    inputName: try borrowCString(event.secondary_text, "loader.inputName"),
                    archiveName: try borrowCString(event.name, "loader.archiveName"),
                    archiveMemberName: member, flags: try LoadFlags(bits: UInt16(event.value)),
                    isRemote: event.flag != 0)
                try module.load(InputFile(lease), request: request)
            case 103:
                let lease = try requireLifecycleHandle(event.lease, "loader.archive")
                let request = ArchiveMemberRequest(
                    archiveName: try borrowCString(event.text, "loader.archiveName"),
                    defaultMember: try borrowCString(event.secondary_text, "loader.defaultMember"),
                    flags: try LoadFlags(bits: UInt16(event.value)))
                if let result = try module.processArchive(InputFile(lease), request: request) {
                    try moduleStrings(lease, 101, [result.extractedFile, result.memberName])
                    try moduleNumbers(lease, 101, [Int64(try result.flags.encoded())])
                    reply.pointee.decision = 1
                }
            case 104:
                let lease = try requireLifecycleHandle(event.lease, "loader.save")
                let query = event.flag != 0
                let request = SaveRequest(
                    formatName: try borrowCString(event.text, "loader.format"), capabilityQuery: query,
                    isRemote: event.secondary_flag != 0)
                reply.pointee.decision =
                    try module.save(query ? nil : OutputFile(lease), request: request) ? 1 : 0
            case 105:
                let request = MoveSegmentRequest(
                    formatName: try borrowCString(event.text, "loader.format"),
                    wholeProgramRebase: event.flag != 0, reload: event.secondary_flag != 0)
                try module.moveSegment(
                    from: event.address, to: event.secondary_address, size: event.size, request: request)
            default: throw IDAError(category: .unsupported, message: "Unknown loader callback")
            }
        }
        try bridgeCall("module.exportLoader") { idax_swift_module_publish(1, callbacks, $0) }
    }
}
public protocol LoaderModule: AnyObject {
    var options: Loader.Options { get }
    func accept(_ file: Loader.InputFile) throws(IDAError) -> Loader.AcceptResult?
    func load(_ file: Loader.InputFile, formatName: String) throws(IDAError)
    func load(_ file: Loader.InputFile, request: Loader.LoadRequest) throws(IDAError)
    func processArchive(_ file: Loader.InputFile, request: Loader.ArchiveMemberRequest) throws(IDAError)
        -> Loader.ArchiveMemberResult?
    func save(_ file: Loader.OutputFile?, formatName: String) throws(IDAError) -> Bool
    func save(_ file: Loader.OutputFile?, request: Loader.SaveRequest) throws(IDAError) -> Bool
    func moveSegment(from: Address, to: Address, size: UInt64, formatName: String) throws(IDAError)
    func moveSegment(from: Address, to: Address, size: UInt64, request: Loader.MoveSegmentRequest)
        throws(IDAError)
}
extension LoaderModule {
    public var options: Loader.Options { .init() }
    public func load(_ file: Loader.InputFile, request: Loader.LoadRequest) throws(IDAError) {
        try load(file, formatName: request.formatName)
    }
    public func processArchive(_ file: Loader.InputFile, request: Loader.ArchiveMemberRequest)
        throws(IDAError) -> Loader.ArchiveMemberResult?
    { nil }
    public func save(_ file: Loader.OutputFile?, formatName: String) throws(IDAError) -> Bool { false }
    public func save(_ file: Loader.OutputFile?, request: Loader.SaveRequest) throws(IDAError) -> Bool {
        try save(file, formatName: request.formatName)
    }
    public func moveSegment(from: Address, to: Address, size: UInt64, formatName: String) throws(IDAError) {
        throw IDAError(category: .unsupported, message: "Segment movement is not implemented")
    }
    public func moveSegment(from: Address, to: Address, size: UInt64, request: Loader.MoveSegmentRequest)
        throws(IDAError)
    { try moveSegment(from: from, to: to, size: size, formatName: request.formatName) }
}
