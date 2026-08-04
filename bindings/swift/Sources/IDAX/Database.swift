internal import CIDAX

// MARK: - Database Option Types

/// How to open a database file.
public enum OpenMode: Int32, Sendable {
    case analyze     = 0
    case skipAnalysis = 1
}

/// What kind of file to load.
public enum LoadIntent: Int32, Sendable {
    case autoDetect = 0
    case binary     = 1
    case nonBinary  = 2
}

/// Options for initializing the IDA runtime.
public struct RuntimeOptions: Sendable {
    /// Suppress idalib progress output (default: false).
    public var quiet: Bool
    /// Prevent loading of user plugins from IDAUSR (default: false).
    public var disableUserPlugins: Bool

    public init(quiet: Bool = false,
                disableUserPlugins: Bool = false) {
        self.quiet = quiet
        self.disableUserPlugins = disableUserPlugins
    }
}

// MARK: - Core Option Types

/// Common operation policy flags.
public struct OperationOptions: Sendable {
    public var strictValidation: Bool
    public var allowPartialResults: Bool
    public var cancelOnUserBreak: Bool
    public var quiet: Bool

    public init(strictValidation: Bool = true,
                allowPartialResults: Bool = false,
                cancelOnUserBreak: Bool = true,
                quiet: Bool = true) {
        self.strictValidation = strictValidation
        self.allowPartialResults = allowPartialResults
        self.cancelOnUserBreak = cancelOnUserBreak
        self.quiet = quiet
    }
}

/// Generic wait/poll policy.
public struct WaitOptions: Sendable {
    public var timeoutMilliseconds: UInt32
    public var pollIntervalMilliseconds: UInt32

    public init(timeoutMilliseconds: UInt32 = 0,
                pollIntervalMilliseconds: UInt32 = 10) {
        self.timeoutMilliseconds = timeoutMilliseconds
        self.pollIntervalMilliseconds = pollIntervalMilliseconds
    }
}

/// Compiler metadata returned by `Database.compilerInfo()`.
public struct CompilerInfo: Sendable {
    public let id: UInt32
    public let uncertain: Bool
    public let name: String
    public let abbreviation: String
}

/// A single imported symbol within an import module.
public struct ImportSymbol: Sendable {
    public let address: Address
    public let name: String
    public let ordinal: UInt64
}

/// An import module containing its symbols.
public struct ImportModule: Sendable {
    public let index: Int
    public let name: String
    public let symbols: [ImportSymbol]
}

/// A database snapshot (recursive tree node).
public struct Snapshot: Sendable {
    public let id: Int64
    public let flags: UInt16
    public let description: String
    public let filename: String
    public let children: [Snapshot]
}

/// Processor architecture identifier stored in the IDA database.
///
/// Mirrors C++ `ida::database::ProcessorID` (values 0–77).
public enum ProcessorID: Int32, Sendable {
    case intelX86 = 0
    case z80 = 1
    case intelI860 = 2
    case intel8051 = 3
    case tms320c5x = 4
    case mos6502 = 5
    case pdp11 = 6
    case motorola68k = 7
    case javaVM = 8
    case motorola6800 = 9
    case st7 = 10
    case motorola68hc12 = 11
    case mips = 12
    case arm = 13
    case tms320c6x = 14
    case powerPC = 15
    case intel80196 = 16
    case z8 = 17
    case superH = 18
    case dotNet = 19
    case avr = 20
    case h8 = 21
    case pic = 22
    case sparc = 23
    case alpha = 24
    case hppa = 25
    case h8500 = 26
    case triCore = 27
    case dsp56k = 28
    case c166 = 29
    case st20 = 30
    case ia64 = 31
    case intelI960 = 32
    case f2mc16 = 33
    case tms320c54x = 34
    case tms320c55x = 35
    case trimedia = 36
    case m32r = 37
    case nec78k0 = 38
    case nec78k0s = 39
    case mitsubishiM740 = 40
    case mitsubishiM7700 = 41
    case st9 = 42
    case fujitsuFR = 43
    case motorola68hc16 = 44
    case mitsubishiM7900 = 45
    case tms320c3 = 46
    case kr1878 = 47
    case adsp218x = 48
    case oakDSP = 49
    case tlcs900 = 50
    case rockwellC39 = 51
    case cr16 = 52
    case mn10200 = 53
    case tms320c1x = 54
    case necV850x = 55
    case scriptAdapter = 56
    case efiBytecode = 57
    case msp430 = 58
    case spu = 59
    case dalvik = 60
    case wdc65c816 = 61
    case m16c = 62
    case arc = 63
    case unsp = 64
    case tms320c28x = 65
    case dsp96000 = 66
    case spc700 = 67
    case adsp2106x = 68
    case pic16 = 69
    case s390 = 70
    case xtensa = 71
    case riscV = 72
    case rl78 = 73
    case rx = 74
    case wasm = 75
    case nds32 = 76
    case mcore = 77
}

/// Database lifecycle and metadata operations.
///
/// Mirrors C++ `ida::database`.
public enum Database {

    // MARK: - Lifecycle

    public static func initialize() throws(IDAError) {
        try checkStatus(idax_database_init(0, nil), "database.init")
        idax_sync_ida_globals()
    }

    /// Initialize the IDA runtime with custom options.
    public static func initialize(options: RuntimeOptions) throws(IDAError) {
        var raw = IdaxRuntimeOptions()
        raw.quiet = options.quiet ? 1 : 0
        raw.disable_user_plugins = options.disableUserPlugins ? 1 : 0
        try checkStatus(idax_database_init_with_options(&raw), "database.initWithOptions")
        idax_sync_ida_globals()
    }

    public static func open(_ path: String, autoAnalysis: Bool = true) throws(IDAError) {
        try checkStatus(
            path.withCString { idax_database_open($0, autoAnalysis ? 1 : 0) },
            "database.open"
        )
    }

    /// Open a database with explicit intent and mode.
    public static func open(_ path: String, intent: LoadIntent = .autoDetect,
                            mode: OpenMode = .analyze) throws(IDAError) {
        let result = path.withCString { pathPointer in
            idax_database_open_with_intent(pathPointer, intent.rawValue, mode.rawValue)
        }
        try checkStatus(result, "database.openWithIntent")
    }

    public static func save() throws(IDAError) {
        try checkStatus(idax_database_save(), "database.save")
    }

    /// Save the current database to a new file path.
    public static func save(to outputDatabasePath: String) throws(IDAError) {
        try checkStatus(
            outputDatabasePath.withCString { idax_database_save_to($0) },
            "database.saveTo"
        )
    }

    public static func close(save: Bool = false) throws(IDAError) {
        try checkStatus(idax_database_close(save ? 1 : 0), "database.close")
    }

    // MARK: - Metadata

    public static func inputFilePath() throws(IDAError) -> String {
        try withStringOutput("database.inputFilePath") { idax_database_input_file_path($0) }
    }

    public static func fileTypeName() throws(IDAError) -> String {
        try withStringOutput("database.fileTypeName") { idax_database_file_type_name($0) }
    }

    public static func loaderFormatName() throws(IDAError) -> String {
        try withStringOutput("database.loaderFormatName") { idax_database_loader_format_name($0) }
    }

    public static func inputMD5() throws(IDAError) -> String {
        try withStringOutput("database.inputMD5") { idax_database_input_md5($0) }
    }

    public static func processorName() throws(IDAError) -> String {
        try withStringOutput("database.processorName") { idax_database_processor_name($0) }
    }

    public static func abiName() throws(IDAError) -> String {
        try withStringOutput("database.abiName") { idax_database_abi_name($0) }
    }

    public static func imageBase() throws(IDAError) -> Address {
        try withOutput("database.imageBase", UInt64(0)) { idax_database_image_base($0) }
    }

    public static func minAddress() throws(IDAError) -> Address {
        try withOutput("database.minAddress", UInt64(0)) { idax_database_min_address($0) }
    }

    public static func maxAddress() throws(IDAError) -> Address {
        try withOutput("database.maxAddress", UInt64(0)) { idax_database_max_address($0) }
    }

    public static func addressBitness() throws(IDAError) -> Int {
        Int(try withOutput("database.addressBitness", Int32(0)) { idax_database_address_bitness($0) })
    }

    public static func setAddressBitness(_ bits: Int) throws(IDAError) {
        try checkStatus(idax_database_set_address_bitness(Int32(bits)), "database.setAddressBitness")
    }

    public static func isBigEndian() throws(IDAError) -> Bool {
        try withOutput("database.isBigEndian", Int32(0)) { idax_database_is_big_endian($0) } != 0
    }

    public static func addressSpan() throws(IDAError) -> AddressSize {
        try withOutput("database.addressSpan", UInt64(0)) { idax_database_address_span($0) }
    }

    public static func processorID() throws(IDAError) -> Int32 {
        try withOutput("database.processorID", Int32(0)) { idax_database_processor_id($0) }
    }

    public static var processor: ProcessorID {
        get throws(IDAError) {
            let rawID = try processorID()
            guard let id = ProcessorID(rawValue: rawID) else {
                throw IDAError(category: .unsupported, code: rawID,
                               message: "unknown processor ID: \(rawID)")
            }
            return id
        }
    }

    public static var addressBounds: (start: Address, end: Address) {
        get throws(IDAError) {
            (try minAddress(), try maxAddress())
        }
    }

    // MARK: - Binary Loading

    public static func openBinary(_ path: String, mode: Int) throws(IDAError) {
        try checkStatus(
            path.withCString { idax_database_open_binary($0, Int32(mode)) },
            "database.openBinary"
        )
    }

    public static func openNonBinary(_ path: String, mode: Int) throws(IDAError) {
        try checkStatus(
            path.withCString { idax_database_open_non_binary($0, Int32(mode)) },
            "database.openNonBinary"
        )
    }

    public static func fileToDatabase(
        filePath: String, fileOffset: Int64, address: Address,
        size: UInt64, patchable: Bool, remote: Bool
    ) throws(IDAError) {
        try checkStatus(
            filePath.withCString {
                idax_database_file_to_database(
                    $0, fileOffset, address, size,
                    patchable ? 1 : 0, remote ? 1 : 0
                )
            },
            "database.fileToDatabase"
        )
    }

    public static func memoryToDatabase(
        bytes: Span<UInt8>, address: Address, fileOffset: Int64
    ) throws(IDAError) {
        try checkStatus(
            idax_database_memory_to_database(bytes, address, fileOffset),
            "database.memoryToDatabase"
        )
    }

    // MARK: - Compiler Info

    public static func compilerInfo() throws(IDAError) -> CompilerInfo {
        var raw = IdaxDatabaseCompilerInfo()
        try checkStatus(idax_database_compiler_info(&raw), "database.compilerInfo")
        defer { idax_database_compiler_info_free(&raw) }
        return CompilerInfo(
            id: raw.id,
            uncertain: raw.uncertain != 0,
            name: borrowCString(raw.name),
            abbreviation: borrowCString(raw.abbreviation)
        )
    }

    // MARK: - Imports

    public static func importModules() throws(IDAError) -> [ImportModule] {
        var ptr: UnsafeMutablePointer<IdaxDatabaseImportModule>? = nil
        var count: Int = 0
        try checkStatus(idax_database_import_modules(&ptr, &count), "database.importModules")
        defer { idax_database_import_modules_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        var result: [ImportModule] = []
        for i in 0..<count {
            let raw = ptr[i]
            var symbols: [ImportSymbol] = []
            if let symPtr = raw.symbols, raw.symbol_count > 0 {
                for j in 0..<raw.symbol_count {
                    let s = symPtr[j]
                    symbols.append(ImportSymbol(
                        address: s.address,
                        name: borrowCString(s.name),
                        ordinal: s.ordinal
                    ))
                }
            }
            result.append(ImportModule(
                index: raw.index,
                name: borrowCString(raw.name),
                symbols: symbols
            ))
        }
        return result
    }

    // MARK: - Snapshots

    public static func snapshots() throws(IDAError) -> [Snapshot] {
        var ptr: UnsafeMutablePointer<IdaxDatabaseSnapshot>? = nil
        var count: Int = 0
        try checkStatus(idax_database_snapshots(&ptr, &count), "database.snapshots")
        defer { idax_database_snapshots_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        var result: [Snapshot] = []
        for i in 0..<count {
            result.append(convertSnapshot(ptr[i]))
        }
        return result
    }

    public static func setSnapshotDescription(_ description: String) throws(IDAError) {
        try checkStatus(
            description.withCString { idax_database_set_snapshot_description($0) },
            "database.setSnapshotDescription"
        )
    }

    public static func isSnapshotDatabase() throws(IDAError) -> Bool {
        try withOutput("database.isSnapshotDatabase", Int32(0)) {
            idax_database_is_snapshot_database($0)
        } != 0
    }

    // MARK: - Private Helpers

    private static func convertSnapshot(_ raw: IdaxDatabaseSnapshot) -> Snapshot {
        var kids: [Snapshot] = []
        if let childPtr = raw.children, raw.child_count > 0 {
            for i in 0..<raw.child_count {
                kids.append(convertSnapshot(childPtr[i]))
            }
        }
        return Snapshot(
            id: raw.id,
            flags: raw.flags,
            description: borrowCString(raw.description),
            filename: borrowCString(raw.filename),
            children: kids
        )
    }
}
