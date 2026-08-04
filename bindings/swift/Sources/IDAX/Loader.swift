internal import CIDAX

/// Decoded representation of IDA loader flags.
public struct LoadFlags: Sendable {
    public var createSegments: Bool
    public var loadResources: Bool
    public var renameEntries: Bool
    public var manualLoad: Bool
    public var fillGaps: Bool
    public var createImportSegment: Bool
    public var firstFile: Bool
    public var binaryCodeSegment: Bool
    public var reload: Bool
    public var autoFlatGroup: Bool
    public var miniDatabase: Bool
    public var loaderOptionsDialog: Bool
    public var loadAllSegments: Bool

    public init(
        createSegments: Bool = false,
        loadResources: Bool = false,
        renameEntries: Bool = false,
        manualLoad: Bool = false,
        fillGaps: Bool = false,
        createImportSegment: Bool = false,
        firstFile: Bool = false,
        binaryCodeSegment: Bool = false,
        reload: Bool = false,
        autoFlatGroup: Bool = false,
        miniDatabase: Bool = false,
        loaderOptionsDialog: Bool = false,
        loadAllSegments: Bool = false
    ) {
        self.createSegments = createSegments
        self.loadResources = loadResources
        self.renameEntries = renameEntries
        self.manualLoad = manualLoad
        self.fillGaps = fillGaps
        self.createImportSegment = createImportSegment
        self.firstFile = firstFile
        self.binaryCodeSegment = binaryCodeSegment
        self.reload = reload
        self.autoFlatGroup = autoFlatGroup
        self.miniDatabase = miniDatabase
        self.loaderOptionsDialog = loaderOptionsDialog
        self.loadAllSegments = loadAllSegments
    }
}

/// Borrowed handle to an IDA loader input file.
///
/// Move-only wrapper around the SDK's `linput_t*`. The handle is **not** owned
/// by this struct — IDA manages its lifetime — so there is no `deinit`.
/// Making it `~Copyable` prevents accidental aliasing.
public struct InputFile: ~Copyable, @unchecked Sendable {
    let handle: UnsafeMutableRawPointer

    /// Wrap an existing loader input handle.
    ///
    /// - Parameter handle: Opaque `linput_t*` pointer borrowed from IDA.
    public init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    // MARK: - Position / Size

    /// Total size of the input file in bytes.
    public var size: Int64 {
        get throws(IDAError) {
            try withOutput("loader.inputSize", Int64(0)) { idax_loader_input_size(handle, $0) }
        }
    }

    /// Current read position within the input file.
    public func tell() throws(IDAError) -> Int64 {
        try withOutput("loader.inputTell", Int64(0)) { idax_loader_input_tell(handle, $0) }
    }

    /// Seek to `offset` from the beginning of the input file.
    ///
    /// - Returns: The new absolute position after seeking.
    @discardableResult
    public func seek(to offset: Int64) throws(IDAError) -> Int64 {
        try withOutput("loader.inputSeek", Int64(0)) { idax_loader_input_seek(handle, offset, $0) }
    }

    // MARK: - Reading

    /// Read `count` bytes from the current position.
    public func readBytes(count: Int) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(
            idax_loader_input_read_bytes(handle, count, &ptr, &len),
            "loader.inputReadBytes"
        )
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    /// Read `count` bytes starting at `offset` without moving the file position.
    public func readBytes(at offset: Int64, count: Int) throws(IDAError) -> [UInt8] {
        var ptr: UnsafeMutablePointer<UInt8>? = nil
        var len: Int = 0
        try checkStatus(
            idax_loader_input_read_bytes_at(handle, offset, count, &ptr, &len),
            "loader.inputReadBytesAt"
        )
        defer { idax_free_bytes(ptr) }
        guard let ptr, len > 0 else { return [] }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    /// Read a null-terminated string starting at `offset`, up to `maxLength` bytes.
    public func readString(at offset: Int64, maxLength: Int = 4096) throws(IDAError) -> String {
        try withStringOutput("loader.inputReadString") { out in
            idax_loader_input_read_string(handle, offset, maxLength, out)
        }
    }

    /// The filename associated with this input file.
    public var filename: String {
        get throws(IDAError) {
            try withStringOutput("loader.inputFilename") { idax_loader_input_filename(handle, $0) }
        }
    }
}

/// File loading, input file I/O, and processor setup.
///
/// Mirrors C++ `ida::loader`.
public enum Loader {

    // MARK: - Load Flags

    /// Decode a raw 16-bit flag value into structured `LoadFlags`.
    public static func decodeLoadFlags(_ rawFlags: UInt16) throws(IDAError) -> LoadFlags {
        var raw = IdaxLoaderLoadFlags()
        try checkStatus(idax_loader_decode_load_flags(rawFlags, &raw), "loader.decodeLoadFlags")
        return LoadFlags(
            createSegments: raw.create_segments != 0,
            loadResources: raw.load_resources != 0,
            renameEntries: raw.rename_entries != 0,
            manualLoad: raw.manual_load != 0,
            fillGaps: raw.fill_gaps != 0,
            createImportSegment: raw.create_import_segment != 0,
            firstFile: raw.first_file != 0,
            binaryCodeSegment: raw.binary_code_segment != 0,
            reload: raw.reload != 0,
            autoFlatGroup: raw.auto_flat_group != 0,
            miniDatabase: raw.mini_database != 0,
            loaderOptionsDialog: raw.loader_options_dialog != 0,
            loadAllSegments: raw.load_all_segments != 0
        )
    }

    /// Encode structured `LoadFlags` into a raw 16-bit flag value.
    public static func encodeLoadFlags(_ flags: LoadFlags) throws(IDAError) -> UInt16 {
        var raw = IdaxLoaderLoadFlags(
            create_segments: flags.createSegments ? 1 : 0,
            load_resources: flags.loadResources ? 1 : 0,
            rename_entries: flags.renameEntries ? 1 : 0,
            manual_load: flags.manualLoad ? 1 : 0,
            fill_gaps: flags.fillGaps ? 1 : 0,
            create_import_segment: flags.createImportSegment ? 1 : 0,
            first_file: flags.firstFile ? 1 : 0,
            binary_code_segment: flags.binaryCodeSegment ? 1 : 0,
            reload: flags.reload ? 1 : 0,
            auto_flat_group: flags.autoFlatGroup ? 1 : 0,
            mini_database: flags.miniDatabase ? 1 : 0,
            loader_options_dialog: flags.loaderOptionsDialog ? 1 : 0,
            load_all_segments: flags.loadAllSegments ? 1 : 0
        )
        return try withOutput("loader.encodeLoadFlags", UInt16(0)) {
            idax_loader_encode_load_flags(&raw, $0)
        }
    }

    // MARK: - Loading Data

    /// Copy bytes from an input file into the IDA database.
    ///
    /// - Parameters:
    ///   - input: Borrowed loader input file handle.
    ///   - fileOffset: Offset within the input file to start reading.
    ///   - address: Target address in the database.
    ///   - size: Number of bytes to copy.
    ///   - patchable: Whether the loaded bytes should be patchable.
    public static func fileToDatabase(
        _ input: borrowing InputFile,
        fileOffset: Int64,
        address: Address,
        size: UInt64,
        patchable: Bool = false
    ) throws(IDAError) {
        try checkStatus(
            idax_loader_file_to_database(
                input.handle, fileOffset, address, size, patchable ? 1 : 0
            ),
            "loader.fileToDatabase"
        )
    }

    /// Copy bytes from a memory buffer into the IDA database.
    ///
    /// - Parameters:
    ///   - data: Byte array to load.
    ///   - address: Target address in the database.
    ///   - size: Number of bytes to copy (must not exceed `data.count`).
    public static func memoryToDatabase(
        _ data: [UInt8],
        address: Address,
        size: UInt64
    ) throws(IDAError) {
        let ret = data.withUnsafeBufferPointer { buffer in
            idax_loader_memory_to_database(buffer.baseAddress, address, size)
        }
        try checkStatus(ret, "loader.memoryToDatabase")
    }

    /// Abort the current load operation with a diagnostic message.
    ///
    /// This function does not return in the IDA runtime — it longjmps out
    /// of the loader. Treat it as a fatal abort.
    public static func abortLoad(_ message: String) {
        message.withCString { idax_loader_abort_load($0) }
    }

    // MARK: - Utilities

    /// Set the target processor type by name (e.g. "metapc", "ARM").
    public static func setProcessor(_ processorName: String) throws(IDAError) {
        try checkStatus(
            processorName.withCString { idax_loader_set_processor($0) },
            "loader.setProcessor"
        )
    }

    /// Create a standard filename comment in the database.
    public static func createFilenameComment() throws(IDAError) {
        try checkStatus(idax_loader_create_filename_comment(), "loader.createFilenameComment")
    }
}
