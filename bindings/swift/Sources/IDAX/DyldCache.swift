internal import CIDAX

/// Apple dyld shared-cache inventory and incremental loading.
public enum DyldCache {
    public struct ModuleInfo: Equatable, Sendable {
        public var path: String
        /// Unslid address for an offline inventory; database address online.
        public var loadAddress: Address

        public init(path: String = "", loadAddress: Address = badAddress) {
            self.path = path
            self.loadAddress = loadAddress
        }

        internal init(copying value: IdaxDyldCacheModuleInfo, _ operation: String) throws(IDAError) {
            path = try borrowCString(value.path.map { UnsafePointer($0) }, operation)
            loadAddress = value.load_address
        }
    }

    public static func isAvailable() throws(IDAError) -> Bool {
        try requireRuntimeThread("DyldCache.isAvailable")
        var output: Int32 = 0
        try checkStatus(idax_dyld_cache_is_available(&output), "DyldCache.isAvailable")
        return output != 0
    }

    public static func listModules() throws(IDAError) -> [ModuleInfo] {
        let operation = "DyldCache.listModules"
        try requireRuntimeThread(operation)
        var output: UnsafeMutablePointer<IdaxDyldCacheModuleInfo>?
        var count: Int = 0
        defer { idax_dyld_cache_modules_free(output, count) }
        try checkStatus(idax_dyld_cache_list_modules(&output, &count), operation)
        return try copyNativeValues(output, count: count, operation) {
            (value) throws(IDAError) -> ModuleInfo in try ModuleInfo(copying: value, operation)
        }
    }

    /// Read a toplevel cache file without opening a database or initializing IDA.
    public static func listModules(cachePath: String) throws(IDAError) -> [ModuleInfo] {
        let operation = "DyldCache.listModules(cachePath:)"
        try validateCString(cachePath, operation)
        var output: UnsafeMutablePointer<IdaxDyldCacheModuleInfo>?
        var count: Int = 0
        defer { idax_dyld_cache_modules_free(output, count) }
        try checkStatus(cachePath.withCString {
            idax_dyld_cache_list_modules_from_file($0, &output, &count)
        }, operation)
        return try copyNativeValues(output, count: count, operation) {
            (value) throws(IDAError) -> ModuleInfo in try ModuleInfo(copying: value, operation)
        }
    }

    public static func loadModule(path: String, waitForAnalysis: Bool = false) throws(IDAError) {
        let operation = "DyldCache.loadModule"
        try requireRuntimeThread(operation)
        try validateCString(path, operation)
        try checkStatus(path.withCString {
            idax_dyld_cache_load_module($0, waitForAnalysis ? 1 : 0)
        }, operation)
    }

    /// Loading an image section loads the entire image atomically.
    public static func loadSection(address: Address, waitForAnalysis: Bool = false) throws(IDAError) {
        try requireRuntimeThread("DyldCache.loadSection")
        try checkStatus(idax_dyld_cache_load_section(address, waitForAnalysis ? 1 : 0), "DyldCache.loadSection")
    }

    /// Verify the header originally loaded by the cache loader is mapped.
    public static func loadDyldHeader(waitForAnalysis: Bool = false) throws(IDAError) {
        try requireRuntimeThread("DyldCache.loadDyldHeader")
        try checkStatus(idax_dyld_cache_load_dyld_header(waitForAnalysis ? 1 : 0), "DyldCache.loadDyldHeader")
    }

    /// Return the number of unique previously unloaded entities loaded.
    public static func loadBranchIslands(waitForAnalysis: Bool = false) throws(IDAError) -> Int {
        try loadCount("DyldCache.loadBranchIslands", waitForAnalysis, idax_dyld_cache_load_branch_islands)
    }
    public static func loadBranchMappings(waitForAnalysis: Bool = false) throws(IDAError) -> Int {
        try loadCount("DyldCache.loadBranchMappings", waitForAnalysis, idax_dyld_cache_load_branch_mappings)
    }
    public static func loadGlobalOffsetTables(waitForAnalysis: Bool = false) throws(IDAError) -> Int {
        try loadCount("DyldCache.loadGlobalOffsetTables", waitForAnalysis, idax_dyld_cache_load_global_offset_tables)
    }
    public static func loadGaps(waitForAnalysis: Bool = false) throws(IDAError) -> Int {
        try loadCount("DyldCache.loadGaps", waitForAnalysis, idax_dyld_cache_load_gaps)
    }
    public static func loadCacheData(waitForAnalysis: Bool = false) throws(IDAError) -> Int {
        try loadCount("DyldCache.loadCacheData", waitForAnalysis, idax_dyld_cache_load_cache_data)
    }

    private static func loadCount(_ operation: String, _ wait: Bool,
        _ body: (Int32, UnsafeMutablePointer<Int>?) -> Int32
    ) throws(IDAError) -> Int {
        try requireRuntimeThread(operation)
        var output = 0
        try checkStatus(body(wait ? 1 : 0, &output), operation)
        return output
    }
}
