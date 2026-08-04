internal import CIDAX

/// A single image (module) contained in a dyld shared cache.
///
/// Maps directly to C `IdaxDyldCacheModule`.
public struct DyldCacheModule: Sendable {
    /// Full path inside the cache (e.g. "/usr/lib/libobjc.A.dylib").
    public let path: String
    /// Mach-O header address of the image within the cache.
    public let loadAddress: Address
}

/// dyld shared cache utilities — programmatic access to IDA's bundled "dscu"
/// (dyld shared cache utils) plugin.
///
/// Every operation requires the current database to have been opened from a
/// dyld shared cache with the "single module" option. Check `isAvailable()`
/// first; otherwise each call throws `IDAError` with category `.unsupported`.
///
/// Every `load*` method accepts an optional `waitForAnalysis` flag (default
/// `false`). When `true`, the call drains IDA's auto-analysis queue before
/// returning; on a multi-gigabyte macOS dyld shared cache this can take tens
/// of minutes (CPU-bound, looks like a hang). The safer default is `false`:
/// dscu still creates segments synchronously, but the cascading code analysis
/// runs in the background. Wait once after batching loads if you need a
/// quiescent database.
///
/// Mirrors C++ `ida::dyld_cache`.
public enum DyldCache {

    /// Whether dyld shared cache utilities are available for the current
    /// database (i.e. the "dscu" plugin is loaded).
    public static func isAvailable() -> Bool {
        idax_dyld_cache_is_available() != 0
    }

    /// Enumerate every module contained in the current database's input cache.
    ///
    /// Use the returned paths with `loadModule`.
    public static func listModules() throws(IDAError) -> [DyldCacheModule] {
        var modulesPointer: UnsafeMutablePointer<IdaxDyldCacheModule>? = nil
        var count: Int = 0
        let returnCode = idax_dyld_cache_list_modules(&modulesPointer, &count)
        if returnCode != 0 {
            throw consumeLastError(fallback: "dyldCache.listModules")
        }
        defer { idax_dyld_cache_list_modules_free(modulesPointer, count) }
        guard let modulesPointer, count > 0 else { return [] }
        return (0..<count).map { index in
            let rawModule = modulesPointer[index]
            return DyldCacheModule(
                path: borrowCString(rawModule.path),
                loadAddress: rawModule.load_address
            )
        }
    }

    /// Enumerate every module directly from a dyld shared cache file.
    ///
    /// This overload does not require an open database, which allows callers
    /// to resolve image names before selecting the first cache image.
    public static func listModules(in cachePath: String) throws(IDAError) -> [DyldCacheModule] {
        var modulesPointer: UnsafeMutablePointer<IdaxDyldCacheModule>? = nil
        var moduleCount: Int = 0
        let returnCode = cachePath.withCString {
            idax_dyld_cache_list_modules_at_path($0, &modulesPointer, &moduleCount)
        }
        if returnCode != 0 {
            throw consumeLastError(fallback: "dyldCache.listModulesAtPath")
        }
        defer { idax_dyld_cache_list_modules_free(modulesPointer, moduleCount) }
        guard let modulesPointer, moduleCount > 0 else { return [] }
        return (0..<moduleCount).map { moduleIndex in
            let rawModule = modulesPointer[moduleIndex]
            return DyldCacheModule(
                path: borrowCString(rawModule.path),
                loadAddress: rawModule.load_address
            )
        }
    }

    /// Load one module (image) from the shared cache by its full path.
    ///
    /// - Parameters:
    ///   - modulePath: Full path inside the cache, e.g.
    ///     "/usr/lib/libobjc.A.dylib" (see `listModules`).
    ///   - waitForAnalysis: Drain the auto-analysis queue before returning.
    public static func loadModule(
        _ modulePath: String,
        waitForAnalysis: Bool = true
    ) throws(IDAError) {
        try checkStatus(
            modulePath.withCString {
                idax_dyld_cache_load_module($0, waitForAnalysis ? 1 : 0)
            },
            "dyldCache.loadModule"
        )
    }

    /// Load the shared-cache region that contains `address`.
    ///
    /// The region kind — a module section, branch island, branch mapping,
    /// global offset table, or gap — is detected automatically.
    ///
    /// - Parameters:
    ///   - address: Any address that falls inside the desired region.
    ///   - waitForAnalysis: Drain the auto-analysis queue before returning.
    public static func loadSection(
        at address: Address,
        waitForAnalysis: Bool = true
    ) throws(IDAError) {
        try checkStatus(
            idax_dyld_cache_load_section(address, waitForAnalysis ? 1 : 0),
            "dyldCache.loadSection"
        )
    }

    /// Load the formatted `dyld_cache_header` structure into the database.
    ///
    /// Requires the initial auto-analysis to have completed.
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    public static func loadDyldHeader(
        waitForAnalysis: Bool = true
    ) throws(IDAError) {
        try checkStatus(
            idax_dyld_cache_load_dyld_header(waitForAnalysis ? 1 : 0),
            "dyldCache.loadDyldHeader"
        )
    }

    /// Load every branch-island region from the shared cache.
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    /// - Returns: The number of branch-island regions loaded.
    @discardableResult
    public static func loadBranchIslands(
        waitForAnalysis: Bool = true
    ) throws(IDAError) -> Int {
        try withOutput("dyldCache.loadBranchIslands", 0) {
            idax_dyld_cache_load_branch_islands(waitForAnalysis ? 1 : 0, $0)
        }
    }

    /// Load every branch-mapping region from the shared cache (iOS 16+).
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    /// - Returns: The number of branch-mapping regions loaded.
    @discardableResult
    public static func loadBranchMappings(
        waitForAnalysis: Bool = true
    ) throws(IDAError) -> Int {
        try withOutput("dyldCache.loadBranchMappings", 0) {
            idax_dyld_cache_load_branch_mappings(waitForAnalysis ? 1 : 0, $0)
        }
    }

    /// Load every global-offset-table region from the shared cache (iOS 16+).
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    /// - Returns: The number of global-offset-table regions loaded.
    @discardableResult
    public static func loadGlobalOffsetTables(
        waitForAnalysis: Bool = true
    ) throws(IDAError) -> Int {
        try withOutput("dyldCache.loadGlobalOffsetTables", 0) {
            idax_dyld_cache_load_global_offset_tables(waitForAnalysis ? 1 : 0, $0)
        }
    }

    /// Load every unknown region from the shared cache.
    ///
    /// IDA 9.4 calls these unknown regions. The historical method name is
    /// preserved for source compatibility with IDA 9.3.
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    /// - Returns: The number of gap regions loaded.
    @discardableResult
    public static func loadGaps(
        waitForAnalysis: Bool = true
    ) throws(IDAError) -> Int {
        try withOutput("dyldCache.loadGaps", 0) {
            idax_dyld_cache_load_gaps(waitForAnalysis ? 1 : 0, $0)
        }
    }

    /// Load every cache-wide data region from the shared cache.
    ///
    /// This region type requires IDA SDK 9.4 or newer.
    ///
    /// - Parameter waitForAnalysis: Drain the auto-analysis queue before returning.
    /// - Returns: The number of cache-wide data regions loaded.
    @discardableResult
    public static func loadCacheData(
        waitForAnalysis: Bool = true
    ) throws(IDAError) -> Int {
        try withOutput("dyldCache.loadCacheData", 0) {
            idax_dyld_cache_load_cache_data(waitForAnalysis ? 1 : 0, $0)
        }
    }
}
