import Testing
import Foundation
@testable import IDAX

/// Integration walkthrough of `ida::dyld_cache`.
///
/// Requires:
///   - IDA Pro installed (so `IDARuntime.isAvailable` returns true)
///   - `IDAX_TEST_DSC_DATABASE` environment variable pointing at a `.i64`
///     database that was opened from a dyld shared cache with the
///     "single module" option.
///
/// When either prerequisite is missing the test prints a skip notice and
/// passes — `swift test` can be run without any setup; only developers
/// who provide a DSC fixture exercise the dscu driver end-to-end.
@Suite("IDA DyldCache Integration")
struct DyldCacheIntegrationTests {

    @Test func dscuDriverWalkthrough() async throws {
        guard let databasePath = ProcessInfo.processInfo.environment["IDAX_TEST_DSC_DATABASE"] else {
            print("IDAX_TEST_DSC_DATABASE not set — skipping dyld-cache integration test")
            return
        }

        guard IDARuntime.isAvailable else {
            print("IDA runtime not available — skipping dyld-cache integration test")
            return
        }

        // IDA's Mach-O loader picks the cache image via an environment
        // variable; without it, opening the raw cache file fails outright.
        // The dscu plugin is only registered when the database is opened
        // this way (the "single module" option in the GUI).
        //   IDA_DYLD_CACHE_MODULE — module path inside the cache
        //   IDA_DYLD_CACHE_DEPTH  — dependency depth (0 = module only,
        //                            -1 = all)
        var modulePath = "/System/iOSSupport/System/Library/PrivateFrameworks/UIKitCore.framework/Versions/A/UIKitCore"
        
        setenv("IDA_DYLD_CACHE_MODULE", modulePath, 1)
        setenv("IDA_DYLD_CACHE_DEPTH", "0", 1)
        defer {
            unsetenv("IDA_DYLD_CACHE_MODULE")
            unsetenv("IDA_DYLD_CACHE_DEPTH")
        }

        print("=== DyldCache Integration ===")
        print("Cache:  \(databasePath)")
        print("Module: \(modulePath)")

        try Database.initialize()
        try Database.open(databasePath, autoAnalysis: false)
        defer { try? Database.close() }

        try #require(
            DyldCache.isAvailable(),
            "dscu plugin not loaded — open the database from a dyld shared cache with the 'single module' option"
        )

        let cachedModules = try DyldCache.listModules()
        #expect(!cachedModules.isEmpty, "Expected at least one image in the cache header")
        print("Modules in cache: \(cachedModules.count)")
        
        modulePath = "/System/Library/PrivateFrameworks/UIKitMacHelper.framework/Versions/A/UIKitMacHelper"
        print("Loading module: \(modulePath)")
        try DyldCache.loadModule(modulePath)
        
        modulePath = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
        print("Loading module: \(modulePath)")
        try DyldCache.loadModule(modulePath)

        let globalOffsetTableCount = try DyldCache.loadGlobalOffsetTables()
        print("Global offset tables loaded: \(globalOffsetTableCount)")

        try Database.save()
        try Database.close()
    }
}
