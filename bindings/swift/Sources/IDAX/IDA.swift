// IDAX — Swift bindings for the idax C++ IDA SDK wrapper.
//
// Module: IDAX
// Backing C module: CIDAX
//
// Usage:
//   import IDAX
//   guard IDARuntime.isAvailable else { fatalError("IDA Pro not installed") }
//   try Database.initialize()
//   try Database.open("firmware.i64")
//   try Analysis.wait()
//   for seg in try Segment.all() { print(seg.name) }

import Darwin

/// IDA Pro runtime availability.
///
/// The IDAX library loads IDA's shared libraries (`libida.dylib` /
/// `libida64.so`) at runtime via `dlopen` rather than linking them
/// at build time.  Use ``isAvailable`` to check whether the IDA
/// runtime can be located before calling any IDAX function.
///
/// ```swift
/// guard IDARuntime.isAvailable else {
///     print("IDA Pro is not installed")
///     return
/// }
/// try Database.initialize()
/// ```
public enum IDARuntime {

    /// Whether the IDA Pro runtime libraries can be located on this system.
    ///
    /// Uses file-existence checks (`access`) instead of `dlopen` to avoid
    /// pre-loading `libida.dylib`.  Pre-loading would cause the C shim's
    /// `IdaLibLoader::ensure_loaded()` to skip loading `libidalib.dylib`
    /// (which exports `init_library`), leading to a crash.
    ///
    /// The actual loading happens inside ``Database/initialize()`` via
    /// the C shim's `IdaLibLoader`.
    public static var isAvailable: Bool {
        #if os(macOS)
        let libName = "libida.dylib"
        #elseif os(Linux)
        let libName = "libida64.so"
        #else
        return false
        #endif

        // Already loaded (e.g. running as an IDA plugin)?
        if dlopen(libName, RTLD_LAZY | RTLD_NOLOAD) != nil {
            return true
        }

        // $IDADIR takes priority.
        if let env = getenv("IDADIR") {
            let path = String(cString: env) + "/" + libName
            if access(path, F_OK) == 0 { return true }
        }

        return discoverIDA(libName)
    }

    // MARK: - Platform-specific discovery

    #if os(macOS)
    private static func discoverIDA(_ libName: String) -> Bool {
        guard let dir = opendir("/Applications") else { return false }
        defer { closedir(dir) }
        while let entry = readdir(dir) {
            var nameBuf = entry.pointee.d_name
            let name = withUnsafeBytes(of: &nameBuf) { buf in
                String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            guard name.hasPrefix("IDA"), name.hasSuffix(".app") else { continue }
            let path = "/Applications/\(name)/Contents/MacOS/\(libName)"
            if access(path, F_OK) == 0 { return true }
        }
        return false
    }
    #elseif os(Linux)
    private static func discoverIDA(_ libName: String) -> Bool {
        let prefixes = ["/opt/idapro", "/opt/ida"]
        for prefix in prefixes {
            let path = "\(prefix)/\(libName)"
            if access(path, F_OK) == 0 { return true }
        }
        // Scan /opt for versioned directories (e.g. /opt/idapro-9.0).
        guard let dir = opendir("/opt") else { return false }
        defer { closedir(dir) }
        while let entry = readdir(dir) {
            var nameBuf = entry.pointee.d_name
            let name = withUnsafeBytes(of: &nameBuf) { buf in
                String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            guard name.hasPrefix("idapro-") || name.hasPrefix("ida-") else { continue }
            let path = "/opt/\(name)/\(libName)"
            if access(path, F_OK) == 0 { return true }
        }
        return false
    }
    #else
    private static func discoverIDA(_: String) -> Bool { false }
    #endif
}
