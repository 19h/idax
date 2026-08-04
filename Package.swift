// swift-tools-version: 6.2
import PackageDescription
import Foundation

// CIDAX links the static libraries produced by bindings/swift/scripts/build-libs.sh.
// Run that script once before `swift build`; it writes libidax.a and libidax_shim.a
// into bindings/swift/.build-libs (override with IDAX_LIB_DIR).
//
// To ship the C shim to downstream Xcode projects, `swift package build-xcframework`
// packages the same libraries as CIDAX.xcframework.
let libraryDirectory: String = {
    if let directory = ProcessInfo.processInfo.environment["IDAX_LIB_DIR"] {
        return directory
    }
    let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
    return "\(packageDirectory)/bindings/swift/.build-libs"
}()

// libidax.a calls into the IDA runtime, so anything that links — the example
// executable and the test bundle — needs libida/libidalib on the link line.
// Mirrors the discovery order in bindings/rust/idax-sys/build.rs: $IDADIR
// first, then the installed applications.
let idaRuntimeDirectory: String? = {
    let fileManager = FileManager.default
    func containsRuntime(_ directory: String) -> Bool {
        fileManager.fileExists(atPath: "\(directory)/libida.dylib")
    }

    if let directory = ProcessInfo.processInfo.environment["IDADIR"], containsRuntime(directory) {
        return directory
    }

    let applications = (try? fileManager.contentsOfDirectory(atPath: "/Applications")) ?? []
    return applications
        .filter { $0.hasPrefix("IDA") && $0.hasSuffix(".app") }
        .sorted()
        .reversed()
        .map { "/Applications/\($0)/Contents/MacOS" }
        .first(where: containsRuntime)
}()

let idaRuntimeLinkerFlags: [String] = idaRuntimeDirectory.map { directory in
    ["-L\(directory)", "-lida", "-lidalib", "-Xlinker", "-rpath", "-Xlinker", directory]
} ?? []

let package = Package(
    name: "IDAX",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "IDAX", targets: ["IDAX"]),
    ],
    targets: [
        .target(
            name: "CIDAX",
            path: "bindings/swift/Sources/CIDAX",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-L\(libraryDirectory)",
                    "-lidax", "-lidax_shim",
                    // libidax.a is C++, but SPM links CIDAX as a C target and so
                    // does not pull in the C++ runtime on its own.
                    "-lc++",
                ] + idaRuntimeLinkerFlags),
            ]
        ),
        .target(
            name: "IDAX",
            dependencies: ["CIDAX"],
            path: "bindings/swift/Sources/IDAX",
            swiftSettings: [
                .enableExperimentalFeature("SafeInteropWrappers"),
            ]
        ),
        .executableTarget(
            name: "idax-example",
            dependencies: ["IDAX"],
            path: "bindings/swift/Examples"
        ),
        .testTarget(
            name: "IDAXTests",
            dependencies: ["IDAX"],
            path: "bindings/swift/Tests/IDAXTests"
        ),
        .plugin(
            name: "BuildXCFramework",
            capability: .command(
                intent: .custom(
                    verb: "build-xcframework",
                    description: "Build CIDAX.xcframework (macOS arm64 + x86_64) from the C++ sources."
                ),
                permissions: [
                    .writeToPackageDirectory(
                        reason: "Write the generated CIDAX.xcframework and CMake build artifacts into the package directory."
                    ),
                    .allowNetworkConnections(
                        scope: .all(),
                        reason: "CMake FetchContent may download the IDA SDK when IDASDK is unset."
                    ),
                ]
            ),
            path: "bindings/swift/Plugins/BuildXCFramework"
        ),
    ]
)
