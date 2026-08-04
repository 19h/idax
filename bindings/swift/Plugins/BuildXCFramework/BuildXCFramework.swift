// Stub plugin source — restored to satisfy Package.swift target resolution.
// The real implementation lives in scripts/build-xcframework.sh; this command
// plugin defers to that script when invoked.

import PackagePlugin
import Foundation

@main
struct BuildXCFramework: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let script = context.package.directoryURL
            .appending(path: "bindings/swift/scripts/build-xcframework.sh")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script.path] + arguments
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            throw NSError(
                domain: "BuildXCFramework",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "build-xcframework.sh failed"]
            )
        }
    }
}
