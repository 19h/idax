// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "IDAX",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "IDAX", targets: ["IDAX"]),
        .library(name: "IDAXShared", type: .dynamic, targets: ["IDAX"]),
    ],
    targets: [
        .systemLibrary(
            name: "CIDAX",
            path: "bindings/swift/Sources/CIDAX",
            pkgConfig: "idax-swift"
        ),
        .target(
            name: "IDAX",
            dependencies: ["CIDAX"],
            path: "bindings/swift/Sources/IDAX"
        ),
        .testTarget(
            name: "IDAXTests",
            dependencies: ["IDAX", "CIDAX"],
            path: "bindings/swift/Tests/IDAXTests"
        ),
        .executableTarget(
            name: "IDAXRuntimeTests",
            dependencies: ["IDAX", "CIDAX"],
            path: "bindings/swift/Tests/Runtime"
        ),
        .executableTarget(
            name: "IDAXInventory",
            dependencies: ["IDAX"],
            path: "bindings/swift/Examples/Inventory"
        ),
    ],
    swiftLanguageModes: [.v6]
)
