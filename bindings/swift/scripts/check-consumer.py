#!/usr/bin/env python3
"""Build and run a clean transitive SwiftPM consumer using configured pkg-config."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    repository = Path(__file__).resolve().parents[3]
    runtime = os.environ.get("IDADIR")
    if not runtime:
        raise SystemExit("Set IDADIR to the IDA 9.4 runtime directory")
    identity = repository.name.lower()
    with tempfile.TemporaryDirectory(prefix="idax-swift-consumer-") as temporary:
        root = Path(temporary)
        middle = root / "middle"
        consumer = root / "consumer"
        (middle / "Sources/Middle").mkdir(parents=True)
        (consumer / "Sources/Consumer").mkdir(parents=True)
        (middle / "Package.swift").write_text(
            '// swift-tools-version: 6.0\nimport PackageDescription\n'
            'let package = Package(name: "Middle", platforms: [.macOS(.v13)], '
            'products: [.library(name: "Middle", targets: ["Middle"])], '
            'dependencies: [.package(path: ' + json.dumps(str(repository), ensure_ascii=False) + ')], '
            'targets: [.target(name: "Middle", dependencies: [.product(name: "IDAX", package: '
            + json.dumps(identity) + ')])])\n', encoding="utf-8")
        (middle / "Sources/Middle/Middle.swift").write_text('''import IDAX
public func probe() throws(IDAError) -> Int {
    try Runtime.initialize(arguments: ["idax-swift-consumer"], options: .init(quiet: true, pluginPolicy: .init(disableUserPlugins: true)))
    let unspecified = try TypeInfo()
    let kind = try unspecified.kind()
    precondition(kind == .unknown)
    try unspecified.close()
    let array = try TypeInfo.array(of: TypeInfo.pointer(to: TypeInfo.int32()), count: 2)
    let child = try array.arrayElementType().pointeeType()
    try array.close()
    let childSize = try child.size()
    precondition(childSize == 4)
    try child.close()
    let type = try TypeInfo.int32()
    let size = try type.size()
    try type.close()
    return size
}
''', encoding="utf-8")
        (consumer / "Package.swift").write_text('''// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "Consumer", platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../middle")],
    targets: [.executableTarget(name: "Consumer", dependencies: [.product(name: "Middle", package: "middle")])])
''', encoding="utf-8")
        (consumer / "Sources/Consumer/main.swift").write_text('''import Middle
let size = try probe()
precondition(size == 4)
print("PASS: clean transitive SwiftPM consumer initializes and calls the real native runtime")
''', encoding="utf-8")
        subprocess.run(["swift", "run", "--package-path", str(consumer),
                        "-Xlinker", "-rpath", "-Xlinker", runtime, "Consumer"], check=True)


if __name__ == "__main__":
    main()
