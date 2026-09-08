# IDAX for Swift

Swift bindings for the current IDAX C++ domains, including native plugins, loaders, processor modules, decompiler trees and microcode, type metadata, debugger callbacks, and dyld-cache services. The public API contains Swift values and checked owners. SDK pointers and private C transport types are not public.

The source package declares Swift 6.0 language/toolchain support and macOS 13 as its deployment baseline. CI exercises the minimum Swift 6.0 toolchain and a current Swift toolchain on macOS against pinned IDA SDK 9.4 and the real IDA Professional 9.4 runtime. Linux native-build paths exist; a passing macOS run does not establish Linux Swift runtime support. Add-on binaries target the build host architecture.

## Build and run

Provide the SDK source root containing `include/pro.h`, an IDA runtime directory containing `libida` and `libidalib`, CMake, pkg-config, and Swift. CI pins SDK commit `6929db6868a524496eb66e76e4ec6c9d720a0594`.

From the repository root:

```sh
export IDASDK="<ida-sdk-root>"
export IDADIR="<ida-runtime>"
export IDAX_SWIFT_BUILD_DIR="$PWD/build-swift-native"
bash bindings/swift/scripts/build-and-test.sh
export PKG_CONFIG_PATH="$IDAX_SWIFT_BUILD_DIR/bindings/swift/pkgconfig"
swift run --build-system native \
  -Xlinker -rpath -Xlinker "$IDADIR" IDAXInventory "<binary-or-database>"
```

The helper builds `idax_swift_native`, runs XCTest, a separate process-main runtime client, the public inventory example, and a clean transitive SwiftPM consumer. It cleans prior SwiftPM products so C++ changes always reach the linked tests. Set `IDAX_SWIFT_REQUIRE_DECOMPILER=1` to require positive Hex-Rays runtime coverage. The native archive is deliberately named differently from the Swift `IDAX` product so case-insensitive filesystems resolve the intended library.

For an application package, add the checkout as a normal dependency:

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AnalysisClient",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../idax")],
    targets: [
        .executableTarget(name: "AnalysisClient", dependencies: [
            .product(name: "IDAX", package: "idax")
        ])
    ]
)
```

Use the same `PKG_CONFIG_PATH` while building the consumer and give its executable an rpath to the actual runtime. The package manifest uses ordinary system-library metadata and supports transitive dependencies. It contains no unsafe linker settings or SDK global replacements.

## First operations

The complete [inventory example](Examples/Inventory/main.swift) initializes the runtime, opens an input, copies the function inventory, and closes the database. SDK calls and explicit cleanup execute on the initializing operating-system thread. Swift actor isolation alone does not guarantee that thread.

```swift
import IDAX

try Runtime.initialize(arguments: ["analysis-client"])
try Database.open(path: "sample.bin")
let functions = try Functions.all()
for function in functions {
    print(function.name, function.start)
}
try Database.close()
```

Fallible operations use `throws(IDAError)`. Its category, numeric code, message, and context preserve the native structured error. Optional absence, an empty string or array, a false Boolean result, and a failure remain distinct. Inputs to C-string interfaces reject embedded NUL; length-bearing IDC strings preserve it.

Copied records, strings, arrays, and microcode graphs own their data. Native resources such as `TypeInfo`, `Decompiler.Function`, subscriptions, graph owners, and script values are reference types without `Sendable`. Assignment retains the same owner; `copy()` duplicates native values where copying is supported. Explicit `close()` is idempotent. Database close invalidates dependent owners, and retaining them across a later open does not revive them. Foreign-thread ARC cleanup is queued for the runtime thread.

Decompiler expression, statement, popup, and lifting contexts are callback borrows. Their methods validate the lease and reject use after callback return. Copy semantic values during the callback when they must survive it. An explicit `Decompiler.Session` remains open until dependent functions, snapshots, and registrations are released; early explicit close reports a conflict.

## Native add-ons

[Plugin](Examples/Modules/Plugin.swift), [loader](Examples/Modules/Loader.swift), and [processor](Examples/Modules/Processor.swift) examples implement protocol requirements and export named Swift bootstrap functions. The helper builds the real SDK descriptor, checks exported symbols, and links every add-on to one shared `IDAXShared` library.

```sh
python3 bindings/swift/scripts/build-module.py \
  --kind plugin --name SwiftPluginExample \
  --symbol idax_swift_example_plugin \
  --source bindings/swift/Examples/Modules/Plugin.swift \
  --output "$PWD/build-addons/plugins/SwiftPluginExample.dylib" \
  --support-dir "$PWD/build-addons/lib"
```

Use that same support directory for loaders under `build-addons/loaders` and processors under `build-addons/procs`. Keep the relative directory layout when moving the artifacts. Each add-on owns its descriptor and factory state; the shared image owns the Swift class definitions and runtime state. Rebuild the support image and its add-ons together. The helper relinks the shared image on every invocation because SwiftPM does not track changes to the external native archive. The resulting image still depends on the external IDA runtime.

## Coverage and validation

The [C++ inventory](cpp_api_inventory.json) comes from the authoritative [umbrella headers](../../include/ida/idax.hpp). The [Swift inventory](swift_api_inventory.json) comes from the compiled public symbol graph. The [mapping files](api_mapping) account separately for every C++ declaration, overload, enum case, and field, including explicit Swift adaptations for ARC, collections, OptionSet, typed throws, and private native construction. A mapping is declaration evidence; runtime tests establish behavior.

```sh
python3 bindings/swift/scripts/generate_values.py --check
python3 bindings/swift/scripts/inventory_cpp_api.py --check
python3 bindings/swift/scripts/inventory_swift_api.py --check
python3 bindings/swift/scripts/check_api_mapping.py --check
python3 bindings/swift/scripts/check-source-package.py
```

Run the Swift inventory after building the native-layout debug module. The source-package check audits a committed Git archive and compiles its extracted Swift target against the external native transport. `--index` checks the exact staged source tree before a commit. Source archives exclude local compiled products, SDK/runtime acquisitions, licenses for the installed IDA runtime, and identity-bearing host paths.

The [binding contract](CONTRACT.md) records assumptions, falsification probes, lifetime rules, bounded impacts, complexity, and the distinction between source, declaration, and actual-host evidence. The [PR review](../../docs/reviews/pr-6-swift.md) records the independently reproduced defects motivating this rewrite.
