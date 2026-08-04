# IDA 9.4 Dyld Cache Adaptation

## Motivation

IDA 9.4 replaces the private numeric dscu command surface used by earlier
versions with a public service in `dscu.h`. The new `dscu_svc_t` API provides
typed image enumeration, region discovery, atomic load requests, loaded-state
queries, and a new cache-wide data region type. IDAX now uses this supported
surface whenever it is compiled with IDA SDK 9.4 or newer.

## Implementation

`ida::dyld_cache` selects its backend at compile time:

- IDA SDK 9.4 or newer calls `get_dscu_svc()`, uses image indexes for image
  loads, and builds `dscu_load_request_t` values for region loads.
- IDA SDK 9.3 retains the established netnode and plugin-mode compatibility
  backend. Existing public IDAX source remains build-compatible.
- `load_gaps` maps to the 9.4 `rt_unknown` region type. The historical name is
  preserved for source compatibility, while the CLI also exposes
  `--load-unknown-region` and `--load-unknown-regions`.
- `load_cache_data` and Swift `DyldCache.loadCacheData` expose 9.4
  `rt_cache_data`. An IDA 9.3 build returns Unsupported for this operation.
- `load_dyld_header` remains callable on both versions. It is idempotent on
  IDA 9.4 because the dedicated DSC loader creates the header initially.

IDA SDK 9.4 also replaced the old root `bootstrap.cmake` entry point with the
`src/cmake/idasdkConfig.cmake` package. The root CMake project recognizes both
layouts so the same IDAX source tree can be configured with either SDK.

## Dynamic Framework Symbol Isolation

The Swift framework carries definitions for the IDA SDK data declarations
`callui`, `dbg`, and `under_debugger` so the framework can be linked with
dynamic IDA symbol lookup. Those definitions must remain hidden. Exporting
them allows the dynamic loader to interpose IDA's real globals when the 9.4
`_ida_dscu.so` plugin is loaded, which can redirect plugin calls through a null
stub and crash during `init_library`.

The framework build now emits these symbols with hidden visibility. They still
satisfy internal framework references but cannot replace IDA runtime symbols.

## Compatibility and Distribution

The committed `CIDAX.xcframework` is universal for macOS arm64 and x86_64 and
is built against IDA SDK 9.4. Consumers must provide their own compatible IDA
Professional runtime and license. Set `IDADIR` to the matching runtime:

```bash
export IDADIR="/Applications/IDA Professional 9.4.app/Contents/MacOS"
```

When targeting IDA 9.3, rebuild the framework from source with the 9.3 SDK.
Do not assume a framework built against one SDK generation is a portable
replacement for the other generation's dscu implementation.

## Validation

The adaptation is covered by IDA SDK 9.3 and 9.4 C++ builds, Swift package
tests, universal framework symbol inspection, and real IDA 9.4 runs. The real
cache checks created a database containing AppKit and SwiftUI, then separately
loaded six cache-wide data regions and saved the result successfully.
