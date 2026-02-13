# Compatibility Validation Matrix

Date: 2026-02-13 (updated)

This matrix tracks what has been validated across operating systems, compilers,
and validation profiles.

## Validation profiles

- `full`: configure + build + full CTest run (all available tests)
- `unit`: configure + build + unit/API-parity tests only
- `compile-only`: configure + build only

Automation helper:

```bash
scripts/run_validation_matrix.sh [full|unit|compile-only] [build-dir] [build-type]
```

Environment requirements:

- `IDASDK` is required for all profiles (headers + ida-cmake bootstrap).
- `IDADIR` (or platform auto-discovery) is required for full integration-test
  coverage. Without a runtime install, integration tests are skipped by CMake.

## Current matrix status

| OS | Arch | Compiler | Build Type | Profile | Runtime | Status | Evidence |
|---|---|---|---|---|---|---|---|
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | default (`CMAKE_BUILD_TYPE=`) | full | IDA 9.3 | pass | 16/16 tests (`build/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | compile-only | none | pass | build successful (`build-matrix-compile/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | unit | optional | pass | 2/2 tests (`build-matrix-unit/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | full | IDA 9.3 | pass | 16/16 tests (`build-matrix-full/`, via script) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | Release | full | IDA 9.3 | pass | 16/16 tests (`build-release/`) |
| Linux | x86_64 | GCC 13+ | RelWithDebInfo | compile-only | none | pending | queued |
| Linux | x86_64 | Clang 17+ | RelWithDebInfo | compile-only | none | pending | queued |
| Windows | x64 | MSVC v143 | RelWithDebInfo | compile-only | none | pending | queued |
| Linux | x86_64 | GCC 13+ | RelWithDebInfo | full | IDA 9.3 | pending | requires runtime install |
| Windows | x64 | MSVC v143 | RelWithDebInfo | full | IDA 9.3 | pending | requires runtime install |

## Recommended commands per row

```bash
# Full validation (with IDA runtime available)
scripts/run_validation_matrix.sh full build-matrix-full RelWithDebInfo

# Compiler/OS smoke validation without runtime integration tests
scripts/run_validation_matrix.sh compile-only build-matrix-compile RelWithDebInfo

# Unit/API parity only
scripts/run_validation_matrix.sh unit build-matrix-unit RelWithDebInfo
```

## Notes

- On macOS, linking against IDA 9.3 dylibs can emit deployment-target warnings
  (`built for newer version 12.0`). Current runs are stable and all tests pass.
- Full multi-OS completion requires Linux and Windows hosts with licensed IDA
  runtime installations available to the test harness.
