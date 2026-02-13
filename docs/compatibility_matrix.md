# Compatibility Validation Matrix

Date: 2026-02-13 (updated after Linux Docker compile-only reruns)

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

GitHub Actions helper:

- `.github/workflows/validation-matrix.yml` runs `compile-only` + `unit`
  profiles across Linux, macOS (x86_64 + arm64), and Windows.
- Hosted matrix sets `IDAX_BUILD_EXAMPLES=ON` and
  `IDAX_BUILD_EXAMPLE_ADDONS=ON` so plugin/loader/procmod example targets are
  compiled on every row.

Environment requirements:

- `IDASDK` is required for all profiles (headers + ida-cmake bootstrap).
- `IDADIR` (or platform auto-discovery) is required for full integration-test
  coverage. Without a runtime install, integration tests are skipped by CMake.

## Current matrix status

| OS | Arch | Compiler | Build Type | Profile | Runtime | Status | Evidence |
|---|---|---|---|---|---|---|---|
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | default (`CMAKE_BUILD_TYPE=`) | full | IDA 9.3 | pass | 16/16 tests (`build/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | compile-only | none | pass | build successful (`build-matrix-compile/`, rerun) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | unit | optional | pass | 2/2 tests (`build-matrix-unit/`, rerun) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | full | IDA 9.3 | pass | 16/16 tests (`build-matrix-full/`, rerun via script) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | full + packaging | IDA 9.3 | pass | 16/16 + `build-matrix-full-pack/idax-0.1.0-Darwin.tar.gz` |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | Release | full | IDA 9.3 | pass | 16/16 tests (`build-release/`) |
| Linux | x86_64 | GCC 13.3.0 | RelWithDebInfo | compile-only | none | pass | build successful (`build-matrix-linux-gcc-docker/`) |
| Linux | x86_64 | Clang 18.1.3 | RelWithDebInfo | compile-only | none | fail | default toolchain misses `std::expected` (`build-matrix-linux-clang-docker/`); libc++ attempt hits SDK `snprintf` macro clash (`build-matrix-linux-clang-libcpp/`) |
| Windows | x64 | MSVC v143 | RelWithDebInfo | compile-only | none | pending | queued |
| Linux | x86_64 | GCC 13+ | RelWithDebInfo | full | IDA 9.3 | pending | requires runtime install |
| Windows | x64 | MSVC v143 | RelWithDebInfo | full | IDA 9.3 | pending | requires runtime install |

## Recommended commands per row

```bash
# Full validation (with IDA runtime available)
scripts/run_validation_matrix.sh full build-matrix-full RelWithDebInfo

# Full validation + package generation
RUN_PACKAGING=1 scripts/run_validation_matrix.sh full build-matrix-full RelWithDebInfo

# Compiler/OS smoke validation without runtime integration tests
scripts/run_validation_matrix.sh compile-only build-matrix-compile RelWithDebInfo

# Unit/API parity only
scripts/run_validation_matrix.sh unit build-matrix-unit RelWithDebInfo
```

## Notes

- On macOS, linking against IDA 9.3 dylibs can emit deployment-target warnings
  (`built for newer version 12.0`). Current runs are stable and all tests pass.
- Packaging output is pinned to the selected build dir via `cpack -B <build-dir>`
  in the matrix script.
- Linux Clang row currently fails in the Ubuntu 24.04 container because the
  selected C++ standard library/toolchain combo does not surface
  `std::expected` for this build configuration, while the GCC row passes under
  the same host setup.
- Forcing libc++ with Clang in this container does not currently unblock the
  row: IDA SDK `pro.h` stdio remaps (for example `snprintf`) conflict with
  libc++ standard headers.
- Full multi-OS completion requires Linux and Windows hosts with licensed IDA
  runtime installations available to the test harness.

## Host execution checklist

Linux host (GCC/Clang):

```bash
export IDASDK=/path/to/ida-sdk
export IDADIR=/path/to/ida

# compile-only row(s)
scripts/run_validation_matrix.sh compile-only build-matrix-linux-gcc RelWithDebInfo

# full row(s)
scripts/run_validation_matrix.sh full build-matrix-linux-gcc-full RelWithDebInfo
```

Windows host (MSVC):

```powershell
$env:IDASDK = "C:\path\to\ida-sdk"
$env:IDADIR = "C:\path\to\IDA"

# from a shell with CMake + MSVC toolchain configured
bash scripts/run_validation_matrix.sh compile-only build-matrix-win-msvc RelWithDebInfo
bash scripts/run_validation_matrix.sh full build-matrix-win-msvc-full RelWithDebInfo
```
