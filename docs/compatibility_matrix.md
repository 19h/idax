# Compatibility Validation Matrix

Date: 2026-02-14 (updated after open-point closure automation run)

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
  profiles across Linux, macOS arm64, and Windows.
- Hosted matrix sets `IDAX_BUILD_EXAMPLES=ON` and
  `IDAX_BUILD_EXAMPLE_ADDONS=ON` plus `IDAX_BUILD_EXAMPLE_TOOLS=ON` so
  plugin/loader/procmod addons and idalib tool-port examples are compiled on
  every row.

Environment requirements:

- `IDASDK` is required for all profiles (headers + ida-cmake bootstrap).
- `IDADIR` (or platform auto-discovery) is required for full integration-test
  coverage. Without a runtime install, integration tests are skipped by CMake.
- Appcall runtime-path validation is tracked separately in
  `docs/appcall_runtime_validation.md`.

## Current matrix status

| OS | Arch | Compiler | Build Type | Profile | Runtime | Status | Evidence |
|---|---|---|---|---|---|---|---|
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | default (`CMAKE_BUILD_TYPE=`) | full | IDA 9.3 | pass | 16/16 tests (`build/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | full | IDA 9.3 | pass | 16/16 tests (`build-matrix-full/`, rerun via script) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | full + packaging | IDA 9.3 | pass | 16/16 + `build-matrix-full-pack/idax-0.1.0-Darwin.tar.gz` |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | Release | full | IDA 9.3 | pass | 16/16 tests (`build-release/`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | tool-port runtime (non-debugger flows) | IDA 9.3 | pass | `build-port-gap/examples/idax_ida2py_port --list-user-symbols ...`, `build-port-gap/examples/idax_idalib_dump_port --list ...`, `build-port-gap/examples/idax_idalib_lumina_port ...` |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | tool-port appcall smoke | IDA 9.3 | blocked | launch attempts fail with `start_process failed (return code: -1)` in this host runtime (`build-open-points-run2/logs/appcall-smoke.log`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | tool-port lumina smoke | IDA 9.3 + Lumina service | pass | `pull: requested=1 succeeded=1 failed=0`, `push: requested=1 succeeded=1 failed=0` (`build-open-points-run2/logs/lumina-smoke.log`) |
| Linux | x86_64 | GCC 13.3.0 | RelWithDebInfo | compile-only | none | pass | GitHub Actions `compile-only - linux-x86_64` (`job-logs1.txt`), profile complete |
| Linux | x86_64 | GCC 13.3.0 | RelWithDebInfo | unit | none | pass | GitHub Actions `unit - linux-x86_64` (`job-logs4.txt`), 2/2 tests passed |
| macOS 14 | arm64 | AppleClang 15.0.0.15000309 | RelWithDebInfo | compile-only | none | pass | GitHub Actions `compile-only - macos-arm64` (`job-logs2.txt`), profile complete |
| macOS 14 | arm64 | AppleClang 15.0.0.15000309 | RelWithDebInfo | unit | none | pass | GitHub Actions `unit - macos-arm64` (`job-logs5.txt`), 2/2 tests passed |
| Windows Server 2025 | x64 | MSVC 19.44.35222.0 | RelWithDebInfo | compile-only | none | pass | GitHub Actions `compile-only - windows-x64` (`job-logs3.txt`), profile complete |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | compile-only | none | pass | local rerun with example addons ON (`build-matrix-jbc-compile/`, includes `idax_jbc_full_loader` + `idax_jbc_full_procmod`) |
| macOS 14 | arm64 | AppleClang 17.0.0.17000603 | RelWithDebInfo | unit | optional | pass | local rerun with example addons ON (`build-matrix-jbc-unit/`, 2/2 tests, examples built including JBC full pair) |
| Linux | x86_64 | GCC 13.3.0 | RelWithDebInfo | compile-only | none | pass | build successful (`build-matrix-linux-gcc-docker/`) |
| Linux | x86_64 | Clang 18.1.3 | RelWithDebInfo | compile-only | none | fail | baseline container run fails because `std::expected` is unavailable with this compiler/libstdc++ pairing (`build-matrix-linux-clang18-amd64-baseline/`) |
| Linux | x86_64 | Clang 19.1.1 | RelWithDebInfo | compile-only | none | pass | baseline container run passes with `IDAX_BUILD_EXAMPLE_ADDONS=OFF` and `IDAX_BUILD_EXAMPLE_TOOLS=OFF` (`build-matrix-linux-clang19-amd64-baseline/`) |
| Linux | x86_64 | Clang 19.1.1 | RelWithDebInfo | compile-only (+tools/addons) | none | fail | current SDK checkout lacks `x64_linux_clang_64` runtime libs needed for addon/tool linkage (`build-matrix-linux-clang19-amd64-docker/`, `build-matrix-linux-clang19-amd64-noaddons/`) |
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

# Open-point closure sweep (full matrix + appcall + lumina)
scripts/run_open_points.sh build-open-points RelWithDebInfo
```

## Notes

- Hosted log bundle audit (`job-logs1.txt`..`job-logs5.txt`) confirms all
  provided jobs succeeded via `Complete job name`,
  `validation profile '<profile>' complete`, and `100% tests passed` markers.
- On macOS, linking against IDA 9.3 dylibs can emit deployment-target warnings
  (`built for newer version 12.0`). Current runs are stable and all tests pass.
- Tool-port example executables now prefer real IDA runtime dylibs when
  available (`IDADIR` or common macOS install paths), which avoids SDK-stub
  runtime symbol-mismatch crashes in local functional runs.
- Open-point closure automation now exists in `scripts/run_open_points.sh`; it
  runs full validation when runtime is present, then attempts appcall and
  lumina smoke paths and classifies each as pass/blocked/fail.
- Packaging output is pinned to the selected build dir via `cpack -B <build-dir>`
  in the matrix script.
- Linux Clang 18 in Ubuntu 24.04 fails baseline C++23 builds because
  libstdc++'s `<expected>` guard requires `__cpp_concepts >= 202002L`, while
  this compiler reports `201907L`.
- Linux Clang 19 in Ubuntu 24.04 passes baseline compile-only validation
  (`IDAX_BUILD_EXAMPLE_ADDONS=OFF`, `IDAX_BUILD_EXAMPLE_TOOLS=OFF`).
- In the current SDK checkout, Linux Clang addon/tool rows fail when ON because
  `x64_linux_clang_64` runtime libs are missing (`libida.so` / `libidalib.so`).
- On the current macOS host/runtime, appcall smoke is blocked by debugger
  backend readiness (`start_process failed`, return code `-1`) despite
  successful fixture/tool setup and launch fallback attempts.
- On the current macOS host/runtime, Lumina pull/push smoke succeeds against the
  configured service (`build-open-points-run2/logs/lumina-smoke.log`).
- Full multi-OS completion requires Linux and Windows hosts with licensed IDA
  runtime installations available to the test harness.

## Host execution checklist

Linux host (GCC/Clang):

```bash
export IDASDK=/path/to/ida-sdk
export IDADIR=/path/to/ida

# compile-only row(s)
scripts/run_validation_matrix.sh compile-only build-matrix-linux-gcc RelWithDebInfo

# Linux Clang baseline (current known-good in Ubuntu 24.04)
export CC=clang-19
export CXX=clang++-19
IDAX_BUILD_EXAMPLE_ADDONS=OFF IDAX_BUILD_EXAMPLE_TOOLS=OFF \
  scripts/run_validation_matrix.sh compile-only build-matrix-linux-clang19 RelWithDebInfo

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
