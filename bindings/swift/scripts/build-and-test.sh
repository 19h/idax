#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
native_build_dir="${IDAX_SWIFT_BUILD_DIR:-${repo_root}/build-swift-native}"

: "${IDADIR:?Set IDADIR to the IDA 9.4 directory containing libida and libidalib}"
: "${IDASDK:?Set IDASDK to the IDA 9.4 SDK source directory}"
command -v cmake >/dev/null
command -v pkg-config >/dev/null
command -v swift >/dev/null

native_options=()
if [[ "$(uname -s)" == Darwin ]]; then
    native_options+=(-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0)
fi

cmake -S "${repo_root}" -B "${native_build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DIDASDK="${IDASDK}" \
    -DIDAX_BUILD_SWIFT=ON \
    -DIDAX_SWIFT_RUNTIME_DIR="${IDADIR}" \
    -DIDAX_BUILD_TESTS=OFF \
    -DIDAX_BUILD_EXAMPLES=OFF "${native_options[@]}"
cmake --build "${native_build_dir}" --config Release --target idax_swift_native idax_swift_runtime_fixture --parallel

export PKG_CONFIG_PATH="${native_build_dir}/bindings/swift/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
case "$(uname -s)" in
    Darwin) export DYLD_LIBRARY_PATH="${IDADIR}${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}" ;;
    Linux) export LD_LIBRARY_PATH="${IDADIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" ;;
esac

# Runtime search paths belong to the consuming executable, and remain command
# arguments rather than unsafe package-manifest settings. Apple's toolchain
# launchers may discard DYLD_LIBRARY_PATH before loading XCTest bundles.
# SwiftPM does not track the external pkg-config archive as a link input.
# Remove prior package products so validation always links the native rebuild.
swift package --build-system native --package-path "${repo_root}" clean
swift test --build-system native --package-path "${repo_root}" \
    -Xlinker -rpath -Xlinker "${IDADIR}" "$@"
swift run --build-system native --package-path "${repo_root}" \
    -Xlinker -rpath -Xlinker "${IDADIR}" IDAXRuntimeTests \
    "${IDAX_SWIFT_TEST_BINARY:-${native_build_dir}/bindings/swift/idax_swift_runtime_fixture}"
example_workspace="$(mktemp -d "${TMPDIR:-/tmp}/idax-swift-example.XXXXXXXX")"
trap 'rm -rf -- "${example_workspace}"' EXIT
cp "${IDAX_SWIFT_TEST_BINARY:-${native_build_dir}/bindings/swift/idax_swift_runtime_fixture}" \
    "${example_workspace}/fixture"
swift run --build-system native --package-path "${repo_root}" \
    -Xlinker -rpath -Xlinker "${IDADIR}" IDAXInventory \
    "${example_workspace}/fixture"
python3 "${script_dir}/check-consumer.py"
