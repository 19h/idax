#!/usr/bin/env bash
# build-libs.sh — Build libidax.a and libidax_shim.a for the Swift package.
#
# Usage:
#   build-libs.sh [options]
#   build-libs.sh [output-dir] [build-type]          # legacy positional form
#
# Options:
#   --arch <arch>          Target architecture (e.g. arm64, x86_64).
#                          Sets CMAKE_OSX_ARCHITECTURES and compiler -arch flag.
#   --output-dir <dir>     Where to place the built .a files.
#                          Default: bindings/swift/.build-libs
#   --build-type <type>    CMake build type (Debug, Release, RelWithDebInfo, …).
#                          Default: RelWithDebInfo
#   -h, --help             Show this help message.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWIFT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SWIFT_DIR/../.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────
ARCH=""
OUTPUT_DIR=""
BUILD_TYPE=""

# ── Argument parsing ─────────────────────────────────────────────────────────
# Collect any remaining positional arguments for backwards-compat.
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"; shift 2 ;;
        --output-dir)
            OUTPUT_DIR="$2"; shift 2 ;;
        --build-type)
            BUILD_TYPE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set /{ /^#/!d; s/^# \{0,1\}//; p; }' "$0"
            exit 0 ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2; exit 1 ;;
        *)
            POSITIONAL+=("$1"); shift ;;
    esac
done

# Legacy positional form: build-libs.sh [output-dir] [build-type]
if [[ -z "$OUTPUT_DIR" && ${#POSITIONAL[@]} -ge 1 ]]; then
    OUTPUT_DIR="${POSITIONAL[0]}"
fi
if [[ -z "$BUILD_TYPE" && ${#POSITIONAL[@]} -ge 2 ]]; then
    BUILD_TYPE="${POSITIONAL[1]}"
fi

# Apply final defaults
OUTPUT_DIR="${OUTPUT_DIR:-$SWIFT_DIR/.build-libs}"
BUILD_TYPE="${BUILD_TYPE:-RelWithDebInfo}"

# ── Derived paths ────────────────────────────────────────────────────────────
# Use a per-architecture CMake build directory to avoid collisions when
# building for multiple architectures in parallel.
if [[ -n "$ARCH" ]]; then
    BUILD_DIR="$SWIFT_DIR/.cmake-build-${ARCH}"
else
    BUILD_DIR="$SWIFT_DIR/.cmake-build"
fi

# ── CMake: build libidax.a ───────────────────────────────────────────────────
echo "==> Building idax static library..."
[[ -n "$ARCH" ]] && echo "    Architecture: $ARCH"
echo "    Build type:   $BUILD_TYPE"
echo "    Build dir:    $BUILD_DIR"
echo "    Output dir:   $OUTPUT_DIR"

CMAKE_EXTRA_ARGS=()
if [[ -n "$ARCH" ]]; then
    CMAKE_EXTRA_ARGS+=("-DCMAKE_OSX_ARCHITECTURES=${ARCH}")
fi

cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
    -DIDAX_BUILD_TESTS=OFF \
    -DIDAX_BUILD_EXAMPLES=OFF \
    "${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"}"

cmake --build "$BUILD_DIR" --target idax --config "$BUILD_TYPE"

# ── Copy libidax.a ───────────────────────────────────────────────────────────
echo "==> Building C shim..."
mkdir -p "$OUTPUT_DIR"

# Find the built libidax.a
LIBIDAX="$(find "$BUILD_DIR" -name 'libidax.a' -print -quit)"
if [ -z "$LIBIDAX" ]; then
    echo "ERROR: libidax.a not found in $BUILD_DIR" >&2
    exit 1
fi
cp "$LIBIDAX" "$OUTPUT_DIR/libidax.a"

# ── Compile the C shim ──────────────────────────────────────────────────────
SHIM_CPP="$REPO_ROOT/bindings/rust/idax-sys/shim/idax_shim.cpp"
IDASDK="${IDASDK:-}"

# If IDASDK is not set, try to use the SDK fetched by CMake
if [ -z "$IDASDK" ]; then
    FETCHED_SDK="$BUILD_DIR/_deps/ida_sdk-src"
    if [ -d "$FETCHED_SDK" ]; then
        echo "    Using FetchContent SDK at $FETCHED_SDK"
        IDASDK="$FETCHED_SDK"
    else
        echo "ERROR: IDASDK environment variable not set and no FetchContent SDK found" >&2
        exit 1
    fi
fi

# Resolve SDK include path (handle both layouts)
SDK_INCLUDE="$IDASDK/include"
if [ ! -d "$SDK_INCLUDE" ] && [ -d "$IDASDK/src/include" ]; then
    SDK_INCLUDE="$IDASDK/src/include"
fi

SHIM_OBJ="$OUTPUT_DIR/idax_shim.o"

# Detect C++ standard flag
CXX="${CXX:-c++}"
if $CXX -std=c++23 -x c++ /dev/null -fsyntax-only 2>/dev/null; then
    STD_FLAG="-std=c++23"
else
    STD_FLAG="-std=c++2b"
fi

ARCH_FLAGS=()
if [[ -n "$ARCH" ]]; then
    ARCH_FLAGS+=("-arch" "$ARCH")
fi

$CXX $STD_FLAG "${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"}" \
    -c "$SHIM_CPP" -o "$SHIM_OBJ" \
    -I"$REPO_ROOT/bindings/c/include" \
    -I"$REPO_ROOT/include" \
    -I"$REPO_ROOT/src" \
    -I"$SDK_INCLUDE" \
    -D__EA64__ \
    -mmacosx-version-min=13.0 \
    -fPIC -O2

ar rcs "$OUTPUT_DIR/libidax_shim.a" "$SHIM_OBJ"
rm -f "$SHIM_OBJ"

echo "==> Libraries ready in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"/*.a
