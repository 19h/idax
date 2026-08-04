#!/usr/bin/env bash
# build-xcframework.sh — Build a CIDAX.xcframework (arm64 + x86_64) for macOS.
#
# Usage:
#   build-xcframework.sh [output-dir] [build-type]
#
# Arguments:
#   output-dir   Where to place the .xcframework (default: $SWIFT_DIR/Frameworks)
#   build-type   CMake build type (default: RelWithDebInfo)
#
# Environment:
#   IDASDK       IDA SDK root (passed through to build-libs.sh)
#
# The script calls build-libs.sh twice (arm64, x86_64), merges the resulting
# static libraries, compiles the IDA SDK data symbol stubs, links everything
# into a dynamic framework with -undefined dynamic_lookup, and packages into
# an XCFramework via xcodebuild.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWIFT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SWIFT_DIR/../.." && pwd)"

# ── Arguments ──────────────────────────────────────────────────────────────
OUTPUT_DIR="${1:-$SWIFT_DIR/Frameworks}"
BUILD_TYPE="${2:-RelWithDebInfo}"

STAGING="$SWIFT_DIR/.xcframework-staging"
ARCHS=(arm64 x86_64)

echo "==> Building CIDAX.xcframework (dynamic)"
echo "    Output dir:  $OUTPUT_DIR"
echo "    Build type:  $BUILD_TYPE"
echo "    Staging dir: $STAGING"
echo ""

# ── Clean staging ──────────────────────────────────────────────────────────
rm -rf "$STAGING"
mkdir -p "$STAGING"

# ── Step 1: Build per-architecture libraries via build-libs.sh ─────────────
for arch in "${ARCHS[@]}"; do
    echo "==> Building libraries for $arch..."
    "$SCRIPT_DIR/build-libs.sh" \
        --arch "$arch" \
        --output-dir "$STAGING/$arch" \
        --build-type "$BUILD_TYPE"
    echo ""
done

# ── Step 2: Merge libidax.a + libidax_shim.a → libCIDAX.a per arch ────────
for arch in "${ARCHS[@]}"; do
    echo "==> Merging static libraries for $arch..."
    ARCH_DIR="$STAGING/$arch"
    libtool -static \
        "$ARCH_DIR/libidax.a" \
        "$ARCH_DIR/libidax_shim.a" \
        -o "$ARCH_DIR/libCIDAX.a"
    echo "    Created $ARCH_DIR/libCIDAX.a"
done

# ── Step 3: Compile stubs (callui, dbg, under_debugger) per arch ───────────
STUBS_SRC="$SWIFT_DIR/Sources/CIDAX/shim.c"
for arch in "${ARCHS[@]}"; do
    echo "==> Compiling SDK data stubs for $arch..."
    ARCH_DIR="$STAGING/$arch"
    STUBS_OBJ="$ARCH_DIR/shim_stubs.o"

    cc -arch "$arch" -mmacosx-version-min=13.0 -c "$STUBS_SRC" -o "$STUBS_OBJ" -O2
    ar r "$ARCH_DIR/libCIDAX.a" "$STUBS_OBJ"
    rm -f "$STUBS_OBJ"
    echo "    Added stubs to $ARCH_DIR/libCIDAX.a"
done

# ── Step 4: Link into dynamic framework per arch ────────────────────────────
# Using -undefined dynamic_lookup so IDA SDK symbols are resolved at runtime
# when libida.dylib is dlopen'd with RTLD_GLOBAL by ensure_loaded().
for arch in "${ARCHS[@]}"; do
    echo "==> Linking dynamic framework for $arch..."
    ARCH_DIR="$STAGING/$arch"
    FW_DIR="$ARCH_DIR/CIDAX.framework"
    mkdir -p "$FW_DIR/Headers" "$FW_DIR/Modules"

    c++ -dynamiclib \
        -arch "$arch" \
        -mmacosx-version-min=13.0 \
        -install_name @rpath/CIDAX.framework/CIDAX \
        -undefined dynamic_lookup \
        -all_load "$ARCH_DIR/libCIDAX.a" \
        -lc++ \
        -o "$FW_DIR/CIDAX"

    echo "    Created $FW_DIR/CIDAX"
done

# ── Step 5: Create universal (fat) framework ─────────────────────────────────
echo "==> Creating universal fat framework..."
UNIVERSAL_FW="$STAGING/universal/CIDAX.framework"
mkdir -p "$UNIVERSAL_FW/Headers" "$UNIVERSAL_FW/Modules"

lipo -create \
    "$STAGING/arm64/CIDAX.framework/CIDAX" \
    "$STAGING/x86_64/CIDAX.framework/CIDAX" \
    -output "$UNIVERSAL_FW/CIDAX"
echo "    $(lipo -info "$UNIVERSAL_FW/CIDAX")"

# ── Step 6: Prepare headers + modulemap ────────────────────────────────────
echo "==> Preparing headers..."
cp "$REPO_ROOT/bindings/c/include/idax_shim.h" "$UNIVERSAL_FW/Headers/"

cat > "$UNIVERSAL_FW/Modules/module.modulemap" <<'MODULEMAP'
framework module CIDAX {
    header "idax_shim.h"
    export *
}
MODULEMAP

# Info.plist (required for framework bundles)
cat > "$UNIVERSAL_FW/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>CIDAX</string>
    <key>CFBundleIdentifier</key>
    <string>com.idax.CIDAX</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleExecutable</key>
    <string>CIDAX</string>
    <key>MinimumOSVersion</key>
    <string>13.0</string>
</dict>
</plist>
PLIST
echo "    Framework ready at $UNIVERSAL_FW"

# ── Step 7: Create XCFramework ─────────────────────────────────────────────
echo "==> Creating XCFramework..."
mkdir -p "$OUTPUT_DIR"

# Remove any previous XCFramework
rm -rf "$OUTPUT_DIR/CIDAX.xcframework"

xcodebuild -create-xcframework \
    -framework "$UNIVERSAL_FW" \
    -output "$OUTPUT_DIR/CIDAX.xcframework"

# ── Step 8: Clean up staging ──────────────────────────────────────────────
rm -rf "$STAGING"

# ── Step 9: Verify and print summary ──────────────────────────────────────
echo ""
echo "==> CIDAX.xcframework created successfully!"
echo ""
echo "--- Structure ---"
find "$OUTPUT_DIR/CIDAX.xcframework" -type f | head -20
echo ""

# Find the dylib inside the xcframework
XCFW_LIB="$(find "$OUTPUT_DIR/CIDAX.xcframework" -name 'CIDAX' -not -name '*.plist' -print -quit)"
if [ -n "$XCFW_LIB" ]; then
    echo "--- Architecture info ---"
    lipo -info "$XCFW_LIB"
    echo ""
    echo "--- Stub symbol check ---"
    nm "$XCFW_LIB" | grep '_callui' || echo "WARNING: _callui stub not found!"
    echo ""
    echo "--- Undefined symbols (IDA SDK, expected) ---"
    nm -u "$XCFW_LIB" | head -10
    echo "    ... ($(nm -u "$XCFW_LIB" | wc -l | tr -d ' ') total undefined symbols)"
    echo ""
fi

echo "==> Done: $OUTPUT_DIR/CIDAX.xcframework"
