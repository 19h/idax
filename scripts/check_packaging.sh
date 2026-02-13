#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:-build}"

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "error: build dir not found: $BUILD_DIR"
  exit 1
fi

echo "[idax] packaging check in $BUILD_DIR"

cmake --build "$BUILD_DIR"
cpack --config "$BUILD_DIR/CPackConfig.cmake" -B "$BUILD_DIR"

PKG=""
for candidate in "$BUILD_DIR"/*.tar.gz; do
  if [[ -f "$candidate" ]]; then
    PKG="$candidate"
    break
  fi
done

if [[ -z "$PKG" ]]; then
  echo "error: no TGZ package produced"
  exit 1
fi

echo "[idax] package created: $PKG"
