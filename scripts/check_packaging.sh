#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:-build}"

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "error: build dir not found: $BUILD_DIR"
  exit 1
fi

echo "[idax] packaging check in $BUILD_DIR"

cmake --build "$BUILD_DIR"
cpack --config "$BUILD_DIR/CPackConfig.cmake"

PKG=$(ls "$BUILD_DIR"/*.tar.gz 2>/dev/null | head -n 1 || true)
if [[ -z "$PKG" ]]; then
  PKG=$(ls ./*.tar.gz 2>/dev/null | head -n 1 || true)
fi
if [[ -z "$PKG" ]]; then
  echo "error: no TGZ package produced"
  exit 1
fi

echo "[idax] package created: $PKG"
