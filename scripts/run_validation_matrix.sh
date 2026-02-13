#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PROFILE="${1:-full}"
BUILD_DIR="${2:-$ROOT/build-matrix-${PROFILE}}"
BUILD_TYPE="${3:-RelWithDebInfo}"

BUILD_EXAMPLES="${IDAX_BUILD_EXAMPLES:-ON}"
RUN_PACKAGING="${RUN_PACKAGING:-0}"

case "$PROFILE" in
  full)
    BUILD_TESTS="ON"
    RUN_TESTS="1"
    TEST_REGEX=""
    ;;
  unit)
    BUILD_TESTS="ON"
    RUN_TESTS="1"
    TEST_REGEX="idax_unit_test|api_surface_parity"
    ;;
  compile-only)
    BUILD_TESTS="OFF"
    RUN_TESTS="0"
    TEST_REGEX=""
    ;;
  *)
    echo "usage: $0 [full|unit|compile-only] [build-dir] [build-type]"
    echo "example: $0 full build-matrix-release Release"
    exit 1
    ;;
esac

if [[ -z "${IDASDK:-}" ]]; then
  echo "error: IDASDK is not set"
  echo "set IDASDK to your ida-sdk path before running this script"
  exit 1
fi

echo "[idax] validation profile: $PROFILE"
echo "[idax] build dir: $BUILD_DIR"
echo "[idax] build type: $BUILD_TYPE"
echo "[idax] build tests: $BUILD_TESTS"
echo "[idax] build examples: $BUILD_EXAMPLES"

cmake -S "$ROOT" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DIDAX_BUILD_TESTS="$BUILD_TESTS" \
  -DIDAX_BUILD_EXAMPLES="$BUILD_EXAMPLES"

cmake --build "$BUILD_DIR" --config "$BUILD_TYPE"

if [[ "$RUN_TESTS" == "1" ]]; then
  if [[ -n "$TEST_REGEX" ]]; then
    ctest --test-dir "$BUILD_DIR" --output-on-failure -C "$BUILD_TYPE" -R "$TEST_REGEX"
  else
    ctest --test-dir "$BUILD_DIR" --output-on-failure -C "$BUILD_TYPE"
  fi
fi

if [[ "$RUN_PACKAGING" == "1" ]]; then
  cpack --config "$BUILD_DIR/CPackConfig.cmake" -B "$BUILD_DIR"
fi

echo "[idax] validation profile '$PROFILE' complete"
