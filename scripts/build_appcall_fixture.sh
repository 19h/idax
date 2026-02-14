#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/tests/fixtures/simple_appcall_host.c"
OUT="${1:-${ROOT}/tests/fixtures/simple_appcall_host}"
CC_BIN="${CC:-cc}"

if [[ ! -f "${SRC}" ]]; then
  echo "error: fixture source not found: ${SRC}"
  exit 1
fi

OUT_DIR="$(dirname "${OUT}")"
mkdir -p "${OUT_DIR}"

echo "[idax] building appcall fixture"
echo "[idax] compiler: ${CC_BIN}"
echo "[idax] source: ${SRC}"
echo "[idax] output: ${OUT}"

"${CC_BIN}" -std=c11 -O0 -g -fno-omit-frame-pointer -fno-inline \
  "${SRC}" -o "${OUT}"

echo "[idax] fixture build complete"
