#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[idax] cross-namespace naming and API consistency audit"

echo "[audit] public headers:"
find "$ROOT/include/ida" -name '*.hpp' | wc -l

echo "[audit] unexpected raw SDK leaks in public headers:"
rg -n "\bea_t\b|\bfunc_t\b|\bsegment_t\b|\btinfo_t\b|\bqstring\b|\bnetnode\b" \
  "$ROOT/include/ida" || true

echo "[audit] std::expected usage count:"
rg -n "std::expected|Result<|Status" "$ROOT/include/ida" | wc -l

echo "[audit] done"
