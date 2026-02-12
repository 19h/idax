#!/usr/bin/env bash
set -euo pipefail

# Batch validation helper oriented around `idump <binary>` as preferred.

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [idump-path]"
  exit 1
fi

BIN="$1"
IDUMP_BIN="${2:-idump}"

if [[ ! -f "$BIN" ]]; then
  echo "error: fixture binary not found: $BIN"
  exit 1
fi

echo "[idax] running idump validation on $BIN"
"$IDUMP_BIN" "$BIN" >/tmp/idax_idump_validation.txt

LINES=$(wc -l </tmp/idax_idump_validation.txt | tr -d ' ')
BYTES=$(wc -c </tmp/idax_idump_validation.txt | tr -d ' ')

echo "[idax] idump output lines: $LINES"
echo "[idax] idump output bytes: $BYTES"
echo "[idax] report: /tmp/idax_idump_validation.txt"
