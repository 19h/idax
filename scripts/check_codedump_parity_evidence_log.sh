#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--self-test" ]]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  default_log="${tmpdir}/default.log"
  cat > "${default_log}" <<'LOG'
=== clipboard backend contract ===
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
=== host-gated Hex-Rays scoped session ===
[SKIP] set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host
codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped
LOG
  "$0" "${default_log}" default >/dev/null

  failed_summary_log="${tmpdir}/failed-summary.log"
  cat > "${failed_summary_log}" <<'LOG'
=== clipboard backend contract ===
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
=== host-gated Hex-Rays scoped session ===
[SKIP] set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host
codedump_parity_host_gates_test: 3 passed, 1 failed, 3 skipped
LOG
  if "$0" "${failed_summary_log}" default >/dev/null 2>&1; then
    echo "error: self-test expected failed summary to fail" >&2
    exit 1
  fi

  contaminated_summary_log="${tmpdir}/contaminated-summary.log"
  cat > "${contaminated_summary_log}" <<'LOG'
=== clipboard backend contract ===
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
=== host-gated Hex-Rays scoped session ===
[SKIP] set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host
codedump_parity_host_gates_test: 3 passed, 1 failed, 3 skipped
codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped
LOG
  if "$0" "${contaminated_summary_log}" default >/dev/null 2>&1; then
    echo "error: self-test expected contaminated failed summary to fail" >&2
    exit 1
  fi

  if "$0" "${default_log}" not-a-gate >/dev/null 2>&1; then
    echo "error: self-test expected unknown gate to fail" >&2
    exit 1
  fi

  default_missing_clipboard_log="${tmpdir}/default-missing-clipboard.log"
  cat > "${default_missing_clipboard_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
=== host-gated Hex-Rays scoped session ===
[SKIP] set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host
codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped
LOG
  if "$0" "${default_missing_clipboard_log}" default >/dev/null 2>&1; then
    echo "error: self-test expected missing default clipboard section to fail" >&2
    exit 1
  fi

  hexrays_log="${tmpdir}/hexrays.log"
  cat > "${hexrays_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
=== host-gated Hex-Rays scoped session ===
codedump_parity_host_gates_test: 9 passed, 0 failed, 2 skipped
LOG
  "$0" "${hexrays_log}" hexrays >/dev/null

  hexrays_skip_log="${tmpdir}/hexrays-skip.log"
  cat > "${hexrays_skip_log}" <<'LOG'
=== host-gated Hex-Rays scoped session ===
[SKIP] set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host
codedump_parity_host_gates_test: 9 passed, 0 failed, 2 skipped
LOG
  if "$0" "${hexrays_skip_log}" hexrays >/dev/null 2>&1; then
    echo "error: self-test expected skipped Hex-Rays evidence to fail" >&2
    exit 1
  fi

  combined_log="${tmpdir}/combined.log"
  cat > "${combined_log}" <<'LOG'
=== clipboard backend contract ===

=== host-gated clipboard roundtrip ===

=== host-gated codedump-shaped typed form ===

=== host-gated Hex-Rays scoped session ===

codedump_parity_host_gates_test: 14 passed, 0 failed, 0 skipped
LOG
  "$0" "${combined_log}" hexrays >/dev/null
  "$0" "${combined_log}" modal >/dev/null
  "$0" "${combined_log}" qt-clipboard >/dev/null

  hexrays_too_few_passes_log="${tmpdir}/hexrays-too-few-passes.log"
  cat > "${hexrays_too_few_passes_log}" <<'LOG'
=== host-gated Hex-Rays scoped session ===
codedump_parity_host_gates_test: 8 passed, 0 failed, 0 skipped
LOG
  if "$0" "${hexrays_too_few_passes_log}" hexrays >/dev/null 2>&1; then
    echo "error: self-test expected weak Hex-Rays pass count to fail" >&2
    exit 1
  fi

  modal_ok_log="${tmpdir}/modal-ok.log"
  cat > "${modal_ok_log}" <<'LOG'
=== host-gated codedump-shaped typed form ===
codedump_parity_host_gates_test: 4 passed, 0 failed, 3 skipped
LOG
  "$0" "${modal_ok_log}" modal >/dev/null

  modal_skip_log="${tmpdir}/modal-skip.log"
  cat > "${modal_skip_log}" <<'LOG'
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped
LOG
  if "$0" "${modal_skip_log}" modal >/dev/null 2>&1; then
    echo "error: self-test expected skipped modal evidence to fail" >&2
    exit 1
  fi

  modal_missing_log="${tmpdir}/modal-missing.log"
  cat > "${modal_missing_log}" <<'LOG'
codedump_parity_host_gates_test: 4 passed, 0 failed, 3 skipped
LOG
  if "$0" "${modal_missing_log}" modal >/dev/null 2>&1; then
    echo "error: self-test expected missing modal section to fail" >&2
    exit 1
  fi

  modal_too_few_passes_log="${tmpdir}/modal-too-few-passes.log"
  cat > "${modal_too_few_passes_log}" <<'LOG'
=== host-gated codedump-shaped typed form ===
codedump_parity_host_gates_test: 1 passed, 0 failed, 3 skipped
LOG
  if "$0" "${modal_too_few_passes_log}" modal >/dev/null 2>&1; then
    echo "error: self-test expected weak modal pass count to fail" >&2
    exit 1
  fi

  qt_ok_log="${tmpdir}/qt-ok.log"
  cat > "${qt_ok_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
codedump_parity_host_gates_test: 2 passed, 0 failed, 3 skipped
LOG
  "$0" "${qt_ok_log}" qt-clipboard >/dev/null

  qt_skip_log="${tmpdir}/qt-skip.log"
  cat > "${qt_skip_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped
LOG
  if "$0" "${qt_skip_log}" qt-clipboard >/dev/null 2>&1; then
    echo "error: self-test expected skipped Qt clipboard evidence to fail" >&2
    exit 1
  fi

  qt_missing_log="${tmpdir}/qt-missing.log"
  cat > "${qt_missing_log}" <<'LOG'
codedump_parity_host_gates_test: 2 passed, 0 failed, 3 skipped
LOG
  if "$0" "${qt_missing_log}" qt-clipboard >/dev/null 2>&1; then
    echo "error: self-test expected missing Qt clipboard section to fail" >&2
    exit 1
  fi

  qt_too_few_passes_log="${tmpdir}/qt-too-few-passes.log"
  cat > "${qt_too_few_passes_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
codedump_parity_host_gates_test: 1 passed, 0 failed, 3 skipped
LOG
  if "$0" "${qt_too_few_passes_log}" qt-clipboard >/dev/null 2>&1; then
    echo "error: self-test expected weak Qt clipboard pass count to fail" >&2
    exit 1
  fi

  hexrays_missing_log="${tmpdir}/hexrays-missing.log"
  cat > "${hexrays_missing_log}" <<'LOG'
=== host-gated clipboard roundtrip ===
[SKIP] set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access
=== host-gated codedump-shaped typed form ===
[SKIP] set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host
codedump_parity_host_gates_test: 9 passed, 0 failed, 2 skipped
LOG
  if "$0" "${hexrays_missing_log}" hexrays >/dev/null 2>&1; then
    echo "error: self-test expected missing Hex-Rays section to fail" >&2
    exit 1
  fi

  echo "evidence log verifier self-test ok"
  exit 0
fi

if [[ $# -lt 2 ]]; then
  echo "usage: $0 [--self-test] | <evidence-log> <default|hexrays|modal|qt-clipboard>" >&2
  exit 2
fi

LOG="$1"
GATE="$2"

if [[ ! -f "${LOG}" ]]; then
  echo "error: evidence log not found: ${LOG}" >&2
  exit 1
fi

require_line() {
  local pattern="$1"
  local description="$2"
  if ! grep -Eq "${pattern}" "${LOG}"; then
    echo "error: missing ${description}" >&2
    exit 1
  fi
}

reject_line() {
  local pattern="$1"
  local description="$2"
  if grep -Eq "${pattern}" "${LOG}"; then
    echo "error: found ${description}" >&2
    exit 1
  fi
}

reject_section_skip() {
  local section="$1"
  if awk -v section="${section}" '
      $0 == "=== " section " ===" { in_section = 1; next }
      in_section && /^=== / { in_section = 0 }
      in_section && /\[SKIP\]/ { found = 1 }
      END { exit found ? 0 : 1 }
    ' "${LOG}"; then
    echo "error: ${section} was skipped" >&2
    exit 1
  fi
}

require_section() {
  local section="$1"
  if ! grep -Fxq "=== ${section} ===" "${LOG}"; then
    echo "error: missing ${section} section" >&2
    exit 1
  fi
}

reject_line '^codedump_parity_host_gates_test: [0-9]+ passed, [1-9][0-9]* failed, [0-9]+ skipped$' \
  "failed final summary"
require_line '^codedump_parity_host_gates_test: [0-9]+ passed, 0 failed, [0-9]+ skipped$' \
  "successful final summary"

case "${GATE}" in
  default)
    require_section "clipboard backend contract"
    require_section "host-gated clipboard roundtrip"
    require_section "host-gated codedump-shaped typed form"
    require_section "host-gated Hex-Rays scoped session"
    require_line '^codedump_parity_host_gates_test: 3 passed, 0 failed, 3 skipped$' \
      "default 3-pass/3-skip summary"
    require_line 'set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access' \
      "clipboard roundtrip skip"
    require_line 'set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host' \
      "modal typed-form skip"
    require_line 'set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host' \
      "Hex-Rays scoped-session skip"
    ;;
  hexrays)
    require_section "host-gated Hex-Rays scoped session"
    reject_section_skip "host-gated Hex-Rays scoped session"
    require_line '^codedump_parity_host_gates_test: (9|[1-9][0-9]+) passed, 0 failed, [0-9]+ skipped$' \
      "Hex-Rays scoped-session success summary"
    ;;
  modal)
    require_section "host-gated codedump-shaped typed form"
    reject_section_skip "host-gated codedump-shaped typed form"
    require_line '^codedump_parity_host_gates_test: ([4-9]|[1-9][0-9]+) passed, 0 failed, [0-9]+ skipped$' \
      "modal accepted-form success summary"
    ;;
  qt-clipboard)
    require_section "host-gated clipboard roundtrip"
    reject_section_skip "host-gated clipboard roundtrip"
    require_line '^codedump_parity_host_gates_test: ([2-9]|[1-9][0-9]+) passed, 0 failed, [0-9]+ skipped$' \
      "clipboard roundtrip success summary"
    ;;
  *)
    echo "error: unknown gate '${GATE}'" >&2
    exit 2
    ;;
esac

echo "evidence log ok: ${LOG} (${GATE})"
