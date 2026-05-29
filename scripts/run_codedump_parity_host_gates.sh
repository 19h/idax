#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUILD_DIR="${1:-${ROOT}/build-codedump-parity-host}"
FIXTURE="${2:-${ROOT}/tests/fixtures/simple_appcall_linux64}"
BUILD_TYPE="${3:-RelWithDebInfo}"

QT_CLIPBOARD="${IDAX_ENABLE_QT_CLIPBOARD:-OFF}"
JOBS="${IDAX_JOBS:-2}"

truthy() {
  local value="${1:-}"
  [[ -n "${value}" && "${value}" != "0" && "${value}" != "false" && "${value}" != "FALSE" ]]
}

host_evidence_modes() {
  local modes=()
  if truthy "${IDAX_RUN_MODAL_FORMS:-}"; then
    modes+=("modal")
  fi
  if truthy "${IDAX_RUN_QT_CLIPBOARD:-}"; then
    modes+=("qt-clipboard")
  fi
  if truthy "${IDAX_RUN_HEXRAYS_SESSION:-}"; then
    modes+=("hexrays")
  fi
  if [[ "${#modes[@]}" -eq 0 ]]; then
    modes+=("default")
  fi
  printf '%s\n' "${modes[@]}"
}

host_evidence_slug() {
  local modes=("$@")
  local IFS=-
  echo "${modes[*]}"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  assert_modes() {
    local expected="$1"
    local IDAX_RUN_MODAL_FORMS="${2:-}"
    local IDAX_RUN_QT_CLIPBOARD="${3:-}"
    local IDAX_RUN_HEXRAYS_SESSION="${4:-}"
    local modes=()
    local actual

    mapfile -t modes < <(host_evidence_modes)
    actual="$(host_evidence_slug "${modes[@]}")"
    if [[ "${actual}" != "${expected}" ]]; then
      echo "error: expected host evidence modes '${expected}', got '${actual}'" >&2
      exit 1
    fi
  }

  assert_modes "default" "" "" ""
  assert_modes "modal" "1" "" ""
  assert_modes "qt-clipboard" "" "1" ""
  assert_modes "hexrays" "" "" "1"
  assert_modes "modal-qt-clipboard" "1" "1" ""
  assert_modes "modal-hexrays" "1" "" "1"
  assert_modes "qt-clipboard-hexrays" "" "1" "1"
  assert_modes "modal-qt-clipboard-hexrays" "1" "1" "1"
  assert_modes "default" "0" "false" "FALSE"

  if env -u IDAX_QT6_DIR \
      IDAX_RUN_QT_CLIPBOARD=1 \
      IDAX_ENABLE_QT_CLIPBOARD=ON \
      "$0" "${tmpdir}/build-qt-missing-dir" "${ROOT}/tests/fixtures/simple_appcall_linux64" "${BUILD_TYPE}" \
      >/dev/null 2>&1; then
    echo "error: expected Qt clipboard preflight without IDAX_QT6_DIR to fail" >&2
    exit 1
  fi

  if env \
      IDAX_RUN_QT_CLIPBOARD=1 \
      IDAX_ENABLE_QT_CLIPBOARD=ON \
      IDAX_QT6_DIR="${tmpdir}/does-not-exist" \
      "$0" "${tmpdir}/build-qt-bad-dir" "${ROOT}/tests/fixtures/simple_appcall_linux64" "${BUILD_TYPE}" \
      >/dev/null 2>&1; then
    echo "error: expected Qt clipboard preflight with missing IDAX_QT6_DIR path to fail" >&2
    exit 1
  fi

  if env \
      IDAX_RUN_HEXRAYS_SESSION=1 \
      "$0" "${tmpdir}/build-hexrays-missing-fixture" "${tmpdir}/missing-fixture" "${BUILD_TYPE}" \
      >/dev/null 2>&1; then
    echo "error: expected Hex-Rays preflight with missing fixture to fail" >&2
    exit 1
  fi

  echo "host-gate runner self-test ok"
  exit 0
fi

if [[ -n "${IDAX_EVIDENCE_LOG:-}" && "${IDAX_EVIDENCE_LOG_WRAPPED:-0}" != "1" ]]; then
  mkdir -p "$(dirname "${IDAX_EVIDENCE_LOG}")"

  set +e
  env IDAX_EVIDENCE_LOG_WRAPPED=1 "$0" "$@" 2>&1 | tee "${IDAX_EVIDENCE_LOG}"
  run_status="${PIPESTATUS[0]}"
  set -e
  if [[ "${run_status}" -ne 0 ]]; then
    exit "${run_status}"
  fi

  mapfile -t evidence_modes < <(host_evidence_modes)

  for evidence_mode in "${evidence_modes[@]}"; do
    {
      echo "[idax] verify evidence log: ${evidence_mode}"
      "${ROOT}/scripts/check_codedump_parity_evidence_log.sh" \
        "${IDAX_EVIDENCE_LOG}" "${evidence_mode}"
    } 2>&1 | tee -a "${IDAX_EVIDENCE_LOG}"
  done

  exit 0
fi

if [[ -n "${IDAX_EVIDENCE_LOG:-}" ]]; then
  echo "[idax] evidence log: ${IDAX_EVIDENCE_LOG}"
fi

if truthy "${IDAX_RUN_QT_CLIPBOARD:-}"; then
  if [[ "${QT_CLIPBOARD}" != "ON" && "${QT_CLIPBOARD}" != "1" && "${QT_CLIPBOARD}" != "TRUE" ]]; then
    echo "error: IDAX_RUN_QT_CLIPBOARD=1 requires IDAX_ENABLE_QT_CLIPBOARD=ON"
    echo "also set IDAX_QT6_DIR to an IDA-compatible Qt6 package built with QT_NAMESPACE=QT"
    exit 1
  fi
  if [[ -z "${IDAX_QT6_DIR:-}" ]]; then
    echo "error: IDAX_RUN_QT_CLIPBOARD=1 requires IDAX_QT6_DIR"
    echo "set IDAX_QT6_DIR to an IDA-compatible Qt6 package built with QT_NAMESPACE=QT"
    exit 1
  fi
  if [[ ! -d "${IDAX_QT6_DIR}" ]]; then
    echo "error: IDAX_QT6_DIR does not exist: ${IDAX_QT6_DIR}"
    exit 1
  fi
fi

if [[ "${FIXTURE}" = /* ]]; then
  FIXTURE_ABS="${FIXTURE}"
else
  FIXTURE_ABS="${PWD}/${FIXTURE}"
fi
FIXTURE_DIR="$(dirname "${FIXTURE_ABS}")"
if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "error: fixture directory does not exist: ${FIXTURE_DIR}"
  exit 1
fi
FIXTURE_ABS="$(cd "${FIXTURE_DIR}" && pwd -P)/$(basename "${FIXTURE_ABS}")"

if truthy "${IDAX_RUN_HEXRAYS_SESSION:-}" && [[ ! -f "${FIXTURE_ABS}" ]]; then
  echo "error: IDAX_RUN_HEXRAYS_SESSION=1 requires an existing fixture: ${FIXTURE_ABS}"
  exit 1
fi

cmake_args=(
  -S "${ROOT}"
  -B "${BUILD_DIR}"
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
  -DIDAX_BUILD_TESTS=ON
  -DIDAX_ENABLE_QT_CLIPBOARD="${QT_CLIPBOARD}"
)

if [[ -n "${IDAX_QT6_DIR:-}" ]]; then
  cmake_args+=("-DIDAX_QT6_DIR=${IDAX_QT6_DIR}")
fi

echo "[idax] configure: ${BUILD_DIR}"
echo "[idax] build type: ${BUILD_TYPE}"
echo "[idax] qt clipboard build: ${QT_CLIPBOARD}"
if [[ -n "${IDAX_QT6_DIR:-}" ]]; then
  echo "[idax] qt6 package: ${IDAX_QT6_DIR}"
fi
cmake "${cmake_args[@]}"

echo "[idax] build: idax_codedump_parity_host_gates_test"
cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" \
  --target idax_codedump_parity_host_gates_test -j "${JOBS}"

find_exe() {
  local candidate
  for candidate in \
    "${BUILD_DIR}/tests/integration/idax_codedump_parity_host_gates_test" \
    "${BUILD_DIR}/tests/integration/${BUILD_TYPE}/idax_codedump_parity_host_gates_test" \
    "${BUILD_DIR}/tests/integration/idax_codedump_parity_host_gates_test.exe" \
    "${BUILD_DIR}/tests/integration/${BUILD_TYPE}/idax_codedump_parity_host_gates_test.exe"; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

EXE="$(find_exe)"

DEFAULT_FIXTURE="${ROOT}/tests/fixtures/simple_appcall_linux64"
DEFAULT_I64="${ROOT}/tests/fixtures/simple_appcall_linux64.i64"
RESTORE_DEFAULT_FIXTURE=0
if [[ "${FIXTURE_ABS}" == "${DEFAULT_FIXTURE}" && -f "${DEFAULT_I64}" ]]; then
  if git -C "${ROOT}" diff --quiet -- "tests/fixtures/simple_appcall_linux64.i64"; then
    RESTORE_DEFAULT_FIXTURE=1
  fi
fi

restore_fixture() {
  if [[ "${RESTORE_DEFAULT_FIXTURE}" == "1" ]]; then
    if ! git -C "${ROOT}" diff --quiet -- "tests/fixtures/simple_appcall_linux64.i64"; then
      echo "[idax] restoring default .i64 fixture"
      git -C "${ROOT}" show HEAD:tests/fixtures/simple_appcall_linux64.i64 > "${DEFAULT_I64}"
    fi
  fi
}
trap restore_fixture EXIT

echo "[idax] gate: modal=${IDAX_RUN_MODAL_FORMS:-0} qt_clipboard=${IDAX_RUN_QT_CLIPBOARD:-0} hexrays=${IDAX_RUN_HEXRAYS_SESSION:-0}"
echo "[idax] fixture: ${FIXTURE_ABS}"
"${EXE}" "${FIXTURE_ABS}"
