#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${1:-${ROOT}/build-open-points}"
BUILD_TYPE="${2:-RelWithDebInfo}"
STRICT_MODE="${STRICT_MODE:-0}"

MATRIX_STATUS="skipped"
MATRIX_NOTE=""
APPCALL_STATUS="skipped"
APPCALL_NOTE=""
LUMINA_STATUS="skipped"
LUMINA_NOTE=""

if [[ -z "${IDASDK:-}" ]]; then
  echo "error: IDASDK is not set"
  echo "set IDASDK to your ida-sdk path before running this script"
  exit 1
fi

LOG_DIR="${BUILD_ROOT}/logs"
mkdir -p "${LOG_DIR}"

has_runtime_libs() {
  local dir="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    [[ -f "${dir}/libidalib.dylib" && -f "${dir}/libida.dylib" ]]
    return
  fi
  if [[ "$(uname -s)" == "Linux" ]]; then
    [[ -f "${dir}/libidalib.so" && -f "${dir}/libida.so" ]]
    return
  fi
  [[ -f "${dir}/idalib.lib" && -f "${dir}/ida.lib" ]]
}

detect_runtime_dir() {
  if [[ -n "${IDADIR:-}" ]] && has_runtime_libs "${IDADIR}"; then
    echo "${IDADIR}"
    return
  fi

  if [[ "$(uname -s)" == "Darwin" ]]; then
    local candidate
    for candidate in \
      "/Applications/IDA Professional 9.3.app/Contents/MacOS" \
      "/Applications/IDA Professional 9.2.app/Contents/MacOS"; do
      if has_runtime_libs "${candidate}"; then
        echo "${candidate}"
        return
      fi
    done
  fi
}

find_tool_binary() {
  local build_dir="$1"
  local base_name="$2"
  local candidate
  for candidate in \
    "${build_dir}/examples/${base_name}" \
    "${build_dir}/examples/${base_name}.exe" \
    "${build_dir}/examples/${BUILD_TYPE}/${base_name}" \
    "${build_dir}/examples/${BUILD_TYPE}/${base_name}.exe"; do
    if [[ -f "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

RUNTIME_DIR="$(detect_runtime_dir || true)"
if [[ -n "${RUNTIME_DIR}" ]]; then
  export IDADIR="${RUNTIME_DIR}"
  echo "[idax] runtime detected: ${RUNTIME_DIR}"
else
  echo "[idax] runtime not detected (IDADIR unset/missing libs)"
fi

if [[ -n "${RUNTIME_DIR}" ]]; then
  echo "[idax] step: full validation matrix"
  MATRIX_LOG="${LOG_DIR}/full-matrix.log"
  if IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON IDAX_BUILD_EXAMPLE_TOOLS=ON \
    "${ROOT}/scripts/run_validation_matrix.sh" full "${BUILD_ROOT}/full" "${BUILD_TYPE}" \
    >"${MATRIX_LOG}" 2>&1; then
    MATRIX_STATUS="pass"
    MATRIX_NOTE="full matrix completed"
  else
    MATRIX_STATUS="fail"
    MATRIX_NOTE="see ${MATRIX_LOG}"
  fi
else
  MATRIX_STATUS="blocked"
  MATRIX_NOTE="runtime install required"
fi

TOOLS_BUILD_DIR="${BUILD_ROOT}/tools"
TOOLS_LOG="${LOG_DIR}/tools-build.log"
IDA2PY_BIN=""
LUMINA_BIN=""

if [[ -n "${RUNTIME_DIR}" ]]; then
  echo "[idax] step: build tool-port binaries"
  if cmake -S "${ROOT}" -B "${TOOLS_BUILD_DIR}" \
      -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
      -DIDAX_BUILD_EXAMPLES=ON \
      -DIDAX_BUILD_EXAMPLE_TOOLS=ON \
      -DIDAX_BUILD_EXAMPLE_ADDONS=OFF \
      -DIDAX_BUILD_TESTS=OFF \
      >"${TOOLS_LOG}" 2>&1 \
    && cmake --build "${TOOLS_BUILD_DIR}" --config "${BUILD_TYPE}" \
      --target idax_ida2py_port idax_idalib_lumina_port >>"${TOOLS_LOG}" 2>&1; then
    if ! IDA2PY_BIN="$(find_tool_binary "${TOOLS_BUILD_DIR}" "idax_ida2py_port")"; then
      IDA2PY_BIN=""
    fi
    if ! LUMINA_BIN="$(find_tool_binary "${TOOLS_BUILD_DIR}" "idax_idalib_lumina_port")"; then
      LUMINA_BIN=""
    fi
  else
    APPCALL_STATUS="fail"
    APPCALL_NOTE="tool build failed, see ${TOOLS_LOG}"
    LUMINA_STATUS="fail"
    LUMINA_NOTE="tool build failed, see ${TOOLS_LOG}"
  fi
fi

APPCALL_FIXTURE="${BUILD_ROOT}/fixtures/simple_appcall_host"
if [[ -z "${APPCALL_STATUS}" || "${APPCALL_STATUS}" == "skipped" ]]; then
  if [[ -n "${RUNTIME_DIR}" && -n "${IDA2PY_BIN}" ]]; then
    echo "[idax] step: build host appcall fixture"
    FIXTURE_LOG="${LOG_DIR}/appcall-fixture-build.log"
    if "${ROOT}/scripts/build_appcall_fixture.sh" "${APPCALL_FIXTURE}" >"${FIXTURE_LOG}" 2>&1; then
      :
    else
      APPCALL_FIXTURE="${ROOT}/tests/fixtures/simple_appcall_linux64"
    fi

    echo "[idax] step: appcall smoke"
    APPCALL_LOG="${LOG_DIR}/appcall-smoke.log"
    if "${IDA2PY_BIN}" --quiet --appcall-smoke "${APPCALL_FIXTURE}" >"${APPCALL_LOG}" 2>&1; then
      APPCALL_STATUS="pass"
      APPCALL_NOTE="appcall smoke succeeded (${APPCALL_FIXTURE})"
    else
      if grep -E "error_code=1552|dbg_appcall failed|start_process failed|Failed to launch debuggee" "${APPCALL_LOG}" >/dev/null 2>&1; then
        APPCALL_STATUS="blocked"
        APPCALL_NOTE="debugger backend/session not ready (see ${APPCALL_LOG})"
      else
        APPCALL_STATUS="fail"
        APPCALL_NOTE="unexpected appcall failure (see ${APPCALL_LOG})"
      fi
    fi
  elif [[ -z "${RUNTIME_DIR}" ]]; then
    APPCALL_STATUS="blocked"
    APPCALL_NOTE="runtime install required"
  else
    APPCALL_STATUS="fail"
    APPCALL_NOTE="idax_ida2py_port binary not found"
  fi
fi

if [[ "${LUMINA_STATUS}" == "skipped" ]]; then
  if [[ -n "${RUNTIME_DIR}" && -n "${LUMINA_BIN}" ]]; then
    LUMINA_INPUT="${ROOT}/tests/fixtures/simple_appcall_linux64"
    if [[ -f "${APPCALL_FIXTURE}" ]]; then
      LUMINA_INPUT="${APPCALL_FIXTURE}"
    fi

    echo "[idax] step: lumina pull/push smoke"
    LUMINA_LOG="${LOG_DIR}/lumina-smoke.log"
    if "${LUMINA_BIN}" "${LUMINA_INPUT}" >"${LUMINA_LOG}" 2>&1; then
      LUMINA_STATUS="pass"
      LUMINA_NOTE="lumina pull/push succeeded"
    else
      if grep -E "Lumina connection is unavailable|Lumina pull failed|Lumina push failed" "${LUMINA_LOG}" >/dev/null 2>&1; then
        LUMINA_STATUS="blocked"
        LUMINA_NOTE="lumina service/credentials unavailable (see ${LUMINA_LOG})"
      else
        LUMINA_STATUS="fail"
        LUMINA_NOTE="unexpected lumina failure (see ${LUMINA_LOG})"
      fi
    fi
  elif [[ -z "${RUNTIME_DIR}" ]]; then
    LUMINA_STATUS="blocked"
    LUMINA_NOTE="runtime install required"
  else
    LUMINA_STATUS="fail"
    LUMINA_NOTE="idax_idalib_lumina_port binary not found"
  fi
fi

echo
echo "[idax] open-point closure summary"
echo "  full matrix:   ${MATRIX_STATUS} - ${MATRIX_NOTE}"
echo "  appcall smoke: ${APPCALL_STATUS} - ${APPCALL_NOTE}"
echo "  lumina smoke:  ${LUMINA_STATUS} - ${LUMINA_NOTE}"

FAILED=0
BLOCKED=0
for status in "${MATRIX_STATUS}" "${APPCALL_STATUS}" "${LUMINA_STATUS}"; do
  if [[ "${status}" == "fail" ]]; then
    FAILED=1
  fi
  if [[ "${status}" == "blocked" ]]; then
    BLOCKED=1
  fi
done

if [[ "${FAILED}" == "1" ]]; then
  exit 1
fi

if [[ "${STRICT_MODE}" == "1" && "${BLOCKED}" == "1" ]]; then
  exit 2
fi

exit 0
