#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUILD_DIR="${1:-${ROOT}/build-test-fetch}"
BUILD_TYPE="${2:-RelWithDebInfo}"
HOST_BUILD_DIR="${IDAX_CODEDUMP_HOST_BUILD_DIR:-${ROOT}/build-codedump-parity-host}"
EXAMPLES_BUILD_DIR="${IDAX_CODEDUMP_EXAMPLES_BUILD_DIR:-${ROOT}/build-examples-fetch}"
FIXTURE="${IDAX_CODEDUMP_FIXTURE:-${ROOT}/tests/fixtures/simple_appcall_linux64}"
NODE_IDASDK="${IDAX_NODE_IDASDK:-${BUILD_DIR}/_deps/ida_sdk-src/src}"
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

  echo "local validation runner self-test ok"
  exit 0
fi

if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  echo "[idax] configure: ${BUILD_DIR}"
  env -u IDASDK cmake -S "${ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DIDAX_BUILD_TESTS=ON
fi

DEFAULT_I64="${ROOT}/tests/fixtures/simple_appcall_linux64.i64"
RESTORE_DEFAULT_FIXTURE=0
if [[ -f "${DEFAULT_I64}" ]]; then
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

echo "[idax] build: focused C++ parity targets"
env -u IDASDK cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}" \
  --target \
    idax_api_surface_check \
    idax_unit_test \
    idax_codedump_parity_host_gates_test \
    idax_decompiler_storage_hardening_test \
    idax_segment_function_edge_cases_test \
    idax_type_roundtrip_test \
  -j "${JOBS}"

echo "[idax] test: focused C++ parity CTest"
ctest --test-dir "${BUILD_DIR}" -C "${BUILD_TYPE}" \
  -R '^idax_unit_test$|api_surface_parity|codedump_parity_host_gates|decompiler_storage_hardening|segment_function_edge_cases|type_roundtrip' \
  --output-on-failure

mapfile -t HOST_EVIDENCE_MODES < <(host_evidence_modes)
HOST_EVIDENCE_SLUG="$(host_evidence_slug "${HOST_EVIDENCE_MODES[@]}")"
HOST_EVIDENCE_LOG="${HOST_BUILD_DIR}/codedump-host-${HOST_EVIDENCE_SLUG}.log"

echo "[idax] test: host-gate evidence (${HOST_EVIDENCE_SLUG})"
mkdir -p "${HOST_BUILD_DIR}"
env -u IDASDK IDAX_EVIDENCE_LOG="${HOST_EVIDENCE_LOG}" \
  "${ROOT}/scripts/run_codedump_parity_host_gates.sh" \
    "${HOST_BUILD_DIR}" "${FIXTURE}" "${BUILD_TYPE}"
for evidence_mode in "${HOST_EVIDENCE_MODES[@]}"; do
  "${ROOT}/scripts/check_codedump_parity_evidence_log.sh" \
    "${HOST_EVIDENCE_LOG}" "${evidence_mode}"
done
"${ROOT}/scripts/check_codedump_parity_evidence_log.sh" --self-test

echo "[idax] build: codedump parity probe example"
if [[ ! -f "${EXAMPLES_BUILD_DIR}/CMakeCache.txt" ]]; then
  echo "[idax] configure: ${EXAMPLES_BUILD_DIR}"
  env -u IDASDK cmake -S "${ROOT}" -B "${EXAMPLES_BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DIDAX_BUILD_EXAMPLES=ON \
    -DIDAX_BUILD_EXAMPLE_ADDONS=ON \
    -DIDAX_BUILD_TESTS=OFF
fi
env -u IDASDK cmake --build "${EXAMPLES_BUILD_DIR}" --config "${BUILD_TYPE}" \
  --target idax_codedump_parity_probe_plugin -j "${JOBS}"

echo "[idax] test: Node unit parity coverage"
if [[ ! -d "${NODE_IDASDK}" ]]; then
  echo "error: Node IDASDK not found: ${NODE_IDASDK}" >&2
  echo "set IDAX_NODE_IDASDK or run the C++ configure step first" >&2
  exit 1
fi
(cd "${ROOT}/bindings/node" && env IDASDK="${NODE_IDASDK}" npm run build)
(cd "${ROOT}/bindings/node" && env IDASDK="${NODE_IDASDK}" npm test)

if truthy "${IDAX_RUN_NODE_INTEGRATION:-}"; then
  echo "[idax] test: Node fixture integration"
  if [[ -z "${IDADIR:-}" ]]; then
    echo "error: IDAX_RUN_NODE_INTEGRATION=1 requires IDADIR" >&2
    exit 1
  fi
  (cd "${ROOT}/bindings/node" && env IDASDK="${NODE_IDASDK}" IDADIR="${IDADIR}" \
    npm run test:integration -- ../../tests/fixtures/simple_appcall_linux64)
else
  echo "[idax] skip: Node fixture integration (set IDAX_RUN_NODE_INTEGRATION=1 and IDADIR)"
fi

echo "[idax] test: Rust parity coverage"
(cd "${ROOT}/bindings/rust" && env -u IDASDK \
  cargo test -p idax ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui --lib)
(cd "${ROOT}/bindings/rust" && env -u IDASDK cargo test -p idax --lib --no-run)
(cd "${ROOT}/bindings/rust" && env -u IDASDK \
  cargo test -p idax types_parse_declarations --test integration --no-run)

echo "[idax] codedump parity local validation complete"
