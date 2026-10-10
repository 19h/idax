# Appcall Runtime Validation

Date: 2026-02-15

This checklist records how to validate real debugger-backed Appcall behavior on a
known-good host/runtime.

## Goal

Exercise `ida::debugger::appcall` against a real debug backend (not only compile
surface checks and external-executor dispatch tests).

## Preconditions

- Host has licensed IDA runtime/debugger support for the fixture platform.
- `IDASDK` is configured and idax tool examples can be built.
- A C compiler is available (`cc`/`clang`/`gcc`) to build a host-native fixture.

## Build

```bash
cmake -S . -B build-port-gap \
  -DIDAX_BUILD_EXAMPLES=ON \
  -DIDAX_BUILD_EXAMPLE_TOOLS=ON \
  -DIDAX_BUILD_EXAMPLE_ADDONS=OFF \
  -DIDAX_BUILD_TESTS=OFF
cmake --build build-port-gap --target idax_ida2py_port

# Build host-native Appcall fixture (contains symbol ref4)
scripts/build_appcall_fixture.sh build-port-gap/fixtures/simple_appcall_host
```

## Appcall Smoke Command

```bash
build-port-gap/examples/idax_ida2py_port \
  --quiet \
  --appcall-smoke \
  build-port-gap/fixtures/simple_appcall_host
```

The smoke flow resolves `ref4` and calls:

- `int ref4(int *p)` with `p = NULL`

This path is intentionally chosen because it avoids writable-debuggee pointer
setup and still exercises the full Appcall request/type/argument/return bridge.

## Expected Result

On a debugger-capable host, output includes:

- `Debugger Appcall Smoke`
- `Target: ref4 @ ...`
- `Call: int ref4(int* p) with p = NULL`
- `Return: signed=-1` (fixture-specific expected return)

## In-process GUI probe

The opt-in host module tests four real wrapper calls against an already
suspended process: `ref4(NULL) == -1`, `ref1(41) == 42`,
`ref1(-42) == -41` and `ref3(38) == 41`. It requires a loaded
Appcall-capable backend and rejects absent/running processes.

```bash
IDASDK='<ida-sdk-root>/src' IDADIR='<ida-runtime>' \
  cmake -S . -B '<build-root>' -DIDAX_BUILD_TESTS=ON \
    -DIDAX_BUILD_HOST_EVIDENCE_MODULE=ON
cmake --build '<build-root>' --target idax_appcall_host_gates
```

Load the host-native fixture in the GUI, configure its supported debugger,
break at `main`, and invoke from the GUI Python console on its UI thread:

```python
import ctypes
module = ctypes.CDLL('<build-root>/tests/host/libidax_appcall_host_gates.dylib')
probe = module.idax_run_appcall_host_gates
probe.argtypes = [ctypes.c_char_p]
probe.restype = ctypes.c_int
print(probe(b'<build-root>/appcall-host-evidence.txt'))
```

Replace the macOS module suffix/path for Linux/Windows. Retain the complete
log and a zero probe exit code; successful loading/compilation is not Appcall
execution evidence. The module's four signed-return assertions must all pass.

Current probe status (2026-10-11): native module compilation passes. Local
macOS backend setup requires elevated permissions; its cancellation produced
a native IDA SIGSEGV alert before the wrapper probe ran (cause unknown).
The vendor ARM Linux 9.4 debug server, host-native fixture and loopback SSH
transport have been prepared on the existing local VM; actual process-backed
wrapper assertions remain pending under P73.5. No elevated-host or remote
success is inferred from readiness.

## If It Fails

- Capture full stderr/stdout and the reported `ida::Error` context.
- The probe now auto-selects/loads the first appcall-capable debugger backend
  (local preferred) before launch attempts.
- If startup fails with `start_process failed (return code: 0)` across launch
  candidates and `request_start` succeeds but debugger state remains
  `NoProcess` after bounded request-drain settling cycles, classify as
  debugger-backend/session-readiness gap on that host.
- If external spawn+attach fallback is attempted and reports
  `attach_process failed (return code: -1)` while `request_attach` also leaves
  debugger state at `NoProcess` after bounded request-drain settling cycles,
  classify as debugger-backend/session-readiness on that host (not a wrapper
  crash).
- On hosts without a usable debugger backend/session, a graceful
  `dbg_appcall failed` error (for example error code `1552`) is expected and
  should be tracked as environment/runtime readiness, not a wrapper crash.
- Classify as runtime-host limitation if the failure is backend/session setup
  related (for example debugger unavailable on host).
- Record evidence in:
  - `docs/compatibility_matrix.md`
  - `docs/validation_report.md`
  - `agents.md` (Findings + Progress Ledger)
