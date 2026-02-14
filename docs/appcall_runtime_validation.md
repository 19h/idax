# Appcall Runtime Validation

Date: 2026-02-14

This checklist records how to validate real debugger-backed Appcall behavior on a
known-good host/runtime.

## Goal

Exercise `ida::debugger::appcall` against a real debug backend (not only compile
surface checks and external-executor dispatch tests).

## Preconditions

- Host has licensed IDA runtime/debugger support for the fixture platform.
- `IDASDK` is configured and idax tool examples can be built.
- Fixture is available: `tests/fixtures/simple_appcall_linux64`.

## Build

```bash
cmake -S . -B build-port-gap \
  -DIDAX_BUILD_EXAMPLES=ON \
  -DIDAX_BUILD_EXAMPLE_TOOLS=ON \
  -DIDAX_BUILD_EXAMPLE_ADDONS=OFF \
  -DIDAX_BUILD_TESTS=OFF
cmake --build build-port-gap --target idax_ida2py_port
```

## Appcall Smoke Command

```bash
build-port-gap/examples/idax_ida2py_port \
  --quiet \
  --appcall-smoke \
  tests/fixtures/simple_appcall_linux64
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

## If It Fails

- Capture full stderr/stdout and the reported `ida::Error` context.
- On hosts without a usable debugger backend/session, a graceful
  `dbg_appcall failed` error (for example error code `1552`) is expected and
  should be tracked as environment/runtime readiness, not a wrapper crash.
- Classify as runtime-host limitation if the failure is backend/session setup
  related (for example debugger unavailable on host).
- Record evidence in:
  - `docs/compatibility_matrix.md`
  - `docs/validation_report.md`
  - `agents.md` (Findings + Progress Ledger)
