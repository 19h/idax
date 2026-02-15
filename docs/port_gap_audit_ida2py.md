# Port Gap Audit: ida2py

Date: 2026-02-15

This audit records findings from porting:

- `/Users/int/Downloads/plo/ida2py-main`

to idax-first surfaces.

## Port artifact in this repository

- `examples/tools/ida2py_port.cpp`

## Covered migration flows

- Headless session bring-up (`ida::database::init/open` + `ida::analysis::wait`).
- User-defined symbol discovery (`ida::name::all_user_defined`).
- Symbol resolution by name/address and type inspection (`ida::type::retrieve`,
  `TypeInfo::to_string`, xref summaries).
- Type-apply parity checks (`TypeInfo::from_declaration` + `TypeInfo::apply`).
- Callsite listing for a callee (`ida::xref::refs_to` + decompiler call text via
  `ida::decompiler::for_each_expression`).
- Runtime Appcall smoke path via `examples/tools/ida2py_port.cpp`
  (`--appcall-smoke`, using `ida::debugger::appcall`).

## Recent parity closures

- User-name inventory is now first-class via `ida::name::all` and
  `ida::name::all_user_defined`, so ports no longer need full-address-space
  fallback scans for common name enumeration flows.
- `ida::type::TypeInfo` now exposes decomposition helpers:
  `pointee_type`, `array_element_type`, `array_length`, `is_typedef`, and
  `resolve_typedef`.
- `ida::decompiler::ExpressionView` now exposes typed call-subexpression helpers:
  `call_callee` and `call_argument(index)` in addition to
  `call_argument_count`, enabling direct callsite-argument workflows.
- `ida::data` now exposes a generic typed-value facade:
  `read_typed(address, TypeInfo)` and `write_typed(address, TypeInfo, TypedValue)`
  with recursive array support and byte-array/string write paths.
- `ida::debugger` now exposes appcall/executor primitives:
  `appcall(AppcallRequest)`, `cleanup_appcall(...)`, and external executor hooks
  (`AppcallExecutor`, `register_executor`, `appcall_with_executor`) for
  debugger-native and pluggable execution backends.

## Confirmed parity gaps

- None currently for the audited ida2py probe workflows.

## Notes

- Python global-scope interception (`hook(globals())`) is intentionally language
  specific and was not treated as a required C++ wrapper parity goal.
- The port probe intentionally focuses on static query/type/callsite workflows
  where idax is expected to be the primary abstraction layer.
- Local functional execution is now verified for non-debugger flows when tool
  examples are linked against real IDA runtime dylibs (not SDK stubs).
- Appcall runtime validation still requires a debugger-capable host/session;
  the current host run now auto-selects/loads an appcall-capable debugger
  backend, attempts multi-path debuggee launch with both `--wait` and default
  args, then external spawn+attach fallback, and still fails cleanly
  (`start_process` return `0` with request-start no-process, `attach_process`
  return `-1` with request-attach no-process) when the backend/session is not
  ready (no wrapper crash).
- Runtime validation procedure is tracked in
  `docs/appcall_runtime_validation.md`.
