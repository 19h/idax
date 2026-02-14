# Port Gap Audit: ida2py

Date: 2026-02-14

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

## Confirmed parity gaps

1. No generic typed-value reader/writer from `TypeInfo`.
   - Impact: callers must hand-roll per-width/per-kind data decoding logic.
   - Mitigation: add an optional `ida::data::read_typed(address, TypeInfo)` /
     `write_typed(...)` facade that preserves opaque boundaries.

2. No Appcall/execution facade or executor-extension hook in idax.
   - Impact: ida2py dynamic invocation flows (Appcall + angr executor swapping)
   cannot be ported through idax-only APIs.
   - Mitigation: add a debugger execution facade (for direct Appcall-style
     invocation) and an optional pluggable external-executor interface.

## Notes

- Python global-scope interception (`hook(globals())`) is intentionally language
  specific and was not treated as a required C++ wrapper parity goal.
- The port probe intentionally focuses on static query/type/callsite workflows
  where idax is expected to be the primary abstraction layer.
