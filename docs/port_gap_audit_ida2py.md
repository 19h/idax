# Port Gap Audit: ida2py

Date: 2026-02-14

This audit records findings from porting:

- `/Users/int/Downloads/plo/ida2py-main`

to idax-first surfaces.

## Port artifact in this repository

- `examples/tools/ida2py_port.cpp`

## Covered migration flows

- Headless session bring-up (`ida::database::init/open` + `ida::analysis::wait`).
- User-defined symbol discovery (fallback scan over `ida::address::items` +
  `ida::name::is_user_defined`).
- Symbol resolution by name/address and type inspection (`ida::type::retrieve`,
  `TypeInfo::to_string`, xref summaries).
- Type-apply parity checks (`TypeInfo::from_declaration` + `TypeInfo::apply`).
- Callsite listing for a callee (`ida::xref::refs_to` + decompiler call text via
  `ida::decompiler::for_each_expression`).

## Confirmed parity gaps

1. No first-class user-name enumeration API.
   - Impact: ports must scan address ranges and probe names item-by-item.
   - Mitigation: add dedicated iterators (for example `ida::name::all()` and
     `ida::name::all_user_defined()`).

2. `ida::type::TypeInfo` lacks public decomposition helpers for pointer/array
   inner types and lengths.
   - Impact: generic `ida2py`-style recursive value materialization cannot be
     implemented cleanly in pure public API.
   - Mitigation: add additive introspection helpers (for example `pointee()`,
     `array_element_type()`, `array_length()`, typedef-resolution helpers).

3. No generic typed-value reader/writer from `TypeInfo`.
   - Impact: callers must hand-roll per-width/per-kind data decoding logic.
   - Mitigation: add an optional `ida::data::read_typed(address, TypeInfo)` /
     `write_typed(...)` facade that preserves opaque boundaries.

4. Decompiler expression views do not expose call callee/argument subexpressions
   directly.
   - Impact: `ida2py` callsite-argument workflows (for example extracting first
     `printf` argument object addresses) are only partially portable.
   - Mitigation: add typed call-expression accessors for callee and argument
     expression views.

5. No Appcall/execution facade or executor-extension hook in idax.
   - Impact: ida2py dynamic invocation flows (Appcall + angr executor swapping)
     cannot be ported through idax-only APIs.
   - Mitigation: add a debugger execution facade (for direct Appcall-style
     invocation) and an optional pluggable external-executor interface.

## Notes

- Python global-scope interception (`hook(globals())`) is intentionally language
  specific and was not treated as a required C++ wrapper parity goal.
- The port probe intentionally focuses on static query/type/callsite workflows
  where idax is expected to be the primary abstraction layer.
