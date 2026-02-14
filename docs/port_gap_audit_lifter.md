# Port Gap Audit: lifter

Date: 2026-02-14

This audit records findings from porting:

- `/Users/int/dev/lifter`

to idax-first surfaces.

## Port artifact in this repository

- `examples/plugin/lifter_port_plugin.cpp`

## Covered migration flows

- Plugin lifecycle wiring through `ida::plugin::Plugin` + `IDAX_PLUGIN`.
- Action registration and menu wiring for lifter-style commands (`dump snapshot`,
  `toggle outline intent`, `show gaps`).
- Pseudocode-popup attachment through `ida::ui::on_widget_visible` +
  `ida::plugin::attach_to_popup` by widget title.
- Decompiler snapshot workflows (`decompile`, `lines`, `microcode_lines`,
  `for_each_expression`) for call-expression counting and microcode preview.
- Fallback inline/outlining intent flow via function repeatable comments
  (`ida::function::comment` / `set_comment`) and `DecompiledFunction::refresh()`.

## Confirmed parity gaps

1. No public microcode-filter hook registration API
   - lifter requires `install_microcode_filter(..., true/false)` style match/apply
     hooks to transform decoded instructions during Hex-Rays lifting passes.
   - Impact: full AVX/VMX lifting logic cannot be expressed in idax-only code.

2. No public microcode write/emission surface
   - lifter emits and rewrites microcode instructions (`m_call`, `m_nop`, `m_ldx`,
     helper-call construction, typed mop/reg orchestration).
   - idax currently exposes microcode text readout (`microcode_lines`) but not a
     writable IR API.
   - Impact: instruction-to-intrinsic lowering cannot be implemented.

3. No Hex-Rays maturity callback routing
   - lifter uses `hxe_maturity` to capture before/after microcode stages and
     decompilation debug instrumentation.
   - Impact: stage-aware pass tracing and maturity-driven diagnostics are blocked.

4. No FUNC_OUTLINE + global decompiler cache invalidation parity APIs
   - lifter toggles `FUNC_OUTLINE`, calls `update_func`, and dirties current +
     caller functions with `mark_cfunc_dirty`.
   - idax fallback can tag comments and refresh one decompiled function, but
     cannot reproduce kernel-level outlining + caller-cache invalidation semantics.
   - Impact: inline/outlining workflow parity is partial.

5. Action context is intentionally normalized and SDK-opaque
   - lifter popup handlers rely on direct `vdui_t` / `cfunc_t` level handles.
   - idax `ActionContext` provides stable high-value fields (address/widget metadata)
     but not raw decompiler-view objects.
   - Impact: advanced per-view decompiler manipulations are limited.

## Notes

- The current idax decompiler surface is strong for read/query workflows
  (pseudocode text, ctree traversal, variable edits, comments, microcode text
  extraction) and supports partial lifter diagnostics.
- The blocker set is concentrated in decompiler write-path and event-stage APIs,
  not in plugin bootstrapping or basic action ergonomics.
- The port probe intentionally keeps all interactions SDK-opaque and additive,
  so every listed gap corresponds to a concrete missing public wrapper surface.
