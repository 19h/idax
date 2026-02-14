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
- Outlining + cache invalidation flow via `ida::function::is_outlined` /
  `ida::function::set_outlined` and `ida::decompiler::mark_dirty_with_callers`.

## Confirmed parity gaps

1. Microcode filter hooks are now available but still minimal for lifter-class use
   - idax now supports registration/unregistration and match/apply dispatch
     (`register_microcode_filter`, `unregister_microcode_filter`,
     `MicrocodeContext`, `MicrocodeApplyResult`).
   - Current context now includes primitive operand/register/memory/helper
     operations (`load_operand_register`, `store_operand_register`,
     `emit_move_register`, `emit_load_memory_register`,
     `emit_store_memory_register`, `emit_helper_call`), but still lacks rich
     typed instruction construction/mutation primitives.

2. No rich public microcode write/emission surface
   - lifter emits and rewrites microcode instructions (`m_call`, `m_nop`, `m_ldx`,
      helper-call construction, typed mop/reg orchestration).
   - idax currently exposes microcode text readout (`microcode_lines`) plus basic
     filter hooks, typed helper-call argument builders (integer + float + byte-array/vector/type-declaration views),
      explicit argument-location hints (register/register-pair/register-offset/register-relative/stack/static/scattered), and lightweight
      helper call-shaping options (calling-convention/flags plus scalar callinfo fields like callee/spd/solid-arg hints), but not a comprehensive writable IR API.
   - Impact: instruction-to-intrinsic lowering cannot be implemented.

3. Action context is intentionally normalized and SDK-opaque
   - lifter popup handlers rely on direct `vdui_t` / `cfunc_t` level handles.
   - idax `ActionContext` provides stable high-value fields (address/widget metadata)
     but not raw decompiler-view objects.
   - Impact: advanced per-view decompiler manipulations are limited.

## Newly closed since initial audit

- Added decompiler maturity subscriptions: `ida::decompiler::on_maturity_changed`,
  `ida::decompiler::unsubscribe`, and RAII `ScopedSubscription`.
- Added cache invalidation helpers: `ida::decompiler::mark_dirty` and
  `ida::decompiler::mark_dirty_with_callers`.
- Added function outlining helpers: `ida::function::is_outlined` and
  `ida::function::set_outlined`.
- Added microcode-filter registration helpers: `ida::decompiler::register_microcode_filter`,
  `ida::decompiler::unregister_microcode_filter`, and RAII `ScopedMicrocodeFilter`.
- Expanded helper-call option shaping: `ida::decompiler::MicrocodeCallOptions`
  now includes scalar callinfo hints (`callee_address`, `solid_argument_count`,
  `call_stack_pointer_delta`, `stack_arguments_top`) with validation on invalid
  counts.

## Notes

- The current idax decompiler surface is strong for read/query workflows
  (pseudocode text, ctree traversal, variable edits, comments, microcode text
  extraction) and supports partial lifter diagnostics.
- The blocker set is concentrated in decompiler write-path depth and advanced
  per-view handle access, not in plugin bootstrapping or basic action ergonomics.
- The port probe intentionally keeps all interactions SDK-opaque and additive,
  so every listed gap corresponds to a concrete missing public wrapper surface.
