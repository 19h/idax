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
- VMX microcode lifting subset through idax filter APIs and typed helper-call
  emission (`vzeroupper`, `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/
  vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`).
- AVX scalar math/conversion subset through typed microcode emission
  (`vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd`,
  `vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`,
  `vcvtss2sd`, `vcvtsd2ss`, `vmovss`, `vmovsd`).
- AVX packed math/move subset through typed microcode emission
  (`vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd`,
  `vaddsubps/vaddsubpd`, `vhaddps/vhaddpd`, `vhsubps/vhsubpd`,
  typed `vpadd*`/`vpsub*` integer add/sub direct forms
  (with helper fallback for memory-source and saturating variants),
  typed `vpmulld`/`vpmullq` integer multiply direct forms
  (with helper fallback for `vpmullw`/`vpmuludq`/`vpmaddwd` variants),
  with typed binary paths accepting both three-operand and destination-implicit
  two-operand encodings,
  typed `vand*/vor*/vxor*`, `vpand*/vpor*/vpxor*`
  (with helper fallback for `*andn*` forms),
  helper-fallback `vblend*/vpblend*` + `vshuf*/vperm*` families,
  typed `vps*` shift forms with helper fallback for rotate/mixed variants,
  helper-fallback `vcmp*`/`vpcmp*` compare families,
  helper-fallback `vdpps` + `vround*`/`vrcp*`/`vrsqrt*`/`vget*`/`vfixup*`/
  `vscale*`/`vrange*`/`vreduce*` + `vbroadcast*`/`vextract*`/`vinsert*`/
  `vunpck*`/`vmov*dup`/`vmaskmov*` families,
  with mixed register/immediate/memory-source forwarding and deterministic
  compare mask-destination operand writeback,
  `vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd`,
  `vcvtps2pd/vcvtpd2ps`, `vcvtdq2ps/vcvtudq2ps`, `vcvtdq2pd/vcvtudq2pd`,
  plus helper-fallback `vcvt*2dq/udq/qq/uqq` forms,
  `vmovaps/vmovups/vmovapd/vmovupd`, `vmovdqa/vmovdqu` families).

## Confirmed parity gaps

1. Microcode filter hooks are now available and VMX+AVX scalar/packed subset lifting is wired,
   but full lifter-class write-path depth is still incomplete
    - idax now supports registration/unregistration and match/apply dispatch
      (`register_microcode_filter`, `unregister_microcode_filter`,
      `MicrocodeContext`, `MicrocodeApplyResult`).
    - The port probe now uses those hooks for concrete VMX + AVX scalar/packed
      instruction subsets with helper-call and typed microcode lowering.
    - Current context includes primitive operand/register/memory/helper
      operations (`load_operand_register`, `store_operand_register`,
      `emit_move_register`, `emit_load_memory_register`,
      `emit_store_memory_register`, `emit_helper_call`) plus richer typed
      instruction operand/mop kinds (`RegisterPair`, `GlobalAddress`,
      `StackVariable`, `HelperReference`, `BlockReference`), but deep mutation
      breadth is still additive follow-up.

2. No rich public microcode write/emission surface
   - lifter emits and rewrites microcode instructions (`m_call`, `m_nop`, `m_ldx`,
      helper-call construction, typed mop/reg orchestration).
   - idax currently exposes microcode text readout (`microcode_lines`) plus basic
      filter hooks, typed helper-call argument builders (integer + float +
      byte-array/vector/type-declaration views, plus register-pair/
      global-address/stack-variable/helper-reference argument forms and
      declaration-driven vector element typing), explicit argument-location hints
      (register/register-pair/register-offset/register-relative/stack/static/
      scattered), and expanded helper call-shaping options (calling-convention/
      flags, scalar callinfo fields like callee/spd/solid-arg hints,
      return-type/return-location hints, and register-list/visible-memory
      callinfo list shaping), but not a comprehensive writable IR API.
   - Impact: instruction-to-intrinsic lowering cannot be implemented.

3. Action context now has opaque host bridges and typed decompiler-view
   session helpers for high-value edit/read workflows
   - lifter popup handlers rely on direct `vdui_t` / `cfunc_t` level handles.
    - idax now provides scoped host access from action callbacks
      (`with_widget_host`, `with_decompiler_view_host`) plus context host fields,
      and first-class typed wrappers (`DecompilerView`, `view_from_host`,
      `view_for_function`, `current_view`) for variable/comment/refresh flows.
    - Impact: advanced workflows no longer require raw host-pointer handling for
      common edit/read tasks. Remaining work is deeper in-view mutation breadth,
      not baseline typed access.

## Comprehensive source-backed gap matrix (current)

The initial gap list above is directionally correct, but broad. This section
maps concrete lifter usage patterns to idax coverage status so follow-up work can
be executed in small, testable API slices.

### A) Microcode instruction construction/emission depth

- Source evidence (`/Users/int/dev/lifter`):
  - `src/avx/handlers/handler_logic.cpp`
  - `src/avx/handlers/handler_math.cpp`
  - `src/avx/handlers/handler_mov.cpp`
  - `src/avx/handlers/handler_cvt.cpp`
  - `src/avx/avx_helpers.cpp`
  - `src/vmx/vmx_lifter.cpp`
- Pattern used in lifter:
  - frequent direct `cdg.emit(...)` with explicit opcodes (`m_mov`, `m_ldx`,
    `m_stx`, `m_xdu`, `m_fadd`, `m_fsub`, `m_fmul`, `m_fdiv`, `m_f2f`,
    `m_i2f`, `m_add`, `m_call`, `m_nop`) and explicit operand wiring.
- Current idax status:
  - partial, with a new baseline closure increment. `MicrocodeContext` now
    exposes generic typed instruction emission via
    `MicrocodeOpcode`/`MicrocodeOperand`/`MicrocodeInstruction` and
    `emit_instruction`/`emit_instructions` for the high-value opcode family
    (`mov`, `add`, `xdu`, `ldx`, `stx`, `fadd`, `fsub`, `fmul`, `fdiv`,
    `i2f`, `f2f`, `nop`).
  - Remaining depth (rich typed operands/callinfo/tmop semantics) is still
    additive follow-up.
- Migration impact:
  - high. Broad handler families cannot be ported one-to-one without raw SDK.

### B) Typed microcode operand model and mutation controls

- Source evidence (`/Users/int/dev/lifter`):
  - `src/avx/avx_intrinsic.cpp`
  - `src/vmx/vmx_lifter.cpp`
  - `src/avx/avx_helpers.cpp`
- Pattern used in lifter:
  - direct `mop_t` construction and mutation (`make_reg`, immediate values,
    helper refs, nested-insn refs, explicit sizes/UDT/flags), plus direct
    `minsn_t` field updates.
- Current idax status:
  - partial. Typed helper-call arguments now cover integer/float/byte-array/
    vector/type-declaration values, plus register-pair/global-address/
    stack-variable/helper-reference forms and rich location hints; temporary
    register allocation is available via
    `MicrocodeContext::allocate_temporary_register`.
  - Generic typed instruction operands now include richer opaque mop builders
    (`RegisterPair`, `GlobalAddress`, `StackVariable`, `HelperReference`,
    `BlockReference`), but deeper nested-insn/tmop-specialized builder breadth
    is still additive follow-up.
- Migration impact:
  - high. Non-helper instruction rewrites remain blocked.

### C) Callinfo/tmop richness beyond current option hints

- Source evidence (`/Users/int/dev/lifter`):
  - `src/avx/avx_intrinsic.cpp`
  - `src/vmx/vmx_lifter.cpp`
- Pattern used in lifter:
  - direct `mcallinfo_t` and `mcallarg_t` shaping, including argument metadata,
    per-arg placement details, and call-shape flags.
- Current idax status:
  - partial, with baseline closure increments. `MicrocodeCallOptions` now
  covers useful flag and scalar hints (calling convention, selected `FCI_*`,
  callee/SPD/stack/solid-arg hints, function-role hint,
  return-location hint, return-type declaration), advanced register-list and
  visible-memory callinfo shaping (`return_registers`, `spoiled_registers`,
  `passthrough_registers`, `dead_registers`, `visible_memory_ranges`,
  `visible_memory_all`), and declaration-driven typed register argument/return
  emission with size validation.
  - Per-argument metadata is now partially covered through
    `MicrocodeValue::argument_name` and `MicrocodeValue::argument_flags`
    (`MicrocodeArgumentFlag` bitmask values) mapped to callarg metadata.
  - `MicrocodeValue` now also supports tmop-oriented helper-call arguments via
    `BlockReference` and `NestedInstruction`, and helper-call destinations can
    be authored with typed micro-operands through
    `emit_helper_call_with_arguments_to_micro_operand[_and_options]`.
  - Remaining depth is richer typed callinfo/tmop authoring controls beyond
    current option-hint shaping (especially broader non-helper rewrite parity).
- Migration impact:
  - medium/high. Many helper-call flows are now possible, but complex callinfo
    parity still requires raw SDK.

### D) Microblock placement/lifecycle editing

- Source evidence (`/Users/int/dev/lifter`):
  - `src/avx/avx_intrinsic.cpp`
  - `src/vmx/vmx_lifter.cpp`
- Pattern used in lifter:
  - explicit insertion into microblocks (`insert_into_block(..., mb->tail)`),
    and lifetime ownership transfer expectations for emitted instructions.
- Current idax status:
  - partial, with a baseline closure increment. `MicrocodeContext` now exposes
  deterministic placement policy controls for typed instruction emission via
  `MicrocodeInsertPolicy` (`Tail`, `Beginning`, `BeforeTail`) and
  `emit_instruction_with_policy`/`emit_instructions_with_policy`.
  - Placement controls now also cover key low-level emit helpers through
    `emit_noop_with_policy`, `emit_move_register_with_policy`,
    `emit_load_memory_register_with_policy`, and
    `emit_store_memory_register_with_policy`.
  - Low-level move/load/store helpers now also expose optional UDT operand
    marking (`mark_user_defined_type`) so wide non-scalar operand flows can be
    modeled without dropping to raw SDK calls.
  - Remaining depth is demand-driven parity expansion for any additional
    emission paths not yet policy-aware. Helper-call insertion also supports
    `insert_policy` through `MicrocodeCallOptions`.
  - Lifecycle ergonomics now include block index query/removal
    (`has_instruction_at_index`, `remove_instruction_at_index`) in addition to
    tracked-last-emitted helpers.
- Migration impact:
  - medium. Some deterministic rewrite ordering patterns cannot be expressed
    through public APIs yet.

### E) Typed decompiler-view edit ergonomics

- Source evidence (`/Users/int/dev/lifter`):
  - `src/plugin/lifter_plugin.cpp` (popup and decompiler-view driven flows)
- Pattern used in lifter:
  - direct `vdui_t*` context use in popup workflows.
- Current idax status:
  - partially closed with typed baseline coverage. `ActionContext` includes
    opaque view/widget handles with scoped host callbacks, and
    `ida::decompiler::DecompilerView` now provides typed wrappers for
    high-value edit/read workflows without exposing SDK view types.
- Migration impact:
  - low/medium. Bridge path + typed wrappers cover common flows; remaining work
    is deeper in-view mutation breadth for specialized ports.

## Prioritized additive API slices for lifter closure

1. `P0` - Generic typed microcode instruction builder/emitter (baseline closure increment complete)
   - `MicrocodeInstruction` + `MicrocodeOperand` and
     `emit_instruction(...)`/`emit_instructions(...)` are now available in
     `MicrocodeContext` with strict validation + typed error mapping.
   - Remaining closure for this slice is depth-oriented (richer typed operand
     semantics, not basic opcode dispatch).

2. `P1` - Extended typed callinfo authoring surface (baseline closure increment complete)
   - `MicrocodeCallOptions` now includes additive function-role and
     return-location hinting in addition to existing scalar call-shape flags.
   - Remaining closure is richer per-argument metadata and deeper typed
     callinfo/tmop controls beyond option-hint shaping.

3. `P2` - Placement policy controls (baseline closure increment complete)
   - `MicrocodeInsertPolicy` + policy-aware typed emission APIs provide
     constrained insertion controls without exposing raw block internals.
   - Helper-call paths also support insertion policy via
     `MicrocodeCallOptions::insert_policy`.
   - Remaining closure is demand-driven expansion to additional emission paths.

4. `P3` - Typed high-value decompiler-view helpers
   - Add first-class wrappers only for repeatedly observed flows from real ports
     (do not mirror all `vdui_t` breadth by default).

## Newly closed since initial audit

- Added decompiler maturity subscriptions: `ida::decompiler::on_maturity_changed`,
  `ida::decompiler::unsubscribe`, and RAII `ScopedSubscription`.
- Added cache invalidation helpers: `ida::decompiler::mark_dirty` and
  `ida::decompiler::mark_dirty_with_callers`.
- Added function outlining helpers: `ida::function::is_outlined` and
  `ida::function::set_outlined`.
- Added microcode-filter registration helpers: `ida::decompiler::register_microcode_filter`,
  `ida::decompiler::unregister_microcode_filter`, and RAII `ScopedMicrocodeFilter`.
- Added generic typed microcode instruction emission helpers:
  `MicrocodeOpcode`, `MicrocodeOperandKind`, `MicrocodeOperand`,
  `MicrocodeInstruction`, `MicrocodeContext::emit_instruction`, and
  `MicrocodeContext::emit_instructions`.
- Added constrained placement controls for typed instruction emission:
  `MicrocodeInsertPolicy`, `MicrocodeContext::emit_instruction_with_policy`,
  and `MicrocodeContext::emit_instructions_with_policy`.
- Added placement-aware low-level emit helpers for deterministic ordering in
  additive rewrite paths: `MicrocodeContext::emit_noop_with_policy`,
  `MicrocodeContext::emit_move_register_with_policy`,
  `MicrocodeContext::emit_load_memory_register_with_policy`, and
  `MicrocodeContext::emit_store_memory_register_with_policy`.
- Added optional UDT operand marking to low-level move/load/store helpers
  (`store_operand_register`, `emit_move_register*`,
  `emit_load_memory_register*`, `emit_store_memory_register*`) for wider typed
  operand semantics in additive rewrite paths.
- Added helper-call insertion policy hinting via
  `MicrocodeCallOptions::insert_policy`.
- Expanded helper-call option shaping: `ida::decompiler::MicrocodeCallOptions`
  now includes scalar callinfo hints (`callee_address`, `solid_argument_count`,
  `call_stack_pointer_delta`, `stack_arguments_top`) with validation on invalid
  counts.
- Helper-call callinfo shaping now infers `solid_argument_count` from the
  provided argument list when not explicitly set, reducing manual call-shape
  boilerplate in lifter-style builders.
- Auto stack-location assignment now supports optional start/alignment shaping
  (`auto_stack_start_offset`, `auto_stack_alignment`) for deterministic
  argument placement in helper-call paths.
- Expanded helper-call option shaping with semantic role + return-location
  hinting (`function_role`, `return_location`) for additive callinfo depth
  without raw `mcallinfo_t` mutation in public APIs.
- Expanded helper-call typed-return shaping for register-return paths:
  declaration-driven return typing now supports non-integer widths when
  destination size matches the declared type.
- Expanded helper-call typed-argument shaping for register argument paths:
  declaration-driven register argument typing now supports non-integer
  declarations with explicit size validation.
- Expanded helper-call typed-argument shaping for immediate argument paths:
  unsigned/signed immediates now accept optional declaration-driven typing with
  parse/size validation and declaration-derived width inference when byte width
  is omitted.
- Expanded helper-call per-argument metadata shaping:
  arguments can now carry formal name/flag metadata via
  `MicrocodeValue::argument_name` + `MicrocodeValue::argument_flags`
  (`MicrocodeArgumentFlag`).
- Expanded typed microcode operand/mop builders for generic instruction
  emission and helper arguments:
  `RegisterPair`, `GlobalAddress`, `StackVariable`, `HelperReference`, and
  `BlockReference`.
- Added typed nested-instruction operand support for generic instruction
  emission (`MicrocodeOperandKind::NestedInstruction` +
  `MicrocodeOperand::nested_instruction`) with recursive validation and depth
  limiting.
- Added typed local-variable operand support for generic instruction emission
  (`MicrocodeOperandKind::LocalVariable` +
  `MicrocodeOperand::{local_variable_index, local_variable_offset}`) mapped to
  SDK local-variable mop construction with validation.
- Added local-variable helper-argument and context-query support
  (`MicrocodeValueKind::LocalVariable`,
  `MicrocodeValue::{local_variable_index, local_variable_offset}`,
  `MicrocodeContext::local_variable_count`) for additive local-variable-aware
  rewrite paths.
- Updated `examples/plugin/lifter_port_plugin.cpp` to consume
  `MicrocodeOperandKind::LocalVariable` in real rewrite paths
  (`vzeroupper`, `vmxoff`) via a shared local-variable self-move helper,
  preserving no-op/helper fallback behavior when locals are unavailable.
- Expanded vector helper-call typing with declaration-driven element types,
  enabling richer non-scalar/UDT-style element modeling when concrete widths are
  validated.
- Expanded advanced callinfo list shaping in `MicrocodeCallOptions` with
  register-list and visible-memory controls (`return_registers`,
  `spoiled_registers`, `passthrough_registers`, `dead_registers`,
  `visible_memory_ranges`, `visible_memory_all`).
- Tightened callinfo register-list validation semantics so
  `passthrough_registers` must always be a subset of
  `spoiled_registers` (not only when both lists were explicitly provided),
  preventing contradictory pass/spoil combinations.
- Added structured instruction operand metadata for lifter-class lowering
  (`Operand::byte_width`, `Operand::register_name`,
  `Operand::register_class`, `Operand::is_vector_register`,
  `Operand::is_mask_register`, plus address-index helpers), replacing
  operand-text-width heuristics in the lifter probe.
- Added helper-call return writeback to arbitrary instruction operands via
  `MicrocodeContext::emit_helper_call_with_arguments_to_operand[_and_options]`,
  enabling deterministic compare/mask-destination lowering without no-op
  tolerance paths.
- Expanded executable probe coverage from VMX-only lowering to include AVX
  scalar and packed math/move flows (`vadd*`/`vsub*`/`vmul*`/`vdiv*`, `vcvt*`,
  `vmin*`/`vmax*`, `vsqrt*`, `vmov*`) through typed instruction emission,
  helper-return composition, and store-aware move lowering.
- Added action-context host bridges for advanced decompiler popup workflows:
  `ActionContext::{widget_handle, focused_widget_handle, decompiler_view_handle}`
  plus scoped helpers `with_widget_host` / `with_decompiler_view_host`.
- Added typed decompiler-view session wrappers for high-value edit/read flows:
  `DecompilerView`, `view_from_host`, `view_for_function`, `current_view`
  with wrappers for rename/retype/comment/save/refresh operations.
- Added microblock index-level lifecycle helpers:
  `MicrocodeContext::has_instruction_at_index` and
  `MicrocodeContext::remove_instruction_at_index`.
- Expanded helper-call tmop shaping with typed micro-operand destinations
  (`emit_helper_call_with_arguments_to_micro_operand[_and_options]`) and
  additional typed call-argument value kinds (`BlockReference`,
  `NestedInstruction`).
- Applied typed micro-operand destination routing in additional AVX/VMX helper
  branches (`vmread`, scalar/packed min/max/sqrt, packed conversion, and
  variadic helper register destinations), and now prefer resolved-memory
  compare destinations (any memory operand with resolvable target address ->
  `GlobalAddress`) before operand writeback fallback.
- Began additive callinfo/tmop depth in executable probe helper paths:
  compare-family helper calls now use semantic role hints
  (`MicrocodeFunctionRole::SseCompare4`/`SseCompare8` for
  `vcmp*`/`vpcmp*` forms), rotate-family helper calls now use
  `RotateLeft`/`RotateRight` role hints, and helper arguments across variadic,
  VMX, and explicit scalar/packed helper paths carry `argument_name` metadata
  for clearer typed call-argument semantics. Selected destination-helper paths
  now also apply declaration-driven return typing (`vmread` register destination
  integer widths and scalar `vmin*`/`vmax*`/`vsqrt*` float/double returns),
  with explicit register `return_location` hints on stable register-destination
  helper flows. Compare helper routing now attempts typed register-destination
  micro-operand emission from structured operand register ids before fallback,
  retries register-location hints without explicit location metadata on
  validation-level rejection, and falls back to base compare call options
  (without declaration/location hints) if validation rejection persists,
  applies static-address `return_location` hints on resolved-memory destination
  micro-routes (with validation-safe fallback when unsupported, including
  fallback to base compare call options on repeated validation rejection),
  and hardening coverage now validates static-location `BadAddress` rejection on
  `to_operand` helper routes for cross-route contract consistency plus
  global-destination return-type-size mismatch validation (including
  `to_operand` route checks). For unresolved compare destinations, helper-return
  routing now also attempts temporary-register helper emission +
  `store_operand_register` writeback before direct `to_operand` fallback;
  resolved-memory micro routes, register micro routes, temporary-register bridge
  routes, and degraded `to_operand` routes now all apply validation-safe retry
  with base compare options when hint-rich options are rejected. Temporary
  writeback now degrades `store_operand_register` `Validation`/`NotFound`
  outcomes to non-fatal not-handled behavior while preserving hard
  SDK/internal failures,
  and operand-index writeback fallback is now
  constrained to unresolved destination shapes only (mask-register destination
  or memory destination without resolvable target address).

## Notes

- The current idax decompiler surface is strong for read/query workflows
  (pseudocode text, ctree traversal, variable edits, comments, microcode text
  extraction) and supports partial lifter diagnostics.
- The blocker set is concentrated in decompiler write-path depth and advanced
  decompiler write-path depth and deeper in-view mutation breadth, not in plugin
  bootstrapping or basic action ergonomics.
- The port probe intentionally keeps all interactions SDK-opaque and additive,
  so every listed gap corresponds to a concrete missing public wrapper surface.
