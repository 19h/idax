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
  with mixed register/immediate/memory-source forwarding and compare
  mask-destination no-op tolerance,
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

3. Action context now has opaque host bridges, but typed decompiler-view
   ergonomics are still pending
   - lifter popup handlers rely on direct `vdui_t` / `cfunc_t` level handles.
   - idax now provides scoped host access from action callbacks
     (`with_widget_host`, `with_decompiler_view_host`) plus context host fields,
     which unblocks practical advanced interop without exposing SDK types in
     public headers.
    - Impact: advanced workflows are now possible through opaque host bridges,
      but typed first-class wrappers for high-value `vdui_t`/`cfunc_t` edit flows
      are still additive follow-up work.

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
  - Remaining depth is richer typed callinfo/tmop authoring controls beyond
  current option-hint shaping.
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
  - Remaining depth is placement control parity for additional non-typed-
    emitter paths. Helper-call insertion now also supports `insert_policy`
    through `MicrocodeCallOptions`.
- Migration impact:
  - medium. Some deterministic rewrite ordering patterns cannot be expressed
    through public APIs yet.

### E) Typed decompiler-view edit ergonomics

- Source evidence (`/Users/int/dev/lifter`):
  - `src/plugin/lifter_plugin.cpp` (popup and decompiler-view driven flows)
- Pattern used in lifter:
  - direct `vdui_t*` context use in popup workflows.
- Current idax status:
  - partial but much improved. `ActionContext` now includes opaque view/widget
    handles with scoped host callbacks; this is sufficient for advanced interop
    without exposing SDK types. Pure typed first-class decompiler-view edit APIs
    remain additive follow-up.
- Migration impact:
  - medium. Bridge path exists now; typed ergonomics remain a convenience gap.

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
- Expanded helper-call per-argument metadata shaping:
  arguments can now carry formal name/flag metadata via
  `MicrocodeValue::argument_name` + `MicrocodeValue::argument_flags`
  (`MicrocodeArgumentFlag`).
- Expanded typed microcode operand/mop builders for generic instruction
  emission and helper arguments:
  `RegisterPair`, `GlobalAddress`, `StackVariable`, `HelperReference`, and
  `BlockReference`.
- Expanded vector helper-call typing with declaration-driven element types,
  enabling richer non-scalar/UDT-style element modeling when concrete widths are
  validated.
- Expanded advanced callinfo list shaping in `MicrocodeCallOptions` with
  register-list and visible-memory controls (`return_registers`,
  `spoiled_registers`, `passthrough_registers`, `dead_registers`,
  `visible_memory_ranges`, `visible_memory_all`).
- Expanded executable probe coverage from VMX-only lowering to include AVX
  scalar and packed math/move flows (`vadd*`/`vsub*`/`vmul*`/`vdiv*`, `vcvt*`,
  `vmin*`/`vmax*`, `vsqrt*`, `vmov*`) through typed instruction emission,
  helper-return composition, and store-aware move lowering.
- Added action-context host bridges for advanced decompiler popup workflows:
  `ActionContext::{widget_handle, focused_widget_handle, decompiler_view_handle}`
  plus scoped helpers `with_widget_host` / `with_decompiler_view_host`.

## Notes

- The current idax decompiler surface is strong for read/query workflows
  (pseudocode text, ctree traversal, variable edits, comments, microcode text
  extraction) and supports partial lifter diagnostics.
- The blocker set is concentrated in decompiler write-path depth and advanced
  per-view handle access, not in plugin bootstrapping or basic action ergonomics.
- The port probe intentionally keeps all interactions SDK-opaque and additive,
  so every listed gap corresponds to a concrete missing public wrapper surface.
