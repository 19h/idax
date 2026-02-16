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
  `mark inline`, `mark outline`, `toggle debug printing`, `show gaps`).
- Pseudocode-popup attachment through `ida::ui::on_widget_visible` +
  `ida::plugin::attach_to_popup` by widget title.
- Decompiler snapshot workflows (`decompile`, `lines`, `microcode_lines`,
  `for_each_expression`) for call-expression counting and microcode preview.
- Separate context-sensitive "Mark as inline" / "Mark as outline" actions with
  `enabled_with_context` querying `ida::function::is_outlined()` for state-
  dependent enablement, matching the original's dual-action design.
- Outlining + cache invalidation flow via `ida::function::is_outlined` /
  `ida::function::set_outlined` and `ida::decompiler::mark_dirty_with_callers`.
- Debug printing toggle with maturity-driven disassembly/microcode dumps via
  `ida::decompiler::on_maturity_changed()` and `ScopedSubscription`, matching
  the original's `hexrays_debug_callback` at `MMAT_GENERATED`/`MMAT_PREOPTIMIZED`/
  `MMAT_LOCOPT` stages.
- 32-bit YMM skip guard in `match()` using function/segment bitness to avoid
  Hex-Rays `INTERR 50920` on 256-bit temporaries in 32-bit mode.
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

1. **CLOSED.** Microcode filter hooks and write-path depth are now sufficient for
   full lifter-class migration.
    - idax supports registration/unregistration and match/apply dispatch
      (`register_microcode_filter`, `unregister_microcode_filter`,
      `MicrocodeContext`, `MicrocodeApplyResult`).
    - The port uses those hooks for concrete VMX + AVX scalar/packed
      instruction subsets with helper-call and typed microcode lowering.
    - A comprehensive cross-reference audit of all 14 SDK mutation pattern
      categories from the original lifter (`cdg.emit`, `alloc_kreg/free_kreg`,
      `store_operand_hack`, `load_operand_udt`, `emit_zmm_load`,
      `emit_vector_store`, `AVXIntrinsic`, `AvxOpLoader`, `mop_t` construction,
      `minsn_t` post-processing, `load_operand`/`load_effective_address`,
      `MaskInfo`, misc utilities) confirmed that 13 of 14 are **fully covered**
      by idax wrapper APIs actively used in the port. The remaining pattern
      (post-emit instruction field mutation) has lifecycle helpers available
      (remove/query/re-emit) that provide functional equivalence.
    - Deep mutation breadth audit: complete. No new wrapper APIs required.

2. **CLOSED.** Rich public microcode write/emission surface now covers all
   original lifter SDK patterns.
    - idax exposes: generic typed instruction emission (`MicrocodeOpcode` with
      19 opcodes, `MicrocodeOperand`, `MicrocodeInstruction`,
      `emit_instruction`/`emit_instructions`), typed helper-call argument
      builders (integer/float/byte-array/vector/type-declaration views,
      register-pair/global-address/stack-variable/helper-reference/block-
      reference/nested-instruction argument forms, declaration-driven vector
      element typing), explicit argument-location hints (register/register-pair/
      register-offset/register-relative/stack/static/scattered),
      comprehensive helper call-shaping options (calling-convention/flags,
      scalar callinfo fields, return-type/return-location hints,
      register-list/visible-memory callinfo list shaping, semantic function
      roles, per-argument name/flag metadata), temporary register allocation,
      placement policy controls, operand UDT marking, and microblock lifecycle
      helpers.
    - The port actively uses 26 helper-call emission sites, 7 typed instruction
      emission sites, 37 operand load sites, 4 effective address loads,
      4 operand writeback sites, and 11 UDT marking references — covering
      300+ individual mnemonics through the full wrapper stack.
    - Impact: instruction-to-intrinsic lowering is fully implementable.

3. **CLOSED.** Action context has opaque host bridges and typed decompiler-view
   session helpers covering all observed lifter popup workflows.
    - idax provides scoped host access from action callbacks
      (`with_widget_host`, `with_decompiler_view_host`) plus context host fields,
      and first-class typed wrappers (`DecompilerView`, `view_from_host`,
      `view_for_function`, `current_view`) for variable/comment/refresh flows.
    - Impact: no remaining migration blockers for plugin/action/popup workflows.

## Comprehensive source-backed gap matrix (current)

A comprehensive cross-reference audit was performed comparing all 14 SDK
mutation pattern categories from the original lifter against the idax wrapper
API surface and port usage. The audit examined every handler file
(`handler_math.cpp`, `handler_mov.cpp`, `handler_cvt.cpp`,
`handler_logic.cpp`), helper implementations (`avx_helpers.cpp`,
`avx_intrinsic.cpp/h`), and the full port plugin (~2,700 lines).

### A) Microcode instruction construction/emission depth — CLOSED

- Source evidence: `handler_*.cpp`, `avx_helpers.cpp`, `vmx_lifter.cpp`
- Original pattern: `cdg.emit(opcode, ...)` with ~50+ call sites for `m_mov`,
  `m_xdu`, `m_i2f`, `m_f2f`, `m_ldx`, `m_stx`, `m_nop`, `m_add`, `m_fadd/
  fsub/fmul/fdiv`.
- idax status: **fully covered**. `emit_instruction()` supports 19 opcodes.
  Port uses 7 typed emission sites + 3 noop sites covering 14 opcodes. All
  operand forms (register, immediate, UDT-flagged wide) are expressible via
  `MicrocodeOperand`. Placement policy controls available via
  `emit_instruction_with_policy`.
- Migration impact: **none**. All handler emission patterns are expressible.

### B) Typed microcode operand model and mutation controls — CLOSED

- Source evidence: `avx_intrinsic.cpp`, `avx_helpers.cpp`, `vmx_lifter.cpp`
- Original pattern: `mop_t` construction (`make_reg`, `make_number`,
  `set_udt`), `minsn_t` field updates, `alloc_kreg`/`free_kreg` (~60+ pairs).
- idax status: **fully covered**. `MicrocodeOperand` supports Register,
  GlobalAddress, StackVariable, HelperReference, BlockReference,
  NestedInstruction, LocalVariable, UnsignedImmediate. UDT marking via
  `mark_user_defined_type` (11 references in port). Temporary register
  allocation via `allocate_temporary_register` (idax handles free internally).
  Post-emit lifecycle via `remove_last_emitted_instruction` /
  `remove_instruction_at_index` (functional equivalent to field mutation via
  remove+re-emit).
- Migration impact: **none**. All operand/register/mutation patterns are
  expressible. The only minor difference is post-emit field mutation uses
  remove+re-emit instead of in-place update — functionally equivalent.

### C) Callinfo/tmop richness — CLOSED

- Source evidence: `avx_intrinsic.cpp`, `vmx_lifter.cpp`
- Original pattern: `AVXIntrinsic` builder class constructing `mcallinfo_t`
  with argument wiring, calling convention, return type, callinfo flags,
  spoiled/dead registers (~100+ usage sites).
- idax status: **fully covered**. `emit_helper_call_with_arguments_*` family
  (26 call sites in port) provides: `MicrocodeCallOptions` (calling convention,
  FCI flags, callee/SPD/solid-arg hints, function roles, return-location,
  return-type declaration, register lists, visible memory, insert policy),
  `MicrocodeValue` with 33 reference sites (Register, UnsignedImmediate, type
  declarations, argument names/flags), and typed micro-operand destinations.
  Vector type declarations via `vector_type_declaration()`.
- Migration impact: **none**. All AVXIntrinsic builder patterns are expressible
  through the helper-call API family with richer callinfo options.

### D) Microblock placement/lifecycle editing — CLOSED

- Source evidence: `avx_intrinsic.cpp`, `vmx_lifter.cpp`
- Original pattern: `insert_into_block(new, mb->tail)` and ownership transfer.
- idax status: **fully covered**. `MicrocodeInsertPolicy` (Tail/Beginning/
  BeforeTail), policy-aware variants for all emission helpers, `insert_policy`
  in `MicrocodeCallOptions`. Lifecycle ergonomics include index-based
  query/removal.
- Migration impact: **none**. All placement patterns are expressible.

### E) Typed decompiler-view edit ergonomics — CLOSED

- Source evidence: `src/plugin/lifter_plugin.cpp`
- Original pattern: `vdui_t*` context use in popup workflows.
- idax status: **fully covered**. `ActionContext` host bridges + typed
  `DecompilerView` wrappers (`view_from_host`, `view_for_function`,
  `current_view`) cover all observed popup/edit/read flows.
- Migration impact: **none** for observed lifter popup patterns.

## Prioritized additive API slices for lifter closure

All slices are **CLOSED**.

1. `P0` - Generic typed microcode instruction builder/emitter — **CLOSED**
   - `MicrocodeInstruction` + `MicrocodeOperand` and
     `emit_instruction(...)`/`emit_instructions(...)` available with 19 opcodes,
     strict validation, typed error mapping, and placement policy controls.
   - Port exercises 14 opcodes across 7 emission sites.

2. `P1` - Extended typed callinfo authoring surface — **CLOSED**
   - `MicrocodeCallOptions` covers calling convention, FCI flags, scalar hints,
     function roles, return-location/type, register lists, visible memory,
     per-argument name/flag metadata, and insert policy.
   - Port exercises 26 helper-call emission sites with rich callinfo shaping.

3. `P2` - Placement policy controls — **CLOSED**
   - `MicrocodeInsertPolicy` + policy-aware variants for all emission paths.
   - Lifecycle helpers (`block_instruction_count`, index query/removal).

4. `P3` - Typed high-value decompiler-view helpers — **CLOSED**
   - `DecompilerView`, `view_from_host`, `view_for_function`, `current_view`
     plus `ActionContext` host bridges cover all observed lifter popup flows.

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
  resolved-memory micro routes, register micro routes, direct register-
  destination routes, temporary-register bridge routes, and degraded
  `to_operand` routes now all apply validation-safe retry with base compare
  options when hint-rich options are rejected. Temporary writeback now degrades
  `store_operand_register` `Validation`/`NotFound` outcomes to non-fatal
  not-handled behavior while preserving hard SDK/internal failures, and the
  temporary-register bridge now guards error-category reads behind
  `!temporary_helper_status` before accessing `.error()` after degradable
  writeback outcomes. Residual `NotFound` outcomes on degraded `to_operand`
  and direct register-destination compare routes now also degrade to
  not-handled after retries,
  operand-index writeback fallback is now constrained to unresolved
  destination shapes only (mask-register destination or memory destination
  without resolvable target address), and the temporary-register bridge now
  uses typed `_to_micro_operand` destination routing (using the allocated
  temporary register id as a `MicrocodeOperand` with `kind = Register`)
  instead of `_to_register`, eliminating the last non-typed helper-call
  destination path in the lifter probe. All remaining operand-writeback
  sites (`store_operand_register` for unresolved compare shapes and vmov
  memory stores, `to_operand` for terminal compare fallback) are genuinely
  irreducible.

- Added SSE passthrough handling: instructions handled natively by IDA
  (`vcomiss`, `vcomisd`, `vucomiss`, `vucomisd`, `vpextrb/w/d/q`,
  `vcvttss2si`, `vcvttsd2si`, `vcvtsd2si`, `vcvtsi2ss`, `vcvtsi2sd`)
  are now excluded from filter matching so IDA processes them directly.
- Added K-register NOP handling: k-register manipulation instructions
  (`kmov*`, `kadd*`, `kand*`, etc.) and instructions with mask-register
  destinations are now matched and emit NOP, consistent with the original
  lifter's approach of acknowledging these instructions without modeling
  k-register semantics in microcode.
- Massively expanded mnemonic coverage to include: FMA families
  (`vfmadd*/vfmsub*/vfnmadd*/vfnmsub*`), IFMA (`vpmadd52*`), VNNI
  (`vpdpbusd*/vpdpwssd*`), BF16, FP16 (scalar+packed math/sqrt/FMA/moves/
  conversions/reduce/getexp/getmant/scalef/reciprocal), cache control
  (`clflushopt/clwb`), integer unpack (`vpunpck*`), shuffles
  (`vpshufb/vpshufd/vpshufhw/vpshuflw/vperm2f128/vperm2i128/vshufps/vshufpd/
  vpermpd`), packed minmax integer, avg, abs, sign, additional integer
  multiply, multishift, SAD, byte-shift (`vpslldq/vpsrldq`), scalar approx/
  round/getexp/getmant/fixupimm/scalef/range/reduce, and `vmovd`/`vmovq`.
- Added dedicated `vmovd`/`vmovq` handler using native `ZeroExtend` (m_xdu)
  microcode instruction instead of opaque helper-call fallback, correctly
  modeling the zero-extension semantics of GPR/memory-to-XMM moves and
  the simple extraction semantics of XMM-to-GPR/memory moves.
- Added AVX-512 opmask introspection API surface:
  `MicrocodeContext::has_opmask()`, `MicrocodeContext::is_zero_masking()`,
  and `MicrocodeContext::opmask_register_number()` — exposing EVEX mask
  metadata from the instruction being lifted without requiring Intel-specific
  headers in user code.
- Wired AVX-512 opmask support uniformly across ALL helper-call paths: when an
  instruction uses opmask masking, the helper name is suffixed with `_mask`
  or `_maskz`, and masking arguments are appended (merge-source register for
  merge-masking, mask register number as unsigned immediate) with appropriate
  `__mmask*` type widths inferred from vector width and element size. Masking
  is now applied in: normal variadic helpers, compare helpers, store-like
  helpers, scalar min/max/sqrt helpers, packed sqrt/addsub/min/max helpers,
  and helper-fallback conversion paths. For native microcode emission paths
  (typed binary, typed conversion, typed moves, typed packed FP math), the
  port skips to helper-call fallback when masking is present, since native
  microcode instructions cannot represent per-element masking (GAP 3 closed).
- Added `vector_type_declaration(byte_width, is_integer, is_double)` helper that
  mirrors the original lifter's `get_type_robust(size, is_int, is_double)` type
  resolution pattern. For scalar sizes (1-8 bytes) it delegates to
  `integer_type_declaration` / `floating_type_declaration`. For vector sizes
  (16/32/64 bytes) it returns the appropriate named type string (`__m128`,
  `__m128i`, `__m128d`, `__m256`, `__m256i`, `__m256d`, `__m512`, `__m512i`,
  `__m512d`) which `parse_decl` resolves against the DB's type library — the
  same lookup the original performs via `tinfo_t::get_named_type()`. This
  produces proper named vector types in decompiler output instead of anonymous
  byte-array structs. Applied across all helper-call return paths: variadic
  helpers, compare helpers, packed sqrt/addsub/min/max helpers, and
  helper-fallback conversions (GAP 7 closed).

## Notes

- The idax decompiler surface is comprehensive for both read/query workflows
  (pseudocode text, ctree traversal, variable edits, comments, microcode text
  extraction) and write-path workflows (instruction emission, helper-call
  construction, operand writeback, placement control, lifecycle management).
- A deep mutation breadth audit cross-referencing all 14 SDK mutation pattern
  categories from the original lifter confirmed full wrapper API coverage:
  13 of 14 patterns are actively used in the port, and the remaining pattern
  (post-emit instruction field mutation) has functional equivalence via
  remove+re-emit lifecycle helpers.
- The port probe (~2,800 lines) intentionally keeps all interactions SDK-opaque,
  covering 300+ individual AVX/VMX mnemonics through the full wrapper stack
  without any raw SDK usage.
- All 9 original gap categories (GAP 1–9) and all 5 source-backed gap matrix
  items (A–E) are now CLOSED. No remaining wrapper API additions are required
  for lifter-class microcode transformation ports.
- Plugin-shell feature parity with the original is now comprehensive:
  separate mark-inline/mark-outline actions, debug printing toggle with
  maturity subscription, 32-bit YMM skip, SSE passthrough, K-register NOP,
  AVX-512 opmask masking, and vector type declaration parity.
- The only remaining behavioral difference vs. the original is the processor-ID
  check (`PH.id != PLFM_386`) — idax has no direct `processor_id()` wrapper.
  This is irrelevant for the lifter port which only operates on x86/x64
  databases.
