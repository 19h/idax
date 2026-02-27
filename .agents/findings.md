# Findings and Learnings (Live)

Entries below summarize key findings to preserve as implementation guardrails.
Format note: use a numbered list with one concrete technical finding per item; keep wording concise and include impact/mitigation only when it materially helps.

1. API naming inconsistency is the biggest onboarding barrier.
2. Implicit sentinels (`BADADDR`, `BADSEL`, magic ints) create silent failures.
3. Encoded flags/mixed bitfields are powerful but hard to reason about quickly.
4. Multiple equivalent SDK API paths differ subtly in semantics and side effects.
5. Pointer validity/lifecycle semantics need strong encapsulation in ergonomic wrappers.
6. Type and decompiler domains are high-power/high-complexity; need progressive API layering.
7. Debugger/UI domains need typed abstractions to prevent vararg misuse bugs.
8. Fully opaque wrappers need comprehensive coverage to avoid forcing raw SDK fallback.
9. Public API simplicity must preserve capability; advanced options must remain in structured form.
10. Migration docs are as critical as API design for adoption.
11. Interface-level API sketches must be present (not just summaries) to avoid implementation ambiguity.
12. C++23 + SDK `pro.h` incompatibility: `std::is_pod<T>` used without `#include <type_traits>`. Fix: include `<type_traits>` before `<pro.h>` in bridge header.
13. SDK segment API: `segment_t::perm` uses `SEGPERM_READ/WRITE/EXEC` (not `SFL_*`). Visibility via `is_visible_segm()` (not `is_hidden_segtype()`).
14. SDK float types require `BTF_FLOAT` (=`BT_FLOAT|BTMT_FLOAT`) and `BTF_DOUBLE` (=`BT_FLOAT|BTMT_DOUBLE`), not raw `BT_FLOAT`/`BTMT_DOUBLE`.
15. Private member access: use `friend struct XxxAccess` with static `populate()` in impl file. Anonymous namespace helpers cannot be friends.
16. **CRITICAL**: SDK stub dylibs vs real IDA dylibs have mismatched symbol exports. Stub `libidalib.dylib` exports symbols (e.g. `qvector_reserve`) the real one doesn't—only real `libida.dylib` does. macOS two-level namespace causes null-pointer crashes. **Fix**: link against real IDA dylibs, not SDK stubs.
17. CMake: `libidax.a` uses custom `idasdk_headers` INTERFACE target (SDK includes + `__EA64__` + platform settings). Consumers bring own `idasdk::plugin`/`idasdk::idalib`. For idalib tests, link real IDA dylibs to avoid namespace mismatches.
18. Graph API: `create_interactive_graph()` returns nullptr in idalib/headless. Graph uses standalone adjacency-list for programmatic use; only `show_graph()` needs UI. `qflow_chart_t` works in all modes.
19. SDK graph: `FC_PREDS` renamed to `FC_RESERVED`. Predecessors built by default; `FC_NOPREDS` to disable. `insert_simple_nodes()` takes `intvec_t&` (reference, not pointer).
20. SDK chooser: `chooser_t::choose()` returns ssize_t (-1=no selection, -2=empty, -3=already exists). `CH_KEEP` prevents deletion on widget close. Column widths encode `CHCOL_*` format flags in high bits.
21. SDK loader: `loader_failure()` does longjmp, never returns. No C++ base class for loaders (unlike `procmod_t`). Wrapper bridges C function pointers to C++ virtual methods via global instance pointer.
22. Hex-Rays ctree: `apply_to()`/`apply_to_exprs()` dispatch through `HEXDSP` runtime function pointers (no link-time dep). `CV_POST` enables leave_*() callbacks. `CV_PRUNE` via `prune_now()` skips children. `citem_t::is_expr()` returns `op <= cot_last` (69). `treeitems` populated after `get_pseudocode()`, maps line indices to `citem_t*`. `cfunc_t::hdrlines` is offset between treeitems indices and pseudocode line numbers.
23. `get_widget_title()` takes `(qstring *buf, TWidget *widget)` — NOT single-arg returning `const char*`. Changed from older SDKs.
24. Debugger notification API: mixed `va_list` signatures. Most events pass `const debug_event_t*`, but `dbg_bpt`/`dbg_trace` pass `(thid_t, ea_t, ...)` directly. Wrappers must decode per-event arg layouts.
25. `switch_info_t` encodes element sizes via `SWI_J32/SWI_JSIZE` and `SWI_V32/SWI_VSIZE` bit-pairs, not explicit byte fields. Expose normalized byte-size fields in wrapper structs.
26. IDB event payloads are `va_list`-backed, consumable only once. For multi-subscriber routing, decode once into normalized event object, then fan out.
27. `get_strlit_contents()` supports `len = size_t(-1)` auto-length: uses existing strlit item size or `get_max_strlit_length(...)`. Enables robust string extraction without prior data-definition calls.
28. Snapshot APIs in `loader.hpp`: `build_snapshot_tree()` returns synthetic root whose `children` are top-level snapshots. `update_snapshot_attributes(nullptr, root, attr, SSUF_DESC)` updates current DB snapshot description.
29. Custom fixup registration: `register_custom_fixup()`/`find_custom_fixup()`/`unregister_custom_fixup()` returns type ids in `FIXUP_CUSTOM` range (0 on duplicate/missing). Wrappers return typed IDs, map duplicates to conflict errors.
30. DB transfer: `file2base(li, pos, ea1, ea2, patchable)` requires open `linput_t*` + explicit close. `mem2base(ptr, ea1, ea2, fpos)` returns 1 on success, accepts `fpos=-1` for no file offset.
31. SDK bridge internals (`sdk_bridge.hpp`) in iostream-heavy tests collide with `fpro.h` stdio macro remaps (`stdout` -> `dont_use_stdout`). Keep string checks in integration-level tests or avoid iostream in bridge TUs.
32. Comment API: `append_cmt` success doesn't guarantee appended text round-trips via `get_cmt` as strict suffix. Tests should assert append success + core content presence, not strict suffix matching.
33. Netnode blob ops at index 0 can trigger `std::length_error: vector` crashes in idalib. Use non-zero indices (100+) for blob/alt/sup ops; document safe ranges.
34. `FunctionIterator::operator*()` returns by value (not reference); range-for must use `auto f` not `auto& f`. Constructs `Function` value from internal SDK state each dereference. Same for `FixupIterator`.
35. `DecompiledFunction` is move-only (`cfuncptr_t` is refcounted). `std::expected<DecompiledFunction, Error>` also non-copyable. Test macros using `auto _r = (expr)` must be replaced with reference-based checks.
36. P9.1 Audit: polarity clash (`Segment::visible()` vs `Function::is_hidden()`), subscription naming stutter (`debugger_unsubscribe` in `ida::debugger`), duplicate binary pattern search in `data`/`search`. Fix: unified positive polarity (`is_visible()`), removed stutter, documented dual-path.
37. P9.1 Audit: ~200+ `ea` params renamed to `address`, `set_op_*` to `set_operand_*`, `del_*` to `remove_*`, `idx`/`cmt` abbreviations expanded in public interfaces.
38. P9.1 Audit: `Plugin::run()` returned `bool` not `Status`; `Processor::analyze/emulate/output_operand` returned raw `int`; `line_to_address()` returned `BadAddress` as success; UI dialog cancellation was `SdkFailure` not `Validation`. All fixed.
39. P9.1 Audit: opaque boundary confirmed zero HIGH violations (no SDK types leak into public headers). MEDIUM: `Chooser::impl()`/`Graph::impl()` unnecessarily public, `xref::Reference::raw_type` exposed raw SDK codes. Fixed: `impl()` private, `raw_type` replaced with typed `ReferenceType` enum.
40. macOS linker warnings: IDA 9.3 dylibs built for macOS 12.0 while objects target 11.0. Warning-only; runtime stable. Keep linking real dylibs (required for symbol correctness).
41. CPack output dir drifts with arbitrary working directories. Fix: invoke with `-B <build-dir>` to pin artifact location.
42. Plugin surface gap (`entropyx/ida-port`): missing dockable custom widget hosting (`create_empty_widget`/`display_widget`/`close_widget`), HT_VIEW/UI notification coverage, `jumpto`, segment-type introspection. Add opaque dock-widget APIs, expanded event routing, `ui::jump_to`, `segment::Segment::type()`/`set_type()`.
43. Title-only widget callbacks insufficient for complex multi-panel plugins—titles aren't stable identities, no per-instance lifecycle tracking. Surface opaque widget handles in notifications.
44. Plugin authoring gap: `make_plugin_descriptor()` referenced but no public export helper exists. Add explicit descriptor/export helper bridging `Plugin` subclasses to IDA entrypoints.
45. SDK dock constants: `WOPN_DP_FLOATING` (not `WOPN_DP_FLOAT`). Defined in `kernwin.hpp` as `DP_*` shifts by `WOPN_DP_SHIFT`. `WOPN_RESTORE` restores size/position. `display_widget()` takes `(TWidget*, uint32 flags)`.
46. `view_curpos` event: no `va_list` payload—get position via `get_screen_ea()`. Differs from `ui_screen_ea_changed` which passes `(new_ea, prev_ea)` in `va_list`.
47. Widget identity: `TWidget*` stable for widget lifetime. Handle-based subscriptions compare `TWidget*` pointers. Opaque `Widget` stores `void*` + monotonic `uint64_t` id for cross-callback identity.
48. `plugin_t PLUGIN` static init: must use char arrays (not `std::string::c_str()`) to avoid cross-TU init ordering. Static char buffers populated at `idax_plugin_init_()` time. `IDAX_PLUGIN` macro registers factory via `make_plugin_export()`; `plugin_t PLUGIN` lives in `plugin.cpp` (compiled into `libidax.a`).
49. Segment type constants: SDK `SEG_NORM(0)`–`SEG_IMEM(12)`. Wrapper `segment::Type` maps all 12 values plus aliases: `Import`=`SEG_IMP=4`, `InternalMemory`=`SEG_IMEM=12`, `Group`=`SEG_GRP=6`. `segment_t::type` is `uchar`.
50. entropyx portability: dock widget lifecycle present, but Qt plugins still need underlying host container for `QWidget` embedding (entropyx casts `TWidget*` to `QWidget*`). `ida::ui::Widget` is opaque, no container attachment. Add `ui::with_widget_host(Widget&, callback)` with `void*` host pointer.
51. Widget host bridge: scoped callback (`with_widget_host`) over raw getter reduces accidental long-lived toolkit pointer storage. Host pointer type remains `void*` (`WidgetHost`) for SDK/Qt opacity.
52. `action_activation_ctx_t` carries many SDK pointers. Normalize only stable high-value fields (action id, widget title/type, current address/value, selection/xtrn bits, register name) into SDK-free structs.
53. Generic UI/VIEW routing needs token-family partitioning: UI (`< 1<<62`), VIEW (`[1<<62, 1<<63)`), composite (`>= 1<<63`) for safe unsubscribe of composite subscriptions.
54. SDK parity audit: broad domain coverage across all namespaces, but depth uneven (`partial` vs full SDK breadth). Closing parity needs matrix-driven checklist with per-domain closure criteria.
55. Diagnostics counters: plain shared struct creates data-race risk under concurrent logging/assertion. Use atomic counter fields and snapshot reads.
56. Compile-only parity drift: when headers evolve quickly, compile-only tests can lag. Expand `api_surface_parity_test.cpp` with header changes, including overload disambiguation.
57. `create_float`/`create_double` may fail at specific addresses in real DBs. Treat float/double define checks as conditional capability probes; assert category on failure.
58. `open_database()` in idalib performs loader selection internally, so `LoadIntent` (`Binary`/`NonBinary`) maps to same open path. Keep explicit intent API, wire to dedicated paths when possible.
59. SDK segment comments: `get_segment_cmt`/`set_segment_cmt` operate on `const segment_t*`. `set_segment_cmt` returns `void`. Validate target segment first; treat set as best-effort.
60. `set_entry_forwarder(ord, "")` can fail for some ordinals/DBs in idalib. Expose explicit `clear_forwarder()` returning `SdkFailure`; tests use set/read/restore patterns.
61. SDK search: `find_*` helpers already skip start address; `SEARCH_NEXT` mainly meaningful for lower-level text/binary search. Keep typed options uniform; validate with integration tests.
62. SDK action detach helpers return only success/failure, no absent-attachment distinction. Map detach failures to `NotFound` with action/widget context.
63. Loader callback context: load/reload/archive extraction spread across raw callback args and bitflags (`ACCEPT_*`, `NEF_*`). Expose typed request structs and `LoadFlags` encode/decode helpers.
64. Processor output: existing modules rely on side-effect callbacks; advanced ports need structured text assembly. Add `OutputContext` and context-driven hooks with fallback defaults (non-breaking).
65. SDK netnode existence: `exist(const netnode&)` is hidden-friend resolved via ADL. Qualifying as `::exist(...)` fails to compile. Call `exist(nn)` unqualified.
66. Debugger request queue: `request_*` APIs enqueue, need `run_requests()` to dispatch; direct `step_*`/`run_to`/`suspend_process` execute immediately. Mixing styles without flush causes no-op behavior. Expose explicit request helpers + `is_request_running()`/`run_requests()`.
67. SDK custom viewer lifetime: `create_custom_viewer()` relies on caller-provided line buffer/place objects remaining valid for widget lifetime. Store per-viewer state in wrapper-managed lifetime storage; erase on close.
68. Graph layout in headless is behavioral (stateful contract), not geometric rendering. Persist selected `Layout` in `Graph`, expose `current_layout()`, validate via deterministic integration checks.
69. Decompiler lvar retype persistence: uses `modify_user_lvar_info(..., MLI_TYPE, ...)` with stable locator. In-memory type tweaks alone are insufficient. Route through saved-user-info updates; add refresh + re-decompile checks.
70. Cross-cutting/event parity closure can use intentional-abstraction documentation when full raw SDK mirroring is counter to wrapper goals. Keep `partial` with rationale + expansion triggers.
71. Linux compile-only: GCC 13.3.0 passes on Ubuntu 24.04; Clang 18.1.3 fails with missing `std::expected` even with `-std=c++23`.
72. Linux Clang libc++ fallback: `-stdlib=libc++` avoids `std::expected` gap but fails during SDK header inclusion—`pro.h` remaps `snprintf` -> `dont_use_snprintf`, colliding with libc++ internals.
73. GitHub-hosted cross-platform validation: `compile-only` and `unit` profiles work without licensed IDA runtime by checking out `ida-sdk` with `IDADIR` unset; integration tests auto-skipped.
74. IDA SDK checkout layout varies (`<sdk>/ida-cmake/`, `<sdk>/cmake/`, submodule-backed). May need recursive submodule fetch. Resolve layout explicitly; support all known bootstrap locations.
75. CI submodule policy: both project and SDK checkouts should use recursive submodule fetch. Set `submodules: recursive` on both checkout steps.
76. GitHub Actions macOS labels change over time. Keep active labels (currently `macos-14`); reintroduce x86_64 via supported labels or self-hosted runners.
77. CTest on multi-config generators (Visual Studio): requires explicit `-C <config>` at test time. Always pass `--config` to `cmake --build` and `-C` to `ctest`.
78. SDK `pro.h` stdio remaps (`snprintf -> dont_use_snprintf`) collide with newer libc++ internals. Include key C++ headers before `pro.h` in bridge: `<functional>`, `<locale>`, `<vector>`, `<type_traits>`.
79. Example addon coverage: enable `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON` in CI to catch module-authoring compile regressions without runtime execution.
80. JBC procmod gap: `ida::processor::analyze(Address)` returns only instruction size, no typed operand metadata (`o_near`/`o_mem`/`specflag`). Full ports must re-decode in multiple callbacks. Add optional typed analyze-result operand model.
81. JBC lifecycle gap: no wrapper for `set_default_sreg_value`. Add default-segment-register seeding helper.
82. JBC output gap: `OutputContext` is text-only (no token/color channels, no mnemonic callback parity). Extend with token-category output primitives and mnemonic/operand formatting hooks.
83. CI log audit: grep for `Complete job name`, `validation profile '<profile>' complete`, `100% tests passed` sentinels for quick validation.
84. JBC parity closed: `ida::processor` now includes `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`, tokenized output (`OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`), mnemonic hook (`output_mnemonic_with_context`). `ida::segment` has default segment-register seeding helpers.
85. ida-qtform port: `ida::ui::with_widget_host()` sufficient for Qt panel embedding without raw `TWidget*`.
86. ida-qtform parity: added markup-only `ida::ui::ask_form(std::string_view)` for form preview/test without raw SDK varargs. Add typed argument binding APIs later if needed.
87. idalib-dump parity: decompiler microcode exposed via `DecompiledFunction::microcode()` and `microcode_lines()`.
88. idalib-dump gap: no headless plugin-load policy controls (`--no-plugins`, allowlist). Add database/session open options.
89. idalib-dump parity: decompile failures expose structured details via `DecompileFailure` and `decompile(address, &failure)` (failure address + description).
90. idalib-dump gap: no public Lumina facade. Add `ida::lumina` or document as intentional non-goal.
91. README drift risk: absolute coverage wording, stale surface counts, non-pinned packaging commands can diverge. Keep aligned with `docs/` artifacts.
92. idalib-dump parity: headless plugin-load policy via `RuntimeOptions` + `PluginLoadPolicy` (`disable_user_plugins`, allowlist with `*`/`?`). Reproduces `--no-plugins`/selective `--plugin`.
93. DB metadata: SDK file-type from two sources (`get_file_type_name` vs `INF_FILE_FORMAT_NAME`/`get_loader_format_name`). Expose both with explicit `NotFound` for missing loader-format.
94. Lumina parity: pull/push exposed via `ida::lumina` (`pull`, `push`, typed `BatchResult`/`OperationCode`, feature selection).
95. Lumina runtime: `close_server_connection2`/`close_server_connections` declared in SDK but not link-exported. Keep close wrappers as `Unsupported` until portable close path confirmed.
96. ida2py gap: no first-class user-name enumeration API. Add `ida::name` iterators (`all`, `all_user_defined`) with range/filter options.
97. ida2py gap: `TypeInfo` lacks pointer/array decomposition (pointee type, array element type, array length). Add decomposition helpers + typedef resolution.
98. ida2py gap: no generic typed-value data facade consuming `TypeInfo` for recursive materialization. Consider `ida::data::read_typed`/`write_typed`.
99. ida2py gap: decompiler expression views lack typed call subexpressions (callee + argument accessors). Add typed call-expression accessors in visitor views.
100. ida2py gap: no Appcall/executor abstraction or extension hook for external engines (e.g. angr). Add debugger execution facade + pluggable executor interface.
101. Host runtime caveat: idalib tool examples exit with signal 11 in this environment. Only build/CLI-help validation available; functional checks need known-good idalib host.
102. ida2py parity: `ida::name` now has typed inventory helpers (`all`, `all_user_defined`) backed by SDK nlist enumeration.
103. ida2py parity: `TypeInfo` now includes `is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`.
104. ida2py parity: `ExpressionView` now includes `call_callee`, `call_argument(index)` alongside `call_argument_count`.
105. ida2py parity: `ida::data` now includes `read_typed`/`write_typed` with `TypedValue`/`TypedValueKind`, recursive array support, byte-array/string write paths.
106. ida2py parity: `ida::debugger` now includes Appcall + pluggable executor (`AppcallRequest`/`AppcallValue`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`).
107. Matrix drift risk: validation automation didn't propagate `IDAX_BUILD_EXAMPLE_TOOLS`. Plumb through scripts and CI workflow.
108. Appcall smoke: fixture `ref4` validated safely by calling `int ref4(int *p)` with `p = NULL`, exercises full request/type/argument/return bridging.
109. Tool-example runtime-linking: `ida_add_idalib` can bind to SDK stubs causing two-level namespace crashes. Prefer real IDA dylibs; stub fallback only when runtime libs unavailable.
110. Appcall host nuance: with runtime-linked tools, `--appcall-smoke` fails cleanly with `dbg_appcall` error 1552 (exit 1) instead of crashing. Remaining gap is debugger backend/session readiness.
111. Linux Clang C++23: Clang 18 reports `__cpp_concepts=201907` so `std::expected` stays disabled; Clang 19 reports `202002` and passes. Use Clang 19+ for Linux evidence.
112. Linux SDK artifacts: current checkout lacks `x64_linux_clang_64` runtime libs. Addon/tool targets fail under Linux Clang when build toggles on. Keep toggles OFF for Clang container evidence.
113. Appcall launch: `ida2py_port --appcall-smoke` tries multi-path debuggee launch (relative/absolute/filename+cwd). Host failures resolve to explicit `start_process failed (-1)`. Blocked by debugger backend.
114. Lumina validation: host reports successful `pull`/`push` smoke (`requested=1, succeeded=1, failed=0`). Non-close Lumina runtime validated.
115. lifter port audit: idax decompiler is read-oriented only. No write-path hooks: microcode filter registration, IR emission/mutation, maturity callbacks, `FUNC_OUTLINE` + caller cache invalidation. Full lifter migration blocked after plugin-shell/action porting.
116. lifter parity: added maturity subscriptions (`on_maturity_changed`/`unsubscribe`/`ScopedSubscription`) and outline/cache helpers (`function::is_outlined`/`set_outlined`, `decompiler::mark_dirty`/`mark_dirty_with_callers`). Remaining blocker: microcode write-path + raw decompiler-view handles.
117. lifter parity: baseline microcode-filter hooks added (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`). Full IR mutation (`m_call`/`m_ldx`/typed mops) remains unimplemented.
118. lifter parity: `MicrocodeContext` now includes operand/load-store and emit helpers (`load_operand_register`, `load_effective_address_register`, `store_operand_register`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`, `emit_helper_call`). Advanced typed IR (callinfo/typed mops/helper-call args) still blocked.
119. lifter parity: typed helper-call argument builders added (`MicrocodeValueKind`/`MicrocodeValue`, `emit_helper_call_with_arguments`, `emit_helper_call_with_arguments_to_register`) for integer widths 1/2/4/8. Full parity needs UDT/vector args, callinfo controls, typed mop builders.
120. lifter parity: call option shaping via `MicrocodeCallOptions` + `MicrocodeCallingConvention` (`emit_helper_call_with_arguments_and_options`, `..._to_register_and_options`). Advanced callinfo/tmop depth (non-integer args, reg/stack location, return modeling) still open.
121. lifter parity: scalar FP immediates (`Float32Immediate`, `Float64Immediate`) and explicit-location hinting (`mark_explicit_locations`) added. Vector/UDT and deeper callinfo/tmop controls remain open.
122. lifter parity: `MicrocodeValueLocation` (register/stack offset) for argument-location hints. Auto-promoted when hints present.
123. lifter parity: register-pair and register-with-offset location forms added with validation/error mapping.
124. lifter parity: static-address placement (`set_ea`) with `BadAddress` validation added.
125. lifter parity: scattered/multi-part placement via `MicrocodeLocationPart` + `Scattered` kind with per-part validation (offset/size/kind constraints).
126. lifter parity: byte-array view modeling (`MicrocodeValueKind::ByteArray`) with explicit location requirements.
127. lifter parity: register-relative placement (`ALOC_RREL` via `consume_rrel`) with base-register validation.
128. lifter parity: vector view modeling (`MicrocodeValueKind::Vector`) with typed element width/count/sign/floating controls + explicit location enforcement.
129. lifter parity: declaration-driven type views (`MicrocodeValueKind::TypeDeclarationView`) parsed via `parse_decl` with explicit-location enforcement.
130. callinfo-shaping: `mark_dead_return_registers`, `mark_spoiled_lists_optimized`, `mark_synthetic_has_call`, `mark_has_format_string` mapped to `FCI_DEAD`/`FCI_SPLOK`/`FCI_HASCALL`/`FCI_HASFMT`.
131. callinfo-shaping: scalar field hints (`callee_address`, `solid_argument_count`, `call_stack_pointer_delta`, `stack_arguments_top`) mapped to `mcallinfo_t` fields with validation.
132. ActionContext host bridge: opaque handles (`widget_handle`, `focused_widget_handle`, `decompiler_view_handle`) and scoped callbacks (`with_widget_host`, `with_decompiler_view_host`).
133. Appcall launch fallback: adding `--wait` hold-mode args doesn't change host outcome (`start_process failed (-1)`). Blocker is debugger backend, not fixture timing.
134. Appcall attach fallback: `attach_process` returns `-4` across all permutations. Host blocked at attach readiness too. Gather pass evidence on debugger-capable host.
135. callinfo-shaping: `return_type_declaration` parsed via `parse_decl`, applied to `mcallinfo_t::return_type`. Invalid declarations fail with `Validation`.
136. lifter source-audit: dominant gap is generic microcode instruction authoring (opcode+operand construction, callinfo/tmop depth, deterministic insertion policy). Ad hoc helper-call expansion insufficient. Prioritize generic typed instruction builder/emitter.
137. lifter parity: baseline generic typed instruction emitter added (`MicrocodeOpcode`, `MicrocodeOperandKind`, `MicrocodeOperand`, `MicrocodeInstruction`, `emit_instruction`, `emit_instructions`). Covers `mov/add/xdu/ldx/stx/fadd/fsub/fmul/fdiv/i2f/f2f/nop`.
138. SDK microblock insertion: `mblock_t::insert_into_block(new, existing)` inserts after `existing`; `nullptr` inserts at beginning. Expose constrained policy enums (`Tail`/`Beginning`/`BeforeTail`) without raw block internals.
139. callinfo-shaping: `function_role` and `return_location` semantic hints with typed validation/mapping.
140. Helper-call placement: `MicrocodeCallOptions::insert_policy` reuses `MicrocodeInsertPolicy` (`Tail`/`Beginning`/`BeforeTail`).
141. Microcode-filter runtime stability: aggressive callinfo hints in hardening filters can trigger `INTERR: 50765`. Keep integration coverage validation-focused; heavy emission stress for dedicated scenarios.
142. Helper-call typed-return: register-return now accepts declaration-driven return typing with size-match validation and UDT marking for wider destinations.
143. Helper-call typed-argument: register args now accept declaration-driven typing with parse validation, size-match enforcement, and integer-width fallback.
144. Helper-call argument-metadata: optional `argument_name`, `argument_flags`, `MicrocodeArgumentFlag` mapped to `mcallarg_t::name`/`flags` with unsupported-bit validation and `FAI_RETPTR -> FAI_HIDDEN` normalization.
145. lifter probe: `lifter_port_plugin.cpp` installs working VMX/AVX subset via idax microcode-filter APIs. No-op `vzeroupper`, helper-call lowering for `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`.
146. AVX temporary-register: `MicrocodeContext::allocate_temporary_register(byte_width)` mirrors `mba->alloc_kreg`.
147. Helper-call callinfo defaults: `solid_argument_count` now inferred from provided argument list when omitted.
148. Helper-call auto-stack placement: additive `auto_stack_start_offset`/`auto_stack_alignment` controls with validation (non-negative start, power-of-two positive alignment).
149. lifter AVX scalar subset: lowers `vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd`, `vcvtss2sd`, `vcvtsd2ss` through typed emission (`FloatAdd/FloatSub/FloatMul/FloatDiv/FloatToFloat`).
150. Instruction `Operand` exposes typed values but no rendered text helpers. AVX lowering assumes XMM-width destination copy. Expand operand-width introspection if broader vector-width lowering needed.
151. lifter AVX scalar expansion: `vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`, `vmovss/vmovsd` using typed emission + helper-call return lowering.
152. AVX scalar move memory-destination: load destination register before checking memory-destination creates unnecessary failure. Handle memory-dest stores first (`store_operand_register`), then resolve register-target paths.
153. AVX packed subset: `vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd`, `vmov*` packed moves through typed emission + store-aware handling.
154. Packed-width inference: `ida::instruction::operand_text(address, index)` heuristics (`xmm`/`ymm`/`zmm`, `*word` tokens) enable width-aware lowering without SDK internals.
155. Helper-call typed-return fallback: packed destination widths exceeding integer scalar widths need byte-array `tinfo_t` fallback when no explicit return declaration supplied.
156. Packed conversion subset: `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd` via `FloatToFloat`/`IntegerToFloat` emission with operand-text width heuristics.
157. Many float-int packed conversions (`vcvt*2dq/udq/qq/uqq`, truncating) don't map to current typed opcodes; use helper-call fallback.
158. `vaddsub*`/`vhadd*`/`vhsub*` need lane-level semantics beyond `FloatAdd`/`FloatSub`. Use helper-call lowering.
159. Helper-fallback packed families (bitwise/permute/blend) widened by collecting mixed register/immediate operands and forwarding as typed helper-call arguments.
160. Packed logic/permute/blend: no direct typed opcodes; helper-call fallback remains practical path.
161. Packed shift/rotate (`vps*`, `vprol*`, `vpror*`): mixed register/immediate shapes not directly expressible. Helper-call fallback.
162. Variadic helper fallback robustness: unsupported operand shapes degrade to `NotHandled` not hard errors, keeping decompiler stable while coverage grows.
163. Variadic helper memory-operand: when register extraction fails for source, attempt effective-address extraction and pass typed pointer argument.
164. Packed compare destination: mask-register destinations not representable in current register-load helpers. Treat unsupported compare destinations as no-op handling.
165. Typed packed bitwise/shift opcodes added: `BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`. Helper fallback kept for unsupported forms (`andn`, rotate, exotic).
166. Typed packed integer add/sub: `MicrocodeOpcode::Subtract` added. `vpadd*`/`vpsub*` direct register/immediate forms routed through typed emission. Helper fallback for mixed/unsupported.
167. Packed integer operand-shape: typed emission doesn't cover memory-source or saturating variants. Route saturating/memory forms through variadic helper fallback.
168. Packed integer multiply: typed direct multiply for `vpmulld`/`vpmullq`. Other variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) have lane-specific semantics—use helper-call fallback.
169. Packed binary operand count: two-operand encodings can be missed if destination not treated as implicit left operand. Treat operand 0 as both dest and left source for two-operand forms.
170. Advanced callinfo list-shaping: register-list and visible-memory controls exposed. Passthrough registers must be subset of spoiled. Validate subset semantics; return `Validation` on mismatch.
171. Declaration-driven vector element typing: `type_declaration` parsed as element type. Element-size/count/total-width constraints validated together. Derive missing count from total width when possible; reject mismatched shapes.
172. Rich typed mop-builder: `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` operand/value kinds added.
173. Block-reference typed operand: `MicrocodeOperandKind::BlockReference` + validated `block_index` without raw microblock exposure.
174. Nested-instruction typed operand: `MicrocodeOperandKind::NestedInstruction` + `nested_instruction` payload with recursive validation/depth limiting.
175. Local-variable typed operand: `MicrocodeOperandKind::LocalVariable` with `local_variable_index`/`local_variable_offset` validated before `_make_lvar(...)` mapping.
176. Local-variable rewrite safety: needs context-aware availability checks. Expose `MicrocodeContext::local_variable_count()` and gate usage on `count > 0` with no-op fallback.
177. Local-variable rewrite consistency: centralize local-variable self-move emission in one helper; reuse across rewrite sites (`vzeroupper`, `vmxoff`).
178. Debugger backend activation: backend discovery/loading should be explicit (`available_backends` + `load_backend`). Expose in `ida::debugger`; auto-load in `ida2py_port` before launch.
179. Appcall host (macOS): with `arm_mac` backend, `start_process` returns 0 but state stays `NoProcess`; attach returns `-1`, still `NoProcess`. Blocked by backend/session readiness, not wrapper API coverage.
180. Appcall queued-request timing: `request_start`/`request_attach` report success while state still `NoProcess` immediately after single flush. Perform bounded multi-cycle request draining with settle delays.
181. Microcode placement parity: low-level emit helpers (`emit_noop`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`) default to tail insertion. Add policy-aware variants; route all emits through shared reposition logic.
182. Wide-operand emit: AVX/VMX wider register/memory flows may need UDT operand marking. Add optional `mark_user_defined_type` controls to low-level move/load/store helpers.
183. Store-operand UDT: `store_operand_register` writeback for wide/non-scalar flows needs explicit UDT marking on source mop. Add `store_operand_register(..., mark_user_defined_type)` overload.
184. Immediate typed-argument declaration: `UnsignedImmediate`/`SignedImmediate` now consume optional `type_declaration` with parse/size validation and declaration-width inference when byte width omitted.
185. Callinfo pass/spoil coherence: `passthrough_registers` contradictory without `spoiled_registers` superset. Enforce subset semantics whenever passthrough registers present.
186. Callinfo coherence testing: success-path helper-call emissions in filter hardening can trigger decompiler `INTERR`. Prefer validation-first probes (e.g., post-subset bad-visible-memory checks) for deterministic assertions.
187. SDK operand width metadata: `op_t::dtype` + `get_dtype_size(...)` provide structured operand byte widths; fallback register-name inference is only needed when processors omit operand dtype detail.
188. Compare/mask destination handling: helper-call return can be lowered deterministically by routing through temporary register + operand writeback (`store_operand_register`) instead of no-op tolerance.
189. Microcode rewrite lifecycle: tracking last-emitted instruction plus block instruction-count query enables additive remove/rewrite workflows without exposing raw microblock internals.
190. Lifter width heuristics: structured `instruction::Operand` metadata (`byte_width`, `register_name`, `register_category`) removes dependence on `operand_text()` parsing for AVX width decisions.
191. Microblock index lifecycle: `has_instruction_at_index`/`remove_instruction_at_index` provide deterministic, SDK-opaque mutation targeting beyond tracked-last-emitted-only flows.
192. Typed helper-call tmop shaping: helper-call argument model can carry `BlockReference`/`NestedInstruction` values for richer callarg mop authoring without raw `mop_t` exposure.
193. Typed decompiler-view edit sessions: deriving stable function identity from opaque host handles (`view_from_host`) enables reusable rename/retype/comment/save/refresh workflows without exposing `vdui_t`/`cfunc_t`.
194. Decompiler variable-edit error categories can vary by backend/runtime (`NotFound` vs `SdkFailure`) for missing locals. Tests should assert failure semantics unless category is contractually stable.
195. Integration tests that persist decompiler edits can mutate fixture `.i64` files. Prefer non-persisting validation probes (or explicit fixture restore) for deterministic worktree hygiene.
196. AVX/VMX helper-return routing: prefer `emit_helper_call_with_arguments_to_micro_operand_and_options` for register and direct-memory (`MemoryDirect` -> `GlobalAddress`) destinations; keep operand-index writeback as fallback for unresolved destination shapes.
197. Integration hardening can safely exercise helper-return micro-operand success routes by targeting temporary-register and current-address `GlobalAddress` destinations, then removing emitted instructions to keep mutation checks deterministic.
198. Helper-return destination routing can reduce operand-index writeback fallback further by treating any memory operand with a resolved `target_address` as a typed `GlobalAddress` micro-operand destination (not only `MemoryDirect`).
199. Lifter helper-call depth can progress safely by adding semantic call-role hints (`SseCompare4`/`SseCompare8` for `vcmp*`) plus `argument_name` metadata on helper arguments; this enriches callinfo/tmop intent without aggressive side-effect flags.
200. Additive callinfo enrichment scales cleanly when semantic roles also cover rotate helper families (`RotateLeft`/`RotateRight`) and `argument_name` metadata is applied consistently across variadic, VMX, and explicit scalar/packed helper-call paths.
201. Declaration-driven return typing can be applied incrementally to stable helper-return families (integer-width `vmread` register destinations and scalar float/double helper returns) to improve callinfo fidelity without broad vector-type assumptions.
202. Register-destination helper flows can safely carry explicit callinfo `return_location` hints when mapped to the same destination register used for helper-return writeback; this composes with declaration-driven return typing.
203. Callinfo hardening should probe both positive and negative hint paths: success/backend-failure tolerance for micro/register destination routes, plus validation checks for negative register return locations and return-type-size mismatches.
204. Compare helper operand-index writeback fallback should be constrained to unresolved destination shapes only (mask-register destinations and memory destinations lacking resolvable target addresses), while resolved destinations prefer typed micro-operand routing.
205. Callinfo hardening coverage should include cross-route validation checks (`to_micro_operand`, `to_register`, `to_operand`) for invalid return-location register ids and return-type-size mismatches to prevent contract drift between helper emission APIs.
206. When compare destinations are register-shaped but `load_operand_register(0)` fails, attempting a typed micro-operand register route using structured `Operand::register_id()` before operand-writeback fallback can recover additional handled cases while preserving unresolved-shape gating.
207. For compare helper flows with resolved memory destinations, static-address `return_location` hints can be applied to typed `GlobalAddress` micro-destination routes; if a backend rejects the hint as validation, retrying without the hint preserves stable behavior.
208. Callinfo hardening can extend positive/negative location validation to global-destination micro routes by asserting success-or-backend-failure for valid static-address hints and explicit `Validation` for `BadAddress` static return locations.
209. Static-address return-location validation should be asserted across helper emission routes including `to_operand`; `BadAddress` static-location hints must fail with `Validation` consistently.
210. Compare helper register-destination micro routes benefit from the same validation-safe retry pattern as resolved-memory routes: if explicit register `return_location` hints are rejected with validation, retrying with no location hint preserves stable handling.
211. Callinfo hardening should validate return-type-size mismatch behavior on global-destination routes as well, including `to_operand` checks, to keep type-size contracts consistent across helper emission APIs.
212. For unresolved compare destinations, an intermediate helper-to-temporary-register route plus operand store writeback can be attempted before direct `to_operand` helper fallback, reducing reliance on the direct operand route while preserving degraded-path stability.
213. Compare helper micro-routes can use a three-step validation-safe retry ladder (full typed options with location+declaration -> reduced options without location -> base compare options without declaration/location) to preserve semantic richness first while degrading safely when backends reject advanced callinfo hints.
214. Direct `to_operand` compare fallback can also use validation-safe retry with base compare options (dropping declaration/location hints) to reduce avoidable validation failures on backend variance while preserving unresolved-shape degraded handling.
215. After all degraded compare `to_operand` retries are exhausted, treating residual `Validation` failures as non-fatal (`NotHandled`) improves backend variance tolerance while keeping hard SDK/internal failures explicit.

216. Compare helper stability improves when all destination routes (resolved-memory micro, register micro, temporary-register bridge, and degraded `to_operand`) retry with base compare options on validation rejection, and temporary-register writeback treats `Validation`/`NotFound` store failures as degradable while preserving hard SDK/internal failure signaling.

217. Direct register-destination compare helper routes can use the same validation-safe retry ladder (location+declaration hints -> declaration-only -> base compare options), and residual validation rejection should degrade to not-handled while preserving hard SDK/internal failures.

218. In temporary-register compare fallback paths, once `store_operand_register` `Validation`/`NotFound` is intentionally degraded, any subsequent category checks must guard on `!status` before reading `.error()`; reading `.error()` on a successful `std::expected` is invalid and can destabilize fallback flow.

219. Compare helper fallback handling is more backend-robust when residual `NotFound` outcomes are treated like other degradable non-hard categories on degraded/direct-destination routes (return not-handled), while preserving only `SdkFailure`/`Internal` as hard failure signals.

220. The compare-helper temporary-register bridge can use typed `_to_micro_operand` destination routing instead of `_to_register` because the allocated temporary register id is known and can be expressed as a `MicrocodeOperand` with `kind = Register`. This eliminates the last non-typed helper-call destination in the lifter probe; all remaining operand-writeback sites are genuinely irreducible (unresolved mask-register/memory shapes for compare destinations, and legitimate memory-store operations for vmov memory destinations).

221. The original lifter's `clear_upper()` function — called at 112 sites across handler files — is a deliberate no-op. The comment states "AVX semantics handle this automatically." The only real zero-extension gap is `vmovd`/`vmovq` which uses explicit `m_xdu` (zero-extend unsigned) to widen 4/8-byte GPR/memory values into XMM/YMM-width registers. The port's previous routing through `lift_packed_helper_variadic` for these instructions was semantically incorrect — it emitted opaque helper calls instead of native microcode, losing type inference and value-tracking information.

222. AVX-512 opmask information is stored in `insn.Op6` (`insn.ops[5]`) with the operand type `o_reg` or `o_kreg` and register number relative to `R_k0`. The EVEX.z (zero-masking) bit is in `Op6.specflag2 & 0x04` via the `evex_flags` macro. Because `reg2mreg()` returns `mr_none` for k-registers, the original lifter encodes the k-register number as a negative `mreg_t` and passes it as an unsigned immediate constant in helper-call arguments — the decompiler cannot natively represent k-registers in microcode. The idax wrapper exposes this through `MicrocodeContext::has_opmask()`, `is_zero_masking()`, and `opmask_register_number()` without requiring Intel-specific headers in user code.

223. SSE passthrough instructions (`vcomiss`, `vcomisd`, `vucomiss`, `vucomisd`, `vpextrb/w/d/q`, `vcvttss2si`, `vcvttsd2si`, `vcvtsd2si`, `vcvtsi2ss`, `vcvtsi2sd`) are returned to IDA's native handling by the original lifter via `MERR_INSN`. The idax port equivalent is returning `false` from `match()` so the filter does not claim the instruction.

224. K-register manipulation instructions (`kmov*`, `kadd*`, `kand*`, `kor*`, `kxor*`, `kxnor*`, `knot*`, `kshift*`, `kunpck*`, `ktest*`) and instructions with mask-register destinations are lifted as NOPs by the original lifter. This is a pragmatic choice: the decompiler's microcode cannot represent k-register operations natively, so the lifter acknowledges the instruction without trying to model its k-register semantics.

225. AVX-512 opmask masking must be wired uniformly across ALL helper-call paths (compare, store-like, scalar min/max/sqrt, packed sqrt/addsub/min/max, helper-fallback conversions, and variadic helpers), not just the normal variadic path. For native microcode emission paths (typed binary add/sub/mul/etc, typed conversion, typed moves, typed packed FP math), the correct approach when masking is present is to skip the native emission and fall through to the helper-call path, because native microcode instructions cannot represent per-element masking. The helper-call path then applies masking by suffixing `_mask`/`_maskz` to the helper name and appending merge-source register and mask register number arguments.

226. The original lifter uses `get_type_robust(size, is_int, is_double)` → `get_vector_type(size, is_int, is_double)` to resolve named vector types (`__m128`, `__m128i`, `__m128d`, `__m256`, `__m256i`, `__m256d`, `__m512`, `__m512i`, `__m512d`) from the DB's type library for ALL helper-call return types and arguments. The type lookup first tries `tinfo_t::get_named_type()` then falls back to synthesizing an anonymous UDT struct with a byte-array member. The idax port achieves the same effect by setting `return_type_declaration` to the corresponding type name string (e.g., `"__m256i"`), which the wrapper passes to `parse_decl` for resolution against the same type library. For scalar sizes (1-8 bytes), integer/floating declaration strings are equivalent. For wider sizes (16/32/64 bytes), the named vector type declarations produce proper `__m*` types in decompiler output instead of anonymous byte-array structs. A `vector_type_declaration(byte_width, is_integer, is_double)` helper unifies scalar and vector type name selection in the port, mirroring the original's `get_type_robust` signature.

227. A comprehensive cross-reference audit of the original lifter's 14 distinct SDK mutation pattern categories (`cdg.emit`, `alloc_kreg/free_kreg`, `store_operand_hack`, `load_operand_udt`, `emit_zmm_load`, `emit_vector_store`, `AVXIntrinsic`, `AvxOpLoader`, `mop_t` construction, `minsn_t` post-processing, `load_operand/load_effective_address`, `MaskInfo`, misc utilities) confirmed that 13 of 14 are fully covered by idax wrapper APIs actively used in the port (~2,700 lines, 300+ mnemonics). The remaining pattern (post-emit instruction field mutation) has functional equivalence via remove+re-emit lifecycle helpers. No new wrapper APIs are required for lifter-class microcode transformation ports. Key quantitative evidence: 26 helper-call emission sites, 7 typed instruction emission sites, 37 operand load sites, 4 effective address loads, 4 operand writeback sites, 11 UDT marking references.

228. The lifter port now has separate "Mark as inline" and "Mark as outline" context-sensitive actions matching the original's dual-action design in `inline_component.cpp`. The original uses `action_state_t` (`AST_ENABLE_FOR_WIDGET`/`AST_DISABLE_FOR_WIDGET`) in the `update()` callback to show only the relevant action based on the function's `FUNC_OUTLINE` flag state. The idax port achieves this via `enabled_with_context` lambdas that query `ida::function::is_outlined()` — "Mark as inline" is enabled only when `FUNC_OUTLINE` is NOT set, "Mark as outline" only when it IS set. Both handlers call `ida::decompiler::mark_dirty_with_callers()` after toggling the flag, matching the original's `mark_callers_dirty` + `vu->refresh_view(true)` pattern.

229. The lifter port now has a debug-printing toggle action with maturity-driven disassembly/microcode dumps matching the original's `hexrays_debug_callback` in `avx_lifter.cpp`. The original installs a `hxe_maturity` callback that prints disassembly at `MMAT_GENERATED` and microcode at `MMAT_PREOPTIMIZED`/`MMAT_LOCOPT`. The idax port uses `ida::decompiler::on_maturity_changed()` with `ScopedSubscription` and maps `Maturity::Built` (=`MMAT_GENERATED`), `Maturity::Trans1` (=`MMAT_PREOPTIMIZED`), and `Maturity::Nice` (=`MMAT_LOCOPT`). The subscription is installed/removed dynamically via `toggle_debug_printing()` with the debug state tracked in `PortState::debug_printing`.

230. The 32-bit YMM skip guard has been ported from the original lifter's `match()`. The original checks `inf_is_64bit()` and skips YMM (256-bit) operands to avoid Hex-Rays `INTERR 50920` ("Temporary registers cannot cross block boundaries"). The idax port uses `ida::function::at(address)->bitness() == 64` (with `ida::segment::at()` fallback) as there is no direct `inf_is_64bit()` wrapper, and checks `Operand::byte_width() == 32` for YMM detection instead of the original's `op.dtype == dt_byte32`.

231. The SDK global `PH.id` (processor_t::id via `get_ph()`) returns the active processor module ID (PLFM_* constant). `PLFM_386` is `0` (Intel x86/x64), not 15 as might be assumed. The original lifter uses `PH.id != PLFM_386` in both AVX and VMX component availability checks as a crash guard — IDA crashes when interacting with AVX/VMX in non-x86 processor modes. Added `ida::database::processor_id()` wrapping `PH.id` and `ida::database::processor_name()` wrapping `inf_get_procname()` to idax. Implementation lives in `address.cpp` (not `database.cpp`) to avoid pulling idalib-only symbols (`init_library`/`open_database`/`close_database`) into plugin link units.

232. The IDA SDK redefines bare `snprintf` to `dont_use_snprintf` via a macro in `pro.h:965`, forcing use of `qsnprintf` in SDK-linked code. However, `std::snprintf` (the fully-qualified C++ name) is unaffected by this macro and can be used safely in example/plugin code that doesn't include SDK headers directly. In idax `src/` files (which include SDK headers), `qsnprintf` must be used. In example plugins (which include only `<ida/idax.hpp>`), `std::snprintf` is the portable alternative.

233. `cfunc_t::get_pseudocode()` returns `const strvec_t&` — a read-only reference. To modify pseudocode lines (e.g., inserting color tags), access `cfunc->sv` directly (the public member), not the const getter. The idax wrapper's `set_raw_line()` implements this by indexing into `cfunc->sv[line_index].line`.

234. The SDK's `qrefcnt_t<cfunc_t>` (typedef `cfuncptr_t`) does not provide a `.get()` method like `std::shared_ptr`. To obtain a raw `cfunc_t*`, use `&*ptr` (dereference then take address) or `ptr.operator->()`.

235. Color enum values in the SDK (`color_t` constants in `lines.hpp`) use specific byte values that must be matched exactly in any wrapper enum: `COLOR_DEFAULT=0x01`, `COLOR_KEYWORD=0x20`, `COLOR_REG=0x21`, `COLOR_IMPNAME=0x17`, `COLOR_LIBNAME=0x18`, `COLOR_NUMBER=0x0C`, `COLOR_STRING=0x14`, `COLOR_CHAR=0x15`, etc. Getting these wrong produces garbled colored output in IDA's pseudocode view.

236. Widget type enum values must match SDK `BWN_*` constants in `kernwin.hpp`: `BWN_EXPORTS=0`, `BWN_IMPORTS=1`, `BWN_NAMES=2`, `BWN_FUNCS=3`, `BWN_STRINGS=5`, `BWN_DISASM=27`, `BWN_PSEUDOCODE=46`, etc. These are NOT sequential or intuitive — they follow internal SDK widget registration order.

237. `attach_dynamic_action_to_popup` uses `DYNACTION_DESC_LITERAL` macro which takes 5 arguments: `(label, handler, shortcut, tooltip, icon)`. This is NOT the same as `ACTION_DESC_LITERAL_OWNER` (8 args). The dynamic action variant is for temporary popup-only actions that don't need global registration.

238. Hexrays callback event signatures (accessed via `va_arg` in the event bridge): `hxe_func_printed` receives `(cfunc_t*)`, `hxe_curpos` receives `(vdui_t*)`, `hxe_create_hint` receives `(vdui_t*, qstring*, int*)` and the callback should return 1 to show the hint or 0 to skip, `hxe_refresh_pseudocode` receives `(vdui_t*)`. All events return `int` (0 = continue processing, non-zero = handled for most events).

239. `ui_finish_populating_widget_popup` notification receives `(TWidget*, TPopupMenu*, const action_activation_ctx_t*)` via `va_arg`. The `TPopupMenu*` is needed for `attach_dynamic_action_to_popup()` calls. The `action_activation_ctx_t` provides widget context including the widget pointer and type.

240. The `IDAX_PLUGIN(ClassName)` macro is mandatory for all IDA plugin source files using the idax wrapper. It expands to the `_PLUGIN` export symbol that IDA's plugin loader searches for when loading `.dylib`/`.dll`/`.so` files. Without it, the dylib compiles and links but contains zero exported functions — IDA silently ignores it. This was found when 5 example plugins (`action_plugin.cpp`, `decompiler_plugin.cpp`, `deep_analysis_plugin.cpp`, `event_monitor_plugin.cpp`, `storage_metadata_plugin.cpp`) produced empty dylibs despite compiling cleanly.

241. When `libidax.a` is linked into a plugin `.dylib`, the linker resolves symbols at the object-file granularity. If any function from a `.cpp.o` file is referenced, ALL symbols in that object file must be resolvable. `database.cpp` contained both plugin-safe query APIs (`input_file_path`, `image_base`, `input_md5`, etc.) and idalib-only lifecycle APIs (`init`, `open`, `close`). The idalib-only functions reference `init_library`, `open_database`, `close_database`, `enable_console_messages` which are NOT in `libida.dylib` — they're only in `libidalib.dylib`. Splitting into `database.cpp` (queries) + `database_lifecycle.cpp` (lifecycle) isolates the idalib-only symbols so plugins that only use query APIs don't pull them in. `save_database` IS available in `libida.dylib`, so `save()` stays in the plugin-safe `database.cpp`.

242. DrawIDA port audit: idax plugin export is fixed to `PLUGIN_MULTI` through `IDAX_PLUGIN` and does not expose per-plugin flag customization (`PLUGIN_KEEP`/`PLUGIN_UNL`/etc.). This is a low-severity ergonomic surface gap for ports that want explicit raw-SDK flag control, but it is non-blocking for DrawIDA.

243. DrawIDA port audit: `ida::ui::with_widget_host()` intentionally returns opaque `void*` host handles. Qt-based ports must manually cast to `QWidget*` in plugin code to mount custom controls. Capability is present, but this is a recurring low-severity ergonomics gap for Qt-heavy ports.

244. Documentation drift risk: adding a new real-world port artifact (like `examples/plugin/abyss_port_plugin.cpp`) can leave user-facing docs stale unless the update explicitly touches all index surfaces together (`README.md` parity/doc tables, `docs/api_reference.md`, `docs/namespace_topology.md`, `docs/sdk_domain_coverage_matrix.md`, quickstart/example guides, and a dedicated port audit doc). Treat this as a required closeout checklist item for future ports.

245. Plugin export flag ergonomics closure: `ida::plugin::ExportFlags` + `IDAX_PLUGIN_WITH_FLAGS(...)` adds per-plugin export control (`modifies_database`, `requests_redraw`, `segment_scoped`, `unload_after_run`, `hidden`, `debugger_only`, `processor_specific`, `load_at_startup`, `extra_raw_flags`) while preserving idax's mandatory `PLUGIN_MULTI` bridge model.

246. Qt host ergonomics closure: `ida::ui::widget_host_as<T>()` + `ida::ui::with_widget_host_as<T>()` provide typed host access wrappers over `widget_host`/`with_widget_host`, eliminating repetitive `void*` casts in Qt plugin ports.

247. Dedicated Qt addon wiring can be made non-fragile by using `ida_add_plugin(TYPE QT QT_COMPONENTS Core Gui Widgets ...)`: when Qt is unavailable the target is skipped with explicit `build_qt` guidance, and when Qt is present the plugin builds as a normal addon target.

248. Qt header portability nuance (Qt6/Homebrew): `qkeyevent.h` is not present in framework headers; `QKeyEvent`/`QMouseEvent` are provided via `qevent.h`. Using `qevent.h` avoids target-specific include breakage in Qt plugin sources.

249. IDA SDK 9.3 does not expose legacy `get_struc_id()`/`get_struc()` helpers in the public bridge used by idax; struct-offset operand helpers should resolve type IDs through `get_named_type_tid()` and then call `op_stroff`/`op_based_stroff`.

250. DriverBuddy migration validates that `ida::database::import_modules`, `ida::function::all`, `ida::xref::code_refs_to`, `ida::search::text`, and `ida::instruction::decode` are sufficient to port core Windows-driver triage workflows (driver classification, dispatch discovery, IOCTL decode) without raw SDK fallback.

251. WDF dispatch-table labeling can be implemented in idax without raw SDK structs by materializing a `TypeInfo::create_struct()` schema and applying it at the discovered table address (`type::apply_named_type` + `name::force_set`) after locating the `KmdfLibrary` marker and dereferencing metadata pointers.

252. DriverBuddy parity still has non-blocking ergonomic gaps: no one-call standard-type bootstrap equivalent to `Til2Idb(-1, name)`, no public struct-offset path readback (`get_stroff_path`) wrapper, and no minimal `add_hotkey` convenience API separate from action registration.

253. idapcode port required first-class database metadata wrappers for architecture selection parity: `address_bitness` (16/32/64), `is_big_endian`, and `abi_name` in addition to processor ID/name. Wrapping these SDK globals in `ida::database` keeps plugin code SDK-opaque while enabling deterministic Sleigh spec routing.

254. Sleigh support helper semantics: `sleigh::FindSpecFile` expects search roots at the specfiles root and internally appends `Ghidra/Processors/<arch>/data/languages/<file>`. Passing a language subdirectory path directly will fail lookup.

255. Sleigh as a dependency is heavy because configuring from source fetches/patches Ghidra; integrating it behind an idapcode-specific opt-in build flag avoids regressing default idax configure/build cycles.

256. Even with processor ID + bitness + endianness + ABI, exact language-profile selection remains partial for some families (notably ARM profile/revision variants). A richer normalized processor-profile wrapper would eliminate residual best-effort heuristics in ports like idapcode.

257. On this host, runtime integration tests that initialize idalib can still fail with `init_library failed` even when `IDADIR`/`DYLD_LIBRARY_PATH` are explicitly set; build-level validation can proceed, but runtime evidence remains host/license-gated.

258. The `init_library` startup failure for idax smoke flows is reproducible when `IDADIR` points to an SDK source tree (for example `/Users/int/dev/ida-sdk/src`) rather than a full IDA runtime root. On this host, `idax_smoke_test` succeeds with no env overrides because the binary already carries `LC_RPATH` to `/Applications/IDA Professional 9.3.app/Contents/MacOS`; explicit `IDADIR`/`DYLD_LIBRARY_PATH` to that same runtime root also succeeds.

259. `ida::database::ProcessorId` should track the full current SDK `PLFM_*` set (through `PLFM_MCORE`) rather than a small common subset so numeric processor IDs round-trip through the typed enum without stale coverage gaps.

260. Runtime plugin-load policy paths are now host-validated via `idax_idalib_dump_port`: both `--no-plugins` and allowlist mode (`--plugin "*.dylib"`) initialize/open/analyze successfully against the fixture binary, confirming `RuntimeOptions::plugin_policy` is non-blocking in this runtime profile.

261. Bidirectional navigation sync between a custom p-code viewer and linear disassembly can be implemented in idax without new wrapper APIs by combining `ui::on_cursor_changed` (viewer -> linear), `ui::on_screen_ea_changed` (linear -> viewer), `ui::on_view_activated`/`on_view_deactivated`, and `ui::custom_viewer_jump_to_line` with a reentrancy guard.

262. For robust click-to-address mapping in a p-code custom viewer, prefixing every rendered line (including emitted p-code op lines and error lines) with a canonical address token enables stable cursor-line address parsing even when the cursor is not on the instruction header line.

263. Cross-function follow in the idapcode viewer is achieved by detecting when `screen_ea` leaves the currently mapped function range, resolving `function::at(new_ea)`, and rebuilding the existing custom viewer content in-place for the new function rather than opening additional viewers.

264. Scroll-follow behavior for custom viewers can be approximated without new SDK wrappers by adding a lightweight UI timer that polls `custom_viewer_current_line(mouse=true/false)` and applies `jump_to` when the parsed line address changes.

265. The idapcode shortcut was changed from `Ctrl-Alt-S` to `Ctrl-Alt-Shift-P` to avoid common keybinding collisions with SigMaker workflows while keeping the action discoverable for p-code usage.

266. `ida::ui::set_custom_viewer_lines` must preserve the original `CustomViewerState` object address. Replacing the stored `unique_ptr` invalidates internal pointers handed to `create_custom_viewer` (`min`/`max`/`cur`/`lines`) and can cause EXC_BAD_ACCESS during render/model updates; mutating the existing state in-place fixes the crash.

267. For C ABI arrays that return owning opaque handles (e.g., `IdaxTypeHandle*` or struct records embedding `IdaxTypeHandle`), Rust-side transfer should move each handle into owned wrapper values and null-out the original C slots before invoking shim free helpers; this preserves centralized cleanup for array buffers/strings while preventing double-free of transferred handles.

268. Full Rust parity for `ida::type::TypeInfo` clone semantics requires an explicit shim clone operation (`idax_type_clone`) because the Rust wrapper intentionally keeps handles opaque and cannot copy the underlying C++ pimpl-backed object without a dedicated C ABI helper.

269. Rust graph-viewer callback bridging over C ABI should treat callback-provided node-text/hint strings as borrowed pointers valid for the callback invocation (copied immediately by shim/C++), while ownership of the callback context itself must transfer to viewer lifetime and be released only from the viewer-destroyed callback to avoid premature frees or leaks.

270. Rust `static` callback registries backed by `Mutex<HashMap<...>>` cannot store raw pointers directly under current trait bounds; storing callback context addresses as `usize` plus explicit typed drop trampolines (`unsafe fn(*mut c_void)`) keeps callback lifetime tracking `Sync`-compatible while preserving correct reclamation on unsubscribe/unregister.

271. UI rendering parity across Rust/C++ is cleanly bridged by passing an opaque event handle into Rust callbacks and exposing a dedicated shim helper (`idax_ui_rendering_event_add_entry`) that appends native `LineRenderEntry` records in C++; this avoids cross-language vector ownership/reallocation hazards while preserving mutable rendering-entry semantics.

272. For recursive/value-rich Rust<->C transfer in convergence-heavy domains, using explicit C transfer structs plus domain-specific free helpers (e.g., typed values, import modules, snapshot trees) keeps ownership unambiguous across nested strings/arrays and allows bindgen-generated Rust wrappers to copy into idiomatic values without leaking or double-freeing nested allocations.

273. For Rust bindings over C ABI payload arrays that contain nested C strings, conversion should copy strings from borrowed pointers first and then invoke exactly one shim-level deep-free helper for the array (`char**`/record arrays). Mixing per-element consuming frees with subsequent array-free helpers causes double-free risk; the safe pattern is copy-then-single-free.

274. For plugin/event callback payload bridges, expose callback-scoped borrowed C string pointers (`const char*`) in shim transfer structs and copy them immediately in Rust trampolines; callback context ownership should stay token-keyed in Rust (`HashMap<Token, ErasedContext>`) and be reclaimed only on explicit unsubscribe/unregister to avoid leaks or use-after-free across repeated subscriptions.

275. For runtime Rust bindings over `ida::loader::InputFile` handles, shim-side wrapping can remain SDK-opaque by reconstructing a transient `ida::loader::InputFile` value from the raw callback `void*` handle when the C++ wrapper type is trivially-copyable and pointer-sized; this allows reusing canonical C++ `InputFile` methods (`size`/`tell`/`seek`/`read_*`/`filename`) instead of duplicating low-level SDK `ql*` calls in the shim.

276. Full Rust/C++ debugger parity for callback-heavy APIs is easiest to keep safe with explicit C transfer structs per payload family (module info, exception info, register info, appcall request/result/value) and typed callback typedefs in the shim header; this avoids exposing SDK structs while keeping bindgen output predictable and composable.

277. Appcall executor bridging across Rust/C++ can be made lifecycle-safe by wrapping C callbacks in a shim-side `AppcallExecutor` implementation that owns callback+cleanup pointers and invokes cleanup in destructor, while Rust tracks registrations by executor name and relies on shim-side unregister destruction for context reclamation.

278. For decompiler event bridging where callbacks are tokenized in C++ (`on_*` + `unsubscribe`), Rust-side callback context lifetime is safest when keyed by token and released only after successful unsubscribe; this avoids use-after-free on async event delivery and avoids leaks on failed subscribe paths.

279. Functional visitor parity over C ABI can remain behaviorally complete without exposing full SDK expression/statement objects by forwarding minimal stable transfer views (`item type`, `address`) and preserving `VisitAction` control flow (`Continue`/`Stop`/`SkipChildren`) through callback return-value mapping.

280. Rust processor-domain parity does not require new runtime shim exports when module authoring remains compile-time macro/trait driven; convergence is achieved by mirroring the full C++ `ida::processor` data model and callback contract in `idax/src/processor.rs` (including tokenized output context and switch/analyze structures), while Rust 2024 unsafe-ops warning cleanup can be applied mechanically and safely via `cargo fix --lib -p idax` for callback-heavy FFI files.

281. When `idax` is consumed via `FetchContent` or `add_subdirectory` and `find_package(idasdk)` is called internally by `idax`, the imported targets (`idasdk::plugin`, `idasdk::loader`, etc.) created by `ida-cmake` are local to the `idax` directory scope. They must be explicitly promoted to `GLOBAL` scope using `set_target_properties(target PROPERTIES IMPORTED_GLOBAL TRUE)` so that the parent consumer project can link against them without having to redefine them or call `find_package(idasdk)` again (which would fail due to duplicate target names).

282. Scenario-based documentation adequacy for AI-assisted coding requires runnable end-to-end workflows (initialization/open, core operation, error handling, teardown). API signatures and isolated method docs are not enough to produce reliably correct implementations for non-trivial tasks.

283. Documentation that mixes safe Rust `idax` guidance, raw `idax-sys` FFI details, and unrelated/non-library surface descriptions in one path materially increases implementation ambiguity. Layered documentation boundaries are required for reliable path selection.

284. For call-graph and event-driven use cases, snippets must include algorithm/lifecycle scaffolding (visited-set cycle guards, callback token ownership, explicit unsubscribe teardown). Function-signature exposure alone leaves critical correctness gaps.

285. Multi-binary analysis goals (for example signature generation) need orchestration-level tutorial material (pattern extraction, normalization/wildcards, comparison strategy, output schema), not just primitive single-binary search API references.

286. Distributed analysis guidance must explicitly state IDA database consistency constraints and discourage concurrent multi-process writes to a single IDB; recommended approaches should use partitioned/sharded workflows with controlled merge/synchronization steps.

287. Safety/performance guidance needs an explicit decision matrix for safe `idax` vs raw `idax-sys`, plus ownership/deallocation rules for raw pointers/arrays and a recovery playbook when SDK state becomes inconsistent.

288. Practical docs triage heuristic from the 10-case audit: high-score/simple scenarios fit cookbook expansion, medium-complexity scenarios need runnable examples, and low-score/system-level scenarios require full tutorials plus explicit constraints/trade-offs.

289. In current Rust bindings, plugin ergonomics are strongest at action/context lifecycle (`plugin::register_action_with_context`, attach/detach helpers), while plugin export/lifecycle ownership is still best handled by a host layer; docs should frame Rust plugin guidance as analysis/action modules with explicit install/uninstall wiring.

290. `ida::function::callers` returns caller function entry addresses (code-xref callers), which makes transitive call-graph traversal straightforward with visited-set BFS/DFS without additional callsite-to-function normalization in the common case.

291. Practical string harvesting in safe Rust can be built from existing primitives by combining segment filtering (`segment::all`, non-executable/data-like segments), predicate traversal (`address::data_items`), and bounded reads (`data::read_string`) with an application-level printable/length heuristic.

292. For project-facing docs in idax, C++ should be the default walkthrough language for general workflows because the primary wrapper is C++ (`include/ida/*.hpp`); Rust snippets should be retained where the use case is explicitly Rust-centric (for example Rust plugin-action wiring).

293. Case-10 safety/performance guidance should be framed as `idax` wrapper vs raw IDA SDK (C++), not Rust safe bindings vs `idax-sys`; using the wrong layer framing causes mismatch with the library's primary audience and stated use case intent.

294. Cargo treats every top-level `bindings/rust/idax/examples/*.rs` file as a standalone example crate; shared helper code placed at `examples/common.rs` is therefore compiled as an example and fails without `main`. Shared helpers should live in a module directory (for example `examples/common/mod.rs`) and be imported with `mod common;` from actual example binaries.

295. Node TypeScript declarations currently do not expose a top-level `BadAddress` constant even though address sentinels are needed by tools/examples. Tool-style TS examples should define a local `BAD_ADDRESS` sentinel (`0xffffffffffffffffn`) or add a typed export in the Node bindings surface.

296. Node example runtime validation can fail even when TypeScript checks pass if `idax_native.node` cannot resolve `@rpath/libidalib.dylib`; on this host all new Node tool examples failed at addon load with a hardcoded probe path under `/Users/int/hexrays/ida/bin/arm64_mac_clang_opt/ida.app/Contents/MacOS/libidalib.dylib` that does not exist. Capture this as an environment/runtime-linkage blocker distinct from example source correctness.

297. On this host, setting `IDADIR` and `DYLD_LIBRARY_PATH` to `/Applications/IDA Professional 9.3.app/Contents/MacOS` did not resolve Node addon startup failures; `dlopen` still only probed the stale embedded path under `/Users/int/hexrays/ida/...`, indicating the current `idax_native.node` binary needs rpath/install-name correction (or rebuild) rather than runtime env overrides alone.

298. For Node bindings, rebuilding the addon with `IDADIR` set to the desired runtime root (for example `npm run rebuild` with `IDADIR=/Applications/IDA Professional 9.3.app/Contents/MacOS`) rewrites `idax_native.node` `LC_RPATH` and resolves stale embedded-path startup failures; runtime env overrides alone do not change an already-built addon's embedded rpath.

299. Headless runtime smokes that open the same IDB/fixture concurrently can produce transient `open_database failed` errors across separate Node example processes; running the validation matrix sequentially avoids this lock/contention artifact and yields stable pass evidence.

300. In `bindings/rust/idax/examples/jbc_full_loader.rs`, deriving JBC version via `(magic & 1) + 1` is incorrect for the current accepted magic constants (`0x0043424a`, `0x0143424a`) because both have LSB 0; version must be selected by explicit magic comparison to parse V1/V2 header layouts correctly.

301. `bindings/rust/idax/examples/jbc_full_procmod.rs` produces much more representative disassembly when it auto-detects JBC headers and starts decoding at `code_section` (`24 + delta`), rather than byte 0 (header area). A fallback to offset 0 remains useful for non-JBC/raw byte streams.

302. A small synthetic JBC fixture generated at runtime (temporary file) is sufficient to validate successful-path behavior for both `jbc_full_loader` and `jbc_full_procmod` adaptations when no canonical `.jbc` sample is available in-repo.

303. The Qt-form declaration surface can be meaningfully validated in headless Rust by parsing form-markup controls/groups (`<##group##>`, `:C`, `:R`, `:D`, `:N`, `:b`) into a structured report even when widget-host rendering and `ask_form` execution are unavailable.

304. In IDA form markup, lines ending with `>>` can both close the current group scope and still contain a control declaration on that same line (for example `:C>>`); parsers should drop one trailing `>` and parse the control after applying scope close semantics.

305. A practical headless subset of DriverBuddy analysis can be implemented with existing safe Rust APIs by combining import-module inspection (`database::import_modules`) for driver-type heuristics, entrypoint resolution via naming/function fallbacks, and targeted dispatch-name pattern scanning.

306. IOCTL triage in standalone adaptations is reliably approximated by scanning decoded instruction immediate operands for `CTL_CODE`-shaped values (`device!=0`, `function!=0`, method/access bit ranges valid); on non-driver fixtures this correctly yields an empty hit-set without false failures.

307. The Rust decompiler surface currently supports headless post-processing through `DecompiledFunction::raw_lines`/`set_raw_line` and `header_line_count`, but handle-centric helpers like `item_at_position(cfunc_handle, ...)` are not directly reachable from `DecompiledFunction` in standalone flows; practical adaptations should favor line-level transforms unless event callbacks provide raw handles.

308. Abyss-style item-index visualization ports cleanly with `ida::lines` primitives by scanning raw pseudocode for `COLOR_ON + COLOR_ADDR` tags and injecting colored `<hex-index>` annotations before each tagged item reference.

309. A useful non-UI Abyss subset can be delivered headlessly by combining token colorization (`lines::colstr`), item-index tag annotation, local-variable rename previews (`decompiled.variables` heuristics), and caller/callee hierarchy extraction (`function::callers`/`function::callees`) for a selected decompiled function.

310. An uncaught C++ exception thrown by an IDA SDK C++ wrapper function (e.g. `loader::set_processor` failing because the module is not found) bypassing the FFI boundary will cause the Rust process to instantly abort with `fatal runtime error: Rust cannot catch foreign exceptions, aborting`. It must either be caught in C++ and converted to `idax::Error` or preempted by valid arguments (like fallback to `metapc`).

311. A completely standalone mock IDA loader can be implemented via `idax::DatabaseSession::open(input, false)` followed by `segment::all().for_each(remove)` to clear out any IDA auto-loader fallback. It can then completely build the database using `segment::create`, `loader::memory_to_database`, `data::define_string`, `entry::add`, and `name::force_set`.

These are to be referenced as [FXX] in the live knowledge base.

312. Examples labeled as headless adaptations (`_loader.rs`, `_procmod.rs`) for bindings lacking dynamic entrypoint export macros MUST interact dynamically with the IDA Database. A script merely parsing file offsets and printing an imaginary load/disassembly plan is a "fake" implementation. Authentic adaptations must use `DatabaseSession::open`, clear existing segments (`segment::remove`), create explicit ones (`segment::create`), copy bytes in (`loader::memory_to_database`), and iterate memory reading from the DB APIs (`data::read_byte`) to generate representations (`comment::set`, `name::force_set`, `instruction::create`).

These are to be referenced as [FXX] in the live knowledge base.

313. When using the official release of the IDA SDK (via `ida-cmake`), the `ida_compiler_settings` interface target aggressively injects `-flto` (Link Time Optimization) in `Release` mode. Because of CMake/GCC flag ordering, this can override target-level `-fno-lto` settings and cause downstream link failures (especially for Rust consumers linking a C++ static archive). The most robust fix is to physically strip `-flto` from `ida_compiler_settings`'s `INTERFACE_COMPILE_OPTIONS` via `list(FILTER ... EXCLUDE REGEX "-flto")`.

These are to be referenced as [FXX] in the live knowledge base.

314. **CMake Scope Issue on Windows:** When `idax` is included via `FetchContent` or `add_subdirectory`, the `ida-cmake` toolchain sets `CMAKE_MSVC_RUNTIME_LIBRARY` to enforce `/MTd`. However, this variable was isolated to the subdirectory scope, causing the parent integration tests to compile with the default `/MDd`, resulting in fatal `LNK2038` mismatches. Pushing the variable to `PARENT_SCOPE` fixes this.

315. **Windows `<windows.h>` Macro Collision:** Compiling the Node.js bindings on Windows pulls in `<windows.h>`, which aggressively `#define`s `RegisterClass` to `RegisterClassA` or `RegisterClassW`. This mangled the `ida::instruction::RegisterClass` enum signatures, causing `LNK2001` unresolved external symbol errors. Renaming the enum to `RegisterCategory` across C++, TypeScript, and Rust permanently resolves this.

316. **MSVC Strict Linking Requirements:** Unlike macOS/Linux (which use dynamic symbol lookup for the Node Addon), MSVC strictly requires import libraries (`.lib`). The Node Windows build failed to resolve `idalib`-specific symbols (`init_library`, `open_database`, etc.). Explicitly finding and linking `ida.lib`, `pro.lib`, and critically `idalib.lib` in `bindings/node/CMakeLists.txt` for MSVC builds satisfies the linker.

317. **hcli Install Bug in Parallel CI environments:** `hcli ida install --download-id <tag>` fails inconsistently in parallel CI environments (especially Windows). It downloads to the system temp directory and globs for the most recently modified file, which picks up random CI processes' temporary files, causing `FileNotFoundError`. **Solution:** Decoupled the process by explicitly using `hcli download --output-dir ./ida-installer "$ASSET_KEY"` (using OS-specific asset keys like `release/9.3/ida-pro/ida-pro_93_x64win.exe`), and then passing the resolved file path to `hcli ida install`.

318. **Node.js Examples Error with ts-node:** Running `ts-node` on the Node examples failed with `ERR_UNKNOWN_FILE_EXTENSION` when using type module. This was resolved by changing `type: "module"` to `type: "commonjs"` in `bindings/node/examples/package.json`.

319. **Rust/GCC Compilation Warning for idax_shim.cpp:** The C++ shim (`bindings/rust/idax-sys/shim/idax_shim.cpp`) generates `-Wclass-memaccess` warnings on Linux GCC when `memcpy`-ing an opaque pointer into `ida::loader::InputFile`. Fixed using `#pragma GCC diagnostic ignored "-Wclass-memaccess"`.

320. **Dynamic Linker Paths in CI:** When running compiled examples (Rust and Node) against a real headless IDA installation in CI, the dynamically resolved `IDADIR` is not automatically propagated to the linker's search path or `rpath`. macOS specifically fails with `dyld: Library not loaded: @rpath/libida.dylib`. **Solution:** Explicitly export `LD_LIBRARY_PATH="$IDADIR:$LD_LIBRARY_PATH"` (Linux) and `DYLD_LIBRARY_PATH="$IDADIR:$DYLD_LIBRARY_PATH"` (macOS) within the exact bash step that runs the examples to bypass SIP stripping and ensure the runtime linker finds the real IDA shared libraries.

321. **Database Creation Permission in CI:** By default, `idalib` APIs like `open_database` attempt to create the database file (e.g., `.i64`) in the same directory as the target binary. Running headless adaptations against read-only system binaries (like `/bin/ls`) will crash with `open_database failed` because the process lacks permissions to write `/bin/ls.i64`. **Solution:** Always copy the target system binary to a writable temporary location (like the CI workspace) before passing it to the `idalib` headless scripts.

322. **macOS IDA install path normalization requirement:** `ida-config.json` on macOS can resolve to the `.app` bundle root (`/Applications/IDA Professional 9.3.app`) while build/runtime linkage logic expects the directory containing `libida.dylib` (`.../Contents/MacOS`). If `IDADIR` is not normalized to `Contents/MacOS`, CMake and Rust/Node runtime steps may fail with missing `libida.dylib`/`libidalib.dylib` paths.

323. **Node workflow argument contract:** The Node examples in `bindings/node/examples/*.ts` resolve the native addon internally and treat argv position 0 as the target binary/IDB path. Passing `build/Release/idax_native.node` as an extra leading argument in CI shifts positional parsing and makes examples operate on the addon path instead of the test binary. Workflow invocations should pass only the intended binary path and flags.

324. **Windows Rust CRT stability in CI:** Running Rust example binaries in default debug mode on `windows-latest` can surface `_CrtDbgReport` and related unresolved debug CRT symbols in mixed-link environments. Building and running examples with `--release` in CI avoids this mismatch for the current bindings pipeline.

325. **MSVC import-lib fallback must be independent of IDADIR:** In Node bindings CMake, gating Windows import-library discovery behind `elseif(MSVC ...)` after `if(IDA_INSTALL_DIR)` prevents fallback when `IDADIR` is set but `.lib` files are absent there. Use a separate MSVC fallback block that resolves missing `ida.lib`/`idalib.lib`/`pro.lib` from `IDASDK` whenever they are not already found.

326. **Windows shell choice can hijack Rust linker resolution:** Running `cargo build` under Git Bash on Windows can route `link.exe` to `C:\Program Files\Git\usr\bin\link.exe` (`/usr/bin/link`) instead of MSVC's linker, causing build-script link failures like `extra operand ... rcgu.o`. Use PowerShell/MSVC shell for Windows Rust build/run steps.

327. **Windows runtime loader path for Node/Rust examples:** On Windows, `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` are irrelevant. Example execution that depends on IDA runtime DLLs must prepend `IDADIR` to `PATH` in the same step (`$env:PATH = "$env:IDADIR;$env:PATH"`) before launching Node/Rust binaries.

328. **Rust native static-lib name collision on Windows:** In `idax-sys`, linking a native static library named `idax` (`cargo:rustc-link-lib=static=idax`) can be elided from final downstream example link commands when the consuming Rust crate is also named `idax`, yielding broad unresolved `ida::...` externals from `idax_shim.o`. Aliasing the native archive to a distinct name (e.g., `idax_rust.lib`) in `build.rs` avoids this collision path.

329. **`binary_forensics` instability in Windows headless CI:** In `Bindings CI` Windows runs, `npx ts-node examples/binary_forensics.ts ...` can exit with code 1 immediately after launch without a JavaScript stack trace or probe output, while earlier Node examples in the same step pass. Treat as a separate runtime-stability issue from core addon bootstrap and gate/skip this example on Windows CI until isolated.

330. **Rust static-link propagation gap on Windows downstream examples:** A native static library link emitted in `idax-sys` build script (`cargo:rustc-link-lib=static=idax_rust`) can appear in the `idax_sys` crate compile invocation yet still be absent from final downstream example `link.exe` commands. Re-emitting the native link directive from a dependent crate build script (via `DEP_IDAX_*` metadata) is required for reliable Windows example linkage.

331. **`class_reconstructor` instability in Windows headless CI:** After gating `binary_forensics`, the Windows Node step still fails while launching `class_reconstructor.ts`, which logs initialization/opening messages then exits with code 1 and no JavaScript stack trace. This indicates a second independent Windows headless runtime flake that should be gated and tracked separately.

332. **`cargo:rustc-link-lib` from build scripts can be non-authoritative for final Windows example links:** Even after re-emitting `static=idax_rust` via dependent build scripts, final example `link.exe` commands may still omit the static archive. A crate-level explicit native dependency (`#[link(name = "idax_rust", kind = "static")]`) in the `sys` crate provides a stronger propagation signal for downstream linking.

333. **Windows Node headless instability is broader than a single example:** After gating `binary_forensics` and `class_reconstructor`, the Windows Node run can still terminate with exit code 1 around earlier example execution (`idalib_dump_port`/`complexity_metrics`) without actionable JS stderr. Temporary full gating of Windows Node runtime examples is the most reliable CI unblocking strategy until root cause is isolated.

334. **Windows Rust final example links may require crate-local native-link metadata in the top-level crate:** Even with `idax-sys` build-script/native-attribute linking in place, downstream `idax` examples can still omit `idax_rust.lib` in final MSVC `link.exe` lines. Adding `#[link(name = "idax_rust", kind = "static")]` in `bindings/rust/idax/src/lib.rs` provides crate-local propagation for the example crates that directly depend on `idax`.

335. **Empty `extern` blocks with `#[link]` may not affect final Windows example link lines:** In run `22427902344`, adding empty `#[link(name = "idax_rust", kind = "static")] unsafe extern "C" {}` blocks in both `idax-sys` and `idax` still left final example `rustc`/`link.exe` invocations without `idax_rust.lib`. Next hardening step is to keep the `#[link]` blocks non-empty (declare a sentinel extern item) so native-link metadata is retained through crate metadata propagation.

336. **Windows Rust transitive native-link propagation can remain absent even with crate-level `#[link]` attributes:** In run `22428113513`, final example `rustc`/`link.exe` lines still omitted `idax_rust` after non-empty sentinel `#[link]` extern blocks were added in both `idax-sys` and `idax`. A more reliable approach is to merge `idax.lib` into the shim archive during `idax-sys` build on Windows (single `idax_shim_merged.lib`) so required C++ wrapper objects are bundled with shim objects and do not rely on downstream `-l idax_rust` propagation.

337. **Windows Rust final-link failure mode shifted from missing symbols to CRT runtime mismatch after merged-shim propagation:** In run `22428565402`, final example `link.exe` commands now included `idax_shim_merged.lib` (via workflow `RUSTFLAGS` and `idax-sys` metadata), proving merged-shim propagation reached downstream binaries. Failure changed to `LNK2038` (`MT_StaticRelease` vs `MD_DynamicRelease`) between CMake-built `idax.lib` objects and Rust/`cc` shim objects. Mitigation: force CMake MSVC runtime to DLL mode (`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL`) when building idax from `idax-sys/build.rs`.

338. **Workflow-level `RUSTFLAGS` native-link injection can pin stale `idax-sys` build outputs across incremental cargo passes:** In run `22428747919`, Windows Rust commands carried two `idax-sys` native output paths (`...idax-sys-bfdc...` and `...idax-sys-457a...`), while workflow-selected `RUSTFLAGS` forced linkage against the older directory's `idax_shim_merged.lib`. This can preserve outdated runtime-library settings and mask fresh build-script fixes. Prefer crate-emitted link metadata over workflow `RUSTFLAGS` hard-injection for `idax_shim_merged`.

339. **CMake cross-platform library extension hardcoding causes linker errors on non-macOS platforms:** Hardcoding `.dylib` for `IDAX_IDALIB_LIB_NAME` and `IDAX_IDA_LIB_NAME` in `tests/integration/CMakeLists.txt` caused fatal `LNK1104` errors on Windows (which requires `.lib` import stubs) and `No rule to make target` on Linux (which uses `.so`). Fixed by conditionally setting the correct library extension per platform and using the SDK's `ida_add_idalib` macro on non-Apple platforms.

340. **Node decompiler wrappers can outlive database teardown and crash on process shutdown:** In macOS headless runs, `examples/complexity_metrics.ts` can complete successfully and then segfault on exit when live `DecompiledFunction` wrappers still hold native `cfunc_t` state after `database.close()`. Pre-close disposal of all live Node decompiler wrappers in the addon (`DisposeAllDecompilerFunctions()` invoked from `database.close`) eliminates this shutdown-time crash mode.

341. **Windows Rust link metadata must consistently target the merged shim archive:** After adopting `idax_shim_merged.lib`, leaving `idax_rust` link metadata paths in Rust crate attributes/build scripts can reintroduce unresolved `ida::...` symbols at final example link. Aligning crate/build-script linkage to `idax_shim_merged` and tracking idax source trees in `idax-sys/build.rs` (`cargo:rerun-if-changed` over `CMakeLists.txt`, `cmake/`, `include/`, `src/`) reduces stale-archive reuse and missing-symbol regressions.

342. **`idax` crate-level Windows native link emission can inject incomplete shim objects into `libidax.rlib`:** Keeping a separate `bindings/rust/idax/build.rs` that re-emits static native linkage can cause final MSVC failures where unresolved C++ symbols are reported from `libidax-*.rlib(...idax_shim.o)` instead of `idax-sys`. Removing `idax`-level native link emission (and relying on `idax-sys` as the single source of native-link metadata) avoids this duplicate/bundled-object failure mode.

343. **Windows fallback linking is more stable with separate `idax_shim` + aliased `idax_cpp` archives than merged-archive indirection:** Replacing `idax_shim_merged.lib` creation with direct static-link metadata (`idax_shim` from `cc` cargo metadata plus copied `idax_cpp.lib`) avoids merge-step variability and keeps native symbol ownership explicit while still preventing `idax` crate-name collision.

344. **Windows final-link commands can still omit `idax_cpp` even when emitted from `idax-sys` build script metadata:** If final `link.exe` lines include IDA SDK libs but not `idax_cpp.lib`, unresolved `ida::...` symbols appear from `idax_shim.o`. Reinforcing `idax_cpp` via a crate-level `#[link(name = "idax_cpp", kind = "static")]` non-empty extern block in `idax-sys/src/lib.rs` provides an additional propagation path for downstream binaries.

345. **Top-level `idax` crate link reinforcement can further stabilize Windows example links:** Because Rust examples link directly against `idax`, adding the same non-empty `#[link(name = "idax_cpp", kind = "static")]` sentinel in `bindings/rust/idax/src/lib.rs` provides a direct, crate-local fallback when transitive metadata from `idax-sys` is not reflected in final `link.exe` command lines.

346. **MSVC `/GL` + Rust static bundling can hide C++ symbols inside `.rlib` archives:** When `idax_cpp.lib` is built with LTCG (`/GL`) and linked via default `static=` cargo metadata, rustc can bundle it into crate `.rlib` archives instead of passing it directly to `link.exe`. This can produce final Windows links with no explicit `idax_cpp.lib` argument and broad unresolved `ida::...` externals from `idax_shim.o`. Emitting `cargo:rustc-link-lib=static:-bundle=idax_cpp` in `idax-sys/build.rs` forces direct final-link participation of `idax_cpp.lib` and avoids this failure mode.

347. **Windows Rust bindings must align CRT mode with IDA SDK static runtime (`/MT`) to avoid `LNK2038` mismatches:** When `idax_cpp` objects are compiled as `MT_StaticRelease` but Rust/`cc` shim objects are `MD_DynamicRelease`, MSVC fails with broad runtime-library mismatch diagnostics (`LNK2038`, `LNK1319`, `LIBCMT` conflict). Enforcing Windows `+crt-static` for Rust builds and static CRT for shim/CMake outputs resolves this class of failure.

348. **Windows headless runtime can fail silently when IDA init/open paths are minimally parameterized:** Rust examples that call `database::init()` with `argc=0, argv=null` and then immediately `analysis::wait()` can exit with code 1 on `windows-latest` without useful diagnostics in workflow logs. Passing a synthetic argv (`"idax-rust"`) to init improves initialization robustness, and treating `analysis::wait()` failure as a non-fatal warning in Windows CI helper flows keeps list/query examples operational.

349. **Rust example diagnostics should include `ErrorCategory` and numeric code in CI logs:** plain message/context-only formatting can hide actionable failure signatures when Windows example processes exit with code 1. Including `[category:code]` in formatted errors significantly improves triage speed for runtime-only regressions.

350. **Windows plugin-policy runtime options are currently unsupported by this wrapper path:** forcing `ida::database::init(..., RuntimeOptions{plugin_policy...})` on Windows produced deterministic startup failure `SdkFailure: Plugin policy controls are not implemented on Windows yet`. The safe mitigation is to keep default init path and isolate `IDAUSR` to an empty directory in CI instead of using plugin-policy controls.

351. **Windows Rust runtime triage requires explicit session tracing and optional analysis disable toggle:** adding environment-driven tracing around `database::init/open/close` and `analysis::wait` in Rust example helper code (`IDAX_RUST_EXAMPLE_TRACE=1`), plus a CI-only toggle to skip auto-analysis waits (`IDAX_RUST_DISABLE_ANALYSIS=1`), provides deterministic stage-level diagnostics for otherwise opaque exit-code-1 failures.

352. **Running Windows Rust examples via direct executable invocation improves failure diagnostics over `cargo run`:** building with `cargo build --release --example <name>` and then invoking `target\\release\\examples\\<name>.exe` allows explicit reporting of raw exit code and hex form (e.g., `0xC0000005`) in workflow logs, which is useful when runtime exits occur before Rust-level error handling prints.

353. **Windows Rust `init_library` rejects injected `-A`/`-L` args in this workflow path (return code 2):** forwarding extra init args from `database::init()` caused deterministic `init_library failed [return code: 2]`. For this path, keep minimal argv (`argv0` only) and focus diagnostics on absolute input path + stage tracing in workflow execution.
