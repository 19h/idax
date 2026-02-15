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
190. Lifter width heuristics: structured `instruction::Operand` metadata (`byte_width`, `register_name`, `register_class`) removes dependence on `operand_text()` parsing for AVX width decisions.
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

These are to be referenced as [FXX] in the live knowledge base inside agents.md.
