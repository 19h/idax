## 12) Knowledge Base (Live)

Note:
- This section is a hierarchical representation of the findings and learnings (live) in `.agents/findings.md`.
- You must add any findings and learnings into `.agents/findings.md`.
- Then, integrate the findings and learnings into this section appropriately with optional reference to a fact from `.agents/findings.md` in the format [FXXX] as suffix of a leaf of the knowledge base tree.

### 1. SDK Systemic Pain Points
- 1.1. Naming Inconsistency
  - 1.1.1. Mixed abbreviations and full words coexist (`segm` vs `segment`, `func` vs `function`, `cmt` vs `comment`) — biggest onboarding barrier [F1]
  - 1.1.2. Ambiguous prefixes and overloaded constants across domains
  - 1.1.3. Multiple retrieval variants for names/xrefs differ subtly in behavior [Pain7]
  - 1.1.4. Normalization applied during P9.1 audit
    - 1.1.4.1. ~200+ `ea` params renamed to `address` [F37]
    - 1.1.4.2. `set_op_*` → `set_operand_*`, `del_*` → `remove_*`, `idx` → `index`, `cmt` → `comment` [F37]
    - 1.1.4.3. `delete_register_variable` → `remove_register_variable`
    - 1.1.4.4. Polarity clash resolved: `Segment::visible()` → `Segment::is_visible()`, removed `Function::is_hidden()` [F36]
    - 1.1.4.5. Subscription naming stutter removed (`debugger_unsubscribe` in `ida::debugger`) [F36]
- 1.2. Conceptual Opacity
  - 1.2.1. Highly encoded flags and bitfields with domain-specific hidden meaning [F3]
  - 1.2.2. `flags64_t` packs unrelated concerns (state/type/operand metadata) behind overlapping bit regions [Pain6]
  - 1.2.3. Implicit sentinels (`BADADDR`, `BADSEL`, magic ints) create silent failures [F2]
  - 1.2.4. Search direction defaults rely on zero-value bitmasks that are not self-evident [Pain11]
- 1.3. Inconsistent Error/Reporting Patterns
  - 1.3.1. Mixed `bool`, integer codes, sentinel values, and side effects [F4, Pain8]
  - 1.3.2. Several APIs rely on magic argument combinations and sentinel values for special behavior [Pain9]
  - 1.3.3. P9.1 audit corrections
    - 1.3.3.1. `Plugin::run()` returned `bool` not `Status` [F38]
    - 1.3.3.2. `Processor::analyze/emulate/output_operand` returned raw `int` [F38]
    - 1.3.3.3. `line_to_address()` returned `BadAddress` as success [F38]
    - 1.3.3.4. UI dialog cancellation was `SdkFailure` not `Validation` [F38]
- 1.4. Hidden Dependencies and Lifecycle Hazards
  - 1.4.1. Pointer validity/lifecycle semantics need strong encapsulation [F5]
  - 1.4.2. Include-order dependencies expose features conditionally in a non-obvious way [Pain10]
  - 1.4.3. Manual lock helpers (`lock_*`) not enforced by type system [Pain5]
  - 1.4.4. Manual memory and ownership conventions still appear in several API families [Pain16]
- 1.5. Redundant and Overlapping API Paths
  - 1.5.1. Multiple equivalent SDK API paths differ subtly in semantics and side effects [F4]
  - 1.5.2. Debugger APIs duplicate direct and request variants [Pain12]
  - 1.5.3. Duplicate binary pattern search in `data`/`search` [F36]
- 1.6. C-Style Varargs and Weak Type Safety
  - 1.6.1. UI and debugger dispatch rely on varargs notification systems with weak compile-time checks [F7, Pain13]
  - 1.6.2. Debugger notification API: mixed `va_list` signatures per event [F24]
    - 1.6.2.1. Most events pass `const debug_event_t*`
    - 1.6.2.2. `dbg_bpt`/`dbg_trace` pass `(thid_t, ea_t, ...)` directly
    - 1.6.2.3. Wrappers must decode per-event arg layouts
  - 1.6.3. IDB event payloads are `va_list`-backed, consumable only once [F26]
    - 1.6.3.1. For multi-subscriber routing: decode once into normalized event object, then fan out
- 1.7. Legacy Compatibility Burden
  - 1.7.1. Obsolete values and historical naming still present in modern workflows
  - 1.7.2. Type APIs contain deep complexity with historical encodings [Pain14]
  - 1.7.3. Decompiler APIs enforce maturity/order constraints easy to violate [Pain15]
  - 1.7.4. Numeric and representation controls are spread across low-level helper patterns [Pain17]

---

### 2. Build System & Toolchain
- 2.1. C++23 Compatibility
  - 2.1.1. `std::is_pod<T>` used without `#include <type_traits>` in SDK `pro.h` [F12]
    - 2.1.1.1. Fix: include `<type_traits>` before `<pro.h>` in bridge header
  - 2.1.2. SDK `pro.h` stdio remaps (`snprintf` → `dont_use_snprintf`) collide with newer libc++ internals [F78]
    - 2.1.2.1. Fix: include key C++ headers before `pro.h` in bridge: `<functional>`, `<locale>`, `<vector>`, `<type_traits>`
  - 2.1.3. Linux Clang 18 fails with missing `std::expected` even with `-std=c++23` [F71]
    - 2.1.3.1. Reports `__cpp_concepts=201907` so `std::expected` stays disabled
    - 2.1.3.2. Clang 19 reports `202002` and passes [F111]
  - 2.1.4. Linux Clang libc++ fallback fails during SDK header inclusion [F72]
    - 2.1.4.1. `-stdlib=libc++` collides with `pro.h` `snprintf` remap
  - 2.1.5. SDK bridge internals in iostream-heavy tests collide with `fpro.h` stdio macro remaps [F31]
    - 2.1.5.1. `stdout` → `dont_use_stdout`
    - 2.1.5.2. Keep string checks in integration-level tests or avoid iostream in bridge TUs
- 2.2. Linking & Symbol Resolution
  - 2.2.1. **CRITICAL**: SDK stub dylibs vs real IDA dylibs have mismatched symbol exports [F16]
    - 2.2.1.1. Stub `libidalib.dylib` exports symbols (e.g., `qvector_reserve`) the real one doesn't
    - 2.2.1.2. Only real `libida.dylib` exports these
    - 2.2.1.3. macOS two-level namespace causes null-pointer crashes
    - 2.2.1.4. Fix: link against real IDA dylibs, not SDK stubs
  - 2.2.2. Tool-example runtime-linking: `ida_add_idalib` can bind to SDK stubs causing crashes [F109]
    - 2.2.2.1. Prefer real IDA dylibs; stub fallback only when runtime libs unavailable
  - 2.2.3. macOS linker warnings: IDA 9.3 dylibs built for macOS 12.0 while objects target 11.0 [F40]
    - 2.2.3.1. Warning-only; runtime stable
  - 2.2.4. Linux SDK artifacts: current checkout lacks `x64_linux_clang_64` runtime libs [F112]
    - 2.2.4.1. Addon/tool targets fail under Linux Clang when build toggles on
- 2.3. CMake Architecture
  - 2.3.1. `libidax.a` uses custom `idasdk_headers` INTERFACE target [F17]
    - 2.3.1.1. SDK includes + `__EA64__` + platform settings
    - 2.3.1.2. Consumers bring own `idasdk::plugin`/`idasdk::idalib`
  - 2.3.2. CPack output dir drifts with arbitrary working directories [F41]
    - 2.3.2.1. Fix: invoke with `-B <build-dir>` to pin artifact location
  - 2.3.3. CTest on multi-config generators (Visual Studio): requires explicit `-C <config>` [F77]
    - 2.3.3.1. Always pass `--config` to `cmake --build` and `-C` to `ctest`
  - 2.3.4. IDA SDK checkout layout varies [F74]
    - 2.3.4.1. `<sdk>/ida-cmake/`, `<sdk>/cmake/`, submodule-backed
    - 2.3.4.2. May need recursive submodule fetch
    - 2.3.4.3. Resolve layout explicitly; support all known bootstrap locations
  - 2.3.5. CI submodule policy: both project and SDK checkouts should use recursive submodule fetch [F75]
- 2.4. CI/CD
  - 2.4.1. GitHub Actions macOS labels change over time [F76]
    - 2.4.1.1. Keep active labels (currently `macos-14`)
    - 2.4.1.2. Reintroduce x86_64 via supported labels or self-hosted runners
  - 2.4.2. Example addon coverage: enable `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON` in CI [F79]
  - 2.4.3. Matrix drift risk: validation automation didn't propagate `IDAX_BUILD_EXAMPLE_TOOLS` [F107]
  - 2.4.4. CI log audit sentinels: `Complete job name`, `validation profile '<profile>' complete`, `100% tests passed` [F83]
  - 2.4.5. GitHub-hosted cross-platform validation [F73]
    - 2.4.5.1. `compile-only` and `unit` profiles work without licensed IDA runtime
    - 2.4.5.2. Checkout `ida-sdk` with `IDADIR` unset; integration tests auto-skipped
- 2.5. CMake & Integration
  - 2.5.1. `FetchContent` / `add_subdirectory` without `IDASDK` environment set [F281]
    - 2.5.1.1. `idax` fetches `ida-sdk` via `FetchContent` and bootstraps `ida-cmake` internally.
    - 2.5.1.2. The `find_package(idasdk REQUIRED)` call inside `idax` creates imported targets (`idasdk::plugin`, etc.) that are local to the `idax` subdirectory scope.
    - 2.5.1.3. These targets must be promoted to `GLOBAL` scope using `set_target_properties(target PROPERTIES IMPORTED_GLOBAL TRUE)` in `idax/CMakeLists.txt` so parent consumer projects can link them directly.

---

### 3. Opaque Boundary Design
- 3.1. Zero HIGH violations confirmed [F39]
  - 3.1.1. No SDK types leak into public headers
- 3.2. MEDIUM violations found and resolved [F39]
  - 3.2.1. `Chooser::impl()`/`Graph::impl()` were unnecessarily public → made private
  - 3.2.2. `xref::Reference::raw_type` exposed raw SDK codes → replaced with typed `ReferenceType` enum
- 3.3. Private Member Access Pattern [F15]
  - 3.3.1. Use `friend struct XxxAccess` with static `populate()` in impl file
  - 3.3.2. Anonymous namespace helpers cannot be friends
- 3.4. No public `.raw()` escape hatches permitted
- 3.5. Public string policy
  - 3.5.1. Output: `std::string`
  - 3.5.2. Input: `std::string_view` where suitable; `std::string` otherwise
  - 3.5.3. Conversion boundary helpers between `std::string` and `qstring` internally

---

### 4. SDK Domain-Specific Findings
- 4.1. Segment API
  - 4.1.1. `segment_t::perm` uses `SEGPERM_READ/WRITE/EXEC` (not `SFL_*`) [F13]
  - 4.1.2. Visibility via `is_visible_segm()` (not `is_hidden_segtype()`) [F13]
  - 4.1.3. Segment type constants: SDK `SEG_NORM(0)`–`SEG_IMEM(12)` [F49]
    - 4.1.3.1. Wrapper `segment::Type` maps all 12 values
    - 4.1.3.2. Aliases: `Import`=`SEG_IMP=4`, `InternalMemory`=`SEG_IMEM=12`, `Group`=`SEG_GRP=6`
    - 4.1.3.3. `segment_t::type` is `uchar`
  - 4.1.4. SDK segment comments: `get_segment_cmt`/`set_segment_cmt` operate on `const segment_t*` [F59]
    - 4.1.4.1. `set_segment_cmt` returns `void`
    - 4.1.4.2. Validate target segment first; treat set as best-effort
- 4.2. Type System
  - 4.2.1. SDK float types require `BTF_FLOAT` (=`BT_FLOAT|BTMT_FLOAT`) and `BTF_DOUBLE` (=`BT_FLOAT|BTMT_DOUBLE`) [F14]
    - 4.2.1.1. Not raw `BT_FLOAT`/`BTMT_DOUBLE`
  - 4.2.2. `create_float`/`create_double` may fail at specific addresses in real DBs [F57]
    - 4.2.2.1. Treat as conditional capability probes; assert category on failure
  - 4.2.3. Type and decompiler domains are high-power/high-complexity; need progressive API layering [F6]
- 4.3. Graph API
  - 4.3.1. `create_interactive_graph()` returns nullptr in idalib/headless [F18]
    - 4.3.1.1. Graph uses standalone adjacency-list for programmatic use
    - 4.3.1.2. Only `show_graph()` needs UI
    - 4.3.1.3. `qflow_chart_t` works in all modes
  - 4.3.2. SDK graph naming: `FC_PREDS` renamed to `FC_RESERVED` [F19]
    - 4.3.2.1. Predecessors built by default; `FC_NOPREDS` to disable
    - 4.3.2.2. `insert_simple_nodes()` takes `intvec_t&` (reference, not pointer)
  - 4.3.3. Graph layout in headless is behavioral (stateful contract), not geometric rendering [F68]
    - 4.3.3.1. Persist selected `Layout` in `Graph`, expose `current_layout()`
    - 4.3.3.2. Validate via deterministic integration checks
- 4.4. Chooser API
  - 4.4.1. `chooser_t::choose()` returns `ssize_t` [F20]
    - 4.4.1.1. -1 = no selection, -2 = empty, -3 = already exists
    - 4.4.1.2. `CH_KEEP` prevents deletion on widget close
    - 4.4.1.3. Column widths encode `CHCOL_*` format flags in high bits
- 4.5. Loader API
  - 4.5.1. `loader_failure()` does longjmp, never returns [F21]
  - 4.5.2. No C++ base class for loaders (unlike `procmod_t`) [F21]
    - 4.5.2.1. Wrapper bridges C function pointers to C++ virtual methods via global instance pointer
  - 4.5.3. Loader callback context: load/reload/archive extraction spread across raw callback args and bitflags [F63]
    - 4.5.3.1. `ACCEPT_*`, `NEF_*` flags
    - 4.5.3.2. Expose typed request structs and `LoadFlags` encode/decode helpers
- 4.6. Comment API
  - 4.6.1. `append_cmt` success doesn't guarantee appended text round-trips via `get_cmt` as strict suffix [F32]
    - 4.6.1.1. Tests should assert append success + core content presence, not strict suffix matching
- 4.7. Netnode / Storage
  - 4.7.1. Blob ops at index 0 can trigger `std::length_error: vector` crashes in idalib [F33]
    - 4.7.1.1. Use non-zero indices (100+) for blob/alt/sup ops
    - 4.7.1.2. Document safe ranges
  - 4.7.2. `exist(const netnode&)` is hidden-friend resolved via ADL [F65]
    - 4.7.2.1. Qualifying as `::exist(...)` fails to compile
    - 4.7.2.2. Call `exist(nn)` unqualified
- 4.8. String Literal Extraction
  - 4.8.1. `get_strlit_contents()` supports `len = size_t(-1)` auto-length [F27]
    - 4.8.1.1. Uses existing strlit item size or `get_max_strlit_length(...)`
    - 4.8.1.2. Enables robust string extraction without prior data-definition calls
- 4.9. Snapshot API
  - 4.9.1. `build_snapshot_tree()` returns synthetic root whose `children` are top-level snapshots [F28]
  - 4.9.2. `update_snapshot_attributes(nullptr, root, attr, SSUF_DESC)` updates current DB snapshot description [F28]
- 4.10. Custom Fixup Registration
  - 4.10.1. `register_custom_fixup()`/`find_custom_fixup()`/`unregister_custom_fixup()` return type ids in `FIXUP_CUSTOM` range [F29]
    - 4.10.1.1. Returns 0 on duplicate/missing
    - 4.10.1.2. Wrappers return typed IDs, map duplicates to conflict errors
- 4.11. Database Transfer
  - 4.11.1. `file2base(li, pos, ea1, ea2, patchable)` requires open `linput_t*` + explicit close [F30]
  - 4.11.2. `mem2base(ptr, ea1, ea2, fpos)` returns 1 on success, accepts `fpos=-1` for no file offset [F30]
- 4.12. Switch Info
  - 4.12.1. `switch_info_t` encodes element sizes via `SWI_J32/SWI_JSIZE` and `SWI_V32/SWI_VSIZE` bit-pairs [F25]
    - 4.12.1.1. Not explicit byte fields
    - 4.12.1.2. Expose normalized byte-size fields in wrapper structs
- 4.13. Entry API
  - 4.13.1. `set_entry_forwarder(ord, "")` can fail for some ordinals/DBs in idalib [F60]
    - 4.13.1.1. Expose explicit `clear_forwarder()` returning `SdkFailure`
    - 4.13.1.2. Tests use set/read/restore patterns
- 4.14. Search API
  - 4.14.1. `find_*` helpers already skip start address [F61]
    - 4.14.1.1. `SEARCH_NEXT` mainly meaningful for lower-level text/binary search
    - 4.14.1.2. Keep typed options uniform; validate with integration tests
- 4.15. Action Detach
  - 4.15.1. SDK action detach helpers return only success/failure, no absent-attachment distinction [F62]
    - 4.15.1.1. Map detach failures to `NotFound` with action/widget context
- 4.16. Database Open
  - 4.16.1. `open_database()` in idalib performs loader selection internally [F58]
    - 4.16.1.1. `LoadIntent` (`Binary`/`NonBinary`) maps to same open path
    - 4.16.1.2. Keep explicit intent API, wire to dedicated paths when possible
- 4.17. DB Metadata
  - 4.17.1. SDK file-type from two sources [F93]
    - 4.17.1.1. `get_file_type_name` vs `INF_FILE_FORMAT_NAME`/`get_loader_format_name`
    - 4.17.1.2. Expose both with explicit `NotFound` for missing loader-format
- 4.18. Active Processor Query
- 4.18.1. SDK `PH.id` via `get_ph()` returns active processor module ID (`PLFM_*`) [F231]
  - 4.18.1.1. `PLFM_386` = 0 (Intel x86/x64), not 15 (which is `PLFM_PPC`)
  - 4.18.1.2. `inf_get_procname()` returns short name (e.g. "metapc", "ARM")
  - 4.18.1.3. Both are `libida.dylib` symbols (not idalib-only)
- 4.18.2. Implementation in `address.cpp` to avoid idalib link contamination [F231]
  - 4.18.2.1. `database.cpp` pulls idalib-only symbols (`init_library`, `open_database`)
  - 4.18.2.2. Plugin link units referencing `processor_id()` would fail if in `database.cpp`
  - 4.18.2.3. Declared in `database.hpp`, implemented in `address.cpp` (no idalib deps)
- 4.18.3. Typed processor-id surface should mirror the full current SDK enum set: `ProcessorId` now tracks `PLFM_*` coverage through `PLFM_MCORE` so `processor()` avoids subset-staleness for non-mainstream modules [F259]

---

### 5. Widget / UI System
- 5.1. Widget Identity and Lifecycle
  - 5.1.1. `TWidget*` stable for widget lifetime [F47]
    - 5.1.1.1. Handle-based subscriptions compare `TWidget*` pointers
    - 5.1.1.2. Opaque `Widget` stores `void*` + monotonic `uint64_t` id for cross-callback identity
  - 5.1.2. Title-only widget callbacks insufficient for complex multi-panel plugins [F43]
    - 5.1.2.1. Titles aren't stable identities
    - 5.1.2.2. No per-instance lifecycle tracking
    - 5.1.2.3. Surface opaque widget handles in notifications
  - 5.1.3. `get_widget_title()` takes `(qstring *buf, TWidget *widget)` [F23]
    - 5.1.3.1. NOT single-arg returning `const char*`
    - 5.1.3.2. Changed from older SDKs
- 5.2. Dock Widget System
  - 5.2.1. SDK dock constants: `WOPN_DP_FLOATING` (not `WOPN_DP_FLOAT`) [F45]
    - 5.2.1.1. Defined in `kernwin.hpp` as `DP_*` shifts by `WOPN_DP_SHIFT`
    - 5.2.1.2. `WOPN_RESTORE` restores size/position
    - 5.2.1.3. `display_widget()` takes `(TWidget*, uint32 flags)`
  - 5.2.2. Qt plugins need underlying host container for `QWidget` embedding [F50]
    - 5.2.2.1. entropyx casts `TWidget*` to `QWidget*`
    - 5.2.2.2. `ida::ui::Widget` is opaque, no container attachment
    - 5.2.2.3. Solution: `ui::with_widget_host(Widget&, callback)` with `void*` host pointer [F51]
    - 5.2.2.4. Scoped callback over raw getter reduces accidental long-lived toolkit pointer storage
- 5.3. View Events
  - 5.3.1. `view_curpos` event: no `va_list` payload [F46]
    - 5.3.1.1. Get position via `get_screen_ea()`
    - 5.3.1.2. Differs from `ui_screen_ea_changed` which passes `(new_ea, prev_ea)` in `va_list`
  - 5.3.2. Generic UI/VIEW routing needs token-family partitioning [F53]
    - 5.3.2.1. UI (`< 1<<62`), VIEW (`[1<<62, 1<<63)`), composite (`>= 1<<63`)
    - 5.3.2.2. For safe unsubscribe of composite subscriptions
- 5.4. Custom Viewer
  - 5.4.1. SDK custom viewer lifetime: `create_custom_viewer()` relies on caller-provided line buffer/place objects remaining valid for widget lifetime [F67]
    - 5.4.1.1. Store per-viewer state in wrapper-managed lifetime storage
    - 5.4.1.2. Erase on close
- 5.5. Plugin Bootstrap
  - 5.5.1. `plugin_t PLUGIN` static init: must use char arrays (not `std::string::c_str()`) [F48]
    - 5.5.1.1. Avoids cross-TU init ordering issues
    - 5.5.1.2. Static char buffers populated at `idax_plugin_init_()` time
    - 5.5.1.3. `IDAX_PLUGIN` macro registers factory via `make_plugin_export()`
    - 5.5.1.4. `plugin_t PLUGIN` lives in `plugin.cpp` (compiled into `libidax.a`)
  - 5.5.2. `make_plugin_descriptor()` referenced but no public export helper existed [F44]
    - 5.5.2.1. Added explicit descriptor/export helper bridging `Plugin` subclasses to IDA entrypoints
- 5.6. Action Context
  - 5.6.1. `action_activation_ctx_t` carries many SDK pointers [F52]
    - 5.6.1.1. Normalize only stable high-value fields into SDK-free structs
    - 5.6.1.2. Fields: action id, widget title/type, current address/value, selection/xtrn bits, register name
  - 5.6.2. Host bridges: opaque handles [F132]
    - 5.6.2.1. `widget_handle`, `focused_widget_handle`, `decompiler_view_handle`
    - 5.6.2.2. Scoped callbacks `with_widget_host`, `with_decompiler_view_host`
- 5.7. Form API
  - 5.7.1. ida-qtform parity: `ida::ui::with_widget_host()` sufficient for Qt panel embedding [F85]
  - 5.7.2. Added markup-only `ida::ui::ask_form(std::string_view)` for form preview/test [F86]
    - 5.7.2.1. Without raw SDK varargs
    - 5.7.2.2. Add typed argument binding APIs later if needed

---

### 6. Decompiler / Hex-Rays
- 6.1. Ctree System
  - 6.1.1. `apply_to()`/`apply_to_exprs()` dispatch through `HEXDSP` runtime function pointers [F22]
    - 6.1.1.1. No link-time dependency
  - 6.1.2. `CV_POST` enables `leave_*()` callbacks [F22]
  - 6.1.3. `CV_PRUNE` via `prune_now()` skips children [F22]
  - 6.1.4. `citem_t::is_expr()` returns `op <= cot_last` (69) [F22]
  - 6.1.5. `treeitems` populated after `get_pseudocode()`, maps line indices to `citem_t*` [F22]
  - 6.1.6. `cfunc_t::hdrlines` is offset between treeitems indices and pseudocode line numbers [F22]
- 6.2. Move-Only Semantics
  - 6.2.1. `DecompiledFunction` is move-only (`cfuncptr_t` is refcounted) [F35]
    - 6.2.1.1. `std::expected<DecompiledFunction, Error>` also non-copyable
    - 6.2.1.2. Test macros using `auto _r = (expr)` must be replaced with reference-based checks
- 6.3. Variable Retype Persistence
  - 6.3.1. Uses `modify_user_lvar_info(..., MLI_TYPE, ...)` with stable locator [F69]
    - 6.3.1.1. In-memory type tweaks alone are insufficient
    - 6.3.1.2. Route through saved-user-info updates
    - 6.3.1.3. Add refresh + re-decompile checks
  - 6.3.2. Error category variance (`NotFound` vs `SdkFailure`) across backends [F194]
    - 6.3.2.1. Tests should assert general failure semantics unless category is contractually stable
- 6.4. Decompile Failure Details
  - 6.4.1. Structured via `DecompileFailure` and `decompile(address, &failure)` [F89]
    - 6.4.1.1. Failure address + description
- 6.5. Microcode Retrieval
  - 6.5.1. Exposed via `DecompiledFunction::microcode()` and `microcode_lines()` [F87]
- 6.6. Call-Subexpression Accessors
  - 6.6.1. `ExpressionView` now includes `call_callee`, `call_argument(index)` alongside `call_argument_count` [F104]
- 6.7. Interactive View Sessions
  - 6.7.1. Stable identity via `view_from_host` (opaque handle derivation) [F193]
  - 6.7.2. Enables reusable rename/retype/comment/save/refresh workflows without exposing `vdui_t`/`cfunc_t` [F193]

---

### 7. Microcode Write-Path / Lifter Infrastructure
- 7.1. Filter Registration
  - 7.1.1. `register_microcode_filter`/`unregister_microcode_filter` [F117]
  - 7.1.2. `MicrocodeContext`/`MicrocodeApplyResult`/`ScopedMicrocodeFilter` [F117]
- 7.2. Low-Level Emit Helpers
  - 7.2.1. `MicrocodeContext` operand/register/memory helpers [F118]
    - 7.2.1.1. `load_operand_register` / `load_effective_address_register`
    - 7.2.1.2. `store_operand_register` / `emit_move_register`
    - 7.2.1.3. `emit_load_memory_register` / `emit_store_memory_register`
    - 7.2.1.4. `emit_helper_call`
  - 7.2.2. Low-level emits default to tail insertion [F181]
    - 7.2.2.1. Policy-aware variants added: `emit_noop/move/load/store_with_policy`
    - 7.2.2.2. Route all emits through shared reposition logic
  - 7.2.3. Wide-operand UDT marking [F182, F183]
    - 7.2.3.1. `mark_user_defined_type` overloads for move/load/store emit (with and without policy)
    - 7.2.3.2. `store_operand_register(..., mark_user_defined_type)` overload
- 7.3. Typed Helper-Call Arguments
  - 7.3.1. `MicrocodeValueKind` / `MicrocodeValue` [F119]
    - 7.3.1.1. Integer widths 1/2/4/8
    - 7.3.1.2. `Float32Immediate` / `Float64Immediate` [F121]
    - 7.3.1.3. `ByteArray` with explicit-location enforcement [F126]
    - 7.3.1.4. `Vector` with typed element width/count/sign/floating controls [F128]
    - 7.3.1.5. `TypeDeclarationView` parsed via `parse_decl` [F129]
    - 7.3.1.6. `LocalVariable` with `local_variable_index`/`offset` [F175]
    - 7.3.1.7. `BlockReference` / `NestedInstruction` for richer callarg mop authoring [F192]
  - 7.3.2. `emit_helper_call_with_arguments[_to_register]` [F119]
  - 7.3.3. Immediate typed-argument with optional `type_declaration` [F184]
    - 7.3.3.1. Parse/size validation + width inference when byte width omitted
- 7.4. Helper-Call Options
  - 7.4.1. `MicrocodeCallOptions` / `MicrocodeCallingConvention` [F120]
  - 7.4.2. `emit_helper_call_with_arguments_and_options[_to_register_and_options]` [F120]
  - 7.4.3. `insert_policy` reuses `MicrocodeInsertPolicy` [F140]
  - 7.4.4. Default `solid_argument_count` inference from argument list when omitted [F147]
  - 7.4.5. Auto-stack placement controls [F148]
    - 7.4.5.1. `auto_stack_start_offset` / `auto_stack_alignment`
    - 7.4.5.2. Non-negative start, power-of-two positive alignment
- 7.5. Argument Locations
  - 7.5.1. `MicrocodeValueLocation` (register/stack-offset) with auto-promotion [F122]
  - 7.5.2. Register-pair and register-with-offset forms [F123]
  - 7.5.3. Static-address placement (`set_ea`) with `BadAddress` validation [F124]
  - 7.5.4. Scattered/multi-part placement via `MicrocodeLocationPart` [F125]
    - 7.5.4.1. Per-part validation (offset/size/kind constraints)
  - 7.5.5. Register-relative placement (`ALOC_RREL` via `consume_rrel`) [F127]
    - 7.5.5.1. Base-register validation
  - 7.5.6. Explicit-location hinting via `mark_explicit_locations` [F121]
- 7.6. Callinfo Shaping
  - 7.6.1. FCI Flags [F130]
    - 7.6.1.1. `mark_dead_return_registers` → `FCI_DEAD`
    - 7.6.1.2. `mark_spoiled_lists_optimized` → `FCI_SPLOK`
    - 7.6.1.3. `mark_synthetic_has_call` → `FCI_HASCALL`
    - 7.6.1.4. `mark_has_format_string` → `FCI_HASFMT`
  - 7.6.2. Scalar field hints [F131]
    - 7.6.2.1. `callee_address`, `solid_argument_count`
    - 7.6.2.2. `call_stack_pointer_delta`, `stack_arguments_top`
  - 7.6.3. `return_type_declaration` parsed via `parse_decl` [F135]
    - 7.6.3.1. Invalid declarations fail with `Validation`
  - 7.6.4. Function role + return-location semantic hints [F139]
    - 7.6.4.1. `MicrocodeFunctionRole` / `function_role` / `return_location`
  - 7.6.5. Declaration-driven register-return typing [F142]
    - 7.6.5.1. Size-match validation, UDT marking for wider destinations
  - 7.6.6. Declaration-driven register-argument typing [F143]
    - 7.6.6.1. Parse validation, size-match, integer-width fallback
  - 7.6.7. Argument metadata [F144]
    - 7.6.7.1. `argument_name`, `argument_flags`, `MicrocodeArgumentFlag`
    - 7.6.7.2. `FAI_RETPTR` → `FAI_HIDDEN` normalization
  - 7.6.8. List shaping [F170]
    - 7.6.8.1. Register-list and visible-memory controls
    - 7.6.8.2. Passthrough registers must be subset of spoiled [F185]
    - 7.6.8.3. Validate subset semantics; return `Validation` on mismatch
    - 7.6.8.4. Return registers auto-merged into spoiled
  - 7.6.9. Declaration-driven vector element typing [F171]
    - 7.6.9.1. Element-size/count/total-width constraints validated together
    - 7.6.9.2. Derive missing count from total width when possible
  - 7.6.10. Coherence testing: success-path helper-call emissions in filters can trigger `INTERR` [F186]
    - 7.6.10.1. Prefer validation-first probes for deterministic assertions
  - 7.6.11. Probe-level callinfo enrichment now applies compare/rotate semantic role hints and helper argument-name metadata across variadic, AVX scalar/packed, and VMX helper paths [F199, F200]
  - 7.6.12. Probe-level helper-return typing now applies declaration-driven return types for stable scalar/integer helper families (`vmread` register destinations, scalar `vmin*`/`vmax*`/`vsqrt*`) [F201]
  - 7.6.13. Probe-level helper-return location hints now apply explicit register `return_location` metadata on stable register-destination helper flows [F202]
  - 7.6.14. Hardening probes now validate callinfo hint routes (micro/register success-or-backend-failure tolerance + explicit invalid-location/type-size validation checks) [F203]
  - 7.6.15. Hardening validation now asserts cross-route callinfo contracts (`to_micro_operand`, `to_register`, `to_operand`) for invalid return-location and return-type-size inputs [F205]
  - 7.6.16. Hardening validation now covers global-destination location contracts (valid static-address success-or-backend-failure tolerance + invalid `BadAddress` static-location validation checks) [F208]
  - 7.6.17. Cross-route hardening now includes static-location `BadAddress` validation in `to_operand` helper routes to keep location contracts consistent across emission APIs [F209]
  - 7.6.18. Register-destination callinfo hints now use validation-safe retry semantics (retry without explicit `return_location` when backend returns validation) to preserve stable handling on compare helper routes [F210]
  - 7.6.19. Cross-route hardening now includes global-destination return-type-size validation checks to keep type-size contracts aligned across helper emission APIs [F211]
  - 7.6.20. Compare helper micro-routes now use a three-step validation-safe retry ladder (full location+declaration hints -> declaration-only hints -> base compare options) to preserve semantics first while degrading safely on backend validation rejection [F213]
  - 7.6.21. Direct compare `to_operand` fallback now also applies validation-safe retry with base compare options to reduce backend-variant validation failures on degraded routes [F214]
  - 7.6.22. Degraded compare `to_operand` routes now treat residual validation failures as non-fatal not-handled outcomes after retry exhaustion, while preserving hard SDK/internal failure handling [F215]
  - 7.6.23. Compare helper routes now apply validation-safe base-options retry consistently across resolved-memory micro, register micro, temporary-register bridge, and degraded `to_operand` paths; temporary-register `store_operand_register` writeback now treats `Validation`/`NotFound` as degradable while preserving hard SDK/internal failures [F216]
  - 7.6.24. Direct register-destination compare helper routes now apply the same validation-safe retry ladder (location+declaration hints -> declaration-only -> base compare options), and residual validation rejection degrades to not-handled while preserving hard SDK/internal failures [F217]
  - 7.6.25. Temporary-register compare fallback now guards `std::expected` error access (`!status` before `.error()`) after degradable writeback outcomes, preventing invalid `.error()` reads on success-path states [F218]
  - 7.6.26. Compare helper degraded/direct destination routes now treat residual `NotFound` outcomes as non-fatal not-handled after retry exhaustion, while preserving hard SDK/internal failure handling [F219]
  - 7.6.27. Compare helper temporary-register bridge now uses typed `_to_micro_operand` destination routing instead of `_to_register`, since allocated temporary register ids are known and expressible as `MicrocodeOperand` with `kind = Register`; this eliminates the last non-typed helper-call destination in the lifter probe [F220]
- 7.7. Generic Typed Instruction Emission
  - 7.7.1. Dominant gap identified: generic microcode instruction authoring (opcode+operand construction) [F136]
  - 7.7.2. `MicrocodeOpcode` covering `mov/add/xdu/ldx/stx/fadd/fsub/fmul/fdiv/i2f/f2f/nop` [F137]
  - 7.7.3. `MicrocodeOperandKind` [F137]
    - 7.7.3.1. `RegisterPair` / `GlobalAddress` / `StackVariable` / `HelperReference` [F172]
    - 7.7.3.2. `BlockReference` + validated `block_index` [F173]
    - 7.7.3.3. `NestedInstruction` + recursive validation/depth limiting [F174]
    - 7.7.3.4. `LocalVariable` with `local_variable_index`/`offset` [F175]
  - 7.7.4. `MicrocodeOperand` / `MicrocodeInstruction` [F137]
  - 7.7.5. `emit_instruction` / `emit_instructions` [F137]
  - 7.7.6. Placement-policy controls [F138]
    - 7.7.6.1. `MicrocodeInsertPolicy` (`Tail`/`Beginning`/`BeforeTail`)
    - 7.7.6.2. `emit_instruction_with_policy` / `emit_instructions_with_policy`
    - 7.7.6.3. SDK: `mblock_t::insert_into_block(new, existing)` inserts after `existing`; `nullptr` inserts at beginning
  - 7.7.7. Extended typed opcodes
    - 7.7.7.1. `BitwiseAnd`/`BitwiseOr`/`BitwiseXor` [F165]
    - 7.7.7.2. `ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic` [F165]
    - 7.7.7.3. `Subtract` [F166]
    - 7.7.7.4. `Multiply` [F168]
- 7.8. Temporary Register Allocation
  - 7.8.1. `MicrocodeContext::allocate_temporary_register(byte_width)` mirrors `mba->alloc_kreg` [F146]
- 7.9. Local Variable Context
  - 7.9.1. `MicrocodeContext::local_variable_count()` for availability checks [F176]
  - 7.9.2. Gate usage on `count > 0` with no-op fallback [F176]
  - 7.9.3. Consolidated `try_emit_local_variable_self_move` helper [F177]
    - 7.9.3.1. Reused across `vzeroupper`, `vmxoff`
- 7.10. Microcode Runtime Stability
  - 7.10.1. Aggressive callinfo hints in hardening filters can trigger `INTERR: 50765` [F141]
    - 7.10.1.1. Keep integration coverage validation-focused
    - 7.10.1.2. Heavy emission stress for dedicated scenarios
- 7.11. Maturity / Outline / Cache
  - 7.11.1. Maturity subscriptions: `on_maturity_changed`/`unsubscribe`/`ScopedSubscription` [F116]
  - 7.11.2. Outline/cache helpers [F116]
    - 7.11.2.1. `function::is_outlined`/`set_outlined`
    - 7.11.2.2. `decompiler::mark_dirty`/`mark_dirty_with_callers`
- 7.12. Rewrite Lifecycle
  - 7.12.1. Tracking last-emitted instruction plus block instruction-count query enables additive remove/rewrite workflows [F189]
    - 7.12.1.1. Avoids exposing raw microblock internals
  - 7.12.2. Deterministic mutation via `has_instruction_at_index` / `remove_instruction_at_index` [F191]
    - 7.12.2.1. Allows targeting beyond tracked-last-emitted-only flows

---

### 8. AVX/VMX Lifter Probe
- 8.1. VMX Subset
  - 8.1.1. No-op `vzeroupper` [F145]
  - 8.1.2. Helper-call lowering for VMX family [F145]
    - 8.1.2.1. `vmxon/vmxoff/vmcall/vmlaunch/vmresume`
    - 8.1.2.2. `vmptrld/vmptrst/vmclear/vmread/vmwrite`
    - 8.1.2.3. `invept/invvpid/vmfunc`
- 8.2. AVX Scalar Subset
  - 8.2.1. Math: `vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd` [F149]
  - 8.2.2. Conversion: `vcvtss2sd`, `vcvtsd2ss` [F149]
  - 8.2.3. Extended: `vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`, `vmovss/vmovsd` [F151]
  - 8.2.4. Scalar subset XMM-oriented [F150]
    - 8.2.4.1. Decoded `Operand` value objects lack rendered width text
    - 8.2.4.2. AVX lowering assumes XMM-width destination copy
  - 8.2.5. Memory-destination handling: load destination register before checking memory-destination creates unnecessary failure [F152]
    - 8.2.5.1. Handle memory-dest stores first (`store_operand_register`), then resolve register-target paths
- 8.3. AVX Packed Subset
  - 8.3.1. Math: `vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd` [F153]
  - 8.3.2. Moves: `vmov*` packed via typed emission + store-aware handling [F153]
  - 8.3.3. Width inference via `ida::instruction::operand_text(address, index)` heuristics [F154]
    - 8.3.3.1. `xmm`/`ymm`/`zmm` tokens, `*word` tokens enable width-aware lowering
    - 8.3.3.2. **Refinement**: Structured `instruction::Operand` metadata (`byte_width`, `register_name`, `register_category`) removes dependence on `operand_text()` parsing [F190]
    - 8.3.3.3. `op_t::dtype` + `get_dtype_size(...)` provide structured operand byte widths [F187]
  - 8.3.4. Min/max/sqrt: `vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd` [extended]
  - 8.3.5. Helper-call return fallback: byte-array `tinfo_t` for packed destination widths exceeding integer scalar [F155]
- 8.4. AVX Packed Conversions
  - 8.4.1. Typed emission: `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd` [F156]
  - 8.4.2. Helper-call fallback: `vcvt*2dq/udq/qq/uqq`, truncating forms [F157]
    - 8.4.2.1. Don't map to current typed opcodes; use helper-call fallback
- 8.5. AVX Packed Bitwise / Shift / Permute / Blend
  - 8.5.1. Bitwise: typed opcodes added, helper fallback for `andn`/rotate/exotic [F165]
  - 8.5.2. Shift/rotate (`vps*`, `vprol*`, `vpror*`): mixed register/immediate shapes → helper-call [F161]
  - 8.5.3. Permute/blend: no direct typed opcodes → helper-call fallback [F160]
- 8.6. AVX Packed Integer Arithmetic
  - 8.6.1. `vpadd*`/`vpsub*` direct typed emission; saturating (`vpadds*`/`vpaddus*`/`vpsubs*`/`vpsubus*`) via helper [F166, F167]
  - 8.6.2. `vpmulld`/`vpmullq` typed direct; `vpmullw`/`vpmuludq`/`vpmaddwd` lane-specific → helper [F168]
  - 8.6.3. Two-operand encodings: treat operand 0 as both dest and left source [F169]
- 8.7. Variadic Helper Fallback Architecture
  - 8.7.1. Broad families (`vaddsub*`/`vhadd*`/`vhsub*`) via helper-call [F158]
  - 8.7.2. Mixed register/immediate forwarding via variadic helper [F159]
  - 8.7.3. Memory-operand: attempt effective-address extraction when register fails → typed pointer argument [F163]
  - 8.7.4. Compare mask-register destinations: not representable in current register-load helpers [F164]
    - 8.7.4.1. Lower deterministically by routing through temporary register + operand writeback (`store_operand_register`) [F188]
  - 8.7.5. Unsupported operand shapes degrade to `NotHandled` not hard errors [F162]
    - 8.7.5.1. Keeps decompiler stable while coverage grows
  - 8.7.6. Widened misc families [extended]
    - 8.7.6.1. gather/scatter/compress/expand/popcnt/lzcnt/gfni/pclmul/aes/sha
    - 8.7.6.2. movnt/movmsk/pmov/pinsert/extractps/insertps/pack/phsub/fmaddsub
  - 8.7.7. Helper-return destination routing now prefers typed micro-operands (register/resolved-memory `GlobalAddress`) with operand-writeback fallback for unresolved shapes [F196, F198]
    - 8.7.7.1. Integration hardening now exercises both typed helper-return destination success routes (`Register`, `GlobalAddress`) in `decompiler_storage_hardening` with post-emit cleanup via `remove_last_emitted_instruction` [F197]
    - 8.7.7.2. Compare helper operand-writeback fallback is now explicitly constrained to unresolved destination shapes (mask register or unresolved-memory target) [F204]
    - 8.7.7.3. Compare helper routing now attempts typed register-destination micro-operand emission from structured `Operand::register_id()` before unresolved-shape operand-writeback fallback [F206]
    - 8.7.7.4. Compare helper routing now applies static-address `return_location` hints for resolved-memory `GlobalAddress` micro-routes with validation-safe retry fallback to no-location options [F207]
    - 8.7.7.5. Compare helper register-destination micro-routes now also use validation-safe retry fallback to no-location options when explicit register `return_location` hints are rejected [F210]
    - 8.7.7.6. Compare helper unresolved-shape routing now attempts helper-return to temporary register plus `store_operand_register` writeback before direct `to_operand` fallback [F212]
    - 8.7.7.7. Compare helper micro-routes now retry with base compare options when declaration/location hints continue to fail validation, reducing false-negative handling loss on backend variance [F213]
    - 8.7.7.8. Compare helper degraded `to_operand` path now retries with base compare options when declaration/location hints fail validation, reducing avoidable fallback loss on backend variance [F214]
    - 8.7.7.9. Compare helper degraded `to_operand` path now degrades residual validation rejection to non-fatal not-handled outcome after retry exhaustion, while preserving hard failure signals for SDK/internal categories [F215]
    - 8.7.7.10. Compare helper temporary-register bridge and typed micro routes now use the same validation-safe base-options retry policy, and writeback-level `Validation`/`NotFound` now degrades to not-handled instead of hard failure [F216]
    - 8.7.7.11. Direct register-destination compare helper route now mirrors the same validation-safe retry ladder and not-handled degradation semantics used by other compare destination routes [F217]
    - 8.7.7.12. Temporary-register bridge fallback now explicitly guards error-category reads behind `!temporary_helper_status` after degradable writeback outcomes, avoiding invalid success-path `.error()` access while preserving fallback progression [F218]
    - 8.7.7.13. Compare helper degraded `to_operand` and direct register-destination routes now also degrade residual `NotFound` outcomes to not-handled after retries, preserving hard SDK/internal categories [F219]
    - 8.7.7.14. Compare helper temporary-register bridge now emits to typed `_to_micro_operand` destination (Register kind) instead of `_to_register`, eliminating the last non-typed helper-call destination path in the lifter probe; all remaining operand-writeback sites are genuinely irreducible (unresolved shapes, vmov memory stores) [F220]
- 8.8. SSE Passthrough
  - 8.8.1. `vcomiss/vcomisd/vucomiss/vucomisd/vpextrb/w/d/q/vcvttss2si/vcvttsd2si/vcvtsd2si/vcvtsi2ss/vcvtsi2sd` returned to IDA's native handling via `match()` returning `false` [F223]
- 8.9. K-Register NOP Handling
  - 8.9.1. K-register manipulation (`kmov*`, `kadd*`, `kand*`, etc.) and mask-destination instructions emit NOP [F224]
  - 8.9.2. Pragmatic: decompiler microcode cannot represent k-register operations natively
- 8.10. vmovd/vmovq Dedicated Handler
  - 8.10.1. GPR/memory→XMM: native `ZeroExtend` (`m_xdu`) microcode for correct zero-extension semantics [F221]
  - 8.10.2. XMM→GPR/memory: simple `Move`/`store_operand_register` extraction [F221]
  - 8.10.3. Removed from `is_packed_helper_misc_mnemonic()` set
- 8.11. AVX-512 Opmask Wiring
  - 8.11.1. API surface: `MicrocodeContext::has_opmask()`, `is_zero_masking()`, `opmask_register_number()` [F222]
  - 8.11.2. Helper-call paths: masking wired uniformly across normal variadic, compare, store-like, scalar min/max/sqrt, packed sqrt/addsub/min/max, and helper-fallback conversions [F225]
  - 8.11.3. Native microcode paths: typed binary/conversion/move/math skip to helper-call fallback when masking present (native microcode cannot represent per-element masking) [F225]
  - 8.11.4. Masking protocol: helper name suffixed `_mask`/`_maskz`, merge-source register arg (merge-masking only), mask register number as unsigned immediate
- 8.12. Mnemonic Coverage Expansion
  - 8.12.1. FMA (`vfmadd*/vfmsub*/vfnmadd*/vfnmsub*`), IFMA (`vpmadd52*`), VNNI (`vpdpbusd*/vpdpwssd*`), BF16, FP16
  - 8.12.2. Cache control (`clflushopt/clwb`), integer unpack (`vpunpck*`), shuffles, packed integer minmax/avg/abs/sign
  - 8.12.3. Additional integer multiply, multishift, SAD, byte-shift (`vpslldq/vpsrldq`)
  - 8.12.4. Scalar approx/round/getexp/getmant/fixupimm/scalef/range/reduce
- 8.13. Vector Type Declaration Parity
  - 8.13.1. Original uses `get_type_robust(size, is_int, is_double)` → `get_vector_type` → named `tinfo_t` lookup (`__m128`/`__m256i`/`__m512d` etc.) with UDT fallback [F226]
  - 8.13.2. Port uses `vector_type_declaration(byte_width, is_integer, is_double)` → `return_type_declaration` string resolved via `parse_decl` against same type library
  - 8.13.3. Functionally equivalent: both resolve named types when available, both produce correct sizes
  - 8.13.4. Applied across all helper-call return paths: variadic, compare, packed sqrt/addsub/min/max, helper-fallback conversions
- 8.14. Deep Mutation Breadth Audit (B-LIFTER-MICROCODE Closure)
  - 8.14.1. All 14 SDK mutation pattern categories cross-referenced against wrapper API + port usage [F227]
  - 8.14.2. 13/14 fully covered, 1/14 (post-emit field mutation) functionally equivalent via remove+re-emit
  - 8.14.3. Port quantitative evidence: 26 helper-call sites, 7 typed emission sites, 37 operand loads, 300+ mnemonics
  - 8.14.4. No new wrapper APIs required for lifter-class microcode transformation ports
- 8.15. Plugin-Shell Feature Parity
  - 8.15.1. Separate "Mark as inline" / "Mark as outline" actions with context-sensitive enablement [F228]
    - 8.15.1.1. Original uses `action_state_t` (`AST_ENABLE/DISABLE_FOR_WIDGET`) in `update()` callback
    - 8.15.1.2. Port uses `enabled_with_context` lambdas querying `ida::function::is_outlined()`
    - 8.15.1.3. "Mark as inline" enabled when `FUNC_OUTLINE` NOT set; "Mark as outline" enabled when IS set
  - 8.15.2. Debug printing toggle with maturity-driven dumps [F229]
    - 8.15.2.1. Original: `hexrays_debug_callback` for `hxe_maturity` at `MMAT_GENERATED`/`MMAT_PREOPTIMIZED`/`MMAT_LOCOPT`
    - 8.15.2.2. Port: `ida::decompiler::on_maturity_changed()` with `ScopedSubscription`
    - 8.15.2.3. Maturity mapping: `Built`=`MMAT_GENERATED`, `Trans1`=`MMAT_PREOPTIMIZED`, `Nice`=`MMAT_LOCOPT`
    - 8.15.2.4. Subscription installed/removed dynamically via `toggle_debug_printing()`
  - 8.15.3. 32-bit YMM skip guard [F230]
    - 8.15.3.1. Original: `inf_is_64bit()` + `op.dtype == dt_byte32` in `match()`
    - 8.15.3.2. Port: `function::at(address)->bitness() == 64` with segment fallback + `Operand::byte_width() == 32`
    - 8.15.3.3. Avoids Hex-Rays `INTERR 50920` for 256-bit kregs in 32-bit mode
  - 8.15.4. Processor ID crash guard — CLOSED [F231]
    - 8.15.4.1. Original: `PH.id != PLFM_386` in `isMicroAvx_avail()` / `isVMXLifter_avail()`
    - 8.15.4.2. Port: `ida::database::processor_id() != 0` in `install_vmx_lifter_filter()`
    - 8.15.4.3. Prevents IDA crash when interacting with AVX/VMX in non-x86 processor modes
    - 8.15.4.4. All behavioral differences vs. original: CLOSED

---

### 9. Debugger / Appcall
- 9.1. Debugger Backend
  - 9.1.1. Backend discovery: `available_backends` + `load_backend` [F178]
  - 9.1.2. Exposed in `ida::debugger`; auto-load in tools before launch
  - 9.1.3. Debugger request queue [F66]
    - 9.1.3.1. `request_*` APIs enqueue, need `run_requests()` to dispatch
    - 9.1.3.2. Direct `step_*`/`run_to`/`suspend_process` execute immediately
    - 9.1.3.3. Mixing styles without flush causes no-op behavior
    - 9.1.3.4. Expose explicit request helpers + `is_request_running()`/`run_requests()`
- 9.2. Appcall Host Issues
  - 9.2.1. macOS (`arm_mac` backend): `start_process` returns 0 but state stays `NoProcess` [F179]
    - 9.2.1.1. Attach returns `-1`, still `NoProcess`
    - 9.2.1.2. Blocked by backend/session readiness, not wrapper API coverage
  - 9.2.2. Queued-request timing: `request_start`/`request_attach` report success while state still `NoProcess` [F180]
    - 9.2.2.1. Perform bounded multi-cycle request draining with settle delays
  - 9.2.3. Attach fallback: `attach_process` returns `-4` across all permutations [F134]
  - 9.2.4. Hold-mode args don't change host outcome [F133]
  - 9.2.5. Appcall with runtime-linked tools: fails cleanly with `dbg_appcall` error 1552 (exit 1) instead of crashing [F110]
  - 9.2.6. Appcall smoke fixture: `ref4` validated safely by calling `int ref4(int *p)` with `p = NULL` [F108]
    - 9.2.6.1. Exercises full request/type/argument/return bridging
  - 9.2.7. Multi-path launch bootstrap: relative/absolute/filename+cwd [F113]
    - 9.2.7.1. Host failures resolve to explicit `start_process failed (-1)`

---

### 10. Lumina
- 10.1. Runtime validation: host reports successful `pull`/`push` smoke [F114]
  - 10.1.1. `requested=1, succeeded=1, failed=0`
- 10.2. `close_server_connection2`/`close_server_connections` declared in SDK but not link-exported [F95]
  - 10.2.1. Keep close wrappers as `Unsupported` until portable close path confirmed

---

### 11. Processor Module Authoring
- 11.1. Processor output: existing modules rely on side-effect callbacks [F64]
  - 11.1.1. Advanced ports need structured text assembly
  - 11.1.2. `OutputContext` and context-driven hooks with fallback defaults
- 11.2. JBC Parity Gaps
  - 11.2.1. `ida::processor::analyze(Address)` returns only instruction size, no typed operand metadata [F80]
    - 11.2.1.1. Full ports must re-decode in multiple callbacks
    - 11.2.1.2. Added optional typed `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`
  - 11.2.2. No wrapper for `set_default_sreg_value` [F81]
    - 11.2.2.1. Added default-segment-register seeding helper
  - 11.2.3. `OutputContext` was text-only (no token/color channels, no mnemonic callback) [F82]
    - 11.2.3.1. Added `OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`
    - 11.2.3.2. Added `output_mnemonic_with_context`

---

### 12. Iterator / Range Semantics
- 12.1. `FunctionIterator::operator*()` returns by value (not reference) [F34]
  - 12.1.1. Range-for must use `auto f` not `auto& f`
  - 12.1.2. Constructs `Function` value from internal SDK state each dereference
  - 12.1.3. Same behavior for `FixupIterator`

---

### 13. Diagnostics & Cross-Cutting
- 13.1. Diagnostics counters: plain shared struct creates data-race risk [F55]
  - 13.1.1. Use atomic counter fields and snapshot reads
- 13.2. Compile-only parity drift risk [F56]
  - 13.2.1. When headers evolve quickly, compile-only tests can lag
  - 13.2.2. Expand `api_surface_parity_test.cpp` with header changes, including overload disambiguation
- 13.3. Cross-cutting/event parity closure [F70]
  - 13.3.1. Can use intentional-abstraction documentation when full raw SDK mirroring is counter to wrapper goals
  - 13.3.2. Keep `partial` with rationale + expansion triggers
- 13.4. Parity Audit Depth [F54]
  - 13.4.1. Broad domain coverage exists, but depth is uneven (`partial` vs full SDK breadth)
  - 13.4.2. Closing parity needs matrix-driven checklist with per-domain closure criteria

---

### 14. Port Audits & Migration Evidence
- 14.1. entropyx/ida-port Gaps [F42]
  - 14.1.1. Missing dockable custom widget hosting → closed
  - 14.1.2. Missing HT_VIEW/UI notification coverage → closed
  - 14.1.3. Missing `jumpto` → `ui::jump_to` added
  - 14.1.4. Missing segment-type introspection → `Segment::type()`/`set_type()` added
  - 14.1.5. Missing plugin bootstrap helper → `IDAX_PLUGIN` macro added
- 14.2. ida-qtform Port [F85, F86]
  - 14.2.1. `ida::ui::with_widget_host()` sufficient for Qt panel embedding
  - 14.2.2. Markup-only `ask_form` for preview/test
- 14.3. idalib-dump Port [F87-F92]
  - 14.3.1. Microcode retrieval added
  - 14.3.2. Structured decompile-failure details added
  - 14.3.3. Plugin-load policy added (`RuntimeOptions` + `PluginLoadPolicy`)
  - 14.3.4. Gap: no headless plugin-load policy controls → closed [F88, F92]
  - 14.3.5. Gap: no public Lumina facade → closed [F90]
- 14.4. ida2py Port [F96-F106]
  - 14.4.1. Gap: no user-name enumeration API → added `ida::name` iterators [F96, F102]
  - 14.4.2. Gap: `TypeInfo` lacks decomposition → added [F97, F103]
    - 14.4.2.1. `is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`
  - 14.4.3. Gap: no generic typed-value facade → added `read_typed`/`write_typed` [F98, F105]
  - 14.4.4. Gap: call subexpressions lack typed accessors → added [F99, F104]
  - 14.4.5. Gap: no Appcall/executor abstraction → added [F100, F106]
- 14.5. Lifter Port [F115-F186]
  - 14.5.1. Read-oriented decompiler only; no write-path hooks initially [F115]
  - 14.5.2. Plugin shell/action/pseudocode-popup workflows verified
  - 14.5.3. Remaining blocker: deeper tmop semantics and advanced decompiler write-path surfaces [B-LIFTER-MICROCODE]
- 14.6. Runtime Caveats
  - 14.6.1. idalib tool examples exit with signal 11 in this environment [F101]
    - 14.6.1.1. Only build/CLI-help validation available
    - 14.6.1.2. Functional checks need known-good idalib host
  - 14.6.2. README drift risk: absolute coverage wording, stale surface counts [F91]

---

### 15. Architecture & Design Decisions (Locked)
- 15.1. Language: C++23
- 15.2. Packaging: Hybrid (header-only thin wrappers + compiled library for complex behavior)
- 15.3. Public API: Fully opaque (no `.raw()` escape hatches)
- 15.4. Public string type: `std::string` (input optimization via `std::string_view`)
- 15.5. Scope: Full (plugins + loaders + processor modules)
- 15.6. Error model: `std::expected<T, ida::Error>` / `std::expected<void, ida::Error>`
  - 15.6.1. ErrorCategory: Validation, NotFound, Conflict, Unsupported, SdkFailure, Internal
- 15.7. Engineering constraints
  - 15.7.1. Prefer straightforward and portable implementations
  - 15.7.2. Avoid compiler-specific intrinsics unless unavoidable
  - 15.7.3. Avoid heavy bit-level micro-optimizations that reduce readability
  - 15.7.4. Prefer SDK helpers (including `pro.h`) for portability/clarity
  - 15.7.5. For batch analysis: prefer `idump <binary>` over `idat`
- 15.8. API Philosophy
  - 15.8.1. Public API simplicity must preserve capability; advanced options must remain in structured form [F9]

---

### 16. Testing Strategy
- 16.1. Validation profiles: `full`, `unit`, `compile-only`
- 16.2. 16/16 test targets passing (232/232 smoke checks + 15 dedicated suites)
- 16.3. idalib-based integration tests with real IDA dylibs
  - 16.3.1. Decompiler edit persistence mutates fixture `.i64` files [F195]
    - 16.3.1.1. Prefer non-persisting validation probes or explicit fixture restore for worktree hygiene
- 16.4. Compile-only API surface parity check as mandatory for every new public symbol [F56]
- 16.5. Three-profile validation via `scripts/run_validation_matrix.sh`
- 16.6. Example addon compilation enabled in CI for regression coverage [F79]
- 16.7. Linux GCC 13.3.0 passes on Ubuntu 24.04 [F71]
- 16.8. Linux Clang 19+ required for `std::expected` support [F111]

---

### 17. Process & Methodology
- 17.1. Documentation
  - 17.1.1. Migration docs are as critical as API design for adoption [F10]
  - 17.1.2. Interface-level API sketches must be present (not just summaries) to avoid implementation ambiguity [F11]
  - 17.1.3. Real-world port additions must update all documentation index surfaces in one pass (README parity/doc tables, API reference, topology/coverage matrices, quickstart/example links, dedicated audit doc) to prevent drift [F244]

---

### 18. SDK Color/Lines System
- 18.1. SDK redefines bare `snprintf` → `dont_use_snprintf` in `pro.h:965`; use `qsnprintf` in src/, `std::snprintf` in examples [F232]
- 18.2. Color tag system uses `COLOR_ON` (byte 0x01) / `COLOR_OFF` (byte 0x02) brackets around single-byte color codes
- 18.3. `COLOR_ADDR` tag (byte 0x05) embeds address metadata as `kColorAddrSize` hex chars within pseudocode lines
- 18.4. Color enum values are specific SDK `color_t` constants, not sequential — must match exactly [F235]
- 18.5. `::tag_remove()`, `::tag_advance()`, `::tag_strlen()` are the SDK functions for stripping/navigating/measuring colored text

### 19. Hexrays Event System (Decompiler Callbacks)
- 19.1. `cfunc_t::get_pseudocode()` returns `const strvec_t&`; modify lines via `cfunc->sv` directly [F233]
- 19.2. `cfuncptr_t` (`qrefcnt_t<cfunc_t>`) lacks `.get()` — use `&*ptr` or `operator->()` [F234]
- 19.3. Event signatures via `va_arg`: `hxe_func_printed` → `(cfunc_t*)`, `hxe_curpos` → `(vdui_t*)`, `hxe_create_hint` → `(vdui_t*, qstring*, int*)`, `hxe_refresh_pseudocode` → `(vdui_t*)` [F238]
- 19.4. `hxe_create_hint` return convention: 1 = show hint, 0 = skip [F238]

### 20. UI Widget/Popup System
- 20.1. Widget type values match `BWN_*` constants — not sequential, follow internal SDK registration order [F236]
- 20.2. `attach_dynamic_action_to_popup` uses `DYNACTION_DESC_LITERAL` (5 args: label, handler, shortcut, tooltip, icon) [F237]
- 20.3. `ui_finish_populating_widget_popup` receives `(TWidget*, TPopupMenu*, const action_activation_ctx_t*)` [F239]

### 21. Abyss Port Architecture (Phase 11)
- 21.1. Abyss is a Hex-Rays decompiler post-processing filter framework by Dennis Elser (patois)
- 21.2. 8 filters: token_colorizer, signed_ops, hierarchy, lvars_alias, lvars_info, item_sync, item_ctype, item_index
- 21.3. Core dispatch via hexrays hooks (func_printed, maturity, curpos, create_hint, refresh_pseudocode) and UI hooks (finish_populating_widget_popup, get_lines_rendering_info, screen_ea_changed)
- 21.4. Filters modify pseudocode by editing `simpleline_t.line` strings with color tags in `func_printed` event
- 21.5. Port identified and closed 18 API gaps across lines, decompiler, and ui domains
- 21.6. Artifact: `examples/plugin/abyss_port_plugin.cpp` (~845 lines)

### 22. Plugin Build & Link Requirements
- 22.1. `IDAX_PLUGIN(ClassName)` macro is mandatory for all plugin source files; without it the dylib exports no `_PLUGIN` symbol and IDA ignores it [F240]
- 22.2. Static library link granularity is per object file — if any symbol from a `.cpp.o` is pulled in, ALL symbols in that object must resolve [F241]
- 22.3. idalib-only symbols (`init_library`, `open_database`, `close_database`, `enable_console_messages`) are NOT in `libida.dylib`; `save_database` IS [F241]
- 22.4. `database.cpp` was split into `database.cpp` (plugin-safe queries + save) and `database_lifecycle.cpp` (idalib-only init/open/close) to prevent link failures in plugins that use `ida::database` query APIs [F241]
- 22.5. CMake `GLOB_RECURSE` auto-discovers new `.cpp` files in `src/`, so TU splits need no CMakeLists.txt changes

### 23. DrawIDA Port Findings (Phase 12)
- 23.1. DrawIDA (`/Users/int/Downloads/plo/DrawIDA-main`) ports cleanly to existing idax plugin/UI surfaces (`ida::plugin::Plugin`, `ida::ui::create_widget`, `ida::ui::show_widget`, `ida::ui::activate_widget`) with no open parity gaps for draw/text/erase/select + undo/redo/style/clear workflows
- 23.2. Prior plugin-flag ergonomics gap [F242] is closed via `ida::plugin::ExportFlags` + `IDAX_PLUGIN_WITH_FLAGS(...)`; idax keeps `PLUGIN_MULTI` mandatory and layers optional SDK bits through structured flags + `extra_raw_flags` [F245]
- 23.3. Prior host-cast ergonomics gap [F243] is closed via typed host helpers `ida::ui::widget_host_as<T>()` and `ida::ui::with_widget_host_as<T>()`, eliminating repetitive `void*` casts in Qt ports [F246]
- 23.4. Dedicated DrawIDA addon target is wired using `ida_add_plugin(TYPE QT QT_COMPONENTS Core Gui Widgets ...)`, yielding skip-on-missing-Qt behavior with explicit `build_qt` guidance and normal addon build when Qt is available [F247]
- 23.5. Qt6/Homebrew include nuance: use `qevent.h` for `QKeyEvent`/`QMouseEvent` portability (`qkeyevent.h` is not present in that header layout) [F248]

### 24. DriverBuddy Port Findings (Phase 13)
- 24.1. DriverBuddy (`/Users/int/Downloads/plo/DriverBuddy-master`) ports through idax plugin/analysis/search/xref/instruction/type surfaces with no raw SDK usage for core Windows-driver triage workflows (driver classification, dispatch discovery, IOCTL decode) [F250]
- 24.2. Struct-offset operand representation closure: `ida::instruction` now exposes `set_operand_struct_offset(...)` and `set_operand_based_struct_offset(...)` wrappers over SDK `op_stroff`/`op_based_stroff`; on SDK 9.3, named-type TIDs must be resolved via `get_named_type_tid()` (not legacy `get_struc_id`) [F249]
- 24.3. WDF table annotation is achievable in idax by constructing a `TypeInfo` struct schema (`TypeInfo::create_struct` + `add_member` + `save_as`) and applying it at resolved table addresses (`type::apply_named_type` + `name::force_set`) after locating the `KmdfLibrary` marker and dereferencing metadata pointers [F251]
- 24.4. Remaining DriverBuddy migration deltas are non-blocking ergonomics: no one-call standard-type bootstrap equivalent to `Til2Idb(-1, name)`, no stroff-path introspection wrapper (`get_stroff_path`), and no minimal hotkey-only callback helper outside the action system [F252]

### 25. idapcode Port Findings (Phase 14)
- 25.1. idapcode (`/Users/int/Downloads/plo/idapcode-main`) ports cleanly to idax plugin/UI/function/data flows when paired with external Sleigh C++ translation (`examples/plugin/idapcode_port_plugin.cpp`) [F253]
- 25.2. Added database metadata wrappers (`address_bitness`, `is_big_endian`, `abi_name`) plus typed `ProcessorId`/`processor()` to support deterministic architecture-to-Sleigh routing without raw SDK fallback in plugin code [F253]
- 25.3. Sleigh spec lookup helper expects spec-root paths and appends `Ghidra/Processors/.../data/languages/<file>` internally; this affects runtime path configuration semantics (`IDAX_IDAPCODE_SPEC_ROOT`) [F254]
- 25.4. Sleigh source integration is intentionally opt-in in examples due heavy configure-time fetch/patch behavior against Ghidra; default idax build path remains lightweight [F255]
- 25.5. Residual parity gap: processor-profile granularity is still partial for exact language-profile selection (e.g., ARM profile/revision nuances), so mapping remains best-effort in the current wrapper model [F256]
- 25.6. Runtime startup diagnostics: `init_library` failures are reproducible when `IDADIR` is pointed at an SDK source tree (for example `/Users/int/dev/ida-sdk/src`) instead of a full IDA runtime root; this is an environment-root mismatch, not an API-surface failure [F258]
- 25.7. On this host, `idax_smoke_test` passes with no env overrides because the binary carries `LC_RPATH` to `/Applications/IDA Professional 9.3.app/Contents/MacOS`; explicit `IDADIR`/`DYLD_LIBRARY_PATH` to that same runtime root also passes [F258]
- 25.8. Runtime plugin-load policy paths are host-validated: `idax_idalib_dump_port` succeeds with both `--no-plugins` and allowlist mode (`--plugin "*.dylib"`) on the fixture binary, confirming `RuntimeOptions::plugin_policy` behavior is non-blocking in this profile [F260]
- 25.9. idapcode custom-viewer navigation can be synchronized bidirectionally with linear disassembly using existing ui wrappers only (`on_cursor_changed`, `on_screen_ea_changed`, `on_view_activated`/`on_view_deactivated`, `custom_viewer_jump_to_line`) when guarded against reentrant event loops [F261]
- 25.10. Prefixing every p-code display line with a canonical instruction address token enables reliable cursor-line address parsing for click/keyboard sync even on non-header p-code lines [F262]
- 25.11. Cross-function follow works by rebuilding the same p-code viewer in-place whenever `screen_ea` enters a different function, using `function::at(new_ea)` and fresh per-function address-to-line mapping [F263]
- 25.12. Scroll-follow is implemented with a low-interval UI timer polling `custom_viewer_current_line(mouse=true/false)` and syncing linear view when the parsed line address changes [F264]
- 25.13. Hotkey changed to `Ctrl-Alt-Shift-P` to avoid common SigMaker collision on `Ctrl-Alt-S` [F265]
- 25.14. Crash-hardening detail: `set_custom_viewer_lines` must update `CustomViewerState` in-place (not replace the stored pointer) because IDA retains pointers to `min`/`max`/`cur`/`lines` passed at custom-viewer creation; pointer replacement can trigger EXC_BAD_ACCESS during model/render refresh [F266]

### 26. Rust Type-Domain FFI Ownership & Lifecycle (Phase 15)
- 26.1. For returned C arrays that contain owning `IdaxTypeHandle` values, Rust should transfer ownership per element and then null original C slots before calling shim free helpers; this allows helper-driven cleanup of array/string allocations while avoiding double-frees for moved handles [F267]
- 26.2. Opaque `TypeInfo` clone parity in Rust requires an explicit shim clone ABI (`idax_type_clone`) because handle internals are intentionally hidden and cannot be copied safely from Rust without C++ participation [F268]
- 26.3. Graph-viewer callback ABI bridging should use borrowed callback-string pointers for node text/hints (copied immediately by shim/C++), while callback-context ownership transfers to viewer lifetime and must be reclaimed from the destroy callback to avoid premature frees/leaks [F269]

### 27. Rust UI-Domain Callback/Lifecycle Bridging (Phase 15)
- 27.1. For Rust-side callback registries used by UI/timer subscriptions, store context pointers as `usize` in static maps and pair each entry with a typed drop trampoline; this satisfies `Sync` bounds on `OnceLock<Mutex<HashMap<...>>>` while keeping deterministic cleanup on unsubscribe/unregister [F270]
- 27.2. Rendering-info parity should pass an opaque rendering-event handle through C ABI and append entries via a shim-owned helper (`idax_ui_rendering_event_add_entry`) so Rust can mutate rendering output without owning/reallocating C++ vectors directly [F271]

### 28. Rust FFI Ownership for Nested Transfer Payloads (Phase 15 Batch 5)
- 28.1. In convergence domains with nested payloads (typed values, import modules/symbols, snapshot trees), C ABI should expose explicit transfer structs plus dedicated deep-free helpers so ownership of nested strings/arrays is deterministic across language boundaries [F272]
- 28.2. Rust wrappers should eagerly copy transfer payloads into idiomatic owned values (`String`, `Vec<T>`) and then invoke shim free helpers exactly once on the top-level buffer/record to avoid leaks and double-free hazards [F272]

### 29. Rust FFI Array/String Cleanup Discipline (Phase 15 Batch 6)
- 29.1. For returned `char**` or record arrays with nested string fields, Rust wrappers should copy strings from borrowed pointers and then call a single shim deep-free helper for the array/record block; combining per-element consuming frees with a later array free introduces double-free risk [F273]
- 29.2. Keep ownership responsibilities explicit per API: either transfer each nested pointer individually (and null before helper free), or treat the payload as borrowed and free only via the domain helper after copy, but never both in the same path [F273]

### 30. Rust Plugin/Event Callback Payload Bridging (Phase 15 Batch 7)
- 30.1. For callback-driven plugin/event transfer structs, shim payload string fields should be exposed as borrowed `const char*` valid for callback scope only, and Rust callback trampolines should copy into owned `String` immediately before returning [F274]
- 30.2. Callback context lifetime for typed plugin/event subscriptions should be token/action keyed in Rust static registries with erased drop trampolines, and reclaimed strictly on unsubscribe/unregister success to avoid leaks and stale-context use-after-free [F274]

### 31. Rust Loader Runtime-Handle Bridging (Phase 15 Batch 8)
- 31.1. For loader callback-supplied opaque input handles in Rust (`void*`), shim wrappers can preserve SDK opacity by reconstructing a transient `ida::loader::InputFile` from the raw pointer and delegating to canonical C++ wrapper methods; this avoids direct shim dependence on low-level SDK `linput_t`/`ql*` symbols while keeping behavior aligned with `ida::loader` semantics [F275]
- 31.2. Loader parity closure in Rust should use explicit transfer structs for flag bitfields (`IdaxLoaderLoadFlags`) and an explicit raw-handle wrapper type on the Rust side (`InputFileHandle`) so callback-time handle usage is clear, typed, and ownership-neutral [F275]

### 32. Rust Debugger Full-Surface Convergence (Phase 15 Batch 9)
- 32.1. Debugger parity with safe Rust callback bridging benefits from dedicated shim transfer models for every non-trivial payload (`ModuleInfo`, `ExceptionInfo`, `RegisterInfo`, appcall value/options/request/result) plus explicit C callback typedefs for each debugger event and executor path, rather than generic `void*` payload casting [F276]
- 32.2. Keep request/thread/register parity complete in both shim and Rust (`request_attach`, request-queue status, thread index/name selectors, suspend/resume request variants, register-classification helpers) so Rust wrappers do not regress behind already-implemented shim coverage [F276]
- 32.3. For external appcall executor bridges, model C callbacks as a shim-owned `AppcallExecutor` adapter with destructor cleanup callback; Rust should register boxed contexts and reclaim via unregister-driven cleanup, with a name-keyed registry for predictable lifecycle tracking [F277]

### 33. Rust Decompiler Broad/Full Convergence (Phase 15 Batch 10)
- 33.1. Decompiler event parity (`on_maturity_changed`, `on_func_printed`, `on_refresh_pseudocode`, `on_curpos_changed`, `on_create_hint`, `unsubscribe`) should use explicit C transfer event structs plus tokenized callback lifecycle management in Rust (`HashMap<Token, ErasedContext>`) to preserve safe callback context reclamation and avoid stale-context use-after-free [F278]
- 33.2. Raw pseudocode edit/read parity is practical through opaque `cfunc_handle` flow from event payloads, with dedicated shim wrappers for line array transfer/free, line replacement, and header-line count; this keeps behavior aligned with C++ `raw_pseudocode_lines`/`set_pseudocode_line`/`pseudocode_header_line_count` while preserving ownership clarity across FFI [F278]
- 33.3. Functional visitor parity over C ABI can carry stable, opaque-safe expression/statement transfer views (`item type` + `address`) and still preserve traversal control by mapping callback int return values back to `VisitAction` (`Continue`/`Stop`/`SkipChildren`) in shim [F279]

### 34. Rust Processor Model Parity (Phase 15 Batch 11)
- 34.1. `ida::processor` runtime shim exposure is intentionally minimal because module-authoring is compile-time/subclass driven; Rust convergence should therefore focus on full data-model + callback-contract parity in `idax/src/processor.rs` rather than forcing artificial runtime C ABI endpoints [F280]
- 34.2. Processor-model parity in Rust includes full advanced assembler directives/options, expanded processor metadata/flag fields, full switch descriptor shape, typed analyze operand/detail models, tokenized output models, and `OutputContext` helper semantics that mirror C++ behavior [F280]
- 34.3. Rust 2024 unsafe-op compatibility cleanup in callback-heavy FFI wrappers (for example debugger trampolines) is safely automatable with `cargo fix --lib -p idax`, and should be followed by a full `cargo build` to verify warning-free status [F280]

### 35. Scenario-Driven Documentation Coverage Hardening (Phase 18 Planning)
- 35.1. Practical implementation reliability is scenario-driven: docs must provide runnable end-to-end flows (setup, operation, error handling, teardown), not only API signatures [F282]
- 35.2. Documentation should be explicitly layered by surface (`idax` safe Rust, C++ wrapper, `idax-sys` raw FFI) to prevent path-selection ambiguity during implementation [F283]
- 35.3. Call-graph and event workflows require algorithm/lifecycle templates (visited-set cycle guards, callback token ownership, explicit unsubscribe teardown) in addition to API references [F284]
- 35.4. Multi-binary signature workflows should be covered as advanced tutorials with extraction/normalization/comparison/output stages, not as single-snippet recipes [F285]
- 35.5. Distributed-analysis guidance must document IDB consistency constraints and prescribe partition/shard + merge orchestration patterns for multi-process scaling [F286]
- 35.6. Safety/performance docs should include a safe-vs-raw decision matrix, raw ownership/freeing rules, and an inconsistent-state recovery playbook [F287]
- 35.7. Triage heuristic for docs backlog: cookbook for simple/high-score gaps, runnable examples for medium complexity, tutorials/design notes for low-score/system-level scenarios [F288]
- 35.8. Rust plugin guidance should center on action/context lifecycle wiring and explicit install/uninstall flows; plugin-export ownership is still best treated as host-layer responsibility in current docs architecture [F289]
- 35.9. Transitive caller traversal can directly use `function::callers` outputs as node addresses with visited-set BFS/DFS and optional depth caps, because caller results are function-entry oriented [F290]
- 35.10. String-harvest workflows in safe Rust are achievable with existing primitives (`segment::all` + `address::data_items` + `data::read_string`) when paired with bounded-read and printable-text heuristics [F291]
- 35.11. General-purpose idax documentation should be C++-first (primary wrapper surface) with Rust kept for explicitly Rust-scoped scenarios; this reduces language-surface confusion for default readers [F292]
- 35.12. Safety/performance trade-off guidance for case-10 should compare idax wrapper usage against direct raw IDA SDK usage (C++), not Rust safe bindings against `idax-sys`, to match project audience and use-case framing [F293]

### 36. Examples Portability Across Rust/Node Bindings (Phase 19)
- 36.1. Rust examples layout constraint: Cargo treats each top-level file in `bindings/rust/idax/examples/` as an executable example crate; helper-only files there must include `main` or compilation fails. Shared helpers should be moved under a module directory (for example `examples/common/mod.rs`) and imported from real examples [F294]
- 36.2. Node tool examples need explicit bad-address handling in TypeScript because current Node declarations do not expose a typed top-level `BadAddress` export; use a local `BAD_ADDRESS = 0xffffffffffffffffn` sentinel or add a binding-surface export [F295]
- 36.3. Node runtime validation has a distinct environment-linkage failure mode: `idax_native.node` may load successfully at build/type-check time yet fail at execution if `@rpath/libidalib.dylib` cannot be resolved on the host runtime path; treat this as host setup/rpath blocker rather than TypeScript/example logic failure [F296]
- 36.4. For the current Node addon build, runtime env overrides (`IDADIR`, `DYLD_LIBRARY_PATH`) are insufficient when the binary embeds a stale runtime search path; if `dlopen` still probes only the stale path, resolve via addon rpath/install-name fix or rebuild with correct IDA runtime root [F297]
- 36.5. Operational recovery for stale Node addon linkage is deterministic: rebuild `bindings/node` with `IDADIR` set to the intended IDA runtime root so `idax_native.node` receives a corrected `LC_RPATH`; this fixes load failures caused by stale embedded search paths [F298]
- 36.6. Runtime validation orchestration for headless examples should avoid parallel opens of the same IDB fixture across multiple processes, because concurrent opens can produce transient `open_database failed` outcomes unrelated to example logic; run matrix rows sequentially for stable evidence [F299]
- 36.7. JBC header-version decoding in adapted loaders should use explicit magic-to-version mapping, not low-bit arithmetic, when accepted magic constants share the same LSB; otherwise V2 fields can be parsed with V1 offsets and produce incorrect section metadata [F300]
- 36.8. For procmod/disassembler adaptations over containerized bytecode formats, defaulting decode start to the format's `code_section` offset yields materially better output quality than decoding from file start, while preserving a fallback path for raw-byte inputs [F301]
- 36.9. Synthetic, runtime-generated fixture binaries are acceptable for adaptation smoke validation when canonical format samples are unavailable in-repo, provided generation parameters and commands are captured in the validation matrix evidence [F302]
- 36.10. GUI-oriented form-declaration plugins can still be adapted for headless validation by parsing markup into structured control/group reports (`checkbox`/`radio`/`number`/`address`/choice), which preserves core semantic validation even without docked widget rendering [F303]
- 36.11. Form-markup parsers should model `>>` suffix semantics carefully: a line may close group scope and still declare a control token on the same line (`:C>>`), so scope closure and token parsing are both required for parity [F304]
- 36.12. Driver-analysis plugin semantics can be adapted headlessly in Rust by using import-symbol heuristics for driver-family classification plus entrypoint/name-based dispatch candidate discovery, without requiring plugin action/menu wiring [F305]
- 36.13. IOCTL candidate discovery in standalone adaptation is robust via operand-immediate heuristic decoding of `CTL_CODE`-shaped constants; empty result sets on non-driver fixtures should be treated as valid evidence, not failures [F306]
- 36.14. In the current Rust decompiler API, headless plugin adaptations should prefer `DecompiledFunction::raw_lines` and related per-object methods for pseudocode transforms; helper APIs that require explicit `cfunc_handle` are more naturally consumed from callback/event contexts where the handle is provided [F307]
- 36.15. Abyss-style item-index overlays are reproducible in safe Rust by detecting `COLOR_ADDR` tags in raw pseudocode (`COLOR_ON` + `COLOR_ADDR` + 16-hex payload) and inserting colored inline annotations before each tag [F308]
- 36.16. A high-value non-UI Abyss adaptation set is: token-colorizer pass, item-index visualization pass, lvar rename-preview reporting, and caller/callee hierarchy output for one target function; this preserves core post-processing semantics without UI popup/render hooks [F309]

---
- 36.17. An uncaught C++ exception thrown by an IDA SDK C++ wrapper function (e.g. `loader::set_processor` failing because the module is not found) bypassing the FFI boundary will cause the Rust process to instantly abort with `fatal runtime error: Rust cannot catch foreign exceptions, aborting`. It must either be caught in C++ and converted to `idax::Error` or preempted by valid arguments (like fallback to `metapc`) [F310]
- 36.18. A completely standalone mock IDA loader can be implemented via `idax::DatabaseSession::open(input, false)` followed by `segment::all().for_each(remove)` to clear out any IDA auto-loader fallback. It can then completely build the database using `segment::create`, `loader::memory_to_database`, `data::define_string`, `entry::add`, and `name::force_set` [F311]
- 36.19. Examples labeled as headless adaptations (`_loader.rs`, `_procmod.rs`) for bindings lacking dynamic entrypoint export macros MUST interact dynamically with the IDA Database. A script merely parsing file offsets and printing an imaginary load/disassembly plan is a "fake" implementation. Authentic adaptations must use `DatabaseSession::open`, clear existing segments (`segment::remove`), create explicit ones (`segment::create`), copy bytes in (`loader::memory_to_database`), and iterate memory reading from the DB APIs (`data::read_byte`) to generate representations (`comment::set`, `name::force_set`, `instruction::create`) [F312]
- 36.20. When using the official release of the IDA SDK (via `ida-cmake`), the `ida_compiler_settings` interface target aggressively injects `-flto` (Link Time Optimization) in `Release` mode. Because of CMake/GCC flag ordering, this can override target-level `-fno-lto` settings and cause downstream link failures (especially for Rust consumers linking a C++ static archive). The most robust fix is to physically strip `-flto` from `ida_compiler_settings`'s `INTERFACE_COMPILE_OPTIONS` via `list(FILTER ... EXCLUDE REGEX "-flto")` [F313].

### 37. Cross-Platform Integration Build Issues (Phase 19)
- **CMake Scope Issue on Windows:** When `idax` is included via `FetchContent` or `add_subdirectory`, the `ida-cmake` toolchain sets `CMAKE_MSVC_RUNTIME_LIBRARY` to enforce `/MTd`. However, this variable was isolated to the subdirectory scope, causing the parent integration tests to compile with the default `/MDd`, resulting in fatal `LNK2038` mismatches. Pushing the variable to `PARENT_SCOPE` fixes this. [F314]
- **Windows `<windows.h>` Macro Collision:** Compiling the Node.js bindings on Windows pulls in `<windows.h>`, which aggressively `#define`s `RegisterClass` to `RegisterClassA` or `RegisterClassW`. This mangled the `ida::instruction::RegisterClass` enum signatures, causing `LNK2001` unresolved external symbol errors. Renaming the enum to `RegisterCategory` across C++, TypeScript, and Rust permanently resolves this. [F315]
- **MSVC Strict Linking Requirements:** Unlike macOS/Linux (which use dynamic symbol lookup for the Node Addon), MSVC strictly requires import libraries (`.lib`). The Node Windows build failed to resolve `idalib`-specific symbols (`init_library`, `open_database`, etc.). Explicitly finding and linking `ida.lib`, `pro.lib`, and critically `idalib.lib` in `bindings/node/CMakeLists.txt` for MSVC builds satisfies the linker. [F316]
- **IDA Pro Setup in CI (Race Condition):** `hcli ida install --download-id` uses globbing in the global temp directory to find downloaded installers. This creates race conditions in parallel CI builds leading to `FileNotFoundError`. The stable approach is explicitly separating `hcli download --output-dir ./ida-installer` and passing the resolved path to `hcli ida install`. [F317]
- **Node.js Examples ESM Resolution:** `ts-node` fails with `ERR_UNKNOWN_FILE_EXTENSION` when the `package.json` specifies `"type": "module"`. Switch to `"type": "commonjs"` to allow TypeScript execution of the bindings examples. [F318]
- **Rust/C++ Shim Warnings:** `memcpy`-ing opaque pointer types (like `ida::loader::InputFile`) across the FFI boundary triggers GCC `-Wclass-memaccess` warnings. This must be locally ignored via `#pragma GCC diagnostic ignored "-Wclass-memaccess"` in the C++ shim compilation to maintain a clean build. [F319]
- **Dynamic Linker Stripping in CI Environments:** On macOS, SIP strips `DYLD_LIBRARY_PATH` and related variables when crossing process boundaries via `bash`. To dynamically link the `idax_native.node` or compiled Rust binaries to the headless CI IDA installation at runtime, environment variables (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`) must be exported *inside* the execution step directly rather than relying on `$GITHUB_ENV`. Furthermore, on macOS, the dylibs are explicitly in `IDADIR/Contents/MacOS`, not the root of the `.app` bundle. [F320]
- **Database Creation Permission in CI:** By default, `idalib` APIs like `open_database` attempt to create the database file (e.g., `.i64`) in the same directory as the target binary. Running headless adaptations against read-only system binaries (like `/bin/ls`) will crash with `open_database failed` because the process lacks permissions to write `/bin/ls.i64`. **Solution:** Always copy the target system binary to a writable temporary location (like the CI workspace) before passing it to the `idalib` headless scripts. [F321]
- **macOS IDA install path normalization:** `ida-config.json` may return the `.app` bundle root, but most build/runtime linkage logic needs the dylib directory itself. Normalize `IDADIR` from `/Applications/IDA Professional 9.3.app` to `/Applications/IDA Professional 9.3.app/Contents/MacOS` before CMake and runtime steps to avoid missing-library failures. [F322]
- **Node example CLI invocation shape in CI:** Node examples under `bindings/node/examples` resolve the addon internally and expect argv[0] to be the test binary/IDB path. Passing `build/Release/idax_native.node` as a leading argument in workflow commands misroutes parsing; invoke with only the target binary path + flags. [F323]
- **Windows Rust CI CRT mismatch mitigation:** Rust example runs on `windows-latest` are more stable in `--release`; debug-mode executions can hit unresolved debug CRT symbols (`_CrtDbgReport` family) in mixed-link setups. Build/run examples in release mode for CI reliability. [F324]
- **MSVC library resolution fallback:** Node CMake logic must resolve missing `ida.lib`/`idalib.lib`/`pro.lib` from `IDASDK` even when `IDADIR` is set; fallback cannot be `elseif`-gated behind install-dir detection. Use conditional fill-in of missing libraries after install-dir probing. [F325]
- **Windows Rust shell/linker pitfall:** Executing Windows Rust builds from Git Bash can select `/usr/bin/link` (`C:\Program Files\Git\usr\bin\link.exe`) instead of the MSVC linker, producing `extra operand` link errors for build scripts. Use PowerShell/MSVC-native shells for Windows Rust build/run steps. [F326]
- **Windows runtime DLL lookup in CI:** For Node/Rust example execution on Windows, propagate `IDADIR` via `PATH` (not `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`) in-step before launching binaries so IDA runtime DLLs resolve consistently. [F327]
- **Windows Rust native-lib naming collision:** In the Rust bindings pipeline, a native static link directive named `idax` can be dropped/neutralized in downstream example link stages when the Rust crate is also named `idax`, causing mass unresolved wrapper symbols from `idax_shim.o`. Mitigation: alias the produced native archive to a distinct name (for example `idax_rust.lib`) and link that alias from `build.rs`. [F328]
- **Windows Node `binary_forensics` headless flake mode:** `examples/binary_forensics.ts` may terminate with exit code 1 on `windows-latest` headless CI without stack trace/probe output, even when other Node examples in the same job pass. This should be tracked independently from addon bootstrap/linker setup and temporarily gated in Windows workflow execution until root cause is isolated. [F329]
- **Windows Rust static-link propagation nuance:** Emitting `cargo:rustc-link-lib=static=idax_rust` in `idax-sys` is not sufficient by itself for downstream Windows example links in all cases; link directives may be visible for `idax_sys` compile yet absent in final example `link.exe` command-lines. Re-emitting native link directives from a dependent crate build script via `DEP_IDAX_*` metadata is a reliable mitigation. [F330]
- **Windows Node `class_reconstructor` headless flake mode:** Even after gating `binary_forensics`, `examples/class_reconstructor.ts` can fail in headless `windows-latest` runs right after init/open logging with exit code 1 and no JS stacktrace. Treat as a separate unstable scenario and gate independently while investigating root cause. [F331]
- **Windows Rust final-link hardening:** Build-script `rustc-link-lib` directives alone may still be omitted from final downstream example link lines under MSVC; adding an explicit crate-level `#[link(name = "idax_rust", kind = "static")]` dependency in `idax-sys` is a stronger and more reliable way to force native archive propagation. [F332]
- **Windows Node runtime gating policy:** Headless instability can shift across multiple Node examples with the same silent exit-1 signature; when this occurs, gate the entire Windows Node runtime example block (while preserving build/addon compile validation) until reproducible diagnostics are available. [F333]
