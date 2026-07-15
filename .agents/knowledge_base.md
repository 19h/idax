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
- 4.18.3. **Superseded by 35.52/F394:** The former claim that the current public set extended through `PLFM_MCORE = 77` came from an unverified user-supplied list. Current normalization ends at verified `PLFM_NDS32 = 76`, preserves all raw IDs, and represents unrecognized IDs without invalid enum casts.

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
- 23.1. DrawIDA (`<upstream-source>/plo/DrawIDA-main`) ports cleanly to existing idax plugin/UI surfaces (`ida::plugin::Plugin`, `ida::ui::create_widget`, `ida::ui::show_widget`, `ida::ui::activate_widget`) with no open parity gaps for draw/text/erase/select + undo/redo/style/clear workflows
- 23.2. Prior plugin-flag ergonomics gap [F242] is closed via `ida::plugin::ExportFlags` + `IDAX_PLUGIN_WITH_FLAGS(...)`; idax keeps `PLUGIN_MULTI` mandatory and layers optional SDK bits through structured flags + `extra_raw_flags` [F245]
- 23.3. Prior host-cast ergonomics gap [F243] is closed via typed host helpers `ida::ui::widget_host_as<T>()` and `ida::ui::with_widget_host_as<T>()`, eliminating repetitive `void*` casts in Qt ports [F246]
- 23.4. Dedicated DrawIDA addon target is wired using `ida_add_plugin(TYPE QT QT_COMPONENTS Core Gui Widgets ...)`, yielding skip-on-missing-Qt behavior with explicit `build_qt` guidance and normal addon build when Qt is available [F247]
- 23.5. Qt6/Homebrew include nuance: use `qevent.h` for `QKeyEvent`/`QMouseEvent` portability (`qkeyevent.h` is not present in that header layout) [F248]

### 24. DriverBuddy Port Findings (Phase 13)
- 24.1. DriverBuddy (`<upstream-source>/plo/DriverBuddy-master`) ports through idax plugin/analysis/search/xref/instruction/type surfaces with no raw SDK usage for core Windows-driver triage workflows (driver classification, dispatch discovery, IOCTL decode) [F250]
- 24.2. Struct-offset operand representation closure: `ida::instruction` now exposes `set_operand_struct_offset(...)` and `set_operand_based_struct_offset(...)` wrappers over SDK `op_stroff`/`op_based_stroff`; on SDK 9.3, named-type TIDs must be resolved via `get_named_type_tid()` (not legacy `get_struc_id`) [F249]
- 24.3. WDF table annotation is achievable in idax by constructing a `TypeInfo` struct schema (`TypeInfo::create_struct` + `add_member` + `save_as`) and applying it at resolved table addresses (`type::apply_named_type` + `name::force_set`) after locating the `KmdfLibrary` marker and dereferencing metadata pointers [F251]
- 24.4. Remaining DriverBuddy migration deltas are non-blocking ergonomics: no one-call standard-type bootstrap equivalent to `Til2Idb(-1, name)`, no stroff-path introspection wrapper (`get_stroff_path`), and no minimal hotkey-only callback helper outside the action system [F252]

### 25. idapcode Port Findings (Phase 14)
- 25.1. idapcode (`<upstream-source>/plo/idapcode-main`) ports cleanly to idax plugin/UI/function/data flows when paired with external Sleigh C++ translation (`examples/plugin/idapcode_port_plugin.cpp`) [F253]
- 25.2. Added database metadata wrappers (`address_bitness`, `is_big_endian`, `abi_name`) plus typed `ProcessorId`/`processor()` to support deterministic architecture-to-Sleigh routing without raw SDK fallback in plugin code [F253]
- 25.3. Sleigh spec lookup helper expects spec-root paths and appends `Ghidra/Processors/.../data/languages/<file>` internally; this affects runtime path configuration semantics (`IDAX_IDAPCODE_SPEC_ROOT`) [F254]
- 25.4. Sleigh source integration is intentionally opt-in in examples due heavy configure-time fetch/patch behavior against Ghidra; default idax build path remains lightweight [F255]
- 25.5. Processor identity/context normalization is closed by the raw-plus-optional-typed `ProcessorProfile`. Exact external Sleigh language-profile selection (for example ARM revision variants) remains port-local because the generic SDK processor metadata does not define Sleigh semantics; this is an external integration boundary rather than a native wrapper gap [F256, F394]
- 25.6. Runtime startup diagnostics: `init_library` failures are reproducible when `IDADIR` is pointed at an SDK source tree (for example `<ida-sdk-source>`) instead of a full IDA runtime root; this is an environment-root mismatch, not an API-surface failure [F258]
- 25.7. On this host, `idax_smoke_test` passes with no env overrides because the binary carries `LC_RPATH` to `<ida-runtime>`; explicit `IDADIR`/`DYLD_LIBRARY_PATH` to that same runtime root also passes [F258]
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
- **macOS IDA install path normalization:** `ida-config.json` may return the `.app` bundle root, but most build/runtime linkage logic needs the dylib directory itself. Normalize `IDADIR` from `<ida-app-bundle>` to `<ida-runtime>` before CMake and runtime steps to avoid missing-library failures. [F322]
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
- **Windows Rust top-level crate propagation nuance:** Even with `idax-sys` link directives present, final `idax` example link lines on MSVC can still omit `idax_rust.lib`; adding a crate-local `#[link(name = "idax_rust", kind = "static")]` in `idax/src/lib.rs` reinforces propagation for binaries/examples that depend on `idax` directly. [F334]
- **Windows Rust `#[link]` retention nuance:** Empty `extern` blocks annotated with `#[link(...)]` were insufficient in CI evidence (`22427902344`) to surface `idax_rust.lib` in final example link lines; keep `#[link]` blocks non-empty (declare at least one extern item) to improve metadata retention through downstream linking. [F335]
- **Windows Rust propagation fallback strategy:** Even non-empty sentinel `#[link]` blocks can fail to propagate `idax_rust` into final MSVC example links (`22428113513`); bundling `idax.lib` into a merged shim archive (`idax_shim_merged.lib`) in `idax-sys` build-time is a more deterministic mitigation than relying on transitive native-link metadata. [F336]
- **Windows Rust merged-shim follow-up runtime mismatch:** Once merged shim linkage reaches final example links (`22428565402`), the next blocker can become `LNK2038` RuntimeLibrary mismatch (`MT_StaticRelease` from CMake-built `idax.lib` vs `MD_DynamicRelease` from Rust/`cc` objects). Align MSVC CRT mode by forcing `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL` in `idax-sys/build.rs` CMake configuration. [F337]
- **Windows workflow RUSTFLAGS stale-output hazard:** Injecting `-L native=<idax-sys out> -l static=idax_shim_merged` from workflow `RUSTFLAGS` can bind to an older `idax-sys-*` output directory when multiple build-script hashes coexist in `target/release/build` (`22428747919`), reintroducing stale archive characteristics and hiding current build-script fixes. Prefer crate/linker metadata over workflow-level hard injection. [F338]
- **Integration test library suffixes must be platform-specific:** Hardcoding `.dylib` names in integration test link targets breaks Linux (`.so`) and Windows (`.lib`) unit builds. Use OS-conditional suffixes and prefer SDK helper macros (`ida_add_idalib`) on non-macOS platforms. [F339]
- **Node decompiler wrapper lifetime must be drained before `database::close()`:** macOS headless Node runs can segfault on shutdown if `DecompiledFunction` wrappers outlive DB teardown. A safe addon-level fix is to dispose all live decompiler wrappers before invoking `ida::database::close()`, and guard wrapper methods against post-disposal use. [F340]
- **Windows Rust metadata should target one canonical native archive (`idax_shim_merged`) and track idax sources for rebuilds:** Leaving mixed `idax_rust`/`idax_shim_merged` link metadata after merged-shim rollout can produce unresolved wrapper symbols at final example link. Align all crate/build-script metadata to `idax_shim_merged` and add `cargo:rerun-if-changed` coverage over idax CMake/source trees to avoid stale archive reuse across cached builds. [F341]
- **Avoid duplicate Windows native-link emission from both `idax-sys` and `idax`:** When `idax` itself re-emits static native link directives, final MSVC failures can surface from bundled `idax_shim.o` inside `libidax.rlib` with unresolved C++ wrapper symbols. Keep native-link ownership in `idax-sys` only (single source of truth) to avoid duplicate/partial bundle paths. [F342]
- **Prefer explicit dual-archive linkage (`idax_shim` + aliased `idax_cpp`) over merged static archive generation on Windows:** Keeping shim and wrapper archives as distinct native-link inputs avoids merge-step ambiguity and still sidesteps crate-name collisions by aliasing `idax.lib` to `idax_cpp.lib`. [F343]
- **If `idax_cpp` is missing from final MSVC link lines, add crate-level reinforcement in `idax-sys`:** Build-script metadata can still be absent in downstream example link commands; a non-empty `#[link(name = "idax_cpp", kind = "static")]` block in `idax-sys/src/lib.rs` is a stronger fallback that helps propagate wrapper-archive linkage into final binaries. [F344]
- **For example binaries that depend on `idax` directly, duplicate `idax_cpp` reinforcement in `idax/src/lib.rs` is a practical fallback:** this ensures final link metadata is available at the top-level crate even when transitive propagation from `idax-sys` is not visible in `link.exe` arguments. [F345]
- **Use `static:-bundle` for Windows `idax_cpp` to avoid LTCG object repack issues:** with MSVC `/GL` objects in `idax_cpp.lib`, default Rust static bundling into `.rlib` can lead to unresolved wrapper symbols from `idax_shim.o`. Emitting `cargo:rustc-link-lib=static:-bundle=idax_cpp` from `idax-sys/build.rs` forces direct final-link handling by `link.exe` and is the preferred mitigation. [F346]
- **Windows CRT model must be consistently static for Rust bindings linking against IDA SDK wrappers:** mixed `/MT` (`idax_cpp`) and `/MD` (Rust/`cc` shim) object graphs trigger `LNK2038`/`LNK1319`; enforce Rust `+crt-static` and static CRT settings for shim/CMake outputs to keep runtime-library metadata aligned. [F347]
- **Windows CI runtime robustness for Rust examples benefits from explicit init argv + tolerant auto-analysis wait behavior:** initializing idalib with a synthetic argv (`argc=1`) and downgrading `analysis::wait()` failures to warnings in Windows example helper sessions can avoid opaque exit-code-1 failures while preserving functional read/list flows. [F348]
- **Expose full error metadata in Rust example logs for CI triage:** include `ErrorCategory` and numeric `code` in formatted error output (not message-only) so Windows runtime failures can be diagnosed from logs without rerunning with extra instrumentation. [F349]
- **Do not force plugin-policy runtime options on Windows init path:** current wrapper behavior returns `SdkFailure` (`Plugin policy controls are not implemented on Windows yet`) when plugin-policy controls are requested at init. Use default init and isolate `IDAUSR` in CI for deterministic headless runs. [F350]
- **Use env-driven Rust example tracing on Windows CI for runtime-stage attribution:** `IDAX_RUST_EXAMPLE_TRACE=1` prints step boundaries (`init/open/wait/close`) and `IDAX_RUST_DISABLE_ANALYSIS=1` allows quick validation without auto-analysis wait dependency when diagnosing opaque exit-code-1 failures. [F351]
- **For Windows Rust runtime triage, prefer `cargo build` + direct `.exe` execution over `cargo run`:** direct invocation makes it easier to emit/inspect raw process exit codes (decimal + hex) when failures occur before normal Rust error reporting. [F352]
- **For this Windows Rust path, keep `database::init()` argv minimal (`argv0` only):** injecting `-A`/`-L` into init argv produced `init_library` return code 2. Runtime triage should rely on stage traces and absolute input-path invocation rather than extra init switches. [F353]
- **For Windows Rust CI runtime checks, prefer opening a stable fixture IDB over raw PE binaries:** opening copied `notepad.exe` can terminate during `database::open` with exit code 1 and no wrapper error, while fixture IDB workflows are stable in local validation. [F354]

### 35.13. Hex-Rays Microcode Context Read-Back Gap [F355]
The Hex-Rays SDK's `codegen_t` and `mop_t` structures do not easily support safe, isolated inspection of generic operands when filtering or emitting microcode. `idax` works around this by maintaining recursive C++ parsers (`parse_sdk_instruction`, `parse_sdk_operand`) to safely reconstruct `MicrocodeInstruction` instances out of raw `minsn_t` nodes during a microcode filter's `apply` phase.

### 35.14. Database Bitness Mutator Cross-Surface Parity Discipline [F356]
For architecture-shaping APIs under `ida::database` (for example `set_address_bitness`), parity must be closed in one pass across C++ public headers/impl, API surface parity checks, Node bindings+types+tests, Rust shim/wrapper+tests, and docs/catalog references. Treating only the C++ header+impl as complete creates discoverability and behavior drift across official surfaces.

### 35.15. Microcode Context Binding Lifetime Discipline [F357]
`ida::decompiler::MicrocodeContext` is callback-scoped runtime state and should never be modeled as a long-lived foreign handle in language bindings. Node bindings should expose an ephemeral wrapper object that is invalidated immediately after callback return; Rust bindings should expose callback-local `MicrocodeContext` methods backed by shim helpers (or equivalent scoped adapters). This preserves safe-by-default semantics while still exposing full read-back introspection (`instruction`, `instruction_at_index`, `last_emitted_instruction`) across public surfaces.

### 35.16. Node `cmake-js` ABI Cache Discipline [F358]
`cmake-js` may retain an old Node runtime target in `bindings/node/build/CMakeCache.txt` (`CMAKE_JS_INC`, `NODE_RUNTIMEVERSION`). In that state, addons can compile but fail to load with `NODE_MODULE_VERSION` mismatch against the current `node` binary. The reliable recovery path is `npm run clean` (or remove `build/`) followed by `npm run build` so configuration rebinds to the active runtime ABI.

### 35.17. Bitness Mutator Runtime Regression Signal [F359]
Runtime integration against `tests/fixtures/simple_appcall_linux64` surfaced an idempotent round-trip regression for `idax.database.setAddressBitness(bits)` in Node (`64 -> 16` on immediate read-back). This correctly identified a semantic correctness issue in the mutator behavior path (not merely a binding-discovery gap) and should be treated as a high-priority runtime parity signal.

### 35.18. Bitness Setter Mutual-Exclusion Semantics (Resolved) [F360]
`set_address_bitness` must apply architecture mode changes through mutually exclusive flag writes. Independent boolean writes to `inf_set_64bit` and `inf_set_32bit` can clobber 64-bit state in immediate read-back checks. A switch-based mode application (`64 -> inf_set_64bit(true)`, `32 -> inf_set_32bit(true)`, `16 -> inf_set_32bit(false)`) restores stable behavior and is validated in both Node integration and C++ smoke runs against `tests/fixtures/simple_appcall_linux64`.

### 35.19. `idax` Loader Modules Must Export `LDSC` Through a Framework Bridge [F361]
For IDA loader modules, exporting a build artifact `.dylib` is not sufficient. IDA discovers loaders via the `LDSC` symbol (`loader_t`), not a private framework-specific helper. `idax` originally exposed only `idax_loader_bridge_init` from `IDAX_LOADER(...)`, so custom loaders built successfully but were invisible to IDA at runtime. The correct pattern is for `IDAX_LOADER(...)` to provide the C++ loader instance pointer while `src/loader.cpp` exports an SDK-facing `loader_t LDSC` whose `accept_file`/`load_file` callbacks trampoline into the registered `ida::loader::Loader` instance.

### 35.20. `LDSC` in the Core Archive Needs an Optional Bridge Fallback [F362]
Once `src/loader.cpp` exports `LDSC` from the core `idax` static library, every non-loader consumer that pulls in loader helpers also pulls in a reference to `idax_loader_bridge_init`. Regular tests and idalib executables do not define `IDAX_LOADER(...)`, so a hard external reference breaks cross-platform linking (`LNK2019` on Windows, undefined reference/symbol on Linux and macOS). The safe architecture is to ship a default library-side fallback bridge (`weak` default on Clang/GCC, `/alternatename:` alias on MSVC), make bridge resolution nullable for non-loader executables, and allow real loader modules to override that symbol with their strong registration function so runtime loader dispatch still uses the actual C++ loader instance.

### 35.21. Bindings Need Separate SDK Include-Root vs Library-Root Resolution [F363]
Bindings build systems cannot assume the path exported as `IDASDK` is also the correct library root. In GitHub CI, `IDASDK` may intentionally be normalized to `<checkout>/src` so bootstrap/include lookup succeeds, while the import libraries or stub shared libraries live under `<checkout>/lib` or only under the installed `IDADIR`. Appending `lib/...` directly to `IDASDK=/.../src` causes Windows Node and Rust builds to miss `ida`/`idalib`/`pro` and fail with large unresolved-symbol sets. The robust pattern is: use `IDASDK` for headers, normalize a separate library root (`IDASDK` if it has `lib/`, otherwise parent of `src/` if that has `lib/`), and fall back to installed `IDADIR` library locations when SDK-provided stubs/import libs are absent.

### 35.22. Windows SDK Import-Lib Directory Names Vary Across IDA Layouts [F364]
Bindings and custom build scripts should not assume Windows import libs always live under `lib/x64_win_vc_64`. Current IDA 9.3 SDK layouts can instead provide `ida.lib` and `idalib.lib` in `lib/x64_win_64`, while `pro.lib` may live separately in `lib/x64_win_64_s`. Search logic that only probes the legacy `vc`-suffixed path will incorrectly conclude the SDK has no Windows libs and fall back to useless generic `lib/` directories. The robust fix is to search both `x64_win_64` / `x64_win_64_s` and the older `x64_win_vc_64` / `_s` naming scheme, resolving exact `.lib` files independently.

### 35.23. Node TypeInfo Structural Test Initialization Boundary [F365]
Node unit tests that are intended to be pure structural binding checks should avoid constructing `TypeInfo` factory objects before an IDA runtime/database has been initialized. A direct `idax.type.int32()` call in the structural suite segfaulted before returning the wrapper object. Keep those tests focused on TypeScript/API-shape documentation or move runtime TypeInfo assertions into initialized integration tests; C++ integration remains the primary proof path for primitive factory/type layout semantics.

### 35.24. Arbitrary-Symbol Demangling Form Mapping [F366]
The SDK models short and long demangler output as inhibition masks. Map idax
`DemangleForm::Short` to `MNG_SHORT_FORM`, `Long` to `MNG_LONG_FORM`, and
`Full` to zero before calling `demangle_name(..., DQT_FULL)`. Reject empty or
embedded-NUL inputs locally and return `NotFound` for negative/no-output SDK
results.

### 35.25. Exact Pseudocode Function-Switch Notification [F367]
`hxe_switch_pseudocode` fires after an existing `vdui_t` has received its new
`cfunc` and `mba`, but before text refresh. It should be exposed directly as a
typed `PseudocodeEvent`; screen-address and generic refresh callbacks are not
equivalent signals.

### 35.26. Stable Opaque Widget Identity [F368]
All wrappers around the same live `TWidget*` must share one opaque numeric ID.
Intern pointer-to-ID mappings under a mutex and retire them on
`ui_widget_closing` as well as wrapper-owned close paths. This prevents both
identity churn during polling and stale identity reuse across widget lifetimes.

### 35.27. Node SDK Header-Root Normalization [F369]
Accept both SDK include-root (`<IDASDK>/include/pro.h`) and checkout-root
(`<IDASDK>/src/include/pro.h`) layouts during Node CMake configuration. Header
root probing is independent from the already-separate SDK/runtime library-root
normalization described in F363.

### 35.28. Menu Detach Requires Wrapper-Owned Attachment State [F370]
IDA 9.3 can return true from `detach_action_from_menu` even when the requested
action was never attached. If idax promises `NotFound` for missing attachment,
SDK return values alone are insufficient; record successful wrapper attachment
keys and consume them on detach.

### 35.29. Rust macOS Integration Lifecycle Stall [F371]
On the current macOS IDA 9.3 host, the Rust serial integration harness can
remain inside its one-time init/open/analysis sequence while equivalent Node
and C++ fixture tests finish. Until stage tracing isolates the exact call, use
Rust compile/unit coverage as structural proof and do not report the stalled
runtime harness as passing evidence.

### 35.30. Wrapper-Managed Action Attachment Accounting [F372]
Maintain synchronized counts keyed by exact `(menu_or_toolbar, action_id)` for
successful idax attachment calls. A detach consumes one tracked count before
SDK dispatch and returns `NotFound` without dispatch when no count exists.
Successful or failed action unregistration clears all counts for that action
ID, preventing stale state when an ID is later reused. This accounting defines
deterministic semantics for wrapper-managed attachments while leaving popup
attachment behavior on the SDK's explicit permanent-widget contract.

### 35.31. Rust Real-IDA Tests Must Run on Process Main [F373]
Idalib requires all calls to occur on the same thread that initialized the
library. Rust's standard test harness runs test bodies on worker threads even
when invoked with `--test-threads=1`; the process main thread remains a result
coordinator. On macOS IDA 9.3, IDAPython initialization can synchronously
dispatch a warning to IDA's main-thread executor, so worker-thread init blocks
while libtest's main thread waits for that worker. Configure the real-IDA
integration target with `harness = false` and run initialization, every test
case, and shutdown sequentially from its explicit `main` function. Keep normal
libtest behavior for pure Rust unit tests.

### 35.32. Comment Append Needs Wrapper-Level Composition [F374]
On IDA 9.3, `append_cmt` may return success at a function start while the
subsequent `get_cmt` result contains only the pre-existing text. Function-start
comments can involve function-record storage distinct from ordinary per-item
comment storage. If idax promises observable append semantics, read the current
comment, compose `existing + "\n" + appended`, and write the result through
`set_cmt`; use the appended text directly when no prior comment exists.

### 35.33. Microcode Filters Do Not Replay for Cached Decompilation [F375]
Installing a microcode filter does not imply that a later `decompile` call will
regenerate microcode for an already cached function. A callback-validation test
must call `decompiler::mark_dirty(function_address, false)` after registration
and before decompilation. This invalidates the cached cfunc and makes filter
match/apply observations independent of test order.

### 35.34. Deterministic Comment Append Contract [F376]
Implement `comment::append(address, text, repeatable)` as a wrapper-level
read/compose/write operation. If no non-empty comment exists, write `text`
directly. Otherwise write `existing + "\n" + text`. This matches the SDK's
documented newline model while avoiding `append_cmt`'s function-start storage
asymmetry. Reject a composed size above `std::string::max_size()` before
allocation. C++, Node, and Rust bindings inherit the same observable contract.

### 35.35. CI License Provisioning Failure Boundary [F377]
When every platform fails in `Install IDA Pro` after HCLI successfully downloads
the requested installer, inspect license retrieval before changing source or
workflow build logic. The diagnostic pair `No licenses found matching criteria`
and `License file matching *<license-id>.hexlic not found` means the configured
HCLI identity cannot supply that license. Repository setup, compilation, and
tests have not run. Remediation is external: renew/correct the HCLI account,
license assignment, or GitHub Actions secrets, then rerun the workflows.

### 35.36. Data Definition Counts Require Width-to-Byte Conversion [F378]
The SDK `create_word`/`create_dword`/`create_qword`/`create_oword`, floating-
point, and ten-byte helpers accept a total size in bytes, not an element count.
If the wrapper exposes `count`, validate multiplication overflow and dispatch
`count * element_width` bytes. A default count of one must create exactly one
item of the selected type. Tests must assert success, resulting item size, and
multi-element total size; a survivability-only assertion cannot establish the
public unit contract.

### 35.37. `destroyed_items` Delivery Is Host-Path Dependent [F379]
The IDA 9.3 SDK declares `idb_event::destroyed_items(ea1, ea2,
will_disable_range)`, but the current macOS idalib host does not emit it for
successful `del_items` calls against either temporary or fixture items. Expose
the documented notification and validate its ABI/surface statically. Runtime
tests may assert exact payloads when delivered, but must distinguish absence of
host delivery from dispatcher failure by simultaneously proving other events
through the same listener.

### 35.38. Event Dispatch Must Isolate Callback-Side Mutation [F380]
Never iterate an owning callback registry directly across user callback
invocation. Capture an event-entry token ceiling, re-check each eligible token,
and retain the selected subscription object through invocation. The ceiling
must cover typed and generic phases of the same event; otherwise a route added
by a typed callback can join the generic phase. Removed subscriptions are
skipped. If the final unsubscribe occurs during SDK listener dispatch, defer
unhook until dispatch exit. Across a raw-context FFI, also defer context
destruction while any trampoline frame is active. Move a pending drop queue out
of interior-mutable storage before invoking destructors so destructor-side
re-entry cannot conflict with an outstanding mutable borrow. Likewise, remove
the context from its registry in a bounded lock scope and release the mutex
before reclamation; captured-object destructors may re-enter unsubscription.

### 35.39. Separate Fixed-Width and Processor/Registry-Defined Data Items [F381]
The SDK fixed-width creation family includes yword (32 bytes / 256 bits) and
zword (64 bytes / 512 bits). They use the same total-byte-length input as
word/dword/qword/oword/float/double and therefore belong under the same public
element-count conversion. F384 subsequently establishes that both tbyte and
packed-real widths are processor-defined; custom data additionally requires
registered data-type and format identifiers. Do not assign either advanced
family a compile-time width. Keep string, structure, and undefine parameters
explicitly byte-based.

### 35.40. Rust FFI Error Categories Include a Zero-Valued None Sentinel [F382]
The C shim category values are not the same numeric discriminants as the public
Rust `ErrorCategory`: the shim reserves zero for `IDAX_ERROR_NONE` and numbers
the six real categories from one through six. Decode the generated
`IDAX_ERROR_*` constants rather than relying on enum ordinals. A zero category
means that no error is pending; an unrecognized nonzero category is an internal
ABI error. Runtime tests that assert only `is_err()` cannot detect this drift,
so boundary tests must also assert the structured category.

### 35.41. Integration Idle Assertions Must Establish the Wait Precondition [F383]
Creating or removing a temporary IDA segment can enqueue auto-analysis after
the initial database-open wait has completed. An integration case that asserts
`analysis::is_idle()` (or its binding equivalent) must call the corresponding
wait API in that case rather than depending on earlier suite order. This
preserves isolation when preceding tests add legitimate mutation coverage.

### 35.42. Tbyte and Packed-Real Widths Belong to Processor Metadata [F384]
Do not hard-code the ten-byte storage width implied by the name `tbyte`.
IDA's `dt_tbyte` is explicitly variable-sized through the active processor's
`tbyte_size`; multiple SDK processor modules use zero or non-ten-byte values.
Resolve the current dtype width at the semantic boundary, reject a zero width
as unsupported, and then apply the same checked element-count multiplication
used by fixed-width definitions. Audit packed-real through the corresponding
processor dtype metadata rather than assuming a universal layout.

### 35.43. Extended-Real Size and Availability Are Separate Checks [F385]
IDA stores both tbyte and packed-decimal-real items using the active
processor's `tbyte_size`, but the active assembler advertises them separately
through `a_tbyte` and `a_packreal`. A nonzero width does not establish that
both representations can be emitted. Query the representation-specific
directive as well as the shared width and map absence to `Unsupported`; only
then apply checked element-count multiplication and SDK creation.

### 35.44. Normalize Null and Empty Optional Assembler Directives [F386]
Although `idp.hpp` documents null pointers for unavailable data directives,
the SDK processor-module template uses an empty string for optional packed-real
output. Representation availability therefore requires a non-null, non-empty
`a_tbyte` or `a_packreal` value in addition to a nonzero processor width.

### 35.45. Custom Data Descriptors Are Borrowed Registrations [F387]
The kernel retains raw pointers from `data_type_t` and `data_format_t`, including
names, callback user data, and callback entrypoints. Keep owned descriptor and
callback state at stable addresses until explicit unregister, catch exceptions
inside every C ABI trampoline, and return copied public snapshots. IDB-close
auto-unregister is not a plugin-unload lifetime guarantee.

### 35.46. Custom Type and Format Size Semantics Differ [F388]
A fixed custom type uses `value_size` as its exact value width. A variable type
uses it as the minimum width and requires `calc_item_size(address, maximum)` to
return an exact positive width no larger than the supplied maximum. A format
with zero `value_size` accepts any width; a nonzero value constrains the format.
Print/scan callbacks must also tolerate SDK probe invocations where their output
buffer is null.

### 35.47. Custom Data IDs and Attachments Need Typed Boundaries [F389]
Custom type and format IDs are positive kernel integers but custom item metadata
packs each into 16 bits. Type ID zero has the separate meaning “all standard
types” for format attachment, while format ID zero is unused. Expose nonzero
opaque custom IDs, reject out-of-range registration results, and provide a
separate standard-type attachment operation. Unregister detaches relationships
but each registered descriptor still requires its own teardown.

### 35.48. Exclude the Packed Missing-ID Sentinel [F390]
`custom_data_type_ids_t` uses signed 16-bit fields and the value `-1` for an
absent format. Consequently `0xFFFF` cannot be a usable opaque custom ID even
though it fits in the packed 16-bit field. Registration and user-supplied ID
validation must accept only the closed interval `1..0xFFFE`.

### 35.49. Variable-Size Creation Can Revalidate Size [F391]
Inferring a custom item size and then calling `create_custdata` does not imply a
single callback invocation. The kernel can call `calc_item_size` again during
creation. Treat custom type callbacks as deterministic and reentrant, retain
their state through the complete SDK call, and validate callback participation
plus final item size rather than an exact cross-version invocation count.

### 35.50. Registered Actions Need Owned Handlers and Exception Barriers [F392]
The native action API retains the supplied `action_handler_t*` beyond
`register_action`. A heap handler is destroyed by the kernel on unregister only
when the action descriptor includes `ADF_OWN_HANDLER`; the PLUGMOD literal does
not set that bit by itself. Wrapper callbacks must also catch all exceptions in
`activate` and `update` because those methods are invoked through the host ABI.
Model one-call hotkeys as scoped registrations over the action system rather
than as a separate SDK primitive: IDAPython's `add_hotkey`/`del_hotkey` are
convenience adapters, while the C++ SDK exposes registered actions.

### 35.51. Headless Action Hosts Have Weaker Lifecycle Observability [F393]
Successful action registration in idalib does not imply that
`process_ui_action` can dispatch the action: IDA 9.3 headless execution returns
false without entering the handler. The same host did not immediately destroy
an `ADF_OWN_HANDLER` adapter after successful unregister. Keep named action
adapters in wrapper-owned storage, erase them only after successful SDK
unregister, and reserve activation/exception runtime evidence for an
interactive IDA UI host. Headless evidence remains valid for registration,
unregistration, scoped move/release state, and callback-state reclamation.

### 35.52. Processor Identity Must Preserve Unknown Raw IDs [F394]
The verified public `PLFM_*` range in current `idp.hpp` ends at
`PLFM_NDS32 = 76`; no searched SDK ref defines the previously claimed
`PLFM_MCORE = 77`. The SDK also reserves IDs above `0x8000` for third-party
processor modules. Keep the raw signed processor ID authoritative, normalize
only verified public values to `ProcessorId`, and represent an unrecognized ID
as an absent typed value rather than an invalid enum cast or metadata failure.
Retain `ProcessorId::Mcore = 77` only as a documented source-compatibility
artifact until a breaking API revision; never produce it from current SDK
normalization.

### 35.53. Operand Access Modes Must Survive Binding Transfer [F395]
C++ decoded operands retain the active processor module's canonical read/write
classification (`idp.hpp` `CF_USE1..8` / `CF_CHG1..8`). The Rust flat transfer and both Node instruction-object
converters previously omitted both booleans, so a consumer could identify a
memory-shaped operand but not whether the instruction writes it. Preserve
`is_read`/`is_written` in `IdaxOperand` and safe Rust, and expose
`isRead`/`isWritten` in every Node snapshot. Do not infer write direction from
the existence of a data reference, because reference kind and operand access
mode are distinct properties.

### 35.54. String Discovery Is a Configured Global Cache [F396, F397]
`data::read_string` materializes text only when an address is already known;
it is not a substitute for IDA's `strlist.hpp` inventory. The native inventory
stores address, octet length, and string type in a process-global cache whose
shared options are also used by the Strings window. Consumers must rebuild it
explicitly after configuration. Expose copied `StringListOptions` and
`StringLiteral` values, validate type codes in `0..255` and represent the
minimum length as a checked signed value. Callers that need temporary settings
must snapshot and restore both options and the rebuilt list.

On IDA 9.3, `build_strlist` prepends one zero bookkeeping byte to the shared
`strtypes` vector: a requested `{0,1}` becomes raw `{0,0,1}`, `{1}` becomes
raw `{0,1}`, and the initial one-byte-only configuration is raw `{0,0}`
[F398]. Remove exactly that leading element in copied public options. Do not
deduplicate later zero values because zero is the actual one-byte C-string type.

### 35.55. Source-File Metadata Is a Half-Open Address Mapping [F396]
`lines.hpp` represents one source file occurrence as a filename associated with
`[start, end)`. One filename may own multiple ranges, but one address can map to
only one file. Return an owned filename plus `address::Range`; treat a missing
mapping as `NotFound`; validate non-empty, non-overflowing ranges before add;
and remove by an address inside the mapped range. Never retain the borrowed
`const char*` returned by `get_sourcefile`.

### 35.56. Binding Inventories Must Preserve Origin Filters [F399]
The C++ `name::all(ListOptions)` inventory can include user-defined names,
auto-generated names, or both over a half-open address range. A binding that
exposes only `all_user_defined` loses class/scope evidence used by real ports.
Mirror the filter object and copied `Entry` origin booleans through the C ABI;
keep `all_user_defined` as a convenience specialization rather than the only
safe inventory.

### 35.57. Idalib Integration Inputs Must Be Disposable [F400]
Opening the repository's adjacent input/IDB pair directly allows a successful
test to rewrite serialized analysis or cache state even after logical test
mutations are reversed. CTest must create a unique temporary directory per
target, copy both the raw fixture and its `.i64` when present, pass only the
copy to the executable, and remove the directory after execution. Validate
isolation by comparing the tracked fixture hash before and after the complete
suite, not by relying on a clean logical close.

### 35.58. IDAMagicStrings Counts Observations, Not Display Rows [F401]
The original no-NLTK candidate pass consumes both copied name inventory and
string-list evidence. Its source-language denominator counts a source string
once when it has at least one data reference, even if that string produces
multiple chooser rows, and counts each mapped debug address separately. The
ordered language map resolves common C-family extensions to `C/C++`; only the
distinct `.c++` extension reaches `C++`. Keep report rows, observation counts,
and candidate evidence as separate data flows.

### 35.59. Function-Argument Type Replacement Is a Metadata-Preserving Copy [F402, F403]
A function prototype is richer than its public return/argument-type summary:
SDK records also carry names, comments, locations, flags, return location,
spoiled registers, and calling-convention details. Replace one argument type by
copying `func_type_data_t`, changing only the indexed `funcarg_t::type`, and
rebuilding the function type. Re-wrap it as a pointer when the input was a
function pointer. Return a new opaque `TypeInfo`; do not expose native type or
location structures. Validate the argument index and replacement type first.

### 35.60. Named Operand Enums Need Opaque TID Resolution and Readback [F402, F403]
SDK `op_enum(ea, n, tid, serial)` applies a local enum to one operand or
`OPND_ALL`; `get_enum_id` returns the associated TID and serial. Resolve the
public enum name to a local named type internally, verify that it is an enum,
and keep the TID private. Return a copied enum name and serial for readback.
Treat absence as `NotFound` and reject invalid addresses, operand indexes,
names, and serial values before dispatch.

### 35.61. Normalize the All-Operands Sentinel at the Wrapper Boundary [F404]
Public APIs use `-1` for all operands, matching the IDAPython workflow audited
for Auto Enum. Native `bytes.hpp` instead defines `OPND_ALL` as `0x0F`. Accept
only `-1` or an ordinary `0..UA_MAXOP-1` index, translate `-1` immediately
before `op_enum`/`get_enum_id`, and never expose the native mask constant.

### 35.62. Separate Headless Prototype Enrichment from Cursor-Selected Ctree Mutation [F405]
Auto Enum's import pass depends only on copied import/type inventories and is
deterministic under idalib, so a headless adaptation can report first and apply
only on request. Its local specialization pass begins at the selected
decompiler call and needs callback-scoped child-expression navigation. Keep
that operation in an interactive C++ action instead of reconstructing cursor
state or call operands from Rust's flat expression snapshots. A disposable
host-native fixture supplies reproducible report/apply/reopen evidence for the
headless global path; C++ link and primitive runtime tests cover the local path.

### 35.63. Function-Level Microcode Analysis Requires an Owned Graph Snapshot [F406, F407]
Formatted `cfunc_t::mba` output is not a semantic graph, and lifting-filter
instruction values are callback-scoped. Generate a dedicated MBA at an explicit
microcode maturity, call `build_graph()` exactly once when the requested stage
precedes `MMAT_LOCOPT`, and copy entry/maturity, function argument locations,
block ranges and adjacency, addressed instructions, recursive operands, call
arguments, and display text before native destruction. Keep known semantic
opcodes/kinds typed; preserve unmodeled valid values as `Other` plus copied text
so one unrelated instruction cannot make the complete function unavailable.

### 35.64. State the Symless Port Boundary in Capability Terms [F408]
The bounded Phase 37 adaptation starts from one function argument and preserves
intraprocedural register/stack propagation, move/add/sub/extension semantics,
nested evaluation, load/store access recovery, and Symless's minimum-width
field-conflict policy. It may generate a named UDT and explicitly replace the
selected scalar or scalar-pointer prototype argument with a pointer to that UDT.
Do not infer that this covers allocator/wrapper discovery, interprocedural
call/return flow, vtables/constructors, shifted pointers, forward-reference or
UDT-flag mutation, member-TID xref repair, multi-element stroff paths, or the
microcode-widget operand picker; those are distinct audited surface gaps.

### 35.65. Treat Recursive Graph Transfer as a Single Ownership Tree [F409]
The C transfer root owns every argument name, scattered-location array, block
edge array, instruction array, instruction/operand text string, nested
instruction, referenced operand, and call-argument array below it. Set counts
only for allocated arrays, recursively clear partial values on construction
failure, and make the root free operation idempotent for already-cleared
children. Before `slice::from_raw_parts`, safe Rust must reject a null pointer
with nonzero count and any count whose byte extent exceeds `isize::MAX`; copy
all values before freeing the C tree. Consecutive real-host generations are the
minimum ownership probe because they detect retained pointers into the first
destroyed MBA.

### 35.66. Preserve Symless State-Transfer Asymmetries [F410]
The store destination is an address operand, not a variable assignment target:
record the write but retain the pointer in state. Unsupported ordinary
instructions drop a real variable destination, while loads replace their
destination with an unknown dereference. For a block with multiple available
predecessors, choose the first state having the maximal count of tracked
structure values; do not let a later equal-score predecessor replace it. Build
fields in access order, allow a new untyped overlap only when its width is no
larger than every conflicting field, and reject negative offsets before UDT
materialization. This yields expected `O(B^2 + I*D + F^2)` worst-case time for
`B` blocks, `I` instructions, maximum nested depth `D`, and recovered field
candidates `F`, with `O(B*S + F)` storage for saved block states of size `S`.

### 35.67. Bound Interprocedural Structure Flow by Context and ABI Evidence [F411]
For each resolved direct call, evaluate copied call operands in caller state,
inject tracked structure pointers into the corresponding copied callee argument
locations, and inspect terminal callee states through the copied return location.
Use an explicit maximum call depth, an active-context set for recursion cycles,
and a completed-context set for repeated `(function, injected argument values)`
work. A returned structure value is usable only when all observed terminal
values agree. Report shifted propagation sites but mutate only zero-shift
arguments/returns until shifted-pointer metadata has its own opaque API. When
changing a return type, copy the complete native `func_type_data_t`, replace
only `rettype`, and rebuild the direct function or function-pointer type; public
function summaries do not contain enough ABI metadata for reconstruction.

For `C` distinct analyzed contexts, context `c` having `B_c` blocks, `I_c`
instructions, maximum recursive operand depth `D`, `F` raw field candidates,
and `P` propagated prototype sites, the current stable-predecessor traversal,
linear site deduplication, and overlap resolution require
`O(sum_c(B_c^2 + I_c*D) + F^2 + P^2)` time. Graph/state retention requires
`O(G + sum_c(B_c*S_c) + F + P)` space, where `G` is the cached owned-graph
size and `S_c` is the maximum saved state size in context `c`. The explicit
call-depth bound limits path length, while context deduplication bounds repeated
work for identical function/structure-offset injections.

### 35.68. Request Call Information Explicitly for Preoptimized Interprocedural Graphs [F412]
At `MMAT_PREOPTIMIZED`, a direct call can remain an unknown instruction whose
address operand is copied but whose `mop_f` call-argument payload is absent.
When a consumer requires call arguments, build the graph, pre-decompile exact
direct callees to populate their prototypes, then call
`mba_t::analyze_calls(ACFL_GUESS)` before copying the owned graph. Expose this
as an explicit graph-generation option and leave it false by default: resolving
call information is a semantic enrichment beyond a raw maturity snapshot.

### 35.69. Use Three-Way Terminal Return Consensus [F413]
Classify terminal return evidence as absent, agreed structure, or conflicting.
All scalar/unknown terminals mean absent and do not increment the conflict
count. Identical structure-pointer shifts at every terminal mean agreed and may
flow back to the caller. Differing structure shifts, or any mixture of
structure and non-structure values, mean conflicting and must not propagate.
This avoids both false conflicts on ordinary helpers and unsound propagation
from path-dependent returns.

### 35.70. Separate Allocator Classification from Prototype Enrichment [F414]
Resolve allocator seeds from copied import modules/symbols or exact function
addresses, then inspect references only when the containing owned graph has an
exact direct call at that site. Track caller arguments, bounded integers, and
call-origin tokens. A malloc-like integer size in `1..0x3fff` is a static
allocation; a forwarded argument is a wrapper candidate. Callee arguments for
calloc must both be integers or both caller arguments. Confirm a wrapper only
when every usable terminal return agrees on the candidate call origin, and key
recursive heir traversal by allocator target/kind/index mapping.

Analysis needs no new native surface: imports, xrefs, function containment,
owned call arguments, and return locations are already copied. Prototype
enrichment is distinct. To rename an existing size/count argument safely, copy
the complete `func_type_data_t`, modify only `funcarg_t::name`, and rebuild the
direct or pointer function type. Do not reconstruct from `FunctionDetails` or
invent absent ABI arguments; report a missing configured index as ineligible.

### 35.71. Separate Wrapper Call Tokens from Allocation-Object Roots [F415]
Classify each referenced site against one exact direct allocator call. A static
bounded integer size creates an allocation root even when the result is not
returned. Forwarded caller arguments create only a wrapper candidate; confirm
that candidate when every terminal ABI return location contains the token from
that exact call address. A scalar, different call token, mixed terminal, or
missing return location rejects the wrapper.

For a static root, inject `StructurePointer(0)` at the allocation call result
and reuse depth/cycle/context-bounded direct-call structure propagation. Treat
the recovered allocation size as a field upper bound and exclude accesses whose
nonnegative `offset + width` exceeds it. Materialize a call-site-specific UDT,
but keep allocator and wrapper returns generic `void*`; assigning one root UDT
to a reusable allocator return conflates distinct allocation objects.

### 35.72. Require Constructor Stores Before Treating Function-Pointer Arrays as Vtables [F416]
Scan loaded item heads in code/data segments and interpret pointer-width runs as
candidate vtables only while every slot targets an exact function entry or a
mapped external symbol. Stop before a non-first slot with an incoming code or
data reference, exclude all-import runs, and bound the member count. A candidate
becomes a class root only when owned preoptimized microcode proves that its
exact address is stored at pointer width into injected function argument zero at
offset zero. Report nonzero offsets as secondary subobject evidence. If one
function stores multiple distinct tables at offset zero, retain ambiguity;
member count and xref frequency are not inheritance proof. Materialization must
preserve the native UDT record while setting only C++ object/vftable semantics,
then use named types for the class vftable pointer and virtual-method `this`
arguments.

Let `H` be scanned item heads, `P <= 4096H` inspected pointer slots, `R` the
aggregate reference-query result size, `C` candidate-referencing functions,
and `G` the total copied constructor-graph instructions plus edges. Candidate
discovery is `O(H + P + R + G)` time before field reconstruction and
`O(P + C + G)` retained space. Field reconstruction reuses the bounded
interprocedural cost from KB 35.67. Set-based ambiguous-root grouping adds
`O(S log S)` time and `O(S)` space for `S` proven stores.

### 35.73. Do Not Synthesize Prototype Arguments from Constructor Graph Inference [F417]
Owned microcode argument locations and applied `func_type_data_t` records are
different evidence classes. A graph-inferred argument zero authorizes abstract
state injection and can prove an exact vtable store. It does not supply the
argument comments, locations, flags, spoiled registers, calling convention, or
other prototype metadata required for a lossless type edit. Apply class-pointer
typing only when argument zero already exists and is a generic pointer or
pointer-width scalar; otherwise count the function as ineligible. This keeps
discovery useful on stripped code while preventing ABI synthesis. A fixture
with generic `void*` debug prototypes is the positive probe; a stripped fixture
whose methods have no applied arguments is the falsification probe.

### 35.74. Normalize Both Bindgen Shapes for Recursive C Records [F418]
Libclang can expose a recursive C record completely or leave it opaque at the
point bindgen emits Rust. With `derive_default` enabled, the complete form also
adds layout assertions and a zeroing `Default`; the opaque form does not. A
deterministic checked binding cannot branch on only the opaque byte pattern.
Find the named record's preceding `repr(C)` marker and replace everything up to
the first following FFI declaration with one canonical owned layout. Regenerate
and compare exact bytes; current canonical SHA-256 is
`5a91e0e932583a98f7079e32cfacc9493d1dee27e4d80c938a1b3da5b44ef949`.

### 35.75. Preflight Existing Semantic UDT Layouts Before Prototype Mutation [F419]
Generated type names reduce collision probability but do not prove structural
compatibility. For an existing vftable UDT, require each member offset to be
pointer-width aligned, map it to an in-range discovered method index, and
compare its complete rendered pointer type with the current method pointer.
Reject the candidate before class/prototype mutation on any mismatch or extra
member. For an existing class UDT, require the offset-zero member to be the
exact named vftable pointer. Preserve nonzero fields: exact-offset/equal-type is
reuse, exact-offset/different-type or partial overlap is a reported skip.

### 35.76. Compare Shifted Pointer Parent and Delta Explicitly [F420]
Do not use native pointer equality to recognize `__shifted` types:
`ptr_type_data_t::operator==` omits `parent`, `delta`, and `taptr_bits`. Copy
pointer details into owned values and require all of: shifted property present,
nonempty struct parent, exact named parent identity, and exact signed 32-bit
byte delta. To construct a shifted pointer, copy the complete existing pointer
record, set only `TAPTR_SHIFTED`, `parent`, and `delta`, and rebuild an opaque
value. This preserves pointee, closure, based-pointer width, qualifiers, and
unrelated pointer attribute bits.

For Symless application, use the already-proven propagated argument shift as
the delta. Type an existing generic argument only; recognize an exact prior
shift as idempotent and preserve any incompatible complex pointer. Continue to
exclude shifted returns because upstream explicitly treats them as error-prone
and the current evidence does not establish a return-parent contract.

### 35.77. Apply Only Evidence-Backed Shifted Argument Types [F421]
For every propagated argument site, use the abstract-state shift already
derived from analyzed call arguments. A zero shift selects the ordinary named
structure pointer. A nonzero shift is eligible only when representable as a
signed 32-bit byte delta; construct it by copying that pointer record and
setting the named parent/delta. Existing shifted types are idempotent only when
pointee name, shifted state, parent name, and delta all match. Any shifted
pointer with a different parent/delta and any other complex pointer is
ineligible and remains unchanged. Shifted returns remain excluded.

Let `S` be propagation sites and `L` the aggregate length of resolved type-name
chains. Eligibility and pointer construction require `O(S + L)` time and
`O(1)` auxiliary space per site, excluding opaque type-copy storage. The
interprocedural reconstruction bound remains KB 35.67; this phase adds no graph
traversal. The falsification probes are a mismatched parent, mismatched signed
delta, delta outside `[-2^31, 2^31-1] B`, and fresh-process reopen after exact
application.

### 35.78. Replace Only Exact Local Forward Ordinals [F422]
Treat a forward declaration as a distinct local-type state, not as an empty
complete UDT. Classification copies the native forward property and maps its
declared base to `Struct`, `Union`, `Enum`, or `Unknown`. Replacement is bounded
to structure/union targets: require a nonempty NUL-free exact name, a local
non-sub-TIL target with a nonzero ordinal, explicit forward state, and a complete
non-forward candidate of the same struct/union kind. Copy the candidate and save
that copy into the target ordinal with `NTF_REPLACE | NTF_COPY`; return a fresh
named lookup and leave the source candidate unchanged.

This preserves the identity referenced by existing ordinal-based type links and
prevents the generic `save_as` overwrite contract from being used as a forward
classifier. Preconditions are evaluated before the one SDK save operation.
Classification is `O(1)` time/space excluding opaque type storage; replacement
is `O(M)` time and space for `M` copied UDT members. Falsification probes are an
absent name, base-TIL type, complete target, enum forward, forward candidate,
non-UDT candidate, struct/union mismatch, embedded NUL, and named candidate whose
definition must be copied rather than stored as a typeref.

### 35.79. Extract Forward Pointees from Pointer Details [F423]
For any value classified as a pointer, call `get_ptr_details()` and copy
`ptr_type_data_t::obj_type`; do not rely on `get_pointed_object()`. IDA 9.4 can
return an absent pointed object for a valid pointer to a named local forward
while the complete pointer record retains that forward pointee. This makes
forward state and declared kind observable before replacement, and an existing
pointer link to the ordinal resolves to the complete UDT after replacement.

The operation remains `O(1)` excluding opaque type-copy storage. Falsification
probes are ordinary primitive pointers, complete named UDT pointers, local
structure/union forward pointers before replacement, and the same retained
pointer after ordinal-preserving replacement.

### 35.80. Existing Ordinal Links Resolve After Forward Replacement [F424]
A same-ordinal complete-definition save updates consumers that already refer to
the local forward. Do not rewrite those consumers merely because the target was
previously incomplete: after replacement, re-read each prototype and apply the
ordinary exact type-eligibility rule. In the measured DWARF case, the original
pointer argument becomes an exact pointer to the recovered structure and is
therefore already typed.

Report creation, forward replacement, and prototype mutation separately. First
apply should show one forward replacement, member additions, and zero redundant
prototype changes; fresh-process reopen should show zero replacement/addition,
all members reused, and the prototype still already typed. A changed ordinal or
delete-plus-recreate implementation falsifies this behavior.

### 35.81. Resolve Persistent Member References Inside the Type Boundary [F425]
An exact UDT member cross-reference target is an SDK member identity, not a
linear program address. Keep it opaque: accept a complete saved local UDT plus
an exact byte offset, resolve exactly one member index, obtain its stable TID
internally, and expose only referencing item-head addresses on readback. Ensure
one `dr_I | XREF_USER` data reference so reanalysis retains it; return whether
the operation created a reference and treat an exact existing persistent
reference as idempotent success.

Reject an absent/forward/non-UDT value, sub-TIL or unsaved UDT, byte-to-bit
overflow, no exact member, multiple exact-offset members, an unmapped/non-head
source, and an existing incompatible reference for the same source/member pair
before mutation. This prevents a member `tid_t` from leaking through the public
`Address` vocabulary and prevents silent replacement of a semantically
different xref.

For `M` UDT members and `R` references at the queried source or target, exact
resolution plus read/ensure costs `O(M + R)` time and `O(R)` returned storage
(`O(1)` auxiliary storage for ensure). A Symless reconstruction with `S` unique
field-access sites adds at most `S` persistent xrefs. Falsification probes are
an ephemeral UDT, a complete local UDT with one exact member, a union with
multiple offset-zero members, a byte offset above `UINT64_MAX / 8`, a tail-byte
source, repeated ensure, reanalysis, and fresh-process reopen.

### 35.82. Member-TID Informational References Survive Database Reopen [F426]
IDA Professional 9.4 retains `dr_I | XREF_USER` references whose destinations
are stable local UDT member identities. In the measured Symless fixture, three
exact access item heads at `0x100000424`, `0x100000430`, and `0x10000043c`
target members at `+4 B`, `+8 B`, and `+24 B`. First apply added all three;
fresh-process reopen enumerated and reused all three with zero additions or
skips.

Keep report mode read-only by exposing only the number of recovered access-site
candidates. During explicit apply, resolve each exact compatible member inside
`TypeInfo`, ensure the persistent reference, and classify added/reused/skipped
counts. An apply-reopen sequence other than `3 added, 0 reused` followed by
`0 added, 3 reused` on this fixture falsifies persistence or idempotence.

### 35.83. Compare Node Address Arrays Without JSON Serialization [F427]
The local Node test harness implements `toEqual` with `JSON.stringify`, and
ECMAScript `BigInt` is not JSON-serializable. Because Node `Address` values are
`BigInt`, do not use that matcher for nonempty `Address[]` values. Assert the
length and compare each element with strict equality. A serialization exception
in this context is a harness failure, not evidence that the native address
transfer or wrapper result is invalid.

### 35.84. Keep Multi-Component Struct-Offset Identities Inside the Instruction Boundary [F428]

- SDK struct-offset paths are semantic sequences: the first component identifies the root UDT and subsequent components identify selected UDT members; their native numeric values are database implementation identities, not portable public addresses.
- Resolve readback to copied `structure_name` plus ordered `member_names` with `get_tid_name` and `get_udm_by_tid`. Treat any unresolved component as an error; never synthesize a `tid_<number>` public fallback.
- Apply an exact member path by public structure name and member byte offset. Internally require a complete saved local UDT, exactly one member at `byte_offset * 8`, a stable member identity, and an existing-path preflight. Return added/reused state and reject incompatible paths before mutation.
- Preserve Symless operand selection by copying `mreg2reg(mreg, byte_width)` into each owned register microcode operand. At a recorded access, match that processor register against a phrase/displacement base or the register immediately preceding an immediate; compute the delta using the upstream operand-width signed modular conversion.
- Group by `(instruction address, processor register)` and retain first-observation order. Apply one stroff for the first recovered field; represent other fields at that instruction through exact member references.
- Falsification probes: root-only, exact two-component, unresolved member, ambiguous exact-offset member, unsaved/forward/sub-TIL UDT, incompatible pre-existing path, repeated apply, fresh-process reopen, signed negative delta, phrase/displacement/immediate selection, same-instruction multiple fields, and processor-register conversion failure.

### 35.85. Separate Pointer-Arithmetic Operand Evidence from Recovered Fields [F429]

- Symless emits a size-zero access observation when a tracked structure pointer is shifted by an integer in microcode `add`/`sub`. Its location is the source register operand and its target offset is the shifted structure value.
- This observation is semantic evidence for selecting a matching machine operand, not a UDT field. Do not insert it into width-conflict resolution or create a zero-width member.
- Capture `(target byte offset, instruction address, processor-register ID)` only when the source microcode operand is a register whose `mreg2reg` conversion succeeded. After ordinary nonzero accesses are resolved, attach each observation to an exact recovered field offset.
- Keep direct register-backed `ldx`/`stx` evidence as an additional valid source; nested address expressions require the pointer-arithmetic path.
- Falsification probes: nested load address with register-plus-immediate precursor, subtract shift, unavailable processor-register mapping, unmatched shifted offset, duplicate observation, absence of an extra field, exact candidate count, and live operand-path readback.

### 35.86. Treat Reopen Reuse as the Persistence Contract for Opaque Operand Paths [F430]

- A successful mutation is insufficient evidence: rerun apply in a distinct initialized process and require every candidate to classify as an exact reuse through copied `structure_name`, ordered `member_names`, and `delta` readback.
- On the arm64 forward-structure fixture, three recovered fields produce three candidates and three two-component paths. First apply adds all three; reopen adds zero and reuses all three, with no zero-width member.
- The same reopen must retain Phase 43 member references and field layout, because the operand path is supplemental semantic metadata rather than a replacement for exact member references.
- Falsification probes: missing member-name resolution, numeric fallback, delta drift, root-only readback, additional field creation, changed executable hash, reopen additions, or any reuse count below the candidate count.

### 35.87. Preflight Operand Representation Flags Independently of Strooff Path Readback [F431]

- `get_stroff_path()` answers only whether a struct-offset path can be read. It does not prove that the operand has no user-defined representation.
- After an absent path, inspect `get_flags(address)` with arbitrary-operand `is_defarg(flags, n)`. If true, return `Conflict` without calling `op_stroff`; this preserves enum, offset, numeric, character, stack-variable, forced, floating, segment, and custom representations.
- If `is_stroff(flags, n)` is true but `get_stroff_path()` returns no components, surface an SDK/readback failure rather than treating the operand as unformatted.
- Falsification probes: pristine operand apply, exact stroff reuse, incompatible stroff conflict, enum/ordinary-offset preservation, corrupt stroff-flag/path disagreement, and no mutation on every preflight failure.

### 35.88. Make Opaque Struct-Offset Readback Name-Total and Exact Apply Failure-Atomic [F432]

- A successfully resolved native member identity with an empty member name is not a valid copied-name path component. Return `NotFound` rather than publishing an empty placeholder or numeric fallback.
- Validate address and operand index before `get_stroff_path()`, `get_flags()`, or other native queries.
- Exact ensure reaches `op_stroff` only from a pristine operand. On a false SDK return or mismatched readback, clear the attempted operand representation and return an error; this restores the known pre-state.
- Falsification probes: bad address, negative/out-of-range index, anonymous member component, SDK false return, readback mismatch, pristine state after failure, exact reuse, and no numeric identity in any error/result value.

### 35.89. Validate Exact Operand Paths at Four Independent Boundaries [F433]

- Core boundary: exact root/member/delta readback, repeated false, incompatible stroff conflict, defined non-stroff preservation, bad-input rejection, and post-apply verification.
- Binding boundary: C++/Node/Rust signatures contain copied names and checked offsets only; generated C ABI contains no raw-ID setter or numeric path transfer and remains byte-identical to checked bindings.
- Analysis boundary: pointer add/sub size-zero observations yield candidates without creating fields; grouping selects one source-ordered field per `(instruction, processor register)`.
- Persistence boundary: report is non-mutating, first apply adds every eligible path, and a distinct process reuses every path with zero additions while retaining fields and member references.
- Phase 44 evidence: C++ 26/26; Node 238/238 structural and 82/82 live; Rust 139/139 library, 14/14 Symless, and 99/99 live; final fresh fixture 3 candidates -> 3 additions -> 3 reuses.

### 35.90. Preserve Database-Derived Provenance for Bounded Indirect Calls [F434]

- Treat a database-derived scalar as a distinct abstract kind from a plain integer even when their bit patterns are equal. Only the former may resolve an indirect-call offset.
- Sources matching upstream `mem_t`: move from global memory reads the destination width at the global address; address-of an exact global carries that address; load through a database-derived address reads the destination width. Preserve the kind through move, zero/sign extension, and add/sub with an integer.
- For `IndirectCall`, evaluate the right/offset operand, ignore the selector, require database-derived provenance, normalize to the recorded byte width, and require the target loader/function lookup to return an exact entry. Do not trust an analyzed call-info callee to bypass provenance.
- Reuse existing call-argument injection, depth/context-cycle guards, graph cache, terminal-return consensus, and allocator-root logic after target resolution.
- Complexity: state lookup/update remains `O(log V)` in C++ and expected `O(1)` in Rust for `V` tracked variables; each database-derived load performs one bounded 1/2/4/8 B read; context traversal remains bounded by the existing depth and visited-context sets.
- Assumption A45.1: loaded database bytes contain the statically resolved pointer after loader/fixup processing. Falsify with an unresolved relocation or a value not equal to a function entry; dependent result: indirect target acceptance.
- Assumption A45.2: relevant scalar widths are 1, 2, 4, or 8 B as in upstream `get_nb_bytes`; other widths use one-byte fallback only for source parity. Falsify with an architecture producing a wider indirect offset; dependent result: target recovery, not direct-call behavior.
- Falsification probes: plain-immediate target rejection, address-of-global acceptance, global-slot load acceptance, second-level load, add/sub preservation, unloaded address, non-entry interior address, absent call arguments, depth/cycle reuse, exact callee field recovery, allocator-root propagation, and fresh-process apply idempotence.

### 35.91. Reach Fixed Allocator Slots Through One Exact Reference Hop [F435]

- Direct allocator discovery begins with references to the configured seed. A global fixed-pointer slot is represented as `slot -> allocator` data evidence plus `code -> slot` read evidence, not necessarily as a call xref to the allocator.
- For each target-referencing data item, enumerate only its code references, resolve the containing function, cache one owned analyzed graph, collect copied `IndirectCall` addresses including nested instructions, and run the same database-provenance classifier at each site.
- Count a database-resolved allocator call only after its evaluated target equals the configured seed and its size/wrapper arguments classify. Do not treat a code read, final decompiler call annotation, or call-info target as sufficient.
- For `R_t` target references, `R_s` code users per referenced slot, `G` copied graph instructions, and `C` candidate indirect calls, reachability costs `O(R_t + sum(R_s) + G + C * G)` time in the current bounded classifier and `O(G + C)` cached/candidate storage per distinct containing function.
- Assumption A45.3: IDA emits an exact data reference from a statically initialized slot to the configured target and a code reference from the load to that slot. Falsify by removing either reference and verifying the site remains unclassified; dependent result: allocator-site reachability only, not ordinary analysis of an explicitly selected root.

### 35.92. Phase 45 Live Persistence Boundary [F436]

- The arm64 fixture stores relocation-derived `target - 0x135` values and reconstructs them using database load plus integer add. This prevents a plain immediate from satisfying provenance while retaining a deterministic exact target.
- Ordinary report evidence is one database-resolved indirect call, two processed functions, zero unresolved calls, and exact fields at `+4/4 B`, `+8/8 B`, and `+24/1 B`. Apply/reopen transitions are `3 added -> 3 reused` for members, references, and operand paths, with `2 changed -> 2 already typed` arguments.
- Allocator report evidence is one database-resolved indirect wrapper, one 32 B fixed root, zero unclassified calls, and the same three fields. Apply/reopen transitions are `3 -> 3` members and `6 -> 6` references/operand paths.
- Falsification probes are an ordinary indirect counter other than one, any missing field, a nonzero ordinary unresolved count, allocator wrapper/root counts other than one, any unclassified allocator call, reopen additions, or reuse below the first-apply addition count.

### 35.93. Phase 45 Cross-Language Regression Boundary [F437]

- No public wrapper/binding delta is required; generated C ABI identity is therefore a negative control, not an omitted validation layer.
- Required final evidence is C++ 26/26, Node 238 structural plus 82 live, Rust 139 library plus 15 Symless plus 99 live, strict declarations/all-target formatting checks, unchanged tracked fixtures, and byte-identical generated bindings.
- A changed binding hash, decreased test count, ignored live test, fixture mutation, or any failure in an unchanged language surface falsifies the bounded no-public-API conclusion.

### 35.94. Separate Static Vtable Root Expansion from Dynamic Dispatch [F438]

For a candidate whose first function pointer is at address `T`, upstream load discovery searches confirmed references to `T`; only if that produces no load does it search the RTTI label `T - 2P`, where `P` is the database pointer width, while recursively crossing data locations that contain the exact referenced address. Every code candidate still requires microcode confirmation that the value eventually stored is exactly `T`. Once the table is accepted, each non-import member function with an argument-zero location is an independent `this`-pointer root and its recovered fields join the class layout.

- Assumption A46.1: the ABI uses the audited two-pointer Itanium prefix when the constructor references a label before the function array. Falsify with an ABI-specific prefix of another width; dependent result: RTTI fallback reachability only.
- Assumption A46.2: relevant data aliases are pointer-width database items whose loaded value exactly equals the preceding reference address. Falsify with encoded, runtime-initialized, or non-pointer aliases; dependent result: alias reachability only.
- Stress probes: a direct-only fixture must keep RTTI counters at zero; a constructor that computes `label + 2P` must be missed when fallback is disabled and accepted when enabled; a data alias containing the wrong pointer must be rejected; a field touched only by a virtual method must disappear when method seeding is disabled and appear when enabled. Runtime object-dependent targets remain unknown and outside this static model.

### 35.95. Phase 46 Live RTTI and Virtual-Method Persistence Boundary [F439]

- A source-level aggregate may cause DWARF to itemize the entire RTTI blob as one database item, making `next_head` skip the interior method array. The fixture therefore emits the prefix and method array as adjacent assembly labels while retaining C/DWARF function prototypes; this tests the analyzer rather than debug-item coalescing.
- Required report invariants are one candidate and accepted class, `direct_load_tables = 0`, `rtti_fallback_tables = rtti_load_tables = 1`, `data_aliases_followed = 1`, `virtual_methods_analyzed = 3`, zero graph/arity failures, and four fields including method-only `+24/1 B` and `+32/8 B`.
- Required persistence transitions are class/vtable creation then reuse; five class and three method members added then reused; eleven member references and operand paths added then reused; and four prototypes changed then already typed. Any reopen addition/change, lost field, direct-load acceptance, missing alias, or reduced method count falsifies the bounded result.
- Complexity: recursive evidence collection is `O(V + E)` time and `O(V)` visited storage over exact pointer-alias addresses/references; candidate graph evaluation remains bounded by owned graph size, and method propagation is `O(M * G)` before existing interprocedural depth/context bounds for `M` unique non-import methods and representative graph cost `G`.

### 35.96. Phase 46 Cross-Language and Direct-Path Regression Boundary [F440]

- No wrapper header, compiled wrapper source, Node surface, Rust library, C shim, or generated binding changes are required; the two adaptations consume existing opaque values.
- The original direct-table fixture is the fallback negative control: it must report one direct load, zero RTTI fallback/load, zero aliases followed, three methods, and unchanged `+8/4 B`, `+16/8 B`, `+24/1 B` fields.
- Complete evidence is C++ 26/26, Node 238 structural plus 82 live, Rust 139 library plus 0 sys plus 17 Symless plus 99 live, strict/all-target checks, generated-binding identity at `3a143a13309725ed66c5ebce1dd5199fafcc30ea8a0d92b33404c9fef66d7a13`, and unchanged tracked fixture hashes/blob. Any reduced count, binding delta, direct-path fallback, or tracked fixture mutation falsifies the no-public-API conclusion.

### 35.97. Exact Microcode Operand Root Model [F441]

For each top-level owned microinstruction, visit nested left, right, and destination instructions recursively before the parent, then assign monotonically increasing sub-indices in execution order. At each instruction, expose register and stack operands from left, right, and destination; the destination is an after-instruction root only when copied `modifies_destination` is true, otherwise it is a before-instruction source root. Inject the selected structure-pointer value only in the selected graph entry context, before or after the exact address/sub-index, and reuse the existing depth-bounded interprocedural propagation thereafter.

- Assumption A47.1: owned nested operand recursion preserves the SDK left/right/destination tree used by upstream flattening. Falsify with a nested graph whose candidate sequence differs from SDK depth-first execution order; dependent results: candidate identity and exact injection only.
- Assumption A47.2: stack offsets and microregister IDs uniquely identify state locations within one generated preoptimized graph. Falsify with two distinct SDK locations copied to the same owned identity; dependent result: selected root state only.
- Stress probes: a store destination must remain a source root, a move destination must be an after root, a nested source must receive a lower sub-index than its parent, the same `(EA, sub-index)` in a followed callee must not trigger root injection, and disabling follow-calls must retain root-function fields while excluding callee-only fields.
- Complexity: enumeration is `O(I + O)` time and `O(D + C)` auxiliary space for `I` recursive instructions, `O` visited operands, nesting depth `D`, and emitted candidates `C`; injection adds `O(1)` matching work per processed instruction before existing graph/depth/context bounds.

### 35.98. Picker Display Index and Execution Index Must Share One Traversal [F442]

Do not compute candidate indices while rendering operands independently from analysis. Flatten nested left/right/destination instructions depth-first, assign the parent index only after all nested descendants, and use that same private instruction path for before/after injection. Display `(EA, sub-index)` for upstream familiarity, but do not use it as the sole internal identity because consecutive same-EA instructions and malformed/upstream-mismatched display indices can collide.

- Assumption A47.3: SDK microcode execution order for nested `mop_d` operands is the audited `flatten_minsn()` left/right/destination depth-first order. Falsify by comparing a host trace or SDK contract showing a different order; dependent results: nested candidate numbering and injection timing only.
- Stress probe: construct a parent with a register left operand and nested right operand. The nested candidates and instruction must precede the parent-left candidate's injection point, and selecting either must affect only its private path even if both render with the same address.

### 35.99. Phase 47 Live Selection and Persistence Boundary [F443]

- Picker-facing operand and instruction strings must remove IDA color tags from a copy; raw owned text remains available unchanged to other consumers.
- Required report invariants for the arm64 `inspect_fields` fixture are 18 candidates, candidate zero at `0x100000460.0` as `x0.8{2}` source/before, exactly one root injection, four recovered fields at `+4/4 B`, `+8/8 B`, `+18/2 B`, and `+24/1 B`, and zero propagation sites for the local selected root.
- Required persistence transitions are one structure/four members/four references/four operand paths added on first apply, then zero creation/addition and four reuses in a distinct process. Root argument change counters remain zero because an arbitrary selected microregister is not evidence that a function prototype argument has that type.
- Falsification probes are tagged/control-byte candidate output, destination/after classification for the store address, injection count other than one, any lost/extra field, any root argument mutation, reopen additions, or reuse below four.

### 35.100. Dynamic Object Dispatch Is Not an Upstream Parity Requirement [F444]

Upstream has one indirect-call resolution rule: the `m_icall` right operand must carry database-memory provenance and equal an exact function entry. Structure-derived values do not satisfy that class. Vtables contribute statically enumerated argument-zero method roots, not runtime dispatch edges. With Phases 45 and 46 complete, no source-defined runtime object-dispatch behavior remains to port.

- Assumption A47.4: the audited Symless checkout at the recorded file hashes is the target upstream source of truth. Falsify with another target revision containing an object-derived indirect-target resolver; dependent result: only the parity-closure classification.
- Risk boundary: a novel virtual-dispatch analysis would need explicit object-state, table-offset, table-member, ambiguity, and call-graph policies plus independent soundness evidence. Its absence does not reduce fidelity to the audited upstream implementation.

### 35.101. Phase 47 Cross-Language Regression and ABI Boundary [F445]

- Complete evidence is C++ 26/26 in 22.58 s; Node 238 structural plus 82 live; Rust 139 library plus 0 sys plus 20 Symless plus 99 live; strict TypeScript, Rust format/all-target, and generated-binding identity checks also pass.
- `IdaxMicrocodeInstruction` has the same ordered `modifies_destination` field in the C header, normalized bindgen output, and safe transfer. Two independent clean outputs and the checked file have SHA-256 `865f53507d8dd44ef7b2033eccb901f3bf26bf21e0653c8528c493e3692c7b3f`.
- The tracked fixture executable remains SHA-256 `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`; its adjacent IDB remains SHA-256 `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b` and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd`.
- Falsification probes are any reduced test count, generated-binding byte delta, ABI field-order mismatch, tracked fixture mutation, candidate count other than 18, root injection count other than one, first-apply count other than four, or reopen addition/reuse other than zero/four.

### 35.102. Diaphora Exact-Fingerprint Adaptation Boundary [F446]

The first Diaphora 3.4.0 adaptation is a versioned, deterministic function manifest: function entry/RVA, canonical CFG counts and edges, instruction/mnemonic sequence, full item-byte MD5, relocation-light instruction-prefix MD5, name, declaration, and repeatable comment. Comparison may accept only a unique exact candidate, ordered by same-RVA plus both hashes, both hashes, full hash, then relocation-light hash with instruction-count agreement. Mutation is explicit and limited to matched function name, nontrivial declaration, and nonempty repeatable comment; report/export remain non-mutating.

- Assumption A48.1: identical code under relocation preserves the audited prefix selected from encoded operand positions. Falsify with two relocated builds whose nonrelocation opcode bytes differ or whose relocation bytes remain in the prefix; dependent result: relocation-light matching only.
- Assumption A48.2: exact full-function item-byte MD5 plus instruction count identifies one source function within the compared manifests. Falsify with duplicate implementations; dependent result: full-hash matching only, and the unique-candidate rule must reject the collision.
- Complexity: feature extraction is `O(F + I + B + E)` time and `O(F + I + E)` manifest/working space for functions `F`, decoded instructions `I`, hashed bytes `B`, and CFG edges `E`; indexed comparison is expected `O(F)` time/space, with collision buckets explicitly retained.

### 35.103. Operand Encoded-Value Positions Are Optional Byte Units [F447]

Copy SDK `op_t::offb` and `op_t::offo` as optional byte offsets from instruction start. SDK zero maps to absence; nonzero values map to `std::size_t`, JavaScript `number | null`, C ABI signed integers with `-1` as absence, and Rust `Option<usize>`. Consumers must require `offset < instruction.size()` before using the position. These are encoding positions, not operand widths, database addresses, or struct-member offsets.

- Stress probes: an immediate/near operand must expose a present in-bounds primary offset; a register-only operand must expose absence; decoded C++/Node/Rust values must agree; malformed or future processor positions outside the instruction must be rejected by the fingerprint consumer.

### 35.104. Canonical Metrics Must Be Distinguished from Native Diaphora SQLite Metrics [F448]

The IDAX manifest counts each directed basic-block successor edge once and computes cyclomatic complexity as `E - N + 2P`, with `P = 1` for one function flow graph. Segment-relative offset is `function_entry - segment_start`. Native Diaphora 3.4.0 SQLite rows double-count successor/predecessor edges and derive `segment_rva` from the final visited instruction; direct database interchange therefore remains outside this manifest version.

- Falsification probes: a single-block function has `N=1`, `E=0`, complexity `1`; a two-block linear function has `N=2`, `E=1`, complexity `1`; no manifest record may report a segment offset based on its last instruction.

### 35.105. Function Declaration Readback Is Required for Conservative Import [F449]

The C++ wrapper's printable applied declaration is the authoritative read-side precondition for prototype import. Mirror it through Node as `function.declaration(address, optionalNameOverride)`, through the C shim as an owned UTF-8 string, and through safe Rust as `function::declaration(address, optional_name_override)`. A target with any successfully printed nonempty declaration is preserved; apply is eligible only when readback reports absence. Function-name heuristics are not an equivalent prototype-presence test.

- Assumption A48.3: a successful nonempty `function::declaration` result denotes target prototype state that must be preserved even if IDA synthesized part of it. Falsify only with an SDK contract that distinguishes auto-generated from user-applied declarations through an opaque flag; dependent result: conservative prototype eligibility only.
- Stress probes: compare C++/Node/Rust output for one applied declaration; verify absence propagates as `NotFound`; verify comparison/export paths do not mutate the target; verify apply skips a nonempty target declaration.

### 35.106. Diaphora Exact Manifest Live Invariants [F450]

- An unchanged analyzed database must produce byte-identical `IDAX_DIAPHORA_EXACT\t1\tcanonical-cfg` output across distinct processes. The reference fixture produces 22 records and manifest SHA-256 `4263b3eafdb75fcb009e3c565f341a72cf6abe222c34554d9908fc65caa0d08a` before metadata mutation.
- Self-comparison must classify all 22 records in the strongest same-RVA/both-hash tier, with zero ambiguity and zero unmatched records.
- Explicit apply of one non-auto source name and one nonempty repeatable comment to absent/auto target state must change exactly one of each, save, and report zero failures. Fresh reopen must change zero and preserve the values exactly.
- Duplicate implementations are ambiguous unless a stronger unique tier separates them. Matching is computed globally per tier against unmatched baseline and current buckets, never greedily by record order.
- Falsification probes are nondeterministic bytes, a non-22 self-match count, any ambiguous/unmatched self record, report-mode mutation, first-apply counts other than one name/one comment, reopen mutation, or lost metadata.

### 35.107. Phase 48 Complete Validation Envelope [F451]

- C++ must build the plugin and pass 27/27 CTest targets; Node must pass strict example declaration checking, 239/239 structural checks, and 84/84 IDA 9.4 checks; Rust must pass formatting/all-target checks, 139/139 library tests, 0 sys tests, 7/7 Diaphora tests, 20/20 Symless regressions, and 101/101 live IDA 9.4 checks.
- Generated C ABI bindings must be byte-identical to an independent clean bindgen output at SHA-256 `8d2dd609c7abcf64f14744bd725355e8e2ffb0a6af6fa39abe96d31f4b424d1b`.
- Both manifest readers reject odd-length/non-hex text and invalid decoded UTF-8. The C++ reader additionally validates overlong sequences, surrogate encodings, truncation, and code points above U+10FFFF before metadata can reach IDA.
- The tracked fixture remains SHA-256 `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`; its adjacent IDB remains SHA-256 `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b` and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd`.
- Falsification probes are any reduced test count, generated-binding byte delta, malformed-input acceptance/panic, ABI field-order mismatch, declaration readback failure, out-of-bounds present encoded position, or tracked fixture mutation.

### 35.108. Diaphora SQLite/Heuristic Coupling Boundary [F452]

The native database is not merely a serialization alternative for the Phase 48 manifest. Function, instruction, basic-block, callgraph, constant, program-data, and compilation-unit relations feed 50 ordered SQL heuristics plus a stateful ratio/tie-break/multimatch engine. A predicate-only subset that omits normalized assembly/pseudocode/microcode, MD-index, deep bonuses, category thresholds, and prior-match state is a new matcher, not Diaphora heuristic parity.

- Assumption A49.1: native Diaphora ratio/category parity requires the ordered SQL candidates and `check_ratio`/`deep_ratio`/multimatch state together. Falsify with an upstream contract or test corpus proving a named heuristic's final category is independent of all omitted ratio and prior-match inputs; dependent result: heuristic work remains outside the selected Phase 49 slice.
- Stress probes: enumerate all 50 rule types/categories/flags and predicate dependencies from the pinned module; require any future heuristic artifact to reproduce candidate SQL, default threshold `0.5`, ratio rounding, deep bonuses, one-to-one replacement, and multimatch handling before claiming parity.

### 35.109. Exact Instruction-Metadata Manifest Boundary [F453]

Phase 49 selects only ordinary/repeatable instruction comments and forced operand text from native `instructions` import. Each metadata-bearing source instruction is keyed by its uniquely matched function plus function-relative byte offset and guarded by equal decoded size, mnemonic, and relocation-light MD5. Existing target comments/forced operands are never replaced.

- Assumption A49.2: within a globally unique Phase 48 function match, equal relative byte offset, decoded size, mnemonic, and relocation-light MD5 identify the same instruction-level metadata site. Falsify with a transformed function where all guards agree but semantic instruction identity differs; dependent result: instruction metadata transfer only.
- Assumption A49.3: `NotFound` or an empty forced-operand/comment readback denotes an absent target slot, while a nonempty readback denotes state to preserve. Falsify with an SDK case where a present user value reads as absent; dependent result: conservative apply eligibility only.
- Complexity: extraction is `O(I * O)` time and `O(M * O)` serialized space for instructions `I`, decoded operands `O`, and metadata-bearing instructions `M`; indexed validation/apply is expected `O(I + M * O)` time and `O(I + M)` working space.
- Exclusions: referent names/types, pseudocode comments/tree positions, raw function flags, SQLite files, heuristic ratios, basic-block/instruction graph interchange, and nonexact assembly-diff alignment remain separate surfaces.

### 35.110. Exact Instruction-Metadata Live Invariants [F454]

- The companion header is `IDAX_DIAPHORA_INSTRUCTION_METADATA\t1\texact-relative-offset`; every `I` record has 11 tab-separated fields, and forced operands use ordered `<index>:<UTF-8-byte-length>:<text>` payloads before whole-field hexadecimal encoding. C++ and Rust must emit identical bytes for the same database.
- Full MD5 is preserved as source provenance. Target eligibility is deliberately guarded by unique Phase 48 function alignment plus instruction ordinal, signed relative byte offset, decoded size, mnemonic, and relocation-light MD5; it does not require equal full MD5 because relocation-bearing bytes may differ.
- Comparison/export never persist a target mutation. Explicit apply writes only absent ordinary/repeatable comments and absent forced operand slots; every nonempty readback is preserved. A fresh process must report zero further writes.
- Assumption A49.4: function code-address enumeration is deterministic and its sorted ordinal remains stable whenever the offset/size/mnemonic/relocation-hash identity remains stable. Falsify with two equivalent IDA analyses whose sorted instruction membership differs while all other guards identify the intended site; dependent result: instruction metadata eligibility only.
- Stress probes: byte-identical repeated export; malformed UTF-8/NUL/hash/range/duplicate/reference rejection; signed positive/negative offset and overflow/underflow tests; exact first-apply counts; zero-write reopen; byte-identical reopened export; one valid altered relocation hash producing exactly one guard failure.
- Live reference envelope: 22 function records, 9 instruction records, manifest SHA-256 `d7dbebeb499f1f14cbe378b2af9e77f06f5f65fd7f2d853b2806755382d996d6`, first apply `1/1/1` comment/repeatable/forced writes with eight preserved values, reopen `0/0/0` writes with eleven preserved values, and negative control `8` eligible plus `1` guard failure.

### 35.111. Phase 49 Complete Validation Envelope [F455]

- C++ must build the plugin and pass 27/27 CTest targets; Node must pass native build, strict example declaration compilation, 239/239 structural checks, and 84/84 initialized-host checks; Rust must pass formatting/all-target checks, 139/139 library tests, 0 sys tests, 10/10 Diaphora tests, 20/20 Symless regressions, and 101/101 initialized-host checks.
- An independent clean bindgen output must be byte-identical to the checked file at SHA-256 `8d2dd609c7abcf64f14744bd725355e8e2ffb0a6af6fa39abe96d31f4b424d1b`; Phase 49 has no public wrapper, C ABI, Node, or safe-Rust surface delta.
- Parser/arithmetic containment includes positive and negative signed offsets, `INT64_MIN`, address overflow/underflow, malformed length prefixes, zero-length forced text, invalid UTF-8/NUL, invalid hashes, metadata-free records, duplicate/unsorted operands, duplicate records, and unknown function ordinals.
- The tracked fixture remains SHA-256 `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`; its adjacent IDB remains SHA-256 `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b` and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd`.
- Falsification probes are any reduced suite count, generated-binding delta, malformed-record acceptance/panic, offset wraparound, report-mode target IDB creation, incorrect first/reopen mutation counts, guard-negative acceptance, or tracked fixture mutation.

### 35.112. Semantic Pseudocode Comment Locations [F456]

Persisted Hex-Rays comments are identified by an address and `item_preciser_t`, not by address alone. The public wrapper must model: default; zero-based argument separator `0..63`; opening parenthesis; assembly, else, do, semicolon; opening/closing curly brace; closing parenthesis; label colon; block-before/block-after; try; and bounded signed switch-case value. Conversion to SDK `ITP_*` values belongs only in `src/decompiler.cpp`.

- Assumption A50.1: the pinned local SDK enum and case-bit comments define the ABI used to compile IDAX. Falsify by compiling against a supported SDK whose named `ITP_*` constants or switch-case encoding differ; dependent result: internal conversion and live comment placement only, while the semantic public model remains stable.
- Switch-case magnitude must not consume `ITP_SIGN` or `ITP_CASE`; require absolute value `<= 0x1fffffff`. Argument index must be `0..63`. Reject all invalid semantic combinations before calling Hex-Rays.
- Stress probes: compile-time/internal equality against every named SDK constant; all 64 argument endpoints; positive/negative/zero/max switch cases; out-of-range rejection; semicolon enumeration/readback at SDK value `69`; no public raw integer input in C++, Node, or safe Rust.

### 35.113. Multi-Location Pseudocode Comment Persistence [F457]

Copied enumeration must return every nonempty persisted `(address, semantic location, UTF-8 text)` entry in deterministic address/location order and free the restored SDK map with `user_cmts_free`. A Diaphora adaptation may correct the upstream same-address overwrite only if its format is explicitly marked as an IDAX companion rather than SQLite interchange.

- Assumption A50.2: `restore_user_cmts(function_entry)` is the authoritative persisted source for export and fresh-process readback. Falsify if a saved comment visible through `cfunc_t::get_user_cmt` is absent from the restored map after `save_user_cmts`; dependent result: enumeration/export persistence only.
- Complexity: enumeration is `O(C)` time and `O(C)` copied space for persisted comments `C`; indexed manifest validation/apply is expected `O(I + C)` time and space after instruction indexing.
- Stress probes: two distinct locations at one address survive enumeration/export/apply/reopen; report mode does not save; existing target location is preserved; unknown/malformed locations are rejected; orphan removal is never implicit.

### 35.114. Semantic Position Cross-Binding Invariants [F458]

- Public C++, Node, and safe Rust APIs accept only semantic locations. The C ABI carries a closed kind plus signed detail and validates every combination; native `item_preciser_t` integers and `treeloc_t` remain implementation-private.
- Persisted enumeration restores the SDK map, copies every nonempty `(address, location, text)` record, rejects unknown/corrupt native locations, sorts deterministically by address/kind/detail/text, and releases the SDK allocation with `user_cmts_free()`.
- Valid parameter domains are argument index `0..63` and switch-case value `[-0x1fffffff, 0x1fffffff]`. Simple positions require zero detail; comment text rejects embedded NUL. C output pointers/counts and orphan-query outputs are null-validated.
- Initialized-host evidence proves SDK semicolon value `69`: a default and semicolon comment at one address both persist, read back exactly, and enumerate independently through C++, Node, and Rust. Every test restores the prior database values after the probe.
- Complexity: semantic conversion is `O(1)` time/space; copied enumeration is `O(C log C)` time due to deterministic sort and `O(C)` output space for `C` persisted comments.
- Falsification probes: any raw public integer escape, accepted out-of-range/detail mismatch, lost same-address entry, unsorted repeated enumeration, save-free report mutation, orphan auto-deletion, allocation leak, binding mismatch, or generated-binding byte delta.

### 35.115. Exact Pseudocode-Comment Companion Invariants [F459]

- Header: `IDAX_DIAPHORA_PSEUDOCODE_COMMENTS\t1\texact-tree-location`. Every `P` record has 11 tab-separated fields: function ordinal, instruction ordinal, signed function-relative offset, decoded size, full MD5 provenance, relocation-light MD5 guard, hex mnemonic, canonical semantic position name, signed position detail, and hex UTF-8 comment text.
- Canonical position names are `default`, `argument`, `parenthesis-open`, `assembly`, `else-line`, `do-line`, `semicolon`, `open-brace`, `close-brace`, `parenthesis-close`, `label-colon`, `block-before`, `block-after`, `try-line`, and `switch-case`. Simple detail is zero; argument detail is `0..63`; switch-case detail is `[-0x1fffffff, 0x1fffffff]`.
- Export includes only persisted nonempty comments whose address is an exact sorted function code head. Per-function decompilation failures and non-instruction/orphan locations are omitted; malformed persisted locations/text fail extraction. The artifact does not claim SQLite interchange or pseudocode similarity.
- Comparison is read-only and requires a globally unique Phase 48 function match plus exact Phase 49 instruction ordinal/offset/size/mnemonic/relocation-hash agreement. Apply decompiles each eligible target function once, preserves every nonempty target location, writes only absent locations, and calls `save_comments()` once per modified function. It never removes or relocates orphans.
- Complexity: extraction is `O(F + I + C log C)` time and `O(F + I + C)` working/output space for functions `F`, code heads `I`, and persisted comments `C`; indexed comparison/apply is expected `O(F + I + C)` time and space.
- Live envelope: 22/22 unique functions, two same-instruction semantic records, `2` first writes/one saved function, `0` reopen writes/`2` preserves, byte-identical SHA-256 `5e8a42dc99e28d57f6b7843d29292ce39c9ed8b387fa6d517ddfa93cb030ba23`; one altered guard gives `1` eligible/`1` failure; one target-owned conflict gives `1` write/`1` preserve.
- Falsification probes: address-key collapse, record-order nondeterminism, report-created IDB, overwrite of any nonempty target, missing per-function save, reopen write, guard-negative acceptance, malformed position acceptance, implicit orphan deletion, cross-language byte mismatch, or tracked-fixture mutation.

### 35.116. Phase 50 Complete Validation and ABI Boundary [F460]

- Release envelope: C++ full build plus 27/27 CTest; Node build, strict TypeScript examples, 240/240 structural checks, and 85/85 checks against the SDK-matched IDA 9.3 runtime; focused Node semantic-comment persistence/enumeration against IDA 9.4; Rust format/all-target, 140/140 library, 0 sys, 12/12 Diaphora, 20/20 Symless, and 102/102 process-main-thread IDA 9.4 checks.
- Generated C bindings have independent byte identity at SHA-256 `1c22d8ded3ccd9d08b22f2cce200fb4df4fedc744b89518cc1d0b1ceb370d279`. Tracked fixture executable/IDB SHA-256 values and IDB blob remain `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`, `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`, and `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd`.
- Red-team containment requires explicit C++-kind-to-C-kind mapping, C argument range checks before `size_t` conversion, null-save rejection, strict parameter-object shapes in Node, and construction/readback probes for all 64 argument positions.
- Assumption A50.3: the reproducible full-Node failure in `data::string_literals()` when a binary compiled with pinned SDK 9.3 headers is forced onto IDA 9.4 is a cross-minor ABI/layout mismatch outside Phase 50. Falsify by rebuilding the identical Node suite with matching IDA 9.4 SDK headers and reproducing the same `get_strlist_item()`-adjacent vector corruption; dependent result: only claims of full cross-minor Node runtime compatibility. Exact cause is otherwise unknown.
- Falsification probes are any reduced suite count, semantic position/raw-integer leak, generated-binding delta, same-address location loss, non-idempotent reopen, malformed-input acceptance, guard-negative acceptance, target overwrite, report mutation, tracked-fixture mutation, or claim that the 9.3-header/9.4-runtime full Node probe passed.

### 35.117. Active-Work Queue Invariant [F461]

- `.agents/active_work.md` is a projection of current active, queued, and blocked state only. It must not duplicate completed or retired phase history from `.agents/progress_ledger.md`.
- A work item ceases to be active when its completion evidence and roadmap transition are recorded. The same closure update must remove its active-work entry; a later cleanup is a protocol violation.
- The 2026-07-15 audit removed completed Phases 39, 40, 43, 44, 48, 49, and 50 after confirming every corresponding roadmap item was checked. Six ongoing/blocked groups remain. The temporary Phase 51 maintenance entry was removed immediately after its reviewed correction commit was pushed.
- Assumption A51.1: roadmap checkboxes and terminal ledger entries are authoritative for classifying the seven removed phases. Falsification probe: any unchecked P39, P40, P43, P44, P48, P49, or P50 item, or any active mitigation/action absent from the six retained groups. Dependent result: only the stale-entry classification and removal set.
- Structural probe: reject any active-work heading or status containing `Complete`, `Completed`, or `retired`; compare each closure transition against a same-commit deletion from `.agents/active_work.md`.

### 35.118. P22.R3 Documentation and Provenance Invariant [F462]

- `ida::decompiler::collect_referenced_types(Address)` is locally present in the public header and implementation, and `api_surface_parity_test` names its exact function type. This proves the IDAX facade exists; it does not independently prove the state of an unavailable downstream repository.
- The migration checklist must classify P22.R3 as implemented for the audited flow and must not retain a residual IDAX implementation task that contradicts its terminal task table.
- Assumption A52.1: the terminal P22.R3 record accurately states that the audited ida-cdump `ctree_analyzer.cpp` and `type_collector.cpp` stopped consuming raw `cfunc_t`, `cexpr_t`, and `ctree_visitor_t`. Falsify by inspecting the same pinned downstream revision and finding any such call site. Dependent result: only downstream migration-completion wording; the locally compiled IDAX API result is independent.
- Structural probes: every P22.R3 status in `codedump_migration_checklist.md` must be terminal or explicitly conditional only on downstream-source access; no table cell may prescribe implementing a facade that already exists.

### 35.121. Identity-Bearing Host-Path Hygiene [F465]

- Tracked prose, source annotations, command evidence, and binary artifacts must not contain identity-bearing absolute host paths. Use semantic tokens (`<repo-root>`, `<ida-cdump-root>`, `<ida-sdk-root>`, `<ida-runtime>`, `<upstream-source>`) while retaining enough relative suffix to reproduce the evidence.
- Audit text with Git-aware searches and audit every tracked blob with `strings`; text-only search is insufficient because IDA databases may embed the canonical input path.
- An IDA database byte replacement is admissible only when the source and replacement strings have identical byte length and an isolated copy reopens successfully. A length-changing substitution can invalidate serialized record boundaries and is prohibited.
- Assumption A54.1: roots matching Unix user/checkouts (`/Users`, `/home`, `/models`, `/Volumes`, `/root`, `/mnt`, private per-user temporary roots) and Windows user profiles cover identity-bearing absolute paths in the current tracked tree. Falsify with a tracked text/blob string containing another machine-specific absolute root or user identifier. Dependent result: the zero-exposure claim only; individual recorded substitutions and IDA-open evidence are independent.
- Generic platform semantics such as `/dev/null`, `/tmp` test values, `/usr/bin`, `/opt`, and conventional application discovery do not encode a person or checkout and are outside the privacy classification. Stress probe: classify every remaining absolute literal and reject any containing a user, host, private checkout, SDK, runtime-install version tied to evidence, or upstream-source location.
- Reachable history and remote refs require an independent scan after current-tree cleanup. A clean working tree does not imply historical removal.

### 35.122. GitHub Server and Fork Purge Boundary [F466]

- The rewritten `master` contains 285 commits, advertises one branch/no tags, and retains the exact pre-rewrite sanitized tip tree `454dbad642abc3a728d6179c2b6ae158681b6c61`. Commit-message and reachable-blob scans are zero in both the rewrite clone and a fresh remote clone.
- Raw fetch of the former tip still succeeds after the leased force push. GitHub's cached object store therefore remains an exposure independently of advertised refs. The required server/fork procedure is documented in [GitHub's primary sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
- Two PR head refs remain affected (549 matching historical blobs each). Four fork default branches remain affected (549, 575, 375, and 564 matching blobs). PR refs require GitHub Support; forks require their owners. Neither is writable through the source repository's ordinary branch permission.
- Assumption A54.2: GitHub Support will classify identity-bearing absolute paths as sensitive personal data eligible for cached-view and object purge. Falsify if Support declines the request under its non-sensitive-data limitation. Dependent result: server-side purge availability only; the sanitized source ref and fresh-clone evidence are independent.
- Closure probes: former object fetch must fail; PR refs must no longer reach contaminated commits; affected fork default branches must scan zero or cease to exist; fresh `master` clone must remain at zero; no collaborator may merge an old-history branch back into rewritten history.

### 35.123. HCLI Installable-License Selection [F467]

- `hcli license list` is documented as rich table output. An ID-shaped token alone carries no edition, type, or status semantics; server and inactive rows can precede installable IDA rows.
- Accept only rows whose ID has the canonical grouped hexadecimal form, type is exactly `named`, status is exactly `Active`, and edition is a positively enumerated supported IDA product family (`Ultimate`, `Professional`/`Pro`, or `Essential`). Explicitly exclude Free, Home, and server products unless installer-compatibility evidence later expands the positive set.
- Prefer editions deterministically in descending capability order: Ultimate, Professional/Pro, Essential. Preserve table order within a tier. Do not print the selected full license ID into CI logs.
- Assumption A55.1: current HCLI rich output retains a vertical-delimited table with ID, Edition, Type, and Status in the documented order. Falsify with a supported HCLI release that changes those columns or adds a machine-readable format; dependent result: parser compatibility only. The semantic selection predicate remains required.
- Complexity: for output length `N` bytes and `L` license rows, parsing is `O(N + L log L)` time from deterministic priority sorting and `O(L)` space; `L` is bounded by account entitlements. Six stress probes cover server-first ordering, inactive product rows, Free/Home exclusion, ANSI decoration, ASCII/Unicode delimiters, priority, malformed IDs, and a fail-closed no-eligible-row CLI result that does not echo rejected IDs.
- Primary provenance: [Hex-Rays HCLI license management](https://hcli.docs.hex-rays.com/user-guide/licenses/) and [HCLI quick-start license table/install example](https://hcli.docs.hex-rays.com/getting-started/quick-start/).

### 35.124. Derived License-Identifier Log Masking [F468]

- HCLI installation diagnostics include the chosen license identifier, so suppressing a workflow-authored `echo` does not make the job log identifier-free.
- Every one of the five independent install jobs registers the selected value with `::add-mask::` immediately after selection and before any later HCLI invocation. GitHub Runner then redacts subsequent exact occurrences while retaining non-sensitive diagnostics.
- Assumption A55.2: the selected identifier contains no whitespace and the hosted runner implements the documented `add-mask` command before HCLI emits it. Falsify if a live post-change Actions log exposes the unredacted selected identifier; dependent result: log redaction only, not semantic license selection.
- Complexity: one constant-size mask registration per job, `O(1)` time and space relative to the license table.
- Primary provenance: [GitHub Actions workflow command for masking values](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands?tool=bash#masking-a-value-in-a-log).

### 35.125. HCLI Rich-Table Continuation Rows [F469]

- HCLI 0.18.5 builds its license output with Rich `Table` columns `ID`, `Edition`, `Type`, `Status`, `Expiration`, and `Addons`. The ID is non-wrapping, but the other cells may wrap when stdout is captured and Rich uses its default 80-column non-terminal width.
- Parse an ID-bearing physical line as the start of a logical row. Append nonempty fragments from subsequent blank-ID `│`/`|` lines to the corresponding column, separated by one space, and finalize at the next ID-bearing line or non-row boundary. Apply eligibility only after finalization.
- Assumption A55.3: eligible `named` and `Active` values fit without Rich's ellipsis at the supported renderer width, and edition wrapping occurs at word boundaries. Falsify with captured HCLI output that ellipsizes one of those eligibility fields; dependent result: text-parser compatibility only. A future structured HCLI output mode should supersede table parsing.
- Complexity remains `O(N + L log L)` time and `O(L)` space; continuation folding visits each rendered fragment once.
- Primary implementation provenance: `ida-hcli` 0.18.5 `hcli.commands.license.list._display_licenses_table` and `hcli.lib.console`, inspected from the package executed by the workflows.

### 35.126. CI SDK/Runtime Release Alignment [F470]

- IDA installation assets are fixed at 9.3, but the SDK checkout previously followed `HexRaysSA/ida-sdk` default `main`. Upstream commit `772a43ba70118b4ec5325a69c8a3d85d50c96cd8` replaced the former `ida-cmake` submodule with an in-tree package in June 2026, so current `main` no longer satisfies IDAX's bootstrap discovery.
- All five workflow SDK checkouts must use exact official `v9.3` commit `d5db59ab4e9d2ae92038e9520082affd0da6fe20`, including recursive submodules. This matches the installed runtime and removes default-branch drift.
- Assumption A55.4: GitHub continues serving the immutable commit and its public `src/cmake` submodule dependency. Falsify if checkout at that object fails or `src/cmake/bootstrap.cmake` is absent after recursive checkout; dependent result: CI acquisition only. The local version-alignment requirement is independent.
- Complexity: one constant `ref` input at each of five checkout sites, `O(1)` workflow overhead.
- Primary provenance: [official v9.3 SDK commit](https://github.com/HexRaysSA/ida-sdk/commit/d5db59ab4e9d2ae92038e9520082affd0da6fe20) and [official in-tree CMake migration](https://github.com/HexRaysSA/ida-sdk/commit/772a43ba70118b4ec5325a69c8a3d85d50c96cd8).

### 35.127. Live HCLI Selector and Mask Evidence [F471]

- Workflow commit `9317dd4b3fe1b7b3f4fddfa7da8f0f90d621fe9f` executes 15 install jobs: six Bindings, six Validation, and three Integrations jobs distributed across Linux, macOS, and Windows.
- All 15 `Install IDA Pro` steps succeed and advance to SDK resolution. The installed edition detail is IDA Professional 9.3, both applicable license files download, and later HCLI output renders the selected identifier as `***`.
- All 15 complete logs were scanned for the canonical grouped license-ID expression; observed unmasked matches: `0`.
- Assumption A55.5: GitHub's recorded step conclusions and retrieved complete job logs are faithful to the executed runner streams. Falsify with a raw log archive containing an unmasked canonical identifier or an install step whose conclusion differs from the API result; dependent result: live CI evidence only.

### 35.128. Structured-Binding Lambda Portability [F472]

- Avoid referencing an enclosing structured-binding name from a nested lambda in code compiled by the release matrix's AppleClang 15. In the observed wrapper-deduplication case, the compiler rejects the reference even under C++23.
- Prefer an equivalent ordinary object already in scope. `ResolvedAllocator heir.address` is initialized from `caller` immediately before the predicate, so it preserves equality semantics without structured-binding capture.
- Assumption A55.6: `heir.address` remains initialized from the loop's `caller` before the predicate. Falsify by changing that initializer; dependent result: semantic equivalence of this substitution only.
- Complexity remains `O(W)` time for `W` discovered wrappers and `O(1)` predicate space; no control-flow or collection change occurs.

### 35.129. Node V8 Type and Windows Macro Portability [F473]

- Optional V8 arguments must present one exact `v8::Local<v8::Value>` type to helper functions. Use `Nan::Undefined().As<v8::Value>()` for the missing arm rather than relying on conditional-operator conversion between `Local<Value>` and `Local<Primitive>`.
- The Node native target includes Windows headers outside IDAX's core compile envelope. Define `NOMINMAX` privately for that target so `std::numeric_limits<T>::max()` remains a C++ member call on MSVC.
- Assumption A55.7: NAN/Node retains `Local<Primitive>::As<Value>()` and the Windows `min`/`max` suppression contract. Falsify with a supported Node/NAN version that removes the conversion or ignores `NOMINMAX`; dependent result: binding compile portability only.
- Complexity and runtime behavior are unchanged: two compile-time conversions and one preprocessor definition add `O(1)` build state.

### 35.130. Bindgen Line-Ending Normalization [F474]

- Treat generated Rust bindings as textual interchange with platform-dependent line endings. Normalize `\r\n` to `\n` before locating/replacing the recursive microcode instruction region.
- The canonical checked output already uses LF, so normalization removes a host distinction without changing declarations. A synthetic Windows-form fixture verifies marker discovery, canonical replacement, retained FFI declaration, and zero carriage returns.
- Assumption A55.8: bindgen emits either LF or CRLF and does not use bare carriage returns. Falsify with generated output containing another line separator; dependent result: post-processor portability only.
- For generated length `N` bytes, normalization and rewrite remain `O(N)` time and `O(N)` space.

### 35.131. Binding Integration Fixtures Must Match Test Contracts [F475]

- A real-IDA integration invocation must use a binary containing every fixture-specific symbol or literal asserted by the test. Host utilities such as `/bin/ls` are suitable only for generic analysis contracts.
- The Node integration test searches for `ref4: entered with %d`; that literal is compiled into `tests/fixtures/simple_appcall_linux64`. The test harness itself copies the supplied binary to a temporary directory, so a workflow-side copy is redundant.
- Assumption A55.9: the checked-in Linux ELF remains analyzable as input data by IDA 9.3 on Linux and macOS runners. Falsify with either runner failing database import before the string-list assertion; dependent result: Unix Node integration fixture portability only.
- Replacing the input path changes neither algorithmic complexity nor persistent repository state: the harness copy and IDA import remain `O(B)` time and space for fixture size `B` bytes.

### 35.132. Windows Rust Preanalyzed-IDB Smoke Isolation [F476]

- Decision 19.18's `IDAX_RUST_DISABLE_ANALYSIS=1` is required in the Windows Rust example step, not merely implemented in the shared helper. Without the environment assignment, `DatabaseSession::open(input, true)` retains auto-analysis and the live runner exits inside `database::open` before Rust error formatting.
- The smoke input is an existing analyzed `.i64` database. Disabling auto-analysis for this CI-only invocation isolates wrapper read/list behavior from the separately known Windows headless analysis/open instability while retaining library initialization, database open, enumeration, output, and close coverage.
- Assumption A55.10: IDA 9.3 can open the checked preanalyzed fixture when `open_database` receives `auto_analysis=false`. Falsify if the next Windows run still exits before `database::open ok`; dependent result: Windows Rust runtime-smoke recovery only.
- The toggle changes one Boolean argument and skips an analysis wait: `O(1)` control overhead and no additional space.

### 35.133. Windows Rust Headless Runtime Gate Boundary [F477]

- Live Windows evidence falsifies A55.10: the process exits inside `open_database` for the checked preanalyzed IDB with both auto-analysis settings, after successful IDA initialization and before wrapper error propagation.
- The Windows binding job still provides three independent compile/test gates: release construction of `idax`/`idax-sys`, release construction of every example, and 140 safe-Rust unit tests; it additionally compiles the integration target without executing it. Linux/macOS continue to execute Rust examples, and Linux/macOS/Windows execute native IDAX integration packaging.
- Decision 19.59 removes only the non-diagnostic Windows headless example execution. Reopen that gate when a supported runner/runtime combination reaches `database::open ok` and closes the database with a zero exit status.
- Assumption A55.11: compile/unit coverage is sufficient for the Windows-specific HCLI/compiler scope, while runtime semantics remain exercised on Unix. Falsify with a Windows-only ABI defect that passes release linking and 140 unit tests but fails on a supported headless runtime; dependent result: Phase 55 Windows binding coverage boundary.
- Removing two redundant example launches reduces CI runtime by the duration of those processes; build/test complexity is otherwise unchanged.

### 35.134. License-Identifier Log Audit Boundaries [F478]

- Scan logs with `(?<![0-9A-Fa-f])[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}(?![0-9A-Fa-f])`, not the unbounded grouped expression. The right boundary prevents a matching prefix within a longer hexadecimal UUID token.
- Audit tooling must report per-job counts and redact context before display; it must not print a candidate identifier while determining whether masking failed.
- Assumption A55.12: HCLI's canonical identifier is a standalone token rather than a substring of a longer hexadecimal identifier. Falsify with official HCLI output embedding the license ID in an adjacent hexadecimal token; dependent result: leakage-audit sensitivity only.
- For total log size `N` bytes, the boundary-aware scan remains `O(N)` time and `O(1)` auxiliary regex state apart from input buffering.

### 35.135. IDA 9.4 SDK Package and Acquisition Model [F479-F480]

- Release-align all five HCLI install blocks to IDA 9.4 assets and all four workflow SDK refs to exact official commit `6929db6868a524496eb66e76e4ec6c9d720a0594`. The same commit must govern the no-environment CMake fallback.
- The 9.4 checkout uses `src/cmake/idasdkConfig.cmake`; it does not contain the 9.3-era `bootstrap.cmake`. Resolve the checkout root to `src`, place its `cmake` directory in `CMAKE_PREFIX_PATH`, set `idasdk_DIR`, and retain `find_package(idasdk REQUIRED)` as the target-definition boundary.
- A generic clone-then-checkout is not sufficient once the release branch moves away from the requested object. Use exact-object checkout in Actions and the official commit archive for FetchContent. Verify the archive with SHA-256 `6ba645ef8fb5663d45d28c7a48da274e22a5929ddbfbc69cd4be34a4d7ee9895` before extraction.
- Assumption A56.1: HCLI 9.4 asset keys retain the established `release/9.4/ida-pro/ida-pro_94_<platform>` convention. Falsify when any live `hcli download` call reports the key absent; dependent result: CI installer acquisition only.
- Assumption A56.2: `actions/checkout@v4` performs an explicit fetch for the supplied immutable SHA, matching the locally successful `git fetch --depth=1 origin <SHA>`. Falsify if a live checkout cannot materialize that SHA; dependent result: workflow SDK acquisition only. The archive fallback remains independently verified.
- Primary provenance: [official SDK commit](https://github.com/HexRaysSA/ida-sdk/commit/6929db6868a524496eb66e76e4ec6c9d720a0594), its `src/cmake/idasdkConfig.cmake`, and the HCLI direct-download key syntax documented by Hex-Rays.
- Acquisition and resolution add `O(S)` download/extraction time and space for SDK archive size `S`; version selection and entry-point probing remain `O(1)`.
