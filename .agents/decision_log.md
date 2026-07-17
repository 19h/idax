## 13) Decision Log (Live)

### 1. Architecture & Core Design Principles

- **1.1. Language Standard**
  - 1.1.1. **Decision:** Target C++23 for modern error handling and API ergonomics

- **1.2. Library Architecture**
  - 1.2.1. **Decision:** Hybrid library architecture balancing ease of use with implementation flexibility

- **1.3. API Opacity**
  - 1.3.1. **Decision:** Fully opaque public API enforcing consistency and preventing legacy leakage

- **1.4. String Model**
  - 1.4.1. **Decision:** Public string model uses `std::string`

- **1.5. Ecosystem Scope**
  - 1.5.1. **Decision:** Scope includes plugins, loaders, and processor modules (full ecosystem)

- **1.6. Documentation**
  - 1.6.1. **Decision:** Keep detailed interface blueprints in `agents.md` for concrete implementation guidance

- **1.7. Diagnostics & Concurrency**
  - 1.7.1. **Decision:** Store diagnostics counters as atomics, return snapshot copies
    - Rejected: Global mutex (unnecessary contention)
    - Rejected: Plain struct (undefined behavior under concurrency)

- **1.8. README Alignment**
  - 1.8.1. **Decision:** Align README with matrix-backed coverage artifacts — replace absolute completeness phrasing with tracked-gap language, pin packaging commands, refresh examples



### 2. Build, Linking & Validation Infrastructure

- **2.1. idalib Linking**
  - 2.1.1. **Decision:** Link idalib tests against real IDA installation dylibs, not SDK stubs
    - 2.1.1.1. **Rationale:** SDK stub `libidalib.dylib` has different symbol exports causing two-level namespace crashes
    - Rejected: `-flat_namespace` (too broad)
    - Rejected: `IDABIN` cmake variable (ida-cmake doesn't use it for lib paths)

- **2.2. Compatibility Validation Profiles**
  - 2.2.1. **Decision:** Standardize into three profiles (`full`, `unit`, `compile-only`) with `scripts/run_validation_matrix.sh`
    - 2.2.1.1. Enables consistent multi-OS/compiler execution without full IDA runtime
    - Rejected: Ad hoc per-host docs (drift-prone)
    - Rejected: CI-only matrix (licensing constraints)

- **2.3. Packaging Artifacts**
  - 2.3.1. **Decision:** Pin matrix packaging artifacts via `cpack -B <build-dir>` for reproducible artifact locations
    - Rejected: CPack default output path (drifts by working directory)

- **2.4. Compile-Only Parity Testing**
  - 2.4.1. **Decision:** Treat compile-only parity test as mandatory for every new public symbol including overload disambiguation
    - Rejected: Integration tests only (insufficient compile-surface guarantees)

- **2.5. GitHub Actions CI**
  - 2.5.1. **Decision:** Add GitHub Actions validation matrix workflow for multi-OS `compile-only` + `unit` with SDK checkout
    - Rejected: Manual host-only execution (slower feedback)
    - Rejected: `full` profile in hosted CI (requires licensed runtime)

- **2.6. SDK Bootstrap Tolerance**
  - 2.6.1. **Decision:** Make SDK bootstrap tolerant to variant layouts (`ida-cmake/`, `cmake/`, `src/cmake/`) with recursive submodule checkout
    - Rejected: Pin to one layout (fragile)
    - Rejected: Require manual path overrides (error-prone)

- **2.7. Cross-Generator Config Passing**
  - 2.7.1. **Decision:** Always pass build config to both build and test commands (`cmake --build --config`, `ctest -C`)
    - Rejected: Conditional branch by generator (higher complexity)

- **2.8. Example Addon Compilation in CI**
  - 2.8.1. **Decision:** Enable example addon compilation in hosted validation (`IDAX_BUILD_EXAMPLES=ON`, `IDAX_BUILD_EXAMPLE_ADDONS=ON`)
    - Rejected: Keep examples disabled (misses regressions)
    - Rejected: Separate examples-only workflow (extra maintenance)

- **2.9. Tool-Port Example Compilation**
  - 2.9.1. **Decision:** Expand matrix automation to compile tool-port examples by default (`IDAX_BUILD_EXAMPLE_TOOLS`)
    - Rejected: Keep out of matrix (higher drift)
    - Rejected: Separate tools-only workflow (extra maintenance)

- **2.10. Linux Compiler Pairing**
  - 2.10.1. **Decision:** Adopt Linux Clang 19 + libstdc++ as known-good compile-only pairing; keep addon/tool toggles OFF until `x64_linux_clang_64` SDK runtime libs available
    - Rejected: Clang 18 + libc++ (SDK macro collisions)
    - Rejected: Force addon/tool ON immediately (deterministic failures)

- **2.11. Open-Point Closure Automation**
  - 2.11.1. **Decision:** Add `scripts/run_open_points.sh` + host-native fixture build helper + multi-path Appcall launch bootstrap
    - Rejected: Manual command checklist only (high friction)
    - Rejected: Direct `dbg_appcall` without launch bootstrap (weaker diagnostics)

- **2.12. idalib Tool Linking Policy**
  - 2.12.1. **Decision:** Prefer real IDA runtime dylibs for idalib tool examples when available, fallback to stubs
    - Rejected: `ida_add_idalib`-only (runtime crashes)
    - Rejected: Require `IDADIR` unconditionally (breaks no-runtime compile rows)

---



### 3. Event System

- **3.1. Generic IDB Event Routing**
  - 3.1.1. **Decision:** Add generic IDB event routing (`ida::event::Event`, `on_event`, `on_event_filtered`) on top of typed subscriptions
    - 3.1.1.1. Enables reusable filtering without raw SDK vararg notifications
    - Rejected: Many narrowly-scoped filtered helpers (API bloat)
    - Rejected: Raw `idb_event` codes (leaks SDK)

- **3.2. Generic UI/VIEW Event Routing**
  - 3.2.1. **Decision:** Add generic UI/VIEW routing in `ida::ui` (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite-token unsubscribe
    - Rejected: Many discrete handlers (cumbersome)
    - Rejected: Raw notification codes + `va_list` (unsafe/non-opaque)

---

### 4. UI & Widget System

- **4.1. Dock Widget Host API**
  - 4.1.1. **Decision:** Add opaque dock widget host API (`Widget` handle, `create_widget`/`show_widget`/`activate_widget`/`find_widget`/`close_widget`/`is_widget_visible`, `DockPosition`, `ShowWidgetOptions`) to `ida::ui`
    - 4.1.1.1. Closes entropyx P0 gaps #1/#2
    - Rejected: Expose `TWidget*` (violates opacity)
    - Rejected: Title-only API (fragile for multi-panel)

- **4.2. Widget Event Subscriptions**
  - 4.2.1. **Decision:** Add handle-based widget event subscriptions (`on_widget_visible/invisible/closing(Widget&, cb)`) alongside title-based variants, plus `on_cursor_changed(cb)` for HT_VIEW `view_curpos`
    - 4.2.1.1. Closes entropyx P0 gaps #2/#3
    - Rejected: Title-based only (fragile for multi-instance)

- **4.3. Widget Host Bridge**
  - 4.3.1. **Decision:** Add opaque widget host bridge (`WidgetHost`, `widget_host()`, `with_widget_host()`) for Qt/content embedding without exposing SDK/Qt types
    - 4.3.1.1. Scoped callback over raw getter reduces accidental long-lived pointer storage
    - Rejected: Expose `TWidget*` (breaks opacity)
    - Rejected: Raw getter only (encourages long-lived storage)

- **4.4. Navigation**
  - 4.4.1. **Decision:** Add `ui::jump_to(Address)` wrapping SDK `jumpto()`
    - 4.4.1.1. Closes entropyx P0 gap #4
    - Rejected: Manual screen_address+navigate (missing core operation)

- **4.5. Form API**
  - 4.5.1. **Decision:** Add markup-only `ida::ui::ask_form(std::string_view)`
    - Rejected: Defer (leaves flow blocked)
    - Rejected: Raw vararg `ask_form` (unsafe/non-opaque)

---

### 5. Plugin / Loader / Processor Module Authoring

- **5.1. Plugin Macro**
  - 5.1.1. **Decision:** Implement `IDAX_PLUGIN(ClassName)` macro with `plugmod_t` bridge, static char buffers for `plugin_t PLUGIN`, factory registration via `detail::make_plugin_export()`
    - 5.1.1.1. Closes entropyx P0 gap #6
    - Rejected: Require users write own PLUGIN struct (defeats wrapper)
    - Rejected: Put PLUGIN in user TU via macro (requires SDK includes)

- **5.2. Processor Callbacks**
  - 5.2.1. **Decision:** Expose processor switch/function-heuristic callbacks through SDK-free public structs and virtuals
    - 5.2.1.1. Keeps procmod authoring opaque while preserving advanced capabilities
    - Rejected: Expose raw `switch_info_t`/`insn_t` (violates opacity)
    - Rejected: Defer until full event bridge rewrite (blocks progressive adoption)

- **5.3. Action Context**
  - 5.3.1. **Decision:** Add `plugin::ActionContext` and context-aware callbacks (`handler_with_context`, `enabled_with_context`)
    - Rejected: Raw `action_activation_ctx_t*` (breaks opacity)
    - Rejected: Replace existing no-arg callbacks (unnecessary migration breakage)

- **5.4. Action Context Host Bridges**
  - 5.4.1. **Decision:** Add `ActionContext::{widget_handle, focused_widget_handle, decompiler_view_handle}` with scoped callbacks
    - Rejected: Normalized context only (blocks lifter popup flows)
    - Rejected: Raw SDK types (breaks opacity)

- **5.5. Headless Plugin-Load Policy**
  - 5.5.1. **Decision:** Add headless plugin-load policy via `RuntimeOptions` + `PluginLoadPolicy`
    - Rejected: Environment-variable workarounds only (weak portability)
    - Rejected: Standalone plugin-policy APIs outside init (weaker lifecycle)

---

### 6. Segment, Function, Address & Instruction APIs

- **6.1. Segment Type**
  - 6.1.1. **Decision:** Add `Segment::type()` getter, `set_type()`, expanded `Type` enum (Import, InternalMemory, Group)
    - 6.1.1.1. Closes entropyx P0 gap #5
    - Rejected: Raw `uchar` (violates opaque naming)

- **6.2. Predicate-Based Traversal Ranges**
  - 6.2.1. **Decision:** Add predicate-based traversal ranges (`code_items`, `data_items`, `unknown_bytes`) and discoverability aliases (`next_defined`, `prev_defined`) in `ida::address`
    - Rejected: Only predicate search primitives (less ergonomic for range-for)

- **6.3. Patch & Load Convenience Wrappers**
  - 6.3.1. **Decision:** Add data patch-revert and load-intent convenience wrappers (`revert_patch`, `revert_patches`, `database::OpenMode`, `LoadIntent`, `open_binary`, `open_non_binary`)
    - Rejected: Raw bool/patch APIs only (low discoverability)
    - Rejected: Raw loader entrypoints (leaks complexity)

- **6.4. Structured Operand Introspection**
  - 6.4.1. **Decision:** Add structured operand introspection in `ida::instruction` (`Operand::byte_width`, `register_name`, `register_category`, vector/mask predicates, address-index helpers) and migrate lifter probe away from operand-text heuristics
    - Rejected: Keep probe-local text parsing (drift-prone)
    - Rejected: Expose raw SDK `op_t` in public API (breaks opacity)

---

### 7. Name, Xref, Comment, Type & Entry APIs

- **7.1. Typed Name Inventory**
  - 7.1.1. **Decision:** Add typed name inventory APIs (`Entry`, `ListOptions`, `all`, `all_user_defined`)
    - Rejected: Keep fallback address scanning (weaker discoverability/performance)
    - Rejected: Raw SDK nlist APIs (leaks SDK concepts)

- **7.2. TypeInfo Decomposition**
  - 7.2.1. **Decision:** Add `TypeInfo` decomposition and typedef-resolution helpers (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`)
    - Rejected: Keep decomposition in external code (duplicated complexity)
    - Rejected: Raw SDK `tinfo_t` utilities (breaks opacity)

---

### 8. Database & Storage

- **8.1. Database Metadata Helpers**
  - 8.1.1. **Decision:** Add database metadata helpers (`file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`)
    - Rejected: Keep metadata in external tools via raw SDK (inconsistent migration)
    - Rejected: New diagnostics namespace (weaker discoverability)

- **8.2. Node-Identity Helpers (P10.7.e)**
  - 8.2.1. **Decision:** Add node-identity helpers (`Node::open_by_id`, `Node::id`, `Node::name`)
    - Rejected: Name-only open (weaker lifecycle ergonomics)
    - Rejected: Raw `netnode` ids/constructors (leaks SDK)

---

### 9. Lumina Integration

- **9.1. Lumina Facade**
  - 9.1.1. **Decision:** Add `ida::lumina` facade with pull/push wrappers (`has_connection`, `pull`, `push`, typed `BatchResult`/`OperationCode`)
    - Rejected: Keep raw SDK for external tools (inconsistent ergonomics)
    - Rejected: Raw `lumina_client_t` (breaks opacity)

- **9.2. Close API Unsupported**
  - 9.2.1. **Decision:** Keep Lumina close APIs as explicit `Unsupported` — runtime dylibs don't export `close_server_connection2`/`close_server_connections` despite SDK declarations
    - Rejected: Call non-exported symbols (link failure)
    - Rejected: Remove close APIs (weaker discoverability)

---

### 10. SDK Parity Closure (Phase 10)

- **10.1. Parity Strategy**
  - 10.1.1. **Decision:** Formalize SDK parity closure as Phase 10 with matrix-driven domain-by-domain checklist and evidence gates
    - Rejected: Ad hoc parity fixes only (poor visibility)
    - Rejected: Docs snapshot without TODO graph (weak progress control)
  - 10.1.2. **Decision:** Use dual-axis coverage matrix (`docs/sdk_domain_coverage_matrix.md`) with domain rows and SDK capability-family rows
    - Rejected: Domain-only (hides cross-domain gaps)
    - Rejected: Capability-only (weak ownership mapping)

- **10.2. Intentional Abstraction Notes (P10.9.a)**
  - 10.2.1. **Decision:** Resolve via explicit intentional-abstraction notes for cross-cutting/event rows (`ida::core`, `ida::diagnostics`, `ida::event`)
    - Rejected: Force all rows `covered` by broad raw-SDK mirroring (API bloat)

- **10.3. Segment/Function/Instruction Parity (P10.3)**
  - 10.3.1. **Decision:** Close P10.3 with additive segment/function/instruction parity
    - 10.3.1.1. Segment: resize/move/comments/traversal
    - 10.3.1.2. Function: update/reanalysis/address iteration/frame+regvar
    - 10.3.1.3. Instruction: jump classifiers + operand text/format unification
    - Rejected: Defer to P10.8 (leaves rows partial)
    - Rejected: Raw SDK classifier/comment entrypoints (violates opacity)

- **10.4. Metadata Parity (P10.4)**
  - 10.4.1. **Decision:** Close P10.4 with additive metadata parity in name/xref/comment/type/entry/fixup
    - 10.4.1.1. Name: identifier validation
    - 10.4.1.2. Xref: range+typed filters
    - 10.4.1.3. Comment: indexed comment editing
    - 10.4.1.4. Type: function/cc/enum type workflows
    - 10.4.1.5. Entry: forwarder management
    - 10.4.1.6. Fixup: expanded descriptor + signed/range helpers
    - Rejected: Defer to docs-only sweep (leaves rows partial)
    - Rejected: Raw SDK enums/flags (weakens conceptual API)

- **10.5. Search/Analysis Parity (P10.5)**
  - 10.5.1. **Decision:** Close P10.5 with additive search/analysis parity
    - 10.5.1.1. Typed immediate/binary options
    - 10.5.1.2. `next_error`/`next_defined`
    - 10.5.1.3. Explicit schedule-intent APIs
    - 10.5.1.4. Cancel/revert wrappers
    - Rejected: Minimal direction-only + AU_CODE-only (low intent clarity)
    - Rejected: Raw `SEARCH_*`/`AU_*` constants (leaks SDK encoding)

- **10.6. Module-Authoring Parity (P10.6)**
  - 10.6.1. **Decision:** Close P10.6 with additive module-authoring parity in plugin/loader/processor
    - 10.6.1.1. Plugin: action detach helpers
    - 10.6.1.2. Loader: typed loader request/flag models
    - 10.6.1.3. Processor: `OutputContext` + context-driven hooks, advanced descriptor/assembler checks
    - Rejected: Replace legacy callbacks outright (migration breakage)
    - Rejected: Raw SDK callback structs/flag bitmasks (violates opacity)

- **10.7. Domain-Specific Parity Sub-Phases**
  - **10.7.1. Debugger Parity (P10.7.a)**
    - 10.7.1.1. **Decision:** Close with async/request and introspection helpers (`request_*`, `run_requests`, `is_request_running`, thread enumeration/control, register introspection)
      - Rejected: Raw `request_*` SDK calls only (inconsistent error model)
      - Rejected: Defer to P10.8 (leaves row partial)
  - **10.7.2. UI Parity (P10.7.b)**
    - 10.7.2.1. **Decision:** Close with custom-viewer and broader UI/VIEW event routing
      - 10.7.2.1.1. Custom viewer: `create_custom_viewer`, line/count/jump/current/refresh/close
      - 10.7.2.1.2. Events: `on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`
      - Rejected: Defer to P10.8 (leaves rows partial)
      - Rejected: Raw SDK custom-viewer structs (weakens opaque boundary)
  - **10.7.3. Graph Parity (P10.7.c)**
    - 10.7.3.1. **Decision:** Close with viewer lifecycle/query helpers (`has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, `close_graph_viewer`) and layout-state introspection (`Graph::current_layout`)
      - Rejected: Title-only refresh/show (insufficient lifecycle)
      - Rejected: UI-only layout effects without state introspection (brittle in headless)
  - **10.7.4. Decompiler Parity (P10.7.d)**
    - 10.7.4.1. **Decision:** Close with variable-retype and expanded comment/ctree workflows (`retype_variable` by name/index, orphan-comment query/cleanup)
      - Rejected: Raw Hex-Rays lvar/user-info structs (breaks opacity)
      - Rejected: Defer to P10.8 (leaves row partial)
  - **10.7.5. Storage Parity (P10.7.e)**
    - *(See §8.2 — Node-identity helpers)*

- **10.8. Evidence Closure (P10.8.d / P10.9.d)**
  - 10.8.1. **Decision:** Close using hosted matrix evidence + local full/packaging evidence
    - Rejected: Keep open until every runtime row is host-complete (scope creep)
    - Rejected: Ignore hosted evidence (weaker reproducibility)

---

### 11. Decompiler Integration

- **11.1. Typed Call-Subexpression Accessors**
  - 11.1.1. **Decision:** Add typed decompiler call-subexpression accessors (`call_callee`, `call_argument(index)`)
    - Rejected: Keep call parsing in external examples (weak portability)
    - Rejected: Raw `cexpr_t*` (breaks opacity)

- **11.2. Generic Typed-Value Facade**
  - 11.2.1. **Decision:** Add generic typed-value facade (`TypedValue`, `TypedValueKind`, `read_typed`, `write_typed`) with recursive array materialization
    - Rejected: Keep typed decoding in external ports (duplicated)
    - Rejected: SDK-level typed-value helpers (weakens opacity)

- **11.3. Structured Decompile-Failure Details**
  - 11.3.1. **Decision:** Add structured decompile-failure details (`DecompileFailure` + `decompile(address, &failure)`)
    - Rejected: Context only in `ida::Error` strings (weakly structured)
    - Rejected: Raw `hexrays_failure_t` (breaks opacity)

- **11.4. Microcode Retrieval**
  - 11.4.1. **Decision:** Add microcode retrieval APIs (`DecompiledFunction::microcode()`, `microcode_lines()`)
    - Rejected: Keep raw SDK for microcode (weak parity)
    - Rejected: Expose `mba_t`/raw printer (breaks opacity)

- **11.5. Lifter Maturity/Outline/Cache Gaps**
  - 11.5.1. **Decision:** Close with additive APIs (`on_maturity_changed`, `mark_dirty`, `mark_dirty_with_callers`, `is_outlined`, `set_outlined`)
    - Rejected: Keep as audit-only gaps (delays value)
    - Rejected: Raw Hex-Rays callbacks (breaks opacity)

- **11.6. Typed Decompiler-View Wrappers**
  - 11.6.1. **Decision:** Add typed decompiler-view edit/session wrappers (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`) operating through stable function identity
    - Rejected: Continue raw host-pointer callback-only workflows (ergonomic gap)
    - Rejected: Expose `vdui_t`/`cfunc_t` in public API (opacity break)
  - 11.6.2. **Decision:** Harden decompiler-view integration checks around backend variance by asserting failure semantics (for missing locals) instead of fixed error category
    - Rejected: Strict `NotFound` category checks (flaky across runtimes)
  - 11.6.3. **Decision:** Keep decompiler-view helper integration coverage non-persisting to avoid fixture drift
    - Rejected: Save-comment roundtrips in helper tests (mutates `.i64` fixtures)
    - Rejected: Fixture rewrite-only cleanup without test hardening (repeat churn)

---

### 12. Microcode Filter & Emission System

- **12.1. Baseline Filter Registration**
  - 12.1.1. **Decision:** Add baseline microcode-filter registration (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`)
    - Rejected: Keep raw SDK-only (blocks migration)
    - Rejected: Expose raw `codegen_t`/`microcode_filter_t` (breaks opacity)

- **12.2. Operand/Register/Memory Emit Helpers**
  - 12.2.1. **Decision:** Expand `MicrocodeContext` with operand/register/memory/helper emit helpers
    - Rejected: Keep only `emit_noop` until full typed-IR design (too limiting)
    - Rejected: Expose raw `codegen_t` (opacity break)

- **12.3. Temporary Register Allocation**
  - 12.3.1. **Decision:** Add `MicrocodeContext::allocate_temporary_register(byte_width)` mirroring `mba->alloc_kreg`
    - Rejected: Keep raw-SDK-only (preserves escape hatches)
    - Rejected: Infer indirectly via load helpers (insufficient)

- **12.4. Helper-Call System**
  - **12.4.1. Typed Helper-Call Argument Builders**
    - 12.4.1.1. **Decision:** Add typed helper-call argument builders (`MicrocodeValueKind`, `MicrocodeValue`, `emit_helper_call_with_arguments[_to_register]`)
      - Rejected: Raw `mcallarg_t`/`mcallinfo_t` (opacity break)
      - Rejected: Defer until full vector/UDT design (delays value)
  - **12.4.2. Helper-Call Option Shaping**
    - 12.4.2.1. **Decision:** Add helper-call option shaping (`MicrocodeCallOptions`, `MicrocodeCallingConvention`, `emit_helper_call_with_arguments_and_options[_to_register_and_options]`)
      - Rejected: Raw `mcallinfo_t` mutators (opacity break)
      - Rejected: Defer all callinfo shaping (delays value)
  - **12.4.3. Scalar FP Immediates & Location Hinting**
    - 12.4.3.1. **Decision:** Expand with scalar FP immediates (`Float32Immediate`/`Float64Immediate`) + explicit-location hinting
      - Rejected: Jump to vector/UDT (too large for one slice)
      - Rejected: Raw `mcallarg_t`/`argloc_t` (opacity break)
  - **12.4.4. Default `solid_argument_count` Inference**
    - 12.4.4.1. **Decision:** Add default inference from argument lists
      - Rejected: Keep all explicit at call sites (repetitive)
      - Rejected: Hardcode one value (incorrect for variable arity)
  - **12.4.5. Auto-Stack Placement Controls**
    - 12.4.5.1. **Decision:** Add `auto_stack_start_offset`, `auto_stack_alignment`
      - Rejected: Fixed internal heuristic only (limited control)
      - Rejected: Require explicit location for every non-scalar (heavier boilerplate)
  - **12.4.6. Insertion Policy Extension**
    - 12.4.6.1. **Decision:** Extend helper-call with insertion-policy hinting (`MicrocodeCallOptions::insert_policy`)
      - Rejected: Separate helper-call-with-policy overload family (API bloat)
      - Rejected: Raw block/anchor handles (opacity break)
  - **12.4.7. Register Return — Wider Widths**
    - 12.4.7.1. **Decision:** Expand helper-call register-return fallback for wider destinations with byte-array `tinfo_t` synthesis
      - Rejected: `Unsupported` for widths >8 (blocks packed patterns)
      - Rejected: Require explicit declaration everywhere (excessive boilerplate)
  - **12.4.8. Register Arguments — Wider Widths**
    - 12.4.8.1. **Decision:** Expand helper-call register-argument with declaration-driven non-integer widths + size validation
      - Rejected: Integer-only arguments (insufficient)
      - Rejected: Require `TypeDeclarationView` + explicit location for all (less ergonomic)
  - **12.4.9. Register Return — Non-Integer**
    - 12.4.9.1. **Decision:** Expand helper-call register-return with declaration-driven non-integer widths + size validation
      - Rejected: Integer-only returns (insufficient for wider types)
      - Rejected: Raw `mcallinfo_t`/`mop_t` return mutation (opacity break)
  - **12.4.10. Argument Metadata**
    - 12.4.10.1. **Decision:** Add optional metadata (`argument_name`, `argument_flags`, `MicrocodeArgumentFlag`)
      - Rejected: Implicit metadata only (insufficient callinfo fidelity)
      - Rejected: Raw `mcallarg_t` mutation (opacity break)
  - **12.4.11. Return Writeback to Instruction Operands**
    - 12.4.11.1. **Decision:** Add `emit_helper_call_with_arguments_to_operand[_and_options]` for compare/mask-destination flows
      - Rejected: Keep compare mask destinations as no-op tolerance (semantic loss)
      - Rejected: Require raw SDK call/mop plumbing in ports (migration friction)
  - **12.4.12. tmop Destinations**
    - 12.4.12.1. **Decision:** Expand helper-call tmop shaping with typed micro-operand destinations (`emit_helper_call_with_arguments_to_micro_operand[_and_options]`) and argument value kinds (`BlockReference`, `NestedInstruction`)
      - Rejected: Keep register/instruction-operand-only helper returns (limits richer callarg modeling)
      - Rejected: Expose raw `mop_t`/`mcallarg_t` APIs (opacity break)
  - **12.4.13. Memory-Source Operand Forwarding**
    - 12.4.13.1. **Decision:** Extend helper fallback to accept memory-source operands via effective-address extraction + pointer arguments
      - Rejected: Register-only fallback (misses many forms)
      - Rejected: Fail hard on memory sources (unnecessary instability)

- **12.5. Argument Location Hints**
  - **12.5.1. Basic Register/Stack**
    - 12.5.1.1. **Decision:** Add basic explicit argument-location hints (`MicrocodeValueLocation` register/stack-offset) with auto-promotion
      - Rejected: Raw `argloc_t` (opacity break)
      - Rejected: Defer all location-shaping (delays value)
  - **12.5.2. Register-Pair & Register-with-Offset**
    - 12.5.2.1. **Decision:** Expand `MicrocodeValueLocation` with register-pair and register-with-offset forms
      - Rejected: Register/stack-only (too limiting)
      - Rejected: Raw `argloc_t` (opacity break)
  - **12.5.3. Static Address**
    - 12.5.3.1. **Decision:** Add static-address location hints (`StaticAddress` → `argloc_t::set_ea`)
      - Rejected: Keep without global-location patterns (misses common patterns)
      - Rejected: Raw `argloc_t` (opacity break)
  - **12.5.4. Scattered/Multi-Part**
    - 12.5.4.1. **Decision:** Add scattered/multi-part location hints (`Scattered` + `MicrocodeLocationPart`)
      - Rejected: Single-location only (insufficient for split-placement)
      - Rejected: Raw `argpart_t`/`scattered_aloc_t` (opacity break)
  - **12.5.5. Register-Relative**
    - 12.5.5.1. **Decision:** Add register-relative location hints (`RegisterRelative` → `consume_rrel`)
      - Rejected: Keep without `ALOC_RREL` (misses practical cases)
      - Rejected: Raw `rrel_t` (opacity break)

- **12.6. Argument Value Kinds**
  - **12.6.1. Byte-Array**
    - 12.6.1.1. **Decision:** Add byte-array helper-call argument modeling (`MicrocodeValueKind::ByteArray`) with explicit-location enforcement
      - Rejected: Defer all non-scalar (delays value)
      - Rejected: Raw `mcallarg_t` (opacity break)
  - **12.6.2. Vector**
    - 12.6.2.1. **Decision:** Add vector helper-call argument modeling (`MicrocodeValueKind::Vector`) with typed element controls
      - Rejected: Defer until full UDT abstraction (delays value)
      - Rejected: Raw `mcallarg_t`/type plumbing (opacity break)
  - **12.6.3. TypeDeclarationView**
    - 12.6.3.1. **Decision:** Add declaration-driven argument modeling (`MicrocodeValueKind::TypeDeclarationView`) via `parse_decl`
      - Rejected: Defer until full UDT APIs (delays value)
      - Rejected: Raw `tinfo_t`/`mcallarg_t` (opacity break)
  - **12.6.4. Immediate Type Declaration**
    - 12.6.4.1. **Decision:** Expand immediate typed arguments with optional `type_declaration` + parse/size validation + width inference
      - Rejected: Keep immediates integer-only (loses declaration intent)
      - Rejected: Separate immediate-declaration kind (unnecessary surface growth)

- **12.7. Callinfo Flags & Fields**
  - **12.7.1. Flags**
    - 12.7.1.1. **Decision:** Expand callinfo flags (`mark_dead_return_registers`, `mark_spoiled_lists_optimized`, `mark_synthetic_has_call`, `mark_has_format_string` → `FCI_DEAD`/`FCI_SPLOK`/`FCI_HASCALL`/`FCI_HASFMT`)
      - Rejected: Minimal flags only (too restrictive)
      - Rejected: Raw `mcallinfo_t` flag mutation (opacity break)
  - **12.7.2. Scalar Field Hints**
    - 12.7.2.1. **Decision:** Expand callinfo with scalar field hints (`callee_address`, `solid_argument_count`, `call_stack_pointer_delta`, `stack_arguments_top`)
      - Rejected: Keep field-level shaping internal (insufficient fidelity)
      - Rejected: Raw `mcallinfo_t` mutators (opacity break)
  - **12.7.3. Semantic Role & Return-Location**
    - 12.7.3.1. **Decision:** Expand callinfo with semantic role + return-location hints (`MicrocodeFunctionRole`, `function_role`, `return_location`)
      - Rejected: Raw `funcrole_t`/`argloc_t`/`mcallinfo_t` (opacity break)
      - Rejected: Scalar hints only (insufficient parity)
  - **12.7.4. Declaration-Based Return-Type**
    - 12.7.4.1. **Decision:** Expand callinfo with declaration-based return-type hints (`return_type_declaration` via `parse_decl`)
      - Rejected: Implicit return via destination register only (insufficient fidelity)
      - Rejected: Raw `mcallinfo_t`/`tinfo_t` mutation (opacity break)
  - **12.7.5. Passthrough/Spoiled Validation**
    - 12.7.5.1. **Decision:** Tighten `passthrough_registers` to always require subset of `spoiled_registers`
      - Rejected: Conditional validation only when both specified (permits inconsistent states)
      - Rejected: Auto-promote into spoiled silently (obscures intent/errors)
  - **12.7.6. Coherence Validation**
    - 12.7.6.1. **Decision:** Validate callinfo coherence via validation-first probes rather than success-path emissions
      - Rejected: Success-path emissions in filter tests (flaky)
      - Rejected: Drop coherence assertions (weaker coverage)
  - **12.7.7. Advanced List Shaping**
    - 12.7.7.1. **Decision:** Expand writable IR with richer non-scalar/callinfo/tmop semantics: declaration-driven vector element typing, `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` mop builders, callinfo list shaping for return/spoiled/passthrough/dead registers + visible-memory ranges
      - Rejected: Option-hint-only callinfo (insufficient parity)
      - Rejected: Raw `mop_t`/`mcallinfo_t` mutators (opacity break)

- **12.8. Generic Typed Instruction Emission**
  - **12.8.1. Baseline**
    - 12.8.1.1. **Decision:** Add baseline generic typed instruction emission (`MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`, `emit_instruction`, `emit_instructions`)
      - Rejected: Helper-call-only expansion (insufficient for AVX/VMX handlers)
      - Rejected: Raw `minsn_t`/`mop_t` (opacity break)
  - **12.8.2. Placement Policy**
    - 12.8.2.1. **Decision:** Add constrained placement-policy controls (`MicrocodeInsertPolicy`, `emit_instruction_with_policy`, `emit_instructions_with_policy`)
      - Rejected: Raw `mblock_t::insert_into_block`/`minsn_t*` (opacity break)
      - Rejected: Tail-only insertion (insufficient for real ordering)
  - **12.8.3. Typed Operand Kinds**
    - 12.8.3.1. **Decision:** Add `MicrocodeOperandKind::BlockReference` with validated `block_index`
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw block handles (opacity break)
    - 12.8.3.2. **Decision:** Add `MicrocodeOperandKind::NestedInstruction` with recursive typed payload + depth limiting
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw `minsn_t*` (opacity/ownership break)
    - 12.8.3.3. **Decision:** Add `MicrocodeOperandKind::LocalVariable` with `local_variable_index`/`offset`
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw `mop_t`/`lvar_t` (opacity break)
  - **12.8.4. Local-Variable Shaping**
    - 12.8.4.1. **Decision:** Expand local-variable shaping with value-side modeling + `MicrocodeContext::local_variable_count()` guard + no-op fallback
      - Rejected: Instruction-only local-variable support (leaves helper/value incomplete)
      - Rejected: Hardcode indices (brittle)
    - 12.8.4.2. **Decision:** Consolidate local-variable self-move emission into shared helper (`try_emit_local_variable_self_move`)
      - Rejected: Duplicate per-mnemonic logic (drift-prone)
      - Rejected: Limit to one mnemonic (weaker parity pressure)

- **12.9. Typed Opcode Expansion**
  - **12.9.1. Packed Bitwise/Shift**
    - 12.9.1.1. **Decision:** Add typed packed bitwise/shift opcodes (`BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`)
      - Rejected: Keep all in helper fallback (weaker typed-IR parity)
      - Rejected: Very broad opcode set in one step (higher regression risk)
  - **12.9.2. Subtract**
    - 12.9.2.1. **Decision:** Add `MicrocodeOpcode::Subtract`, route `vpadd*`/`vpsub*` through typed emission first
      - Rejected: Keep in helper fallback only (weaker parity)
      - Rejected: Broader integer/vector opcode surface in one pass (higher risk)
  - **12.9.3. Packed Integer Dual-Path**
    - 12.9.3.1. **Decision:** Keep packed integer dual-path (typed first, helper fallback second) with saturating-family helper routing
      - Rejected: Map saturating onto plain Add/Subtract (semantic mismatch)
      - Rejected: Typed-only for integer add/sub (misses memory/saturating)
  - **12.9.4. Multiply**
    - 12.9.4.1. **Decision:** Add `MicrocodeOpcode::Multiply`, route `vpmulld`/`vpmullq` through typed emission; other variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) use helper-call fallback
      - Rejected: Keep all multiply in helper (weaker parity)
      - Rejected: Map all variants to typed multiply (semantic mismatch)
  - **12.9.5. Two-Operand Implicit-Source**
    - 12.9.5.1. **Decision:** Treat two-operand packed binary encodings as destination-implicit-left-source
      - Rejected: Three-operand-only typed path (unnecessary fallback churn)
      - Rejected: Force helper for all two-operand (weaker parity)

- **12.10. Low-Level Emit Helpers**
  - **12.10.1. Policy-Aware Placement**
    - 12.10.1.1. **Decision:** Add policy-aware placement for low-level emit helpers (`emit_noop/move/load/store_with_policy`)
      - Rejected: Keep low-level helpers tail-only (uneven placement parity)
      - Rejected: Bespoke per-call-site placement (brittle/non-discoverable)
  - **12.10.2. Optional UDT-Marking**
    - 12.10.2.1. **Decision:** Add optional UDT-marking to low-level move/load/store emit helpers (including policy-aware overloads)
      - Rejected: UDT shaping limited to typed-instruction builders (leaves low-level gap)
      - Rejected: Require raw SDK post-emit mutation (weakens migration path)
  - **12.10.3. Store Operand Register UDT Overload**
    - 12.10.3.1. **Decision:** Add `store_operand_register(..., mark_user_defined_type)` overload
      - Rejected: Keep integer/default-only (leaves residual gap)
      - Rejected: Route all writebacks through lower-level helpers (loses ergonomic path)

- **12.11. Microcode Lifecycle Helpers**
  - 12.11.1. **Decision:** Add microcode lifecycle convenience helpers (`block_instruction_count`, `has_last_emitted_instruction`, `remove_last_emitted_instruction`) on `MicrocodeContext`
    - Rejected: Expose raw `mblock_t`/`minsn_t*` publicly (opacity/ownership hazards)
    - Rejected: Leave lifecycle bookkeeping to ports (duplicated fragile logic)
  - 12.11.2. **Decision:** Expand microblock lifecycle ergonomics with index-based query/removal (`has_instruction_at_index`, `remove_instruction_at_index`)
    - Rejected: Expose raw `mblock_t` iterators/links (opacity break)
    - Rejected: Keep last-emitted-only removal (insufficient for deterministic rewrites)

- **12.12. Lifter Follow-Up Strategy**
  - 12.12.1. **Decision:** Execute lifter follow-up via source-backed gap matrix with closure slices
    - 12.12.1.1. P0: Generic instruction builder
    - 12.12.1.2. P1: Callinfo depth
    - 12.12.1.3. P2: Placement
    - 12.12.1.4. P3: Typed view ergonomics
    - Rejected: Broad blocker-only wording (weak guidance)
    - Rejected: Large raw-SDK mirror (opacity/stability risk)

---

### 13. Debugger Integration

- **13.1. Backend Discovery**
  - 13.1.1. **Decision:** Add debugger backend discovery (`BackendInfo`, `available_backends`, `current_backend`, `load_backend`) + queued launch/attach (`request_start`, `request_attach`)
    - Rejected: Keep backend logic private in examples (weak discoverability)
    - Rejected: Synchronous start/attach only (misses async path)

- **13.2. Appcall Facade**
  - 13.2.1. **Decision:** Add Appcall + pluggable executor facade (`AppcallValue`, `AppcallRequest`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`)
    - Rejected: Keep dynamic execution out-of-scope (leaves gap open)
    - Rejected: Raw SDK `idc_value_t`/`dbg_appcall` (breaks opacity)

- **13.3. Appcall Smoke Testing**
  - 13.3.1. **Decision:** Add fixture-backed Appcall runtime validation (`--appcall-smoke`) plus checklist doc
    - Rejected: Keep as ad hoc notes (low reproducibility)
    - Rejected: Standalone new tool binary (target sprawl)
  - 13.3.2. **Decision:** Expand appcall-smoke with hold-mode + default launches across path/cwd permutations
    - Rejected: Default-args-only (weaker diagnosis)
    - Rejected: Attach-only first (requires additional orchestration)

- **13.4. Loader Bridge Export Semantics**
  - 13.4.1. **Decision:** Make `src/loader.cpp` the single SDK-facing export point for `idax` loader modules by emitting `idaman loader_t ida_module_data LDSC` and trampoline callbacks that forward into the `IDAX_LOADER(...)`-registered C++ `ida::loader::Loader` instance.
    - Rejected: Keep `IDAX_LOADER(...)` as `idax_loader_bridge_init`-only (builds but loader is invisible to IDA)
    - Rejected: Require every example/user loader to hand-write a separate raw-SDK `LDSC` block (defeats the wrapper goal)
  - 13.3.3. **Decision:** Add spawn+attach fallback to appcall smoke for better root-cause classification
    - Rejected: Launch-only probes (ambiguous classification)
    - Rejected: Standalone attach utility (target sprawl)
  - 13.3.4. **Decision:** Upgrade appcall-smoke to backend-aware + multi-path execution (load backend → start → request_start → attach → request_attach with state checks)
    - Rejected: Launch-only fallback (less diagnostic depth)
    - Rejected: Host-specific debugger hacks (non-portable)

- **13.4. Queue-Drain Settling**
  - 13.4.1. **Decision:** Add bounded queue-drain settling for request fallbacks (`run_requests` cycles + delays + state checks)
    - Rejected: One-shot `run_requests` (noisy under async hosts)
    - Rejected: Unbounded polling (can hang)

---

### 14. Example Ports & Audit Probes

- **14.1. JBC Full-Port Example**
  - 14.1.1. **Decision:** Add paired JBC full-port example (loader + procmod + shared header) validating idax against real production migration
    - Rejected: Hypothetical-only examples (weaker parity pressure)
    - Rejected: Port only loader or procmod (misses cross-module interactions)
  - 14.1.2. **Decision:** Close JBC parity gaps (#80–#82) with additive processor/segment APIs (typed analyze operand model, default segment-register seeding, tokenized output, mnemonic hook)
    - Rejected: Keep minimal analyze/output + raw SDK escapes (weaker fidelity)
    - Rejected: Replace callbacks outright (migration breakage)

- **14.2. ida-qtform + idalib-dump Ports**
  - 14.2.1. **Decision:** Add real-world port artifacts for ida-qtform + idalib-dump with dedicated audit doc
    - Rejected: Synthetic parity-only checks (miss workflow edges)
    - Rejected: Ad hoc notes only (poor traceability)

- **14.3. ida2py Port Probe**
  - 14.3.1. **Decision:** Add ida2py port probe (`examples/tools/ida2py_port.cpp`) plus standalone audit doc
    - Rejected: Fold into existing audit only (weak traceability)
    - Rejected: Treat as out-of-scope (misses API ergonomics signals)

- **14.4. Lifter Port Probe**
  - 14.4.1. **Decision:** Add lifter port probe plugin (`examples/plugin/lifter_port_plugin.cpp`) plus gap audit doc
    - Rejected: Full direct lifter port (blocked by missing write-path APIs)
    - Rejected: Docs-only without executable probe (weaker regression signal)

- **14.5. VMX Subset Probe**
  - 14.5.1. **Decision:** Add VMX subset to lifter probe using public microcode-filter APIs (no-op `vzeroupper`, helper-call lowering for `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`)
    - Rejected: Keep probe read-only (weaker evidence)
    - Rejected: Full port in one step (blocked by deep write-path APIs)

- **14.6. AVX Scalar Subset**
  - **14.6.1. Basic Arithmetic/Conversion**
    - 14.6.1.1. **Decision:** Extend lifter probe with AVX scalar math/conversion lowering (`vadd/sub/mul/div ss/sd`, `vcvtss2sd`, `vcvtsd2ss`)
      - Rejected: VMX-only until broader vector API (weaker signal)
      - Rejected: Jump to packed directly (higher risk)
  - **14.6.2. XMM Width Handling**
    - 14.6.2.1. **Decision:** Keep AVX scalar subset XMM-oriented — decoded `Operand` value objects lack rendered width text
      - Rejected: Parse disassembly text ad hoc (brittle)
      - Rejected: Overgeneralize wider widths (correctness risk)
  - **14.6.3. Min/Max/Sqrt/Move**
    - 14.6.3.1. **Decision:** Expand with scalar min/max/sqrt/move families (`vmin/vmax/vsqrt/vmov ss/sd`)
      - Rejected: Keep only add/sub/mul/div (leaves common families unexercised)
      - Rejected: Jump to packed (larger surface per change)
  - **14.6.4. Memory-Destination Moves**
    - 14.6.4.1. **Decision:** Handle `vmovss`/`vmovsd` memory-destination before destination-register loading
      - Rejected: One-path destination-register-first (brittle for memory)
      - Rejected: Skip memory-destination moves (leaves common pattern unlifted)

- **14.7. AVX Packed Subset**
  - **14.7.1. Packed Math/Move**
    - 14.7.1.1. **Decision:** Expand to packed math/move (`vadd/sub/mul/div ps/pd`, `vmov*`) with operand-text width heuristics
      - Rejected: Jump to masked packed (larger surface)
      - Rejected: Keep scalar-only until deeper IR (weaker pressure)
  - **14.7.2. Packed Min/Max/Sqrt**
    - 14.7.2.1. **Decision:** Expand packed subset with min/max/sqrt (`vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd`)
      - Rejected: Postpone until deeper IR (slows coverage)
      - Rejected: Typed-emitter-only (missing opcode parity for these)
  - **14.7.3. Packed Conversions**
    - 14.7.3.1. **Decision:** Expand with packed conversions (`vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd`)
      - Rejected: Defer until full vector/tmop DSL (delays high-frequency patterns)
      - Rejected: Helper-call-only for all (less direct parity)
  - **14.7.4. Helper-Fallback Conversions**
    - 14.7.4.1. **Decision:** Expand with helper-fallback conversions (`vcvt*2dq/udq/qq/uqq`, truncating)
      - Rejected: Postpone until new typed opcodes (delays parity)
      - Rejected: Force inaccurate typed mappings (semantic risk)
  - **14.7.5. Addsub/Horizontal**
    - 14.7.5.1. **Decision:** Expand with addsub/horizontal (`vaddsub*`, `vhadd*`, `vhsub*`) via helper-call
      - Rejected: Skip until lane-aware IR (weaker coverage)
      - Rejected: Approximate through plain opcodes (semantic mismatch)
  - **14.7.6. Variadic Bitwise/Permute/Blend**
    - 14.7.6.1. **Decision:** Expand with variadic helper-fallback bitwise/permute/blend
      - Rejected: Wait for typed opcodes first (slower parity)
      - Rejected: Per-mnemonic bespoke handlers (maintenance churn)
  - **14.7.7. Variadic Shift/Rotate**
    - 14.7.7.1. **Decision:** Expand with variadic helper-fallback shift/rotate (`vps*`, `vprol*`, `vpror*`)
      - Rejected: Postpone until typed shift/rotate opcodes (slower parity)
      - Rejected: Per-mnemonic handlers (maintenance-heavy)
  - **14.7.8. Fallback Tolerance**
    - 14.7.8.1. **Decision:** Keep variadic helper fallback tolerant (`NotHandled` over hard error) for broader compare/misc coverage
      - Rejected: Strict erroring on unsupported loads (brittle)
      - Rejected: Delay broad matching until full typed-IR (slower gains)
  - **14.7.9. Compare Mask-Destination Tolerance**
    - 14.7.9.1. **Decision:** Treat unsupported compare mask-destinations as no-op in fallback
      - Rejected: Hard-fail on non-register (destabilizing)
      - Rejected: Defer compare expansion entirely (slower parity)
  - **14.7.10. Resolved-Memory Destination Routing**
    - 14.7.10.1. **Decision:** Expand helper-return micro-operand destination routing from `MemoryDirect`-only to any memory operand with a resolved target address (`target_address != BadAddress`) mapped as `GlobalAddress`
      - Rejected: Keep `MemoryDirect`-only routing (unnecessary operand-writeback fallback)
      - Rejected: Force all memory destinations through operand-index writeback (weaker typed destination coverage)
  - **14.7.11. Compare/VMX Callinfo Enrichment**
    - 14.7.11.1. **Decision:** Begin 5.3.2 depth work by adding semantic compare roles (`SseCompare4`/`SseCompare8` for `vcmp*`) and helper argument-name metadata in lifter probe helper-call paths
      - Rejected: Add aggressive purity/no-side-effect call flags during this slice (higher `INTERR` risk)
      - Rejected: Keep helper-call metadata absent until full callinfo DSL closure (slower parity progress)
  - **14.7.12. Rotate/Metadata Callinfo Enrichment**
    - 14.7.12.1. **Decision:** Extend additive callinfo hints with rotate semantic roles (`RotateLeft`/`RotateRight` for `vprol*`/`vpror*`) and broaden `argument_name` coverage to explicit scalar/packed helper-call paths in addition to variadic/VMX flows
      - Rejected: Add return-location/value-location hints in this slice (higher mismatch risk without dedicated runtime probes)
      - Rejected: Keep metadata scoped to variadic-only paths (slower callarg intent coverage)
  - **14.7.13. Helper Return-Type Enrichment**
    - 14.7.13.1. **Decision:** Apply declaration-driven return typing only to stable helper-return families (integer-width `vmread` register destinations + scalar float/double helper returns)
      - Rejected: Broad vector return-type declaration in this slice (higher declaration/size mismatch risk)
      - Rejected: Leave all helper-return typing implicit (slower callinfo fidelity gains)
  - **14.7.14. Helper Return-Location Enrichment**
    - 14.7.14.1. **Decision:** Apply explicit register `return_location` hints only where helper-return destinations are stable and already modeled as register-target writeback
      - Rejected: Blanket return-location hinting for all helper families (higher mismatch risk)
      - Rejected: Keep return-location unset on stable register paths (lower callinfo intent fidelity)
  - **14.7.15. Callinfo Hardening Assertions**
    - 14.7.15.1. **Decision:** Expand hardening probes to assert both positive callinfo-hint application paths and negative validation paths for location/type-size contracts
      - Rejected: Validation-only checks without positive-path probes (weaker runtime confidence)
      - Rejected: Positive-only checks without invalid-hint validation (weaker contract enforcement)
  - **14.7.16. Unresolved-Shape Fallback Gating**
    - 14.7.16.1. **Decision:** Gate compare helper operand-index writeback fallback to unresolved destination shapes only (mask-register destination or unresolved memory destination)
      - Rejected: Keep unconditional fallback after typed micro-destination attempts (can mask destination-shape regressions)
      - Rejected: Remove fallback entirely (breaks mask-register destination handling)
  - **14.7.17. Cross-Route Callinfo Contract Hardening**
    - 14.7.17.1. **Decision:** Expand hardening validations to assert invalid callinfo return-location/type-size behavior across helper emission routes (`to_micro_operand`, `to_register`, `to_operand`)
      - Rejected: Route-local validation checks only (contract drift risk)
      - Rejected: Positive-path-only callinfo assertions (insufficient validation coverage)
  - **14.7.18. Structured Register-Destination Recovery**
    - 14.7.18.1. **Decision:** For compare helper flows where `load_operand_register(0)` fails, attempt a typed register-destination micro-operand route using structured `Operand::register_id()` before operand-writeback fallback
      - Rejected: Immediate fallback to operand-index writeback (misses recoverable typed routes)
      - Rejected: Hard-fail when register-load helper rejects destination class (drops stable degraded handling)
  - **14.7.19. Resolved-Memory Location-Hint Retry**
    - 14.7.19.1. **Decision:** For compare helper resolved-memory micro-routes, apply static-address `return_location` hints first, then retry without location hints if backend returns validation-level rejection
      - Rejected: Never apply static return-location hints on resolved-memory routes (lower callinfo fidelity)
      - Rejected: Fail hard on location-hint validation rejection (reduced stability)
  - **14.7.20. Register-Location Hint Retry**
    - 14.7.20.1. **Decision:** For compare helper register-destination micro-routes, apply register `return_location` hints first, then retry without location hints on validation-level backend rejection
      - Rejected: Keep strict location-hint requirement (can reject otherwise valid routes)
      - Rejected: Disable register `return_location` hints entirely (lower callinfo intent fidelity)
  - **14.7.21. Global Type-Size Hardening**
    - 14.7.21.1. **Decision:** Extend return-type-size validation hardening to global-destination micro routes to mirror register-route type-size contract checks
      - Rejected: Limit type-size validation checks to register-destination routes only (cross-route drift risk)
      - Rejected: Add positive-only global route probes without invalid type-size checks (weaker contract coverage)
  - **14.7.22. Unresolved-Shape Register-Store Bridge**
    - 14.7.22.1. **Decision:** For unresolved compare destinations, attempt helper-return to temporary register and `store_operand_register` writeback before direct `to_operand` fallback
      - Rejected: Keep direct `to_operand` as first unresolved-shape path (weaker intermediate typed route coverage)
      - Rejected: Remove direct `to_operand` fallback entirely (stability risk for backend-specific shapes)
  - **14.7.23. Compare Route Retry Ladder**
    - 14.7.23.1. **Decision:** For compare helper micro-routes, apply a three-step validation-safe retry ladder (full location+declaration hints -> declaration-only hints -> base compare options)
      - Rejected: Stop after declaration-only retry (can miss backend-variant valid emissions)
      - Rejected: Start with base compare options only (drops semantic intent fidelity prematurely)
  - **14.7.24. Direct-Operand Retry Parity**
    - 14.7.24.1. **Decision:** Apply validation-safe retry with base compare options to degraded `to_operand` compare fallback paths when hint-rich options fail validation
      - Rejected: Keep degraded `to_operand` path single-shot with hint-rich options (higher backend-variant validation failures)
      - Rejected: Force base options first on degraded path (drops hint fidelity prematurely)
  - **14.7.25. Degraded-Operand Validation Tolerance**
    - 14.7.25.1. **Decision:** After degraded compare `to_operand` retries are exhausted, treat residual validation rejection as non-fatal not-handled outcome
      - Rejected: Keep validation rejection as hard error on degraded `to_operand` path (lower backend variance tolerance)
      - Rejected: Silence all degraded-path failures including SDK/internal categories (would mask hard failures)
  - **14.7.26. Cross-Route Retry + Writeback Tolerance Alignment**
    - 14.7.26.1. **Decision:** Align compare helper validation-safe base-options retry behavior across typed micro routes and temporary-register bridge paths, and degrade temporary writeback `Validation`/`NotFound` outcomes to not-handled
      - Rejected: Keep retry behavior uneven across helper emission routes (drift risk)
      - Rejected: Treat temporary writeback validation/not-found as hard errors (reduces backend variance tolerance)
  - **14.7.27. Direct Register-Route Retry Alignment**
    - 14.7.27.1. **Decision:** Apply the same validation-safe retry ladder and non-fatal residual-validation degradation to direct register-destination compare helper routes
      - Rejected: Keep direct register route strict while other compare routes degrade (semantic drift)
      - Rejected: Treat residual validation on direct register route as hard error (lower backend variance tolerance)
  - **14.7.28. Temporary-Bridge Error-Access Guard**
    - 14.7.28.1. **Decision:** Guard temporary-register compare bridge error-category reads behind `!temporary_helper_status` after degradable writeback outcomes
      - Rejected: Read `.error()` unconditionally after degradable store outcomes (invalid on success-path states)
      - Rejected: Convert degradable writeback outcomes into hard failures to avoid guard logic (reduces fallback resilience)
  - **14.7.29. Residual NotFound Degradation Alignment**
    - 14.7.29.1. **Decision:** Treat residual `NotFound` outcomes as not-handled on degraded `to_operand` and direct register-destination compare routes after retry exhaustion
      - Rejected: Preserve `NotFound` as hard unexpected error on degraded compare routes (reduced backend tolerance)
      - Rejected: Degrade all categories including `SdkFailure`/`Internal` (would hide hard failures)
  - **14.7.30. Temporary-Bridge Typed Micro-Operand Destination**
    - 14.7.30.1. **Decision:** Convert compare-helper temporary-register bridge from `_to_register` to `_to_micro_operand` destination routing using known temporary register id as `MicrocodeOperand` with `kind = Register`
      - Rejected: Keep `_to_register` API for temporary bridge (weaker typed-destination parity with other compare routes)
      - Rejected: Remove temporary-register bridge entirely (loses intermediate typed route for unresolved shapes)

---

### 15. Blockers (Live)

- **15.1. B-LIFTER-MICROCODE — RESOLVED**
  - 15.1.1. **Scope:** Full idax-first port of `<lifter-source>` (AVX/VMX microcode transformations)
  - 15.1.2. **Severity:** ~~High~~ → Resolved
  - **15.1.3. Final Capabilities**
    - 15.1.3.1. Generic typed instruction emission (19 opcodes, 7 emission sites in port)
    - 15.1.3.2. Comprehensive callinfo shaping (calling convention, FCI flags, scalar hints, function roles, return-location/type, register lists, visible memory, per-argument name/flag metadata, insert policy)
    - 15.1.3.3. Temporary-register allocation (with automatic lifetime management)
    - 15.1.3.4. Local-variable context query (`local_variable_count`)
    - 15.1.3.5. Typed packed bitwise/shift/add/sub/mul opcode emission
    - 15.1.3.6. Richer typed operand/value mop builders (`LocalVariable`/`RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference`/`BlockReference`/`NestedInstruction`)
    - 15.1.3.7. Declaration-driven vector element typing + named vector type declarations (`__m128`/`__m256i`/`__m512d`)
    - 15.1.3.8. Advanced callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory)
    - 15.1.3.9. Structured instruction operand metadata (`byte_width`/`register_name`/`register_category`)
    - 15.1.3.10. Helper-call return writeback to operands for compare/mask destinations
    - 15.1.3.11. Typed helper-call micro-operand destinations + tmop-oriented callarg value kinds
    - 15.1.3.12. Microcode lifecycle convenience (`block_instruction_count`, tracked last-emitted remove, index query/remove)
    - 15.1.3.13. Typed decompiler-view edit/session wrappers (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`)
    - 15.1.3.14. AVX-512 opmask introspection + uniform masking across all helper-call paths
    - 15.1.3.15. SSE passthrough + K-register NOP handling
    - 15.1.3.16. 300+ individual mnemonics (FMA, IFMA, VNNI, BF16, FP16, cache control, shuffles, etc.)
  - **15.1.4. Lifter Probe Coverage**
    - 15.1.4.1. Full VMX + AVX scalar/packed lifting (300+ mnemonics)
    - 15.1.4.2. All helper-fallback families (conversion/integer-arithmetic/multiply/bitwise/permute/blend/shift/compare/misc/FMA/FP16/BF16)
    - 15.1.4.3. Mixed register/immediate/memory-source forwarding
    - 15.1.4.4. Deterministic compare/mask writeback paths with validation-safe retry ladders
    - 15.1.4.5. SSE passthrough, K-register NOP, AVX-512 opmask masking
    - 15.1.4.6. Named vector type declarations across all helper-call return paths
  - **15.1.5. Resolution Evidence**
    - 15.1.5.1. Deep mutation breadth audit cross-referenced all 14 SDK mutation pattern categories — 13/14 fully covered, 1/14 functionally equivalent via remove+re-emit [F227]
    - 15.1.5.2. All 9 original gap categories (GAP 1–9) closed
    - 15.1.5.3. All 5 source-backed gap matrix items (A–E) closed
    - 15.1.5.4. Port: ~2,700 lines, 26 helper-call sites, 7 typed emission sites, 37 operand loads, 300+ mnemonics
    - 15.1.5.5. No new wrapper APIs required for lifter-class ports
  - 15.1.6. **Artifact:** `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_examples.md`
  - 15.1.7. **Owner:** idax wrapper core

---

### 16. Abyss Port — Lines Domain & Decompiler/UI Expansion (Phase 11)

- **16.1. Decision D-LINES-DOMAIN**: Create `ida::lines` as a new top-level namespace/domain
  - **16.1.1. Rationale:** Color tag manipulation (colstr, tag_remove, tag_advance, tag_strlen, address tags) is a fundamental capability required by any plugin that modifies pseudocode output. It does not belong in `ida::decompiler` (it's used for disassembly too) or `ida::ui` (it's data-level, not widget-level). A dedicated `ida::lines` domain with its own header and implementation file keeps the domain boundary clean.
  - **16.1.2. Alternatives considered:** (a) Put in `ida::decompiler` — rejected, too narrow scope. (b) Put in `ida::ui` — rejected, lines/colors are not UI widgets. (c) Put in `ida::core` — rejected, too broad.
  - **16.1.3. Evidence:** Used by abyss port in 6 of 8 filters for color tag insertion/removal/measurement.

- **16.2. Decision D-DECOMPILER-EVENT-BRIDGE**: Expand single-event hexrays bridge to multi-event switch
  - **16.2.1. Rationale:** The original bridge only handled `hxe_maturity`. Real decompiler plugins need `hxe_func_printed`, `hxe_curpos`, `hxe_create_hint`, `hxe_refresh_pseudocode` at minimum. Rather than separate bridge functions (which would install multiple hexrays callbacks), a single bridge with a switch over event type is more efficient and mirrors the SDK's single-callback design.
  - **16.2.2. Pattern:** One callback map per event type, lazy bridge installation on first subscription, removal when all maps empty.

- **16.3. Decision D-DYNAMIC-ACTIONS**: Use `DynamicActionHandler` class + `DYNACTION_DESC_LITERAL` for popup-only actions
  - **16.3.1. Rationale:** Abyss attaches temporary actions to the decompiler popup menu. These don't need global action registration (which is heavy). The SDK's `attach_dynamic_action_to_popup` + `DYNACTION_DESC_LITERAL` pattern is exactly designed for this. The idax wrapper wraps this in `attach_dynamic_action()` which creates a `DynamicActionHandler` internally and manages its lifetime.
  - **16.3.2. Trade-off:** The handler is heap-allocated and leaked (like SDK examples do). In practice, popup actions are short-lived and few in number.

- **16.4. Decision D-RAW-LINE-ACCESS**: Expose raw `simpleline_t.line` strings through wrapper, not just cleaned text
  - **16.4.1. Rationale:** Pseudocode post-processing filters need to read AND write the raw color-tagged line strings. The existing `pseudocode_lines()` returns cleaned text (tag_remove'd). `raw_lines()` / `set_raw_line()` provide direct access to `cfunc->sv` members for filters that manipulate color tags.
  - **16.4.2. Safety:** Line index bounds-checked; returns error on out-of-range.

- **16.5. Decision D-DATABASE-TU-SPLIT**: Split `database.cpp` into plugin-safe and idalib-only translation units
  - **16.5.1. Rationale:** `database.cpp` contained both idalib-only lifecycle functions (`init`, `open`, `close` — referencing `init_library`, `open_database`, `close_database`, `enable_console_messages`) and plugin-safe query functions (`input_file_path`, `image_base`, `input_md5`, `save`, etc.) in a single translation unit. When a plugin used any `ida::database` query API, the linker pulled in the entire `database.cpp.o` object, causing unresolved symbol errors for the idalib-only functions that are not exported from `libida.dylib`.
  - **16.5.2. Solution:** Two files: `database.cpp` (queries, metadata, save — all symbols resolvable against `libida.dylib`) and `database_lifecycle.cpp` (init/open/close + RuntimeOptions/sandbox/plugin-policy helpers — only resolvable against `libidalib.dylib`).
  - **16.5.3. Alternatives considered:** (a) Weak symbols / `__attribute__((weak))` — rejected, non-portable and obscures real link errors. (b) Separate static library for idalib-only code — rejected, over-engineering for a single TU split. (c) Move `processor_id()`/`processor_name()` pattern (implement in a different TU) — already done for those two, but doesn't scale to the full lifecycle+query mix.
  - **16.5.4. Key detail:** `save_database` IS exported from `libida.dylib`, so `save()` stays in the plugin-safe `database.cpp`. Only `init_library`/`open_database`/`close_database`/`enable_console_messages` are idalib-exclusive.
  - **16.5.5. Evidence:** `idax_audit_plugin` and `idax_fingerprint_plugin` now link clean; all 7 plugins build; 16/16 tests pass.

### 17. DrawIDA Follow-Up Ergonomics Closure (Phase 12)

- **17.1. Decision D-PLUGIN-EXPORT-FLAGS**: Add structured per-plugin export-flag controls while preserving idax bridge invariants
  - **17.1.1. Decision:** Introduce `ida::plugin::ExportFlags` and `IDAX_PLUGIN_WITH_FLAGS(...)`; keep `IDAX_PLUGIN(...)` as the default convenience path.
  - **17.1.2. Invariant:** `PLUGIN_MULTI` remains mandatory for idax because the bridge is `plugmod_t`-based.
  - **17.1.3. Mechanics:** `ExportFlags` maps to optional SDK bits (`MOD`, `DRAW`, `SEG`, `UNL`, `HIDE`, `DBG`, `PROC`, `FIX`) plus `extra_raw_flags` for advanced cases; composed value is applied at static registration time.
  - **17.1.4. Rationale:** Closes real-world port ergonomics gap without exposing raw SDK structs or abandoning the wrapper lifecycle model.
  - **17.1.5. Alternatives considered:** (a) expose raw `plugin_t.flags` mutation API — rejected (leaks SDK struct and lifecycle details). (b) allow disabling `PLUGIN_MULTI` — rejected (breaks wrapper plugin bridge contract).

- **17.2. Decision D-TYPED-WIDGET-HOST-HELPERS**: Add typed host-access helpers in `ida::ui`
  - **17.2.1. Decision:** Introduce template helpers `widget_host_as<T>()` and `with_widget_host_as<T>()` over existing opaque host APIs.
  - **17.2.2. Rationale:** Preserve opaque core API (`WidgetHost = void*`) while removing repetitive cast boilerplate in Qt-heavy ports.
  - **17.2.3. Trade-off:** Type validity remains caller-responsibility (same as manual cast), but helper centralizes null/error handling and keeps call sites cleaner.

- **17.3. Decision D-DRAWIDA-QT-TARGET-WIRING**: Use `ida_add_plugin(TYPE QT ...)` for DrawIDA addon target
  - **17.3.1. Decision:** Wire DrawIDA as a dedicated addon target via `ida_add_plugin(TYPE QT QT_COMPONENTS Core Gui Widgets ...)`.
  - **17.3.2. Rationale:** Enables first-class addon build when Qt is available while gracefully skipping when Qt is missing (with explicit `build_qt` guidance from ida-cmake).
  - **17.3.3. Alternative considered:** unconditional non-Qt plugin target — rejected (fragile in environments without Qt and duplicates ida-cmake Qt handling).

### 18. DriverBuddy Port + Struct-Offset API Closure (Phase 13)

- **18.1. Decision D-INSTRUCTION-STRUCT-OFFSET-WRAPPERS**: Add first-class operand struct-offset representation helpers in `ida::instruction`
  - **18.1.1. Decision:** Introduce three wrappers: `set_operand_struct_offset(Address,int,std::string_view,AddressDelta)`, `set_operand_struct_offset(Address,int,std::uint64_t,AddressDelta)`, and `set_operand_based_struct_offset(Address,int,Address,Address)`.
  - **18.1.2. Rationale:** Real-world DriverBuddy migration requires a public equivalent for `OpStroffEx`/`op_based_stroff` to annotate WDM dispatch operands as IRP/DEVICE_OBJECT field references without raw SDK fallback.
  - **18.1.3. SDK-specific note:** On SDK 9.3, named-type resolution for this path should use `get_named_type_tid()` (legacy `get_struc_id()` helpers are not available in this bridge context).
  - **18.1.4. Alternatives considered:** (a) keep only generic operand-format wrappers and leave struct-offset annotation to raw SDK — rejected (breaks opacity goal for a common migration pattern). (b) place helper in `ida::type` instead of `ida::instruction` — rejected because operation mutates operand representation, not type definitions.

- **18.2. Decision D-DRIVERBUDDY-WDF-SCHEMA-SUBSET**: Use curated WDF slot subset in example port
  - **18.2.1. Decision:** Materialize a high-value curated `WDFFUNCTIONS` member subset (first 180 slots) in the example port rather than inlining all 440 historical entries.
  - **18.2.2. Rationale:** Keeps the example maintainable/readable while still demonstrating the full idax migration pattern (marker search, metadata dereference, struct materialization, apply+rename).
  - **18.2.3. Trade-off:** Not every historical KMDF slot is named by default in the example; this is documented as a non-blocking audit delta and can be expanded as needed.

### 19. idapcode Port + Sleigh Dependency Model (Phase 14)

- **19.1. Decision D-IDAPCODE-SLEIGH-OPT-IN**: Integrate Sleigh as a submodule with idapcode-specific build gates
  - **19.1.1. Decision:** Add `third-party/sleigh` as a git submodule and wire it only behind `IDAX_BUILD_EXAMPLE_IDAPCODE_PORT` in `examples/CMakeLists.txt`.
  - **19.1.2. Rationale:** Sleigh configuration can fetch/patch large Ghidra sources and should not affect default idax configure/build/test loops.
  - **19.1.3. Additional control:** Keep spec compilation separate via `IDAX_IDAPCODE_BUILD_SPECS` to avoid mandatory all-spec build costs.
  - **19.1.4. Alternatives considered:**
    - Vendoring full Sleigh/Ghidra sources in-tree — rejected (repo bloat + churn).
    - Making Sleigh mandatory for all examples — rejected (unnecessary cost for unrelated examples).

- **19.2. Decision D-DATABASE-PROCESSOR-CONTEXT-WRAPPERS**: Expand `ida::database` metadata for architecture-routing ports
  - **19.2.1. Decision:** Add typed `ProcessorId` + `processor()` and add `address_bitness()`, `is_big_endian()`, `abi_name()` wrappers.
  - **19.2.2. Rationale:** Real-world ports that bridge to external ISA semantics engines need stable processor-context metadata without raw SDK globals in plugin code.
  - **19.2.3. Compatibility detail:** Implement in plugin-safe TU (`src/address.cpp`) alongside `processor_id()`/`processor_name()` to avoid idalib-only linkage bleed.

- **19.3. Decision D-IDAPCODE-SPEC-ROUTING**: Use deterministic best-effort Sleigh spec mapping with explicit override path
  - **19.3.1. Decision:** Map processor context to known `.sla` names in the port and resolve via `sleigh::FindSpecFile`; allow explicit runtime override with `IDAX_IDAPCODE_SPEC_ROOT`.
  - **19.3.2. Rationale:** Keeps the example immediately usable while documenting residual profile-granularity limits as non-blocking parity gaps.
  - **19.3.3. Trade-off:** Some processor-profile variants (e.g., fine ARM profile/revision nuances) remain heuristic without a richer normalized profile model.

- **19.4. Decision D-PROCESSORID-FULL-PLFM-COVERAGE (SUPERSEDED BY 19.34/F394)**: Expand `ida::database::ProcessorId` to mirror the then-supplied `PLFM_*` range
  - **19.4.1. Decision:** Extend `ProcessorId` from a common-subset enum to full coverage through `PLFM_MCORE` (0..77).
  - **19.4.2. Rationale:** Typed `processor()` should not become stale for non-mainstream processor modules; full coverage preserves numeric round-trip fidelity while keeping plugin code SDK-opaque.
  - **19.4.3. Alternative considered:** Keep subset-only enum + rely on raw `processor_id()` for uncommon IDs — rejected (creates avoidable typed-surface gaps for real-world ports).
  - **19.4.4. Supersession:** Current and installed SDK refs do not define the claimed terminal `PLFM_MCORE = 77`. Decision 19.34 replaces closed-enum round-tripping with raw identity plus optional verified typed identity.

- **19.5. Decision D-IDAPCODE-VIEW-SYNC**: Implement bidirectional linear/custom-viewer synchronization in the idapcode port
  - **19.5.1. Decision:** Use existing ui event wrappers (`on_cursor_changed`, `on_screen_ea_changed`, `on_view_activated`, `on_view_deactivated`, `on_view_closed`) plus `custom_viewer_jump_to_line`/`jump_to` and a reentrancy guard.
  - **19.5.2. Rationale:** Provides click/scroll navigation parity without adding new wrapper APIs or exposing raw UI internals.
  - **19.5.3. Implementation detail:** Render each p-code line with a leading address token so cursor-line parsing can always recover a target EA, including non-header p-code lines.
  - **19.5.4. Implementation detail:** Add cross-function follow by rebuilding the existing viewer in-place when linear navigation enters a different function.
  - **19.5.5. Implementation detail:** Add low-interval UI timer polling to capture scroll-driven viewer changes that do not always emit distinct cursor-change notifications.
  - **19.5.6. Alternative considered:** Add new core `ida::ui` APIs for custom-viewer line-index callbacks first — rejected for this iteration (heavier wrapper expansion than needed for immediate port ergonomics).

- **19.6. Decision D-IDAPCODE-HOTKEY-COLLISION-AVOIDANCE**: Change idapcode shortcut from `Ctrl-Alt-S`
  - **19.6.1. Decision:** Set plugin hotkey to `Ctrl-Alt-Shift-P`.
  - **19.6.2. Rationale:** Avoids common collision with SigMaker bindings while keeping mnemonic linkage to p-code workflows.
  - **19.6.3. Alternative considered:** Keep `Ctrl-Alt-S` parity with source plugin — rejected due practical conflict in mixed-plugin setups.

- **19.7. Decision D-UI-CUSTOM-VIEWER-STATE-STABILITY**: Preserve backing-state pointer identity when updating custom viewer lines
  - **19.7.1. Decision:** Update `CustomViewerState` contents in-place inside `set_custom_viewer_lines`; do not replace the stored `unique_ptr` object.
  - **19.7.2. Rationale:** IDA's custom viewer keeps pointers to `min`/`max`/`cur`/`lines` objects passed at creation; replacing the state object invalidates those pointers and can crash during renderer/model updates.
  - **19.7.3. Additional detail:** Clamp preserved cursor line to the new range, refresh range, and jump to the clamped place to keep UI state coherent.
  - **19.7.4. Alternative considered:** Keep replacement model and defer all updates by recreating viewers — rejected (higher churn/flicker and still unsafe if stale pointers survive queued UI work).

- **19.8. Decision D-VENDOR-IDA-SDK-FETCHCONTENT**: Vendor ida-sdk and ida-cmake using CMake FetchContent
  - **19.8.1. Decision:** Automatically clone and vendor `ida-sdk` (HexRaysSA) and `ida-cmake` (allthingsida) using CMake's `FetchContent` capabilities, and default to them in CMake if `$IDASDK` is not set. A shallow clone (`GIT_SHALLOW TRUE`) is used to minimize network cost.
  - **19.8.2. Rationale:** Eliminates the need for external IDA SDK dependencies and avoids repository pollution with Git submodules. FetchContent keeps the dependency fully managed by the build system.
  - **19.8.3. Alternative considered:** Using Git Submodules — rejected because submodules require explicit user tracking, whereas CMake FetchContent handles downloading directly into the ephemeral build directory (`build/_deps/`), resulting in a cleaner root repository.

- **19.9. Decision D-ISOLATE-ARTIFACT-OUTPUT**: Set `IDABIN` to a local build directory to isolate artifacts
  - **19.9.1. Decision:** Override `IDABIN` to `${CMAKE_CURRENT_BINARY_DIR}/idabin` in `CMakeLists.txt` before calling `find_package(idasdk)`.
  - **19.9.2. Rationale:** Prevents the fetched `ida-sdk` directory from being polluted by locally built plugins, loaders, and processor modules. Artifacts now securely output to `build/idabin`.

---

- **19.10. Decision D-NODE-ADDON-PREBUILDS**: Package prebuilds inside npm tarball with dynamic fallback
  - **19.10.1. Decision:** The `idax-node-plugin.tgz` artifact uploaded to the GitHub release page includes all compiled `.node` prebuild binaries for supported platforms inside the `prebuilds/` directory.
  - **19.10.2. Rationale:** This creates a single portable artifact. When users install the package, a custom `scripts/install.js` runs via npm's `install` lifecycle hook. It checks if `prebuilds/${process.platform}-${process.arch}/idax_native.node` exists. If present, it skips compilation. If absent, it invokes `cmake-js compile` as a fallback.
  - **19.10.3. Alternative considered:** Use `@mapbox/node-pre-gyp` or `prebuildify` — rejected because `idax` relies on `cmake-js` rather than `node-gyp`, making standard node-pre-gyp setups complex. A simple install script elegantly meets the requirement.

- **19.11. Decision D-DISABLE-LTO-IDAX-STATIC**: Disable LTO (Link Time Optimization) on the `idax` static library target
  - **19.11.1. Decision:** Explicitly disable LTO (`INTERPROCEDURAL_OPTIMIZATION FALSE` + `-fno-lto` + `CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF`) for the `idax` library when building it for external linkage (e.g. from Rust or downstream CMake consumers).
  - **19.11.2. Rationale:** The fetched `ida-sdk`'s `ida_compiler_settings` interface target aggressively enables `-flto` on GCC/Clang during `Release` builds. When `idax` is built as a static archive (`libidax.a`), GCC/Clang generates object files populated with LTO intermediate representation instead of native machine code. If a downstream consumer (like a standalone Rust binary compiled with `rustc` using its own linker) attempts to link this archive, it will fail unless it has a perfectly matching LTO plugin setup. Disabling LTO guarantees a portable, native static archive that any linker can consume.
  - **19.11.3. Alternative considered:** Try to inject `gcc-ar`/`gcc-ranlib` and configure the Rust build to pass LTO plugins to the linker. Rejected due to overwhelming complexity and fragility across environments; a non-LTO static archive is simpler and universally compatible with minimal performance penalty for the wrapper overhead.

- **19.12. Decision D-NODE-WINDOWS-COMPILATION-MACROS**: Rename `RegisterClass` to `RegisterCategory` across C++, TypeScript, and Rust
  - **19.12.1. Decision:** Rename the `ida::instruction::RegisterClass` enum to `RegisterCategory` globally.
  - **19.12.2. Rationale:** When compiling Node.js bindings on Windows, `<windows.h>` is inevitably included. It aggressively `#define`s `RegisterClass` to `RegisterClassA` or `RegisterClassW`. This mangled the `ida::instruction::RegisterClass` enum signatures, causing `LNK2001` unresolved external symbol errors. A clean rename to `RegisterCategory` completely avoids the collision.

- **19.13. Decision D-RUST-WINDOWS-CRT-STATIC-ALIGNMENT**: Enforce static CRT across Rust bindings when linking against IDA SDK wrappers
  - **19.13.1. Decision:** Align Windows Rust bindings to static CRT by configuring:
    - repository Cargo target setting `x86_64-pc-windows-msvc` with `-C target-feature=+crt-static`,
    - `idax-sys/build.rs` CMake setting `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>`, and
    - `cc::Build::static_crt(true)` for `idax_shim.cpp`.
  - **19.13.2. Rationale:** IDA SDK Windows binaries/libs are built around static CRT assumptions; mixed `/MT` + `/MD` object graphs produced hard linker failures (`LNK2038`/`LNK1319`). Uniform static CRT eliminates runtime-library conflicts.
  - **19.13.3. Alternative considered:** Keep `/MD` for Rust/shim and force CMake `/MD` for wrappers. Rejected due repeated mismatch against IDA SDK static-runtime expectations and unstable downstream linking.

- **19.14. Decision D-RUST-WINDOWS-LTCG-NONBUNDLED-LINK**: Link `idax_cpp` with non-bundled static mode on Windows
  - **19.14.1. Decision:** Emit `cargo:rustc-link-lib=static:-bundle=idax_cpp` in `idax-sys/build.rs` on Windows.
  - **19.14.2. Rationale:** With MSVC LTCG (`/GL`) objects in `idax_cpp.lib`, rustc archive bundling into `.rlib` can hide/skip required symbols at final link. Non-bundled mode keeps `idax_cpp.lib` passed directly to `link.exe`.
  - **19.14.3. Alternative considered:** Reintroduce merged shim archives and crate-level sentinel `#[link]` metadata. Rejected for being more brittle and less transparent than direct non-bundled linkage.

- **19.15. Decision D-RUST-WINDOWS-RUNTIME-SESSION-ROBUSTNESS**: Harden Rust example session init/wait behavior for Windows CI
  - **19.15.1. Decision:** In Rust bindings, initialize idalib with a synthetic argv (`argc=1`, `argv[0]="idax-rust"`) instead of null argv, and in Rust example helper sessions treat `analysis::wait()` failures as warnings on Windows (non-Windows remains strict-error).
  - **19.15.2. Rationale:** Windows CI runtime failures were surfacing as opaque exit-code-1 results. Providing argv and allowing non-fatal wait degradation in helper tooling preserves runtime validation usefulness while avoiding brittle host-specific analysis wait failures.
  - **19.15.3. Scope constraint:** This relaxed wait behavior is limited to Rust example helper code (`examples/common/mod.rs`), not core library APIs.

- **19.16. Decision D-RUST-WINDOWS-USER-PLUGIN-SUPPRESSION**: Disable user-plugin discovery by default for Rust shim sessions on Windows
  - **19.16.1. Decision:** In `idax-sys` shim (`idax_database_init`), call `ida::database::init(argc, argv, RuntimeOptions{plugin_policy.disable_user_plugins=true})` on Windows by default, with opt-in override via `IDAX_ENABLE_USER_PLUGINS=1`.
  - **19.16.2. Decision:** In Windows Rust CI runtime step, explicitly set `IDAX_ENABLE_USER_PLUGINS=0` and point `IDAUSR` at an empty temp directory.
  - **19.16.3. Rationale:** Post-link Windows runtime failures still produced opaque exit-code-1 behavior. Suppressing user plugins reduces host/plugin variability and avoids startup/runtime side effects from non-project plugins in CI agents.
  - **19.16.4. Trade-off:** This narrows parity with default desktop user sessions for Rust example runs, but keeps CI deterministic and focused on core wrapper behavior.

- **19.17. Decision D-RUST-WINDOWS-PLUGIN-POLICY-ROLLBACK**: Roll back shim-level plugin-policy init on Windows; keep environment isolation only
  - **19.17.1. Decision:** Revert `idax_database_init` on Windows to the default `ida::database::init(argc, argv)` path (no `RuntimeOptions.plugin_policy`).
  - **19.17.2. Decision:** Retain Windows CI isolation using an empty `IDAUSR` directory, without setting plugin-policy env controls.
  - **19.17.3. Rationale:** Windows runtime produced explicit `SdkFailure: Plugin policy controls are not implemented on Windows yet` when plugin-policy runtime options were passed via shim init path.
  - **19.17.4. Supersedes:** D-RUST-WINDOWS-USER-PLUGIN-SUPPRESSION (19.16) for Windows shim init behavior.

- **19.18. Decision D-RUST-WINDOWS-RUNTIME-TRACE-TOGGLES**: Add CI-only trace and analysis-control env toggles for Rust example sessions
  - **19.18.1. Decision:** Add `IDAX_RUST_EXAMPLE_TRACE` support in Rust example helper (`examples/common/mod.rs`) to emit step-level lifecycle logs (`database::init/open/close`, `analysis::wait`) with immediate stderr flush.
  - **19.18.2. Decision:** Add optional `IDAX_RUST_DISABLE_ANALYSIS` helper behavior to skip auto-analysis wait/open-analysis coupling when explicitly enabled (Windows CI diagnostics path).
  - **19.18.3. Decision:** Set both env vars in Windows Rust CI runtime step to improve attribution for opaque runtime exits.
  - **19.18.4. Rationale:** When runtime failures occur before regular error propagation, stage-level tracing is required to identify whether failure happens during init, open, or analysis wait.

- **19.19. Decision D-RUST-WINDOWS-DIRECT-EXE-RUNNER**: Split build and execute phases for Rust example runtime checks on Windows
  - **19.19.1. Decision:** Replace `cargo run --release --example ...` in the Windows runtime step with `cargo build --release --example ...` followed by direct execution of `target\\release\\examples\\<name>.exe`.
  - **19.19.2. Decision:** Emit both decimal and hex exit code on failures in the workflow wrapper function.
  - **19.19.3. Rationale:** Direct execution gives cleaner runtime-stage diagnostics when the process exits before Rust-level error paths emit text.

- **19.20. Decision D-RUST-WINDOWS-INIT-ARGV-AUTO-LOGGING**: Pass explicit headless args (`-A`) and optional IDA log path from Rust init wrapper
  - **19.20.1. Decision:** On Windows, `database::init()` now forwards init argv with at least `"idax-rust"` and `"-A"`.
  - **19.20.2. Decision:** If `IDAX_RUST_IDA_LOG` is set, append `-L<path>` to init argv for native IDA logging.
  - **19.20.3. Rationale:** Open-time exits were occurring before wrapper-level diagnostics in CI. Explicit auto-mode and optional native logging improve reproducibility and observability for headless runtime failures.

- **19.21. Decision D-RUST-WINDOWS-INIT-ARGV-ROLLBACK**: Revert injected `-A`/`-L` init args; keep minimal argv
  - **19.21.1. Decision:** Restore `database::init()` to pass minimal argv (`argv0` only) on Windows.
  - **19.21.2. Rationale:** Injected init args produced deterministic `init_library failed [return code: 2]` in CI, blocking database open diagnostics.
  - **19.21.3. Supersedes:** D-RUST-WINDOWS-INIT-ARGV-AUTO-LOGGING (19.20).

- **19.22. Decision D-RUST-WINDOWS-EXAMPLE-FIXTURE-IDB-INPUT**: Use stable fixture IDB as Windows Rust runtime input in CI
  - **19.22.1. Decision:** In Windows Rust runtime workflow step, run examples against `tests/fixtures/simple_appcall_linux64.i64` (resolved absolute path) instead of a copied raw system binary.
  - **19.22.2. Rationale:** Raw PE open path was exiting during `database::open` with opaque code 1 before wrapper-level errors; fixture IDB input removes loader-path variance and validates core wrapper/runtime behavior deterministically.

- **19.23. Decision D-RICH-TYPE-METADATA-OPAQUE-SURFACE**: Expose trida-required type layout metadata through opaque idax APIs
  - **19.23.1. Decision:** Add first-class opaque `ida::type` metadata structs and methods for type kind/name/declaration, function details, enum details, UDT details, and rich member layout flags instead of allowing plugin ports to include `typeinf.hpp` and inspect `tinfo_t`, `udt_type_data_t`, or related SDK structs.
  - **19.23.2. Rationale:** ida-trida needs bit offsets, bitfield backing width, baseclass/vftable/gap flags, named function arguments, enum width/radix, and UDT total-size/object metadata to generate faithful Frida helpers. Keeping this data in idax preserves the fully opaque public API rule while making real generator ports practical.
  - **19.23.3. Binding posture:** Node and Rust expose the same concepts structurally, but structural Node tests must not construct `TypeInfo` factory objects in an uninitialized Node-only process; runtime TypeInfo behavior remains covered by initialized C++/integration paths.

- **19.24. Decision D-STABLE-OPAQUE-WIDGET-IDENTITY**: Intern wrapper IDs for live SDK widgets
  - **19.24.1. Decision:** Assign one opaque idax ID per live `TWidget*`, reuse it across `create_widget`, event payloads, `find_widget`, and `current_widget`, and retire it on `ui_widget_closing` or wrapper-owned close.
  - **19.24.2. Rationale:** Public `Widget::id()` is documented as stable identity. Generating an ID per wrapper instance violated that contract and made polling/event correlation unreliable.
  - **19.24.3. Scope constraint:** The pointer remains implementation-private; bindings receive only the opaque ID and snapshot metadata.

- **19.25. Decision D-IDA-NAMES-QT-TITLE-BRIDGE**: Keep widget-title mutation outside the generic SDK facade
  - **19.25.1. Decision:** The IDA-names example changes window titles through `with_widget_host` and a Qt-only translation unit instead of adding `Widget::set_title()`.
  - **19.25.2. Rationale:** The audited SDK exposes title reads but no generic `set_widget_title` operation. An explicit host bridge preserves public SDK opacity and keeps Qt dependencies confined to a `TYPE QT` example target.

- **19.26. Decision D-WRAPPER-MANAGED-ACTION-ATTACHMENTS**: Define deterministic detach state within idax
  - **19.26.1. Decision:** Track successful idax menu and toolbar attachments as counted `(target, action_id)` pairs; detach only tracked pairs, consume one count per successful wrapper request, and clear residual counts on action unregistration.
  - **19.26.2. Rationale:** IDA 9.3 can return success when detaching a menu action that was never attached, so the SDK boolean cannot implement idax's `NotFound` contract by itself.
  - **19.26.3. Scope constraint:** Deterministic state applies to attachments created through idax. Attachments created exclusively through raw SDK calls are outside this opaque wrapper contract; popup helpers retain their SDK permanent-widget behavior.

- **19.27. Decision D-RUST-REAL-IDA-MAIN-THREAD-HARNESS**: Use a custom sequential runner for the real-IDA integration target
  - **19.27.1. Decision:** Set only `idax/tests/integration.rs` to `harness = false` and register its cases in an explicit `main` that initializes, executes, and closes the shared IDA session on process main.
  - **19.27.2. Rationale:** Idalib requires calls on the initializing thread, whereas Rust libtest executes test functions on workers even at `--test-threads=1`. Live sampling confirmed a deadlock between worker-side IDAPython warning dispatch and libtest's parked main thread.
  - **19.27.3. Compatibility:** The runner retains substring filtering, exact matches, skip patterns, platform ignores, `--list`, graceful no-`IDADIR` skips, per-case panic capture, a nonzero exit on failures, and summary output. Pure Rust unit targets retain the standard test harness.
  - **19.27.4. Rejected alternatives:** Serial libtest execution, initializing on main and operating on workers, suppressing selected plugins, or moving IDA work to a dedicated non-main thread do not satisfy the documented same-thread lifecycle constraint or remove synchronous main-thread dispatch risk.

- **19.28. Decision D-DETERMINISTIC-COMMENT-APPEND**: Compose appended comments inside idax
  - **19.28.1. Decision:** Define append as `text` when no non-empty comment exists and `existing + "\n" + text` otherwise, then commit the result through the existing `set` path.
  - **19.28.2. Rationale:** IDA 9.3's `append_cmt` can return success at a function start without making the new text observable through `get_cmt`. Wrapper-level composition preserves the intuitive append contract across function-record and ordinary item storage.
  - **19.28.3. Boundary:** The operation is a single-thread-oriented read/modify/write sequence consistent with idalib and IDA SDK threading constraints. Mutations performed outside idax between those calls are outside the wrapper contract.
  - **19.28.4. Error behavior:** The wrapper preserves `set_cmt` failure mapping and adds pre-allocation validation for impossible composed sizes.

- **19.29. Decision D-OPAQUE-MUTATION-SAFE-IDB-EVENTS**: Normalize high-value IDB changes into owned snapshots
  - **19.29.1. Decision:** Expose post-change segment/function/type/operand/item/comment/local-type notifications as typed, SDK-independent value snapshots and route the same data through the generic `Event` model; do not expose `segment_t`, `func_t`, `insn_t`, encoded type strings, raw flags, or local-type SDK enums.
  - **19.29.2. Dispatch rule:** Bound every event by its entry token ceiling, retain each selected subscription through shared ownership, re-check route liveness before invocation, and defer final SDK-listener unhook until dispatch returns. New typed or generic routes cannot join any later phase of the active event; a route removed by its filter does not receive its paired callback.
  - **19.29.3. Binding rule:** Node retains callback ownership through the shared C++ subscription and represents 64-bit event sizes as `bigint`. Rust tracks active callback depth, releases the context-registry mutex before reclamation, moves the deferred-drop queue out of thread-local mutable storage before destruction, and reclaims erased contexts only after the outermost callback returns.
  - **19.29.4. Scope boundary:** Phase 28 covers stable high-value post-change notifications used by change tracking and metadata synchronization. Pre-change veto paths, SDK-internal dirtree payloads, and processor-group events remain evidence-driven future surface rather than raw mirroring.

- **19.30. Decision D-FIXED-DATA-ELEMENT-COUNT-CONTRACT**: Define fixed-width data arrays in element units
  - **19.30.1. Decision:** Every fixed-width `define_*` API from byte through zword accepts a positive element count. The C++ semantic boundary performs checked multiplication by the documented element width before calling the SDK's byte-length helper.
  - **19.30.2. Validation rule:** Reject zero, multiplication overflow, and half-open address-range overflow as `Validation` before SDK dispatch. SDK rejection after valid conversion remains `SdkFailure`.
  - **19.30.3. Binding rule:** C++ and Node default to one element; Node accepts only exact non-negative integer `number`/`bigint` representations; Rust keeps an explicit `AddressSize` element count. All bindings inherit the same C++ conversion.
  - **19.30.4. Unit boundary:** `define_string`, `define_struct`, and `undefine` retain byte-length/count semantics. Packed-real and registered custom data remain outside the fixed-width contract until modeled with processor/type-registration context (F381).

- **19.31. Decision D-PROCESSOR-AWARE-EXTENDED-REAL-DEFINITIONS**: Resolve tbyte and packed-real widths from the active processor
  - **19.31.1. Decision:** `define_tbyte` and `define_packed_real` accept positive element counts, but obtain the byte width from active processor metadata rather than a compile-time constant.
  - **19.31.2. Availability rule:** Reject a zero element count as `Validation` independent of processor support. For positive counts, require a nonzero processor `tbyte_size` and a non-null, non-empty active-assembler directive (`a_tbyte` or `a_packreal`); return `Unsupported` before SDK dispatch when the current environment cannot represent the requested item.
  - **19.31.3. Discoverability rule:** Expose explicit tbyte and packed-real element-size queries with the same availability semantics; bindings inherit the C++ result instead of duplicating processor assumptions.
  - **19.31.4. Scope boundary:** Custom type/format registration carries callback ownership and teardown semantics and therefore proceeds as independently committed Phase 31 work.

- **19.32. Decision D-OPAQUE-CUSTOM-DATA-LIFECYCLE**: Own registrations and expose typed snapshots
  - **19.32.1. Identity model:** Represent custom type and format IDs as distinct 16-bit public types restricted to `1..0xFFFE`; zero is reserved for standard-type attachment and `0xFFFF` is the packed missing-ID sentinel. Model standard-type attachment through separate functions rather than a sentinel passed as a custom type.
  - **19.32.2. Ownership model:** Copy every definition string and callback into stable wrapper-owned registration state. SDK trampolines retain that state for callback duration, catch all exceptions at the C ABI boundary, and release it only after deterministic explicit unregister. Lookup/list operations return copied SDK-independent snapshots.
  - **19.32.3. Callback model:** Expose creation-filter and exact-size callbacks for types; expose result-bearing render/scan callbacks and an analyze callback for formats. Provide explicit render/scan/analyze operations so callback behavior, error text, probe safety, and binding adapters can be validated without UI automation.
  - **19.32.4. Creation model:** Keep explicit custom-item byte-length creation and add single-item inferred creation through the fixed width or variable-size callback bounded by a caller-supplied maximum. Validate IDs, attachment, positive lengths, width bounds, and address ranges before `create_custdata`.
  - **19.32.5. Scope boundary:** The public API covers registry metadata, name lookup, size-filtered type enumeration, attached-format enumeration, standard/custom attachment, item identity, callback invocation, creation, and teardown. Raw descriptors, user-data pointers, packed SDK operands, and direct netnode mutation remain private.

- **19.33. Decision D-SCOPED-HOTKEY-OVER-OWNED-ACTIONS**: Model one-call hotkeys as opaque action registrations
  - **19.33.1. API model:** Return a move-only scoped registration from a one-call hotkey function. Generate the internal action identifier inside idax, unregister on destruction, and expose explicit early release without exposing SDK contexts or handler pointers.
  - **19.33.2. Ownership model:** Keep every successfully registered `ActionAdapter` in process-lifetime wrapper-owned keyed storage and erase it only after successful SDK unregister. Register without `ADF_OWN_HANDLER` so host and wrapper ownership cannot double-delete; delete locally on registration failure. Named actions require explicit unregister for deterministic reclamation; omitted teardown retains a safe handler instead of leaving the host with a dangling pointer. This supersedes the initial SDK-owned draft after IDA 9.3 idalib did not immediately reclaim an owned handler on successful unregister (F393).
  - **19.33.3. Callback model:** Catch all exceptions in action activation and availability callbacks. Treat callback failure as a non-refreshing activation or disabled action instead of allowing an exception across the host ABI.
  - **19.33.4. Binding/scope rule:** Mirror scoped ownership in bindings that already expose the plugin/action namespace. Do not create a Node-only plugin namespace solely for this additive convenience. Keep full named actions for menu/toolbar/popup/update behavior; scoped hotkeys are intentionally shortcut-only.
  - **19.33.5. Activation evidence:** Expose programmatic activation because it is part of the native action surface, but classify runtime dispatch and exception-barrier execution as interactive-UI-host-gated. Headless idalib remains authoritative for registration and deterministic wrapper reclamation only (F393).

- **19.34. Decision D-FORWARD-COMPATIBLE-PROCESSOR-PROFILE**: Normalize processor metadata without closing the SDK ID space
  - **19.34.1. Identity model:** Add `ProcessorProfile` with the authoritative raw signed ID plus `std::optional<ProcessorId>`. Normalize only verified current public SDK values `0..76`; unknown/future/third-party IDs remain valid profiles with no typed ID.
  - **19.34.2. Metadata model:** Snapshot processor name, database address bitness, endianness, and optional ABI in one SDK-independent value. Absence of an ABI is ordinary metadata absence; failure of required fields remains an error.
  - **19.34.3. Compatibility rule:** Retain `ProcessorId::Mcore = 77` as a documented legacy source-compatibility enumerator, but do not return it from raw-ID normalization because no searched current SDK ref defines `PLFM_MCORE`. A future breaking revision may remove it.
  - **19.34.4. Binding/port rule:** Mirror the profile in Node and Rust, use optional typed identity rather than unchecked integer-to-enum conversion, and migrate both idapcode adaptations to the normalized profile while retaining function-specific bitness override for Sleigh selection.
  - **19.34.5. Scope boundary:** External Sleigh remains the intentional p-code implementation. Phase 33 closes processor-context normalization; it does not introduce a native `ida::pcode` namespace that would conceal a third-party runtime.

- **19.35. Decision D-INTELLIGENT-INLINER-PORT-EQUIVALENCE**: Preserve scoring semantics and make mutation explicit by host surface
  - **19.35.1. Algorithm model:** Preserve the original thresholds and weights exactly: strict selection below 7 code instructions; otherwise score at least 5 from `<4` instructions (2), one basic block, no memory writes, no calls, exactly one direct call, no indirect calls, and no data reference to the function entry (1 each).
  - **19.35.2. Classification model:** Count every call instruction; classify only a first `NearAddress`/`FarAddress` operand as direct, matching the original operand-class test, and classify other/undecodable calls as indirect. Classify a memory write only when a memory-shaped operand is processor-marked written. Skip thunk, library, non-returning, and positively identified variadic functions. Missing type information is not positive variadic evidence.
  - **19.35.3. Mutation model:** The interactive C++ plugin action applies `FUNC_OUTLINE` like the original script and invalidates decompiler cache entries for changed functions and their callers when Hex-Rays is available. The headless Rust adaptation reports by default and requires `--apply` for database mutation, matching existing command-line adaptation conventions.
  - **19.35.4. Binding model:** Extend the existing owned `IdaxOperand` transfer with read/write booleans and expose immutable Rust accessors; add `isRead`/`isWritten` to ordinary and decompiler-callback Node instruction snapshots. This is parity correction for data already present in the C++ value, not a raw-SDK escape hatch.
  - **19.35.5. Scope boundary:** Retain the original `FUNC_OUTLINE` mechanism and nomenclature caveat. Do not implement binary rewriting, forced decompilation, or an independent inliner; this port marks Hex-Rays inline candidates in IDA metadata.

- **19.36. Decision D-MAGIC-STRINGS-OWNED-INVENTORY-AND-PORT**: Model discovery metadata as owned values and preserve the non-NLTK workflow
  - **19.36.1. String-list model:** Add copied `StringListOptions` and `StringLiteral` values in `ida::data`, with explicit query/configure/rebuild/clear operations. Configuration mutates IDA's documented process-global string-list settings; it never exposes the `strwinsetup_t` singleton or `string_info_t` entries.
    - Normalize the IDA 9.3 cache's one leading zero bookkeeping entry out of copied options while preserving every caller-supplied type code, including the real zero-valued one-byte C-string type (F398).
  - **19.36.2. Source model:** Add copied source filename plus half-open `address::Range` in `ida::lines`, with add/query/remove operations and checked address/range validation. The borrowed SDK filename and `range_t` remain private.
  - **19.36.3. Analysis model:** Preserve the original fallback behavior used when NLTK is unavailable: scan one-byte and two-byte C strings of at least five octets; combine string references with source-debug mappings; count source observations independently from chooser/xref rows; scan both name-list and string-list evidence for candidates/classes; retain insertion-ordered source-language classification; accept function-name tokens of at least six characters outside the original exclusion vocabulary; require a candidate to be unique to one function; and derive `::` class hierarchies.
  - **19.36.4. Mutation/UI model:** The C++ plugin presents source and candidate choosers plus a class graph and exposes separate confirmed candidate/source rename actions. The Rust adaptation reports by default and requires `--apply-candidates` and/or `--apply-sources` for names. Both sanitize proposed identifiers through idax, mutate only existing `sub_*` names, and preserve all names unless mutation is explicitly requested.
  - **19.36.5. Binding/scope rule:** Mirror the new data and lines values through Node and Rust. Add the filtered full `name::all(ListOptions)` inventory to safe Rust because class evidence requires auto-generated as well as user-defined names (F399). Do not add NLTK, Python, or Qt as a core dependency; the original already defines a functional no-NLTK path. UI layout may use idax chooser/graph primitives while preserving analysis and mutation semantics.
  - **19.36.6. Conflict rule:** When both Rust apply modes target one function, a string/class candidate has priority over its source-file fallback and each function is renamed at most once per run. This makes simultaneous apply deterministic without weakening either report inventory.

- **19.37. Decision D-DISPOSABLE-IDALIB-INTEGRATION-FIXTURES**: Run every native integration target against a private input/IDB copy
  - **19.37.1. Execution model:** CTest invokes each idalib executable through one CMake runner that creates a unique directory, copies the raw fixture and adjacent `.i64`, executes against the copied raw path, and removes the directory after the child exits.
  - **19.37.2. Rationale:** A passing smoke target changed the tracked IDB despite logical cleanup. IDA can persist analysis/cache metadata independently of the mutations asserted by a test, so direct fixture execution cannot provide repository isolation.
  - **19.37.3. Validation rule:** Hash the tracked `.i64` before and after complete CTest execution. A passing target count without hash equality is incomplete evidence.

- **19.38. Decision D-AUTO-ENUM-METADATA-PRESERVING-PORT**: Close prototype and operand-enum gaps without exposing native type identities
  - **19.38.1. Prototype model:** Add immutable `TypeInfo::with_function_argument_type(index, replacement)` semantics. Internally copy the complete SDK function record, replace only the selected argument type, rebuild the function or function-pointer value, and return a new opaque type. Preserve the input and all unaffected ABI metadata.
  - **19.38.2. Operand model:** Add name-based enum representation and copied name/serial readback in `ida::instruction`. Resolve and verify local enum types internally; support the SDK all-operands sentinel through the existing signed operand-index convention without exposing TIDs.
  - **19.38.3. Binding model:** Mirror both primitives through Node and Rust with owned strings/types, checked numeric conversion, exact structural tests, and initialized-host runtime evidence.
  - **19.38.4. Port model:** Preserve Auto Enum's two workflows in the interactive C++ plugin: global imported-prototype enrichment from declarative function/enum specifications, and cursor-selected selector-dependent per-call annotation using ctree numeric arguments. The headless Rust adaptation covers the deterministic global workflow, reports by default, and requires an apply flag; it does not approximate interactive cursor state from flat expression snapshots (F405).
  - **19.38.5. Corpus boundary:** Keep the port engine and schema independent of the original Python/JSON loader. Validate representative Linux and Windows specifications in-tree and permit generated/embedded corpus expansion without adding Python or a JSON dependency to the core library. Do not claim bundled coverage for corpus entries not present in the adaptation.

- **19.39. Decision D-OWNED-MICROCODE-GRAPH-AND-BOUNDED-SYMLESS-PORT**: Add a maturity-explicit semantic snapshot and preserve a stated intraprocedural reconstruction boundary
  - **19.39.1. Snapshot model:** Add `MicrocodeMaturity`, `MicrocodeGenerationOptions`, owned function-argument locations, owned blocks, and addressed recursive instructions/operands. Generate a separate MBA for one function, build its CFG when required, copy all public values, and release every native object before returning.
  - **19.39.2. Forward-compatibility model:** Type the opcodes and operand kinds required by reconstruction, including signed extension, address references, and call arguments. Represent other valid native instructions/operands as `Other` with copied display text; do not expose raw SDK enum values or fail a complete graph because an unrelated operation is not yet normalized.
  - **19.39.3. Binding model:** Mirror the owned graph through Node and Rust because both already expose the decompiler namespace and existing microcode values. Preserve recursive ownership, checked counts, copied strings, exact enum conversion, and deterministic freeing across the C ABI.
  - **19.39.4. Port model:** The C++ interactive action and Rust headless adaptation analyze one selected function argument. Preserve Symless's intraprocedural register/stack state model, pointer add/sub shifts, extension/move transfer, nested expressions, load/store access widths, topological predecessor-state preference, and minimum-width conflict policy. Report mode is non-mutating; apply mode creates/reuses the named UDT and changes only an eligible scalar/scalar-pointer function argument through the metadata-preserving replacement API.
  - **19.39.5. Scope boundary:** Do not claim full Symless parity. Exclude interprocedural call/return propagation, allocator and wrapper discovery, constructors/vtables, shifted pointer types, local-type forward replacement/UDT flags, member-TID xref repair, multi-element struct-offset paths, and microcode-widget operand selection until dedicated opaque designs and evidence exist (F408).

- **19.40. Decision D-SYMLESS-BOUNDED-INTERPROCEDURAL-FLOW**: Extend one structure identity through resolved direct callees without exposing native graphs
  - **19.40.1. Traversal model:** Evaluate direct-call arguments from owned caller state, generate owned preoptimized graphs for resolved callees, inject matching structure values at copied ABI locations, and feed an agreed terminal return-location value back into the caller expression.
  - **19.40.2. Termination model:** Require an explicit nonnegative maximum depth, reject active recursion cycles, and deduplicate completed contexts keyed by function plus injected structure argument offsets. Do not follow unresolved helpers, imports without microcode, or indirect calls whose target is not a copied exact function address.
  - **19.40.3. Prototype model:** Add immutable `TypeInfo::with_function_return_type(replacement)` for direct and pointer function types by copying the complete native function record and replacing only `rettype`. Mirror it through Node and Rust with input immutability and ABI-metadata preservation tests.
  - **19.40.4. Mutation model:** Report all propagated sites and return paths. After explicit apply confirmation, type only eligible zero-shift arguments and returns; skip shifted or incompatible sites deterministically and expose counts. Continue to create/reuse one named UDT and preserve report-mode non-mutation.
  - **19.40.5. Scope boundary:** This closes direct resolved call/return structure flow only. Allocator seed discovery/wrapper classification, indirect dynamic calls, constructors/vtables, shifted-pointer types, forward-type/UDT flags, member-TID xrefs, multi-element stroff, and widget operand selection remain independent surfaces.
  - **19.40.6. Call-information model:** Add an explicit `analyze_calls`/`analyzeCalls` graph-generation option. When selected, pre-decompile exact direct callees and run `mba_t::analyze_calls(ACFL_GUESS)` after CFG construction and before the owned copy; retain `false` as the default so existing callers continue to receive the requested raw maturity state (F412).

- **19.41. Decision D-SYMLESS-BOUNDED-ALLOCATOR-DISCOVERY**: Classify declarative allocator heirs with owned values and preserve mutation boundaries
  - **19.41.1. Seed model:** Accept explicit malloc/calloc/realloc specifications resolved by module plus import-name prefix or exact function name/address. Preserve configured size/count argument indexes and reject malformed, duplicate-conflicting, or out-of-range specifications deterministically.
  - **19.41.2. Classification model:** Walk copied references, verify exact resolved direct calls in the containing analyzed graph, propagate caller-argument and bounded-integer values, preserve Symless's `0 < size < 0x4000` rule, and confirm forwarding wrappers only through agreed terminal return of the originating call token.
  - **19.41.3. Termination model:** Key visited allocator heirs by function address, allocator kind, and configured argument indexes. Use Phase 38 context/depth guards for structure flow from each static allocation root; report unresolved/ambiguous sites rather than approximating indirect calls.
  - **19.41.4. Prototype model:** Add immutable `TypeInfo::with_function_argument_name(index, name)` across C++, Node, and Rust. Copy the complete native record and change only the existing argument name. Apply generic allocator return/size/count typing and names only after explicit confirmation; do not synthesize absent parameters.
  - **19.41.5. Allocation-root model:** Report every constant-size root with its recovered fields and known allocation extent. Apply may create/reuse a distinct named UDT and enrich generic allocator/wrapper prototypes; it must not assign one allocation-specific structure to a reusable allocator return or claim local-variable typing without an opaque location mapping.
  - **19.41.6. Scope boundary:** Exclude indirect dynamic calls, constructor/vtable roots, shifted pointer metadata, local-type flags/forward replacement, member-TID xrefs, multi-element stroff, and widget selection. Preserve them as separately testable surfaces.

- **19.42. Decision D-SYMLESS-EVIDENCE-BOUNDED-CONSTRUCTOR-VTABLES**: Materialize only exact argument-zero vtable roots
  - **19.42.1. Table model:** Scan loaded item heads in code/data segments. A table is a bounded pointer-width run of exact function entries or mapped external symbols, terminates before any referenced non-first slot, and must contain at least one non-import method. Clear the ARM Thumb address bit only for function-entry validation, matching upstream.
  - **19.42.2. Constructor model:** Seed argument zero as structure offset zero in an owned preoptimized graph. Record only pointer-width stores whose integer value equals a discovered table address and whose destination carries that structure identity. A root requires offset zero; nonzero offsets remain report-only secondary-subobject evidence. Reject a function with multiple distinct offset-zero table values as ambiguous instead of selecting one by table size or xref frequency.
  - **19.42.3. Semantic type model:** Add one metadata-preserving UDT semantic setter across C++, Node, and Rust. Copy complete `udt_type_data_t`, change only `TAUDT_CPPOBJ` and `TAUDT_VFTABLE`, and rebuild the opaque type. Preserve all members/layout/packing/alignment/unrelated flags and reject non-UDTs plus the invalid simultaneous class-and-vftable state.
  - **19.42.4. Mutation model:** Report discovery without mutation. Explicit apply creates/reuses one named vtable UDT with method-pointer fields and vftable semantics, one named class UDT with an offset-zero pointer to that named table and C++ object semantics, applies the table type to its bytes, and types only eligible constructor and concrete virtual-method argument zero as the class pointer named `this`. Preserve existing complex types and expose create/reuse/change/skip counts.
  - **19.42.5. Cross-language model:** Extend the existing interactive C++ and headless Rust Symless adaptations with the same evidence and mutation rules. Rust adds a mutually exclusive `--vtables` mode, remains report-only by default, and saves only with `--apply`; C++ exposes separate report/apply actions.
  - **19.42.6. Scope boundary:** Do not infer inheritance from heuristic ranking, RTTI-adjusted indirect load chains, or multiple constructor stores. Exclude indirect dynamic calls, shifted-pointer metadata, forward-type replacement, member-TID informational xrefs, multi-element stroff paths, and microcode-widget selection until independently modeled and validated.
  - **19.42.7. Existing-layout preflight:** Before class/prototype mutation, reject any existing named vftable whose members are misaligned, extend beyond the discovered method count, or differ from the corresponding method-pointer type. Require an existing class offset-zero member to match the named table pointer; preserve incompatible nonzero fields and count them as skipped rather than reused.

- **19.43. Decision D-DETERMINISTIC-RECURSIVE-BINDGEN-NORMALIZATION**: Canonicalize recursive instruction bindings independently of libclang shape
  - **19.43.1. Input model:** Accept either bindgen's opaque recursive `IdaxMicrocodeInstruction` placeholder or its complete record plus generated layout/default helpers.
  - **19.43.2. Output model:** Replace the full named `repr(C)` declaration span with the one checked field-complete record and omit parser-version-dependent helpers. Fail generation if the named record, its `repr(C)` marker, or the following FFI boundary is absent.
  - **19.43.3. Validation rule:** Require byte identity between `$OUT_DIR/bindings.rs` and `idax-sys/src/bindings.rs`, not merely successful Rust compilation.

- **19.44. Decision D-SYMLESS-OPAQUE-SHIFTED-POINTERS**: Preserve pointer records and type only evidence-backed shifted arguments
  - **19.44.1. Type model:** Add copied pointer details containing pointee, optional shifted parent, signed byte delta, and shifted state. Add immutable `with_shifted_parent(parent, delta)` for an existing pointer; require a struct parent and a nonzero delta representable by native signed 32-bit `ptr_type_data_t::delta`.
  - **19.44.2. Preservation model:** Copy the complete native pointer record and change only `TAPTR_SHIFTED`, `parent`, and `delta`. Preserve pointee, closure, based-pointer size, pointer declaration kind, and unrelated `taptr_bits`. Never use `ptr_type_data_t::operator==` to compare shifted metadata (F420).
  - **19.44.3. Binding model:** Mirror the copied details and immutable constructor through Node and Rust with owned type handles, exact signed conversion, deterministic freeing, structural signatures, and initialized-host runtime evidence.
  - **19.44.4. Apply model:** For each already-proven propagated argument site, construct the root pointer for shift zero or its explicit shifted-parent variant for nonzero shift. Replace only generic pointers/pointer-width scalars, recognize exact parent/delta as already typed, preserve incompatible complex pointers, and expose separate shifted change/already/ineligible counts.
  - **19.44.5. Scope boundary:** Keep shifted returns excluded. Do not infer shifts from operand formatting, create local-variable mappings, or conflate this slice with indirect dynamic calls, forward local-type replacement, member-TID xrefs, multi-stroff paths, or widget selection.

- **19.45. Decision D-ORDINAL-PRESERVING-FORWARD-REPLACEMENT**: Replace only validated local structure/union forwards with copied complete definitions
  - **19.45.1. Classification model:** Add explicit forward-declaration state and declared-kind inspection to opaque `TypeInfo`; map native struct/union/enum forwards to the existing public `TypeKind` vocabulary and report `Unknown` otherwise.
  - **19.45.2. Replacement model:** A complete candidate invokes `replace_forward_declaration(name)`. Resolve the exact local target, reject sub-TIL types and zero ordinals, require an explicit struct/union forward of the same kind, copy the candidate, and save the copy into the existing ordinal with `NTF_REPLACE | NTF_COPY`. Return a fresh named handle and preserve the candidate.
  - **19.45.3. Failure model:** Reject empty or embedded-NUL names, absent/locality failures, complete targets, enum forwards, forward candidates, non-UDT candidates, and struct/union mismatches before mutation. Surface SDK save errors without falling back to delete-plus-create.
  - **19.45.4. Binding model:** Mirror classification and replacement through Node plus generated C ABI/safe Rust, retaining owned returned handles and exact error categories. Validate structural signatures and initialized-host behavior.
  - **19.45.5. Symless model:** In both adaptations, treat an exact named structure forward as replaceable during explicit apply, create the recovered complete definition off-database, replace the forward ordinal once, and report that transition separately. Preserve any complete same-name definition and all incompatible names.
  - **19.45.6. Scope boundary:** Do not delete local types, replace enum forwards, overwrite complete definitions, infer equivalence across aliases, or conflate this phase with member-TID xrefs, multi-element stroff paths, indirect dynamic calls, RTTI-adjusted vtable chains, or widget selection.

- **19.46. Decision D-OPAQUE-PERSISTENT-MEMBER-REFERENCES**: Resolve exact UDT-member identities internally and expose only source addresses
  - **19.46.1. Identity model:** Add `TypeInfo::member_references(byte_offset)` and `ensure_member_reference(byte_offset, source_address)`. Require a complete saved local UDT and exactly one member whose bit offset equals `byte_offset * 8`; obtain `get_udm_tid(index)` only inside the compiled implementation and never return it.
  - **19.46.2. Persistence model:** Ensure `dr_I | XREF_USER` from a mapped item head. Return `false` for an exact existing persistent informational reference and `true` only after a newly added reference is verified. Reject an incompatible existing source/target reference rather than changing its type or persistence.
  - **19.46.3. Read model:** Enumerate only source `Address` values of exact user informational references targeting the member. Do not reinterpret the member TID as a public program address or include nonpersistent references in idempotence decisions.
  - **19.46.4. Binding model:** Mirror the two methods through Node and generated C ABI/safe Rust on the existing opaque `TypeInfo` handle, with checked unsigned offsets/addresses, deterministic arrays, structural signatures, and initialized-host runtime evidence.
  - **19.46.5. Symless model:** Report recovered access-site candidates without mutation. For each exact compatible materialized field, explicit apply ensures one persistent member reference per unique recovered site and reports added/reused/skipped counts; fresh-process reopen must add zero and classify existing references as reused.
  - **19.46.6. Scope boundary:** Do not apply operand stroff paths, expose member/type TIDs, reference overlapping/incompatible members, infer missing access sites, or conflate this phase with multi-element stroff, indirect dynamic calls, RTTI-adjusted vtable chains, or widget selection.

- **19.47. Decision D-OPAQUE-EXACT-OPERAND-STROFF-PATHS**: Replace raw identities and apply only evidence-selected exact member paths
  - **19.47.1. Opacity correction:** Supersede the raw-ID portion of the earlier instruction stroff design. `StructOffsetPath` contains copied `structure_name`, ordered copied `member_names`, and signed `delta`; remove the public numeric C++ overload, Node numeric input, safe-Rust `*_by_id`, raw-ID C transfer, and unresolved numeric-name fallback. This is a pre-1.0 correction required by the locked fully opaque API decision.
  - **19.47.2. Exact mutation model:** Add `ensure_operand_struct_member_offset(address, operand_index, structure_name, member_byte_offset, delta) -> Result<bool>`. Resolve a complete saved local UDT and exactly one member at the exact bit offset internally, preflight both the current native path and arbitrary-operand representation flags, return `false` for exact equality, reject any incompatible path or defined non-stroff representation before mutation, treat a stroff-flag/path disagreement as an SDK failure, apply `[root, member]`, and verify readback before returning `true`.
  - **19.47.3. Read model:** Validate address/index, resolve the root with `get_tid_name` and every member identity with `get_udm_by_tid`, and require every copied name to be nonempty; fail if any component is unresolved. Retain the flattened names convenience as `root + members`, implemented from the opaque structured result. Exact apply clears its attempted representation after SDK failure or verification mismatch because preflight establishes a pristine operand.
  - **19.47.4. Register-evidence model:** Extend owned `MicrocodeOperand` with `processor_register_id`, set only for register operands through `mreg2reg(mreg, byte_width)`, use `-1` when unavailable, and mirror the copied integer through Node and Rust. The existing microregister ID remains unchanged for data-flow state.
  - **19.47.5. Symless application model:** Record direct register-backed load/store evidence and upstream-equivalent size-zero pointer `add`/`sub` observations. The latter carry the shifted target offset and source processor register but never create fields; attach them by exact offset after nonzero field conflict resolution. Preserve first-observation order, group by `(instruction, processor register)`, select the same phrase/displacement or register-preceded immediate pattern as upstream, and compute width-signed `field_offset - encoded_displacement`. Report candidates without mutation; explicit apply classifies added/reused/skipped, preserves incompatible existing representations, and leaves additional same-instruction fields to exact member references.
  - **19.47.6. Scope boundary:** Do not expose arbitrary native path components, infer an operand without register evidence, overwrite incompatible representations, approximate indirect dynamic calls, follow RTTI-adjusted vtable chains, or infer current widget selection.

- **19.48. Decision D-DATABASE-DERIVED-INDIRECT-CALLS**: Follow only source-equivalent statically loaded `m_icall` targets
  - **19.48.1. Provenance model:** Add an adaptation-internal database-derived scalar kind distinct from plain integers. Create it only from a successful loaded global-memory read, address-of an exact global, or load through an already database-derived address; preserve it through source-equivalent move/extension/add/sub operations.
  - **19.48.2. Target model:** For `IndirectCall`, evaluate only the right/offset operand, require database-derived provenance, normalize its unsigned value to its recorded byte width, and accept only a graph/function whose entry equals that value. Ignore the selector and do not accept a plain integer or analyzed call-info target as a provenance substitute.
  - **19.48.3. Flow model:** After exact target resolution, reuse the Phase 38 call-argument injection, depth bound, active-context rejection, completed-context reuse, graph cache, and terminal-return consensus. Preserve unresolved-call accounting for all rejected targets.
  - **19.48.4. Allocator model:** Permit the same database-derived indirect resolution in allocator call-site classification and fixed-root/wrapper propagation; retain exact configured allocator equality and terminal-origin confirmation.
  - **19.48.5. Binding model:** No public API or binding addition is required. C++, Node, Rust, and the C ABI already expose the owned operands/call arguments plus loaded data and exact function lookup needed by both adaptations.
  - **19.48.6. Scope boundary:** Do not guess runtime register values, accept arbitrary immediate addresses, resolve structure-dependent virtual dispatch, follow RTTI-adjusted vtable-load chains, or model the microcode-widget picker. Those remain separate evidence requirements.
  - **19.48.7. Allocator reachability model:** In addition to exact direct call xrefs, follow one bounded data-reference hop from a configured allocator to a fixed pointer slot and from that slot to code users. Scan only the containing cached owned graphs for indirect sites, and accept a site only after the same database-derived target and allocator-argument classifier succeeds. Do not scan the whole program or treat data/code references themselves as calls.

- **19.49. Decision D-STATIC-RTTI-VTABLE-PROPAGATION**: Expand vtable roots through exact static evidence
  - **19.49.1. Candidate model:** Retain Phase 40 function-array acceptance: exact function entries or mapped imports, no incoming references to non-first slots, at least one non-import member, and bounded scan length.
  - **19.49.2. Reachability model:** Search direct references to the function-array address first. If no constructor load is confirmed, search references to `table - 2 * pointer_width`. Follow only exact pointer-valued data aliases, recursively with a visited-address set; code references contribute containing functions but never prove a load by themselves.
  - **19.49.3. Confirmation model:** Analyze each containing function once per candidate set and accept a load only when owned microcode proves a pointer-width store of the exact final function-array address into a structure pointer derived from argument zero. Count direct, RTTI-label, data-alias, cycle, and graph-failure outcomes explicitly.
  - **19.49.4. Propagation model:** After one unambiguous offset-zero constructor associates a table with a class, reconstruct from each constructor and each accepted non-import table member rooted at argument zero, using the existing depth/cycle/cache/field-conflict engine. Merge duplicate access evidence exactly as current class reconstruction does.
  - **19.49.5. Binding model:** Add no public API. The opaque xref snapshots, database pointer reads, function containment, exact graph entry lookup, and owned microcode graphs already express the complete bounded workflow in C++ and Rust.
  - **19.49.6. Scope boundary:** Do not resolve structure-dependent virtual call instructions, guess runtime object contents, infer inheritance from table size/xref heuristics, accept imported members as analyzable roots, traverse non-pointer data, or approximate current microcode-widget selection.

- **19.50. Decision D-EXACT-MICROCODE-OPERAND-ROOTS**: Preserve writable-destination semantics and inject only an explicitly selected owned location
  - **19.50.1. Owned metadata model:** Add `bool modifies_destination` to `MicrocodeInstruction`, populated solely from SDK `minsn_t::modifies_d()`, and mirror it through Node plus generated C ABI/safe Rust. This copied semantic fact exposes no SDK pointer or mutable callback lifetime.
  - **19.50.2. Enumeration model:** Recursively visit nested left/right/destination instructions before their parent, preserving execution order. Enumerate only register and stack-variable operands in operand order; classify a destination as after-instruction only when `modifies_destination` is true, otherwise classify it as a source before-instruction root.
  - **19.50.2a. Identity correction:** Do not reproduce upstream renderer indexing defects. Derive the displayed sub-index and the injection point from one depth-first execution traversal, retain a private `(block, top-level instruction, nested operand path)` identity, and use `(EA, sub-index)` only as presentation and headless-resolution evidence.
  - **19.50.3. Injection model:** Identify a root by function entry, instruction address, execution-order sub-index, location kind/identity, and before/after phase. Inject exactly once per root-graph evaluation; never trigger the seed in a callee that happens to share an address/sub-index. Reuse existing abstract-state transfer, call-depth, active-context, cache, field-conflict, and report/apply logic after injection.
  - **19.50.4. Interface model:** Use the existing C++ modal chooser for candidate presentation, seeded near the current screen address; use an explicit candidate specification in the headless Rust adaptation. The upstream machine-operand hint and custom colored viewer are optional UI conveniences, not required semantic state.
  - **19.50.5. Scope boundary:** Do not infer pseudocode selection, expose callback-scoped SDK microcode values, inject local-variable or arbitrary operands, guess destination modification from opcode, or treat runtime/object-dependent virtual dispatch as a selectable static root.

- **19.51. Decision D-DYNAMIC-DISPATCH-NON-GAP**: Close audited Symless parity without inventing object-dependent call resolution
  - **19.51.1. Source boundary:** Treat upstream `handle_icall`'s exact database-derived right-operand rule as exhaustive; Phase 45 implements it. Treat upstream `analyze_virtual_methods` static argument-zero seeding as exhaustive for vtable method propagation; Phase 46 implements it.
  - **19.51.2. Classification:** Reclassify runtime/object-dependent dispatch from “future parity gap” to “unknown novel analysis outside audited upstream behavior.” No wrapper or adaptation work is justified by parity alone.
  - **19.51.3. Reopening condition:** Reopen only if a target upstream revision supplies a concrete object-derived resolver or a separate requested feature defines object/vtable state, ambiguity, and branch-set semantics with falsifiable fixtures.

- **19.52. Decision D-DIAPHORA-EXACT-FINGERPRINT-BOUNDARY**: Start the Diaphora port with deterministic exact fingerprints and conservative metadata import
  - **19.52.1. Source boundary:** Pin Diaphora 3.4.0 commit `84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99`. Implement full item-byte and audited relocation-light MD5 fingerprints, canonical CFG/mnemonic metadata, versioned manifest persistence, deterministic unique exact matching, and explicit function-level metadata import.
  - **19.52.2. Wrapper closure:** Add absence-aware primary and secondary operand encoded-value byte offsets copied from `op_t::offb`/`op_t::offo` across C++, Node, generated C ABI, and safe Rust. Do not expose `op_t`, native pointers, or mutable decode lifetimes.
  - **19.52.2a. Declaration readback closure:** Mirror existing C++ `function::declaration(address, name_override)` through Node, the generated C ABI, and safe Rust as owned UTF-8 values. Conservative import treats every successful nonempty target declaration as state to preserve and mutates only when readback is absent.
  - **19.52.3. Matching policy:** Prefer same-RVA plus both hashes, then both hashes, full hash, and finally relocation-light hash with instruction-count agreement. Accept only one unmatched candidate per tier; classify zero or multiple candidates explicitly rather than resolving by order.
  - **19.52.4. Mutation policy:** Report/export/compare are non-mutating. Explicit apply may transfer a non-auto source name, nontrivial declaration, and nonempty repeatable function comment only when target state is absent or auto-generated; incompatible user metadata is preserved and reported.
  - **19.52.5. Corrected metrics:** Count each directed CFG edge once and derive segment-relative offset from function entry. Mark the manifest as an IDAX adaptation, not native Diaphora SQLite interchange.
  - **19.52.6. Deferred independent surfaces:** SQLite schema compatibility, the complete heuristic engine, fuzzy ratios, pseudocode/microcode hashes and diffs, type-library/definition import, instruction-level metadata import, compilation units, callgraph matching, and interactive choosers remain separately auditable gaps.

- **19.53. Decision D-DIAPHORA-EXACT-INSTRUCTION-METADATA-BOUNDARY**: Close conservative native instruction comments/forced operands before the coupled heuristic engine
  - **19.53.1. Source boundary:** Adapt only native `instructions.comment1`, `comment2`, and ordered `operand_names` import. Do not include referent name/type propagation or Hex-Rays pseudocode comments in this slice.
  - **19.53.2. Alignment:** Require a globally unique Phase 48 function match. Within it, require the same function-relative byte offset, decoded size, mnemonic, and relocation-light MD5 before an instruction metadata record is eligible.
  - **19.53.3. Mutation:** Report/export/compare are non-mutating. Explicit apply fills only absent ordinary/repeatable comments and absent forced operand slots; every nonempty target value is preserved and counted.
  - **19.53.4. Persistence:** Use a versioned deterministic tab/hex companion manifest rather than claiming partial native SQLite compatibility. C++ and Rust artifacts must be byte-compatible and reject malformed/duplicate/out-of-range records.
  - **19.53.5. Wrapper closure:** None. Existing opaque comment and forced-operand read/write surfaces cover the selected contract across C++, Node, generated C ABI, and safe Rust.
  - **19.53.6. Deferred independent surfaces:** Native SQLite interchange, full heuristic/ratio/multimatch state, referent names/types, pseudocode comments, raw function flags, program definitions/TILs, compilation units, callgraphs, and chooser UI remain outside this artifact.

- **19.54. Decision D-SEMANTIC-MULTI-LOCATION-PSEUDOCODE-COMMENTS**: Correct comment locations and preserve every persisted ctree comment
  - **19.54.1. Public model:** Replace raw/numerically coupled comment positions with a semantic opaque value supporting every named simple position, zero-based arguments `0..63`, and bounded signed switch cases. Keep all SDK `ITP_*`, `treeloc_t`, and encoded integers internal.
  - **19.54.2. Compatibility correction:** Preserve existing C++ call syntax such as `CommentPosition::Semicolon` through semantic constants, but correct its internal mapping to the pinned SDK. Replace safe Rust's raw `i32`; add equivalent discriminated Node inputs. This pre-1.0 correction supersedes the incorrect numeric enum.
  - **19.54.3. Enumeration:** Add copied deterministic `PseudocodeComment` enumeration from persisted user comments, including address, semantic location, and text. Reject unrepresentable SDK positions rather than leaking raw values; free restored maps with the SDK helper.
  - **19.54.4. Diaphora adaptation:** Use a separate versioned C++/Rust byte-compatible companion manifest. Require a globally unique Phase 48 function match and Phase 49 ordinal/relative-offset/size/mnemonic/relocation-hash instruction guard. Preserve all same-address locations, unlike upstream's lossy address-only dictionary.
  - **19.54.5. Mutation:** Export/compare are non-mutating. Explicit apply fills only absent exact `(address,location)` slots, preserves every nonempty target value, saves only after successful changes in headless Rust, and never deletes orphan comments implicitly.
  - **19.54.6. Scope boundary:** Do not claim native SQLite compatibility, pseudocode hash/similarity parity, ctree semantic identity beyond persisted locations, automatic orphan relocation, referent name/type propagation, raw function-flag parity, or chooser UI.

- **19.55. Decision D-DIAPHORA-EXACT-REFERENT-METADATA-BOUNDARY**: Transfer instruction referent names/types only across unique same-class references
  - **19.55.1. Source correction:** Do not reproduce Diaphora's last-reference export, first-reference import, or secondary-offset follow. Treat those as ambiguous whenever more than one distinct non-flow code or data referent exists.
  - **19.55.2. Persistence:** Add a separate versioned, deterministic, byte-compatible C++/Rust companion containing function records plus one referent record per exact instruction/reference class. Require at least one non-auto source name or applied source type.
  - **19.55.3. Alignment:** Reuse globally unique Phase 48 function matches and Phase 49 exact instruction guards. Require exactly one target referent of the recorded code/data class; zero or multiple targets are explicit reference-guard failures.
  - **19.55.4. Mutation:** Report/export/compare are non-mutating. Explicit apply fills absent/auto names and absent types only; every target-owned name/type is preserved. Never create references or follow offsets.
  - **19.55.5. Wrapper closure:** None. Existing opaque `xref`, `name`, `type`, `instruction`, and `function` APIs cover C++ and safe Rust extraction/readback/application.
  - **19.55.6. Independent exclusions:** Native SQLite interchange, coupled heuristic/ratio/multimatch state, pseudocode/microcode similarity, raw function flags, definition/TIL import, compilation units, callgraph matching, and chooser UI remain separate surfaces.

- **19.56. Decision D-IDENTITY-BEARING-ABSOLUTE-PATH-HYGIENE**: Store reproducible evidence without workstation identity
  - **19.56.1. Scope:** Prohibit identity-bearing absolute paths in tracked text and binary artifacts. This includes user homes, private checkout roots, SDK/runtime evidence paths, and local upstream-source locations.
  - **19.56.2. Representation:** Replace paths with semantic non-absolute tokens plus relevant relative suffixes. Retain generic platform paths only when they are non-identifying runtime semantics or discovery behavior.
  - **19.56.3. Binary safety:** For serialized IDA databases, permit only equal-byte-length substitutions followed by isolated real-IDA open/read validation; otherwise regenerate through a supported API or reject the edit.
  - **19.56.4. Verification:** Scan Git-tracked text and `strings` output for every tracked blob, then scan all reachable Git objects and remote refs. Current-tree cleanup and history cleanup are distinct closure gates.

- **19.57. Decision D-HCLI-SEMANTIC-LICENSE-SELECTION**: Select installer licenses from complete entitlement rows
  - **19.57.1. Input:** Capture complete `hcli license list` output and parse row fields through one repository script; do not duplicate shell token pipelines across workflows.
  - **19.57.2. Eligibility:** Require canonical ID, active status, named type, and a positively enumerated installable IDA edition family. Never select Teams Server, Lumina Server, Free, expired, or activation-pending rows.
  - **19.57.3. Determinism:** Rank supported edition families and preserve source order within equal priority. Emit only the chosen ID on stdout for command substitution and a non-sensitive error on failure.
  - **19.57.4. Confidentiality:** Register the selected identifier with GitHub Actions `add-mask` immediately after selection and before HCLI can repeat it; never log the full entitlement table or identifier from workflow-authored diagnostics.
  - **19.57.5. Validation:** Unit-test the observed server-first table shape plus malformed/no-match cases; run a structural workflow audit proving all install sites call the shared selector and mask the result.

- **19.58. Decision D-CI-IDA-RELEASE-LOCK**: Match the SDK commit to the installed IDA runtime release
  - **19.58.1. Version set:** The 9.3 installer assets and SDK must move as one explicit release set; never combine a fixed runtime asset with an unpinned SDK default branch.
  - **19.58.2. Pin:** Use exact official `v9.3` commit `d5db59ab4e9d2ae92038e9520082affd0da6fe20` at every SDK checkout and retain recursive submodule checkout for its build helper.
  - **19.58.3. Upgrade rule:** A later IDA release requires one reviewed change covering asset keys, SDK commit, compiler/runtime compatibility, and complete cross-platform evidence.

- **19.59. Decision D-WINDOWS-RUST-HEADLESS-RUNTIME-GATE**: Retain Windows compile/unit coverage; gate unstable example execution
  - **19.59.1. Decision:** Remove execution of Rust examples on `windows-latest`; retain release construction of all examples, 140 unit tests, and integration-test compilation. Continue executing Rust examples on Linux/macOS.
  - **19.59.2. Evidence:** Both `open_database(..., true)` and `open_database(..., false)` exit code 1 before wrapper error propagation after successful IDA initialization. The latter run explicitly confirms the analysis-disable toggle was consumed.
  - **19.59.3. Scope:** This supersedes decision 19.18.3 and decision 19.22 for automated Windows example execution only. Trace/analysis controls remain available for diagnostics; no library or public API behavior changes.
  - **19.59.4. Reopening condition:** Restore the gate only after a supported Windows runner/runtime opens and closes a controlled fixture with zero exit status and produces actionable diagnostics on failure.

- **19.60. Decision D-IDA-9-4-CI-RELEASE-ALIGNMENT**: Move installer, SDK, and CMake acquisition as one exact release set
  - **19.60.1. Runtime:** Use IDA 9.4 HCLI assets for Windows x64, Linux x64, macOS arm64, and macOS x64 in every install block.
  - **19.60.2. SDK:** Pin all workflow checkouts and the FetchContent fallback to official commit `6929db6868a524496eb66e76e4ec6c9d720a0594`; do not follow the moving `releases/9.4.0` branch.
  - **19.60.3. Package migration:** Support both legacy bootstrap entry points and the 9.4 `idasdkConfig.cmake` package. Resolve Git checkouts to their `src` SDK root and retain opaque IDAX target construction through `find_package(idasdk)`.
  - **19.60.4. Fallback integrity:** Fetch the exact commit archive with required SHA-256 `6ba645ef8fb5663d45d28c7a48da274e22a5929ddbfbc69cd4be34a4d7ee9895`, because generic clone-then-checkout is not reliable after the release branch moves.
  - **19.60.5. Validation:** Require exact-SHA configure/build evidence, no-environment archive configure evidence, 4/4 YAML parsing, selector regression, structural zero legacy refs, exact staged review, and live cross-platform Actions evidence.
  - **19.60.6. MSVC runtime:** Preserve an explicit consumer `CMAKE_MSVC_RUNTIME_LIBRARY` across SDK package loading; default standalone IDAX to static CRT for its Node/Rust binding contract. Keep SDK import-library resolution on the ordinary 9.4 layout rather than selecting the incomplete all-static suffix.

- **19.61. Decision D-FULL-PYTHON-BINDING-ARCHITECTURE**: Bind the complete opaque IDAX surface through a direct C++ extension and an idiomatic typed Python package
  - **19.61.1. Native boundary:** Use pybind11 3.x with CMake and scikit-build-core. Bind directly to `idax::idax`; do not make the Rust-oriented C allocation shim the public Python backend and do not expose SDK pointers, structs, or raw handles.
  - **19.61.2. Package model:** Publish package `idax` with one private CPython extension, `idax._native`, and public snake-case modules matching all 27 C++ domains. Public modules own documentation, typing, convenience context managers, and compatibility aliases; the native extension owns conversion, error, lifetime, callback, and host-runtime boundaries.
  - **19.61.3. Values and ownership:** Represent copied IDAX snapshots as constructible Python value classes with value equality and informative `repr`; preserve opaque RAII resources as non-copyable native classes with deterministic `close`, context-manager support where applicable, and idempotent finalization. No public `raw`, native pointer integer, or borrowed SDK lifetime is permitted.
  - **19.61.4. Errors:** Convert every failed `Result<T>`/`Status` to `IdaxError` carrying `category`, `code`, `message`, and `context`, with category-specific subclasses. Argument conversion failures use ordinary Python `TypeError`/`ValueError` only when failure occurs before IDAX dispatch.
  - **19.61.5. Runtime and callbacks:** Preserve IDA's initializing-thread requirement for idalib sessions, acquire the GIL at every host-to-Python callback, translate callback exceptions at the ABI boundary, and keep callback objects alive until explicit unregister or owning-object destruction. Do not release the GIL around operations that can synchronously invoke Python.
  - **19.61.6. ABI and distribution:** Build CPython-version-specific wheels; do not claim `abi3` compatibility. Link against user-supplied IDA runtime libraries without bundling proprietary binaries. Require an ABI-compatible Python interpreter for the built extension and retain editable/source builds as the IDAPython deployment path.
  - **19.61.7. Coverage gate:** Maintain an explicit symbol-level manifest derived from the authoritative `include/ida/*.hpp` surface. A domain is complete only when native binding, public Python export, stub/type coverage, documentation, structural tests, and applicable real-IDA evidence all exist. Full parity cannot be inferred from import success or another language binding.
  - **19.61.8. Validation:** Require pure Python tests, native build/import tests, wheel and sdist inspection, strict typing/stub checks, manifest parity checks, initialized-host tests on IDA 9.4, examples, leak/lifecycle/callback tests, and Linux/macOS/Windows CI before Phase 57 closure.

- **19.62. Decision D-PYTHON-OPTIONAL-HOST-CAPABILITY-GATES**: Separate unavailable licensed/interactive host capabilities from independent runtime coverage
  - **19.62.1. Detection:** Use the public capability query before executing a decompiler/debugger/Lumina/GUI-specific tranche. Product version labels do not override SDK/plugin ABI checks.
  - **19.62.2. Default runtime gate:** When an optional capability is absent, report it explicitly and continue exercising independent domains in the same initialized-host run; never treat absence as success for that capability.
  - **19.62.3. Strict hosts:** `IDAX_PYTHON_REQUIRE_DECOMPILER=1` converts Hex-Rays absence into a test failure. Unix CI uses this strict mode after an HCLI SDK-matched IDA installation; local or reduced-license hosts retain non-decompiler evidence.
  - **19.62.4. Safety:** Do not alter API magic, call tables, layouts, or plugin discovery to force a mismatched capability. A matching installed component is the only reopening condition.
  - **19.62.5. Interactive boundary:** Headless automation does not claim action activation, modal-form acceptance, chooser/viewer presentation, popup attachment, or visual rendering. Those remain explicit GUI-host evidence gates while their structural, ownership, and callback behavior stays testable.

- **19.63. Decision D-OPAQUE-PROCESSOR-MODULE-BRIDGE**: Materialize the IDA ABI only inside the compiled IDAX archive
  - **19.63.1. Public boundary:** Keep `ProcessorInfo`, `AnalyzeDetails`, operands, switches, and output tokens SDK-free. Add exact semantic fields/constants where required, but expose no `processor_t`, `procmod_t`, `insn_t`, `op_t`, `outctx_t`, SDK pointer, or raw escape hatch.
  - **19.63.2. Binary entry:** A private compiled bridge owns the exported `LPH`, materialized descriptor arrays, generic assembler fallback, `procmod_t`, and `processor_t::event_t` dispatcher. `IDAX_PROCESSOR` owns one lazy wrapper instance and a dynamic link anchor that forces the private bridge object out of the static archive.
  - **19.63.3. Ownership:** Descriptor strings/arrays live for the module lifetime; IDA owns each returned `procmod_t`; the bridge borrows the macro-owned wrapper singleton until binary unload. Callback exceptions and failed `Result` values are contained at the ABI and converted to conservative SDK return codes with diagnostics.
  - **19.63.4. Analysis/output:** `AnalyzeDetails` supplies canonical instruction code, positive byte length, and at most eight uniquely indexed normalized operands. The bridge validates and copies them into SDK records. Tokenized output is copied immediately into the callback-scoped SDK output context with semantic colors; no borrowed context escapes.
  - **19.63.5. Metadata:** Public `ProcessorFlag`, `ProcessorFlag2`, and `InstructionFeature` values match the pinned SDK exactly. `default_bitness` deterministically supplies the corresponding use/default-segment bits. Empty assembler metadata receives a stable generic assembler so minimal modules remain discoverable.
  - **19.63.6. Validation:** Require exact-SDK constant assertions, per-example `LPH` export checks, descriptor/dispatch rejection tests, real IDA load/decode/render evidence, full native/binding regression, cross-platform CI, and identity-path scanning before closure.

- **19.64. Decision D-RUNTIME-ANALYSED-INTEGRATION-FIXTURES**: Keep generic native integration input release-neutral
  - **19.64.1. Generic boundary:** The common CTest runner copies only the raw fixture and lets the current IDA runtime create its disposable database. It never implicitly places a pre-analysed sidecar beside the input.
  - **19.64.2. Existing-database exceptions:** A test that specifically requires a prebuilt database must select it explicitly, document its release compatibility, and retain byte-level privacy validation; generic semantic tests do not inherit that state.
  - **19.64.3. Validation:** Require the complete exact-SDK/IDA 9.4 CTest matrix, not only the new Phase 53 target, because the former sidecar behavior affected every database-backed native executable.

- **19.65. Decision D-STRING-LIST-EXTENDED-OUTPUT-STORAGE**: Defend the IDA 9.4 string-list ABI discrepancy inside the opaque bridge
  - **19.65.1. Call boundary:** Continue calling the runtime-exported `get_strlist_item`, but provide `string_info_ex_t` storage whose leading base is exactly `string_info_t`; do not expose either SDK type publicly.
  - **19.65.2. Copy boundary:** Validate address and nonnegative octet length, copy ordinary text through the semantic reader, and copy the extended decompiler text when the runtime supplies it. No SDK-owned string lifetime escapes.
  - **19.65.3. Validation:** Require exact-SDK compilation, real IDA 9.4 string-list enumeration, the existing Rust/C++ contract tests, and cross-platform CI; re-audit when the release set changes.

- **19.66. Decision D-OPAQUE-NAMED-UNDO-DOMAIN**: Expose host undo state without exposing native records
  - **19.66.1. Public boundary:** Add `ida::undo` with named point creation, optional copied undo/redo labels, and boolean execution results. Mirror those exact semantics in Node, Rust, and Python; do not expose `bytevec_t`, raw record bytes, `qstring`, pointers, or handles.
  - **19.66.2. Encoding:** Build the SDK `UNDO_ACTION_START` body privately using the official two-`pack_ds` sequence. Reject embedded NUL at the public string boundary; otherwise preserve empty or non-ASCII UTF-8 values byte-for-byte.
  - **19.66.3. State semantics:** Treat absent labels and rejected/unavailable operations as valid state values (`null`/`None`/`Option` and `false`). Reserve structured errors for invalid input or binding/transport failures; do not convert a disabled undo host into a fictitious SDK diagnostic.
  - **19.66.4. Validation:** Require pure invalid-input and signature/parity probes, exact-SDK compilation, one disposable real-IDA checkpoint/comment/label/undo/redo/final-restore round trip, complete binding manifests, full regression, repository privacy, staged review, and cross-platform CI.

- **19.67. Decision D-OPAQUE-ANALYSIS-PROBLEM-DOMAIN**: Expose typed analysis problems independently of generic error search
  - **19.67.1. Public boundary:** Add `ida::problem` with a closed 16-value semantic `Kind`, optional copied description and next-address results, optional-message remember, boolean removal/presence, and copied short/long names. Mirror the semantics in Node, Rust, and Python.
  - **19.67.2. Opacity and validation:** Expose no `problist_id_t`, `qstring`, pointers, records, or raw numeric escape hatch. Reject invalid kinds, `BadAddress`, and embedded-NUL messages before host dispatch; allow unmapped non-sentinel addresses because some problem categories represent out-of-range flow.
  - **19.67.3. State semantics:** Treat missing descriptions and next entries as ordinary optional absence and a missing removal target as `false`. Preserve `None`/`null` versus an explicitly empty message at binding and C ABI boundaries.
  - **19.67.4. Validation:** Require exact discriminants and signatures, malformed-input probes, all-kind name coverage, one disposable real-IDA Unicode remember/describe/traverse/remove round trip, complete manifests, full regression, repository privacy, exact staged review, and cross-platform CI.

- **19.68. Decision D-OPAQUE-EXCEPTION-REGION-DOMAIN**: Model architecture-independent C++ and SEH regions without native records
  - **19.68.1. Public boundary:** Add `ida::exception` values for fragmented protected ranges, common handler metadata, typed/catch-all/cleanup C++ catches, SEH filter ranges and semantic dispositions, calculated nesting, and a closed semantic location mask. Mirror the complete five-operation SDK surface in Node, Rust, and Python.
  - **19.68.2. Opacity:** Expose no `tryblk_t`, `catch_t`, `seh_t`, SDK vectors, pointers, reserved storage, raw error constants, or raw membership integers. Convert every native aggregate immediately to owned IDAX values and rebuild temporary native values only inside `add`.
  - **19.68.3. Validation and state:** Reject `BadAddress` starts, empty/reversed ranges, unknown flags, malformed handler/disposition combinations, negative typed identifiers, and missing handlers before dispatch. Preserve unknown range ends through `BadAddress`, unknown stack/frame/object metadata through optionals, and missing system-region lookup through ordinary optional absence. Map native intersection to `Conflict`, native malformed-input codes to `Validation`, and other failures to `SdkFailure`.
  - **19.68.4. Validation:** Require exact enum/flag assertions, malformed-value probes, isolated real-IDA C++ and SEH add/list/membership/system-lookup/remove round trips, complete binding manifests, full regression and packages, repository privacy, exact staged review, and cross-platform CI.

- **19.69. Decision D-OPAQUE-SOURCE-PARSER-DOMAIN**: Expose third-party parser selection and type ingestion through semantic owned values
  - **19.69.1. Public boundary:** Add `ida::parser` with closed source-language flags, source-text versus file-path input, copied optional selected-parser identity, copied option values, semantic extended parse options, and copied error-count reports. Mirror all nine pinned operations in Node, Rust, and Python.
  - **19.69.2. Opacity and validation:** Expose no `srclang_t`, `til_t`, `qstring`, parser pointer, raw option buffer, or raw `HTI_*` integer. Reject zero/unknown language masks, empty required names or input, embedded NUL bytes, and invalid explicit pack alignment before host dispatch.
  - **19.69.3. State and errors:** Treat the empty selected-parser name as default-parser absence. Map missing selection/parser and missing option to `NotFound`, unsupported argument configuration to `Unsupported`, nonnegative parse returns to error-count reports, and other native rejection to `SdkFailure`. Parser option names/values remain owned strings because their schema is parser-defined.
  - **19.69.4. Local types:** Pass the SDK's null type-library target so parsed declarations enter the current database's local type library; never expose or accept a caller-owned native type-library handle.
  - **19.69.5. Validation:** Require exact language constants and signatures, malformed-input probes, isolated real-IDA selection/arguments/options/source/file/local-type evidence, complete binding manifests, full regression and packages, repository privacy, exact staged review, and cross-platform CI.

- **19.70. Decision D-OPAQUE-STANDARD-DIRECTORY-TREES**: Model built-in database organization through paths and copied snapshots
  - **19.70.1. Public boundary:** Add `ida::directory::Tree` acquired by one of eight closed semantic kinds. Expose copied `Entry` snapshots, owned paths/names/attributes, direct and recursive enumeration, wildcard item search, directory/item organization, natural/custom ordering, and indexed partial bulk reports. Mirror the same surface in Node, Rust, and Python.
  - **19.70.2. Opacity:** Store only the semantic kind publicly and reacquire the host-owned standard tree per operation. Expose no `dirtree_t`, `dirspec_t`, native pointer, inode, directory index, cursor, entry, iterator, visitor, SDK vector, or raw error integer.
  - **19.70.3. State and errors:** Validate strings, batch bounds, ranks, and embedded NUL before host dispatch. Map native already-exists/not-empty/own-child states to `Conflict`, missing paths to `NotFound`, malformed/non-directory paths to `Validation`, non-orderable operations to `Unsupported`, and remaining native failures to `SdkFailure`. Preserve per-input bulk failures as semantic `OperationError` values instead of collapsing partial success.
  - **19.70.4. Scope:** Close every user-facing operation on the host-owned standard trees. Custom `dirspec_t` construction, custom persistence IDs, raw inode notifications, and native event handlers form a separate callback-authoring domain and are not smuggled through this standard-tree value API.
  - **19.70.5. Validation:** Require exact kind/error constants, malformed-value probes, one disposable real-IDA directory/item/link/move/order/bulk/remove round trip, all eight read-only acquisitions, complete binding manifests, full regression/packages, repository privacy, staged review, and cross-platform CI.

- **19.71. Decision D-OPAQUE-SCOPED-PERSISTENT-REGISTRY**: Model plugin configuration through owned scoped stores and typed values
  - **19.71.1. Public boundary:** Add `ida::registry::Store` acquired from a nonempty owned subkey. Expose child stores, key/value existence and enumeration, semantic value kinds, copied optional string/binary/signed-integer/boolean reads, checked writes, value/key/tree deletion, and copied string-list read/write/update. Mirror the same surface in Node, Rust, and Python.
  - **19.71.2. Opacity and validation:** Expose no `qstring`, `qstrvec_t`, `bytevec_t`, raw buffer, `regval_type_t`, native pointer, backend filename/key handle, or platform-specific storage convention. Reject empty keys/names, embedded NUL, invalid child components, out-of-range binding integers, oversized list limits, and contradictory empty updates before host dispatch.
  - **19.71.3. State semantics:** Missing values return ordinary optional absence, existence/deletion return booleans, missing enumerated keys return `NotFound`, and unknown native value kinds return `Unsupported`. Boolean values retain the SDK's integer storage convention but return semantic booleans.
  - **19.71.4. Root boundary:** Do not expose `set_registry_name`; the process-global mutation has no getter or restoration token and is not scoped state. A future reversible SDK contract requires a separate audit.
  - **19.71.5. Validation:** Require exact value-kind and signature assertions, malformed-input probes, one collision-resistant disposable subtree covering every type/enumeration/list/delete operation and cleanup, all binding manifests, full regression/packages, repository privacy, exact staged review, and cross-platform CI.
  - **19.71.6. Deterministic list updates:** Do not surface the native void `reg_update_strlist` result as success because `IDA_NO_HISTORY` suppresses it for every key. Preserve semantic update behavior through copied read/modify/verified-write state, a closed `1..1000` limit, SDK-consistent case comparison, and explicit contradictory-request validation; document the compound-operation concurrency boundary.

- **19.72. Decision D-OPAQUE-REGISTER-VALUE-TRACKING**: Model register-finder results through names and copied semantic state
  - **19.72.1. Public boundary:** Add `ida::registers` with closed tracking states, copied defining origins and constant/stack-delta candidates, optional convenience results, nearest-of-two selection, and semantic control-flow/data-reference cache notifications. Mirror the same behavior in Node, safe Rust, and Python.
  - **19.72.2. Opacity:** Resolve register names privately and expose no processor register numbers, `reg_info_t`, `reg_finder_t`, `reg_value_info_t`, `reg_value_def_t`, native vector/iterator, processor-module pointer, or raw `cref_t`/`dref_t` sentinel. Preserve processor-specific defining instruction codes only as owned numeric metadata, consistent with the existing processor analysis model.
  - **19.72.3. State and errors:** Reject `BadAddress`, empty/NUL register names, invalid aliases, duplicate nearest registers, and depths below `-1` before tracking. Map unsupported processor tracking to `Unsupported`; preserve undefined/dead-end/aborted/seven unknown causes as closed states; preserve every known candidate and origin; return ordinary optional absence only from constant/stack convenience queries.
  - **19.72.4. Cache semantics:** Represent added/removed reference state semantically and translate to native sentinels privately. Provide whole-cache clear operations; never expose raw reference-type integers or a mutable native tracker handle.
  - **19.72.5. Validation:** Require exact signature and state/flag assertions, malformed-input probes, isolated real-IDA unique-constant/multi-candidate/negative-stack/unknown/nearest/cache evidence, recursive binding ownership checks, complete manifests/packages, repository privacy, staged review, and cross-platform CI.
  - **19.72.6. Release ABI compatibility:** In the private bridge translation unit, suppress the pinned header's two `reg_finder94_*` inline redirects and declare the adjacent official unsuffixed signatures that IDA Professional 9.4 actually exports. Retain compile-time function-pointer signature assertions and require all three release-platform link rows; expose no symbol-selection mechanism publicly.
  - **19.72.7. Executable export coverage:** Dispatch every audited convenience/cache export on at least one semantic public path. Use the dedicated constant export at default depth with validated low-width alias truncation, rich named tracking for explicit depth/complete state, numbered rich tracking for nearest capability detection, and the dedicated nearest/stack/cache exports for their matching operations.
  - **19.72.8. Release acquisition reliability:** Pin every setup invocation to immutable setup-uv revision `11f9893b081a58869d3b5fccaea48c9e9e46f990` (`v8.3.2`) and explicit uv `0.11.28`, with `${{ github.token }}` retained for authenticated fallback downloads. This removes latest-release metadata resolution, uses the action's Node 24 runtime and mirror default, preserves all IDAX/runtime/license semantics, and makes future uv/action updates reviewed changes.
  - **19.72.9. Complete-log privacy evidence:** Audit each completed push-triggered release workflow in a separate default-branch `workflow_run` job restricted to `actions:read`/`contents:read`. Download the triggering run ZIP without extraction; reject canonical license IDs and non-runner home paths; bound archive size/count; never print matched values. This removes workstation authentication from the closure invariant and preserves trust separation from pull-request code.
  - **19.72.10. Sanitized audit diagnosis:** Promote only the scanner's entry ordinal/category to an Actions error annotation and provide a read-only numeric-tag replay workflow. Matched bytes remain suppressed; replay uses the default-branch scanner, validates the run identifier, and obtains log access only through the scoped workflow token.
  - **19.72.11. CI service identities (superseded by 19.72.13):** Initially admitted documented GitHub-hosted runner homes and the official Linuxbrew service home as infrastructure paths. Replay falsified Linuxbrew as the observed cause; 19.72.13 removes that unevidenced allowance and retains only exact hosted-runner keys.
  - **19.72.12. Ephemeral private classification:** When a category-only replay remains ambiguous, encrypt each deduplicated matched prefix with one-use RSA-OAEP/SHA-256 to a committed public key, expose only ciphertext annotations, decrypt with an uncommitted local private key, and remove all key/diagnostic code immediately after classification. Do not broaden path allowlists by inference.
  - **19.72.13. Exact case-normalized runner membership:** Supersede the unevidenced Linuxbrew allowance in 19.72.11. Retain only fragment-constructed hosted Linux/macOS runner-home keys, compare complete candidates after ASCII lowercase normalization, and reject all other identities. Remove the ephemeral public key and encryption script in the same correction that consumes their evidence.

- **19.73. Decision D-NODE24-IMMUTABLE-CI-ACTIONS**: Remove Node 20 action runtimes and mutable external action references
  - **19.73.1. Immutable external boundary:** Every external workflow action must use a reviewed full 40-hex commit. Pin checkout v7.0.0, setup-node v7.0.0, upload-artifact v7.0.1, download-artifact v8.0.1, setup-uv v8.3.2, the current stable Rust composite snapshot, and a Node 24 `action-gh-release` snapshot; reject unknown or mutable external references offline.
  - **19.73.2. MSVC boundary:** Replace `ilammy/msvc-dev-cmd` with a repository-local composite PowerShell action limited to current x64 semantics. Discover `vcvarsall.bat` through `vswhere`, call it with validated architecture, parse at the first equals sign, export only changed variables, deduplicate `PATH`/`INCLUDE`/`LIB`/`LIBPATH`, suppress values from logs, and fail if `cl.exe` is not resolvable.
  - **19.73.3. Node setup state:** Retain Node.js 20 as the tested addon runtime while running the setup action itself on Node 24. Explicitly disable setup-node v7's new automatic package-manager cache so the migration does not add credential-bearing or stateful cache behavior.
  - **19.73.4. macOS bindgen state:** Use the selected Xcode toolchain's bundled `libclang.dylib` and fail if absent. Do not invoke Homebrew or weaken tap-trust checks for this dependency.
  - **19.73.5. Validation:** Require offline action-inventory/pin tests, local composite syntax/self-tests, workflow YAML/actionlint, candidate/reachable-history privacy, all 18 source jobs, complete-log audits, and public annotation inspection proving zero Node 20 and Homebrew trust warnings.

- **19.74. Decision D-OPAQUE-ADDRESS-BOOKMARKS**: Model the shared EA-capable bookmark store without native location identities
  - **19.74.1. Public model:** Add `ida::bookmark` with an owned address/slot/description snapshot, copied all/address/slot lookup, deterministic `set`, and idempotent address/slot removal. Slots are semantic unsigned values constrained to the native 1024-slot capacity.
  - **19.74.2. Mutation rule:** Reuse an existing address and update only its description when no conflicting explicit slot is supplied. Allocate the lowest free slot when absent; reject an occupied explicit slot or a different explicit slot for an existing address before mutation. Never invoke native choose-slot or description dialogs.
  - **19.74.3. Opacity rule:** Construct `idaplace_t`, `lochist_entry_t`, and renderer state internally with null EA-store userdata. Do not expose `place_t`, view/widget handles, renderer coordinates, `dirtree_id_t`, inodes, native vectors/strings, bookmark sentinels, or serialized records in any binding.
  - **19.74.4. Scope boundary:** Cover address bookmarks shared by IDA, pseudocode, and hex EA-capable viewers. Defer custom-place viewer bookmarks and `navstack_t` navigation history because they require plugin-owned place templates and widget userdata rather than address semantics.
  - **19.74.5. Validation:** Require exact capacity/sentinel assertions, malformed address/text/slot probes, isolated IDA 9.4 create/enumerate/update/conflict/remove/save/reopen evidence, complete C++/Node/Rust/Python manifests, full regression/packages, repository privacy, exact staged review, and cross-platform CI.
  - **19.74.6. Sparse enumeration:** Supersede compact-ordinal iteration. `size()` is the exclusive high-water slot bound while `get()` is indexed by the actual sparse slot; reject bounds above 1,024, scan `[0, size)`, skip unoccupied slots, and return successful reads in slot order.
  - **19.74.7. Identity-preserving removal:** Do not expose native `erase` compaction as slot deletion. Snapshot the complete store, clear it by repeatedly erasing the current tail, rebuild all survivors at their original explicit slots, and verify exact copied state. On replacement failure, attempt the same operation with the original snapshot and distinguish rollback failure. This retains idempotent public removal while keeping sparse native storage behavior private.
  - **19.74.8. Compile-surface audit:** Treat `idax_api_surface_check` as object-compilation evidence: every defined probe compiles even though its apparent `main` is not linked or executed. Add the bookmark probe, reconcile the dead aggregator with registry/register tracking at 37 groups, and derive a fail-closed umbrella-to-probe inventory at configure time while making no runtime-execution claim.

- **19.75. Decision D-OPAQUE-ADDRESS-NAVIGATION-HISTORY**: Model persistent address trails as named semantic handles
  - **19.75.1. Public values:** Add `ida::navigation::Entry { address, channel, metadata }` and a copyable `History` handle that owns only a validated logical stream name, immutable default entry, and creation observation. Prefix logical names into an IDAX-private native namespace.
  - **19.75.2. Native lifetime:** Construct/register/init/deregister a transient private `navstack_t` for each operation. Treat `init` Boolean as created-vs-existing, pass a private in/out default, and validate size/index/entries after every acquisition. No native object, netnode, stream key, place, renderer, widget, or serialized bytes enter public state.
  - **19.75.3. Operations:** Expose copied entries/current entry/per-channel current/all-current, size/index, current-channel update with explicit `record_in_history`, verified push, seek, optional boundary back/forward, indexed replacement, clear-to-tip, and channel transfer between two histories. Always use `try_to_unhide=false` and history enabled.
  - **19.75.4. Transfer semantics:** Name the Boolean `retain_history`: channel ownership always leaves source; false discards its matching entries and true appends them to destination. Require distinct acquired histories, source presence, destination absence, exact pre/post snapshots, and best-effort rollback with combined failure reporting.
  - **19.75.5. Opacity/scope:** Translate native widget-ID text to a semantic channel string and userdata to metadata. Exclude arbitrary custom `place_t` types, renderer coordinates, live `TWidget` actions/unhiding, native stream movement by raw name, public entry serialization, netnode codes, and deprecated `lochist_t`.
  - **19.75.6. Validation:** Require malformed names/entries/counts/indices; multi-channel current-state evidence; push-after-back truncation; seek/back/forward/replace/clear; both transfer modes and rollback preconditions; transient-handle save/reopen; all bindings/manifests/packages; exact SDK/runtime assertions; full privacy and live cross-platform release gates.
  - **19.75.7. Acquisition isolation:** Initialize transient native sessions with a reserved IDAX bootstrap channel rather than a public default because existing-stream initialization inserts a missing default channel into current state. Filter the bootstrap channel from all public current snapshots, reject the reserved prefix at every public channel input, and install the caller's initial tip/current explicitly only on creation.
  - **19.75.8. Cursor normalization:** After channel transfer, compute the source cursor as the nearest retained predecessor and preserve the destination's prior cursor. Normalize both with the exported seek operation's `apply_cur=false` form so repair cannot alter the independent public current map.

- **19.76. Decision D-OPAQUE-SEGMENT-REGISTER-STATE**: Model segment-register context through names, optional values, and copied ranges
  - **19.76.1. Public values:** Extend `ida::segment` with owned register descriptors containing canonical name, bit width, and semantic code/data roles; optional unsigned values/defaults; copied half-open ranges; and a closed four-value provenance enum. Mirror the same model in Node, safe Rust, and Python.
  - **19.76.2. Opacity:** Resolve names privately through the active processor descriptor and require membership in its segment-register interval. Expose no processor ordinal, `sreg_range_t`, `segment_t`, `segment_info_t`, `sel_t`, `BADSEL`, raw `SR_*` tag, native vector, or processor pointer. Retain the two legacy numeric setters only for source compatibility and route them through the current address-based SDK operation.
  - **19.76.3. State and validation:** Reject `BadAddress`, empty/NUL/unknown names, reserved maximum sentinel values, invalid provenance, reversed next-code bounds, out-of-range legacy ordinals, and same-register copies before dispatch. Preserve unknown register/default values and missing previous/range-index results as ordinary optionals; map an unknown future provenance tag to `Unsupported`.
  - **19.76.4. Mutation verification:** Propagate Boolean SDK rejection, then verify split start/value/source, deletion absence, per-segment defaults, and copied range state. For void next-code/default-data/copy operations, discover a falsifiable expected postcondition before dispatch and compare copied state afterward; report `NotFound` when no bounded next instruction exists. Processor policy may still reject a semantically valid register/value.
  - **19.76.5. Scope:** Cover all 12 current pinned `segregs.hpp` exports. Keep instruction-emulator event ordering, processor-module register declaration, selector creation/mapping policy, and arbitrary non-segment registers outside this segment-state boundary.
  - **19.76.6. Validation:** Require exact signature/tag assertions, malformed-input probes, one disposable exact-IDA 9.4 discovery/query/split/delete/default/next-code/copy/save-reopen lifecycle, all four binding manifests and initialized-host tests, complete regression/packages, repository and reachable-history privacy, exact staged review, and the 18-job release matrix plus complete-log audits.

- **19.77. Decision D-OPAQUE-OFFSET-REFERENCE-SEMANTICS**: Model operand references as owned semantic values with verified layered mutation
  - **19.77.1. Public values:** Add `ida::offset` with ten closed standard kinds plus custom-by-name identity, copied descriptors, main/outer operand locations, nine named Boolean options, optional target/base addresses, signed target delta, copied target/base calculations, plain rendered expressions, and simple/complex classification. Mirror the model in Node, safe Rust, and Python.
  - **19.77.2. Opacity:** Resolve standard/custom native types privately from the live descriptor inventory. Expose no `reftype_t`, custom numeric ID, `refinfo_t`, `REFINFO_*` flags, `OPND_*` sentinel, `qstring`, color tag, `insn_t`, `op_t`, or native vector. Preserve custom descriptor use but keep custom callback registration outside this value-only boundary.
  - **19.77.3. Operations:** Cover descriptor/default/query/apply/remove, stored and explicit expression rendering, OFF32 candidate detection, exact/probable base calculation, target/base calculation, operand-aware data-xref creation, and base-value calculation. Infer operand value and encoded byte location privately only for the ergonomic xref helper; keep explicit `from` and operand value on general calculation/rendering calls.
  - **19.77.4. Validation:** Reject sentinel addresses, indices outside `[0, 8)`, missing/unknown custom names, targets omitted for non-optional kinds, signed mode on non-full-width kinds, conflicting RVA/self-relative state, and explicit forced bases that disagree with image/self bases. Treat native address sentinels as optionals and unknown native types as `Unsupported`.
  - **19.77.5. Mutation safety:** Refuse to overwrite a non-offset user representation. Require decoded outer-displacement capability before an outer mutation. Snapshot any prior reference, dispatch, compare exact normalized copied readback, and restore or clear on failure. Removal must execute metadata deletion plus representation clearing and restore the original reference on partial failure.
  - **19.77.6. Validation evidence:** Require exact signature/constant assertions, malformed-input and pure conversion tests, isolated exact-IDA 9.4 standard-kind/options/apply/query/calculate/render/xref/remove/save-reopen evidence, complete four-binding manifests/packages, repository privacy, exact staged review, and all 18 release jobs plus complete-log audits.

- **19.78. Decision D-OPAQUE-IDC-VALUE-EXECUTION**: Model IDC values as owned semantic objects and execution as synchronous results
  - **19.78.1. Public values:** Add `ida::script::Value` with closed integer/floating/object/function/string/opaque-pointer/reference kinds; independent wrapper storage; native shallow object-copy semantics; explicit deep copy; exact typed access; explicitly named SDK coercions; rendering; object class/attributes; half-open slices; and reference dereference. Retain native non-scalar values privately rather than flattening them.
  - **19.78.2. Execution operations:** Expose current-language and IDC-only expression evaluation, integer evaluation, file/text/snippet compilation, named invocation, file compile-and-call, IDC snippet execution, system-script execution, function discovery, include-path replacement/append, IDC file resolution, copied globals, global assignment, and global references.
  - **19.78.3. Resolver boundary:** Replace synchronous `idc_resolver_t*` inputs with an owned list of name/unsigned-value entries. Validate duplicate/NUL names, retain the map only for the SDK call, return `BADADDR` for absent names, and contain all adapter exceptions. Do not expose bytecode, resolver pointers, or host callbacks.
  - **19.78.4. Errors and validation:** Reject embedded NUL in every SDK C-string input, empty required names/paths/source, invalid addresses, oversized binding indices/indents, duplicate resolver names, and ambiguous include components before dispatch. Determine execution success only from the native Boolean; preserve nonempty error text and the result/exception value on failure. Exact access rejects mismatched kinds; coercion preserves documented SDK behavior, including nonnumeric-string-to-zero conversion.
  - **19.78.5. Opacity and scope:** Expose no `idc_value_t`, `idc_object_t`, `idc_class_t`, `fpvalue_t`, `qstring`, raw tags, pointers, global-variable addresses, or native iterators. Keep IDC class authoring, external IDC function registration, low-condition callback setup, and third-party external-language installation/selection in separate lifecycle phases because they create or manipulate interpreter-global callback/descriptor state.
  - **19.78.6. Validation:** Require exact signatures/tags, scalar/copy/deep-copy/object/attribute/slice/reference/global/evaluate/compile/call/snippet/script/system-path malformed and success probes, exception-object preservation, database-close lifetime checks, complete C++/Node/generated-C/safe-Rust/Python parity, packages/manifests/privacy, exact staged review, and all 18 release jobs plus complete-log audits.
  - **19.78.7. Move-state invariant:** Moving a public `Value` leaves its source as a valid integer-zero value. Represent a null private implementation as immutable logical zero for observation/copy and materialize independent storage only for later mutation, preserving constant-time `noexcept` ownership transfer and language-boundary exception behavior.
