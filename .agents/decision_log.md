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
  - 6.4.1. **Decision:** Add structured operand introspection in `ida::instruction` (`Operand::byte_width`, `register_name`, `register_class`, vector/mask predicates, address-index helpers) and migrate lifter probe away from operand-text heuristics
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
  - 15.1.1. **Scope:** Full idax-first port of `/Users/int/dev/lifter` (AVX/VMX microcode transformations)
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
    - 15.1.3.9. Structured instruction operand metadata (`byte_width`/`register_name`/`register_class`)
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
  - 15.1.6. **Artifact:** `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_lifter.md`
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

---
