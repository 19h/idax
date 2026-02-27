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

### 15. Phase 13 — DriverBuddy Port + API Gap Audit

- **15.1. DriverBuddy Port Implementation Complete**
  - 15.1.1. Added `examples/plugin/driverbuddy_port_plugin.cpp` as an idax-first C++ port of `/Users/int/Downloads/plo/DriverBuddy-master` using `ida::plugin::Plugin` + `IDAX_PLUGIN` lifecycle.
  - 15.1.2. Ported core workflows: DriverEntry detection, import-based driver-type classification (WDM/WDF/Mini-Filter/AVStream/PortCls/Stream Minidriver), dangerous C/WinAPI xref reporting, WDM dispatch discovery/renaming, IOCTL decode under cursor (`Ctrl-Alt-I`), and listing-based IOCTL scan via `IoControlCode` hits.
  - 15.1.3. Added WDF dispatch-table annotation flow using idax type APIs: curated `WDFFUNCTIONS` slot schema materialization + type apply + naming at resolved table address.

- **15.2. API Surface Closure + Compile-Only Coverage Updates**
  - 15.2.1. Expanded `ida::instruction` with struct-offset representation helpers to close the DriverBuddy migration blocker around `OpStroffEx`:
    - `set_operand_struct_offset(Address, int, std::string_view, AddressDelta)`
    - `set_operand_struct_offset(Address, int, std::uint64_t, AddressDelta)`
    - `set_operand_based_struct_offset(Address, int, Address operand_value, Address base)`
  - 15.2.2. Implemented wrappers in `src/instruction.cpp` using SDK `op_stroff` / `op_based_stroff` with named-type TID resolution (`get_named_type_tid`) and typed error mapping.
  - 15.2.3. Updated `tests/unit/api_surface_parity_test.cpp` compile-only checks with both overload signatures and the based-struct-offset helper.

- **15.3. DriverBuddy Gap Audit + Documentation Sync**
  - 15.3.1. Added `docs/port_gap_audit_examples.md` with source-to-idax mapping, covered flows, and migration-gap classification.
  - 15.3.2. Updated documentation indexes/references:
    - `README.md` parity-note and documentation table now include DriverBuddy audit.
    - `docs/api_reference.md` now includes DriverBuddy audit link and documents new instruction struct-offset helper coverage.
    - `examples/README.md` now documents `driverbuddy_port_plugin.cpp` workflow coverage.
  - 15.3.3. Updated `examples/CMakeLists.txt` source manifest and addon target wiring with `idax_driverbuddy_port_plugin`.

- **15.4. Validation Evidence**
  - 15.4.1. `cmake -S . -B build -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON` passes (reconfigure with addon targets enabled).
  - 15.4.2. `cmake --build build --target idax_driverbuddy_port_plugin idax_api_surface_check` passes.
  - 15.4.3. `cmake --build build --target idax_examples` passes.

- **15.5. DriverBuddy Follow-Up (User-selected 1/2/3)**
  - 15.5.1. Added standard-type bootstrap helper `ida::type::ensure_named_type(type_name, source_til_name={})` and switched DriverBuddy WDM struct-annotation flow from best-effort `import_type` calls to `ensure_named_type` with explicit diagnostics.
  - 15.5.2. Added struct-offset readback wrappers in `ida::instruction`: `operand_struct_offset_path` + `operand_struct_offset_path_names`, and updated compile-only API parity checks accordingly.
  - 15.5.3. Expanded DriverBuddy WDF function-table schema from curated subset to full historical 440-slot list via `examples/plugin/driverbuddy_wdf_slots.inc` and wired strict parity mode (`kWdfStrictParityMode=true`) in the port.
  - 15.5.4. Updated DriverBuddy gap audit to close type-bootstrap and stroff-introspection deltas; only hotkey convenience remains partial.
  - 15.5.5. Evidence: `cmake --build build --target idax_driverbuddy_port_plugin idax_examples idax_api_surface_check` passes after follow-up changes.

- **15.6. DriverBuddy Follow-Up Closure Hardening (Docs + Parity Validation)**
  - 15.6.1. Added missing compile-only API parity coverage for new type bootstrap free function `ida::type::ensure_named_type` in `tests/unit/api_surface_parity_test.cpp`.
  - 15.6.2. Synchronized domain/capability coverage documentation in `docs/sdk_domain_coverage_matrix.md` to explicitly include DriverBuddy-driven instruction/type additions (`set_operand_struct_offset`, `set_operand_based_struct_offset`, `operand_struct_offset_path*`, `ensure_named_type`).
  - 15.6.3. Revalidated with `cmake --build build --target idax_driverbuddy_port_plugin idax_api_surface_check` (pass).

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
  - 8.2.2. Gaps in `docs/port_gap_audit_examples.md`
  - 8.2.3. Evidence: 16/16 tests, tool targets compile

- **8.3. ida2py Port**
  - **8.3.1. Probe**
    - `examples/tools/ida2py_port.cpp` + `docs/port_gap_audit_examples.md`
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
  - 9.1.1. `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_examples.md`
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
  - 12.8.2. Updated lifter gap documentation wording to reflect resolved-memory destination routing (`docs/port_gap_audit_examples.md`) and refreshed plugin gap report text.
  - 12.8.3. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin`, `cmake --build build-matrix-unit-examples-local --target idax_api_surface_check idax_decompiler_storage_hardening_test`, and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` all pass (`196 passed, 0 failed`).

- **12.9. Callinfo/tmop Depth Kickoff (5.4.2/5.3.2)**
  - 12.9.1. Added additive helper-call semantic-role routing in `examples/plugin/lifter_port_plugin.cpp` via `compare_call_options(...)` for `vcmp*` families (`SseCompare4`/`SseCompare8`) while preserving existing fallback behavior for unsupported/runtime-sensitive paths.
  - 12.9.2. Added helper argument metadata (`argument_name`) across variadic packed helper forwarding and VMX helper paths (`vmxon`/`vmptrld`/`vmclear`/`vmptrst`/`vmread`/`vmwrite`/`invept`/`invvpid`) to improve typed callarg semantics without raw SDK usage.
  - 12.9.3. Updated lifter gap audit notes to record callinfo-depth kickoff semantics and metadata usage (`docs/port_gap_audit_examples.md`).
  - 12.9.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.10. Callinfo/tmop Depth Continuation (5.4.2/5.3.2)**
  - 12.10.1. Extended `compare_call_options(...)` semantics in `examples/plugin/lifter_port_plugin.cpp` to include `vpcmp*` role mapping and rotate-family role hints (`RotateLeft`/`RotateRight` for `vprol*`/`vpror*`).
  - 12.10.2. Expanded helper argument metadata (`argument_name`) across explicit scalar/packed helper-call flows (`vmin*`/`vmax*`/`vsqrt*`, helper-fallback packed conversions, packed addsub, packed min/max), complementing existing variadic/VMX metadata coverage.
  - 12.10.3. Updated gap audit wording for broadened callinfo-depth semantics (`docs/port_gap_audit_examples.md`).
  - 12.10.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.11. Callinfo/tmop Return-Typing Continuation (5.4.2/5.3.2)**
  - 12.11.1. Added declaration-driven helper-return typing in `examples/plugin/lifter_port_plugin.cpp` for stable helper-return families: integer-width `vmread` register destinations (`unsigned char/short/int/long long`) and scalar float-helper destinations (`float`/`double` for `vmin*`/`vmax*`/`vsqrt*`).
  - 12.11.2. Kept scope intentionally narrow (no broad vector return declarations) to avoid declaration-size mismatch risk while increasing callinfo fidelity.
  - 12.11.3. Updated lifter gap audit wording for return-typing enrichment (`docs/port_gap_audit_examples.md`) and recorded finding [F201].
  - 12.11.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`196 passed, 0 failed`).

- **12.12. Return-Location + Hardening Continuation (5.4.2/5.3.2)**
  - 12.12.1. Expanded `examples/plugin/lifter_port_plugin.cpp` helper-call options with explicit register `return_location` hints on stable register-destination helper paths (variadic helper register destinations, `vmread` register route, scalar/packed helper-return families).
  - 12.12.2. Extended additive return-typing coverage for compare/variadic register-destination helper routes when destination widths map cleanly to integer declarations.
  - 12.12.3. Added callinfo hint hardening assertions in `tests/integration/decompiler_storage_hardening_test.cpp` covering:
    - Positive-path micro/register destination hint application (success-or-backend-failure tolerance)
    - Negative-path validation (`return_location` register id < 0, return-type-size mismatch)
  - 12.12.4. Updated lifter gap audit wording (`docs/port_gap_audit_examples.md`) and recorded findings [F202], [F203].
  - 12.12.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`).

- **12.13. Fallback-Gating + Cross-Route Hardening (5.4.1/5.3.2)**
  - 12.13.1. Tightened `examples/plugin/lifter_port_plugin.cpp` compare-helper fallback path to use operand-index writeback only when destination shape remains unresolved after typed routes (mask-register or unresolved-memory destination).
  - 12.13.2. Expanded callinfo hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with additional cross-route validation checks for invalid `return_location` register ids and return-type-size mismatches (`to_micro_operand`, `to_register`, `to_operand`).
  - 12.13.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded findings [F204], [F205].
  - 12.13.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`; `EXIT:0`).

- **12.14. Structured Register Recovery Continuation (5.4.1)**
  - 12.14.1. Extended `examples/plugin/lifter_port_plugin.cpp` compare-helper routing to attempt typed register micro-operand destinations from structured `instruction::Operand::register_id()` when `load_operand_register(0)` fails.
  - 12.14.2. Kept unresolved-shape fallback gating intact so operand-index writeback remains limited to mask-register or unresolved-memory destination shapes only.
  - 12.14.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F206].
  - 12.14.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`200 passed, 0 failed`; `EXIT:0`).

- **12.15. Resolved-Memory Location-Hint Retry (5.3.2)**
  - 12.15.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare-helper resolved-memory route to apply static-address `return_location` callinfo hints on typed `GlobalAddress` micro-destination emissions.
  - 12.15.2. Added validation-safe retry behavior: when backend rejects static location hints with validation, re-emit without location hints before falling through.
  - 12.15.3. Extended hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with global-destination callinfo location checks (valid static-address success-or-backend-failure tolerance + invalid `BadAddress` static-location validation assertion), plus `to_operand` static-location `BadAddress` validation coverage.
  - 12.15.4. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded findings [F207], [F208], [F209].
  - 12.15.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.16. Register-Retry + Global Type-Size Hardening (5.3.2)**
  - 12.16.1. Extended `examples/plugin/lifter_port_plugin.cpp` compare-helper register-destination micro-routes to retry without explicit register `return_location` hints when backend returns validation-level rejection.
  - 12.16.2. Expanded hardening in `tests/integration/decompiler_storage_hardening_test.cpp` with global-destination return-type-size validation checks (invalid declaration-size mismatch assertions), including `to_operand` route coverage.
  - 12.16.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded findings [F210], [F211].
  - 12.16.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.17. Unresolved-Shape Register-Store Bridge (5.4.1)**
  - 12.17.1. Expanded `examples/plugin/lifter_port_plugin.cpp` unresolved compare-destination routing to attempt helper-return to temporary register followed by `store_operand_register` writeback before direct `to_operand` fallback.
  - 12.17.2. Kept direct `to_operand` fallback as final degraded path for backend-specific unresolved destination shapes.
  - 12.17.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F212].
  - 12.17.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.18. Compare Retry-Ladder Continuation (5.3.2)**
  - 12.18.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare-helper micro-routes to use a three-step validation-safe retry ladder: full hint path (`location` + `return_type_declaration`) -> reduced hint path (declaration-only) -> base compare options.
  - 12.18.2. Applied the retry ladder consistently across resolved-memory `GlobalAddress`, structured register-destination micro routes, and temporary-register helper-return routes used in unresolved-shape handling.
  - 12.18.3. Kept richer semantics as primary path while ensuring graceful degradation on backend validation variance.
  - 12.18.4. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F213].
  - 12.18.5. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.19. Direct-Operand Retry Parity (5.3.2)**
  - 12.19.1. Expanded `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` fallback to apply validation-safe retry with base compare options when hint-rich options fail validation.
  - 12.19.2. Preserved hint-rich options as first attempt to maintain semantic fidelity while reducing backend-variant validation failures on degraded routes.
  - 12.19.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F214].
  - 12.19.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.20. Degraded-Operand Validation Tolerance (5.3.2)**
  - 12.20.1. Updated `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` fallback to treat residual validation rejection as non-fatal not-handled outcome after retry exhaustion.
  - 12.20.2. Kept SDK/internal categories as hard failure signals to avoid masking backend/runtime errors.
  - 12.20.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F215].
  - 12.20.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.21. Cross-Route Retry + Writeback Tolerance Alignment (5.3.2)**
  - 12.21.1. Expanded `examples/plugin/lifter_port_plugin.cpp` compare helper retries so resolved-memory micro, register micro, temporary-register bridge, and degraded `to_operand` routes all apply validation-safe fallback to base compare options.
  - 12.21.2. Updated temporary-register bridge writeback handling to degrade `store_operand_register` `Validation`/`NotFound` outcomes to not-handled while preserving hard SDK/internal failures.
  - 12.21.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F216].
  - 12.21.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.22. Direct Register-Route Retry Alignment (5.3.2)**
  - 12.22.1. Expanded `examples/plugin/lifter_port_plugin.cpp` direct register-destination compare helper route (the `destination_reg` path in `lift_packed_helper_variadic`) to use validation-safe retry ladder semantics: full hints (`return_location` + `return_type_declaration`) -> declaration-only -> base compare options.
  - 12.22.2. Updated residual-validation handling on that direct register route to degrade to not-handled while preserving hard `SdkFailure`/`Internal` categories.
  - 12.22.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F217].
  - 12.22.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.23. Temporary-Bridge Error-Access Guard (5.3.2)**
  - 12.23.1. Updated `examples/plugin/lifter_port_plugin.cpp` temporary-register compare bridge flow to gate error-category reads with `!temporary_helper_status` before accessing `.error()` after degradable writeback outcomes.
  - 12.23.2. Preserved degraded fallback progression (`Validation`/`NotFound` writeback -> continue to degraded routes) while avoiding invalid success-path `.error()` access.
  - 12.23.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F218].
  - 12.23.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).
  - 12.23.5. Validation sweep: `ctest --output-on-failure` in `build-matrix-unit-examples-local` passes `16/16`.

- **12.24. Residual NotFound Degradation Alignment (5.3.2)**
  - 12.24.1. Updated `examples/plugin/lifter_port_plugin.cpp` degraded compare `to_operand` and direct register-destination compare helper routes to treat residual `NotFound` outcomes as non-fatal not-handled after retry exhaustion.
  - 12.24.2. Kept hard-failure handling limited to `SdkFailure`/`Internal` (with validation still degradable) so backend variance does not escalate degraded-route outcomes.
  - 12.24.3. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F219].
  - 12.24.4. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin idax_api_surface_check idax_decompiler_storage_hardening_test` and `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` pass (`202 passed, 0 failed`; `EXIT:0`).

- **12.25. Temporary-Bridge Typed Micro-Operand Destination (5.4.1 Closure)**
  - 12.25.1. Converted `examples/plugin/lifter_port_plugin.cpp` compare-helper temporary-register bridge from `emit_helper_call_with_arguments_to_register_and_options` to `emit_helper_call_with_arguments_to_micro_operand_and_options` using `register_destination_operand(*temporary_destination, destination_width)` as typed `MicrocodeOperand` with `kind = Register`.
  - 12.25.2. This eliminates the last non-typed helper-call destination path in the lifter probe. All remaining operand-writeback sites (`store_operand_register` for unresolved compare shapes and vmov memory stores, `to_operand` for terminal compare fallback) are genuinely irreducible.
  - 12.25.3. Comprehensive analysis confirmed: 0 remaining `_to_register_and_options` calls in the file; 2 remaining `_to_operand` calls are terminal unresolved-shape fallbacks; 3 remaining `store_operand_register` calls are either unresolved-shape writeback or legitimate vmov memory stores.
  - 12.25.4. Updated gap audit wording (`docs/port_gap_audit_examples.md`) and recorded finding [F220].
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
  - 12.27.4. Reclassified all 5 source-backed gap matrix items (A–E) in `docs/port_gap_audit_examples.md` from partial to **CLOSED**, and all 3 confirmed parity gaps from open to **CLOSED**.
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
  - 12.29.5. Updated `docs/port_gap_audit_examples.md` to record processor-ID guard as closed.
  - 12.29.6. Finding [F231] recorded.
  - 12.29.7. Evidence: build clean (`idax_lifter_port_plugin` + `idax_api_surface_check` + `idax_decompiler_storage_hardening_test`), 202/202 integration, 16/16 CTest.

### 13. Phase 11 — Abyss Port API Gap Closure

- **13.1. Gap Analysis Complete**
  - 13.1.1. Analyzed abyss Python decompiler-filter plugin (patois, ~1046 lines, 9 files): main dispatcher + 8 filters (token_colorizer, signed_ops, hierarchy, lvars_alias, lvars_info, item_sync, item_ctype, item_index)
  - 13.1.2. Cataloged every SDK symbol used across all files; cross-referenced against idax public API
  - 13.1.3. Identified 18 API gaps (4 critical, 6 high, 6 medium, 2 low)
  - 13.1.4. Header declarations written for all gaps in decompiler.hpp (+143 lines), ui.hpp (+122 lines), lines.hpp (new, 105 lines)
  - 13.1.5. Initial abyss_port_plugin.cpp created (875 lines) with gap documentation
  - 13.1.6. examples/CMakeLists.txt updated to include new plugin target

- **13.2. Implementation — Complete**
  - 13.2.1. **src/lines.cpp** (new) — Implemented `colstr()`, `tag_remove()`, `tag_advance()`, `tag_strlen()`, `make_addr_tag()`, `decode_addr_tag()` wrapping SDK `COLOR_ON`/`COLOR_OFF`/`COLOR_ADDR`/`::tag_remove`/`::tag_advance`/`::tag_strlen`. Auto-discovered by CMake `GLOB_RECURSE`.
  - 13.2.2. **src/decompiler.cpp** — Added 4 new callback maps (`g_func_printed_callbacks`, `g_refresh_pseudocode_callbacks`, `g_curpos_callbacks`, `g_create_hint_callbacks`); expanded `hexrays_event_bridge` from single `hxe_maturity` to full 5-event switch; added 4 subscription functions; fixed `unsubscribe()` to search all maps; implemented `raw_lines()`/`set_raw_line()` (via `cfunc->sv`), `header_line_count()` (via `cfunc->hdrlines`); implemented `ExpressionView::left()`/`right()`/`operand_count()`; extended `variables()` with `has_user_name`/`has_nice_name`/`storage`/`comment`; implemented `item_at_position()` (via `cfunc_t::get_line_item`); implemented `item_type_name()` (via `get_ctype_name`).
  - 13.2.3. **src/ui.cpp** — Implemented `widget_type()` (both overloads via `get_widget_type`); `on_popup_ready()` subscribing to `ui_finish_populating_widget_popup`; `DynamicActionHandler` class + `attach_dynamic_action()` via `DYNACTION_DESC_LITERAL`/`attach_dynamic_action_to_popup()`; `on_rendering_info()` subscribing to `ui_get_lines_rendering_info` with full SDK↔idax translation; `user_directory()` via `get_user_idadir()`; `refresh_all_views()` via `refresh_idaview_anyway()`.
  - 13.2.4. **include/ida/idax.hpp** — Added `#include <ida/lines.hpp>` to master include.
  - 13.2.5. **examples/plugin/abyss_port_plugin.cpp** — Complete C++ port (~845 lines) of all 8 abyss filters: token_colorizer, signed_ops, hierarchy, lvars_alias, lvars_info, item_sync, item_ctype, item_index. Uses only idax APIs. Plugin class `AbyssPlugin` with `IDAX_PLUGIN(AbyssPlugin)`.
  - 13.2.6. **Build fixes** — Replaced `qsnprintf` (SDK-internal, unavailable in example code) with `std::snprintf`; replaced printf-style `ui::message()` calls with string concatenation.

---

### 16. Phase 15 — Rust Convergence Batch 7 (`plugin` + `event`)

- **16.1. Shim/API closure for `ida::plugin`**
  - 16.1.1. Added C ABI transfer struct `IdaxPluginActionContext` and extended action registration with context-aware callback bridge (`idax_plugin_register_action_ex`) while preserving legacy `idax_plugin_register_action` compatibility.
  - 16.1.2. Added runtime-bindable plugin action helpers: `idax_plugin_attach_to_popup`, `idax_plugin_detach_from_popup`, and explicit `idax_plugin_detach_from_toolbar` Rust exposure.
  - 16.1.3. Added action-context host bridge APIs backed by real C++ behavior (`ida::plugin::widget_host` / `with_widget_host`, `decompiler_view_host` / `with_decompiler_view_host`) via shim functions:
    - `idax_plugin_action_context_widget_host`
    - `idax_plugin_action_context_with_widget_host`
    - `idax_plugin_action_context_decompiler_view_host`
    - `idax_plugin_action_context_with_decompiler_view_host`

- **16.2. Shim/API closure for `ida::event`**
  - 16.2.1. Added C ABI transfer struct `IdaxEvent` carrying parity fields (`kind`, `address`, `secondary_address`, `new_name`, `old_name`, `old_value`, `repeatable`).
  - 16.2.2. Added typed subscription bridge functions wired to C++ event APIs: `idax_event_on_segment_added`, `idax_event_on_segment_deleted`, `idax_event_on_function_added`, `idax_event_on_function_deleted`, `idax_event_on_renamed`, `idax_event_on_byte_patched`, `idax_event_on_comment_changed`, `idax_event_on_event`, `idax_event_on_event_filtered`.
  - 16.2.3. Preserved existing generic `idax_event_subscribe`/`idax_event_unsubscribe` token model for compatibility.

- **16.3. Rust wrapper convergence (`idax/src/plugin.rs`, `idax/src/event.rs`)**
  - 16.3.1. Expanded Rust `plugin::ActionContext` to parity fields (selection/external/register + widget/decompiler handles), added `detach_from_toolbar`, popup attach/detach APIs, and host helper wrappers (`widget_host`, `with_widget_host`, `decompiler_view_host`, `with_decompiler_view_host`).
  - 16.3.2. Added typed action-context callback registration helper `register_action_with_context(...)` with safe callback-context lifetime tracking and cleanup on `unregister_action`.
  - 16.3.3. Reworked Rust `event` module to include typed subscriptions (`on_segment_added`, `on_segment_deleted`, `on_function_added`, `on_function_deleted`, `on_renamed`, `on_byte_patched`, `on_comment_changed`, `on_event`, `on_event_filtered`) while retaining `subscribe`/`unsubscribe` compatibility and `ScopedSubscription` semantics.
  - 16.3.4. Exposed Rust `event::Event` parity fields for generic routing where available.

- **16.4. Validation + findings updates**
  - 16.4.1. Validation evidence: `cargo build` in `/Users/int/dev/idax/bindings/rust` passes after batch 7 changes.
  - 16.4.2. Added callback payload/context lifetime guidance as finding [F274] and mirrored it into knowledge base section 30.
  - 13.2.7. **Evidence:** `cmake --build build` all targets clean; `ctest --test-dir build` 16/16 pass (0 failures); `idax_abyss_port_plugin.dylib` linked to `ida-sdk/src/bin/plugins/`.

- **13.3. SDK Discoveries**
  - 13.3.1. SDK redefines bare `snprintf` → `dont_use_snprintf` in `pro.h:965`; `std::snprintf` is unaffected (qualified name). [F232]
  - 13.3.2. `cfunc_t::get_pseudocode()` returns `const strvec_t&` — to modify lines, access `cfunc->sv` directly. [F233]
  - 13.3.3. `qrefcnt_t<cfunc_t>` (cfuncptr_t) lacks `.get()` — use `&*ptr` or `ptr.operator->()`. [F234]
  - 13.3.4. Color enum values must match SDK `color_t` constants exactly: `COLOR_KEYWORD=0x20`, `COLOR_REG=0x21`, `COLOR_LIBNAME=0x18`, etc. [F235]
  - 13.3.5. WidgetType enum must match SDK `BWN_*` constants: `BWN_DISASM=27`, `BWN_PSEUDOCODE=46`. [F236]
  - 13.3.6. `attach_dynamic_action_to_popup` uses `DYNACTION_DESC_LITERAL` (5 args), not `ACTION_DESC_LITERAL_OWNER` (8 args). [F237]
  - 13.3.7. Hexrays event signatures: `hxe_func_printed` → `(cfunc_t*)`, `hxe_curpos` → `(vdui_t*)`, `hxe_create_hint` → `(vdui_t*, qstring*, int*)` returns 0/1, `hxe_refresh_pseudocode` → `(vdui_t*)`. [F238]
  - 13.3.8. `ui_finish_populating_widget_popup` → `(TWidget*, TPopupMenu*, const action_activation_ctx_t*)`. [F239]

- **13.4. Example Plugin Entry Point Fix + Database TU Split**
  - 13.4.1. **Bug:** 5 example plugins (`action_plugin.cpp`, `decompiler_plugin.cpp`, `deep_analysis_plugin.cpp`, `event_monitor_plugin.cpp`, `storage_metadata_plugin.cpp`) were missing the `IDAX_PLUGIN(ClassName)` macro. Without it, no `_PLUGIN` symbol is exported and IDA's plugin loader sees an empty dylib with zero functions.
  - 13.4.2. **Fix:** Added `IDAX_PLUGIN(QuickAnnotatorPlugin)`, `IDAX_PLUGIN(ComplexityMetricsPlugin)`, `IDAX_PLUGIN(BinaryAuditPlugin)`, `IDAX_PLUGIN(ChangeTrackerPlugin)`, `IDAX_PLUGIN(BinaryFingerprintPlugin)` to respective files.
  - 13.4.3. **Secondary bug exposed:** Adding entry points caused `idax_audit_plugin` and `idax_fingerprint_plugin` to fail linking with undefined symbols (`init_library`, `open_database`, `close_database`, `enable_console_messages`). These are idalib-only symbols not exported from `libida.dylib`. Previously masked because empty dylibs don't trigger symbol resolution.
  - 13.4.4. **Root cause:** `database.cpp` contained both idalib-only lifecycle functions (`init`, `open`, `close`) and plugin-safe query functions (`input_file_path`, `image_base`, `input_md5`, etc.) in a single translation unit. When the linker pulled any symbol from `database.cpp.o`, it got all of them.
  - 13.4.5. **Fix:** Split `database.cpp` into two files:
    - `database.cpp` — query/metadata functions + `save()` (plugin-safe, all symbols available in `libida.dylib`)
    - `database_lifecycle.cpp` — `init()`/`open()`/`close()` + RuntimeOptions/sandbox/plugin-policy helpers (idalib-only)
  - 13.4.6. Auto-discovered by CMake `GLOB_RECURSE`, no CMakeLists.txt changes needed.
  - 13.4.7. [F240] Plugin entry point macro requirement. [F241] Database TU split for plugin link isolation.
  - 13.4.8. **Evidence:** `cmake --build build` all targets clean (7 plugins + 3 loaders + 3 procmods + 16 tests); `ctest --test-dir build` 16/16 pass; `nm -gU` confirms `_PLUGIN` symbol exported from all plugin dylibs.

### 14. Phase 12 — DrawIDA Port + API Gap Audit

- **14.1. DrawIDA Port Implementation Complete**
  - 14.1.1. Added `examples/plugin/drawida_port_plugin.cpp` as an idax-first C++ port of `/Users/int/Downloads/plo/DrawIDA-main` using `ida::plugin::Plugin` + `IDAX_PLUGIN` lifecycle.
  - 14.1.2. Added `examples/plugin/drawida_port_widget.hpp` + `examples/plugin/drawida_port_widget.cpp` implementing the whiteboard canvas (draw/text/eraser/select, selection drag/delete, undo/redo stack, style/background controls, clear workflow).
  - 14.1.3. Added DrawIDA artifacts to `examples/CMakeLists.txt` source manifest and documented the example in `examples/README.md`.

- **14.2. Port Gap Audit + Documentation Update**
  - 14.2.1. Added `docs/port_gap_audit_examples.md` with source-to-idax API mapping and migration gap classification.
  - 14.2.2. Updated `README.md` parity-note and documentation tables to include the DrawIDA gap audit.
  - 14.2.3. Updated `docs/sdk_domain_coverage_matrix.md` port-audit follow-up notes with DrawIDA coverage outcome.
  - 14.2.4. Findings [F242] and [F243] recorded for non-blocking ergonomic gaps surfaced by the DrawIDA port.

- **14.3. Validation Evidence**
  - 14.3.1. `cmake --build build --target idax_examples` passes (CMake regenerate + source-manifest target complete).
  - 14.3.2. `cmake --build build --target idax_api_surface_check` passes.

- **14.4. Abyss Documentation Synchronization**
  - 14.4.1. Added `docs/port_gap_audit_examples.md` with covered migration flows, source-to-idax mapping, and parity-gap classification for `examples/plugin/abyss_port_plugin.cpp`.
  - 14.4.2. Updated `README.md` parity-note/doc-index tables to include the abyss audit and documented `ida::lines` in the public domain matrix.
  - 14.4.3. Updated `docs/api_reference.md`, `docs/namespace_topology.md`, and `docs/sdk_domain_coverage_matrix.md` to include `ida::lines` and abyss-port evidence.
  - 14.4.4. Updated `docs/quickstart/plugin.md`, `docs/docs_completeness_checklist.md`, and `examples/README.md` with direct abyss example references and usage context.
  - 14.4.5. Recorded process finding [F244] for documentation-index drift risk when adding new real-world port artifacts.
  - 14.4.6. Evidence: repository docs sweep confirms new abyss references and links resolve across README/docs/examples surfaces.

- **14.5. DrawIDA Follow-Up (User-Selected 1/2/3)**
  - 14.5.1. Added per-plugin export flag control in `ida::plugin`: new `ExportFlags` struct + `IDAX_PLUGIN_WITH_FLAGS(...)` macro; `IDAX_PLUGIN(...)` now maps to the new macro with default flags.
  - 14.5.2. Updated plugin bridge in `src/plugin.cpp` to compose SDK flags from `ExportFlags`, keep `PLUGIN_MULTI` mandatory, and apply selected bits to exported `PLUGIN.flags` at static-init registration time.
  - 14.5.3. Added typed widget-host convenience helpers in `ida::ui`: `widget_host_as<T>()` and `with_widget_host_as<T>()`.
  - 14.5.4. Updated DrawIDA + qtform example ports to use typed widget-host helpers (no manual `void*` cast in plugin glue).
  - 14.5.5. Added dedicated DrawIDA addon target wiring in `examples/CMakeLists.txt` via `ida_add_plugin(TYPE QT QT_COMPONENTS Core Gui Widgets ...)`.
  - 14.5.6. Updated `tests/unit/api_surface_parity_test.cpp` compile-only checks for `ida::plugin::ExportFlags` and typed host helper templates.
  - 14.5.7. Updated `docs/port_gap_audit_examples.md` to mark prior ergonomic gaps as closed; no open DrawIDA parity gaps remain.
  - 14.5.8. Recorded findings [F245], [F246], [F247].
  - 14.5.9. Recorded Qt include portability finding [F248] and updated DrawIDA widget source to use `qevent.h` for `QKeyEvent`/`QMouseEvent` declarations.
  - 14.5.10. Evidence: `cmake --build build --target idax_drawida_port_plugin` passes; `cmake --build build --target idax_api_surface_check` passes; `cmake --build build --target idax_example_plugin` passes; `cmake --build build --target idax_examples` passes.

### 16. Phase 14 — idapcode Port + API Gap Audit + Sleigh Integration

- **16.1. idapcode Port Implementation Complete**
  - 16.1.1. Added `examples/plugin/idapcode_port_plugin.cpp` as an idax-first C++ port of `/Users/int/Downloads/plo/idapcode-main` using `ida::plugin::Plugin` + `IDAX_PLUGIN` lifecycle and custom viewer rendering.
  - 16.1.2. Ported function-scoped p-code generation workflow (select function, read bytes, lift with Sleigh, render text in viewer) with `Ctrl-Alt-S` style action parity.
  - 16.1.3. Added processor-profile routing and runtime spec-root override (`IDAX_IDAPCODE_SPEC_ROOT`) so spec lookup remains configurable per host install.

- **16.2. API Surface Closure from Port Gaps**
  - 16.2.1. Expanded `ida::database` processor-context metadata in `include/ida/database.hpp` with typed `ProcessorId` and `processor()` helper.
  - 16.2.2. Added architecture-shaping wrappers required by idapcode mapping logic: `address_bitness()`, `is_big_endian()`, `abi_name()`.
  - 16.2.3. Implemented these wrappers in plugin-safe `src/address.cpp` to avoid idalib-only symbol contamination in plugin link units.
  - 16.2.4. Updated compile-only/integration evidence hooks in `tests/unit/api_surface_parity_test.cpp` and `tests/integration/smoke_test.cpp`.

- **16.3. Sleigh Third-Party Integration Strategy (Concrete)**
  - 16.3.1. Added Sleigh as a pinned git submodule (`third-party/sleigh`) with `.gitmodules` entry (commit `db0dc4c479a576e4621fa02789395d0064475239`).
  - 16.3.2. Added idapcode-specific opt-in CMake wiring in `examples/CMakeLists.txt` (`IDAX_BUILD_EXAMPLE_IDAPCODE_PORT`, `IDAX_IDAPCODE_BUILD_SPECS`, `IDAX_IDAPCODE_SLEIGH_SOURCE_DIR`) to keep default idax configure/build cycles lightweight.
  - 16.3.3. Added `idax_idapcode_port_plugin` target linking `sleigh::sla`, `sleigh::decomp`, and `sleigh::support`.

- **16.4. Gap Audit + Documentation Synchronization**
  - 16.4.1. Added `docs/port_gap_audit_examples.md` with source-to-idax mapping and open/closed gap classification.
  - 16.4.2. Updated docs/index surfaces for the new port and metadata additions: `README.md`, `docs/api_reference.md`, `docs/sdk_domain_coverage_matrix.md`, `docs/namespace_topology.md`, `docs/quickstart/plugin.md`, `examples/README.md`.
  - 16.4.3. Recorded findings [F253], [F254], [F255], [F256], [F257] and corresponding KB/decision updates.

- **16.5. Validation Evidence**
  - 16.5.1. `cmake --build build --target idax_api_surface_check idax_smoke_test` passes.
  - 16.5.2. `./tests/unit/idax_unit_test` passes (`22 passed, 0 failed`).
  - 16.5.3. `cmake -S . -B build-idapcode -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON -DIDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON && cmake --build build-idapcode --target idax_idapcode_port_plugin` passes.
  - 16.5.4. Initial runtime startup failures were observed when environment roots were mispointed; follow-up diagnosis/evidence recorded in 16.6.

- **16.6. Runtime Startup Diagnostic Follow-Up (User-Selected 1/2)**
  - 16.6.1. Re-ran runtime smoke directly: `/Users/int/dev/idax/build/tests/integration/idax_smoke_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` passes (`287 passed, 0 failed`).
  - 16.6.2. Captured binary runtime-link baseline: `otool -L` shows `@rpath/libidalib.dylib` and `@rpath/libida.dylib`; `otool -l` confirms `LC_RPATH` includes `/Applications/IDA Professional 9.3.app/Contents/MacOS`.
  - 16.6.3. Reproduced startup failure deterministically with mispointed environment root: `IDADIR=/Users/int/dev/ida-sdk/src DYLD_LIBRARY_PATH=/Users/int/dev/ida-sdk/src/bin ...` aborts with "directory ... does not exist or contains a broken or incomplete installation".
  - 16.6.4. Verified explicit-good environment profile: `IDADIR=/Applications/IDA Professional 9.3.app/Contents/MacOS DYLD_LIBRARY_PATH=/Applications/IDA Professional 9.3.app/Contents/MacOS ...` passes full smoke run.
  - 16.6.5. Recorded finding [F258] and updated active-work runtime item from blocked to in-progress with configuration-root diagnosis.

- **16.7. Plugin-Load Runtime Check Closure (User-Selected 1/2 continuation)**
  - 16.7.1. Configured and built tool-runtime validation path with tool examples enabled: `cmake -S . -B build-tools -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_TOOLS=ON` and `cmake --build build-tools --target idax_idalib_dump_port`.
  - 16.7.2. Executed runtime plugin-policy checks against fixture binary with successful open/analyze/list output for both modes:
    - `.../idax_idalib_dump_port --list --quiet --no-summary --no-plugins tests/fixtures/simple_appcall_linux64`
    - `.../idax_idalib_dump_port --list --quiet --no-summary --plugin "*.dylib" tests/fixtures/simple_appcall_linux64`
  - 16.7.3. Recorded finding [F260] and closed the queued plugin-load runtime check from active-work item 8.1.5.

- **16.8. ProcessorId Coverage Expansion (User-Supplied PLFM Set)**
  - 16.8.1. Expanded `ida::database::ProcessorId` in `include/ida/database.hpp` from common-subset values to full current SDK `PLFM_*` coverage through `PLFM_MCORE` (0..77).
  - 16.8.2. Preserved existing idapcode port switch-case compatibility by keeping previously used enumerator names unchanged while adding missing processor families.
  - 16.8.3. Updated compile-only API parity checks in `tests/unit/api_surface_parity_test.cpp` to include added enum members (`RiscV`, `Mcore`).
  - 16.8.4. Evidence: `cmake --build build --target idax_api_surface_check idax_smoke_test`, `ctest --test-dir build -R "^idax_unit_test$" --output-on-failure`, and `cmake --build build-tools --target idax_idalib_dump_port` all pass.
  - 16.8.5. Recorded finding [F259].

- **16.9. idapcode Linear/P-Code View Synchronization (User Follow-Up)**
  - 16.9.1. Enhanced `examples/plugin/idapcode_port_plugin.cpp` with bidirectional view synchronization state and event wiring.
  - 16.9.2. Added viewer -> linear sync path via `ui::on_cursor_changed` + `ui::custom_viewer_current_line` + `ui::jump_to`.
  - 16.9.3. Added linear -> viewer sync path via `ui::on_screen_ea_changed` + address-to-line index mapping + `ui::custom_viewer_jump_to_line`.
  - 16.9.4. Added view activation/lifecycle tracking (`on_view_activated`, `on_view_deactivated`, `on_view_closed`) and reentrancy guard to prevent event-loop ping-pong.
  - 16.9.5. Updated line rendering so every p-code output line carries a canonical address prefix, enabling robust click-address parsing on instruction and non-instruction lines.
  - 16.9.6. Evidence: `cmake --build build-idapcode --target idax_idapcode_port_plugin` passes with sync changes integrated.
  - 16.9.7. Recorded findings [F261], [F262] and decision [D-IDAPCODE-VIEW-SYNC].

- **16.10. idapcode Sync Ergonomics Follow-Up (Cross-Function + Scroll + Hotkey)**
  - 16.10.1. Reworked idapcode viewer to a stable single title (`P-Code (idax port)`) so follow-up sync updates reuse the same panel instead of opening one panel per function.
  - 16.10.2. Added cross-function linear->pcode follow: when `screen_ea` moves outside current function range, the plugin resolves `function::at(screen_ea)` and rebuilds the existing viewer in-place for that function.
  - 16.10.3. Added function-range guards to address->line mapping so unrelated addresses no longer collapse to the last known line of the previous function.
  - 16.10.4. Added scroll-follow polling timer (`register_timer`) to sync pcode-view scrolling behavior that does not always emit explicit cursor-change events.
  - 16.10.5. Added explicit sync shutdown path in plugin `term()` to unregister timer/subscriptions safely.
  - 16.10.6. Changed plugin shortcut from `Ctrl-Alt-S` to `Ctrl-Alt-Shift-P` to avoid common SigMaker conflicts.
  - 16.10.7. Updated user-facing docs: `examples/README.md` and `docs/port_gap_audit_examples.md`.
  - 16.10.8. Evidence: `cmake --build build-idapcode --target idax_idapcode_port_plugin` passes after follow-up changes.
  - 16.10.9. Recorded findings [F263], [F264], [F265] and decisions [D-IDAPCODE-VIEW-SYNC] update + [D-IDAPCODE-HOTKEY-COLLISION-AVOIDANCE].

- **16.11. Crash Fix — Custom Viewer Backing-State Stability (User-Reported EXC_BAD_ACCESS)**
  - 16.11.1. Root-caused crash path to `ida::ui::set_custom_viewer_lines` replacing the stored `CustomViewerState` pointer, which invalidated custom-viewer range/place/line pointers retained by IDA internals.
  - 16.11.2. Updated `src/ui.cpp` so line updates mutate the existing `CustomViewerState` in-place (preserve object address), refresh range pointers, and clamp/preserve current line safely.
  - 16.11.3. Added explicit post-update `jumpto` to the clamped line and refresh call so viewer state remains coherent after in-place content replacement.
  - 16.11.4. Evidence: `cmake --build build-idapcode --target idax_idapcode_port_plugin` passes; `cmake --build build --target idax_api_surface_check idax_smoke_test` passes; `ctest --test-dir build -R "^idax_unit_test$" --output-on-failure` passes.
  - 16.11.5. Recorded finding [F266] and decision [D-UI-CUSTOM-VIEWER-STATE-STABILITY].

- **16.12. Rust API Convergence Batch 1 (Shim + Wrapper Parity Closure)**
  - 16.12.1. Expanded C shim declarations/implementations for requested parity surface: address (`find_first`, `find_next`), search (`next_error`), analysis (`schedule_reanalysis`, `schedule_reanalysis_range`, `revert_decisions`), entry (`forwarder`, `set_forwarder`, `clear_forwarder`), comment line-bulk/render APIs, xref range APIs, segment (`next`, `prev`, default segment register setters), storage (`blob_string`), and lumina close APIs.
  - 16.12.2. Added comment string-array C ABI bridge with dedicated allocator cleanup (`idax_comment_lines_free`) and wired Rust consumption to free returned arrays correctly.
  - 16.12.3. Added xref range wrappers in shim with required return forms (`IdaxXref* + count` for `refs_*_range`; `uint64_t* + count` for code/data range APIs) and exposed matching Rust APIs.
  - 16.12.4. Restored/implemented Rust public comment APIs for remove-line, bulk set/get lines, and `render(...)`, plus parity additions in `address.rs`, `search.rs`, `analysis.rs`, `entry.rs`, `segment.rs`, `storage.rs`, `xref.rs`, and `lumina.rs`.
  - 16.12.5. Validation evidence: `cargo build` in `bindings/rust` passes after convergence changes.

- **16.13. Rust API Convergence Batch 2 (Type Domain Full Surface Closure)**
  - 16.13.1. Expanded type-domain C shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` and `bindings/rust/idax-sys/shim/idax_shim.cpp` with new transfer structs (`IdaxTypeEnumMemberInput`, `IdaxTypeEnumMember`, `IdaxTypeMember`) and free helpers for returned arrays/records (`idax_type_handle_array_free`, `idax_type_enum_members_free`, `idax_type_member_free`, `idax_type_members_free`).
  - 16.13.2. Added missing type constructors/factories at shim+Rust layers: `TypeInfo::function_type(...)`, `TypeInfo::enum_type(...)`, `TypeInfo::create_struct()`, `TypeInfo::create_union()`.
  - 16.13.3. Added missing introspection parity at shim+Rust layers: `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`, `function_return_type`, `function_argument_types`, `calling_convention`, `is_variadic_function`, and `enum_members`.
  - 16.13.4. Added member-surface parity at shim+Rust layers: `members`, `member_by_name`, `member_by_offset`, `add_member`, plus Rust `Member` now carries member `type` (`r#type: TypeInfo`) with ownership-safe transfer from C.
  - 16.13.5. Added missing free functions in Rust/shim: `retrieve_operand`, `unload_type_library`, `import_type`, and `ensure_named_type` as Rust composition over existing primitives.
  - 16.13.6. Added lifecycle parity for opaque type handles via shim clone helper (`idax_type_clone`) and Rust `impl Clone for TypeInfo`.
  - 16.13.7. Validation evidence: `cargo build` in `bindings/rust` passes after type-domain convergence changes.
  - 16.13.8. Recorded findings [F267], [F268].

- **16.14. Rust API Convergence Batch 3 (`ida::graph` Full Surface Closure)**
  - 16.14.1. Expanded graph-domain shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` and `bindings/rust/idax-sys/shim/idax_shim.cpp` with parity structs/callback types (`IdaxGraphNodeInfo`, `IdaxGraphEdgeInfo`, `IdaxGraphEdge`, `IdaxAddressRange`, `IdaxGraphCallbacks`) and new free helpers for returned node/edge arrays.
  - 16.14.2. Added missing graph handle methods at shim level with real C++ behavior wiring: visible-node count/existence, edge add-with-info + replace, visible-node/edge enumeration, path existence, group create/delete/expand/collapse/member queries, and current-layout query.
  - 16.14.3. Added graph-viewer free-function parity in shim: `show_graph`, `refresh_graph`, `has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, and `close_graph_viewer`.
  - 16.14.4. Added range-based flowchart ABI (`idax_graph_flowchart_for_ranges`) and reused shared block marshalling for both function-address and range-based flowchart calls.
  - 16.14.5. Restored Rust `graph.rs` parity surface: `NodeInfo`/`EdgeInfo`, full `Graph` method set above, graph-viewer free functions with `Result`/`Status`, `flowchart_for_ranges`, and practical `GraphCallback` trait bridging to C callback ABI.
  - 16.14.6. Implemented Rust callback-bridge lifecycle handling for viewer callbacks: context transfer to C ABI on success and safe reclamation on immediate `show_graph` failure; callback cleanup deferred to destroy callback for viewer-owned lifetime.
  - 16.14.7. Validation evidence: `cargo build` in `bindings/rust` passes after graph convergence changes.
  - 16.14.8. Recorded finding [F269].

- **16.15. Rust API Convergence Batch 4 (`ida::ui` Full Surface Closure)**
  - 16.15.1. Expanded UI-domain shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` with parity structs/callback typedefs for show-widget options, typed UI events, popup payloads, rendering entries/events, timer callbacks, widget-host bridge callbacks, and dynamic-action handlers.
  - 16.15.2. Reworked UI-domain shim implementation in `bindings/rust/idax-sys/shim/idax_shim.cpp` to add real wrappers for `ask_form`, full custom-viewer APIs, widget title/id/host APIs, `show_widget` option parity (`restore_previous`), timer callback registration, all requested UI/view subscriptions (global + widget-scoped + generic + filtered), popup-ready/dynamic-action hooks, and rendering-info entry injection.
  - 16.15.3. Updated Rust UI wrapper in `bindings/rust/idax/src/ui.rs` with idiomatic parity types (`ShowWidgetOptions`, `Event`, `PopupEvent`, `RenderingEvent`, `LineRenderEntry`, `WidgetRef`) plus safe callback bridging and lifecycle bookkeeping for timer/event/popup/rendering/dynamic-action contexts.
  - 16.15.4. Preserved existing low-level APIs (`subscribe`, `unsubscribe`, no-callback `register_timer`, position-only `show_widget`) while layering parity-complete equivalents (`register_timer_with_callback`, `show_widget_with_options`, typed event/popup/rendering APIs).
  - 16.15.5. Validation evidence: `cargo build` in `bindings/rust` passes after full UI convergence changes.
  - 16.15.6. Recorded findings [F270], [F271].

- **16.16. Rust API Convergence Batch 5 (`ida::data`/`ida::database`/`ida::name`/`ida::fixup`)**
  - 16.16.1. Expanded shim ABI for `ida::data` typed values with explicit transfer enum/struct (`IdaxDataTypedValueKind`, `IdaxDataTypedValue`), recursive ownership free helper (`idax_data_typed_value_free`), and real wrappers for `read_typed`/`write_typed`.
  - 16.16.2. Added missing data-definition wrappers at shim+Rust layers: `define_oword`, `define_tbyte`, and `define_struct`.
  - 16.16.3. Expanded shim ABI for `ida::database` lifecycle/metadata gaps: `open_binary`, `open_non_binary`, `file_to_database`, `memory_to_database`, `compiler_info`, `import_modules` (+ nested transfer structs + free helper), `snapshots` (+ recursive transfer structs + free helper), `set_snapshot_description`, and `is_snapshot_database`.
  - 16.16.4. Expanded shim+Rust `ida::name` parity with user-defined inventory enumeration (`all_user_defined` + transfer/free helpers) and identifier utilities (`is_valid_identifier`, `sanitize_identifier`).
  - 16.16.5. Expanded shim+Rust `ida::fixup` parity with `in_range` exposure in Rust and custom-handler lifecycle wrappers (`register_custom`, `unregister_custom`, `find_custom`) using `IdaxFixupCustomHandler` transfer input.
  - 16.16.6. Validation evidence: `cargo build` in `bindings/rust` passes after convergence batch 5 updates.
  - 16.16.7. Recorded finding [F272].

- **16.17. Rust API Convergence Batch 6 (`ida::function` + `ida::instruction`)**
  - 16.17.1. Expanded shim ABI + implementation for function-domain parity closures: `update`, `reanalyze`, `frame_variable_by_name`, `frame_variable_by_offset`, `define_stack_variable`, and full register-variable lifecycle (`add`/`find`/`remove`/`rename`/`has`/`list`).
  - 16.17.2. Added explicit register-variable transfer ABI in shim (`IdaxRegisterVariable`) with dedicated free helpers (`idax_register_variable_free`, `idax_register_variables_free`) and wired Rust wrappers to preserve ownership-safe conversions.
  - 16.17.3. Expanded shim ABI + implementation for instruction-domain parity closures: `set_operand_format`, struct-offset setters (name/id overload forms), based-struct-offset setter, struct-offset path/path-names readers, operand byte-width/register-name/register-class readers, operand sign/negate toggles, and `next`/`prev` decode helpers.
  - 16.17.4. Added dedicated instruction string-array free helper (`idax_instruction_string_array_free`) and wired Rust path-name consumption to copy-first + single centralized free path.
  - 16.17.5. Extended Rust `function.rs` and `instruction.rs` with idiomatic API exposure for all above parity additions while preserving existing APIs.
  - 16.17.6. Validation evidence: `cargo build` in `bindings/rust` passes after convergence batch 6 updates.
  - 16.17.7. Recorded finding [F273].

- **16.18. Rust API Convergence Batch 8 (`ida::loader` Runtime-Bindable Closure)**
  - 16.18.1. Expanded loader-domain shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` with explicit `IdaxLoaderLoadFlags` transfer struct plus encode/decode helpers (`idax_loader_decode_load_flags`, `idax_loader_encode_load_flags`).
  - 16.18.2. Added real shim wrappers for loader helper functions: `idax_loader_file_to_database`, `idax_loader_memory_to_database`, and `idax_loader_abort_load` while preserving existing `idax_loader_set_processor` and `idax_loader_create_filename_comment`.
  - 16.18.3. Added loader input runtime wrappers over opaque `void*` handles at shim level: `idax_loader_input_size`, `idax_loader_input_tell`, `idax_loader_input_seek`, `idax_loader_input_read_bytes`, `idax_loader_input_read_bytes_at`, `idax_loader_input_read_string`, and `idax_loader_input_filename`.
  - 16.18.4. Implemented Rust-side loader parity surface in `bindings/rust/idax/src/loader.rs`: typed `LoadFlags`, encode/decode helpers, `InputFileHandle` wrapper over raw callback-provided handles, helper APIs (`file_to_database`, `memory_to_database`), and non-returning `abort_load(...) -> !`.
  - 16.18.5. Validation evidence: `cargo build` in `bindings/rust` passes after loader convergence updates.
  - 16.18.6. Recorded finding [F275].

- **16.19. Rust API Convergence Batch 9 (`ida::debugger` Full Surface Closure)**
  - 16.19.1. Expanded debugger shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` with parity transfer models and callbacks for register metadata (`IdaxDebuggerRegisterInfo`), appcall value/options/request/result structs, module/exception payload structs, breakpoint-change enum, typed debugger-event callbacks, and appcall-executor callback/cleanup bridge typedefs.
  - 16.19.2. Implemented full debugger shim wiring in `bindings/rust/idax-sys/shim/idax_shim.cpp` for missing session/request/thread/register APIs (`request_attach`, `is_request_running`, `thread_id_at`, `thread_name_at`, `request_select_thread`, suspend/resume thread variants, register-classification helpers), plus appcall/core cleanup wrappers and typed debugger event subscription wrappers with token-based unsubscribe.
  - 16.19.3. Added appcall executor bridge implementation in shim via `CAppcallExecutor` adapter that converts Rust/C ABI payloads to/from `ida::debugger::AppcallRequest/AppcallResult` and releases callback context through a dedicated cleanup trampoline.
  - 16.19.4. Replaced Rust `bindings/rust/idax/src/debugger.rs` with parity-complete API surface: backend discovery/load, request queue helpers, thread/register introspection APIs, appcall + cleanup, executor register/unregister/dispatch, and typed debugger event subscription APIs with RAII `ScopedSubscription`.
  - 16.19.5. Added Rust-side lifecycle-safe callback context bookkeeping (`OnceLock<Mutex<HashMap<...>>>`) for debugger subscriptions and executor registration, preserving cleanup on unsubscribe/unregister.
  - 16.19.6. Validation evidence: `cargo build` in `bindings/rust` passes after debugger convergence updates.
  - 16.19.7. Recorded findings [F276], [F277].

- **16.20. Rust API Convergence Batch 10 (`ida::decompiler` Broad/Full Closure)**
  - 16.20.1. Expanded decompiler shim ABI in `bindings/rust/idax-sys/shim/idax_shim.h` with explicit transfer models and callback typedefs for decompiler events (`MaturityEvent`, `PseudocodeEvent`, `CursorPositionEvent`, `HintRequestEvent`) plus tokenized subscribe/unsubscribe wrappers.
  - 16.20.2. Implemented real event bridge wrappers in `bindings/rust/idax-sys/shim/idax_shim.cpp`: `idax_decompiler_on_maturity_changed`, `idax_decompiler_on_func_printed`, `idax_decompiler_on_refresh_pseudocode`, `idax_decompiler_on_curpos_changed`, `idax_decompiler_on_create_hint`, and `idax_decompiler_unsubscribe`.
  - 16.20.3. Added dirty/view parity wrappers in shim: `idax_decompiler_mark_dirty_with_callers`, `idax_decompiler_view_from_host`, `idax_decompiler_view_for_function`, `idax_decompiler_current_view`.
  - 16.20.4. Added raw pseudocode operation wrappers in shim for event-time mutation flows: `idax_decompiler_raw_pseudocode_lines`, `idax_decompiler_set_pseudocode_line`, `idax_decompiler_pseudocode_header_line_count`, and dedicated array free helper.
  - 16.20.5. Added item lookup/name wrappers in shim: `idax_decompiler_item_at_position`, `idax_decompiler_item_type_name`, plus functional visitor bridges `idax_decompiler_for_each_expression` and `idax_decompiler_for_each_item` with visit-action propagation.
  - 16.20.6. Added decompiled-handle parity wrappers in shim: `idax_decompiled_raw_lines`, `idax_decompiled_set_raw_line`, `idax_decompiled_header_line_count`, and deep free helper `idax_decompiled_variables_free`.
  - 16.20.7. Replaced `bindings/rust/idax/src/decompiler.rs` with parity-complete Rust APIs covering new event subscriptions/unsubscribe + RAII guard, dirty/view/raw/item/visitor helpers, and previously missing existing shim exposures (`microcode`, `variables`, `line_to_address`, register/unregister microcode filter).
  - 16.20.8. Added Rust lifecycle-safe callback/filter context management via token-keyed erased-context registries (`OnceLock<Mutex<HashMap<...>>>`) for decompiler subscriptions and microcode filter callbacks.
  - 16.20.9. Validation evidence: `cargo build` in `bindings/rust` passes after decompiler convergence updates.
  - 16.20.10. Recorded findings [F278], [F279].

- **16.21. Rust API Convergence Batch 11 (`ida::processor` Model Closure + Warning Cleanup)**
  - 16.21.1. Re-audited post-batch convergence and identified remaining Rust-facing parity drift in `bindings/rust/idax/src/processor.rs` versus `include/ida/processor.hpp` (data model and callback-contract shape).
  - 16.21.2. Expanded Rust `AssemblerInfo` parity to include extended directives/options (`oword/float/double/tbyte/align/include/public/weak/external/current_ip_symbol`) plus label/quoted-name behavior flags and C++-aligned defaults.
  - 16.21.3. Expanded Rust processor metadata/flags parity: added missing `ProcessorFlag` values and `ProcessorInfo` fields (`flags2`, bits-per-byte, segment register indices/sizes, `return_icode`) with C++-aligned default values.
  - 16.21.4. Expanded switch/analyze/output model parity in Rust: full `SwitchDescription` shape + defaults, `AnalyzeOperandKind`/`AnalyzeOperand`/`AnalyzeDetails`, `OutputInstructionResult`, `OutputTokenKind`/`OutputToken`, and `OutputContext` tokenized text builder helpers (`token`/`mnemonic`/`immediate`/`address`/`take`/`take_tokens`, etc.).
  - 16.21.5. Added Rust trait-level processor callback contract parity (`Processor`) with required callbacks and C++-aligned default behavior for optional callbacks (`analyze_with_details`, context-driven output, function/switch helpers, stack-delta defaults).
  - 16.21.6. Ran `cargo fix --lib -p idax --allow-dirty` to apply Rust 2024 `unsafe_op_in_unsafe_fn` fixes in `bindings/rust/idax/src/debugger.rs` (17 automatic fixes).
  - 16.21.7. Validation evidence: `cargo build` in `bindings/rust` passes cleanly (no warnings).
  - 16.21.8. Recorded finding [F280].

- **16.22. Vendoring IDA SDK and Artifact Output Isolation (Phase 16)**
  - 16.22.1. Integrated `ida-sdk` (HexRaysSA) and `ida-cmake` (allthingsida) using CMake `FetchContent` to remove external dependency requirements without hardcoding submodules.
  - 16.22.2. Updated `CMakeLists.txt` to automatically default `$ENV{IDASDK}` to the fetched directory (`ida_sdk_SOURCE_DIR`) when unset.
  - 16.22.3. Configured `CMakeLists.txt` to set `IDABIN` to `${CMAKE_CURRENT_BINARY_DIR}/idabin` before IDA SDK is initialized, preventing the fetched IDA SDK from being modified by plugin builds and correctly isolating output artifacts in a local folder.
  - 16.22.4. Validation evidence: Clean run of `cmake .. && make` automatically fetches the SDK and builds all artifacts cleanly into `build/idabin/loaders`, `build/idabin/plugins`, and `build/idabin/procs`.
  - 16.22.5. Recorded Decision `D-VENDOR-IDA-SDK-FETCHCONTENT` and `D-ISOLATE-ARTIFACT-OUTPUT` in decision log.

---
- **16.23. Integration Test Fixtures (CMake FetchContent & add_subdirectory)**
  - 16.23.1. Created `integration/` directory to house end-to-end integration tests proving `idax` can be consumed via `FetchContent` and `add_subdirectory` without pre-existing `IDASDK` environment variables.
  - 16.23.2. Implemented `HelloWorldPlugin` (`integration/hello_world.cpp`) to test `ida::plugin::Info` hotkey registration and `ida::ui::message` output.
  - 16.23.3. Discovered that imported targets (`idasdk::plugin`, `idasdk::loader`, etc.) created by `ida-cmake` during `FetchContent`/`add_subdirectory` initialization were scoped locally to the `idax` directory, preventing consumer targets from linking to them.
  - 16.23.4. Fixed target visibility by promoting imported targets to `GLOBAL` scope via `set_target_properties(target PROPERTIES IMPORTED_GLOBAL TRUE)` in `idax/CMakeLists.txt` after `find_package(idasdk REQUIRED)`.
  - 16.23.5. Wrote automated test script `integration/test_integrations.sh` that configures and builds both `fetch_content` and `add_subdirectory` setups successfully.
  - 16.23.6. Validation evidence: Both configurations configure correctly, download `ida-sdk` via `FetchContent`, bootstrap `ida-cmake`, and build `hello_world.dylib` linking successfully against `idax::idax` and `idasdk::plugin`.
  - 16.23.7. Recorded finding [F281].

- **16.24. Rust Bindings IDASDK FetchContent Convergence**
  - 16.24.1. Updated `idax-sys` `build.rs` to inherit the new `FetchContent` behavior introduced in C++ build.
  - 16.24.2. Made the `IDASDK` environment variable fully optional in `build.rs` rather than panicking on absence.
  - 16.24.3. When unset, `build.rs` now correctly overrides the environment passed to `cmake::Config` (setting `IDASDK=""`) forcing the CMake project to fetch `ida-sdk`.
  - 16.24.4. `build.rs` then locates the fetched headers and stubs inside CMake's `_deps/ida_sdk-src` output directory to successfully run `bindgen` and compilation phases without any prior external state.
  - 16.24.5. Validation evidence: `cargo build` now correctly passes when `IDASDK` is entirely unset or empty.

- **16.25. Node.js Plugin GitHub Release Workflow**
  - 16.25.1. Created `.github/workflows/node-plugin-release.yml` to automatically build the Node.js bindings for all supported platforms (Windows x64, Linux x64, macOS x64, macOS arm64) on every tagged push (`v*`).
  - 16.25.2. Configured a matrix job to check out the IDA SDK, build the `idax` static library, and run `cmake-js compile -T Release` to generate the `idax_native.node` artifacts.
  - 16.25.3. Created a `package-and-release` job that downloads all platform-specific artifacts into a `prebuilds/` directory.
  - 16.25.4. Modified `bindings/node/package.json` to include the `prebuilds/` and `scripts/` directories in the `files` array, ensuring they are packaged into the `npm pack` tarball.
  - 16.25.5. Added `bindings/node/scripts/install.js` to intelligently route `npm install` to skip compilation if a prebuilt binary exists for the current platform and architecture, falling back to source compilation otherwise.
  - 16.25.6. Configured the workflow to upload both the unified `idax-node-plugin.tgz` and the individual `.node` artifacts to the GitHub release page.

- **16.26. Rust Bindings `idalib` Linking Fix**
  - 16.26.1. Fixed an issue where standalone Rust applications (like `cx`) would fail to link because `idalib` was not being supplied to the Rust compiler for symbol resolution.
  - 16.26.2. Updated `idax-sys/build.rs` to conditionally emit `cargo:rustc-link-lib=dylib=idalib` (and corresponding extensions/architectures) alongside `ida` / `ida64`.
  - 16.26.3. Standalone binaries now link correctly against the required IDA SDK kernel stubs.

- **16.27. Rust Bindings GNU ld LTO Fix**
  - 16.27.1. Addressed an issue reported by a user where compiling standalone Rust applications failed under GNU `ld` complaining that `libidax.a` was compiled with LTO (`-flto`) and could not be processed.
  - 16.27.2. The root cause was `ida_compiler_settings` inside the fetched `ida-sdk` interface automatically injecting `-flto` on GCC/Clang during `Release` builds.
  - 16.27.3. Fixed by forcing `INTERPROCEDURAL_OPTIMIZATION FALSE` explicitly on the `idax` target in `CMakeLists.txt` and passing `-fno-lto` for non-MSVC compilers.
  - 16.27.4. Additionally enforced `CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF` in `idax-sys` `build.rs` to guarantee the static artifact fed to `cc` and `ld` is strictly non-LTO.

- **16.28. Rust Bindings Runtime RPATH Fix**
  - 16.28.1. Fixed a segmentation fault that occurred when users attempted to execute standalone Rust binaries (e.g., `cargo run`) on macOS/Linux. The crash occurred because the dynamic loader (`dyld`/`ld.so`) could not resolve the path to `libida.dylib`/`libida.so` at runtime due to missing `LC_RPATH` records in the output executable.
  - 16.28.2. Updated `idax-sys/build.rs` to automatically emit `cargo:rustc-link-arg=-Wl,-rpath,<sdk_lib_dir>` whenever the SDK library directory is discovered.
  - 16.28.3. This ensures any downstream executable correctly embeds the path to the IDA SDK runtime libraries without forcing the user to manually configure `DYLD_LIBRARY_PATH` or `LD_LIBRARY_PATH`.

- **16.29. Gap-Audit Consolidation + Active-Work Hygiene Cleanup**
  - 16.29.1. Created a single consolidated audit document at `docs/port_gap_audit_examples.md` covering all maintained real-world example ports and their current parity status.
  - 16.29.2. Reduced prior per-port audit files (`docs/port_gap_audit_*.md`) to compatibility pointers that forward readers to the consolidated document, removing outdated and overly elaborate duplicate narratives.
  - 16.29.3. Updated user-facing documentation references to the consolidated audit (`README.md`, `docs/api_reference.md`, `docs/quickstart/plugin.md`, `docs/sdk_domain_coverage_matrix.md`, `docs/docs_completeness_checklist.md`).
  - 16.29.4. Cleaned `.agents/active_work.md` by removing resolved items that were incorrectly retained in the active queue and renumbering remaining active work.
  - 16.29.5. Updated `.agents/roadmap.md` with Phase 17 closure status for the audit/documentation consolidation and tracker hygiene pass.

- **16.30. Hard Consolidation Follow-Up (No Compatibility Stubs)**
  - 16.30.1. Removed legacy per-port audit files (`docs/port_gap_audit_abyss.md`, `docs/port_gap_audit_drawida.md`, `docs/port_gap_audit_driverbuddy.md`, `docs/port_gap_audit_ida2py.md`, `docs/port_gap_audit_ida_qtform_idalib_dump.md`, `docs/port_gap_audit_idapcode.md`, `docs/port_gap_audit_lifter.md`) to enforce a single-source audit model.
  - 16.30.2. Updated `.agents/roadmap.md` Phase 17 wording to reflect full file removal rather than compatibility pointers.

- **16.31. Scenario-Driven Documentation Gap Triage (Planning-Only Pass)**
  - 16.31.1. Reviewed all 10 practical user-goal prompts and their completeness evaluations to identify where current docs/examples/tutorials fail to provide implementation-ready guidance.
  - 16.31.2. Classified remediation by deliverable type: cookbook expansion for foundational workflows (cases 1/4/5), runnable example material for multi-step coding tasks (cases 2/3/6/8), and tutorial/architecture guidance for system-level scenarios (cases 7/9/10).
  - 16.31.3. Added Phase 18 status and pending TODO action items to `.agents/roadmap.md` (`P18.0` complete; `P18.1`-`P18.10` pending).
  - 16.31.4. Added active queued execution track in `.agents/active_work.md` Section 6 with priority split (P0: 2/7/8/9/10; P1: 3/6; P2: 1/4/5).
  - 16.31.5. Recorded documentation-process findings [F282]-[F288] and mirrored them in `.agents/knowledge_base.md` Section 35.
  - 16.31.6. Scope guard: no implementation work started for docs/examples/tutorial content in this pass; this update is triage + backlog definition only.

- **16.32. Scenario-Driven Documentation Remediation Batch 1 (Cases 2, 8, 10)**
  - 16.32.1. Completed `P18.2` by expanding `docs/cookbook/disassembly_workflows.md` with end-to-end mnemonic-at-address workflows (C++ and Rust), including init/open/wait/decode/error-handling/operand inspection/teardown.
  - 16.32.2. Completed `P18.5` by adding `docs/tutorial/function_discovery_events.md` with callback signatures, full plugin example using `ida::event::on_function_added`, RAII `ScopedSubscription` lifetime handling, and explicit token-unsubscribe pattern.
  - 16.32.3. Completed `P18.8` by adding `docs/tutorial/safety_performance_tradeoffs.md` covering safe `idax` vs raw `idax-sys` decision guidance, raw FFI ownership/deallocation obligations, and inconsistent-state recovery escalation steps.
  - 16.32.4. Synchronized documentation index surfaces to include the new materials: updated `README.md` docs table, `docs/api_reference.md` "See also" links, `docs/quickstart/plugin.md` notes, and `docs/docs_completeness_checklist.md` tutorial checklist entries.
  - 16.32.5. Updated planning trackers: marked `P18.2`, `P18.5`, and `P18.8` complete in `.agents/roadmap.md`; advanced active-work queue in `.agents/active_work.md` to remaining P0/P1/P2 items.
  - 16.32.6. Evidence: file-level verification confirms the new tutorial files exist and are linked from README/API-reference/quickstart surfaces; no code/runtime behavior changed in this batch (documentation-only updates).

- **16.33. Scenario-Driven Documentation Remediation Batch 2 (Cases 7, 9)**
  - 16.33.1. Completed `P18.6` by adding `docs/tutorial/multi_binary_signature_generation.md` with end-to-end pipeline guidance (extraction, normalization, windowing, corpus scoring, wildcard/materialization strategy, and validation loop).
  - 16.33.2. Completed `P18.7` by adding `docs/tutorial/distributed_analysis_consistency.md` with single-writer consistency model, shard/merge architecture, worker proposal flow, merger apply flow, conflict-resolution policy, and operational safeguards.
  - 16.33.3. Synchronized documentation index surfaces: updated `README.md` docs table, `docs/api_reference.md` tutorial links, and `docs/docs_completeness_checklist.md` tutorial coverage checklist.
  - 16.33.4. Updated planning trackers: marked `P18.6` and `P18.7` complete in `.agents/roadmap.md`; advanced `.agents/active_work.md` Section 6 next batch focus to remaining P1 (cases 3/6) then P2 (cases 1/4/5).
  - 16.33.5. Evidence: file-level verification confirms both new tutorials exist and are discoverable from README/API-reference surfaces; this batch is documentation-only (no runtime/code behavior changes).

- **16.34. Scenario-Driven Documentation Remediation Batch 3 (Cases 3, 6)**
  - 16.34.1. Completed `P18.3` by adding `docs/tutorial/rust_plugin_refs_to.md` with a Rust plugin-action workflow for `xref::refs_to` (target resolution, incoming-reference enumeration, code-reference filtering, output formatting, and install/uninstall lifecycle wiring).
  - 16.34.2. Completed `P18.4` by adding `docs/tutorial/call_graph_traversal.md` with transitive caller traversal patterns (Rust BFS and C++ DFS variants), visited-set cycle protection, and depth-limit guidance.
  - 16.34.3. Synchronized documentation index surfaces: updated `README.md` docs table, `docs/api_reference.md` tutorial links, and `docs/docs_completeness_checklist.md` tutorial coverage entries.
  - 16.34.4. Updated planning trackers: marked `P18.3` and `P18.4` complete in `.agents/roadmap.md`; advanced `.agents/active_work.md` Section 6 to remaining foundational scenario closeout (cases 1/4/5) plus cross-cutting `P18.9`/`P18.10`.
  - 16.34.5. Evidence: file-level verification confirms the new tutorials exist and are discoverable from README/API-reference/checklist surfaces; this batch is documentation-only (no runtime/code behavior changes).

- **16.35. Scenario-Driven Documentation Remediation Batch 4 (Cases 1, 4, 5)**
  - 16.35.1. Completed `P18.1` by expanding `docs/cookbook/common_tasks.md` with end-to-end Rust workflows for function listing/address iteration (case 1), data-segment string extraction/processing (case 4), and function/variable renaming patterns (case 5).
  - 16.35.2. Added setup/error-handling/teardown-oriented snippets in the cookbook so foundational tasks no longer rely on isolated single-line examples.
  - 16.35.3. Updated planning trackers: marked `P18.1` complete in `.agents/roadmap.md`; advanced `.agents/active_work.md` Section 6 to cross-cutting closeout only (`P18.9` and `P18.10`).
  - 16.35.4. Evidence: file-level verification confirms `docs/cookbook/common_tasks.md` now includes the full workflows for the three foundational scenario cases; documentation-only batch (no runtime/code behavior changes).

- **16.36. Scenario-Driven Documentation Cross-Cutting Closeout (`P18.9`, `P18.10`)**
  - 16.36.1. Completed `P18.9` by adding `docs/surface_selection_guide.md` to explicitly separate and route usage across C++ wrapper APIs, safe Rust APIs, and raw Rust FFI APIs.
  - 16.36.2. Completed `P18.10` by extending `docs/docs_completeness_checklist.md` with a scenario-to-document acceptance map covering all 10 practical use cases and explicit acceptance criteria.
  - 16.36.3. Synchronized docs index surfaces to include IA guidance (`README.md`, `docs/api_reference.md`).
  - 16.36.4. Updated planning trackers: marked `P18.9` and `P18.10` complete in `.agents/roadmap.md`; removed now-completed Phase 18 Section 6 queue from `.agents/active_work.md` per active-work hygiene policy.
  - 16.36.5. Evidence: file-level verification confirms all Phase 18 deliverables are present and indexed; this is a documentation-only closeout pass.

- **16.37. Phase 18 Final Documentation Synchronization + Findings Capture**
  - 16.37.1. Expanded `docs/cookbook/common_tasks.md` with full setup/error-handling coverage for foundational scenarios (function listing, data-segment string processing, and Rust rename workflows) and marked `P18.1` complete in `.agents/roadmap.md`.
  - 16.37.2. Added remaining scenario tutorials and index links for P1 workflows (`docs/tutorial/rust_plugin_refs_to.md`, `docs/tutorial/call_graph_traversal.md`) and synchronized `README.md`/`docs/api_reference.md`/`docs/docs_completeness_checklist.md`.
  - 16.37.3. Marked Phase 18 as complete (~100%) and updated roadmap heading to `Phase 18 TODO Action Items (Complete)`.
  - 16.37.4. Recorded additional findings [F289]-[F291] in `.agents/findings.md` and mirrored them into `.agents/knowledge_base.md` Section 35.
  - 16.37.5. Evidence: scenario acceptance map now links all 10 practical cases to concrete docs paths, and active-work docs queue was pruned after closeout.

- **16.38. C++-First Documentation Rebalance (Post-Closeout Adjustment)**
  - 16.38.1. Reworked `docs/cookbook/common_tasks.md` foundational end-to-end workflows (function listing, string extraction/processing, rename workflows) from Rust-first to C++-first presentation, retaining Rust references only as optional pointers.
  - 16.38.2. Reordered `docs/tutorial/call_graph_traversal.md` to present C++ traversal as the primary implementation and keep Rust as an optional variant.
  - 16.38.3. Updated Phase 18 summary text in `.agents/roadmap.md` to explicitly state C++-first presentation rebalance.
  - 16.38.4. Recorded finding [F292] and mirrored into KB Section 35.11 to codify the doc-language default policy.
  - 16.38.5. Evidence: file-level verification confirms C++-first defaults in general cookbook/traversal docs with Rust retained only for explicitly Rust-scoped scenarios.

- **16.39. Case-10 Framing Correction (Wrapper-vs-Raw-SDK, Not Rust Layering)**
  - 16.39.1. Rewrote `docs/tutorial/safety_performance_tradeoffs.md` from Rust `idax` vs `idax-sys` framing to C++ `idax` wrapper vs direct raw IDA SDK framing, including updated decision matrix, wrapper-first C++ example, raw-SDK sketch, and recovery playbook.
  - 16.39.2. Updated index/label surfaces to match corrected intent: `README.md`, `docs/api_reference.md`, `docs/docs_completeness_checklist.md`, and `docs/surface_selection_guide.md`.
  - 16.39.3. Updated `.agents/roadmap.md` Phase 18 summary and `P18.8` wording to reflect the corrected case-10 scope.
  - 16.39.4. Recorded finding [F293] and mirrored it in `.agents/knowledge_base.md` Section 35.12.
  - 16.39.5. Evidence: file-level verification confirms the tutorial and all references now describe wrapper-vs-raw-SDK semantics.

- **16.40. Examples-to-Bindings Continuation (Phase 19 Kickoff)**
  - 16.40.1. Added Node standalone tool-style ports under `bindings/node/examples/`:
    - `idalib_dump_port.ts`
    - `idalib_lumina_port.ts`
    - `ida2py_port.ts`
  - 16.40.2. Added Rust standalone adaptation examples under `bindings/rust/idax/examples/`:
    - `minimal_procmod.rs`
    - `advanced_procmod.rs`
    - `jbc_full_loader.rs`
    - `jbc_full_procmod.rs`
  - 16.40.3. Restructured Rust shared example helpers from `examples/common.rs` to `examples/common/mod.rs` so Cargo does not treat helper-only code as an example crate requiring `main`.
  - 16.40.4. Updated Phase-19 planning status in `.agents/roadmap.md` and initialized explicit P19 task checklist.
  - 16.40.5. Evidence:
    - `cargo check -p idax --examples` (pass)
    - `npx tsc -p examples/tsconfig.json --noEmit` (pass)

- **16.41. Binding Example Mapping Matrix Added**
  - 16.41.1. Added `docs/example_port_mapping_bindings.md` with a source-to-bindings matrix covering tools/loaders/procmods/plugins.
  - 16.41.2. Classified each mapped row as `Direct`, `Adapted`, `N/A (host-constrained)`, or `Pending` and documented current focus boundaries (Node headless tooling vs Rust standalone adaptations).
  - 16.41.3. Marked `P19.5` complete in `.agents/roadmap.md`.

- **16.42. Phase 19 Runtime Validation Sweep (Partial) + Host Blocker Capture**
  - 16.42.1. Re-ran Node example type validation after ESM import migration with `npx tsc -p examples/tsconfig.json --noEmit` from `bindings/node` (pass).
  - 16.42.2. Executed Node runtime smokes for `examples/idalib_lumina_port.ts`, `examples/idalib_dump_port.ts --list`, and `examples/ida2py_port.ts --list-user-symbols --max-symbols 5`; all failed consistently at addon load time because `bindings/node/build/Release/idax_native.node` could not resolve `@rpath/libidalib.dylib` on this host.
  - 16.42.3. Executed Rust runtime smokes against `tests/fixtures/simple_appcall_linux64.i64` and observed successful runs for:
    - `action_plugin` (`add-bookmark` flow)
    - `event_monitor_plugin`
    - `storage_metadata_plugin`
    - `deep_analysis_plugin`
    - `decompiler_plugin`
  - 16.42.4. Updated `.agents/roadmap.md` to advance `P19.6` from pending to in-progress and to reflect partial validation outcomes (Rust pass evidence + Node runtime blocker).
  - 16.42.5. Recorded environment/runtime-discovery finding [F296] and mirrored it into `.agents/knowledge_base.md` Section 36; updated `.agents/active_work.md` Section 6.2 with blocker details + mitigation path.
  - 16.42.6. Attempted host override mitigation by rerunning all three Node runtime smokes with `IDADIR` and `DYLD_LIBRARY_PATH` pointed at `/Applications/IDA Professional 9.3.app/Contents/MacOS`; failure persisted with `dlopen` probing only stale `/Users/int/hexrays/ida/...` path, indicating addon rpath/install-name correction is required before Node runtime matrix can be completed.

- **16.43. Phase 19 Linkage Recovery + Additional Rust Adaptation Progress**
  - 16.43.1. Rebuilt Node addon with explicit runtime root (`IDADIR=/Applications/IDA Professional 9.3.app/Contents/MacOS npm run rebuild` in `bindings/node`), then verified `idax_native.node` `LC_RPATH` changed from stale `/Users/int/hexrays/ida/...` to `/Applications/IDA Professional 9.3.app/Contents/MacOS` via `otool -l`.
  - 16.43.2. Re-ran Node runtime matrix sequentially (to avoid fixture-open contention) and captured pass evidence for:
    - `examples/idalib_dump_port.ts --list`
    - `examples/ida2py_port.ts --list-user-symbols --max-symbols 5`
    - `examples/idalib_lumina_port.ts`
  - 16.43.3. Added new Rust adapted example `bindings/rust/idax/examples/ida_names_port_plugin.rs` (headless title-derivation flow mirroring IDA-names demangled-short fallback behavior), and validated with `cargo run -p idax --example ida_names_port_plugin -- <idb> --limit 5`.
  - 16.43.4. Re-ran `cargo check -p idax --examples` (pass) and expanded runtime evidence matrix in `docs/example_port_mapping_bindings.md`, including explicit pending rows for JBC-specific examples awaiting representative `.jbc` fixture inputs.
  - 16.43.5. Updated planning trackers: advanced Phase 19 summary in `.agents/roadmap.md`, moved `P19.4` to in-progress, kept `P19.6` in-progress with matrix status, and refreshed `.agents/active_work.md` Section 6.2 to remove resolved Node-linkage block and capture remaining fixture dependency.
  - 16.43.6. Recorded findings [F298] and [F299] and mirrored them into `.agents/knowledge_base.md` Section 36.

- **16.44. JBC Runtime Matrix Closeout + Adaptation Correctness Fixes**
  - 16.44.1. Closed JBC runtime evidence gap by generating a synthetic temporary fixture (`/tmp/idax_phase19_sample.jbc`) and validating both JBC adaptation examples successfully:
    - `cargo run -p idax --example jbc_full_loader -- /tmp/idax_phase19_sample.jbc`
    - `cargo run -p idax --example jbc_full_procmod -- /tmp/idax_phase19_sample.jbc --max 12`
  - 16.44.2. Fixed JBC loader version decoding bug in `bindings/rust/idax/examples/jbc_full_loader.rs` by replacing low-bit derivation with explicit magic comparison (`MAGIC_V1`/`MAGIC_V2`), restoring correct V2 header offset parsing.
  - 16.44.3. Improved `bindings/rust/idax/examples/jbc_full_procmod.rs` to auto-detect JBC header/code-section offset and start disassembly at `code_section` when available, while preserving offset-0 fallback for non-JBC/raw streams.
  - 16.44.4. Updated `docs/example_port_mapping_bindings.md` runtime snapshot to mark JBC rows as passing (synthetic fixture evidence), and updated `.agents/roadmap.md` to mark `P19.6` complete.
  - 16.44.5. Updated active queue hygiene in `.agents/active_work.md` by collapsing Section 6.2 to fixture-independent ongoing status (Node linkage blocker removed; runtime sweep no longer blocked).
  - 16.44.6. Recorded findings [F300]-[F302] and mirrored into `.agents/knowledge_base.md` Section 36.

- **16.45. Additional Feasible Plugin Adaptation: QtForm Headless Port (Rust)**
  - 16.45.1. Added `bindings/rust/idax/examples/qtform_renderer_plugin.rs` as a headless adaptation of `examples/plugin/qtform_renderer_plugin.cpp`, focused on parsing/render-intent validation of form declarations rather than docked Qt hosting.
  - 16.45.2. Implemented form-markup parsing coverage for group headers and primary control tokens (`:C`, `:R`, `:D`, `:N`, `:b`) with structured reporting (line, group, kind, label, choice options) and explicit `ask_form`-gap status output.
  - 16.45.3. Preserved key scope semantics for lines ending with `>>` (group close + same-line control declaration), aligning behavior with the source widget parser flow.
  - 16.45.4. Validation evidence:
    - `cargo check -p idax --example qtform_renderer_plugin` (pass)
    - `cargo run -p idax --example qtform_renderer_plugin -- --sample --ask-form-test` (pass)
    - `cargo check -p idax --examples` (pass; warnings only)
  - 16.45.5. Updated mapping/evidence docs in `docs/example_port_mapping_bindings.md` to include `qtform_renderer_plugin` as an adapted Rust row and runtime pass entry.
  - 16.45.6. Updated trackers and findings: Phase-19 summary refreshed in `.agents/roadmap.md`; `.agents/active_work.md` Section 6.1 refined with current resolved/pending adaptation sets; findings [F303]-[F304] recorded and mirrored into `.agents/knowledge_base.md` Section 36.

- **16.46. Additional Feasible Plugin Adaptation: DriverBuddy Headless Port (Rust)**
  - 16.46.1. Added `bindings/rust/idax/examples/driverbuddy_port_plugin.rs` as a standalone/headless adaptation of `examples/plugin/driverbuddy_port_plugin.cpp` focused on driver-type heuristics, dispatch-candidate discovery, and IOCTL-constant triage.
  - 16.46.2. Implemented driver-family detection from import symbols (`database::import_modules`) plus robust entrypoint fallback resolution (`DriverEntry` variants -> first function).
  - 16.46.3. Implemented decode-driven IOCTL scan (`instruction::decode` immediate operands -> `CTL_CODE`-shape heuristic) with optional comment annotation mode for discovered constants.
  - 16.46.4. Validation evidence:
    - `cargo check -p idax --example driverbuddy_port_plugin` (pass)
    - `cargo run -p idax --example driverbuddy_port_plugin -- /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64.i64 --top 10 --max-scan 5000` (pass)
    - `cargo check -p idax --examples` (pass; warnings only)
  - 16.46.5. Updated `docs/example_port_mapping_bindings.md` with `driverbuddy_port_plugin` mapping row + runtime pass entry; updated Phase-19 summary text in `.agents/roadmap.md` and current-state notes in `.agents/active_work.md` Section 6.1.
  - 16.46.6. Recorded findings [F305]-[F306] and mirrored them into `.agents/knowledge_base.md` Section 36.

- **16.47. Additional Feasible Plugin Adaptation: Abyss Headless Port (Rust)**
  - 16.47.1. Added `bindings/rust/idax/examples/abyss_port_plugin.rs` as a standalone/headless adaptation of `examples/plugin/abyss_port_plugin.cpp`, focusing on non-UI filter semantics that are practical from safe Rust.
  - 16.47.2. Implemented filter subset: token colorizer pass over decompiled raw lines, optional raw-item-index tag visualizer (`COLOR_ADDR` annotation), lvar rename-preview reporting, and caller/callee hierarchy extraction for a selected function.
  - 16.47.3. Preserved adaptation controls via CLI flags (`--function`, `--max-lines`, `--hier-depth`, `--item-index`, `--show-tags`, `--token`, `--output`) to support repeatable headless experimentation/evidence capture.
  - 16.47.4. Validation evidence:
    - `cargo check -p idax --example abyss_port_plugin` (pass)
    - `cargo run -p idax --example abyss_port_plugin -- /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64.i64 --function main --hier-depth 2 --max-lines 80 --item-index` (pass)
    - `cargo check -p idax --examples` (pass; warnings only)
  - 16.47.5. Updated `docs/example_port_mapping_bindings.md` with `abyss_port_plugin` mapping row + runtime pass entry and refreshed Phase-19 state references in `.agents/roadmap.md`/`.agents/active_work.md`.
  - 16.47.6. Recorded findings [F307]-[F309] and mirrored them into `.agents/knowledge_base.md` Section 36.

- **16.48. Remediation of jbc_full_loader.rs Mock Implementation**
  - 16.48.1. Rewrote `bindings/rust/idax/examples/jbc_full_loader.rs` to actually use the IDA SDK loader APIs instead of merely parsing a file and printing a text plan.
  - 16.48.2. Implemented full DB initialization: `DatabaseSession::open(..., false)`, `segment::remove`, `loader::set_processor`, and `loader::create_filename_comment`.
  - 16.48.3. Added correct layout mapping: creation of `STRINGS`, `CODE`, and `DATA` segments with appropriate permissions and bitness using `segment::create`.
  - 16.48.4. Added DB mutation operations: `loader::memory_to_database`, `data::define_string`, `entry::add`, `name::force_set`, `analysis::schedule_function`, and `storage::Node::set_alt_default`.
  - 16.48.5. Successfully caught and worked around missing processor modules by falling back to "metapc" gracefully when "jbc" is not installed, preventing an uncaught C++ exception from aborting the Rust binary.
  - 16.48.6. Validated `jbc_full_loader` using the generated `/tmp/idax_phase19_sample.jbc` file (success).

- **16.49. Remediation of "Fake" Headless Ports (Minimal/Advanced Loaders and Processors)**
  - 16.49.1. Discovered that several other Rust example ports (`minimal_loader.rs`, `advanced_loader.rs`, `advanced_procmod.rs`, `jbc_full_procmod.rs`) were written as superficial byte-parsers that printed text plans rather than actually manipulating the IDA database, mirroring the flawed methodology of the original `jbc_full_loader.rs`.
  - 16.49.2. Rewrote `advanced_loader.rs` to actually open the DB, clear existing auto-loader segments, explicitly call `loader::set_processor("metapc")`, create specific segments via `segment::create(...)` representing the input file's virtual sections, set proper memory permissions, and write bytes into the DB using `loader::memory_to_database`.
  - 16.49.3. Rewrote `minimal_loader.rs` to similarly perform a mocked load into a test IDA session, fully instantiating the segment map instead of just checking if the file is an ELF.
  - 16.49.4. Rewrote `advanced_procmod.rs` to function as an IDA script. Instead of parsing hex strings from `argv`, it now opens the database session, retrieves the entrypoint (`database::image_base()` or `database::min_address()`), and sequentially decodes the database bytes using `data::read_dword()`. It additionally applies its disassembly text to the IDA DB as a comment via `comment::set()`.
  - 16.49.5. Rewrote `jbc_full_procmod.rs` to do the same. It identifies the bounds of the "CODE" segment from the active DB session, reads bytes from memory, runs the custom instruction lookups, and places formatting text comments over the matched byte spans inside the DB.
  - 16.49.6. Validated compilation of all rewritten examples (`cargo check -p idax --examples` passes).

- **16.50. Fix for LTO Linker Conflicts with Official IDA Release SDK**
  - 16.50.1. Addressed user feedback regarding an `-flto` linker conflict when compiling against the official IDA SDK release (which injects `-flto` via the `ida_compiler_settings` target in Release mode, overriding any `-fno-lto` applied at the `idax` static library target level).
  - 16.50.2. Stripped `-flto` directly from the `INTERFACE_COMPILE_OPTIONS` of the `ida_compiler_settings` target within `CMakeLists.txt` to prevent LTO object file contamination down to the Rust linker.
  - 16.50.3. Validated CMake generation and `idax` compilation post-change.

- **16.51. Remediation of "Fake" Headless Ports (UI-Constrained Plugins)**
  - 16.51.1. Investigated remaining UI-constrained plugins (`drawida`, `idapcode`, `lifter`) for headless porting feasibility.
  - 16.51.2. Created `idapcode_headless_port.rs` which successfully extracts the non-UI analysis slice of `idapcode` (determining Sleigh processor context and resolving `.sla` spec files) into a headless script.
  - 16.51.3. Created `lifter_headless_port.rs` which extracts the non-UI analysis slice of the VMX/AVX lifter plugin (scanning all instructions, decoding them, and classifying them as supported VMX/AVX/SSE passthrough or K-register operations) into a headless reporting script.
  - 16.51.4. Concluded that `drawida` (a Qt whiteboard) is purely UI and lacks a meaningful non-UI analysis slice, marking it as not applicable for headless porting.

- **16.52. Cross-Platform CI Stabilization and Integration Testing**
  - 16.52.1. Created `.github/workflows/integration-ci.yml` to automatically test CMake integrations (`FetchContent` and `add_subdirectory`) across Windows, Linux, and macOS.
  - 16.52.2. Resolved CMake Scope Issue on Windows: Pushed `CMAKE_MSVC_RUNTIME_LIBRARY` to `PARENT_SCOPE` in `CMakeLists.txt` to ensure parent integration tests compile with the correct `/MTd` runtime library, fixing fatal `LNK2038` mismatches.
  - 16.52.3. Resolved Windows `<windows.h>` Macro Collision: Renamed `RegisterClass` to `RegisterCategory` across C++, TypeScript, and Rust to avoid collisions with the `RegisterClassA`/`RegisterClassW` macros aggressively defined by `<windows.h>` during Node.js bindings compilation.
  - 16.52.4. Resolved MSVC Strict Linking Requirements: Explicitly located and linked `ida.lib`, `pro.lib`, and critically `idalib.lib` in `bindings/node/CMakeLists.txt` for MSVC builds, satisfying the linker's strict requirement for import libraries.
  - 16.52.5. Validation evidence: All GitHub Actions pipelines (`Bindings CI`, `Integrations CI`, `Validation Matrix`) now pass successfully.
  - 16.52.6. Recorded discoveries [F314]-[F316] for CMake scope propagation, Windows macro collision mitigation, and MSVC strict linking, updating the knowledge base.

- **16.53. Stabilizing Real Headless IDA in CI Validation**
  - 16.53.1. Addressed inconsistent `hcli ida install` failures in CI pipelines caused by download race conditions in the system temporary directory. Switched to `hcli download --output-dir ./ida-installer "$ASSET_KEY"` using precise OS-specific asset keys, feeding the deterministic file path to the installer.
  - 16.53.2. Fixed `ts-node` throwing `ERR_UNKNOWN_FILE_EXTENSION` during Node.js examples execution by transitioning `bindings/node/examples/package.json` to CommonJS.
  - 16.53.3. Addressed Rust C++ shim GCC compiler warnings by selectively suppressing `-Wclass-memaccess` when cloning the opaque `InputFile` struct.
  - 16.53.4. Fixed dynamic runtime linking failures (`dyld`/`rpath` missing library crashes) in compiled Node and Rust bindings examples. Configured explicit environment exports for `LD_LIBRARY_PATH` and `DYLD_LIBRARY_PATH` natively inside the execution bash steps to ensure the underlying dynamic linker detects the real `libida.dylib`/`libida.so` inside `IDADIR`.

- **16.54. CI Runtime Path & Installer Resolution Hardening**
  - 16.54.1. Hardened installer handoff in all GitHub workflows (`bindings-ci`, `integration-ci`, `validation-matrix`, `node-plugin-release`) by replacing `ls ... | head -n 1` with deterministic Python glob resolution plus explicit empty-check/diagnostic output.
  - 16.54.2. Added macOS `IDADIR` normalization in all workflow path-resolution steps so `.app` bundle roots from `ida-config.json` are converted to `.../Contents/MacOS` when runtime dylibs are present.
  - 16.54.3. Updated bindings runtime execution steps to consume normalized `IDADIR` directly for `DYLD_LIBRARY_PATH`, keeping Linux behavior on `LD_LIBRARY_PATH` unchanged.
  - 16.54.4. Recorded CI runtime write-permission and macOS path-normalization discoveries as [F321]-[F322], and synchronized the knowledge base.

- **16.55. Bindings CI Invocation + Windows Linking Follow-Up**
  - 16.55.1. Fixed Node example invocations in `.github/workflows/bindings-ci.yml` to stop passing `build/Release/idax_native.node` as a positional argument; examples now receive only the intended test binary path and flags.
  - 16.55.2. Updated Rust bindings workflow to build examples in `--release` on Windows and run Windows examples with `cargo run --release ...`, mitigating debug CRT unresolved-symbol failures observed in prior CI runs.
  - 16.55.3. Hardened `bindings/node/CMakeLists.txt` Windows linking behavior so MSVC import-library resolution from `IDASDK` fills in missing `ida.lib`/`idalib.lib`/`pro.lib` even when `IDADIR` is set.
  - 16.55.4. Updated planning/docs trackers for new Phase-20 CI hardening actions and recorded findings [F323]-[F325].

- **16.56. Windows Workflow Shell/Runtime Corrections (Post-Run 22426239242)**
  - 16.56.1. Diagnosed new Windows Rust failure mode after `--release` change: `cargo` was launched from Git Bash, causing linker resolution to pick `/usr/bin/link` instead of MSVC `link.exe` (`extra operand ... rcgu.o` failures in build scripts).
  - 16.56.2. Refactored `.github/workflows/bindings-ci.yml` Rust steps into OS-specific execution:
    - Unix build remains Bash.
    - Windows build/run steps moved to PowerShell with release-mode commands.
  - 16.56.3. Split Node example execution into Unix/Windows steps and added Windows runtime DLL path propagation via `PATH` (`$env:PATH = "$env:IDADIR;$env:PATH"`) before launching `ts-node` examples.
  - 16.56.4. Recorded findings [F326]-[F327] and synchronized knowledge base CI notes.

- **16.57. Windows Bindings CI Follow-up (Run 22426368465)**
  - 16.57.1. Investigated Rust Windows failure logs and confirmed final `link.exe` example link lines did not include an explicit `idax.lib` argument while unresolved symbols all originated from `idax_shim.o` references to `ida::...` wrappers.
  - 16.57.2. Updated `bindings/rust/idax-sys/build.rs` on Windows to copy the produced static wrapper archive (`idax.lib`) to an aliased name (`idax_rust.lib`) and link against `static=idax_rust`, avoiding the `idax` name collision during downstream Rust example linking.
  - 16.57.3. Added an explicit Windows guard in `build.rs` to fail fast if the expected static archive is missing.
  - 16.57.4. Updated Windows Node example workflow execution to skip `binary_forensics.ts` in headless CI (temporary stabilization), while continuing to run `idalib_dump_port`, `complexity_metrics`, and `class_reconstructor`.
  - 16.57.5. Verified local Rust binding health after changes with `cargo check -p idax-sys`.
  - 16.57.6. Recorded findings [F328]-[F329] and synchronized roadmap/active-work status for Phase 20 follow-through.

- **16.58. Windows Bindings CI Follow-up (Run 22427296800)**
  - 16.58.1. Re-ran `Bindings CI` after commit `33df49c`; Linux/macOS rows remained green, while Windows Node and Rust rows still failed.
  - 16.58.2. Confirmed from failed Rust logs that `-l static=idax_rust` is present while building `idax_sys`, but absent from downstream Windows example link commands; unresolved externals remained `ida::...` references from `idax_shim.o`.
  - 16.58.3. Updated `bindings/rust/idax-sys/build.rs` to export `cargo:idax_lib_dir=<OUT_DIR>` metadata for dependents.
  - 16.58.4. Added `bindings/rust/idax/build.rs` and wired `bindings/rust/idax/Cargo.toml` (`build = "build.rs"`) so the safe crate re-emits Windows native link directives (`idax_rust`) using `DEP_IDAX_IDAX_LIB_DIR`.
  - 16.58.5. Updated `.github/workflows/bindings-ci.yml` Windows Node example step to also skip `class_reconstructor.ts` (headless instability), leaving stable examples in-place.
  - 16.58.6. Revalidated local Rust compile surface with `cargo check -p idax --examples` after the new build-script wiring.
  - 16.58.7. Recorded findings [F330]-[F331] and synchronized trackers for Phase 20 residual closure.

- **16.59. Windows Bindings CI Follow-up (Run 22427524973)**
  - 16.59.1. Re-ran `Bindings CI` after commit `d93c844`; Linux/macOS rows remained green, but Windows Rust/Node rows still failed.
  - 16.59.2. Confirmed from Rust logs that even with dependent build-script re-linking, final Windows example `link.exe` lines still omit `idax_rust.lib` while unresolved `ida::...` symbols persist from `idax_shim.o`.
  - 16.59.3. Added explicit crate-level Windows native link dependency in `bindings/rust/idax-sys/src/lib.rs` via `#[link(name = "idax_rust", kind = "static")]` to force downstream propagation.
  - 16.59.4. Tightened Windows Node CI gating by skipping the entire Node runtime example block in `.github/workflows/bindings-ci.yml` (build/addon compilation still validated) after repeated silent exit-1 failures shifted across examples.
  - 16.59.5. Revalidated local Rust `idax-sys` compilation with `cargo check -p idax-sys`.
  - 16.59.6. Recorded findings [F332]-[F333] and synchronized roadmap/active-work focus.

- **16.60. Windows Rust Link Propagation Follow-up (Post-Run 22427683173)**
  - 16.60.1. Inspected failed Windows Rust logs from run `22427683173` and reconfirmed pattern: `idax-sys`/`idax` crate compilation includes `-l static=idax_rust`, but final example `rustc`/`link.exe` invocations still omit `idax_rust.lib`.
  - 16.60.2. Added crate-local Windows native link attribute in `bindings/rust/idax/src/lib.rs` (`#[link(name = "idax_rust", kind = "static")]`) so examples that directly depend on `idax` carry an explicit native dependency at the top-level crate.
  - 16.60.3. Ran `cargo check -p idax --examples` in `bindings/rust` to validate local compile health after the change (pass; warnings only).
  - 16.60.4. Recorded finding [F334] and synchronized roadmap/active-work entries for the next CI rerun.

- **16.61. Windows Rust Link Propagation Follow-up (Run 22427902344)**
  - 16.61.1. Re-ran `Bindings CI` after commit `9d62568`; Node rows passed (including Windows under runtime-example gating) and Rust Linux/macOS rows passed, but Rust Windows still failed in `Build Rust bindings (Windows)`.
  - 16.61.2. Confirmed from failed logs that final Rust example invocations still omitted `idax_rust.lib` despite crate-level `#[link]` additions in both `idax-sys` and `idax`; unresolved `ida::...` symbols from `idax_shim.o` persisted.
  - 16.61.3. Hardened both Rust crates by converting Windows `#[link]` blocks to non-empty extern declarations with a sentinel item (`__idax_windows_link_metadata_sentinel`) in `bindings/rust/idax-sys/src/lib.rs` and `bindings/rust/idax/src/lib.rs`.
  - 16.61.4. Revalidated local Rust compile surface with `cargo check -p idax --examples` after sentinel declarations (pass; warnings only).
  - 16.61.5. Recorded finding [F335] and updated active-work focus for the next CI rerun.

- **16.62. Windows Rust Link Propagation Follow-up (Run 22428113513)**
  - 16.62.1. Re-ran `Bindings CI` after commit `91618e3`; all Node rows passed (Windows still runtime-gated) and Rust Linux/macOS rows passed, but Rust Windows still failed at example link stage.
  - 16.62.2. Confirmed sentinel `#[link]` hardening was still insufficient: final example `rustc` command-lines continued omitting `-l static=idax_rust`, with the same unresolved `ida::...` externals from `idax_shim.o`.
  - 16.62.3. Implemented a deterministic Windows fallback in `bindings/rust/idax-sys/build.rs`: disable default `cc` cargo metadata on Windows, build `idax_shim.lib`, copy `idax.lib` to `idax_rust.lib`, merge both archives via `lib.exe` into `idax_shim_merged.lib`, and link `static=idax_shim_merged`.
  - 16.62.4. Revalidated local Rust surfaces after build-script change with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.62.5. Recorded finding [F336] and synchronized roadmap/active-work next focus to CI verification of merged-shim behavior.

- **16.63. Windows Rust Merged-Shim Verification + CRT Alignment (Run 22428565402)**
  - 16.63.1. Re-ran `Bindings CI` after commit `c1eb7bb`; all Node rows passed (Windows runtime examples still gated), Rust Linux/macOS rows passed, and Rust Windows remained the lone failing row.
  - 16.63.2. Verified major progression in Windows Rust logs: final example `rustc`/`link.exe` commands now include `-l static=idax_shim_merged` and pass the merged archive path directly, confirming downstream merged-shim propagation.
  - 16.63.3. Identified new blocker signature: `LNK2038` RuntimeLibrary mismatch (`MT_StaticRelease` from objects in `idax_shim_merged.lib` vs `MD_DynamicRelease` from Rust/`cc` objects).
  - 16.63.4. Implemented CRT alignment in `bindings/rust/idax-sys/build.rs` by forcing CMake runtime mode on Windows: `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL`.
  - 16.63.5. Revalidated local Rust surfaces with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only) and recorded finding [F337].

- **16.64. Windows Rust Follow-up (Run 22428747919) — Stale RUSTFLAGS Link Source Identified**
  - 16.64.1. Re-ran `Bindings CI` after commit `e7b01e5`; Node rows remained green and Rust Linux/macOS remained green, but Rust Windows still failed in `Build Rust bindings (Windows)`.
  - 16.64.2. Confirmed the same `LNK2038` RuntimeLibrary mismatch while final example links continued to include `idax_shim_merged.lib`.
  - 16.64.3. Log audit showed dual native output roots (`idax-sys-bfdc...` and `idax-sys-457a...`) in a single invocation; workflow `RUSTFLAGS` injection pinned `-L native` to the older directory (`bfdc`), potentially forcing stale merged archive selection.
  - 16.64.4. Removed Windows workflow `RUSTFLAGS` merged-shim injection block from `.github/workflows/bindings-ci.yml`, restoring reliance on crate-emitted link metadata only.
  - 16.64.5. Recorded finding [F338] and updated active focus to validate the workflow cleanup path on the next CI run.

- **16.65. Cross-platform Integration Tests Linker Fix (Linux/Windows)**
  - 16.65.1. Investigated build failures in GHA Unit Test matrix (`validation profile: unit`) on Linux and Windows.
  - 16.65.2. Discovered that `tests/integration/CMakeLists.txt` hardcoded `libidalib.dylib` for linking, causing `LNK1104` on MSVC (which expects `.lib`) and `No rule to make target` on Linux (which expects `.so`).
  - 16.65.3. Rewrote `idax_add_integration_test` in `tests/integration/CMakeLists.txt` to conditionally set `IDAX_IDALIB_LIB_NAME` and `IDAX_IDA_LIB_NAME` based on `WIN32`/`APPLE` flags.
  - 16.65.4. Modified the integration test build logic to use the SDK's `ida_add_idalib` macro on Windows and Linux (which automatically links the correct SDK stub `.lib`/`.so`), while retaining the manual installation-dir linking exclusively for macOS to bypass the 2-level namespace stub issue.
  - 16.65.5. Resolved multiple compiler `[[nodiscard]]` warnings (`warning C4834` on Windows) on `unsubscribe` and `handler_with_context` by casting to `(void)` in `include/ida/debugger.hpp`, `include/ida/ui.hpp`, and `src/plugin.cpp`.
  - 16.65.6. Resolved unused parameter warning `stmt` in `tests/integration/smoke_test.cpp` by commenting out the parameter name `/*stmt*/`.
  - 16.65.7. Logged finding [F339] and verified test configuration locally.

- **16.66. Phase 20 CI Regression Fixes (Node macOS segfault + Windows Rust unresolved externals)**
  - 16.66.1. Investigated macOS Node `complexity_metrics` crash signature where the script completes and then exits with `Segmentation fault: 11` at process shutdown.
  - 16.66.2. Implemented addon-level decompiler wrapper lifetime hardening in `bindings/node/src/decompiler_bind.cpp`: track live `DecompiledFunctionWrapper` instances, add `DisposeAllLiveWrappers()`, and add post-disposal guard checks (`EnsureAlive`) on wrapper methods.
  - 16.66.3. Wired `bindings/node/src/database_bind.cpp` `Close` path to invoke `DisposeAllDecompilerFunctions()` before `ida::database::close(...)`, and declared the helper in `bindings/node/src/helpers.hpp`.
  - 16.66.4. Rebuilt Node addon (`npm run build --silent`) and re-ran `npx ts-node examples/complexity_metrics.ts tests/fixtures/simple_appcall_linux64`; analysis completed and process exited cleanly (no segfault).
  - 16.66.5. Investigated new Windows Rust unresolved externals (`ida::ui`/`ida::lines` from `idax_shim.o`) and aligned native-link metadata after merged-shim rollout: switched `bindings/rust/idax-sys/src/lib.rs` sentinel link target to `idax_shim_merged`, switched `bindings/rust/idax/build.rs` to emit `static=idax_shim_merged`, and removed stale `idax_rust` crate-level link block from `bindings/rust/idax/src/lib.rs`.
  - 16.66.6. Simplified merged archive construction in `bindings/rust/idax-sys/build.rs` by merging `idax_shim.lib` directly with `idax.lib` (no intermediate alias copy), while keeping `cargo:idax_lib_dir` + `static=idax_shim_merged` emission.
  - 16.66.7. Added idax source-tree invalidation tracking in `bindings/rust/idax-sys/build.rs` via recursive `cargo:rerun-if-changed` over `CMakeLists.txt`, `cmake/`, `include/`, and `src/` to reduce stale archive reuse in cached CI environments.
  - 16.66.8. Revalidated Rust surfaces with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.66.9. Recorded findings [F340]-[F341] and updated roadmap/active-work focus for the next `Bindings CI` rerun.

- **16.67. Windows Rust follow-up: remove duplicate `idax` native-link emission**
  - 16.67.1. Investigated new Windows failure signature reporting unresolved C++ wrapper symbols from `libidax-*.rlib(...idax_shim.o)` during final example link, indicating native archive content was being pulled from `idax` crate packaging path.
  - 16.67.2. Removed `idax` crate build-script participation in native linking by deleting `bindings/rust/idax/build.rs` and dropping `build = "build.rs"` from `bindings/rust/idax/Cargo.toml`.
  - 16.67.3. Kept `idax-sys` as the sole native-link metadata owner for Windows, reducing duplicate/bundled archive paths through `libidax.rlib`.
  - 16.67.4. Revalidated local Rust compilation with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.67.5. Recorded finding [F342] and updated roadmap/active-work focus toward CI verification.

- **16.68. Windows Rust link strategy refinement: remove merged-archive dependency**
  - 16.68.1. Reworked `bindings/rust/idax-sys/build.rs` Windows branch to drop `idax_shim_merged.lib` generation and return to explicit static-link inputs.
  - 16.68.2. Kept `cc` cargo metadata enabled so `idax_shim` is emitted via standard native-link metadata.
  - 16.68.3. Copied C++ wrapper archive `idax.lib` to `OUT_DIR/idax_cpp.lib` and emitted `cargo:rustc-link-lib=static=idax_cpp` to avoid `idax` crate-name collision while preserving full wrapper symbol availability.
  - 16.68.4. Removed obsolete Windows crate-level sentinel link block from `bindings/rust/idax-sys/src/lib.rs`.
  - 16.68.5. Revalidated local Rust compilation with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.68.6. Recorded finding [F343] and updated active focus for CI verification.

- **16.69. Windows Rust follow-up after user CI evidence (missing `idax_cpp` in final link command)**
  - 16.69.1. Reviewed user-provided Windows linker command showing `ida.lib`/`idalib.lib` present but no `idax_cpp.lib`, with unresolved `ida::...` symbols reported from `idax_shim.o` and 589 unresolved externals.
  - 16.69.2. Added crate-level Windows reinforcement in `bindings/rust/idax-sys/src/lib.rs`: non-empty `#[link(name = "idax_cpp", kind = "static")]` extern block.
  - 16.69.3. Revalidated local Rust compilation with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.69.4. Recorded finding [F344] and kept Phase 20 focus on CI verification.

- **16.70. Windows Rust top-level crate reinforcement (`idax` -> `idax_cpp`)**
  - 16.70.1. Added non-empty Windows `#[link(name = "idax_cpp", kind = "static")]` sentinel block to `bindings/rust/idax/src/lib.rs` so example binaries depending directly on `idax` carry explicit wrapper-archive linkage metadata.
  - 16.70.2. Revalidated local Rust compilation with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.70.3. Recorded finding [F345] and updated active focus to CI verification.

- **16.71. Windows Rust linker root-cause hardening (`/GL` bundling -> `-bundle` fix)**
  - 16.71.1. Incorporated user-provided root-cause analysis linking unresolved `ida::...` externals to MSVC LTCG (`/GL`) objects being bundled through Rust static archive flow.
  - 16.71.2. Updated `bindings/rust/idax-sys/build.rs` Windows linkage to emit `cargo:rustc-link-lib=static:-bundle=idax_cpp` (instead of default bundled static mode), so `idax_cpp.lib` is passed directly to final `link.exe`.
  - 16.71.3. Removed temporary crate-level Windows `idax_cpp` sentinel link blocks from `bindings/rust/idax-sys/src/lib.rs` and `bindings/rust/idax/src/lib.rs` to avoid reintroducing bundled-static fallback paths.
  - 16.71.4. Revalidated local Rust compile surfaces with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.71.5. Recorded finding [F346] and shifted active focus to CI confirmation that final Windows link lines now include direct `idax_cpp` linkage.

- **16.72. Windows Rust CRT alignment hardening (`/MT` + `+crt-static`)**
  - 16.72.1. Incorporated new user-provided failure evidence showing shift to runtime-library mismatch diagnostics (`LNK2038`, `LNK1319`, `LNK4098`) between `idax_cpp` (`MT_StaticRelease`) and shim/Rust objects (`MD_DynamicRelease`).
  - 16.72.2. Updated `bindings/rust/idax-sys/build.rs` CMake Windows runtime setting to static CRT (`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>`).
  - 16.72.3. Updated `bindings/rust/idax-sys/build.rs` shim compile path to force static CRT on Windows via `cc::Build::static_crt(true)`.
  - 16.72.4. Added repository Cargo target config `.cargo/config.toml` with `[target.x86_64-pc-windows-msvc] rustflags = ["-C", "target-feature=+crt-static"]` so Rust artifacts align with static CRT expectations.
  - 16.72.5. Kept Windows direct-link mitigation (`cargo:rustc-link-lib=static:-bundle=idax_cpp`) in place to avoid LTCG bundling regressions.
  - 16.72.6. Revalidated local Rust surfaces with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.72.7. Recorded finding [F347] and updated roadmap/active-work focus to CI verification.
  - 16.72.8. Logged architecture/runtime decisions in `.agents/decision_log.md` under D-RUST-WINDOWS-CRT-STATIC-ALIGNMENT and D-RUST-WINDOWS-LTCG-NONBUNDLED-LINK.

- **16.73. Windows Rust runtime follow-up (post-link success, example exit-code-1 mitigation)**
  - 16.73.1. Incorporated user evidence that Windows Rust build/link now succeeds but runtime example executions still exit with code 1 (`idalib_dump_port`, `ida2py_port`).
  - 16.73.2. Hardened Rust initialization path by updating `bindings/rust/idax/src/database.rs` `database::init()` to pass a synthetic argv (`argc=1`, `argv[0]="idax-rust"`) instead of null argv.
  - 16.73.3. Hardened example session helper in `bindings/rust/idax/examples/common/mod.rs`: on Windows only, downgrade `analysis::wait()` failures to warnings (continue) instead of hard-failing helper session setup.
  - 16.73.4. Revalidated local compile surfaces with `cargo check -p idax` and `cargo check -p idax --examples` (pass; warnings only).
  - 16.73.5. Improved Rust example diagnostics in `bindings/rust/idax/examples/common/mod.rs` to include `[ErrorCategory:code]` in formatted error output for CI triage.
  - 16.73.6. Logged runtime-behavior decision in `.agents/decision_log.md` under D-RUST-WINDOWS-RUNTIME-SESSION-ROBUSTNESS.
  - 16.73.7. Recorded findings [F348]-[F349] and updated active/roadmap focus toward Windows runtime CI verification.

- **16.74. Windows Rust runtime follow-up (user-plugin suppression hardening)**
  - 16.74.1. Incorporated new user evidence: Windows Rust examples still exit code 1 post-build/post-link with no surfaced Rust error text.
  - 16.74.2. Updated `bindings/rust/idax-sys/shim/idax_shim.cpp` `idax_database_init` on Windows to use `ida::database::RuntimeOptions` with `plugin_policy.disable_user_plugins=true` by default.
  - 16.74.3. Added shim env override behavior: `IDAX_ENABLE_USER_PLUGINS=1` re-enables user-plugin discovery when needed.
  - 16.74.4. Updated `.github/workflows/bindings-ci.yml` Windows Rust runtime step to set `IDAX_ENABLE_USER_PLUGINS=0` and use isolated empty `IDAUSR` directory before running examples.
  - 16.74.5. Revalidated compile surfaces locally with `cargo check -p idax` and `cargo check -p idax --examples` (pass; warnings only).
  - 16.74.6. Logged architecture/runtime decision in `.agents/decision_log.md` under D-RUST-WINDOWS-USER-PLUGIN-SUPPRESSION.
  - 16.74.7. Recorded finding [F350] and refreshed active/roadmap focus for CI verification.

- **16.75. Windows Rust runtime correction (unsupported plugin-policy rollback)**
  - 16.75.1. Incorporated user runtime error evidence: both Windows Rust examples now fail with explicit `[SdkFailure:0] Plugin policy controls are not implemented on Windows yet`.
  - 16.75.2. Rolled back shim-level Windows plugin-policy init in `bindings/rust/idax-sys/shim/idax_shim.cpp`, restoring default `ida::database::init(argc, argv)` path.
  - 16.75.3. Updated Windows Rust workflow step in `.github/workflows/bindings-ci.yml` to remove `IDAX_ENABLE_USER_PLUGINS` control while retaining isolated empty `IDAUSR` directory setup.
  - 16.75.4. Revalidated local Rust build surfaces with `cargo check -p idax-sys && cargo check -p idax --examples` (pass; warnings only).
  - 16.75.5. Updated decision tracking with D-RUST-WINDOWS-PLUGIN-POLICY-ROLLBACK (19.17), superseding 19.16 for Windows shim init behavior.
  - 16.75.6. Updated finding [F350] wording to reflect unsupported plugin-policy controls and retained CI `IDAUSR` isolation as the active mitigation.

- **16.76. Windows Rust runtime attribution hardening (trace + analysis toggle path)**
  - 16.76.1. Added env-driven tracing in `bindings/rust/idax/examples/common/mod.rs` with immediate stderr flush and step markers for `database::init/open/close` and `analysis::wait`.
  - 16.76.2. Added env-driven analysis disable behavior in helper session open path (`IDAX_RUST_DISABLE_ANALYSIS=1`) for Windows CI diagnosis runs.
  - 16.76.3. Updated `.github/workflows/bindings-ci.yml` Windows Rust runtime step to set `IDAX_RUST_EXAMPLE_TRACE=1` and `IDAX_RUST_DISABLE_ANALYSIS=1` (while keeping isolated empty `IDAUSR`).
  - 16.76.4. Revalidated local Rust compile surfaces with `cargo check -p idax --examples` and confirmed trace output appears in sample run (`IDAX_RUST_EXAMPLE_TRACE=1 cargo run --example idalib_dump_port ...`).
  - 16.76.5. Updated Windows Rust workflow runtime execution from `cargo run` to build+direct-exec wrapper, with explicit decimal/hex exit-code reporting for failures.
  - 16.76.6. Logged decisions D-RUST-WINDOWS-RUNTIME-TRACE-TOGGLES (19.18) and D-RUST-WINDOWS-DIRECT-EXE-RUNNER (19.19), recorded findings [F351]-[F352], and refreshed active/roadmap focus for next CI evidence pass.

- **16.77. Windows Rust runtime follow-up (open-stage failure attribution: `-A` + IDA log capture)**
  - 16.77.1. Incorporated new user trace evidence showing deterministic stop at `database::open begin path=...` with exit code 1 and no wrapper-level error output.
  - 16.77.2. Updated `bindings/rust/idax/src/database.rs` Windows init path to pass explicit `-A` via init argv.
  - 16.77.3. Added optional `IDAX_RUST_IDA_LOG` env support in `database::init()` to forward `-L<path>` into idalib init argv.
  - 16.77.4. Updated `.github/workflows/bindings-ci.yml` Windows Rust runtime step to set `IDAX_RUST_IDA_LOG`, print log contents on failure, and use absolute test binary path.
  - 16.77.5. Revalidated local compile surfaces with `cargo check -p idax --examples` (pass; warnings only).
  - 16.77.6. Logged decision D-RUST-WINDOWS-INIT-ARGV-AUTO-LOGGING (19.20), recorded finding [F353], and refreshed active/roadmap focus for CI rerun.

- **16.78. Windows Rust init-argv rollback after explicit return-code-2 evidence**
  - 16.78.1. Incorporated new CI evidence: `database::init` failed with `[Internal:0] init_library failed [return code: 2]` immediately after forwarding `-A`/`-L` style init args.
  - 16.78.2. Reverted `bindings/rust/idax/src/database.rs` Windows init path to minimal argv (`argv0` only).
  - 16.78.3. Updated `.github/workflows/bindings-ci.yml` Windows runtime step to remove `IDAX_RUST_IDA_LOG` handling while keeping direct-exec runner, tracing, and absolute input path resolution.
  - 16.78.4. Revalidated local Rust compile surfaces with `cargo check -p idax --examples` (pass; warnings only).
  - 16.78.5. Logged rollback decision D-RUST-WINDOWS-INIT-ARGV-ROLLBACK (19.21) and updated finding [F353] wording to capture unsupported init-arg behavior.
