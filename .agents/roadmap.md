## 10) Phased TODO Roadmap (Exhaustive)

Legend:
- [ ] pending
- [~] in progress
- [x] done
- [!] blocked

Current overall phase status:
- Phase 0: ~100% (scaffold, build, test infra, examples tree, CMake install/export/CPack packaging all done)
- Phase 1: ~100% (core types, shared options, diagnostics/logging, core unit tests, API surface parity check all done)
- Phase 2: ~100% (address/data/database implemented; string extraction + typed helpers + binary pattern search; snapshots + file/memory load helpers; mutation safety tests; predicate search all done)
- Phase 3: ~100% (name, xref, comment, search, analysis implemented; dedicated behavior integration tests added for name/comment/xref/search)
- Phase 4: ~100% (segment, function w/chunks+callers+callees+frame+register variables, type w/struct+member+retrieve+type library, entry, fixup; type roundtrip+fixup relocation+edge-case tests all added; structural parity test done)
- Phase 5: ~100% (instruction/operand decode/text + full representation controls implemented; decode behavior + operand conversion + text snapshot tests added)
- Phase 6: ~100% (plugin includes action attach/detach + context-aware callbacks/docs; loader includes advanced archive/member/reload/save/move request models and typed flag helpers; processor includes output-context abstraction + advanced descriptor/assembler parity checks; sample modules and quickstart docs present; loader/processor scenario tests added)
- Phase 7: ~100% (debugger now includes typed event subscriptions; ui w/chooser+dialogs+timer+event subscriptions, graph w/object+flowchart+viewer+groups, event system now includes generic filtering/routing helpers; advanced validation tests added; all tested)
- Phase 8: ~100% (decompiler full: availability+decompile+pseudocode+variables+rename+ctree visitor+comments+address mapping+refresh; storage full w/blob operations; migration caveats docs added; all P8.4 tests passing)
- Phase 9: ~100% (P9.1 integration audits complete + all audit fixes applied; P9.2 documentation complete; P9.3 validation pass complete — 16/16 tests, CPack packaging verified; P9.4 release readiness complete — validation report, performance baseline)
- Phase 10: ~100% (P10.0 coverage governance/matrix completed; P10.1 core/cross-cutting parity hardening completed; P10.2 address/data/database closure completed; P10.3 segment/function/instruction closure completed; P10.4 metadata closure completed; P10.5 search/analysis closure completed; P10.6 module-authoring closure completed; P10.7.a debugger closure completed; P10.7.b ui closure completed; P10.7.c graph closure completed; P10.7.d decompiler closure completed; P10.7.e storage closure completed; P10.8.a-d docs/validation closure completed; P10.9.a-d exit checks completed; final closure summary recorded)
- Phase 11: ~100% (Abyss port API gap closure: lines domain created; decompiler event hooks + raw line access + expression nav + lvar extensions + item position lookup implemented; UI popup/rendering/widget-type/utility expansion implemented; abyss_port_plugin.cpp complete with all 8 filters; user-facing docs synchronized (README, docs index, namespace/coverage matrices, quickstart/examples, dedicated abyss audit); all targets build clean; 16/16 tests pass)
- Phase 11.x: ~100% (Example plugin entry point fix + database TU split: 5 plugins missing IDAX_PLUGIN macro fixed; database.cpp split into database.cpp + database_lifecycle.cpp to isolate idalib-only symbols from plugin link units; all 7 plugins + 3 loaders + 3 procmods build clean; 16/16 tests pass)
- Phase 12: ~100% (DrawIDA port complete: docked whiteboard plugin added with draw/text/erase/select + undo/redo/style/clear workflows; follow-up closed remaining ergonomic gaps via plugin export flags + typed widget-host helpers + dedicated Qt addon wiring)
- Phase 13: ~100% (DriverBuddy port complete: Windows-driver analysis plugin ported with driver classification, dispatch discovery, IOCTL decoding, WDF table annotation; added struct-offset write+readback wrappers, added `type::ensure_named_type`, expanded WDF schema to full 440-slot strict parity mode, synchronized coverage matrix/API docs, and recorded migration-gap audit)
- Phase 14: ~100% (idapcode port complete: Sleigh-backed custom-viewer plugin added, processor-context metadata wrappers expanded (`ProcessorId`, `processor`, `address_bitness`, `is_big_endian`, `abi_name`), optional third-party submodule build wiring added for idapcode-specific dependency flow, dedicated gap audit/docs synchronization completed, bidirectional linear-view/custom-viewer address sync added with cross-function follow + scroll polling, shortcut updated to avoid common SigMaker collision, and custom-viewer backing-state update path hardened to eliminate cross-function sync crash)
- Phase 15: ~100% (Rust binding API convergence batch 1 complete across shim + Rust wrappers for address/search/analysis/entry/comment/xref/segment/storage/lumina parity APIs; batch 2 completes `ida::type` parity with function/enum factories, deep introspection, member enumeration/mutation, operand-type retrieval, type-library import/unload, and opaque-handle clone/lifecycle parity; batch 3 completes full `ida::graph` convergence including group/layout/traversal parity, graph-viewer free functions, range-based flowchart construction, and callback-bridge parity for `show_graph`; batch 4 completes `ida::ui` convergence with ask-form/custom-viewer/widget-host+metadata/show-options parity, timer callback bridge, full UI/view event subscription parity (including generic + filtered routing), and popup/rendering callback/action bridges; batch 5 completes convergence for `ida::data`/`ida::database`/`ida::name`/`ida::fixup` with typed-value transfer ABI, binary/non-binary open + file/memory DB loads, compiler/import/snapshot transfer APIs, identifier validation/sanitization, and custom-fixup registration wrappers)
- Phase 15.x: ~100% (Rust binding API convergence batch 6 complete for `ida::function` + `ida::instruction`: function update/reanalyze/frame-variable/stack-variable/register-variable parity closed with explicit register-variable transfer ABI and free helpers; instruction operand-format/struct-offset/path-introspection/register-signature/toggle/next-prev parity closed with dedicated string-array free behavior; batch 7 complete for `ida::plugin` + `ida::event`: popup attach/detach + toolbar detach exposure, typed action-context host bridges, typed event subscription callback set, generic filtered event routing bridge, and Rust `Event` payload parity fields; batch 8 complete for `ida::loader`: `LoadFlags` encode/decode transfer ABI, helper parity (`file_to_database`, `memory_to_database`, `abort_load`), and runtime input-handle wrappers for size/tell/seek/read/read-at/read-string/filename; batch 9 complete for `ida::debugger`: full request/thread/register/appcall/executor/event-subscription parity including callback-bridge ABI and Rust lifecycle-safe context management; batch 10 complete for `ida::decompiler`: event subscription parity (`maturity`/`func_printed`/`refresh_pseudocode`/`curpos`/`create_hint` + `unsubscribe`), dirty/view helpers, raw pseudocode line editing helpers, item lookup/type naming, functional visitors, decompiled raw/microcode/variables/line-map exposure, and Rust-side lifecycle-safe callback/filter context management)
- Phase 15.y: ~100% (Rust processor-domain model parity update complete in `idax/src/processor.rs`: added full `ida::processor` data-model coverage (advanced assembler directives/options, processor flags, processor metadata fields, full switch-description shape, typed analyze/result/token models), added `OutputContext` token/text builder parity helpers, added trait-level processor callback contract with C++-aligned defaults, and cleaned Rust 2024 unsafe-ops warnings in debugger via `cargo fix`; `cargo build` now completes warning-free)
- Phase 16: ~100% (Vendored ida-sdk and ida-cmake using CMake `FetchContent`; added CMake support for defaulting to fetched SDKs and isolating artifact output to local `idabin` directory instead of modifying the SDK)
- Phase 17: ~100% (Consolidated per-port gap audits into `docs/port_gap_audit_examples.md`, removed old per-port audit files, synchronized README/api/quickstart/coverage-matrix references, and pruned resolved entries from `.agents/active_work.md`)
- Phase 18: ~100% (Scenario-driven documentation remediation complete: all 10 evaluated practical-use-case docs delivered, cross-cutting API-surface selection guide and scenario acceptance checklist mapping added, cookbook/traversal docs rebalanced to C++-first default presentation, and case-10 safety/perf guidance reframed as wrapper-vs-raw-SDK)
- Phase 19: 100% (examples-to-bindings continuation: Node tool-style ports added for `idalib_dump`/`idalib_lumina`/`ida2py`; Rust standalone adaptation set expanded with procmod + plugin-style standalone flows including `ida_names_port_plugin`, `qtform_renderer_plugin`, `driverbuddy_port_plugin`, and `abyss_port_plugin`; `jbc_full_loader` rewritten to actively mutate database layout instead of just printing text; TypeScript + Cargo example checks passing; Node addon runtime linkage repaired via rebuild with correct IDA install path; runtime matrix passes for Node tool examples and expanded Rust adaptation set including JBC rows via synthetic fixture validation; ported UI-constrained `idapcode` and `lifter` analysis slices to headless examples)
- Phase 20: 100% (real-IDA CI hardening complete: deterministic installer resolution, cross-platform SDK/runtime normalization, Node decompiler teardown safety, Windows Node/Rust link and runtime hardening, stable fixture-IDB execution, and full green `Bindings CI`/`Validation Matrix`/`Integrations CI` evidence)
- Phase 21: 100% (example loader port continuation: completed `sep_firmware_loader.cpp` as a full-functionality idax loader port of the Binary Ninja SEP firmware plugin, covering SEP firmware detection, module-table parsing, Mach-O/raw module mapping, shared-library slide handling, header/load-command annotations, firmware type definitions/application, pointer rewrite passes, entry registration, symbol import, and example build/docs wiring)
- Phase 22: ~99% (ida-cdump parity closure in progress: wait-box UI, multiline text, typed-form C++ bindings/FormBuilder plus fixed-shape Node/Rust typed-form entrypoints, optional Qt clipboard helpers with Node/Rust wrappers and an IDA-compatible `QT_NAMESPACE=QT` build gate, IDB path, portable path helpers, Hex-Rays popup-population events, scoped Hex-Rays ownership, Local Types action-context type references, lvar/prototype metadata helpers, read-only ctree migration helpers, bulk local type declaration import, host-gated runtime harness and runner script including Hex-Rays scoped-session runtime evidence, compact parity probe example, Qt example build bridge, Node native build/runtime validation, and Rust high-level no-run validation are implemented; the updated remaining queue is interactive modal form and Qt clipboard evidence)
- Phase 23: 100% (ida-trida port parity complete: plugin shell ported to idax actions/forms/wait-box/path/clipboard helpers, GitHub Actions build matrix added, rich `ida::type` layout/function/enum metadata API implemented in C++ with Node/Rust binding surfaces, trida generator migrated off direct `typeinf.hpp` use, docs/agent notes updated, and focused C++/Node/Rust/trida validation passed)
- Phase 24: 100% (IDA-names ergonomic parity complete: stable active-widget polling, exact Hex-Rays pseudocode-switch events, arbitrary-symbol demangling, Node/Rust parity, and Qt-host title migration)
- Phase 25: 100% (action-attachment state hardening complete: deterministic menu/toolbar detach contracts, lifecycle cleanup, and 25/25 CTest recovery)

### Phase 18 TODO Action Items (Complete)

- [x] P18.0 Review 10 practical use cases and classify remediation by deliverable type and priority.
- [x] P18.1 Expand cookbook coverage for foundational workflows (cases 1, 4, 5) with complete setup/error-handling snippets.
- [x] P18.2 Add an end-to-end instruction-analysis recipe for mnemonic-at-address workflows (case 2), including database load, address lookup, decode failure handling, and operand inspection.
- [x] P18.3 Add a Rust plugin example + guide for cross-reference analysis (`refs_to`) with plugin lifecycle wiring (case 3).
- [x] P18.4 Add a call-graph traversal recipe/tutorial (case 6) showing transitive caller discovery with visited-set cycle protection and optional depth limits.
- [x] P18.5 Add an event-hooking tutorial for new-function discovery workflows (case 8) with callback signatures, subscription lifetime management, and teardown unsubscribe patterns.
- [x] P18.6 Add an advanced multi-binary signature-generation tutorial (case 7) covering pattern extraction, normalization/wildcards, similarity comparison, and output schema guidance.
- [x] P18.7 Add distributed-analysis architecture guidance (case 9) documenting single-writer IDB constraints, shard/merge patterns, and consistency-safe orchestration.
- [x] P18.8 Add safety/performance guidance (case 10) comparing `idax` wrapper usage vs direct raw IDA SDK usage, including trade-offs and inconsistent-SDK-state recovery playbook.
- [x] P18.9 Run a documentation information-architecture cleanup pass that clearly separates safe Rust APIs, C++ wrapper APIs, and raw FFI surfaces to reduce cross-layer confusion.
- [x] P18.10 Extend `docs/docs_completeness_checklist.md` with scenario-based acceptance criteria requiring each practical use case to map to a runnable recipe/example/tutorial.

### Phase 19 TODO Action Items (Examples-to-Bindings Continuation)

- [x] P19.1 Audit current source-example inventory vs Rust/Node binding examples and classify what is headless/standalone-portable.
- [x] P19.2 Add Node standalone tool-style ports for idalib-expressible workflows (`idalib_dump_port`, `idalib_lumina_port`, `ida2py_port`).
- [x] P19.3 Expand Rust standalone adaptation examples for processor/loader workflows (`minimal_procmod`, `advanced_procmod`, `jbc_full_loader`, `jbc_full_procmod`).
- [x] P19.4 Continue porting remaining feasible Rust adaptations for plugin/procmod/loader examples that can be represented without host plugin entrypoint macros (including `idapcode_headless_port` and `lifter_headless_port`).
- [x] P19.5 Add/refresh per-example README mapping that labels each source example as direct port, adapted standalone port, or host-constrained/not-applicable.
- [x] P19.6 Run deeper runtime validations on a known-good idalib host for newly added tool/adaptation examples and capture pass/fail matrix.

---

### Phase 21 TODO Action Items (Example Loader Port Continuation)

- [x] P21.1 Port `<userhome>/Downloads/sep-binja-main` SEP firmware Binary Ninja loader into a native idax example loader.
- [x] P21.2 Wire the new loader into `examples/CMakeLists.txt` and document it in `examples/README.md`.
- [x] P21.3 Validate the new example loader builds cleanly as `idax_sep_firmware_loader`.

---

### Phase 20 TODO Action Items (Real-IDA CI Hardening)

- [x] P20.1 Fix Node bindings workflow example invocation to pass only expected CLI arguments.
- [x] P20.2 Avoid Windows debug CRT link failures in Rust bindings workflow by building/running examples in `--release`.
- [x] P20.3 Harden Node Windows linkage discovery so MSVC import libs are resolved from `IDASDK` even when `IDADIR` is present.
- [x] P20.4 Fix Windows workflow shell/runtime routing so Rust uses MSVC `link.exe` (not `/usr/bin/link`) and examples resolve IDA DLLs via `PATH`.
- [x] P20.5 Re-run `Bindings CI` matrix and close residual runtime/linking regressions. (`Bindings CI`, `Validation Matrix`, and `Integrations CI` all passed for `fe028da7163d77519262f95762edd4b8564806dc` on 2026-05-31.)
- [x] P20.6 Close `ida::database::set_address_bitness` parity across C++ API surface checks, Node/Rust bindings, and docs/agent catalogs.
- [x] P20.7 Close `MicrocodeContext` introspection parity across Node/Rust bindings and documentation/catalog surfaces.

---

### Phase 22 TODO Action Items (ida-cdump Parity Closure)

- [~] P22.1 Add typed `ida::ui::ask_form` bindings and a compile-time typed `FormBuilder`. (C++ API, Node/Rust fixed-entrypoint bindings, and host-gated modal test path landed; interactive host execution remains pending.)
- [x] P22.2 Add `ida::ui::WaitBox` RAII progress/cancellation helpers.
- [x] P22.3 Expose Hex-Rays `hxe_populating_popup` as `ida::decompiler::on_populating_popup`.
- [x] P22.4 Add Local Types `TypeRef` payload support to `ida::plugin::ActionContext`.
- [~] P22.5 Add Qt clipboard, multiline `ask_text`, `database::idb_path`, and path-helper coverage. (`ask_text`, `idb_path`, `ida::path`, optional Qt clipboard helpers, Node/Rust wrappers for clipboard/text/path helpers, host-gated clipboard test path, Qt header bridge, and `QT_NAMESPACE=QT` configure guard landed; Qt UI-host execution remains pending.)
- [x] P22.6 Add Hex-Rays lvar-settings snapshot/writeback, lvar comment writeback, and function prototype apply APIs.
- [x] P22.7 Add read-only ctree migration helpers needed by `ida-cdump` analysis.
- [x] P22.8 Update docs/examples/tests and map each `ida-cdump` gap row to the new idax API. (`docs/codedump_migration_checklist.md` maps every updated gap row; compact parity probe example, local validation, Node native/runtime validation, and Rust no-run validation landed.)
- [x] P22.9 Add a scoped Hex-Rays initialization/lifetime helper for plugin-host ownership. (C++ API, Node/Rust owned-session wrappers, example lifecycle coverage, and `IDAX_RUN_HEXRAYS_SESSION=1` host runtime execution pass.)
- [x] P22.10 Add bulk local type declaration import over SDK `parse_decls` for `ida-cdump` metadata-apply migration, with Node/Rust wrappers.

---

### Phase 23 TODO Action Items (ida-trida Port Parity)

- [x] P23.1 Port `<dev-root_>/ida-trida` build/plugin shell to consume `idax::idax` instead of vendored ida-cmake and raw SDK UI/action/clipboard helpers.
- [x] P23.2 Add ida-trida GitHub Actions build coverage with Linux, macOS x86_64, macOS arm64, and Windows plugin artifact jobs.
- [x] P23.3 Add rich C++ `ida::type` metadata needed by trida (`TypeKind`, named declarations, function details, enum details, UDT layout/member bit offsets and flags) with API-surface and integration coverage.
- [x] P23.4 Mirror the rich type metadata through Node and Rust binding surfaces, with structural/no-run tests that respect host initialization constraints.
- [x] P23.5 Port trida's Frida generator from direct SDK `typeinf.hpp` layout walking to opaque idax type APIs.
- [x] P23.6 Refresh docs/validation notes and run final focused idax + trida validation.

---

### Phase 24 TODO Action Items (IDA-names Ergonomic Parity)

- [x] P24.1 Add opaque `ida::ui::current_widget()` polling over SDK `get_current_widget()`.
- [x] P24.2 Add `ida::decompiler::on_switch_pseudocode()` over `hxe_switch_pseudocode`.
- [x] P24.3 Add context-free arbitrary-symbol demangling with short/long/full output forms.
- [x] P24.4 Mirror applicable APIs through Node and Rust bindings with structural/runtime tests.
- [x] P24.5 Update the IDA-names example port to consume the new APIs and remove event-tracking workarounds.
- [x] P24.6 Synchronize coverage/docs/agent records and run focused plus full validation. (Focused C++ 4/4, Node 184/184 + 65/65, Rust 127/127; full C++ sweep exposed independent F370, tracked for the next semantic fix.)

---

### Phase 25 TODO Action Items (Action Attachment State Hardening)

- [x] P25.1 Track successful idax menu/toolbar attachments independently of ambiguous SDK detach return values.
- [x] P25.2 Preserve deterministic `NotFound` behavior for missing or already-consumed wrapper-managed attachments.
- [x] P25.3 Add real registration/attach/detach lifecycle coverage and rerun the complete C++ suite.
- [x] P25.4 Synchronize API docs, findings/knowledge, decisions, validation evidence, ledger, roadmap, and active-work state.

---

### Phase 26 TODO Action Items (Rust Real-IDA Main-Thread Harness)

- [x] P26.1 Replace the Rust real-IDA integration target's standard libtest harness with a sequential process-main-thread runner.
- [x] P26.2 Preserve filtered-test selection, skip behavior without `IDADIR`, panic reporting, and deterministic one-session cleanup.
- [x] P26.3 Validate filtered and complete real-IDA Rust integration runs on the current macOS IDA 9.3 host. (Formerly stalled filter passes 1/1; complete execution terminates at 82/83 with independent comment-append defect F374 promoted to Phase 27.)
- [x] P26.4 Synchronize binding documentation, findings/knowledge, decisions, validation evidence, ledger, roadmap, and active-work state.

---

### Phase 27 TODO Action Items (Deterministic Comment Append)

- [x] P27.1 Implement observable newline-delimited append semantics through wrapper-level read/compose/write behavior.
- [x] P27.2 Strengthen C++, Node, and Rust real-IDA assertions at function-start comment storage.
- [x] P27.3 Validate focused and complete C++, Node real-IDA, Rust filtered, and complete Rust real-IDA suites.
- [x] P27.4 Synchronize API documentation, findings/knowledge, decisions, validation evidence, ledger, roadmap, and active-work state.
