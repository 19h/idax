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
- Phase 14: ~100% (idapcode port complete: Sleigh-backed custom-viewer plugin added, processor-context metadata wrappers expanded and later normalized through forward-compatible `ProcessorProfile`, optional third-party submodule build wiring added for idapcode-specific dependency flow, dedicated gap audit/docs synchronization completed, bidirectional linear-view/custom-viewer address sync added with cross-function follow + scroll polling, shortcut updated to avoid common SigMaker collision, and custom-viewer backing-state update path hardened to eliminate cross-function sync crash)
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
- Phase 26: 100% (Rust real-IDA main-thread harness complete: all idalib lifecycle and test operations execute sequentially on process main; filtered and complete runtime execution restored)
- Phase 27: 100% (deterministic comment append complete: wrapper-level newline composition and exact C++/Node/Rust read-back validation)
- Phase 28: 100% (typed IDB change-tracking event parity complete: high-value post-change notifications, binding convergence, event-wide callback-mutation isolation, and full validation)
- Phase 29: complete (fixed-width data definitions use checked element counts through zword with exact cross-binding evidence)
- Phase 30: complete (processor-aware tbyte/packed-real definition semantics)
- Phase 31: complete (opaque custom data type/format registration and creation lifecycle)
- Phase 32: complete (scoped hotkey lifecycle, deterministic action ownership, callback exception barriers, and DriverBuddy migration)
- Phase 33: complete (forward-compatible raw-plus-optional-typed processor profiles across C++/Node/Rust, corrected current-SDK ID provenance, exact conversion/equivalence evidence, and idapcode migration closure)
- Phase 34: complete (Intelligent Function Inliner real-plugin port plus Node/Rust decoded-operand access-mode parity)
- Phase 35: complete (IDAMagicStrings real-plugin port plus string-list/source-file/name-inventory parity and disposable native integration fixtures)
- Phase 36: complete (Auto Enum port plus metadata-preserving function-argument type edits and named operand-enum representations)
- Phase 37: complete (bounded Symless structure reconstruction plus owned maturity-explicit microcode graphs across C++/Node/Rust)
- Phase 38: complete (depth-bounded resolved direct-call argument/return propagation, explicit call analysis, and metadata-preserving return-type edits)
- Phase 39: complete (declarative direct allocator/wrapper discovery, fixed-size roots, metadata-preserving argument-name edits, and report/apply/reopen evidence)
- Phase 40: complete (exact argument-zero constructor/vtable roots, metadata-preserving UDT semantic flags, conservative semantic UDT materialization, and report/apply/reopen evidence)
- Phase 41: complete (opaque shifted-pointer metadata and evidence-bounded shifted argument application)
- Phase 42: complete (opaque local-type declaration classification and failure-atomic ordinal-preserving forward replacement)
- Phase 43: complete (opaque exact-member persistent informational references plus Symless report/apply/reopen integration)
- Phase 44: complete (opaque exact operand root/member paths, processor-register evidence, and Symless report/apply/reopen integration)
- Phase 45: complete (Symless database-resolved indirect-call propagation, fixed-pointer allocator discovery, and report/apply/reopen evidence)
- Phase 46: complete (Symless RTTI-adjusted vtable-load reachability and statically seeded virtual-method propagation)

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

---

### Phase 28 TODO Action Items (Typed IDB Change-Tracking Events)

- [x] P28.1 Add opaque typed C++ events for segment movement, function/type/operand updates, code/data creation, item destruction, extra comments, and local-type changes.
- [x] P28.2 Make event delivery stable when callbacks subscribe or unsubscribe during dispatch, including self-unsubscription and last-listener teardown.
- [x] P28.3 Mirror the new event kinds and payloads through Node and Rust without exposing SDK pointers, flags, or type encodings.
- [x] P28.4 Add compile-time, structural, and real-IDA mutation coverage for exact payload routing and callback-mutation behavior.
- [x] P28.5 Synchronize coverage/API/docs/findings/knowledge/decision/ledger/active-work records and run focused plus complete validation.

---

### Phase 29 TODO Action Items (Multi-Byte Data Definition Units)

- [x] P29.1 Convert element counts to checked byte lengths for byte/word/dword/qword/oword/yword/zword/tbyte/float/double definitions and add the missing fixed-width yword/zword surfaces.
- [x] P29.2 Add exact C++ tests for one element, multiple elements, zero/overflow rejection, and resulting item size.
- [x] P29.3 Add applicable Node/Rust runtime assertions and synchronize docs/protocol records.

---

### Phase 30 TODO Action Items (Processor-Aware Extended Reals)

- [x] P30.1 Resolve tbyte and packed-real availability/element width from active processor and assembler metadata.
- [x] P30.2 Correct `define_tbyte`, add `define_packed_real`, and expose explicit size queries without universal-width assumptions.
- [x] P30.3 Add C++/Node/Rust parity with supported/unsupported and exact item-size validation.
- [x] P30.4 Synchronize API/coverage/docs/findings/knowledge/decision/ledger/active-work records and run complete validation.

---

### Phase 31 TODO Action Items (Custom Data Type/Format Lifecycle)

- [x] P31.1 Audit custom data type/format descriptors, callbacks, registry IDs, attachment state, item-size inference, creation, and teardown semantics.
- [x] P31.2 Design opaque definitions/snapshots and callback adapters with explicit lifetime rules.
- [x] P31.3 Implement C++ APIs plus Node/Rust parity and exact fixed/variable-size real-IDA validation.
- [x] P31.4 Synchronize API/coverage/docs/findings/knowledge/decision/ledger/active-work records and run complete validation.

---

### Phase 32 TODO Action Items (Scoped Hotkey and Action Ownership)

- [x] P32.1 Audit the native action-handler ownership contract and the IDAPython `add_hotkey`/`del_hotkey` convenience lifecycle.
- [x] P32.2 Add a one-call opaque C++ scoped-hotkey API, deterministic handler ownership, and callback exception barriers.
- [x] P32.3 Add applicable Rust parity, migrate the DriverBuddy port, and validate exact registration/move/release behavior against real IDA.
- [x] P32.4 Synchronize API/coverage/docs/findings/knowledge/decision/ledger/active-work records and run complete validation.

---

### Phase 33 TODO Action Items (Forward-Compatible Processor Profile)

- [x] P33.1 Audit current SDK processor-ID provenance, unknown/third-party identity behavior, and idapcode context construction.
- [x] P33.2 Add normalized C++ processor profiles and correct typed-ID conversion without breaking legacy source references.
- [x] P33.3 Add Node/Rust parity, migrate idapcode adaptations, and add exact conversion plus real-IDA equivalence coverage.
- [x] P33.4 Synchronize API/coverage/port/docs/findings/knowledge/decision/ledger/active-work records and run complete validation.

---

### Phase 34 TODO Action Items (Intelligent Function Inliner Port)

- [x] P34.1 Audit the original IDAPython scoring/mutation workflow against C++ and Rust wrapper coverage.
- [x] P34.2 Preserve decoded-operand read/write access through Node and the Rust C ABI, with exact declarations/accessors/tests.
- [x] P34.3 Port the real plugin as a C++ action and a headless Rust adaptation with deterministic report/apply behavior.
- [x] P34.4 Add real-IDA evidence, synchronize API/coverage/port/docs/findings/knowledge/decision/ledger/active-work records, and run complete validation.

---

### Phase 35 TODO Action Items (IDAMagicStrings Port)

- [x] P35.1 Audit the original string/source/candidate/class workflow against current C++/Node/Rust wrapper coverage.
- [x] P35.2 Add opaque configurable string-list snapshots and source-file range metadata with exact cross-binding evidence.
- [x] P35.3 Port the complete non-NLTK analysis and rename workflows to an interactive C++ plugin and headless Rust adaptation.
- [x] P35.4 Add real-IDA evidence, synchronize API/coverage/port/docs/findings/knowledge/decision/ledger/active-work records, and run complete validation.

---

### Phase 36 TODO Action Items (Auto Enum Port)

- [x] P36.1 Audit the original global-prototype and per-call specialization workflows against current C++/Node/Rust wrapper coverage and authoritative SDK contracts.
- [x] P36.2 Add metadata-preserving function-argument type replacement and named operand-enum representation/readback with C++/Node/Rust parity.
- [x] P36.3 Port the Auto Enum analysis and explicit annotation workflows to an interactive C++ plugin and headless Rust adaptation.
- [x] P36.4 Add real-IDA evidence, synchronize API/coverage/port/docs/findings/knowledge/decision/ledger/active-work records, and run complete validation.

---

### Phase 37 TODO Action Items (Symless Structure Reconstruction Port)

- [x] P37.1 Audit the upstream microcode data-flow, pointer-access, structure-generation, vtable, and entry-point workflows against current C++/Node/Rust wrapper coverage and authoritative SDK contracts.
- [x] P37.2 Close each concrete opaque wrapper gap required by the selected reconstruction boundary, with C++/Node/Rust parity where the namespace is already cross-language.
- [x] P37.3 Port a source-audited, explicitly bounded Symless reconstruction workflow to an interactive C++ plugin and a headless Rust adaptation.
- [x] P37.4 Add real-IDA evidence, synchronize API/coverage/port/docs/findings/knowledge/decision/ledger/active-work records, and run complete validation.

---

### Phase 38 TODO Action Items (Symless Interprocedural Structure Propagation)

- [x] P38.1 Audit Symless direct-call argument flow, callee return recovery, recursion control, and prototype application against the owned microcode graph and authoritative SDK contracts.
- [x] P38.2 Add metadata-preserving function return-type replacement with C++/Node/Rust parity and exact preservation tests.
- [x] P38.3 Extend the C++ and Rust Symless adaptations with depth-bounded, cycle-safe direct-callee argument/return propagation and conservative shifted-site mutation rules.
- [x] P38.4 Add pure and real-IDA report/apply/reopen evidence, synchronize all protocol records and documentation, and run complete validation.

---

### Phase 39 TODO Action Items (Symless Allocator Seed and Wrapper Discovery)

- [x] P39.1 Audit Symless allocator configuration, static-size call classification, wrapper-return confirmation, recursive heir discovery, and allocator prototype mutation against current opaque APIs.
- [x] P39.2 Close each concrete C++/Node/Rust wrapper gap required by a bounded allocator-discovery surface, with exact SDK provenance and preservation tests.
- [x] P39.3 Extend the C++ and Rust Symless adaptations with declarative malloc/calloc/realloc seeds, cycle-safe wrapper discovery, and fixed-size allocation-root reconstruction.
- [x] P39.4 Add pure and real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 40 TODO Action Items (Symless Constructor and Vtable Root Discovery)

- [x] P40.1 Audit Symless constructor/vtable seed discovery, root-state injection, structure inheritance, and vftable materialization against current opaque APIs and SDK contracts.
- [x] P40.2 Close each concrete C++/Node/Rust wrapper gap required by a bounded constructor/vtable surface, with exact SDK provenance and preservation tests.
- [x] P40.3 Extend the C++ and Rust Symless adaptations with cycle-safe constructor/vtable root discovery and conservative report/apply behavior.
- [x] P40.4 Add pure and real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 41 TODO Action Items (Symless Shifted-Pointer Metadata)

- [x] P41.1 Audit upstream shifted-pointer construction/eligibility and local `ptr_type_data_t` contracts against current opaque C++/Node/Rust type surfaces.
- [x] P41.2 Add metadata-preserving shifted-pointer construction/introspection across C++, Node, and Rust with exact parent/delta and failure-atomicity tests.
- [x] P41.3 Apply explicit shifted parent/delta types to eligible propagated argument sites in both Symless adaptations while preserving shifted-return and incompatible-type exclusions.
- [x] P41.4 Add pure and real-IDA shifted report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 42 TODO Action Items (Symless Forward Local-Type Replacement)

- [x] P42.1 Audit upstream forward-declaration detection/replacement and local IDA named-type contracts against current opaque C++/Node/Rust type surfaces.
- [x] P42.2 Add explicit local-type declaration classification and failure-atomic forward replacement across C++, Node, and Rust with exact preservation/rejection evidence.
- [x] P42.3 Integrate forward-aware named UDT materialization into both Symless adaptations while preserving complete existing definitions and report/apply separation.
- [x] P42.4 Add real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 43 TODO Action Items (Symless Member-TID Informational Cross-References)

- [x] P43.1 Audit upstream member-TID xref generation and local IDA xref/type-member identity contracts against current opaque C++/Node/Rust surfaces.
- [x] P43.2 Add the minimum opaque member-identity/informational-xref capability across C++, Node, and Rust with exact validation and readback evidence.
- [x] P43.3 Integrate member-TID xrefs into both Symless adaptations while preserving report/apply separation and idempotence.
- [x] P43.4 Add real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 44 TODO Action Items (Symless Exact Operand Struct-Offset Paths)

- [x] P44.1 Audit upstream register-selected multi-component stroff generation and local IDA path/member contracts against the current C++/Node/Rust surfaces.
- [x] P44.2 Replace public native type-ID leakage with opaque copied path metadata and add conflict-safe exact-member stroff application plus processor-register evidence across C++, Node, and Rust.
- [x] P44.3 Integrate source-ordered exact operand stroff application into both Symless adaptations while preserving report/apply separation, additional-member references, and idempotence.
- [x] P44.4 Add real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 45 TODO Action Items (Symless Database-Resolved Indirect Calls)

- [x] P45.1 Audit upstream `m_icall` target provenance/resolution and local owned graph/data/function contracts against both Symless adaptations.
- [x] P45.2 Add source-equivalent database-derived memory-value propagation through move/address/load/extension/add/sub operations without conflating plain integers.
- [x] P45.3 Follow only exact function-entry indirect targets in ordinary and allocator-root propagation, with bounded recursion, report counters, and pure tests.
- [x] P45.4 Add a real indirect-call fixture and report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 46 TODO Action Items (Symless RTTI-Adjusted Vtable Propagation)

- [x] P46.1 Audit upstream vtable load-reference discovery and virtual-method root propagation against the current owned xref/data/microcode surfaces and both Symless adaptations.
- [x] P46.2 Add bounded direct/RTTI-label/data-alias constructor reachability with exact table-value store confirmation and deterministic accounting.
- [x] P46.3 Seed every accepted non-import vtable method at argument zero, merge its depth-bounded recovered fields into the class layout, and preserve existing conflict/application rules.
- [x] P46.4 Add pure and real-IDA RTTI report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---

### Phase 47 TODO Action Items (Symless Microcode Operand Root Selection)

- [x] P47.1 Audit upstream microcode operand enumeration, recursive instruction indexing, destination classification, and before/after root injection against the current owned graph and UI surfaces.
- [x] P47.2 Preserve exact destination-modification metadata across C++, Node, generated C ABI, and safe Rust with structural and live copy evidence.
- [x] P47.3 Add deterministic register/stack root enumeration, modal C++ selection, explicit Rust headless selection, and exact root-function-scoped before/after injection to both Symless adaptations.
- [x] P47.4 Add pure and real-IDA report/apply/reopen evidence, synchronize protocol records/documentation, run complete validation, staged review, and push.

---
