## 16) In-Progress and Immediate Next Actions

> **Tracking Policy:** This list tracks *active* and *queued* work items only. Once an item reaches completion (pass evidence recorded, docs updated, ledger entry written), it **must be removed** from this list and migrated to the Progress Ledger KB. Stale entries degrade signal - prune aggressively.

---

### 1. CI & Validation Infrastructure

- **1.1. GitHub Actions Matrix (Default Path)**
  - 1.1.1. **Action:** Keep `.github/workflows/validation-matrix.yml` as default cross-OS evidence path.
  - 1.1.2. **Scope:** `compile-only` + `unit` on every release-significant change.
  - 1.1.3. **Status:** Active / ongoing.

- **1.2. Host-Specific Hardening**
  - 1.2.1. **Action:** Continue host-specific hardening runs where licenses/toolchains permit.
  - **1.2.2. Linux**
    - 1.2.2.1. Keep Clang 19 as baseline evidence.
    - 1.2.2.2. Execute `full` rows with runtime installs when available.
  - **1.2.3. Windows**
    - 1.2.3.1. Execute `full` rows with runtime installs when available.
  - 1.2.4. **Status:** Ongoing / license-gated.

- **1.3. Real-IDA Bindings CI Stabilization (Phase 20)**
  - 1.3.1. **Action:** Re-run `Bindings CI` after latest workflow/CMake fixes.
- 1.3.2. **Completed this pass:** corrected Node example argv shape, enabled MSVC import-lib fallback even when `IDADIR` is set, moved Windows Rust build/run to PowerShell (MSVC-native linker path), added Windows `PATH` runtime propagation for Node/Rust examples, aliased Rust native static lib link target to `idax_rust`, exported `DEP_IDAX_*` metadata from `idax-sys`, added `idax` crate build-script re-linking, added explicit `#[link(name = "idax_rust", kind = "static")]` in `idax-sys` and `idax`, converted those `#[link]` blocks to non-empty sentinel extern declarations, then implemented a merged Windows shim strategy in `idax-sys/build.rs` (`idax_shim.lib` + `idax_rust.lib` -> `idax_shim_merged.lib` via `lib.exe`) and switched Windows native link output to `static=idax_shim_merged`.
- 1.3.3. **Latest evidence:** build/link now passes on Windows Rust; runtime example invocations surface explicit `SdkFailure: Plugin policy controls are not implemented on Windows yet` after the prior shim plugin-policy change.
- 1.3.4. **Remaining focus:** rerun `Bindings CI` with corrected Windows runtime mitigations (rollback unsupported shim plugin-policy init path; retain isolated empty `IDAUSR`) plus trace toggles/direct exec and fixture-IDB input (`tests/fixtures/simple_appcall_linux64.i64`) instead of raw PE loader path.
  - 1.3.5. **Status:** In progress.

---

### 2. JBC & Processor Module Parity

- **2.1. Validation Continuation**
  - 2.1.1. **Action:** Continue validating JBC parity APIs against additional real-world procmod ports.
  - 2.1.2. **Scope:** Expand typed analyze/output metadata only when concrete migration evidence requires deeper fidelity.
  - 2.1.3. **Status:** Ongoing / evidence-driven.

---

### 3. Lumina Hardening

- **3.1. Beyond Pull/Push Baseline**
  - 3.1.1. **Action:** Keep hardening `ida::lumina` behavior beyond now-passing pull/push smoke baseline.
  - 3.1.2. **Focus:** Close/disconnect semantics once portable runtime symbols are confirmed.
  - 3.1.3. **Blocker:** Runtime dylibs do not export `close_server_connection2`/`close_server_connections`.
  - 3.1.4. **Status:** Blocked on runtime symbol availability.

---

### 4. Appcall Runtime Evidence

- **4.1. Debugger-Capable Host Execution**
  - 4.1.1. **Action:** Execute `docs/appcall_runtime_validation.md` on a debugger-capable host.
  - **4.1.2. Current Block State**
    - 4.1.2.1. Backend loads successfully.
    - 4.1.2.2. `start_process` returns `0` + still `NoProcess`.
    - 4.1.2.3. `request_start` -> no-process.
    - 4.1.2.4. `attach_process` returns `-1` + still `NoProcess`.
    - 4.1.2.5. `request_attach` -> no-process.
  - 4.1.3. **Goal:** Convert block into pass evidence.
  - 4.1.4. **Follow-Up:** Expand Appcall argument/return kind coverage only where concrete ports require additional fidelity.
  - 4.1.5. **Status:** Blocked on debugger-capable host.

---

### 5. IDA-names Port Ergonomic Gaps (Pending Triage)

- **5.1. API Gaps Discovered During Porting**
  - 5.1.1. `ida::ui` lacks a high-level `current_widget()` polling API. `ida_kernwin.get_current_widget()` has no idax equivalent; plugin authors must manually subscribe to `on_current_widget_changed` to track the active view.
  - 5.1.2. `ida::decompiler` lacks an `on_switch_pseudocode` subscription (wrapping `hxe_switch_pseudocode`). The port worked around this using `on_screen_ea_changed` and `on_current_widget_changed`.
  - 5.1.3. `ida::name::demangled` requires an `ida::Address` context. The SDK's bare string demangler `demangle_name(const char*)` is not exposed, forcing plugins to use the address-based lookup rather than demangling an arbitrary string in memory.
  - 5.1.4. `ida::ui::Widget` lacks a `set_title()` method. (Note: The IDA SDK itself lacks `set_widget_title`; in idax this is bridged through `ida::ui::with_widget_host_as<QWidget>` when Qt-level control is needed.)
  - 5.1.5. **Action:** Evaluate adding `current_widget()`, `on_switch_pseudocode`, and a string-only `demangled(string_view)` overload to close these ergonomic gaps.
  - 5.1.6. **Status:** Pending triage.

---

### 6. ida-cdump Parity Closure (Phase 22)

- **6.1. Task Plan**
  - 6.1.1. **Action:** Implement the concrete parity tasks documented in `docs/codedump_parity_tasks.md`.
  - 6.1.2. **Completed this pass:** first low-risk helper slice: `ida::ui::WaitBox`, `ida::ui::ask_text`, `ida::database::idb_path`, and `ida::path::{basename, dirname, is_directory}` with C++ surface/smoke coverage and Node/Rust `database::idb_path` plus path-helper bindings; second slice: `ida::decompiler::on_populating_popup` over Hex-Rays `hxe_populating_popup` with Node/Rust callback bindings and `abyss_port_plugin` example coverage; third slice: `ida::plugin::ActionContext::type_ref` with owned `TypeRef` snapshots and Rust FFI/safe binding coverage; fourth slice: lvar snapshots, variable comment writeback, and function prototype apply helpers with C++ plus Node/Rust binding coverage.
  - 6.1.3. **Gap notes refreshed:** `<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md` now confirms already-closed rows for wait-boxes, popup events, Local Types `type_ref`, lvar/prototype metadata, multiline text, IDB path, path helpers, read-only ctree analysis helpers, and bulk local type declaration import; remaining idax parity work is typed-form runtime evidence and Qt clipboard runtime evidence.
  - 6.1.4. **Completed this pass:** P22.7 C++ read-only ctree helpers (`ExpressionView::helper_name`, `type_declaration`, parent snapshots, `StatementView` parent snapshots, `LocalVariable::index`, `DecompiledFunction::variable(index)`) plus focused integration/API coverage, Node/Rust local-variable index/direct-lookup exposure, Rust visitor payload expansion, and Node synchronous ctree visitor methods carrying helper/type/parent metadata.
  - 6.1.5. **Completed this pass:** P22.1 C++ typed form surface: direct binding factories, SDK-buffer adapters, variadic template `ask_form`, compile-time `FormBuilder`, API surface coverage, and non-modal unit coverage for numeric/address/path adapter prepare/commit validation.
  - 6.1.6. **Completed this pass:** P22.5 clipboard surface: optional `IDAX_ENABLE_QT_CLIPBOARD` build flag, `copy_to_clipboard`, `read_clipboard`, and `clipboard_backend` with Qt backend when enabled and structured `Unsupported` errors otherwise, plus Node/Rust wrappers for the same helpers.
  - 6.1.7. **Completed this pass:** P22.9 C++ scoped Hex-Rays ownership via `ida::decompiler::initialize()` and move-only `ScopedSession`, with a separate owned-session refcount that preserves existing non-owning `available()` behavior.
  - 6.1.8. **Completed this pass:** P22.10 bulk local type declaration import via `ida::type::parse_declarations`, `ParseDeclarationsOptions`, `ParseDeclarationsReport`, C++ integration/API coverage, Node `type.parseDeclarations`, and Rust shim/safe wrappers.
  - 6.1.9. **Completed this pass:** P22.9 example lifecycle coverage: `examples/plugin/abyss_port_plugin.cpp` now acquires `ida::decompiler::ScopedSession` with `initialize()` during plugin init and releases it after teardown; `docs/quickstart/plugin.md` documents the pattern.
  - 6.1.10. **Completed this pass:** P22.1 Node/Rust fixed-entrypoint typed-form bindings for the audited codedump dialog shapes: `(sval,bitset)`, `(sval,path,bitset)`, `(path,bitset)`, `(radio,sval,path,bitset)`, and `(sval,sval,sval,path,bitset,bitset)`.
  - 6.1.11. **Completed this pass:** Added `codedump_parity_host_gates` integration coverage with deterministic default skips and opt-in runtime paths for modal typed forms (`IDAX_RUN_MODAL_FORMS=1`), Qt clipboard (`IDAX_RUN_QT_CLIPBOARD=1`), and scoped Hex-Rays ownership (`IDAX_RUN_HEXRAYS_SESSION=1`).
  - 6.1.12. **Completed this pass:** Added `examples/plugin/codedump_parity_probe_plugin.cpp`, a compact independent example covering typed forms, wait boxes, clipboard fallback, scoped Hex-Rays ownership, pseudocode popup attachment, Local Types `type_ref`, lvar snapshots, and prototype reapply.
  - 6.1.13. **Remaining scope:** interactive host execution evidence for the gated modal form and Qt clipboard paths. The local Node native-build and Rust generated-layout blockers are resolved, and the Hex-Rays scoped-session host gate passes locally.
  - 6.1.14. **Concrete queue established:** `docs/codedump_parity_tasks.md` now assigns file-scoped implementation tasks, binding posture, acceptance checks, and validation targets for the remaining P22 host-evidence work.
  - 6.1.15. **Migration checklist added:** `docs/codedump_migration_checklist.md` maps every updated `IDAX_GAPS.md` row to an idax API, status, binding posture, caveat, and residual task; it also records the concrete codedump dialog vararg signatures.
  - 6.1.16. **Example build blocker closed:** Qt-heavy `qtform_renderer` and `drawida` widgets now mount through non-Qt bridge headers so plugin glue avoids Qt/IDA `q*` helper conflicts; both Qt plugin targets build in `build-examples-fetch`.
  - 6.1.17. **Binding validation blocker closed:** Rust bindgen output for recursive microcode instructions is patched during generation, `cargo test -p idax --lib --no-run` and the type-declaration integration no-run target pass, Node native build passes on Node 26 with NAN 2.27, and Node unit/integration tests load the native addon successfully.
  - 6.1.18. **Qt clipboard build gate clarified:** enabling `IDAX_ENABLE_QT_CLIPBOARD` now rejects plain system Qt and requires an IDA-compatible Qt package built with `QT_NAMESPACE=QT`; the Qt bridge lives outside IDA SDK translation units to avoid `q*` helper conflicts.
  - 6.1.19. **Host-gate runner added:** `scripts/run_codedump_parity_host_gates.sh` now configures, builds, and runs the parity host-gate executable with the documented modal, Qt clipboard, and Qt package environment toggles.
  - 6.1.20. **Rust UI binding evidence tightened:** Rust unit no-run coverage now verifies the fixed typed-form result structs/function signatures and clipboard helper signatures, and the Rust qtform renderer adaptation no longer claims `ui::ask_form` is unavailable.
  - 6.1.21. **Node UI binding evidence tightened:** Node native unit coverage now exercises default unsupported clipboard errors and empty-markup validation failures for every fixed typed-form entrypoint without opening modal UI.
  - 6.1.22. **Multiline text binding parity tightened:** Node and Rust now expose the `ask_text`/`askText` clipboard-fallback dialog wrapper; tests cover signatures/options without opening the host-modal UI.
  - 6.1.23. **Wait-box binding parity tightened:** Node and Rust now expose owned wait-box wrappers with update/cancel/dismiss/active methods; tests verify the surface without opening host UI.
  - 6.1.24. **Path helper binding parity tightened:** Node and Rust now expose `ida::path` basename/dirname/directory helpers; tests run the pure helper behavior locally.
  - 6.1.25. **Scoped Hex-Rays session binding parity tightened:** Node and Rust now expose owned scoped-session wrappers over `ida::decompiler::initialize()`; tests verify the binding surface without requiring Hex-Rays runtime ownership.
  - 6.1.26. **Host-gate evidence refreshed:** The default codedump parity host-gate runner passes with expected skips, and the locally available Hex-Rays scoped-session gate passes with 9 checks and no failures after the binding closures.
  - 6.1.27. **Focused C++ parity validation refreshed:** `idax_api_surface_check`, `idax_unit_test`, and `codedump_parity_host_gates` build and pass under the selected CTest filter after the latest binding/doc closures.
  - 6.1.28. **Concrete task/evidence map established:** `docs/codedump_parity_tasks.md` now names the idax implementation work items for each updated `IDAX_GAPS.md` row, including primary files, binding posture, and exit conditions; `docs/codedump_migration_checklist.md` now maps each row to C++ proof, binding proof, and any remaining host gate.
  - 6.1.29. **Rust lvar/prototype binding evidence tightened:** Rust unit signature checks now directly cover function prototype apply, lvar snapshot capture/restore on `DecompiledFunction` and `DecompilerView`, variable comment setters, and `LvarSnapshot` accessors.
  - 6.1.30. **Node decompiler metadata binding evidence tightened:** Node fixture integration now asserts P22 decompiled-function metadata/snapshot methods and `LvarSnapshot` accessors on a real decompiled function when Hex-Rays is available.
  - 6.1.31. **Bulk declaration binding evidence tightened:** Node unit coverage now checks `type.parseDeclarations` validation behavior, and Rust unit coverage directly checks `types::parse_declarations` signatures/options/report semantics.
  - 6.1.32. **Hex-Rays popup binding evidence tightened:** Node unit coverage now validates `onPopulatingPopup` callback arguments, and Rust unit coverage asserts the callback signature plus payload defaults.
  - 6.1.33. **Read-only ctree binding evidence tightened:** Node fixture integration now inspects ctree callback payload fields and stable local-variable lookup on a real decompiled function, while Rust unit coverage asserts callback payload structs and visitor signatures.
  - 6.1.34. **Local Types binding evidence tightened:** Rust plugin tests now cover safe `TypeRef` construction and the action-context FFI shape used to carry `type_ref` names through context-aware callbacks.
  - 6.1.35. **Rust clipboard binding evidence tightened:** Rust UI wrappers now preserve the default unsupported clipboard category even when the FFI error slot is empty, and tests cover embedded-NUL validation plus unsupported read/write behavior.
  - 6.1.36. **Rust typed-form validation evidence tightened:** Rust fixed typed-form wrappers now reject empty markup as `Validation` before entering modal/FFI paths, and tests cover every audited ida-cdump binding shape.
  - 6.1.37. **P22.V1 local validation refreshed:** Focused C++ parity tests, host-gate default and Hex-Rays modes, Node native build/unit/integration, and Rust high-level no-run plus typed-form validation all pass locally.
  - 6.1.38. **Host evidence workflow hardened:** Added `docs/codedump_host_evidence.md`, runner evidence-log support, and an early Qt clipboard preflight that requires `IDAX_QT6_DIR` before attempting a Qt runtime gate.
  - 6.1.39. **Binding documentation parity refreshed:** Node agent docs and the Rust README now explicitly document fixed typed forms, wait boxes, clipboard backend behavior, popup events, lvar snapshots, ctree callbacks, bulk declaration import, IDB path, and path helper parity surfaces.
  - 6.1.40. **Host evidence verifier added:** `scripts/check_codedump_parity_evidence_log.sh` now mechanically checks default, Hex-Rays, modal, and Qt clipboard evidence logs so skipped or missing host-gate sections cannot be mistaken for closure evidence; it also enforces the default clipboard-backend section and minimum per-gate pass counts. Its `--self-test` covers default/Hex-Rays pass cases, combined host-gate pass cases, failed summaries, contaminated mixed failed+successful summaries, unknown gate names, skipped/unskipped/missing/weak modal and Qt clipboard sections, missing default clipboard evidence, skipped/weak/missing Hex-Rays evidence, and missing Hex-Rays sections.
  - 6.1.41. **Host-gate runner preflight tightened:** `scripts/run_codedump_parity_host_gates.sh` now resolves the fixture before configure/build work and fails early when `IDAX_RUN_HEXRAYS_SESSION=1` points at a missing fixture.
  - 6.1.42. **Host-gate runner auto-verification added:** when `IDAX_EVIDENCE_LOG` is set, `scripts/run_codedump_parity_host_gates.sh` infers the enabled gate modes and runs the evidence-log verifier after the capture stream closes, appending the verifier result to the same log; the runner now has a lightweight `--self-test` for default and combined mode inference plus no-build Qt/Hex-Rays preflight failures.
  - 6.1.43. **Hex-Rays auto-verifying evidence refreshed:** the locally available `IDAX_RUN_HEXRAYS_SESSION=1` path passes through the current race-free logged runner and appends `hexrays` verifier output to `build-codedump-parity-host/codedump-host-hexrays.log`.
  - 6.1.44. **Local validation runner added:** `scripts/run_codedump_parity_local_validation.sh` now refreshes focused C++, default host-gate/verifier, the compact parity probe example build, Node, optional Node integration, and Rust parity evidence with fixture restoration; the current sweep passes locally with Node integration enabled after the composable verifier and race-free logged runner changes.
  - 6.1.45. **Modal evidence semantics tightened:** `codedump_parity_host_gates` now requires the codedump-shaped modal form to be accepted when `IDAX_RUN_MODAL_FORMS=1` is set, so a cancelled dialog cannot close P22.H1.
  - 6.1.46. **Lower-level migration cleanup classified:** the updated `IDAX_GAPS.md` notes also call out `get_func`, `decode_insn`, comments, names, applied types, and bulk type declarations remaining in ida-cdump. `docs/codedump_parity_tasks.md` and `docs/codedump_migration_checklist.md` now classify those as downstream migration cleanup backed by existing idax APIs, not new idax parity blockers; the consolidated local parity runner passes after the classification update.
  - 6.1.47. **Local validation runner host-mode support tightened:** `scripts/run_codedump_parity_local_validation.sh` now infers the same default/modal/Qt/Hex-Rays evidence modes as the host runner, writes mode-specific logs for opt-in gates, verifies each enabled mode, and has a lightweight `--self-test` for default and combined mode inference; the locally available `IDAX_RUN_HEXRAYS_SESSION=1` consolidated sweep passes.
  - 6.1.48. **Concrete remaining task split:** `docs/codedump_parity_tasks.md` and `docs/codedump_migration_checklist.md` now break the remaining parity closure into P22.H1.1-H1.3 modal evidence, P22.H2.1-H2.3 Qt clipboard evidence, and P22.V1.1-V1.2 final validation/documentation refresh.
  - 6.1.49. **Local evidence refreshed:** syntax checks, verifier self-test, host-runner self-test, local-runner self-test, integration-enabled default local validation, explicit default/Hex-Rays evidence-log verification, and the locally available Hex-Rays opt-in local validation all pass after the concrete task split.
  - 6.1.50. **Next order:** host-executed modal form evidence and Qt clipboard evidence once an interactive IDA Qt host and namespaced Qt package are available.
  - 6.1.51. **Status:** In progress.

---
