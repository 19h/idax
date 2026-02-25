## 16) In-Progress and Immediate Next Actions

> **Tracking Policy:** This list tracks *active* and *queued* work items only. Once an item reaches completion (pass evidence recorded, docs updated, ledger entry written), it **must be removed** from this list and migrated to the Progress Ledger KB. Stale entries degrade signal — prune aggressively.

---

### 1. CI & Validation Infrastructure

- **1.1. GitHub Actions Matrix (Default Path)**
  - 1.1.1. **Action:** Keep `.github/workflows/validation-matrix.yml` as default cross-OS evidence path
  - 1.1.2. **Scope:** `compile-only` + `unit` on every release-significant change
  - 1.1.3. **Status:** Active / ongoing

- **1.2. Host-Specific Hardening**
  - 1.2.1. **Action:** Continue host-specific hardening runs where licenses/toolchains permit
  - **1.2.2. Linux**
    - 1.2.2.1. Keep Clang 19 as baseline evidence
    - 1.2.2.2. Execute `full` rows with runtime installs when available
  - **1.2.3. Windows**
    - 1.2.3.1. Execute `full` rows with runtime installs when available
  - 1.2.4. **Status:** Ongoing / license-gated

---

### 2. JBC & Processor Module Parity

- **2.1. Validation Continuation**
  - 2.1.1. **Action:** Continue validating JBC parity APIs against additional real-world procmod ports
  - 2.1.2. **Scope:** Expand typed analyze/output metadata only when concrete migration evidence requires deeper fidelity
  - 2.1.3. **Status:** Ongoing / evidence-driven

---

### 3. Lumina Hardening

- **3.1. Beyond Pull/Push Baseline**
  - 3.1.1. **Action:** Keep hardening `ida::lumina` behavior beyond now-passing pull/push smoke baseline
  - 3.1.2. **Focus:** Close/disconnect semantics once portable runtime symbols are confirmed
  - 3.1.3. **Blocker:** Runtime dylibs don't export `close_server_connection2`/`close_server_connections`
  - 3.1.4. **Status:** Blocked on runtime symbol availability

---

### 4. Appcall Runtime Evidence

- **4.1. Debugger-Capable Host Execution**
  - 4.1.1. **Action:** Execute `docs/appcall_runtime_validation.md` on a debugger-capable host
  - **4.1.2. Current Block State**
    - 4.1.2.1. Backend loads successfully
    - 4.1.2.2. `start_process` returns `0` + still `NoProcess`
    - 4.1.2.3. `request_start` → no-process
    - 4.1.2.4. `attach_process` returns `-1` + still `NoProcess`
    - 4.1.2.5. `request_attach` → no-process
  - 4.1.3. **Goal:** Convert block into pass evidence
  - 4.1.4. **Follow-Up:** Expand Appcall argument/return kind coverage only where concrete ports require additional fidelity
  - 4.1.5. **Status:** Blocked on debugger-capable host

---

### 5. Decompiler Write-Path Depth (Lifter-Class Ports) — RESOLVED

- **5.1. Resolution Summary**
  - 5.1.1. Deep mutation breadth audit confirmed full SDK pattern coverage for lifter-class ports
  - 5.1.2. All 14 SDK mutation pattern categories have wrapper equivalents (13 fully covered, 1 functionally equivalent)
  - 5.1.3. All 9 original gap categories (GAP 1–9) closed
  - 5.1.4. All 5 source-backed gap matrix items (A–E) closed
  - 5.1.5. `B-LIFTER-MICROCODE` blocker resolved — see Progress Ledger 12.27
  - 5.1.6. No new wrapper APIs required for lifter-class ports
  - 5.1.7. **Status:** Resolved / demand-driven expansion only

---

### 6. Abyss Port — API Gap Closure Implementation (Phase 11) — RESOLVED

- **6.1. Resolution Summary**
  - 6.1.1. Port of the "abyss" Hex-Rays decompiler filter framework (Python → C++) identified and closed 18 API gaps
  - 6.1.2. All implementations complete: `src/lines.cpp` (new), `src/decompiler.cpp` (expanded), `src/ui.cpp` (expanded)
  - 6.1.3. New header `include/ida/lines.hpp` created with Color enum, tag control constants, and 6 tag functions
  - 6.1.4. `include/ida/decompiler.hpp` expanded with 4 event subscriptions, raw line access, expression nav, lvar extensions, item position lookup
  - 6.1.5. `include/ida/ui.hpp` expanded with WidgetType enum, widget_type(), popup/rendering subscriptions, dynamic actions, utilities
  - 6.1.6. `examples/plugin/abyss_port_plugin.cpp` complete (~845 lines) with all 8 original filters
  - 6.1.7. All targets build clean, 16/16 tests pass, no regressions
  - 6.1.8. **Status:** Resolved

---

### 7. Example Plugin Entry Points + Database TU Split — RESOLVED

- **7.1. Resolution Summary**
  - 7.1.1. 5 example plugins were missing `IDAX_PLUGIN(ClassName)` macro, producing empty dylibs with no exported `_PLUGIN` symbol
  - 7.1.2. Added macro to: `action_plugin.cpp`, `decompiler_plugin.cpp`, `deep_analysis_plugin.cpp`, `event_monitor_plugin.cpp`, `storage_metadata_plugin.cpp`
  - 7.1.3. Fix exposed latent linker bug: `database.cpp` mixed idalib-only and plugin-safe symbols in one TU
  - 7.1.4. Split `database.cpp` → `database.cpp` (plugin-safe) + `database_lifecycle.cpp` (idalib-only)
  - 7.1.5. All 7 plugins, 3 loaders, 3 procmods build and link clean; 16/16 tests pass
  - 7.1.6. **Status:** Resolved

---

### 8. Vendoring IDA SDK and Artifact Output Isolation (Phase 16) — RESOLVED

- **8.1. Resolution Summary**
  - 8.1.1. Added `third-party/ida-sdk` (HexRaysSA) and `third-party/ida-cmake` (allthingsida) as Git submodules.
  - 8.1.2. Configured `CMakeLists.txt` to automatically default to the vendored SDK when `$ENV{IDASDK}` is unset, including auto-initialization of submodules via `execute_process()`.
  - 8.1.3. Modified `CMakeLists.txt` to override `IDABIN` to `${CMAKE_CURRENT_BINARY_DIR}/idabin`, isolating all built artifacts (plugins, loaders, procmods) to a local directory instead of polluting the vendored `ida-sdk` path.
  - 8.1.4. Validation: Verified that `cmake .. && make` works out of the box and outputs cleanly to `build/idabin/`.
  - 8.1.5. **Status:** Resolved

---

### 8. IDA-names Port — Identified API Gaps

- **8.1. API Gaps Discovered During Porting**
  - 8.1.1. `ida::ui` lacks a high-level `current_widget()` polling API. `ida_kernwin.get_current_widget()` has no idax equivalent; plugin authors must manually subscribe to `on_current_widget_changed` to track the active view.
  - 8.1.2. `ida::decompiler` lacks an `on_switch_pseudocode` subscription (wrapping `hxe_switch_pseudocode`). The port worked around this using `on_screen_ea_changed` and `on_current_widget_changed`.
  - 8.1.3. `ida::name::demangled` requires an `ida::Address` context. The SDK's bare string demangler `demangle_name(const char*)` is not exposed, forcing plugins to use the address-based lookup rather than demangling an arbitrary string in memory.
  - 8.1.4. `ida::ui::Widget` lacks a `set_title()` method. (Note: The IDA SDK itself lacks `set_widget_title`, requiring `ida_kernwin.PluginForm.TWidgetToPyQtWidget(view)` in Python. In idax, this is correctly bridged via `ida::ui::with_widget_host_as<QWidget>` dropping down to Qt).
  - 8.1.5. **Action:** Evaluate adding `current_widget()`, `on_switch_pseudocode`, and a string-only `demangled(string_view)` overload to close these ergonomic gaps.
  - 8.1.6. **Status:** Pending triage
