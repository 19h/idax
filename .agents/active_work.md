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

### 6. Phase 19 Example-Port Continuation

- **6.1. Remaining Rust Adaptation Coverage**
  - 6.1.1. **Action:** Continue adding standalone/adapted Rust ports for remaining source examples that are not blocked on plugin/procmod host export macros.
  - 6.1.2. **Current state:** Added `ida_names_port_plugin`, `qtform_renderer_plugin`, and `driverbuddy_port_plugin` headless adaptations; high-UI ports (`drawida`, `idapcode`, `abyss`, `lifter`) remain the primary unresolved set.
  - 6.1.3. **Next slice:** Extract another non-UI-heavy analysis subset from remaining plugin ports (prefer partial, documented headless slices over forced 1:1 UI parity).
  - 6.1.4. **Status:** In progress.
