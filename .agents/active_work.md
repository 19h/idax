## 16) In-Progress and Immediate Next Actions

> **Tracking Policy:** This list tracks *active*, *queued*, and *blocked* work only. Once an item reaches completion, record its evidence in the Progress Ledger and, when applicable, the Knowledge Base, then remove it from this file in the same closure update. Historical or retired entries are prohibited.

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

### 6. ida-cdump Parity Closure (Phase 22)

- **6.1. Host Evidence Queue**
  - 6.1.1. **Action:** Collect interactive host evidence for the remaining P22 UI/runtime gates documented in `docs/codedump_parity_tasks.md`.
  - 6.1.2. **Modal typed-form evidence:** Run `IDAX_RUN_MODAL_FORMS=1` in an interactive IDA UI host, accept the codedump-shaped dialog, and verify the captured log with `scripts/check_codedump_parity_evidence_log.sh <log> modal`.
  - 6.1.3. **Clipboard evidence:** Run `IDAX_RUN_QT_CLIPBOARD=1` in an IDA UI host with either an IDA-compatible Qt clipboard backend or a working external clipboard command, then verify with `scripts/check_codedump_parity_evidence_log.sh <log> qt-clipboard`.
  - 6.1.4. **Blocker:** Requires an interactive IDA UI host; Qt clipboard mode also requires either a namespaced `QT_NAMESPACE=QT` Qt package or usable host clipboard command access.
  - 6.1.5. **Status:** In progress / host-gated.

### 7. Opaque Operand Offset and Reference Semantics (Phase 70)

- **7.1. Exact-runtime semantic boundary**
  - 7.1.1. **Action:** Falsify the copied reference model and verified mutation rules against disposable exact-IDA 9.4 databases, then implement complete four-binding parity.
  - 7.1.2. **Scope:** Reference descriptors and kinds; main/outer operand locations; semantic options; copied target/base/delta metadata; calculation and plain rendering; offset-candidate helpers; verified apply/remove; data-reference creation.
  - 7.1.3. **Current evidence:** Complete C++/Node/Rust/Python parity builds against exact SDK 9.4; focused core proxy runtime, structural/type/manifest, generated-ABI identity, package, and privacy gates pass. Newly fail-closed binding lifecycles and exact semantic falsification await the live IDA 9.4 matrix because the installed 9.3 proxy cannot load every current 9.4 binding symbol and now terminates in the pre-existing segment-register suite before Phase 70.
  - 7.1.4. **Status:** Active under P70.2-P70.4; no blocker.
