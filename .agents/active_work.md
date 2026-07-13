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

---

### 7. GitHub Actions IDA License Provisioning

- **7.1. HCLI License Retrieval Blocker**
  - 7.1.1. **Impact:** Integrations CI, Bindings CI, and Validation Matrix fail on every runner platform before any repository build or test step executes.
  - 7.1.2. **Evidence:** HCLI downloads IDA 9.3, then reports `No licenses found matching criteria` and cannot find the configured `*96-0000-0000-XX.hexlic` file (F377).
  - 7.1.3. **Mitigation:** Renew or correct the HCLI account/license assignment and corresponding GitHub Actions secrets, then rerun all three workflows on `edbc6f1` or its successor.
  - 7.1.4. **Status:** Blocked on external license/secret provisioning; no repository code fix indicated.

---

### 9. Multi-Byte Data Definition Unit Semantics (Phase 29)

- **9.1. Element Count to Byte-Length Conversion**
  - 9.1.1. **Finding:** Multi-byte `define_*` APIs advertise element counts but pass them unchanged to SDK helpers that require byte lengths (F378).
  - 9.1.2. **Action:** Add checked `count * element_width` conversion for word/dword/qword/oword/tbyte/float/double definitions and preserve byte/string/struct semantics.
  - 9.1.3. **Evidence:** Replace survivability-only assertions with exact success, item-size, multi-element, overflow, and binding runtime checks.
  - 9.1.4. **Status:** Next isolated implementation item after Phase 28 completion.
