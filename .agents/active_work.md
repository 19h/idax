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

Reminder: Every single TODO and sub-TODO update, and every finding/learning, must be reflected here immediately.

---
