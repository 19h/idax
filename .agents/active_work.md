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

### 9. Symless Allocator Seed and Wrapper Discovery (Phase 39)

- **9.1. Capability Audit**
  - 9.1.1. **Action:** Compare upstream malloc/calloc/realloc seed parsing, call-site size evaluation, return-confirmed wrapper classification, heir recursion, and allocator typing with idax graph/xref/type surfaces.
  - 9.1.2. **Status:** Complete (P39.1; F414; decision 19.41).
- **9.2. Bounded Port**
  - 9.2.1. **Boundary:** Preserve declarative direct allocator seeds, constant-size allocation roots, argument-forwarding wrappers, and explicit report/apply behavior; do not conflate constructor/vtable or indirect-dynamic discovery with allocator classification.
  - 9.2.2. **Status:** Complete (P39.2-P39.4; F415; validation synchronized). Both adaptations implement explicit seed parsing/resolution, exact direct-call classification, static roots, terminal-return-confirmed wrappers, cycle-safe heir traversal, bounded root reconstruction, and explicit generic-prototype/UDT apply. No Phase 39 blocker remains.

---

### 10. Symless Constructor and Vtable Root Discovery (Phase 40)

- **10.1. Capability Audit**
  - 10.1.1. **Action:** Compare upstream constructor heuristics, vtable recognition, structure-root injection, inheritance, and vftable materialization with current idax graph/xref/type surfaces and local IDA 9.3 headers.
  - 10.1.2. **Status:** Complete (P40.1; F416; KB 35.72; decision 19.42).
- **10.2. Opaque UDT Semantics**
  - 10.2.1. **Action:** Add metadata-preserving C++ object/vftable UDT semantic mutation with C++/Node/Rust parity and exact native-record preservation evidence.
  - 10.2.2. **Status:** Complete (P40.2; C++/Node/Rust preservation and runtime rejection evidence pass).
- **10.3. Boundary**
  - 10.3.1. **Scope:** Scan loaded code/data item heads for pointer-width tables; require exact function entries or mapped external members, no references to non-first slots, at least one non-import method, and an analyzed pointer-width store of the table into argument zero at offset zero. Treat multiple offset-zero tables for one function as ambiguous, report secondary-offset stores, and never infer inheritance from size/xref counts alone.
  - 10.3.2. **Status:** Complete (P40.3-P40.4; F417-F419; KB 35.73-35.75). Full C++/Node/Rust validation and real report/apply/reopen evidence pass; no Phase 40 blocker remains. Phase 41 closes shifted propagated-argument typing; indirect dynamic calls, forward replacement, member-TID xrefs, multi-stroff paths, and widget picking remain separate.

---

### 11. Symless Shifted-Pointer Metadata (Phase 41)

- **11.1. Capability Audit**
  - 11.1.1. **Action:** Compare upstream `shift_ptr`/argument eligibility and virtual-method shifted `this` construction with `ptr_type_data_t`, current prototype edits, and cross-binding type snapshots.
  - 11.1.2. **Status:** Complete (P41.1; F420; KB 35.76; decision 19.44).
- **11.2. Boundary**
  - 11.2.1. **Scope:** Preserve the complete existing pointer record, add only an explicit named parent plus signed 32-bit nonzero delta, expose copied parent/delta introspection, and type only already-propagated argument sites whose generic type is eligible. Keep shifted returns excluded and do not infer a shift from unrelated operand formatting.
  - 11.2.2. **Status:** P41.2-P41.3 complete. C++/Node/Rust exact metadata tests pass; both Symless adaptations type evidence-backed shifted arguments and preserve mismatches/shifted returns. P41.4 complete-matrix validation, documentation synchronization, staged review, and push are in progress.
