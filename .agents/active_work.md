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

### 11. Symless Member-TID Informational Cross-References (Phase 43)

- **11.1. Capability Audit**
  - 11.1.1. **Action:** Compare upstream member-TID acquisition/xref emission with local IDA type-member identity and xref contracts, then determine the minimum opaque cross-binding surface.
  - 11.1.2. **Status:** Complete (P43.1; F425; KB 35.81; decision 19.46).
- **11.2. Boundary**
  - 11.2.1. **Scope:** Cover only informational references from recovered access instructions to exact generated UDT members, with explicit report/apply separation, deterministic validation, and reopen idempotence. Keep multi-element stroff paths, indirect dynamic calls, RTTI-adjusted vtable chains, and widget selection separate.
  - 11.2.2. **Status:** Complete (P43.2-P43.4; F425-F427; KB 35.81-35.83; decision 19.46). C++ passes 26/26, Node passes 234/234 structural plus 81/81 live checks, and Rust passes 138/138 library, 13/13 Symless, and 98/98 live checks. IDA Professional 9.4 report/apply/fresh-process reopen proves three candidates, three added on first apply, and all three reused with zero additions after reopen. No Phase 43 blocker remains.

---

### 12. Symless Exact Operand Struct-Offset Paths (Phase 44)

- **12.1. Capability Audit**
  - 12.1.1. **Action:** Compare upstream access-register conversion, machine-operand selection, signed delta calculation, two-component stroff application, and same-instruction multi-field handling with the owned graph/instruction/type surfaces and local IDA 9.3 contracts.
  - 12.1.2. **Status:** Complete (P44.1; F428; KB 35.84; decision 19.47). The existing wrapper supports only one-component paths and publicly leaks native type/member identities through raw numeric IDs.
- **12.2. Opaque Path Closure**
  - 12.2.1. **Action:** Replace raw-ID setters/readback with copied root/member names, add exact member-by-byte-offset idempotent application, copy `mreg2reg` evidence into owned microcode operands, and mirror the result through Node and Rust.
  - 12.2.2. **Status:** Complete (P44.2; F428-F429; KB 35.84-35.85). Opaque C++/Node/Rust path and processor-register surfaces pass focused structural and live validation.
- **12.3. Boundary**
  - 12.3.1. **Scope:** Apply one source-ordered stroff path per unique recovered `(instruction, processor register)` group; retain additional same-instruction fields as Phase 43 member references; preserve incompatible existing operand representations and report every candidate/add/reuse/skip. Keep indirect dynamic calls, RTTI-adjusted vtable chains, and microcode-widget selection separate.
  - 12.3.2. **Status:** Complete (P44.3-P44.4; F430-F433; KB 35.86-35.89). The exact 38-file staged review passed without findings; implementation commit `6e523eb40ea0d2b3168b5a81d8584f06bd96b9a7` is pushed and no Phase 44 blocker remains.

---

### 14. Diaphora 3.4.0 Port and Gap Audit (Phase 48)

- **14.1. Source Audit**
  - 14.1.1. **Action:** Pin Diaphora release 3.4.0, inventory plugin/export/diff behavior, and map each IDA-facing operation to existing opaque IDAX surfaces before selecting a bounded first implementation slice.
  - 14.1.2. **Status:** Complete (P48.1; F446-F448; KB 35.102-35.104; decision 19.52). Pinned tag 3.4.0 at commit `84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99`; selected exact function fingerprint export/compare/conservative metadata import as the first bounded surface.
- **14.2. Selection Boundary**
  - 14.2.1. **Evidence:** GitHub API snapshot on 2026-07-14 reports 4,331 stars, 412 forks, IDA 9.4 support, and recent upstream activity. Capa has more repository stars but its IDA plugin is a front end to a substantially larger external rule engine; Diaphora more directly exercises wrapper-native database analysis and persistence surfaces.
  - 14.2.2. **Constraint:** Do not approximate SQLite diff heuristics, pseudocode/microcode similarity, or UI behavior until source audit establishes their exact data and lifecycle contracts.
- **14.3. Encoded-Operand Metadata Closure**
  - 14.3.1. **Action:** Copy primary/secondary operand encoded-value byte positions across C++, Node, generated C ABI, and safe Rust, using absence-aware public values and live instruction bounds evidence.
  - 14.3.2. **Status:** Complete (P48.2; F447, F449; KB 35.103, 35.105); no blocker.
  - 14.3.3. **Additional closure:** Mirror existing C++ function declaration readback through Node, the C shim, and safe Rust so conservative import can preserve preexisting target prototypes (F449; KB 35.105).
- **14.4. Adaptation and validation**
  - 14.4.1. **Status:** P48.3 complete; C++ plugin/Rust headless artifacts, pure tests, and first live report/apply/reopen evidence pass (F450; KB 35.106).
  - 14.4.2. **Status:** Complete and retired. P48.4 implementation, documentation, full C++/Node/Rust validation, generated-binding identity, tracked-fixture integrity, and the exact 38-file staged review pass. Implementation commit `444ca5354e899a3734edb8a84c67ea7eb43d2fd5` is pushed to `origin/master`; no Phase 48 blocker remains.
