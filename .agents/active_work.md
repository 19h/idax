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
  - 3.1.2. **Focus:** Validate source-equivalent virtual cache-owner teardown through the exported no-connect getter.
  - 3.1.3. **Blocker:** The close symbols remain unexported; source-equivalent public virtual destruction is implemented, with positive connected-client proof pending.
  - 3.1.4. **Status:** Active / connected-client runtime validation.

---

### 7. Documented Gap Remediation (Phase 73)

- **7.1. Scope:** All nine rows of the user's attached gap table; roadmap P73.1-P73.9 and Progress Ledger 16.245 are the closure register.
- **7.2. Active:** P73.3 connected-client Lumina teardown validation; P73.9 actual 9.5 ABI/wide-offset consumer correction.
- **7.3. Queued:** P73.7 broad Diaphora parity; P73.8 external GitHub retention.
- **7.4. Publication:** Stage only explicit owned paths; use the user-requested `red` command and push every validated semantic group. SSH remote access passes; the currently invalid GitHub CLI credential is an API-access constraint, with connected GitHub tools and supported local credential recovery as the next probes.
- **7.7. P73.3 constraint:** The inspected runtime close path uses virtual destruction to clear cached ownership. The exported getter/public virtual destructor equivalent is implemented. Local compilation/absence smoke pass; actual local metadata connection fails before cache creation. Publish and inspect the separate hosted positive probe, then retain exact connected-client teardown/reconnection evidence; source equivalence alone is not runtime proof.
- **7.8. P73.9 next action:** Official source-defined SDK 950 headers and build-system packaging are available in the ignored local validation tree. Explicit SDK 950 validation mode and complete native compilation pass after the copied-string compatibility correction. Actual synthetic-provider text passes 44/0. The initial full 950 run is 45/46; its strict identifier failure is corrected and the target passes on both releases. Full 950 native baseline now passes 46/46. Complete actual byte/bit/union producer witnesses now pass with a portable source-built fixture. Correct every affected native/binding consumer and validate against these exact values. The raw SWIG int setter cannot serve as a wide producer.

- **7.9. P73.8 external constraint [high]:** Fresh audit and concrete Support/fork-owner drafts are ready in `docs/reviews/github-retention-audit.md`. Two protected PR heads and four readable forks retain flagged history; one advertised fork is unavailable. Sending these external requests requires explicit user instruction. After requests/owner cleanup, repeat exact-object, all-ref and every-fork scans; do not infer purge from a clean master.

- **7.10. Windows Rust link validation:** The registry fallback system dependency is now emitted by the independent Rust archive consumer. Publish and inspect the exact-head Windows Rust example/library build; native CMake passes do not close this gate.
