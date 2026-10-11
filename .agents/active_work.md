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

### 7. Documented Gap Remediation (Phase 73)

- **7.1. Scope:** All nine rows of the user's attached gap table; roadmap P73.1-P73.9 and Progress Ledger 16.245 are the closure register.
- **7.2. Active:** P73.7.2.2-P73.7.4 broad Diaphora live feature/relation extraction, metadata/chooser entry points and end-to-end evidence. The complete upstream engine entry point passes controlled SQLite interoperability; no broad closure follows yet.
- **7.3. Blocked:** P73.8 external GitHub retention, pending authority and independent owner/Support actions.
- **7.4. Publication:** Stage only explicit owned paths; use the user-requested `red` command and push every validated semantic group. SSH remote access passes; the currently invalid GitHub CLI credential is an API-access constraint, with connected GitHub tools and supported local credential recovery as the next probes.
- **7.9. P73.8 external constraint [high]:** Fresh audit and concrete Support/fork-owner drafts are ready in `docs/reviews/github-retention-audit.md`. Two protected PR heads and four readable forks retain flagged history; one advertised fork is unavailable. Sending these external requests requires explicit user instruction. After requests/owner cleanup, repeat exact-object, all-ref and every-fork scans; do not infer purge from a clean master.

- **7.11. Linux bit-cursor portability:** Exact 2bfe86c0 Linux native/Docker/binding compilation fails unsigned typedef deduction in std::max. The explicit uint64_t template correction passes three local affected tests and is published at c0f4fb6f; inspect exact-source Linux native/Docker/binding reruns. Windows Rust linkage is closed at job 114346346820 (172 tests).
