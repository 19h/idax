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
- **7.2. Active:** P73.7.3.2/P73.7.4 Diaphora GUI stability and remaining GUI category/rendering gates. Complete export/relations/options/resume, saved/reopened metadata, eight changed-binary/model states, positive native matching in all six categories, C++ GUI launcher/navigation/difference views and corrected Rust workflow pass. Native graph actions on all four matched categories now pass (F722). Stable GUI import still fails after F715 correction; unmatched GUI preview/selection, full action/option controls and complete stable operations remain open.
- **7.3. Blocked:** P73.8 external GitHub retention, pending authority and independent owner/Support actions.
- **7.4. Publication:** Stage only explicit owned paths; use the user-requested `red` command and push every validated semantic group. SSH remote access passes; the currently invalid GitHub CLI credential is an API-access constraint, with connected GitHub tools and supported local credential recovery as the next probes.
- **7.9. P73.8 external constraint [high]:** Fresh audit and concrete Support/fork-owner drafts are ready in `docs/reviews/github-retention-audit.md`. Two protected PR heads and four readable forks retain flagged history; one advertised fork is unavailable. Sending these external requests requires explicit user instruction. After requests/owner cleanup, repeat exact-object, all-ref and every-fork scans; do not infer purge from a clean master.

- **7.10. P73.7 GUI stability [high]:** Metadata imports record the expected mutation before a repeated native fault in QMacAccessibilityElement_QT destruction/objc_release. Context-menu removal, duplicate-refresh removal, analysis-wait removal and a fresh-IDB screenshot-only workflow do not prevent it. A fresh native built-in Jump control on macOS 27.2 reproduces the same failure sequence without loaded IDAX Python modules/plugin/extension. OS/automation/vendor-plugin causation remains unknown. F716 identifies primary Qt QTBUG-134784 cache-ownership changes as a lead; next action is a supported stable runtime/OS GUI host or independently validated native ownership fix, followed by positive category/operation proof. No runtime or Qt patch is made.

- **7.15. Active:** P73.7.3.3.2.3-P73.7.3.3.2.4 actual embedded HTML rendering and relative paired docking/zoom-fit fidelity. Pure generation and all 24 actual graph viewers pass in separate closed subitems. Embedded HTML needs a fully opaque display boundary; verify native paired placement/fit controls independently. P73.7.3.4-P73.7.3.5 preserve all remaining upstream actions/selection/options.
