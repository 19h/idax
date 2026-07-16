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

---

### 7. Opaque Register-Value Tracking (Phase 65)

- **7.1. Release Validation and Closure**
  - 7.1.1. **Action:** Pin all six uv setup invocations to immutable Node 24 action revision `11f9893b081a58869d3b5fccaea48c9e9e46f990` (`v8.3.2`) and explicit uv `0.11.28`, retain the workflow token for authenticated fallback download, exact-stage/review/push the isolated CI correction, verify the replacement live matrix and complete-log privacy, then close Phase 65.
  - 7.1.2. **Evidence:** Implementation commit `c66fc8e2bcd7c4084e7c1cc629114a41e96685b1` is on `master`. Runs 29541397249 and 29541397296 reached v5's unpinned latest-version resolution from shared macOS runner addresses; jobs 87764215050 and 87764215005 failed before checkout/build with unauthenticated GitHub API rate-limit annotations. Exact v5 inspection shows that the token input already defaulted to `${{ github.token }}`, so an explicit version pin is required to eliminate that metadata lookup rather than merely restating the default.
  - 7.1.3. **Blocker:** The first live matrix cannot pass because two pre-build latest-version resolution steps reached and exhausted an unauthenticated GitHub API bucket.
  - 7.1.4. **Mitigation:** Remove runtime version discovery with explicit uv `0.11.28`, use setup-uv `v8.3.2`'s Node 24 runtime and Astral-mirror default, and preserve `${{ github.token }}` for authenticated GitHub fallback acquisition.
  - 7.1.5. **Status:** Active / corrective release validation in progress.
