# agents.md - IDA SDK Intuitive Wrapper Program

Last updated: 2026-02-16
Status: Implementation substantially complete; 16/16 tests passing; release candidate ready
Primary goal: Build a fully opaque, highly intuitive, self-explanatory wrapper over the IDA SDK for first-time users while preserving full power for expert workflows.

---

## Modular File System

This file is the **lean hub**. Detailed data lives in `.agents/` files to avoid reading/writing the entire knowledge base on every update. Each file is independently readable and appendable.

### File Map

| File | Contents | When to read | When to write |
|---|---|---|---|
| `AGENTS.md` (this file) | Rules, mission, locked decisions, compliance | Always (entrypoint) | When rules/decisions change |
| `.agents/knowledge_base.md` | Hierarchical findings/learnings KB (Section 12) | When checking known SDK behavior or adding findings | Append new KB entries at end of relevant subsection |
| `.agents/decision_log.md` | All architectural decisions (Section 13) | When making design decisions | Append new decisions at end of relevant category |
| `.agents/progress_ledger.md` | Detailed progress history (Section 15) | When logging completed work | Append new ledger entries at end |
| `.agents/active_work.md` | In-progress and next actions (Section 16) | When picking up work or checking status | Update status of active items |
| `.agents/roadmap.md` | Phased TODO roadmap + progress snapshot (Sections 10-11) | When checking phase status | When phase status changes |
| `.agents/architecture.md` | Analysis recap, target arch, domain mapping, build/test/doc strategy (Sections 4-9) | When designing new domains or checking architecture | Rarely (architecture is stable) |
| `.agents/api_catalog.md` | Public API concept catalog (Section 17) | When implementing new APIs | When API concepts are added |
| `.agents/pain_points.md` | Legacy SDK friction catalog (Section 18) | When designing wrapper behavior | When new pain points discovered |
| `.agents/naming_normalization.md` | Legacy-to-wrapper naming map (Section 19) | When naming new APIs | When new naming patterns established |
| `.agents/interface_blueprint.md` | Detailed interface sketches (Section 21) | When implementing specific namespaces | Rarely (design baseline, actual headers are authoritative) |
| `.agents/findings.md` | Raw findings log (referenced as [FXXX]) | When adding findings to KB | Always alongside KB updates |

### Append-Friendly Convention

Each `.agents/` file uses hierarchical numbered sections. To add a new entry:
1. Read only the **tail** of the target file (last ~50 lines) to understand current numbering
2. Append the new entry following the existing numbering pattern
3. No need to read the entire file for most updates

---

## 1) Non-Negotiable Operating Rules

1. The `.agents/` files are the distributed source of truth for roadmap, progress, findings, and decisions.
2. Any progress on TODOs and sub-TODOs must be reflected in the relevant `.agents/` file immediately.
3. Any findings, learnings, caveats, gotchas, and behavioral discoveries must be logged in `.agents/findings.md` and `.agents/knowledge_base.md` immediately.
4. No TODO transition is valid until both are updated:
   - The TODO status in `.agents/roadmap.md`
   - The corresponding entry in `.agents/progress_ledger.md`
5. No discovery is valid until both are updated:
   - The entry in `.agents/knowledge_base.md`
   - The corresponding entry in `.agents/progress_ledger.md`
6. Any blocker must be captured with impact and mitigation plan in `.agents/active_work.md`.
7. Any design change must be captured in `.agents/decision_log.md` with rationale.

MANDATORY UPDATE PROTOCOL (must always be followed):
- Step 1: Update task checkbox/status in `.agents/roadmap.md` as soon as it changes.
- Step 2: Add a Progress Ledger entry in `.agents/progress_ledger.md` with scope.
- Step 3: If a technical insight was discovered, add it to `.agents/findings.md` AND `.agents/knowledge_base.md`.
- Step 4: If architecture changed, add it to `.agents/decision_log.md`.
- Step 5: If blocked, add/update `.agents/active_work.md` with next action.

---

## 2) Project Mission

Design and implement a wrapper that reinvents the IDA SDK API surface so it is:
- Intuitive on first contact
- Concept-driven instead of header-driven
- Consistent in naming, error handling, and lifecycle semantics
- Safe by default (RAII, type-safe interfaces, reduced hidden pitfalls)
- Comprehensive enough to replace direct SDK usage for plugins, loaders, and processor modules

This wrapper is intended to preserve capability while radically improving usability.

---

## 3) Confirmed Technical Decisions (Locked)

These decisions were explicitly chosen and are currently locked:

1. Language standard: C++23
2. Packaging model: Hybrid
   - Header-only for thin wrappers and utility aliases
   - Compiled library for complex behavior, stateful adapters, iterators, and lifecycle management
3. Public API opacity: Fully opaque
   - No public `.raw()` escape hatches
   - No exposure of SDK structs/pointers in public interface
4. Public string type: `std::string`
   - `std::string_view` allowed for input optimization where safe
5. Scope: Full
   - Plugins + loaders + processor modules

Engineering constraints/preferences to honor during implementation:
- Prefer straightforward and portable implementations
- Avoid compiler-specific intrinsics unless unavoidable
- Avoid heavy bit-level micro-optimizations that reduce readability
- Prefer using SDK helpers (including `pro.h` helpers) when they improve portability/clarity
- For batch analysis/testing workflows, prefer `idump <binary>` over `idat`

---

## 4) Compliance Reminder (Hard Requirement)

No task is complete until the relevant `.agents/` files are updated.

This requirement applies to:
- Parent TODOs (in `.agents/roadmap.md`)
- Sub-TODOs (in `.agents/roadmap.md`)
- Findings and learnings (in `.agents/findings.md` + `.agents/knowledge_base.md`)
- Decisions (in `.agents/decision_log.md`)
- Blockers (in `.agents/active_work.md`)
- Progress ledger entries (in `.agents/progress_ledger.md`)

If any of the above changes and the corresponding file is not updated immediately, the work is considered incomplete.

---

## 5) Current Progress Snapshot

Program-level:
- Architecture definition: complete
- Implementation: complete — all core domains implemented; 16/16 test targets passing (232/232 smoke checks + 15 dedicated integration/unit suites); release candidate ready
- Documentation baseline file: complete
- Build system: working (CMake + ida-cmake, C++23, static library, install/export/CPack packaging)
- Test infrastructure: working (idalib-based integration tests with real IDA dylibs; compile-only API surface parity check)

Phase completion estimates:
- Phase 0-10: All ~100% complete
- See `.agents/roadmap.md` for detailed phase status

Blocker status:
- B-LIFTER-MICROCODE: **RESOLVED** (see `.agents/active_work.md`)
- See `.agents/active_work.md` for all in-progress and next actions
