## 10) Phased TODO Roadmap (Exhaustive)

Legend:
- [ ] pending
- [~] in progress
- [x] done
- [!] blocked

Current overall phase status:
- Phase 0: ~100% (scaffold, build, test infra, examples tree, CMake install/export/CPack packaging all done)
- Phase 1: ~100% (core types, shared options, diagnostics/logging, core unit tests, API surface parity check all done)
- Phase 2: ~100% (address/data/database implemented; string extraction + typed helpers + binary pattern search; snapshots + file/memory load helpers; mutation safety tests; predicate search all done)
- Phase 3: ~100% (name, xref, comment, search, analysis implemented; dedicated behavior integration tests added for name/comment/xref/search)
- Phase 4: ~100% (segment, function w/chunks+callers+callees+frame+register variables, type w/struct+member+retrieve+type library, entry, fixup; type roundtrip+fixup relocation+edge-case tests all added; structural parity test done)
- Phase 5: ~100% (instruction/operand decode/text + full representation controls implemented; decode behavior + operand conversion + text snapshot tests added)
- Phase 6: ~100% (plugin includes action attach/detach + context-aware callbacks/docs; loader includes advanced archive/member/reload/save/move request models and typed flag helpers; processor includes output-context abstraction + advanced descriptor/assembler parity checks; sample modules and quickstart docs present; loader/processor scenario tests added)
- Phase 7: ~100% (debugger now includes typed event subscriptions; ui w/chooser+dialogs+timer+event subscriptions, graph w/object+flowchart+viewer+groups, event system now includes generic filtering/routing helpers; advanced validation tests added; all tested)
- Phase 8: ~100% (decompiler full: availability+decompile+pseudocode+variables+rename+ctree visitor+comments+address mapping+refresh; storage full w/blob operations; migration caveats docs added; all P8.4 tests passing)
- Phase 9: ~100% (P9.1 integration audits complete + all audit fixes applied; P9.2 documentation complete; P9.3 validation pass complete — 16/16 tests, CPack packaging verified; P9.4 release readiness complete — validation report, performance baseline)
- Phase 10: ~100% (P10.0 coverage governance/matrix completed; P10.1 core/cross-cutting parity hardening completed; P10.2 address/data/database closure completed; P10.3 segment/function/instruction closure completed; P10.4 metadata closure completed; P10.5 search/analysis closure completed; P10.6 module-authoring closure completed; P10.7.a debugger closure completed; P10.7.b ui closure completed; P10.7.c graph closure completed; P10.7.d decompiler closure completed; P10.7.e storage closure completed; P10.8.a-d docs/validation closure completed; P10.9.a-d exit checks completed; Phase 10 closure summary logged)

### 10.1 Phase 10 - SDK Domain Coverage Closure TODO (Comprehensive)

Hard tracking note for Phase 10:
- Any progress, findings, learnings, caveats, blockers, or design decisions discovered while executing this checklist MUST be reflected in this file immediately (TODO status + Findings + Decision Log + Progress Ledger + Blockers as applicable).

- [x] P10.0 - Coverage governance and matrix artifact
  - [x] P10.0.a - Create/maintain a canonical coverage matrix doc (`docs/sdk_domain_coverage_matrix.md`) with one row per domain and one row per major SDK capability family.
  - [x] P10.0.b - For every row, mark status as `covered`, `partial`, or `missing`, with concrete API symbol references.
  - [x] P10.0.c - For every `partial`/`missing` row, define closure criteria and required tests/docs evidence.

- [x] P10.1 - Core/cross-cutting parity hardening
  - [x] P10.1.a - Re-audit `ida::error`, `ida::core`, `ida::diagnostics` for consistency and completeness against wrapper-wide usage patterns.
  - [x] P10.1.b - Ensure all new domain APIs preserve opaque-boundary, naming, and error-model rules.
  - [x] P10.1.c - Expand compile-only API parity checks for all newly added symbols.

- [x] P10.2 - Address/data/database domain closure
  - [x] P10.2.a (`ida::address`) - Add missing range iterators/predicates for code/data/unknown traversal parity.
  - [x] P10.2.b (`ida::address`) - Add ergonomic `next_defined`/`prev_defined`-style aliases where naming clarity improves discoverability.
  - [x] P10.2.c (`ida::data`) - Add explicit patch revert API and corresponding behavior tests.
  - [x] P10.2.d (`ida::data`) - Add missing define helpers (including struct/data-definition parity helpers) where SDK coverage exists.
  - [x] P10.2.e (`ida::database`) - Add load-mode/open-mode convenience wrappers (binary/non-binary intent) and metadata parity checks.

- [x] P10.3 - Segment/function/instruction domain closure
  - [x] P10.3.a (`ida::segment`) - Add resize/move wrappers with robust validation + tests.
  - [x] P10.3.b (`ida::segment`) - Add segment comment get/set APIs and traversal helpers (`first`/`last`/`next`/`prev`) where appropriate.
  - [x] P10.3.c (`ida::function`) - Add explicit reanalysis/update intent APIs and additional function-address iteration helpers.
  - [x] P10.3.d (`ida::function`) - Expand frame/register-variable ergonomics for common migration workflows.
  - [x] P10.3.e (`ida::instruction`) - Add missing classification helpers (`is_jump`, `is_conditional_jump`) and operand text/format parity helpers.

- [x] P10.4 - Metadata domain closure (`name`/`xref`/`comment`/`type`/`entry`/`fixup`)
  - [x] P10.4.a (`ida::name`) - Add identifier validation/sanitization and user-defined/auto naming introspection parity.
  - [x] P10.4.b (`ida::xref`) - Add iterator/range-style enumeration parity and richer typed filter utilities.
  - [x] P10.4.c (`ida::comment`) - Add indexed line edit/remove helpers and verify render parity behavior.
  - [x] P10.4.d (`ida::type`) - Expand function-type/calling-convention/enum workflows and higher-level type construction helpers.
  - [x] P10.4.e (`ida::entry`) - Add forwarder management parity helpers.
  - [x] P10.4.f (`ida::fixup`) - Expand descriptor fidelity (flags/base/signed variants) and range traversal helpers.

- [x] P10.5 - Search and analysis control closure
  - [x] P10.5.a (`ida::search`) - Add missing direction/options parity and `next_error`-style helpers.
  - [x] P10.5.b (`ida::search`) - Validate text/immediate/binary search option mappings against SDK semantics.
  - [x] P10.5.c (`ida::analysis`) - Add explicit schedule-intent APIs (`schedule_code`, `schedule_function`, etc.) and rollback/revert wrappers.

- [x] P10.6 - Module-authoring closure (`plugin`/`loader`/`processor`)
  - [x] P10.6.a (`ida::plugin`) - Add action detach helpers and finalize context-aware action ergonomics/docs.
  - [x] P10.6.b (`ida::loader`) - Expand advanced loader scenarios (archive/member/reload/save paths) and scenario tests.
  - [x] P10.6.c (`ida::processor`) - Add output-context abstraction and parity checks for advanced descriptor/assembler surfaces.

- [x] P10.7 - Interactive/advanced closure (`debugger`/`ui`/`graph`/`decompiler`/`storage`)
  - [x] P10.7.a (`ida::debugger`) - Expand async/request parity and thread/register introspection helpers.
  - [x] P10.7.b (`ida::ui`) - Add additional form/custom-viewer coverage and broaden generic UI/VIEW event mapping.
  - [x] P10.7.c (`ida::graph`) - Add viewer lifecycle/query parity helpers and validate layout behavior matrix.
  - [x] P10.7.d (`ida::decompiler`) - Add variable retype and additional ctree/comment workflow coverage.
  - [x] P10.7.e (`ida::storage`) - Add node-id/open-by-id metadata helpers and document safe blob index practices.

- [x] P10.8 - Validation/documentation closure for every domain item
  - [x] P10.8.a - Add/expand dedicated integration tests for each newly closed subgoal.
  - [x] P10.8.b - Update migration docs (`docs/migration/*`) and API reference for each newly exposed wrapper API.
  - [x] P10.8.c - Update `docs/namespace_topology.md` and add domain parity notes where behavior intentionally differs.
  - [x] P10.8.d - Execute compatibility matrix rows (macOS/Linux/Windows) for changed domain surfaces.

- [x] P10.9 - Exit criteria for Phase 10 completion
  - [x] P10.9.a - Every domain/capability row in matrix marked `covered` OR documented as intentional abstraction.
  - [x] P10.9.b - No open high-severity parity blockers for plugin/loader/processor/decompiler/ui migration scenarios.
  - [x] P10.9.c - All new tests pass in `full`, `unit`, and `compile-only` profiles.
  - [x] P10.9.d - Final Phase 10 closure summary logged in Progress Ledger with evidence links.

---

## 11) Current Progress Snapshot

Program-level:
- Architecture definition: complete
- Implementation: complete — all core domains implemented; 16/16 test targets passing (232/232 smoke checks + 15 dedicated integration/unit suites); release candidate ready
- Documentation baseline file: complete (this file)
- Build system: working (CMake + ida-cmake, C++23, static library, install/export/CPack packaging)
- Test infrastructure: working (idalib-based integration tests with real IDA dylibs; compile-only API surface parity check)

Phase completion estimates:
- Phase 0: ~100% (scaffold, build, test infra, examples tree, CMake install/export/CPack packaging all done)
- Phase 1: ~100% (core types, shared options, diagnostics/logging, core unit tests, API surface parity check all done)
- Phase 2: ~100% (address/data/database implemented; string extraction + typed helpers + binary pattern search; snapshots + file/memory load helpers; mutation safety tests; predicate search all done)
- Phase 3: ~100% (name, xref, comment, search, analysis implemented; dedicated behavior integration tests added for name/comment/xref/search)
- Phase 4: ~100% (segment, function w/chunks+callers+callees+frame+register variables, type w/struct+member+retrieve+type library, entry, fixup; type roundtrip+fixup relocation+edge-case tests all added; structural parity test done)
- Phase 5: ~100% (instruction/operand decode/text + full representation controls implemented; decode behavior + operand conversion + text snapshot tests added)
- Phase 6: ~100% (plugin includes action attach/detach + context-aware callbacks/docs; loader includes advanced archive/member/reload/save/move request models and typed flag helpers; processor includes output-context abstraction + advanced descriptor/assembler parity checks; sample modules and quickstart docs present; loader/processor scenario tests added)
- Phase 7: ~100% (debugger now includes typed event subscriptions; ui w/chooser+dialogs+timer+event subscriptions, graph w/object+flowchart+viewer+groups, event system now includes generic filtering/routing helpers; advanced validation tests added; all tested)
- Phase 8: ~100% (decompiler full: availability+decompile+pseudocode+variables+rename+ctree visitor+comments+address mapping+refresh; storage full w/blob operations; migration caveats docs added; all P8.4 tests passing)
- Phase 9: ~100% (P9.1 integration audits complete + all audit fixes applied; P9.2 documentation complete; P9.3 validation pass complete — 16/16 tests, CPack packaging verified; P9.4 release readiness complete — validation report, performance baseline)
- Phase 10: ~100% (P10.0 coverage governance/matrix completed; P10.1 core/cross-cutting parity hardening completed; P10.2 address/data/database closure completed; P10.3 segment/function/instruction closure completed; P10.4 metadata closure completed; P10.5 search/analysis closure completed; P10.6 module-authoring closure completed; P10.7.a debugger closure completed; P10.7.b ui closure completed; P10.7.c graph closure completed; P10.7.d decompiler closure completed; P10.7.e storage closure completed; P10.8.a-d docs/validation closure completed; P10.9.a-d exit checks completed; final closure summary recorded)

---
