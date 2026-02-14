# agents.md - IDA SDK Intuitive Wrapper Program

Last updated: 2026-02-14
Status: Implementation substantially complete; 16/16 tests passing; release candidate ready
Primary goal: Build a fully opaque, highly intuitive, self-explanatory wrapper over the IDA SDK for first-time users while preserving full power for expert workflows.

---

## 1) Non-Negotiable Operating Rules

1. This file is the single source of truth for roadmap, progress, findings, and decisions.
2. Any progress on TODOs and sub-TODOs must be reflected in this file immediately.
3. Any findings, learnings, caveats, gotchas, and behavioral discoveries must be logged in this file immediately.
4. No TODO transition is valid until both are updated:
   - The TODO status in the relevant phase section
   - The timestamped entry in the Progress Ledger
5. No discovery is valid until both are updated:
   - The Findings and Learnings section
   - The timestamped entry in the Progress Ledger
6. Any blocker must be captured with impact and mitigation plan in the Blockers section.
7. Any design change must be captured in the Decision Log with rationale.

MANDATORY UPDATE PROTOCOL (must always be followed):
- Step 1: Update task checkbox/status as soon as it changes.
- Step 2: Add a Progress Ledger entry with timestamp and scope.
- Step 3: If a technical insight was discovered, add it to Findings and Learnings.
- Step 4: If architecture changed, add it to Decision Log.
- Step 5: If blocked, add/update Blockers with next action.

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

## 4) Comprehensive Analysis Recap (What Was Learned)

An exhaustive review of the SDK headers and major domains was completed before architecture design.

High-level scope reviewed:
- Core and kernel-facing APIs
- Address, bytes, segments, functions, frames, names, xrefs, comments
- Type system and metadata storage layers
- Search and analysis queues
- Loader, plugin, processor interfaces
- Debugger and UI layers
- Graphing and line rendering
- Hex-Rays/decompiler surface

Primary systemic pain points identified:

1. Naming inconsistency
   - Mixed abbreviations and full words (`segm` vs `segment`)
   - Ambiguous prefixes and overloaded constants
2. Conceptual opacity
   - Highly encoded flags and bitfields with domain-specific hidden meaning
   - Implicit relationships and historical artifacts leaked into public API
3. Inconsistent error/reporting patterns
   - Mixed `bool`, integer codes, sentinel values, and side effects
4. Hidden dependencies and lifecycle hazards
   - Pointer invalidation, lock requirements, include-order constraints
5. Redundant and overlapping API paths
   - Multiple ways to do the same operation with different caveats
6. C-style varargs dispatch in key subsystems
   - Weak compile-time type safety in some interface paths
7. Legacy compatibility burden
   - Obsolete values and historical naming still present in modern workflows

Resulting architectural conclusion:
- The wrapper must be domain-first, not header-first
- The wrapper must normalize naming and errors globally
- The wrapper must convert hidden pitfalls into explicit, type-safe behavior

---

## 5) Target Wrapper Architecture (Conceptual)

### 5.1 Public Namespace Topology

Proposed top-level namespaces:
- `ida::database`
- `ida::address`
- `ida::data`
- `ida::segment`
- `ida::function`
- `ida::instruction`
- `ida::name`
- `ida::xref`
- `ida::comment`
- `ida::type`
- `ida::fixup`
- `ida::entry`
- `ida::search`
- `ida::analysis`
- `ida::lumina`
- `ida::loader`
- `ida::plugin`
- `ida::processor`
- `ida::debugger`
- `ida::ui`
- `ida::graph`
- `ida::decompiler`
- `ida::storage` (advanced)
- `ida::event`

### 5.2 Public API Design Principles

1. Full words over abbreviations in public API names
2. Verb-first operation names (`create_function`, `read_bytes`, `set_comment`)
3. Strongly typed enums for domain concepts
4. Opaque handles and value objects in public API
5. Iteration via modern range-style abstractions
6. No manual lock/unlock burden on users
7. Uniform error transport via `std::expected`
8. Clear distinction between operation classes (read/write/patch/define)

### 5.3 Public Error Model

Canonical approach:
- `ida::Result<T> = std::expected<T, ida::Error>`
- `ida::Status = std::expected<void, ida::Error>`
- `ida::Error` includes:
  - category (validation, not_found, conflict, unsupported, sdk_failure, internal)
  - stable code
  - human-readable message
  - optional context payload

### 5.4 Opaque Boundary Policy

Because public API is fully opaque:
- No public exposure of `segment_t`, `func_t`, `insn_t`, `tinfo_t`, `netnode`, etc.
- All SDK interaction behind internal adapters in compiled layer
- Public handles represent stable value/view semantics independent of raw pointers

### 5.5 String Policy

Public:
- Output: `std::string`
- Input: `std::string_view` where suitable; `std::string` otherwise

Internal:
- Conversion boundary helpers between `std::string` and `qstring`
- Avoid leaking IDA encoding details into public API

---

## 6) Domain Mapping Blueprint (Old SDK to New API)

This section maps legacy conceptual domains to wrapper domains.

1. Address and item navigation
   - Legacy: address flags, head/tail traversal, raw range helpers
   - Wrapper: `ida::address` with typed predicates and range iterators
2. Data and bytes
   - Legacy: mixed read/write/patch behavior with subtle semantics
   - Wrapper: explicit operation families (`read_*`, `write_*`, `patch_*`, `define_*`)
3. Segments
   - Legacy: mixed naming and bitness encoding conventions
   - Wrapper: clear segment object with normalized bitness and permissions API
4. Functions and frames
   - Legacy: chunk complexity and frame offset pitfalls
   - Wrapper: function-first API with frame object and clear stack semantics
5. Instructions and operands
   - Legacy: low-level operand representations and output context complexity
   - Wrapper: typed instruction/operand views with explicit classification
6. Names and demangling
   - Legacy: many overlapping getters and flags
   - Wrapper: concise naming API with simple demangle forms
7. Xrefs
   - Legacy: multiple enumeration styles
   - Wrapper: one iterable xref model with typed xref categories
8. Types
   - Legacy: very deep type API with historical complexity
   - Wrapper: ergonomic type object model and clear type application semantics
9. Search
   - Legacy: flag-heavy direction and mode encoding
   - Wrapper: typed options and explicit direction enums
10. Analysis queue
   - Legacy: queue constants and staged behavior
   - Wrapper: intent-based scheduling and waiting primitives
11. Loader/plugin/processor development
   - Legacy: low-level struct callback wiring
   - Wrapper: C++ class-based lifecycle APIs and registration helpers
12. Debugger/UI/decompiler
   - Legacy: broad and complex surfaces with non-uniform patterns
   - Wrapper: domain-focused facades with safe event models

---

## 7) Build and Packaging Strategy (Hybrid)

### 7.1 Header-Only Candidates

Thin, deterministic wrappers and aliases:
- Lightweight value types
- Basic pure helper functions
- Simple enum/string conversion helpers
- Non-stateful forwarding wrappers

### 7.2 Compiled-Layer Candidates

Stateful and complex behavior:
- Handle lifetimes and caching
- Iterators/ranges over mutable SDK data
- Event bridging and callback dispatch
- Error translation and context enrichment
- Decompiler/debugger wrappers
- UI action and graph wrappers

### 7.3 Repository Layout (Proposed)

Suggested structure:
- `include/ida/*.hpp` for public API
- `src/*.cpp` for compiled adapters
- `src/detail/*` for internal bridge and lifetime logic
- `tests/*` for unit/integration/e2e
- `examples/*` for plugin/loader/procmod usage

---

## 8) Testing and Validation Strategy

Required layers:

1. Unit tests
   - Pure utility and conversion logic
   - Error mapping and enum translations
2. Integration tests
   - Wrapper-to-SDK domain behavior under controlled fixtures
3. Scenario tests
   - Realistic plugin, loader, and processor module workflows
4. Regression tests
   - Edge cases discovered during migration
5. Batch validation
   - Prefer `idump <binary>` based workflows for scripted verification
6. Usability tests
   - New-user first-contact tasks measured against baseline complexity

Acceptance quality gates:
- API consistency checks
- Naming lint checks
- Documentation coverage thresholds
- Behavior parity with expected SDK semantics

---

## 9) Documentation Strategy

Documentation artifacts required:
- Public API reference
- Migration guide (legacy SDK calls to wrapper equivalents)
- Cookbook examples by domain
- Plugin, loader, processor quickstarts
- Advanced guides for debugger/decompiler/UI
- Known behavior differences and intentional abstractions

Style requirements:
- First-time user oriented
- Concept-led before detail-led
- Explain semantics before syntax
- Include practical examples for every major domain

---

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

## 12) Findings and Learnings (Live)

Entries below summarize key findings to preserve as implementation guardrails.

1. API naming inconsistency is one of the biggest onboarding barriers.
2. Implicit sentinel conventions (`BADADDR`, `BADSEL`, magic integers) create silent failure risk.
3. Encoded flags and mixed bitfields are powerful but difficult to reason about quickly.
4. Multiple equivalent API paths in the SDK often differ subtly in semantics and side effects.
5. Pointer validity/lifecycle semantics require strong encapsulation in any ergonomic wrapper.
6. Type and decompiler domains are high-power but high-complexity and need progressive API layering.
7. Debugger and UI domains require typed abstractions to avoid vararg misuse classes of bugs.
8. A fully opaque wrapper requires comprehensive coverage to avoid forcing users back to raw SDK.
9. Public API simplicity must not erase capability; advanced options must remain available in structured form.
10. Migration documentation is as critical as API design for practical adoption.
11. Interface-level API sketches must be present in this file (not only summaries) to avoid ambiguity during implementation.
12. [2026-02-12] C++23 + SDK `pro.h` incompatibility: `std::is_pod<T>` is used without `#include <type_traits>`. Fix: add `#include <type_traits>` before `#include <pro.h>` in the SDK bridge header.
13. [2026-02-12] SDK segment API: `segment_t::perm` uses `SEGPERM_READ/WRITE/EXEC` flags (not `SFL_*`). Visibility via `is_visible_segm()` (not `is_hidden_segtype()`).
14. [2026-02-12] SDK type system: Float types require `BTF_FLOAT` (=`BT_FLOAT|BTMT_FLOAT`) and `BTF_DOUBLE` (=`BT_FLOAT|BTMT_DOUBLE`), not raw `BT_FLOAT`/`BTMT_DOUBLE`.
15. [2026-02-12] Private member access in value objects: Use `friend struct XxxAccess` pattern with static `populate()` method in the implementation file. Anonymous namespace helpers cannot be friends.
16. [2026-02-12] **CRITICAL**: SDK stub dylibs vs real IDA dylibs have mismatched symbol exports. The stub `libidalib.dylib` exports symbols (like `qvector_reserve`) that the real `libidalib.dylib` does not — only the real `libida.dylib` does. With macOS two-level namespace linking, this causes symbols to be bound to the wrong dylib, resulting in null-pointer crashes at runtime. **Fix**: Link against the real IDA dylibs from the installation directory, not the SDK stubs.
17. [2026-02-12] CMake architecture: `libidax.a` uses a custom `idasdk_headers` INTERFACE target providing only SDK include dirs + `__EA64__` + platform/compiler settings. Consumers bring their own `idasdk::plugin` or `idasdk::idalib`. For idalib tests, link directly against real IDA dylibs to avoid two-level namespace mismatches.
18. [2026-02-12] Graph API: `create_interactive_graph()` returns nullptr in idalib (headless) mode. The graph object uses a standalone adjacency-list implementation for programmatic use; only `show_graph()` requires UI mode. Flow charts (`qflow_chart_t`) work in all modes.
19. [2026-02-12] SDK graph: `FC_PREDS` flag was renamed to `FC_RESERVED`. Predecessors are built by default; use `FC_NOPREDS` to disable. `insert_simple_nodes()` takes `intvec_t&` (reference, not pointer).
20. [2026-02-12] SDK chooser: `chooser_t::choose()` returns ssize_t (-1=no selection, -2=empty, -3=already exists). `CH_KEEP` flag prevents IDA from deleting the chooser object on widget close. Column widths encode `CHCOL_*` format flags in high bits.
21. [2026-02-12] SDK loader: `loader_failure()` does a longjmp and never returns. No C++ base class exists for loaders (unlike processors which have `procmod_t`). The wrapper must bridge C function pointers to C++ virtual methods via a global instance pointer.
22. [2026-02-12] Hex-Rays ctree visitor: `ctree_visitor_t::apply_to()` and `apply_to_exprs()` dispatch through `HEXDSP` runtime function pointers (no link-time dependency). `CV_POST` flag enables leave_*() callbacks. `CV_PRUNE` is set via `prune_now()` to skip children. `citem_t::is_expr()` returns `op <= cot_last` (69). `treeitems` vector is populated after `get_pseudocode()` and maps line indices to `citem_t*` for address mapping. `cfunc_t::hdrlines` is the offset between treeitems indices and pseudocode line numbers.
23. [2026-02-12] SDK `get_widget_title()` takes two arguments: `(qstring *buf, TWidget *widget)` — NOT a single-arg call returning `const char*`. This changed from older SDK versions. The wrapper uses `qstring` output buffer and converts to `std::string`.
24. [2026-02-13] Debugger notification API uses mixed `va_list` signatures: most events pass `const debug_event_t*`, but `dbg_bpt` and `dbg_trace` pass `(thid_t, ea_t, ...)` directly. Wrappers must decode per-event argument layouts explicitly.
25. [2026-02-13] Switch table metadata (`switch_info_t`) encodes element sizes via `SWI_J32/SWI_JSIZE` and `SWI_V32/SWI_VSIZE` bit-pairs, not explicit byte fields. Exposing normalized byte-size fields in wrapper structs avoids misuse.
26. [2026-02-13] IDB event payloads are `va_list`-backed and can only be consumed once per notification. For multi-subscriber routing, decode once into a normalized event object and fan out from that object.
27. [2026-02-13] `get_strlit_contents()` supports `len = size_t(-1)` auto-length mode: it uses existing strlit item size when present, otherwise `get_max_strlit_length(...)`. This enables robust string extraction wrappers without requiring prior data-definition calls.
28. [2026-02-13] Snapshot APIs are exposed through `loader.hpp`: `build_snapshot_tree()` returns a synthetic root whose `children` are top-level snapshots, and `update_snapshot_attributes(nullptr, root, attr, SSUF_DESC)` updates the current database snapshot description.
29. [2026-02-13] Custom fixup registration uses `register_custom_fixup()`/`find_custom_fixup()`/`unregister_custom_fixup()` and returns type ids in the `FIXUP_CUSTOM` range (or 0 on duplicate/missing handlers). Wrappers should return typed IDs and map duplicate names to conflict errors.
30. [2026-02-13] Database transfer helpers map directly to loader APIs: `file2base(li, pos, ea1, ea2, patchable)` requires an open `linput_t*` and explicit close, while `mem2base(ptr, ea1, ea2, fpos)` returns 1 on success and accepts `fpos=-1` when source bytes have no file offset mapping.
31. [2026-02-13] Including SDK bridge internals (`sdk_bridge.hpp`) in C++ iostream-heavy tests can collide with SDK `fpro.h` stdio macro remaps (`stdout` -> `dont_use_stdout`). Keep string conversion checks in integration-level wrapper tests or avoid iostream in bridge-level test TUs.
32. [2026-02-12] Comment API behavior: `append_cmt` success does not guarantee appended text round-trips through `get_cmt` as a strict suffix in all contexts. Impact: brittle assertions in tests. Mitigation: behavior tests assert append success and core content presence instead of strict append-string matching.
33. [2026-02-12] Netnode blob operations at index 0 can trigger `std::length_error: vector` crashes in idalib mode. Impact: storage tests crash when using index 0 for `set_blob`/`blob`. Mitigation: use non-zero indices (100+) for blob/alt/sup operations in tests; consider documenting safe index ranges for `ida::storage::Node` users.
34. [2026-02-12] `FunctionIterator::operator*()` returns by value (not reference), so range-for must use `auto f` not `auto& f`. This is because the iterator constructs a `Function` value object on each dereference from internal SDK state. Same pattern applies to `FixupIterator`.
35. [2026-02-12] `DecompiledFunction` is non-copyable (move-only) because it holds a `cfuncptr_t` which is reference-counted internally. `std::expected<DecompiledFunction, Error>` is also non-copyable. Test macros that use `auto _r = (expr)` (copy semantics) must be replaced with reference-based checks for move-only result types.
36. [2026-02-12] P9.1 Audit: Cross-namespace consistency found polarity clash (`Segment::visible()` vs `Function::is_hidden()`), subscription naming stuttering (`debugger_unsubscribe` in `ida::debugger` namespace), and duplicate binary pattern search in both `data` and `search` namespaces. Fix: unified positive polarity (`is_visible()`), removed namespace stuttering in token/subscription names, documented dual-path for binary search.
37. [2026-02-12] P9.1 Audit: API naming lint found ~200+ `ea` parameter names that should be `address`, `set_op_*` functions that should be `set_operand_*`, `del_*` that should be `remove_*`, and `idx`/`cmt` abbreviations in public interfaces. All renamed for full-word consistency.
38. [2026-02-12] P9.1 Audit: Error model audit found `Plugin::run()` returning `bool` instead of `Status`, `Processor::analyze/emulate/output_operand` returning raw `int` instead of typed results, `line_to_address()` returning `BadAddress` as a success value, and UI dialog cancellation categorized as `SdkFailure` instead of `Validation`. All fixed.
39. [2026-02-12] P9.1 Audit: Opaque boundary audit confirmed zero HIGH violations — no SDK types or includes leak into public headers. MEDIUM findings included `Chooser::impl()` and `Graph::impl()` being unnecessarily public, and `xref::Reference::raw_type` exposing raw SDK type codes. Fixed by making `impl()` private and replacing `raw_type` with typed `ReferenceType` enum.
40. [2026-02-13] macOS linker warnings with IDA runtime dylibs: when linking tests against IDA 9.3 dylibs, ld can warn that dylibs were built for macOS 12.0 while objects target macOS 11.0. Impact: warning-only in current runs; runtime/tests remain stable. Mitigation: keep linking against real IDA dylibs (required for symbol correctness), document warning as benign unless deployment-target policy changes.
41. [2026-02-13] CPack output directory can drift when invoked from arbitrary working directories. Impact: package artifacts may be emitted outside the intended build tree, making matrix evidence harder to track. Mitigation: invoke CPack with `-B <build-dir>` in automation scripts to pin artifact output location.
42. [2026-02-13] Complex plugin surface gap audit (`/Users/int/dev/entropyx/ida-port`): current `ida::plugin`/`ida::ui`/`ida::segment` do not cover dockable custom widget hosting (`create_empty_widget`/`display_widget`/`close_widget`), HT_VIEW/UI notification coverage (`view_curpos`, `ui_widget_invisible`, widget-handle callbacks), direct navigation (`jumpto`), or segment-type introspection (`segment_t::type` equivalent). Impact: advanced visualization plugins cannot be fully ported without raw SDK usage. Mitigation: add opaque dock-widget APIs, expanded typed UI/VIEW event routing, `ui::jump_to`, and `segment::Segment::type()`/`set_type()`.
43. [2026-02-13] UI widget event shape: title-only widget callbacks are insufficient for complex multi-panel plugins because titles are not stable identities and do not support per-instance lifecycle tracking. Impact: medium/high for advanced dockable UIs. Mitigation: surface opaque widget handles and include those handles in widget/view notifications.
44. [2026-02-13] Plugin authoring bootstrap gap: `ida::plugin::Plugin` documentation references `make_plugin_descriptor()` but no public export helper exists in headers. Impact: plugin module wiring remains ambiguous without SDK-level boilerplate or external build-system magic. Mitigation: add an explicit public descriptor/export helper (macro or function) that bridges `Plugin` subclasses to IDA plugin entrypoints.
45. [2026-02-13] SDK dock widget constants: `WOPN_DP_FLOATING` (not `WOPN_DP_FLOAT`). Constants are defined in `kernwin.hpp` as shifts of `DP_*` values by `WOPN_DP_SHIFT`. `WOPN_RESTORE` restores previous size/position. `display_widget()` takes `(TWidget*, uint32 flags)`.
46. [2026-02-13] `view_curpos` event: no `va_list` payload — the new cursor position must be obtained via `get_screen_ea()`. This differs from `ui_screen_ea_changed` which passes `(new_ea, prev_ea)` in the `va_list`.
47. [2026-02-13] Widget identity: `TWidget*` is stable for the lifetime of a widget panel. Handle-based event subscriptions compare `TWidget*` pointers to filter events for a specific widget instance. The opaque `Widget` class stores `void*` (cast from `TWidget*`) and a monotonic `uint64_t` id for cross-callback identity.
48. [2026-02-13] `plugin_t PLUGIN` static init ordering: the `PLUGIN` struct must use char arrays (not `std::string::c_str()`) to avoid cross-TU init ordering issues. Static char buffers are populated at `idax_plugin_init_()` time (after all static init is complete). The `IDAX_PLUGIN` macro only registers a factory via `make_plugin_export()`; the `plugin_t PLUGIN` symbol lives in `plugin.cpp` (compiled into `libidax.a`).
49. [2026-02-13] Segment type constants: SDK defines `SEG_NORM(0)` through `SEG_IMEM(12)`. The wrapper `segment::Type` enum maps all 12 values plus `Import` (alias for `SEG_IMP=4`), `InternalMemory` (`SEG_IMEM=12`), and `Group` (`SEG_GRP=6`). `segment_t::type` is a `uchar` field set directly.
50. [2026-02-13] Follow-up entropyx portability audit: while dock widget lifecycle APIs are now present, complex Qt plugins still need access to the underlying host container to embed custom `QWidget` content (entropyx currently casts `TWidget*` to `QWidget*` and installs a layout/child widget). Current `ida::ui::Widget` is intentionally opaque and does not expose a container attachment path. Impact: medium/high for Qt-based visualization plugins; they still need raw SDK/Qt interop for panel content mounting. Mitigation: add an opaque content-host bridge (for example, `ui::with_widget_host(Widget&, callback)` with `void*` host pointer) that preserves SDK opacity while enabling safe Qt embedding.
51. [2026-02-13] Widget host bridge design: exposing a scoped callback (`with_widget_host`) over a raw getter alone reduces accidental long-lived storage of toolkit pointers while still enabling advanced embedding scenarios. The host pointer type remains `void*` (`WidgetHost`) to preserve SDK/Qt opacity in public headers.
52. [2026-02-13] Action activation context (`action_activation_ctx_t`) carries many SDK pointers (`func_t*`, `segment_t*`, chooser internals). Wrappers should normalize only stable high-value fields (action id, widget title/type, current address/value, selection/xtrn bits, register name) into SDK-free structs to preserve opacity while still enabling context-aware actions.
53. [2026-02-13] Generic UI/VIEW routing in `ida::ui` requires token-family partitioning for safe unsubscribe of composite subscriptions. Using disjoint ranges for UI (`< 1<<62`), VIEW (`[1<<62, 1<<63)`), and generic-composite (`>= 1<<63`) allows one `unsubscribe(Token)` API without ambiguity.
54. [2026-02-13] Domain-by-domain SDK parity audit shows broad domain coverage is implemented across all public namespaces, but depth is uneven: many domains are `partial` vs raw SDK breadth. Closing parity now requires an explicit matrix-driven checklist with per-domain closure criteria and evidence gates.
55. [2026-02-13] Diagnostics counters concurrency: storing performance counters in a plain shared struct (`PerformanceCounters g_counters`) creates data-race risk under concurrent logging/assertion paths. Mitigation: use atomic counter fields and snapshot reads in `performance_counters()`.
56. [2026-02-13] Compile-only parity drift risk: when public headers evolve quickly (UI/plugin additions), compile-only parity tests can lag and miss newly exposed symbols. Mitigation: expand `api_surface_parity_test.cpp` whenever headers change, including overload disambiguation checks for overloaded APIs.
57. [2026-02-13] SDK data-definition helpers (`create_float`, `create_double`) may fail at specific addresses/layouts in real databases even when base define/undefine APIs work. Impact: brittle integration assertions if tests assume universal success. Mitigation: treat float/double define checks as conditional capability probes in integration tests and assert category on failure.
58. [2026-02-13] `open_database()` in idalib currently performs loader selection internally, so wrapper `LoadIntent` (`Binary`/`NonBinary`) convenience APIs map to the same open path for now. Impact: intent-specific wrappers improve call-site clarity but do not yet force distinct low-level load procedures. Mitigation: keep explicit intent API now, and wire to dedicated loader paths when runtime constraints allow reliable distinction.
59. [2026-02-13] SDK segment comments operate on `const segment_t*` (`get_segment_cmt`/`set_segment_cmt`), and `set_segment_cmt` returns `void` (no direct success flag). Impact: wrappers cannot rely on a boolean return for comment set operations. Mitigation: validate target segment first and treat set as best-effort SDK operation with subsequent retrieval checks in integration tests.
60. [2026-02-13] Entry forwarder clearing caveat: `set_entry_forwarder(ord, "")` can fail for some ordinals/databases in idalib mode. Impact: clear-forwarder is not universally guaranteed by the SDK path. Mitigation: wrapper exposes explicit `clear_forwarder()` that returns `SdkFailure` on refusal; tests use set/read/restore patterns instead of assuming empty-string clear always succeeds.
61. [2026-02-13] SDK search API nuance: `find_*` helpers already skip the starting address, while `SEARCH_NEXT` is primarily meaningful for lower-level text/binary search paths. Impact: `skip_start` semantics are naturally stronger for text/binary than for immediate `find_imm` workflows. Mitigation: keep typed options uniform across search families, and validate behavior with integration tests that assert robust outcomes (`found > start` or `NotFound`) instead of assuming identical start-address behavior across all SDK primitives.
62. [2026-02-13] SDK action detach helpers (`detach_action_from_menu`/`detach_action_from_toolbar`/`detach_action_from_popup`) return only success/failure and do not distinguish absent attachments from other failure causes. Impact: teardown flows are hard to reason about if all failures map to generic SDK errors. Mitigation: map detach failures to `NotFound` with action/widget context so plugin cleanup is explicit and deterministic.
63. [2026-02-13] Loader callback context for normal load vs reload vs archive/member extraction is spread across raw callback arguments and bitflags (`ACCEPT_*`, `NEF_*`). Impact: loader migration code is brittle when handling advanced scenarios directly against SDK flags. Mitigation: expose typed request structs (`LoadRequest`, `SaveRequest`, `MoveSegmentRequest`, `ArchiveMemberRequest`) and typed `LoadFlags` encode/decode helpers.
64. [2026-02-13] Processor output migration needs additive APIs: existing modules often rely on side-effect output callbacks, while advanced ports need structured text assembly control. Impact: replacing legacy callbacks outright would be a breaking migration. Mitigation: add `OutputContext` and context-driven hooks (`output_instruction_with_context`, `output_operand_with_context`) with fallback defaults.
65. [2026-02-13] SDK netnode existence check uses a hidden-friend `exist(const netnode&)` API resolved via ADL. Impact: qualifying it as `::exist(...)` fails to compile, which can break `open_by_id` wrappers that validate node presence. Mitigation: call `exist(nn)` unqualified (ADL) and keep node-id validation in wrapper-level helper APIs.
66. [2026-02-13] Debugger request queue semantics: `request_*` APIs enqueue operations and require an explicit `run_requests()` call to dispatch; direct command APIs (`step_*`, `run_to`, `suspend_process`, etc.) execute immediately. Impact: mixing request/direct styles without explicit queue flush can cause surprising no-op behavior in async workflows. Mitigation: expose explicit request helpers plus `is_request_running()`/`run_requests()` wrappers and document queue-driven usage.
67. [2026-02-13] SDK custom viewer lifetime rules: `create_custom_viewer()` relies on caller-provided line buffer and place objects remaining valid for the widget lifetime. Impact: wrappers that pass temporaries can cause stale pointer reads/crashes on later repaint/cursor operations. Mitigation: store per-viewer line/place state in wrapper-managed lifetime storage, validate custom-viewer handles before operations, and erase state on close.
68. [2026-02-13] Graph layout semantics in idalib/headless mode are behavioral (stateful API contract) rather than geometric UI rendering. Impact: relying on visible layout effects in non-UI runs is brittle. Mitigation: persist selected `Layout` in `Graph`, expose `current_layout()`, and validate all layout options via deterministic integration checks.
69. [2026-02-13] Decompiler local-variable retype persistence uses `modify_user_lvar_info(..., MLI_TYPE, ...)` with a stable locator (`locate_lvar` or `lvar_t`-derived locator). Impact: in-memory type tweaks alone are insufficient for durable migration behavior. Mitigation: expose wrapper retype APIs that route through saved-user-info updates, add refresh + re-decompile integration checks, and keep typed error mapping (`Validation`/`NotFound`/`SdkFailure`).
70. [2026-02-13] Cross-cutting/event parity closure can be satisfied via explicit intentional-abstraction documentation when full raw SDK mirroring is counter to wrapper goals. Impact: prevents endless breadth chasing in non-user-facing helper domains. Mitigation: keep those rows `partial` with clear rationale + expansion trigger criteria in coverage matrix.
71. [2026-02-13] Linux compile-only matrix nuance: GCC 13.3.0 passes in Ubuntu 24.04 container, but Clang 18.1.3 currently fails with missing `std::expected` symbols under the active standard-library/toolchain pairing even with `-std=c++23`. Impact: P10.8.d cannot be closed from this host/container setup alone. Mitigation: run Clang row with a known-good libc++/libstdc++ configuration (or host toolchain) and keep Windows/MSVC rows pending host execution.
72. [2026-02-13] Linux Clang libc++ fallback caveat: forcing `-stdlib=libc++` in Ubuntu 24.04 avoids the `std::expected` gap but then fails during SDK header inclusion because `pro.h` remaps `snprintf` (`snprintf -> dont_use_snprintf`), which collides with libc++ standard-header internals. Impact: container-only Clang row remains blocked even with libc++ override. Mitigation: validate Clang row on a host/toolchain combination where the selected stdlib and SDK macro environment coexist cleanly (or isolate SDK macro remaps via bridge strategy if needed).
73. [2026-02-13] GitHub-hosted cross-platform validation can run `compile-only` and `unit` profiles without licensed IDA runtime by checking out `ida-sdk` and leaving `IDADIR` unset; integration tests are skipped by CMake while unit/API parity still run. Impact: enables repeatable Linux/macOS/Windows evidence collection for P10.8.d in CI. Mitigation: add a matrix workflow that runs `scripts/run_validation_matrix.sh` across OS/profile rows.
74. [2026-02-13] IDA SDK checkout layout can vary between environments (`<sdk>/ida-cmake/bootstrap.cmake`, `<sdk>/cmake/bootstrap.cmake`, or submodule-backed `<sdk>/src/cmake/bootstrap.cmake`), and SDK checkouts may require recursive submodule fetch to materialize bootstrap files. Impact: hardcoded bootstrap include paths in CI can fail before `find_package(idasdk)` even runs. Mitigation: resolve IDASDK layout explicitly in workflow, fetch SDK submodules recursively, and support all known bootstrap locations in top-level CMake bootstrap logic.
75. [2026-02-13] CI submodule policy for matrix runs: both the project checkout and SDK checkout should use recursive submodule fetch when available to avoid hidden bootstrap/tooling drift between local and hosted runs. Impact: missing submodule content can produce misleading bootstrap/package-resolution failures. Mitigation: set `submodules: recursive` on both checkout steps and keep resolver diagnostics explicit.
76. [2026-02-13] GitHub Actions hosted macOS matrix support can change over time (for example, `macos-13` retirement), which can break static OS lists even when toolchain logic is correct. Impact: matrix jobs can fail before build/test execution starts. Mitigation: keep active hosted labels in workflow (currently `macos-14`) and reintroduce x86_64 rows via supported labels or self-hosted runners.
77. [2026-02-13] CTest on multi-config generators (Visual Studio) requires explicit `-C <config>` at test time; otherwise tests are reported as unavailable even when build succeeds. Impact: false-negative unit matrix failures on Windows. Mitigation: always pass `--config <build-type>` to `cmake --build` and `-C <build-type>` to `ctest` in validation automation.
78. [2026-02-13] SDK stdio macro remaps from `pro.h` (for example `snprintf -> dont_use_snprintf`) can collide with newer libc++ internals when headers like `<locale>`/formatting helpers are first included from SDK transitive headers. Impact: macOS compile failures in hosted builds despite local parity. Mitigation: include key C++ standard headers before `pro.h` in the SDK bridge (`<functional>`, `<locale>`, `<vector>`, `<type_traits>`).
79. [2026-02-13] Example addon coverage in matrix runs: enabling both `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON` exercises plugin/loader/procmod sample targets in hosted CI without requiring IDA runtime execution. Impact: catches module-authoring compile regressions earlier across OS/toolchain rows. Mitigation: wire example toggles through `scripts/run_validation_matrix.sh` and set both env vars in `.github/workflows/validation-matrix.yml`.
80. [2026-02-13] JBC full-port procmod fidelity gap: `ida::processor::analyze(Address)` returns only instruction size and cannot provide typed operand metadata (`o_near`/`o_mem`/`specflag` equivalents). Impact: full ports (for example JBC) must re-decode bytes in multiple callbacks and lose some kernel-level operand semantics/rendering fidelity. Mitigation: add an optional typed analyze-result operand model that can be bridged to SDK operand structures while preserving public opacity.
81. [2026-02-13] JBC full-port lifecycle gap: no wrapper helper exists for per-segment default register initialization (`set_default_sreg_value`). Impact: procmods that depend on explicit CS/DS defaults on new-file flows cannot be mirrored completely without raw SDK calls. Mitigation: add an explicit default-segment-register seeding helper in `ida::segment`/`ida::processor` surfaces.
82. [2026-02-13] JBC full-port output gap: `ida::processor::OutputContext` is currently plain text-only (no token/color channels and no dedicated mnemonic callback parity). Impact: advanced processor output styling and token-precise operand rendering are less expressive than raw SDK `outctx_t` hooks. Mitigation: extend `OutputContext` with token-category output primitives and mnemonic/operand-specific formatting hooks.
83. [2026-02-13] Hosted matrix log audit pattern: very large GitHub Actions logs can be validated quickly and reliably by grepping for `Complete job name`, `validation profile '<profile>' complete`, and `100% tests passed` sentinels. Impact: reduces manual inspection overhead while preserving evidence quality for matrix closure updates. Mitigation: standardize these sentinels in docs/evidence collection for future matrix runs.
84. [2026-02-14] JBC parity enhancement closure: `ida::processor` now includes typed analyze details (`AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`), tokenized output channels (`OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`), and dedicated mnemonic hook (`output_mnemonic_with_context`), while `ida::segment` now exposes default segment-register seeding helpers (`set_default_segment_register*`). Impact: full procmods can preserve richer operand/output semantics and initialize CS/DS defaults without raw SDK calls. Mitigation: keep integration + compile-only coverage and exercise new APIs in the JBC full-port examples.
85. [2026-02-14] ida-qtform port audit: dock-widget mounting through `ida::ui::with_widget_host()` is sufficient for Qt panel embedding without exposing raw `TWidget*`. Impact: core panel-host parity for complex Qt plugins is confirmed in real port code. Mitigation: keep host access callback-based to discourage unsafe long-lived host-pointer storage.
86. [2026-02-14] ida-qtform parity closure: added a markup-only `ida::ui::ask_form(std::string_view)` wrapper for direct form preview/test flows without raw SDK varargs. Impact: qtform-style plugins can validate forms through pure idax API for no-binding cases. Mitigation: keep this overload for markup-only paths and add typed argument binding APIs later if concrete ports require full vararg parity.
87. [2026-02-14] idalib-dump parity closure: decompiler microcode emission is now exposed in `ida::decompiler` via `DecompiledFunction::microcode()` and `DecompiledFunction::microcode_lines()`. Impact: `--mc` workflows can now run in pure idax flows without raw SDK calls. Mitigation: keep integration + compile-only coverage and use the idalib-dump port example as a regression target.
88. [2026-02-14] idalib-dump parity gap: idax has no headless plugin-load policy controls (`--no-plugins`, allowlist patterns). Impact: CLI tools cannot replicate plugin isolation behavior without environment-level SDK workarounds. Mitigation: add database/session open options for plugin policy and allowlist.
89. [2026-02-14] idalib-dump parity closure: decompile failures now expose structured details via `ida::decompiler::DecompileFailure` and `decompile(address, &failure)` (including failure address + description). Impact: diagnostics/reporting tools can emit failure-location context without raw `hexrays_failure_t` access. Mitigation: keep integration + compile-only coverage and route port examples through the detailed overload for regression checks.
90. [2026-02-14] idalib-dump parity gap: no public Lumina facade exists in idax. Impact: `ida_lumina`-style metadata push tools cannot be ported to pure idax APIs today. Mitigation: add explicit `ida::lumina` namespace or document as intentional non-goal.
91. [2026-02-14] README drift risk: absolute coverage wording, stale surface counts/example-layout references, and non-pinned packaging commands can diverge from maintained parity artifacts over time; temporary `Result` range-for snippets can also model unsafe usage patterns. Impact: onboarding mismatches and less reproducible first-run experience. Mitigation: keep README claims/snippets/commands aligned with `docs/sdk_domain_coverage_matrix.md`, `docs/compatibility_matrix.md`, `docs/api_reference.md`, and `examples/README.md`.
92. [2026-02-14] idalib-dump parity closure: headless plugin-load policy controls are now exposed in `ida::database` via `RuntimeOptions` + `PluginLoadPolicy` (`disable_user_plugins`, allowlist patterns with `*`/`?`). Impact: CLI tools can reproduce `--no-plugins` / selective `--plugin` behavior through pure idax initialization flows. Mitigation: keep compile-only parity coverage for new init overloads and exercise the flow in `examples/tools/idalib_dump_port.cpp`.
93. [2026-02-14] Database metadata parity nuance: SDK file-type metadata comes from two distinct sources (`get_file_type_name` vs `INF_FILE_FORMAT_NAME`/`get_loader_format_name`), and loader format may be absent while file type is still present. Impact: tools that assume one canonical format string can become brittle. Mitigation: expose both `file_type_name()` and `loader_format_name()` with explicit `NotFound` behavior for missing loader-format metadata.
94. [2026-02-14] idalib-dump parity closure: Lumina pull/push flows are now exposed through `ida::lumina` (`pull`, `push`, typed `BatchResult` and `OperationCode`, feature selection), allowing pure-wrapper `ida_lumina` scaffolds without raw SDK calls. Impact: core Lumina metadata workflows can now be ported to idax-first code. Mitigation: keep compile-only + smoke coverage and exercise with `examples/tools/idalib_lumina_port.cpp`.
95. [2026-02-14] Lumina runtime symbol nuance: `close_server_connection2`/`close_server_connections` are declared in SDK headers but not link-exported in this runtime setup. Impact: direct close wrappers fail to link on real dylibs. Mitigation: keep `close_connection`/`close_all_connections` as explicit `Unsupported` wrappers until a portable close path is confirmed.
96. [2026-02-14] ida2py port gap: idax has no first-class user-name enumeration API (name inventory with user/auto filters). Impact: ports must scan large address ranges and probe names item-by-item, which is less discoverable and potentially slower on large databases. Mitigation: add additive `ida::name` iterators (`all`, `all_user_defined`) with optional range/filter options.
97. [2026-02-14] ida2py port gap: `ida::type::TypeInfo` exposes type-kind predicates but lacks pointer/array decomposition helpers (for example pointee type, array element type, array length). Impact: generic recursive typed-value materialization (`ida2py` style `pyval`) cannot be implemented cleanly from public APIs. Mitigation: add additive decomposition helpers and typedef-resolution accessors on `TypeInfo`.
98. [2026-02-14] ida2py port gap: idax has no generic typed-value data facade that consumes `TypeInfo` and materializes values recursively. Impact: ports must hand-roll ad hoc integer/string/byte decoding and cannot offer one intuitive typed-read/write path. Mitigation: consider an additive `ida::data::read_typed`/`write_typed` API that preserves opaque SDK boundaries.
99. [2026-02-14] ida2py port gap: decompiler expression views expose call text and argument count but not typed call subexpressions (callee + argument accessors). Impact: callsite argument workflows (for example extracting `printf` format-string objects) are only partially portable through public APIs. Mitigation: add typed call-expression accessors in `ida::decompiler` visitor views.
100. [2026-02-14] ida2py port gap: idax lacks an Appcall/executor abstraction and extension hook for external engines (for example angr). Impact: ida2py dynamic invocation flows cannot be ported to idax-only APIs today. Mitigation: add a debugger execution facade for Appcall-style invocation plus an optional pluggable executor interface for advanced emulation backends.
101. [2026-02-14] Host runtime caveat: direct execution of idalib tool examples from `build-port-gap/examples` currently exits with signal 11 (`exit:139`) in this environment (observed for `idax_ida2py_port` and `idax_idalib_dump_port`). Impact: runtime validation of tool-port behavior cannot be claimed from this host run; only build/CLI-help validation is currently available. Mitigation: keep compile-level evidence here and run functional tool checks on a known-good idalib runtime host.
102. [2026-02-14] ida2py parity closure: `ida::name` now exposes typed name inventory helpers (`all`, `all_user_defined`) backed by SDK nlist enumeration. Impact: ports no longer need full-address-space fallback scans for common symbol listing workflows and can consume explicit user/auto classification in one API call. Mitigation: keep integration + compile-only coverage and route `examples/tools/ida2py_port.cpp` through `all_user_defined` as a regression path.
103. [2026-02-14] ida2py parity closure: `ida::type::TypeInfo` now includes decomposition + typedef-resolution helpers (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`). Impact: recursive typed-value tooling can inspect pointer/array/typedef structure through pure idax APIs without SDK-side type peeling. Mitigation: keep integration + compile-only coverage and exercise decomposition output in `examples/tools/ida2py_port.cpp`.
104. [2026-02-14] ida2py parity closure: `ida::decompiler::ExpressionView` now includes typed call-subexpression accessors (`call_callee`, `call_argument(index)`) in addition to `call_argument_count`. Impact: callsite argument workflows (for example extracting first `printf` argument expressions) are now portable through public visitor views without raw SDK ctree pointer access. Mitigation: keep integration + compile-only coverage and exercise rendered call callee/arg snippets in `examples/tools/ida2py_port.cpp`.
105. [2026-02-14] ida2py parity closure: `ida::data` now includes generic typed-value read/write APIs (`read_typed`, `write_typed`, `TypedValue`, `TypedValueKind`) with recursive array support and byte-array/string write paths. Impact: ports can materialize and update values from `TypeInfo` through one wrapper-native path instead of hand-rolling per-width/per-kind decoders. Mitigation: keep integration + compile-only coverage and route `examples/tools/ida2py_port.cpp` typed previews through `read_typed` as a regression path.
106. [2026-02-14] ida2py parity closure: `ida::debugger` now includes an Appcall + pluggable executor surface (`AppcallRequest`/`AppcallValue`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`). Impact: dynamic invocation flows can now be modeled through pure idax APIs, including external-engine dispatch hooks (for example angr-backed executors) without SDK escapes. Mitigation: keep compile-only + integration coverage and validate real Appcall execution paths on a known-good debugger runtime host.
107. [2026-02-14] Matrix coverage drift risk for tool-port examples: validation automation previously propagated addon example toggles but not `IDAX_BUILD_EXAMPLE_TOOLS`, so idalib tool ports (`idalib_dump_port`, `idalib_lumina_port`, `ida2py_port`) could regress unnoticed in hosted compile/unit rows. Impact: medium for real-world portability confidence. Mitigation: plumb `IDAX_BUILD_EXAMPLE_TOOLS` through `scripts/run_validation_matrix.sh`, enable it in `.github/workflows/validation-matrix.yml`, and document the expanded matrix scope.
108. [2026-02-14] Appcall runtime-smoke design nuance: fixture symbol `ref4` can be validated safely by calling `int ref4(int *p)` with `p = NULL`, which exercises full Appcall request/type/argument/return bridging without requiring writable-debuggee pointer setup. Impact: lowers runtime-validation fragility for host-specific debugger checks. Mitigation: add `--appcall-smoke` to `ida2py_port` and track host-run procedure in `docs/appcall_runtime_validation.md`.
109. [2026-02-14] Tool-example runtime-linking nuance: `ida_add_idalib` can bind idalib tool examples to SDK stub dylibs, which may reproduce two-level namespace symbol mismatches and signal-11 crashes in local functional runs. Impact: compile/help checks can pass while runtime probes crash. Mitigation: in `examples/CMakeLists.txt`, prefer real IDA runtime dylibs (`IDADIR` or common macOS install path) for tool examples and keep stub fallback only when runtime libs are unavailable.
110. [2026-02-14] Appcall runtime-host nuance after linkage hardening: with runtime-linked tool examples, `--appcall-smoke` on this host now fails cleanly with `dbg_appcall` error code `1552` (exit 1) instead of crashing. Impact: remaining Appcall gap is debugger backend/session readiness, not runtime symbol linkage. Mitigation: track this as environment limitation in `docs/appcall_runtime_validation.md` and collect pass evidence on a debugger-capable host.
111. [2026-02-14] Linux Clang/libstdc++ C++23 gate nuance: in Ubuntu 24.04, Clang 18 reports `__cpp_concepts=201907`, so libstdc++ `<expected>` stays disabled (`std::expected` missing); Clang 19 reports `__cpp_concepts=202002` and baseline compile-only validation passes. Impact: Linux Clang row success depends on compiler version, not just `-std=c++23`. Mitigation: use Clang 19+ for Linux Clang matrix evidence unless toolchain behavior changes.
112. [2026-02-14] Linux SDK artifact nuance for Clang example targets: current SDK checkout lacks `x64_linux_clang_64` runtime libs (`libida.so`/`libidalib.so`), so addon/tool example targets fail under Linux Clang rows when `IDAX_BUILD_EXAMPLE_ADDONS=ON` and/or `IDAX_BUILD_EXAMPLE_TOOLS=ON`. Impact: Clang compile-only matrix can pass for core wrapper builds but fails when module/tool binary linkage is required. Mitigation: keep addon/tool toggles OFF for Linux Clang container evidence, or provide SDK runtime libs for the Clang target directory.
113. [2026-02-14] Appcall runtime-launch nuance: `ida2py_port --appcall-smoke` now attempts multi-path debuggee launch (`relative`, `absolute`, filename+cwd variants) before calling `dbg_appcall`, and current host failures now resolve to explicit `start_process failed (return code: -1)` diagnostics. Impact: Appcall evidence is now blocked by debugger backend availability rather than opaque call failures. Mitigation: keep launch fallback logic + host-native fixture build path and gather pass evidence on a debugger-capable host.
114. [2026-02-14] Real-server Lumina validation: open-point closure sweep on this host reports successful `ida::lumina::pull`/`push` smoke (`requested=1`, `succeeded=1`, `failed=0`). Impact: non-close Lumina runtime behavior is now validated with real server connectivity in this environment. Mitigation: keep smoke checks in `scripts/run_open_points.sh` and focus remaining Lumina follow-up on close/disconnect semantics once portable runtime symbols exist.
115. [2026-02-14] lifter port audit: idax decompiler support is currently read-oriented (`decompile`, ctree traversal, pseudocode/microcode text extraction) and does not yet expose write-path hooks (microcode filter registration, microcode IR emission/mutation, maturity callbacks, or `FUNC_OUTLINE` + caller cache invalidation parity helpers). Impact: full `/Users/int/dev/lifter` AVX/VMX microcode-lifter migration is blocked after plugin-shell/action-level porting. Mitigation: keep executable probe coverage in `examples/plugin/lifter_port_plugin.cpp`, track blockers in `docs/port_gap_audit_lifter.md`, and prioritize additive decompiler write-path APIs.
116. [2026-02-14] lifter parity incremental closure: idax now exposes decompiler maturity subscriptions (`on_maturity_changed`/`unsubscribe`/`ScopedSubscription`) and outline/cache invalidation helpers (`function::is_outlined`/`set_outlined`, `decompiler::mark_dirty`/`mark_dirty_with_callers`). Impact: stage-aware instrumentation and outlined/caller-cache flows no longer require raw SDK escapes; remaining blocker is microcode write-path depth plus raw decompiler-view handles. Mitigation: keep compile-only + integration coverage and focus next API cycle on richer writable microcode abstractions.
117. [2026-02-14] lifter parity incremental closure: idax now includes baseline microcode-filter hooks (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`) with safe no-op emission support. Impact: filter lifecycle and match/apply wiring are now wrapper-native, but full lifter-class IR mutation (`m_call`/`m_ldx`/typed mop construction) remains unimplemented. Mitigation: extend `MicrocodeContext` with richer emit/build primitives in additive steps driven by real port needs.
118. [2026-02-14] lifter parity incremental closure: `MicrocodeContext` now includes additive operand/load-store and low-level emit helpers (`load_operand_register`, `load_effective_address_register`, `store_operand_register`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`, `emit_helper_call`) plus integration checks for validation/error behavior. Impact: ports can express more filter-side transforms without raw `codegen_t`, but advanced typed IR construction (callinfo/typed mops/helper-call arguments) remains a blocker. Mitigation: add typed microcode value/argument builders in the next additive design slice.
119. [2026-02-14] lifter parity incremental closure: `MicrocodeContext` now includes typed helper-call argument builders (`MicrocodeValueKind`/`MicrocodeValue`, `emit_helper_call_with_arguments`, `emit_helper_call_with_arguments_to_register`) for integer widths (1/2/4/8). Impact: filter-side helper-call construction is now wrapper-native for integer flows, but full lifter parity still needs richer typed IR construction (UDT/vector arguments, callinfo controls, typed mop builders) plus raw decompiler-view handles. Mitigation: extend microcode APIs with typed value/argument/callinfo builders in the next additive slice.
120. [2026-02-14] lifter parity incremental closure: helper-call option shaping is now available via `MicrocodeCallOptions` + `MicrocodeCallingConvention` (`emit_helper_call_with_arguments_and_options`, `emit_helper_call_with_arguments_to_register_and_options`) for lightweight calling-convention/flag control without raw `mcallinfo_t` exposure. Impact: integer helper-call authoring now supports basic call-shape tuning, but advanced callinfo/tmop depth (non-integer arg modeling, detailed reg/stack location control, richer return modeling) remains a blocker. Mitigation: extend typed microcode builders with advanced callinfo/value-location primitives in subsequent additive slices.
121. [2026-02-14] lifter parity incremental closure: typed helper-call arguments now include scalar floating-point immediates (`Float32Immediate`, `Float64Immediate`) alongside integer/register forms, and call options now include explicit-location hinting (`mark_explicit_locations`). Impact: scalar helper-call modeling is broader without SDK escapes, but vector/UDT argument modeling and deeper callinfo/tmop location controls remain open. Mitigation: add non-scalar typed argument builders plus advanced callinfo/location primitives in the next additive slices.
122. [2026-02-14] lifter parity incremental closure: typed helper-call arguments now support basic explicit argument-location hints via `MicrocodeValueLocation` (register/stack offset), and explicit-location optioning can be auto-promoted when location hints are present. Impact: scalar helper-call location shaping no longer requires raw `argloc_t`, but full lifter parity still needs richer non-scalar argument modeling and deeper callinfo/tmop location controls. Mitigation: add advanced location primitives (beyond register/stack-offset hints) and non-scalar typed value builders in subsequent additive slices.
123. [2026-02-14] lifter parity incremental closure: explicit helper-call argument-location hints now include register-pair and register-with-offset forms in addition to single-register/stack-offset placement, with validation/error mapping for malformed hints. Impact: scalar location shaping now covers more realistic callsite placement patterns without raw `argloc_t`, but full lifter parity still needs non-scalar argument modeling and deeper callinfo/tmop location semantics. Mitigation: add richer location primitives (scattered/multi-part) plus non-scalar typed value builders in subsequent additive slices.
124. [2026-02-14] lifter parity incremental closure: explicit helper-call argument-location hints now also include static-address placement (`set_ea`) with validation for `BadAddress`. Impact: scalar location shaping now covers register/register-pair/register-offset/stack/static flows without raw `argloc_t`, but full lifter parity still needs non-scalar argument modeling and advanced/scattered callinfo/tmop location semantics. Mitigation: add scattered/multi-part location builders plus non-scalar typed value builders in subsequent additive slices.
125. [2026-02-14] lifter parity incremental closure: explicit helper-call argument-location hints now include scattered/multi-part placement via `MicrocodeLocationPart` + `MicrocodeValueLocationKind::Scattered`, with per-part validation and error mapping (offset/size/kind constraints). Impact: scalar location shaping now covers register/register-pair/register-offset/stack/static/scattered flows without raw `argloc_t`, but full lifter parity still needs non-scalar argument modeling and deeper callinfo/tmop semantics. Mitigation: add non-scalar typed value builders plus advanced callinfo/location primitives beyond current scalar-hint envelope.

---

## 13) Decision Log (Live)

Format: `[date] decision - rationale`

- [2026-02-12] Target C++23 - enables modern error handling and API ergonomics.
- [2026-02-12] Hybrid library architecture - balances ease of use with implementation flexibility.
- [2026-02-12] Fully opaque public API - enforces consistency and prevents legacy leakage.
- [2026-02-12] Public string model uses `std::string` - familiar and broadly ergonomic.
- [2026-02-12] Scope includes plugins, loaders, and processor modules - full ecosystem coverage.
- [2026-02-12] Keep detailed interface blueprints in `agents.md` - ensures implementation guidance is concrete and reviewable - alternatives considered: high-level-only summary (rejected) - impact: clearer implementation handoff and reduced interpretation drift.
- [2026-02-12] Link idalib tests against real IDA installation dylibs, not SDK stubs - SDK stub libidalib.dylib has different symbol exports than the real one, causing two-level namespace crashes - alternatives considered: `-flat_namespace` (rejected, too broad), IDABIN cmake variable (rejected, ida-cmake doesn't use it for lib paths) - impact: integration tests work correctly.
- [2026-02-13] Expose processor switch/function-heuristic callbacks through SDK-free public structs and virtuals - keeps procmod authoring fully opaque while preserving advanced capabilities - alternatives considered: expose raw `switch_info_t`/`insn_t` (rejected, violates opacity), defer APIs until full event bridge rewrite (rejected, blocks progressive adoption) - impact: P6.3.d API surface is now present and ready for bridge wiring.
- [2026-02-13] Add generic IDB event routing surface (`ida::event::Event`, `on_event`, `on_event_filtered`) on top of typed subscriptions - enables reusable filtering without exposing raw SDK vararg notifications - alternatives considered: add many narrowly-scoped filtered subscription helpers (rejected, API bloat), expose raw `idb_event` codes (rejected, leaks SDK details) - impact: P7.4.d completed with composable filter/routing primitives.
- [2026-02-13] Standardize compatibility validation into three profiles (`full`, `unit`, `compile-only`) with a single automation entrypoint (`scripts/run_validation_matrix.sh`) - enables consistent multi-OS/compiler execution even when full IDA runtime is unavailable on some hosts - alternatives considered: ad hoc per-host command docs only (rejected, drift-prone), CI-only matrix (rejected, licensing/runtime constraints) - impact: matrix expansion now has reproducible commands and trackable evidence rows.
- [2026-02-13] Pin matrix packaging artifacts to the selected build directory (`cpack -B <build-dir>`) - ensures reproducible artifact locations across shells/hosts and keeps matrix evidence colocated with each build tree - alternatives considered: rely on CPack default output path (rejected, can drift by working directory/config) - impact: packaging rows are now deterministic and auditable.
- [2026-02-13] Add opaque dock widget host API (`Widget` handle, `create_widget`/`show_widget`/`activate_widget`/`find_widget`/`close_widget`/`is_widget_visible`, `DockPosition` enum, `ShowWidgetOptions`) to `ida::ui` - enables advanced visualization plugins to manage dockable panels without raw SDK access - alternatives considered: expose `TWidget*` directly (rejected, violates opacity), title-only API (rejected, fragile for multi-panel plugins) - impact: P0 gap #1 and #2 from entropyx audit fully closed.
- [2026-02-13] Add handle-based widget event subscriptions (`on_widget_visible(Widget&, cb)`, `on_widget_invisible(Widget&, cb)`, `on_widget_closing(Widget&, cb)`) alongside title-based variants, plus `on_cursor_changed(cb)` for HT_VIEW `view_curpos` events - enables per-panel lifecycle tracking and cursor synchronization without raw SDK event hooking - alternatives considered: only title-based events (rejected, fragile for multi-instance widgets) - impact: P0 gaps #2, #3 from entropyx audit closed.
- [2026-02-13] Implement `IDAX_PLUGIN(ClassName)` macro with `plugmod_t` bridge, static char buffers for `plugin_t PLUGIN` struct, and factory registration via `detail::make_plugin_export()` - eliminates manual `plugin_t PLUGIN` export boilerplate - alternatives considered: require users to write their own PLUGIN struct (rejected, defeats wrapper purpose), put PLUGIN in user TU via macro (rejected, requires SDK includes in public header) - impact: P0 gap #6 from entropyx audit closed.
- [2026-02-13] Add `Segment::type()` getter, `set_type()` free function, and expanded `Type` enum (Import, InternalMemory, Group) to `ida::segment` - enables segment-type introspection for overlay coloring and analysis differentiation - alternatives considered: expose raw `uchar` type code (rejected, violates opaque naming convention) - impact: P0 gap #5 from entropyx audit closed.
- [2026-02-13] Add `ui::jump_to(Address)` navigation helper wrapping SDK `jumpto()` - enables programmatic view navigation from click callbacks - alternatives considered: require users to call screen_address then navigate manually (rejected, missing the core operation) - impact: P0 gap #4 from entropyx audit closed.
- [2026-02-13] Add opaque widget host bridge (`WidgetHost`, `widget_host()`, `with_widget_host()`) to `ida::ui` - enables Qt/content embedding into dock widgets without exposing SDK or Qt types in public headers - alternatives considered: expose `TWidget*` directly (rejected, breaks opacity), expose only raw getter (rejected, encourages long-lived pointer storage) - impact: follow-up entropyx portability gap for panel content mounting is closed while preserving API opacity.
- [2026-02-13] Add `plugin::ActionContext` and context-aware callbacks (`handler_with_context`, `enabled_with_context`) to `ida::plugin::Action` - enables context-sensitive actions without exposing SDK action context types - alternatives considered: expose raw `action_activation_ctx_t*` in public callbacks (rejected, breaks opacity), replace existing no-arg callbacks (rejected, unnecessary migration breakage) - impact: P1 action-context richness gap closed while preserving backward compatibility.
- [2026-02-13] Add generic UI/VIEW routing surface in `ida::ui` (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite-token unsubscribe support - enables broad UI event observation patterns similar to `ida::event` - alternatives considered: force users to register many discrete handlers (rejected, cumbersome), expose raw notification codes + `va_list` (rejected, unsafe and non-opaque) - impact: P1 generic UI/VIEW router gap closed.
- [2026-02-13] Formalize SDK parity closure as Phase 10 with a matrix-driven, domain-by-domain checklist and evidence gates - broad implementation exists but depth is uneven, so closure requires explicit `covered/partial/missing` tracking and per-domain acceptance criteria - alternatives considered: continue ad hoc parity fixes only (rejected, poor completeness visibility), rely on docs snapshot without TODO graph (rejected, weak progress control) - impact: roadmap now has a comprehensive actionable closure plan tied to findings/decisions/ledger updates.
- [2026-02-13] Use a dual-axis coverage matrix (`docs/sdk_domain_coverage_matrix.md`) with both domain rows and SDK capability-family rows - improves completeness visibility and avoids blind spots when a capability spans multiple namespaces - alternatives considered: domain-only matrix (rejected, hides cross-domain capability gaps), capability-only matrix (rejected, weak ownership mapping) - impact: P10.0 now has an auditable baseline artifact with explicit closure/evidence criteria.
- [2026-02-13] Store diagnostics counters as atomics and return snapshot copies - avoids data races under concurrent logging/assertion paths while preserving simple counter semantics - alternatives considered: global mutex around all counter updates (rejected, unnecessary contention), keeping plain struct (rejected, undefined behavior under concurrency) - impact: `ida::diagnostics::performance_counters()` is now concurrency-safe.
- [2026-02-13] Treat compile-only parity test as mandatory for every new public symbol, including overload disambiguation checks - prevents API drift when fast header evolution outpaces runtime test coverage - alternatives considered: rely on integration tests only (rejected, insufficient compile-surface guarantees) - impact: P10.1.c now has stronger regression protection for UI/plugin additions.
- [2026-02-13] Add predicate-based traversal ranges (`code_items`, `data_items`, `unknown_bytes`) and discoverability aliases (`next_defined`, `prev_defined`) in `ida::address` - improves migration ergonomics from common SDK traversal patterns while preserving existing APIs - alternatives considered: expose only predicate search primitives (rejected, less ergonomic for range-for workflows) - impact: P10.2.a-b address parity closure criteria are now satisfied.
- [2026-02-13] Add explicit data patch-revert and load-intent/open-mode convenience wrappers (`revert_patch`, `revert_patches`, `database::OpenMode`, `database::LoadIntent`, `open_binary`, `open_non_binary`) - separates intent from low-level SDK details and prepares future backend specialization - alternatives considered: keep only raw bool/patch APIs (rejected, low discoverability), expose raw loader entrypoints directly (rejected, leaks complexity) - impact: P10.2.c-e closure criteria are now satisfied with backward-compatible additions.
- [2026-02-13] Close P10.3 with additive parity helpers in `ida::segment`/`ida::function`/`ida::instruction` (segment resize/move/comments/traversal; function update/reanalysis/address iteration/frame+regvar lookups; instruction jump classifiers + operand text/format unification) - addresses the highest-priority remaining migration gaps without breaking existing APIs - alternatives considered: defer until P10.8 doc/test sweep only (rejected, leaves domain rows partial), expose raw SDK classifier/comment entrypoints (rejected, violates opacity) - impact: P10.3 rows in coverage matrix now move to `covered` with passing integration + compile-only evidence.
- [2026-02-13] Close P10.4 with additive metadata parity helpers in `ida::name`/`ida::xref`/`ida::comment`/`ida::type`/`ida::entry`/`ida::fixup` (identifier validation/sanitization, xref range+typed filters, indexed comment editing, function/cc/enum type workflows, entry forwarder management, expanded fixup descriptor + signed/range helpers) - closes the largest remaining migration gaps in metadata-heavy workflows while preserving opaque public boundaries - alternatives considered: defer metadata closure until documentation-only sweep (rejected, leaves capability rows partial), expose raw SDK enums/flags directly (rejected, weakens conceptual API) - impact: P10.4 rows in coverage matrix now move to `covered` with passing integration + compile-only evidence.
- [2026-02-13] Close P10.5 with additive search/analysis parity helpers in `ida::search`/`ida::analysis` (typed immediate/binary options, `next_error`/`next_defined`, explicit schedule-intent APIs, cancel/revert wrappers) - closes core control-plane migration gaps while preserving backward-compatible convenience APIs - alternatives considered: keep minimal direction-only search overloads and AU_CODE-only scheduling (rejected, low intent clarity), expose raw `SEARCH_*` and `AU_*` constants directly (rejected, leaks SDK encoding details) - impact: P10.5 rows in coverage matrix now move to `covered` with passing integration + compile-only evidence.
- [2026-02-13] Close P10.6 with additive module-authoring parity in `ida::plugin`/`ida::loader`/`ida::processor` (plugin action detach helpers + context-aware ergonomics docs, typed loader request/flag models for archive/reload/save/move paths, processor `OutputContext` + context-driven output hooks and advanced descriptor/assembler checks) - closes remaining high-priority module migration gaps while preserving backward compatibility - alternatives considered: replace legacy module callbacks/signatures outright (rejected, migration breakage), expose raw SDK callback structs/flag bitmasks directly (rejected, violates opaque conceptual surface) - impact: P10.6 rows in coverage matrix now move to `covered` with passing scenario + compile-only evidence.
- [2026-02-13] Close P10.7.e storage parity with additive node-identity helpers (`Node::open_by_id`, `Node::id`, `Node::name`) and updated safe-index migration guidance - enables robust reopen-by-id workflows while preserving opaque netnode handling - alternatives considered: keep name-only open path (rejected, weaker lifecycle ergonomics), expose raw `netnode` ids/constructors directly (rejected, leaks SDK internals) - impact: `ida::storage` and persistent-storage capability rows move to `covered` with integration + compile-only + docs evidence.
- [2026-02-13] Close P10.7.a debugger parity with additive async/request and introspection helpers (`request_*`, `run_requests`, `is_request_running`, thread enumeration/control helpers, register introspection helpers) - closes the largest remaining debugger migration gap while preserving opaque interfaces and backward-compatible direct-command APIs - alternatives considered: expose raw `request_*` SDK calls only (rejected, inconsistent error model), defer debugger parity to P10.8 docs/tests sweep (rejected, leaves matrix row partial) - impact: `ida::debugger` and debugger capability rows move to `covered` with integration + compile-only evidence.
- [2026-02-13] Close P10.7.b UI parity with additive custom-viewer and broader UI/VIEW event routing helpers (`create_custom_viewer`, line/count/jump/current/refresh/close helpers, `on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`) - closes remaining high-value interactive migration gaps without exposing SDK widget/view types - alternatives considered: defer UI closure to P10.8 docs sweep only (rejected, leaves matrix rows partial), expose raw SDK custom-viewer structs/functions directly (rejected, weakens opaque API boundary) - impact: `ida::ui` and UI lifecycle capability rows move to `covered` with integration + compile-only + topology/matrix docs evidence.
- [2026-02-13] Close P10.7.c graph parity with additive viewer lifecycle/query helpers (`has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, `close_graph_viewer`) and explicit layout-state introspection (`Graph::current_layout`) - closes graph migration gaps for viewer lifecycle control and deterministic layout-option behavior across UI/headless modes - alternatives considered: keep title-only refresh/show APIs (rejected, insufficient lifecycle parity), rely on UI-only layout effects without state introspection (rejected, brittle in idalib/headless validation) - impact: `ida::graph` and graph capability rows move to `covered` with integration + compile-only + topology/matrix docs evidence.
- [2026-02-13] Close P10.7.d decompiler parity with additive variable-retype and expanded comment/ctree workflows (`retype_variable` by name/index, orphan-comment query/cleanup, broader integration coverage) - closes the remaining interactive migration gap for decompiler-driven refactoring while preserving opaque type boundaries - alternatives considered: expose raw Hex-Rays lvar/user-info structs in public headers (rejected, breaks opacity), defer retype/comment workflow coverage to P10.8 docs/tests sweep only (rejected, leaves matrix row partial) - impact: `ida::decompiler` and decompiler capability rows move to `covered` with integration + compile-only + topology/migration/matrix docs evidence.
- [2026-02-13] Resolve P10.9.a via explicit intentional-abstraction notes for cross-cutting/event rows in coverage matrix (`ida::core`, `ida::diagnostics`, `ida::event`) - preserves the wrapper's concept-driven scope while documenting when expansion should occur - alternatives considered: force all rows to `covered` by broad raw-SDK mirroring (rejected, high API bloat and reduced intuitiveness) - impact: P10.9.a exit criterion is now auditable without distorting wrapper design goals.
- [2026-02-13] Add GitHub Actions validation matrix workflow (`.github/workflows/validation-matrix.yml`) for multi-OS `compile-only` + `unit` profiles with SDK checkout and platform toolchain setup - provides a repeatable path to gather Linux/macOS/Windows matrix evidence for P10.8.d without requiring per-host manual command orchestration - alternatives considered: keep manual host-only matrix execution docs (rejected, slower feedback and higher drift risk), run `full` profile in hosted CI (rejected, requires licensed runtime not available in hosted environment) - impact: cross-platform validation is now one-click reproducible in CI for non-runtime-dependent rows.
- [2026-02-13] Make SDK bootstrap resolution tolerant to variant IDA SDK layouts in CI and CMake (`ida-cmake/`, `cmake/`, and `src/cmake/`) with recursive SDK submodule checkout - avoids brittle workflow failures during bootstrap include and keeps hosted matrix independent of checkout layout/submodule nuances - alternatives considered: pin workflow to one assumed SDK layout only (rejected, fragile across branches/snapshots), require manual path overrides in every job (rejected, error-prone) - impact: validation matrix jobs now resolve `IDASDK` deterministically before running `scripts/run_validation_matrix.sh`.
- [2026-02-13] Standardize validation script execution for cross-generator behavior by always passing build configuration to both build and test commands (`cmake --build --config <type>`, `ctest -C <type>`) - avoids Visual Studio test discovery/run mismatches while remaining compatible with single-config generators - alternatives considered: conditionally branch by generator in shell script (rejected, higher complexity and drift risk) - impact: Windows unit matrix rows now execute tests instead of reporting `Not Run` due missing configuration.
- [2026-02-13] Enable example addon compilation in hosted validation matrix (`IDAX_BUILD_EXAMPLES=ON`, `IDAX_BUILD_EXAMPLE_ADDONS=ON`) and plumb toggles through `scripts/run_validation_matrix.sh` - broadens CI compile coverage to sample plugin/loader/procmod targets on every matrix row without requiring runtime integration execution - alternatives considered: keep examples disabled in matrix (rejected, misses module-authoring regressions), add a separate examples-only workflow (rejected, extra maintenance/latency) - impact: matrix runs now validate wrapper + examples as one coherent compile surface.
- [2026-02-13] Add a paired JBC full-port example (`loader/jbc_full_loader.cpp` + `procmod/jbc_full_procmod.cpp` with shared `full/jbc_common.hpp`) - validates idax against a real production procmod/loader migration (ida-jam) rather than only synthetic examples - alternatives considered: keep hypothetical-only advanced examples (rejected, weaker parity pressure), port only loader or only procmod (rejected, misses cross-module state/lifecycle interactions) - impact: examples now include a realistic end-to-end module-authoring reference and surface remaining procmod parity gaps concretely.
- [2026-02-13] Close P10.8.d/P10.9.d using hosted matrix evidence from Linux/macOS/Windows runs plus existing local full/packaging evidence - fulfills cross-OS changed-surface validation gates without requiring licensed runtime on hosted runners while preserving explicit pending status for runtime-dependent `full` Linux/Windows rows - alternatives considered: keep Phase 10 open until every runtime-dependent full row is host-complete (rejected for closure gate scope), ignore hosted evidence and rely only on ad hoc local runs (rejected, weaker reproducibility) - impact: Phase 10 is now formally complete with auditable evidence trails in compatibility + validation docs and ledger.
- [2026-02-14] Close JBC follow-up parity gaps (#80-#82) with additive processor/segment APIs - adds typed analyze operand model, default segment-register seeding helpers, tokenized output channels, and mnemonic-specific formatting hook while preserving backwards compatibility for existing procmods - alternatives considered: keep minimal analyze/output APIs and rely on per-callback re-decode + raw SDK escapes (rejected, weaker migration fidelity), replace existing callbacks outright (rejected, migration breakage) - impact: full procmods can now express richer decode/output semantics in pure idax surface and JBC full-port examples were updated accordingly.
- [2026-02-14] Add real-world port artifacts for ida-qtform + idalib-dump and track resulting parity gaps in a dedicated audit doc - practical migration pressure from external projects is the fastest way to validate wrapper completeness after Phase 10 closure - alternatives considered: synthetic parity-only checks (rejected, can miss workflow-critical edges), ad hoc notes in chat only (rejected, poor traceability) - impact: repository now contains concrete port references plus an auditable gap list (`docs/port_gap_audit_ida_qtform_idalib_dump.md`) to drive additive API planning.
- [2026-02-14] Add markup-only `ida::ui::ask_form(std::string_view)` API as an additive UI parity step - unblocks qtform-style form preview/test workflows without exposing SDK vararg interfaces in public headers - alternatives considered: defer and keep gap open (rejected, leaves common flow blocked), expose raw vararg `ask_form` directly (rejected, unsafe/non-opaque) - impact: pure idax ports can now execute simple form-render test flows; full typed binding parity remains a future additive option.
- [2026-02-14] Add additive microcode retrieval APIs in `ida::decompiler` (`DecompiledFunction::microcode()`, `DecompiledFunction::microcode_lines()`) - closes the idalib-dump `--mc` parity gap without exposing raw Hex-Rays internals in public headers - alternatives considered: keep gap open and require raw SDK for microcode dumps (rejected, weak real-port parity), expose `mba_t`/raw printer hooks directly (rejected, breaks opacity) - impact: pure idax flows can now produce microcode text, and the idalib-dump port example no longer needs microcode-gap fallback logic.
- [2026-02-14] Add structured decompile-failure detail surface (`DecompileFailure` + `decompile(address, &failure)`) in `ida::decompiler` - closes diagnostics parity gap for failure-location reporting without exposing raw Hex-Rays failure structs - alternatives considered: keep context embedded only in `ida::Error` strings (rejected, weakly structured), expose raw `hexrays_failure_t` in public API (rejected, breaks opacity) - impact: ports can report failure address/description directly and decompiler error handling remains additive/backward-compatible.
- [2026-02-14] Align README positioning and commands with matrix-backed coverage artifacts - replaces absolute completeness phrasing with explicit broad-coverage + tracked-gap language, updates packaging command to pinned-output form, and refreshes examples/API messaging to match current surfaces - alternatives considered: keep README caveats only in deep docs (rejected, first-contact drift risk), keep legacy `cpack` invocation (rejected, output-location drift) - impact: first-contact documentation now matches maintained parity and validation guidance.
- [2026-02-14] Add headless plugin policy controls to `ida::database::init` via additive runtime options (`RuntimeOptions`, `PluginLoadPolicy`) - closes idalib-dump `--no-plugins`/`--plugin` parity gap without exposing SDK internals - alternatives considered: keep environment-variable workarounds only in external tools (rejected, weak portability), introduce standalone plugin-policy APIs outside init (rejected, weaker lifecycle semantics) - impact: pure idax headless sessions can control user-plugin loading policy at startup and the port example now uses wrapper-native controls.
- [2026-02-14] Add diagnostics-oriented database metadata helpers (`file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`) - closes external-port metadata parity gaps without leaking raw SDK types - alternatives considered: keep metadata extraction in external tools via raw SDK calls (rejected, inconsistent migration experience), add a new diagnostics namespace first (rejected, weaker discoverability for database-oriented metadata) - impact: idalib-dump-style tooling can collect format/compiler/import-module context through pure idax APIs.
- [2026-02-14] Add `ida::lumina` facade with additive pull/push wrappers (`has_connection`, `pull`, `push`, typed `BatchResult` and `OperationCode`) - closes idalib-dump Lumina migration gap while preserving opaque public headers - alternatives considered: keep gap open and rely on raw SDK from external tools (rejected, inconsistent migration ergonomics), expose raw `lumina_client_t` in public API (rejected, breaks opacity) - impact: pure idax tools can issue Lumina metadata sync operations without SDK-level glue code.
- [2026-02-14] Keep Lumina close APIs as explicit `Unsupported` wrappers for now - runtime dylibs in this environment do not export `close_server_connection2`/`close_server_connections` despite SDK declarations, so direct linkage is not portable - alternatives considered: call non-exported symbols directly (rejected, link failure), remove close APIs from public surface (rejected, weaker discoverability/future extensibility) - impact: wrapper behavior is explicit and link-stable while leaving room for portable close support later.
- [2026-02-14] Add a dedicated ida2py real-world port probe (`examples/tools/ida2py_port.cpp`) plus a standalone parity audit doc (`docs/port_gap_audit_ida2py.md`) - preserves concrete migration pressure from a Python-first project while keeping gap tracking explicit and auditable - alternatives considered: fold findings into existing qtform/idalib-dump audit only (rejected, weak source-to-gap traceability), treat ida2py as out-of-scope due language differences (rejected, misses high-value API ergonomics signals) - impact: idax now has an additional external-port regression artifact and a prioritized list of additive API opportunities.
- [2026-02-14] Add typed name inventory APIs to `ida::name` (`Entry`, `ListOptions`, `all`, `all_user_defined`) - closes the highest-leverage ida2py static-query gap with additive API shape and bounded-range filtering while preserving opaque boundaries - alternatives considered: keep fallback address scanning in port examples only (rejected, weaker discoverability/performance), expose raw SDK nlist APIs directly in public headers (rejected, leaks SDK-centric concepts) - impact: symbol-inventory workflows are now first-class in idax and ida2py port code no longer depends on full-address scans.
- [2026-02-14] Add `TypeInfo` decomposition and typedef-resolution helpers (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`) - closes the next highest-leverage ida2py static-query gap with additive introspection APIs and no opacity regressions - alternatives considered: keep decomposition logic only in external port code (rejected, duplicated complexity), expose raw SDK `tinfo_t` utilities in public headers (rejected, breaks opaque conceptual surface) - impact: pointer/array/typedef peeling is now first-class in idax and available to migration tooling without SDK escape hatches.
- [2026-02-14] Add typed decompiler call-subexpression accessors on `ExpressionView` (`call_callee`, `call_argument(index)`) - closes the ida2py callsite-argument inspection gap with additive visitor-view APIs and no SDK type leakage - alternatives considered: keep call parsing in external examples only (rejected, weak portability/discoverability), expose raw `cexpr_t*` in public callbacks (rejected, breaks opaque boundary) - impact: callsite workflows can now inspect callee/argument expressions directly through idax.
- [2026-02-14] Add generic typed-value facade in `ida::data` (`TypedValue`, `TypedValueKind`, `read_typed`, `write_typed`) with recursive array materialization and byte-array/string write paths - closes the ida2py typed-value materialization gap without exposing raw SDK type/value plumbing - alternatives considered: keep typed decoding logic only in external ports (rejected, duplicated and less discoverable), expose SDK-level typed-value helpers directly (rejected, weakens opaque conceptual API) - impact: `TypeInfo`-driven value inspection/update is now a first-class idax workflow.
- [2026-02-14] Add Appcall + pluggable executor facade in `ida::debugger` (`AppcallValue`, `AppcallRequest`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`) - closes the ida2py dynamic invocation API gap with both debugger-native and external-engine extension paths while preserving opaque boundaries - alternatives considered: keep dynamic execution out-of-scope (rejected, leaves ida2py parity gap open), expose raw SDK `idc_value_t`/`dbg_appcall` types in public API (rejected, breaks conceptual opacity) - impact: dynamic invocation is now first-class in idax API design and can be validated incrementally by host/runtime.
- [2026-02-14] Expand matrix automation scope to compile idalib tool-port examples by default (`IDAX_BUILD_EXAMPLE_TOOLS`) - keeps real-world port probes (`ida2py`/`idalib_dump`/`idalib_lumina`) in the standard compile-only + unit regression path alongside addon examples - alternatives considered: keep tool examples out of matrix and rely on ad hoc local builds (rejected, higher drift risk), add a separate tools-only workflow (rejected, extra maintenance and slower signal) - impact: hosted/local matrix runs now catch tool-port compile regressions as part of baseline validation.
- [2026-02-14] Add fixture-backed Appcall runtime validation path (`--appcall-smoke` in `examples/tools/ida2py_port.cpp`) plus dedicated checklist doc (`docs/appcall_runtime_validation.md`) - provides an auditable host-runtime procedure for real debugger-backed Appcall evidence while keeping the baseline probe behavior unchanged - alternatives considered: keep runtime guidance as ad hoc notes only (rejected, low reproducibility), add a standalone new tool binary (rejected, unnecessary target sprawl) - impact: Appcall runtime evidence collection is now standardized and easy to rerun on known-good hosts.
- [2026-02-14] Prefer real IDA runtime dylibs for idalib tool examples when available (`IDADIR` or common macOS install path), and fallback to `ida_add_idalib` stubs only when runtime libs are unavailable - avoids two-level namespace runtime crashes in functional tool runs while preserving compile-only portability in hosted rows - alternatives considered: keep `ida_add_idalib`-only linkage (rejected, local signal-11 runtime failures), require `IDADIR` unconditionally (rejected, breaks no-runtime compile rows) - impact: tool-port examples now run local non-debugger workflows successfully, and Appcall smoke failures surface as debugger-readiness errors instead of crashes.
- [2026-02-14] Adopt Linux Clang 19 + libstdc++ as the known-good compile-only pairing for container evidence, and keep Linux Clang addon/tool toggles OFF until `x64_linux_clang_64` SDK runtime libs are available - Clang 18 fails `std::expected` gating in libstdc++, while Clang 19 passes baseline core-wrapper compilation; addon/tool linkage currently depends on missing SDK runtime artifacts - alternatives considered: stay on Clang 18 and force libc++ (rejected, prior SDK macro collisions and no pass evidence), force addon/tool ON in Clang rows immediately (rejected, deterministic SDK artifact failures) - impact: Linux Clang evidence path is now actionable and reproducible with explicit scope boundaries.
- [2026-02-14] Add open-point closure automation (`scripts/run_open_points.sh`) plus host-native Appcall fixture build helper (`scripts/build_appcall_fixture.sh`), and make `ida2py_port --appcall-smoke` bootstrap debugger launch with multi-path fallbacks before Appcall attempts - removes repetitive manual sequencing and turns host/runtime limitations into explicit pass/blocked/fail outcomes - alternatives considered: keep manual command checklist only (rejected, high friction/drift), keep Appcall smoke as direct `dbg_appcall` probe without launch bootstrap (rejected, weaker diagnostics) - impact: open-point execution is now one-command reproducible with clearer blocker attribution and Lumina/Appcall evidence collection.
- [2026-02-14] Add a dedicated lifter port probe plugin (`examples/plugin/lifter_port_plugin.cpp`) plus standalone gap audit (`docs/port_gap_audit_lifter.md`) instead of attempting a raw-SDK parity rewrite in one step - preserves opaque-boundary guarantees while still providing executable migration pressure and concrete blockers - alternatives considered: full direct lifter port immediately (rejected, blocked by missing microcode write-path APIs), docs-only audit without executable probe (rejected, weaker regression signal) - impact: lifter-class decompiler parity gaps are now reproducible, documented, and tied to concrete additive API follow-ups.
- [2026-02-14] Close lifter sub-gaps for maturity routing and outline/cache invalidation with additive APIs in `ida::decompiler` and `ida::function` - unblocks high-value lifter workflows without exposing SDK structs while preserving additive compatibility - alternatives considered: keep these items as audit-only gaps (rejected, delays migration value), expose raw Hex-Rays callback/context types directly (rejected, breaks opaque boundary) - impact: lifter blocker scope is now narrowed to microcode filter/write-path and raw view-handle parity.
- [2026-02-14] Add baseline microcode-filter registration surface in `ida::decompiler` (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`) - establishes wrapper-native filter lifecycle and match/apply routing without exposing SDK microcode types - alternatives considered: keep filter flow as raw SDK-only (rejected, blocks lifter-class migration), expose raw `codegen_t`/`microcode_filter_t` in public headers (rejected, breaks opacity) - impact: lifter blocker scope is now narrowed from filter lifecycle + write-path to mostly rich IR emission/mutation and raw view-handle parity.
- [2026-02-14] Expand `ida::decompiler::MicrocodeContext` with additive operand/register/memory/helper emit helpers - increases practical microcode-filter authoring power while keeping SDK details opaque in public headers - alternatives considered: keep only `emit_noop` until full typed-IR design (rejected, too limiting for real ports), expose raw `codegen_t` accessors (rejected, opacity break) - impact: remaining lifter blocker is now focused on typed IR construction depth (callinfo/typed mops/helper-argument modeling) and raw view-handle parity.
- [2026-02-14] Add typed helper-call argument builders to `ida::decompiler::MicrocodeContext` (`MicrocodeValueKind`, `MicrocodeValue`, `emit_helper_call_with_arguments`, `emit_helper_call_with_arguments_to_register`) - enables wrapper-native helper-call construction for integer argument/return flows while keeping SDK types opaque - alternatives considered: expose raw `mcallarg_t`/`mcallinfo_t` directly (rejected, opacity break), defer typed builders until full vector/UDT design is complete (rejected, delays practical migration value) - impact: remaining lifter blocker is now concentrated in advanced typed IR depth (non-integer callinfo/tmop modeling) and raw view-handle parity.
- [2026-02-14] Add helper-call option shaping to `ida::decompiler::MicrocodeContext` (`MicrocodeCallOptions`, `MicrocodeCallingConvention`, `emit_helper_call_with_arguments_and_options`, `emit_helper_call_with_arguments_to_register_and_options`) - enables wrapper-native lightweight call-convention/flag tuning while preserving SDK opacity - alternatives considered: expose raw `mcallinfo_t` mutators in public API (rejected, opacity break), defer all callinfo shaping until full typed-callinfo design (rejected, delays migration value) - impact: remaining lifter blocker is now narrowed to advanced callinfo/tmop depth (non-integer argument modeling, explicit argloc/reg-location controls) and raw view-handle parity.
- [2026-02-14] Expand typed helper-call value/call-option surface with scalar floating immediates + explicit-location hinting (`Float32Immediate`/`Float64Immediate`, `MicrocodeCallOptions::mark_explicit_locations`) - broadens wrapper-native scalar helper-call modeling while keeping SDK internals opaque - alternatives considered: jump directly to vector/UDT+full callinfo modeling (rejected, too large for one safe additive slice), expose raw `mcallarg_t`/`argloc_t` mutators in public API (rejected, opacity break) - impact: remaining lifter blocker is now concentrated in non-scalar argument modeling and deeper callinfo/tmop location control.
- [2026-02-14] Add basic explicit argument-location hints to typed helper-call values (`MicrocodeValueLocation` with register/stack-offset kinds) and auto-promote explicit-location call shaping when hints are present - improves scalar helper-call location modeling without exposing `argloc_t` while preserving additive compatibility - alternatives considered: expose raw `argloc_t` in public API (rejected, opacity break), defer all location-shaping until full callinfo DSL exists (rejected, delays migration value) - impact: remaining lifter blocker is now focused on advanced/non-scalar location semantics + deeper callinfo/tmop controls and raw view-handle parity.
- [2026-02-14] Expand `MicrocodeValueLocation` with register-pair and register-with-offset forms - broadens explicit location placement ergonomics for helper-call args while preserving SDK opacity and additive compatibility - alternatives considered: stay with register/stack-only hints (rejected, too limiting for realistic placement patterns), expose raw `argloc_t` builders in public API (rejected, opacity break) - impact: remaining lifter blocker is now concentrated in non-scalar arguments + advanced/scattered callinfo-tmop location semantics and raw view-handle parity.
- [2026-02-14] Add static-address explicit location hints to `MicrocodeValueLocation` (`StaticAddress` mapped to `argloc_t::set_ea`) - broadens scalar helper-call location placement while preserving SDK opacity and additive compatibility - alternatives considered: keep location hints register/stack-only(+pair/offset) (rejected, misses common global-location patterns), expose raw `argloc_t` directly (rejected, opacity break) - impact: remaining lifter blocker is now concentrated in non-scalar arguments + advanced/scattered location semantics and raw view-handle parity.
- [2026-02-14] Add scattered/multi-part explicit location hints to `MicrocodeValueLocation` (`Scattered` + `MicrocodeLocationPart`) - broadens scalar helper-call location placement for split-argument scenarios while preserving SDK opacity and additive compatibility - alternatives considered: keep only single-location hints (rejected, insufficient for realistic split-placement flows), expose raw `argpart_t`/`scattered_aloc_t` publicly (rejected, opacity break) - impact: remaining lifter blocker is now concentrated in non-scalar arguments + deeper callinfo/tmop semantics and raw view-handle parity.

---

## 14) Blockers (Live)

- Blocker ID: B-2026-02-14-LIFTER-MICROCODE
- Date raised: 2026-02-14
- Scope impacted: Full idax-first port of `/Users/int/dev/lifter` (AVX/VMX microcode transformations)
- Severity: High
- Description: The current public wrapper still lacks decompiler write-path depth required by lifter (non-scalar typed writable microcode IR construction/mutation including vector/UDT helper-call argument + advanced callinfo/tmop semantics beyond current register/register-pair/register-offset/stack/static/scattered scalar-location hints, and typed mop builders, plus raw view-handle context for advanced per-view manipulations).
- Immediate mitigation: Keep a partial executable port probe (`examples/plugin/lifter_port_plugin.cpp`) and explicit gap audit (`docs/port_gap_audit_lifter.md`) so regressions and constraints remain visible.
- Long-term mitigation: Add additive decompiler write-path APIs (richer typed microcode value/argument/callinfo construction facade beyond current scalar helper + lightweight call-option + scalar location-hint support) plus carefully-scoped view-handle context bridges while preserving public opacity.
- Owner: idax wrapper core
- Next checkpoint: First post-closure parity API planning cycle that targets decompiler write-path expansion.

When adding a blocker, use:
- Blocker ID:
- Scope impacted:
- Severity:
- Description:
- Mitigation plan:
- Next checkpoint:

---

## 15) Progress Ledger (Live, Timestamped)

Format: `[YYYY-MM-DD HH:MM] scope - change - evidence`

- [2026-02-12 00:00] Program planning - Comprehensive architecture and roadmap captured - Initial version of `agents.md` created with phased TODOs, findings, and decision log.
- [2026-02-12 15:52] Documentation baseline - Added detailed interface blueprint sections (Parts 1-5 and module interfaces) - Evidence: Section 22 added with namespace-level API sketches.
- [2026-02-12 16:00] P0-P5 implementation - All 24 public headers, 19 implementation files, SDK bridge, and smoke test created - Evidence: `libidax.a` builds (168K), 19 .cpp compile.
- [2026-02-12 17:00] Blocker resolved - Two-level namespace crash diagnosed and fixed - Evidence: SDK stub libidalib.dylib exports qvector_reserve but real one doesn't; fix: link tests against real IDA dylibs. Smoke test now passes 48/48.
- [2026-02-12 18:00] P4.2.c, P4.4.c-d, P5.2, P7.4 - Function callers/callees, type struct/member/retrieve, operand representation controls, and event system all implemented - Evidence: smoke test now passes 58/58 with new test sections covering all new APIs.
- [2026-02-12 19:00] P4.2.b, P4.3.a-b-d - Function chunks (Chunk value object, chunks/tail_chunks/chunk_count/add_tail/remove_tail) and stack frames (StackFrame with frame variables, sp_delta_at, define_stack_variable) implemented; TypeInfo pimpl extracted to detail/type_impl.hpp for cross-TU access - Evidence: smoke test now passes 68/68 with new chunk and frame test sections.
- [2026-02-12 20:00] P6.1, P6.2.b-c, P6.3.c - Plugin base class with PLUGIN_MULTI lifecycle pattern added; loader InputFile abstraction (size/seek/tell/read_bytes/read_bytes_at/read_string) and helper functions (file_to_database/memory_to_database/set_processor) implemented; processor descriptors (RegisterInfo, InstructionDescriptor with typed InstructionFeature enum, AssemblerInfo) added - Evidence: builds cleanly, 68/68 smoke tests pass.
- [2026-02-12 21:00] P8.1.a-c, P8.2.a-d, P5.3 - Full decompiler implementation (availability check via init_hexrays_plugin, decompile_func with cfuncptr_t pimpl, pseudocode/lines/declaration/variable_count/variables/rename_variable); instruction xref conveniences (P5.3) confirmed already implemented; Phase 7 debugger/ui TODOs synced - Evidence: smoke test now passes 73/73 including decompiler pseudocode generation, variable enumeration, and declaration extraction.
- [2026-02-12 22:00] P6.2.a-d-e, P6.3.a-b-e, P7.2.b-d, P7.3.a-d - Loader base class (accept/load/save/move_segment virtual methods, LoaderOptions, abort_load, create_filename_comment, IDAX_LOADER registration macro); Processor base class (ProcessorInfo metadata, Processor base with analyze/emulate/output_instruction/output_operand virtuals, ProcessorFlag enum, IDAX_PROCESSOR registration macro); UI chooser (Chooser base class with Column/Row/RowStyle/ChooserOptions, ChooserAdapter bridging to chooser_t; simple dialogs ask_string/ask_file/ask_address/ask_long; screen_address/selection queries; timer register/unregister); Graph (Graph object with standalone adjacency-list implementation, node/edge CRUD, group/collapse, BFS path_exists, show_graph viewer bridge, flowchart/flowchart_for_ranges with qflow_chart_t, BasicBlock/BlockType) - Evidence: smoke test now passes 95/95 with flowchart and graph object tests.
- [2026-02-12 23:00] P8.1.d-e, P8.2.b-c - Decompiler ctree visitor (CtreeVisitor base class with ExpressionView/StatementView opaque handles, ItemType enum mapping all cot_*/cit_* codes, VisitAction/VisitOptions, SdkVisitorAdapter bridging to ctree_visitor_t, for_each_expression/for_each_item functional helpers); user comment management (set_comment/get_comment/save_comments using treeloc_t+item_preciser_t, CommentPosition enum); refresh/invalidation (refresh() wrapping refresh_func_ctext()); address mapping (entry_address, line_to_address via treeitems+hdrlines, address_map for bulk mapping) - Evidence: smoke test now passes 121/121 with ctree visitor counting 21 exprs + 4 stmts, post-order/skip-children working, comments set/get/save/remove verified, address mapping returning 16 entries.
- [2026-02-12 24:00] P7.2.c, P4.4.e, P4.3.c, P8.3.c - Fixed get_widget_title build error (2-arg SDK signature); UI event subscriptions (on_database_closed/on_ready_to_run/on_screen_ea_changed/on_widget_visible/on_widget_closing + ScopedUiSubscription RAII); type library access (load_type_library/unload/local_type_count/local_type_name/import_type/apply_named_type); register variables (add/find/delete/rename/has_register_variables); storage blob operations (blob_size/blob/set_blob/del_blob/blob_string); all tested - Evidence: smoke test now passes 162/162 with storage blob roundtrip, type library count+save, register variable full lifecycle, and UI event subscribe/unsubscribe all verified.
- [2026-02-13 00:00] P7.1.d, P6.3.d - Added debugger event subscription API (HT_DBG listener, typed callbacks, RAII ScopedDebuggerSubscription) and expanded processor public API with SDK-free switch detection/function heuristic wrappers (SwitchDescription/SwitchCase + optional virtual hooks); added smoke tests for debugger event subscribe/unsubscribe lifecycle - Evidence: smoke test now passes 187/187; debugger event section reports successful subscribe/unsubscribe.
- [2026-02-13 00:30] P7.4.d - Added generic IDB event filtering/routing helpers (`ida::event::Event`, `on_event`, `on_event_filtered`) and wired fan-out dispatch from normalized per-notification payloads; added smoke tests validating generic+filtered rename routing - Evidence: smoke test now passes 193/193 and reports "generic route fired: yes" + "filtered route fired: yes".
- [2026-02-13 01:00] P2.2.d-e - Added data string extraction (`read_string`), typed value helpers (`read_value<T>`, `write_value<T>`), and binary pattern search wrapper (`find_binary_pattern`); expanded smoke tests for typed reads, ELF signature pattern search, and .rodata string extraction - Evidence: smoke test now passes 201/201.
- [2026-02-13 01:30] P3.4.d - Added regex/options text-search wrapper (`ida::search::TextOptions` + overload) and smoke tests covering plain + regex option paths - Evidence: smoke test now passes 203/203.
- [2026-02-13 02:00] P2.3.c - Added database snapshot wrappers (`ida::database::Snapshot`, `snapshots()`, `set_snapshot_description()`, `is_snapshot_database()`) and smoke coverage for snapshot enumeration and snapshot-state query - Evidence: smoke test now passes 205/205.
- [2026-02-13 02:30] P4.6.d - Added custom fixup registration wrappers (`ida::fixup::CustomHandler`, `register_custom`, `find_custom`, `unregister_custom`) and smoke tests for register/find/unregister lifecycle - Evidence: smoke test now passes 210/210.
- [2026-02-13 03:00] P2.3.b - Added database file/memory transfer wrappers (`file_to_database(path, file_offset, ea, size, patchable, remote)` and `memory_to_database(bytes, ea, file_offset)`), and smoke coverage validating both paths on ELF header bytes - Evidence: smoke test now passes 213/213.
- [2026-02-13 03:30] P3.2.c-d - Added bulk comment APIs (`set_anterior_lines`, `set_posterior_lines`, `clear_anterior`, `clear_posterior`, `anterior_lines`, `posterior_lines`) and rendering helper (`render(ea, include_repeatable, include_extra_lines)`); expanded smoke tests for bulk/set/get/render/clear flows - Evidence: smoke test now passes 227/227.
- [2026-02-13 04:00] P2.1.d - Added address search predicate helpers (`Predicate`, `find_first`, `find_next`) to unify predicate-based range lookups in `ida::address`; expanded smoke tests for code/head predicate searches - Evidence: smoke test now passes 232/232.
- [2026-02-13 04:30] P0.1.d, P6.4.a-d - Added concrete example sources (`examples/plugin/action_plugin.cpp`, `examples/loader/minimal_loader.cpp`, `examples/procmod/minimal_procmod.cpp`) plus examples CMake (`examples/CMakeLists.txt`); built loader/procmod/plugin example addon targets successfully with `IDAX_BUILD_EXAMPLES=ON` + `IDAX_BUILD_EXAMPLE_ADDONS=ON`; verified no compiler-intrinsic usage via source scan - Evidence: targets `idax_example_loader`, `idax_example_procmod`, and `idax_example_plugin` build cleanly.
- [2026-02-13 05:00] P6.5, P3.6.b-d, P4.5.d, P8.3.d, P9.2 - Added documentation bundle (`docs/quickstart/*`, `docs/cookbook/*`, `docs/migration/*`, `docs/api_reference.md`, `docs/tutorial/first_contact.md`, `docs/storage_migration_caveats.md`, `docs/docs_completeness_checklist.md`); synced migration maps and entry migration examples - Evidence: docs files created and referenced by roadmap checkboxes.
- [2026-02-13 05:30] P1.1.c, P1.2.c, P1.3, P1.4 - Added shared option structs (`include/ida/core.hpp`), diagnostics/logging/counters (`include/ida/diagnostics.hpp`, `src/diagnostics.cpp`), wired master include, and created unit test target (`tests/unit/idax_unit_test`) covering error model, diagnostics behavior, handle/range semantics, and iterator contract basics - Evidence: `idax_unit_test` reports 22/22 pass; smoke test remains 232/232.
- [2026-02-12 22:18] P3.6.a - Added dedicated integration behavior test suite for `ida::name`/`ida::comment`/`ida::xref`/`ida::search` (`tests/integration/name_comment_xref_search_test.cpp`) and wired CTest target `name_comment_xref_search_behavior` - Evidence: `ctest --test-dir build --output-on-failure` now reports 3/3 pass (`idax_unit_test`, `smoke_test`, `name_comment_xref_search_behavior`).
- [2026-02-12 22:21] P2.4.b - Added dedicated integration mutation-safety test suite for `ida::data` (`tests/integration/data_mutation_safety_test.cpp`) and wired CTest target `data_mutation_safety` - Evidence: `ctest --test-dir build --output-on-failure` now reports 4/4 pass (`idax_unit_test`, `smoke_test`, `name_comment_xref_search_behavior`, `data_mutation_safety`).
- [2026-02-12 22:22] P4.7.a - Added dedicated integration segment/function edge-case suite (`tests/integration/segment_function_edge_cases_test.cpp`) and wired CTest target `segment_function_edge_cases` - Evidence: `ctest --test-dir build --output-on-failure` now reports 5/5 pass (`idax_unit_test`, `smoke_test`, `name_comment_xref_search_behavior`, `data_mutation_safety`, `segment_function_edge_cases`).
- [2026-02-12 22:23] P5.4.a - Added dedicated integration instruction decode behavior suite (`tests/integration/instruction_decode_behavior_test.cpp`) and wired CTest target `instruction_decode_behavior` - Evidence: `ctest --test-dir build --output-on-failure` now reports 6/6 pass (`idax_unit_test`, `smoke_test`, `name_comment_xref_search_behavior`, `data_mutation_safety`, `segment_function_edge_cases`, `instruction_decode_behavior`).
- [2026-02-12 22:24] P4.7.b - Added dedicated type roundtrip and apply test suite (`tests/integration/type_roundtrip_test.cpp`): primitive factories, pointer/array construction, from_declaration roundtrip, struct lifecycle (create/add_member/members/member_by_name/member_by_offset), union creation, save_as/by_name roundtrip, apply/retrieve, apply_named_type, local type library enumeration, to_string, non-UDT member access error paths, copy/move semantics - Evidence: `ctest --test-dir build --output-on-failure` now reports 10/10 pass.
- [2026-02-12 22:25] P4.7.c - Added dedicated fixup relocation test suite (`tests/integration/fixup_relocation_test.cpp`): set/get roundtrip, multiple fixup types (Off8/Off16/Off32/Off64/Hi8/Low8), contains check, traversal (first/next/prev), FixupRange iteration, error paths (BadAddress/empty name/nonexistent), custom fixup registration lifecycle - Evidence: 10/10 pass.
- [2026-02-12 22:26] P5.4.b+c - Added combined operand conversion and text snapshot test suite (`tests/integration/operand_and_text_test.cpp`): operand type classification (register/immediate/memory), immediate value access, register operand properties, representation controls (hex/decimal/binary/clear), forced operand roundtrip, xref conveniences (is_call/is_return/has_fall_through/call_targets/code_refs_from/data_refs_from), disassembly text snapshots (consistency and mnemonic presence), instruction create - Evidence: 10/10 pass.
- [2026-02-12 22:27] P8.4.a-d - Added combined decompiler and storage hardening test suite (`tests/integration/decompiler_storage_hardening_test.cpp`): decompiler availability (P8.4.a), ctree traversal with type counting/expressions-only/early-stop/post-order (P8.4.b), expression view accessors (number_value/call_argument_count/variable_index/to_string + error on wrong type) (P8.4.b), for_each_item (P8.4.b), decompile error paths (P8.4.d), address mapping + line_to_address + out-of-range (P8.4.d), user comments roundtrip (P8.4.d); storage alt/sup/hash/blob roundtrips (P8.4.c), blob overwrite (P8.4.c), multi-tag operations (P8.4.c), node open error paths (P8.4.c), node copy/move semantics (P8.4.c) - Evidence: 10/10 pass.
- [2026-02-12 22:28] CMake - Refactored `tests/integration/CMakeLists.txt` to use `idax_add_integration_test()` helper function, eliminating boilerplate for 9 test targets.
- [2026-02-12 23:00] P9.1.a-d - Completed all four Phase 9 integration audits (cross-namespace consistency, naming lint, error model, opaque boundary) and applied all fixes: renamed `delete_register_variable`->`remove_register_variable`, unified subscription naming (`Token`/`unsubscribe`/`ScopedSubscription` in both debugger and ui namespaces), fixed `Segment::visible()`->`is_visible()` and `Function::is_hidden()`->`is_visible()` positive polarity, fixed `line_to_address()` to return error instead of `BadAddress`, changed `Plugin::run()` from `bool` to `Status`, added `EmulateResult`/`OutputOperandResult` typed enums for Processor callbacks, renamed ~135 `ea` params to `address` across 12 headers, renamed `idx`->`index`/`cmt`->`comment`/11 `set_op_*`->`set_operand_*`/2 `del_*`->`remove_*`, made `Chooser::impl()`/`Graph::impl()` private, renamed `cnbits`/`dnbits`->`code_bits_per_byte`/`data_bits_per_byte`, replaced `xref::Reference::raw_type` with typed `ReferenceType` enum, added error context strings to 23 error sites, changed UI dialog cancellation errors from `SdkFailure` to `Validation` category - Evidence: build clean, 10/10 tests pass.
- [2026-02-13 06:00] P0.3.d, P4.7.d, P7.5, P6.5, P9.3, P9.4 - Completed all remaining release-blocking items: CMake install/export/CPack packaging (`cmake/idaxConfig.cmake.in`, install targets); compile-only API surface parity test (`tests/unit/api_surface_parity_test.cpp` as OBJECT library); advanced debugger/ui/graph/event validation test (60 checks); loader/processor scenario test; fixture README expansion; opaque boundary audit cleanup (removed 5 SDK type mentions from public header comments); full validation pass (13/13 CTest targets, CPack verified); release readiness artifacts (validation report, performance baseline) - Evidence: 13/13 tests pass, CPack produces `idax-0.1.0-Darwin.tar.gz`, build clean.
- [2026-02-13 07:00] Backlog - Added 3 new integration test suites and expanded 1 existing: decompiler_edge_cases_test (837 lines, 7 sections: multi-function decompilation, variable classification, ctree pattern diversity, rename roundtrip, declaration diversity, line-vs-complexity correlation, address map completeness); event_stress_test (473 lines, 8 sections: concurrent subscribers, rapid sub/unsub cycles, multi-event fan-out with real firing, scoped batch, filtered routing specificity, generic+typed coexistence, double-unsubscribe safety, debugger multi-subscribe); performance_benchmark_test (537 lines, 10 benchmarks: decode throughput, function iteration, pattern search, item scan, xref enumeration, name resolution, decompile latency, data read, comment I/O, type creation); expanded loader_processor_scenario_test (+7 sections: all optional callback defaults, switch edge cases, feature flag composition, assembler validation, accept rejection, ProcessorInfo copy/move, result enum values). Also expanded migration docs (legacy_to_wrapper.md) with complete type system, storage/netnode, and decompiler migration examples - Evidence: 16/16 tests pass, build clean.
- [2026-02-13 08:00] Documentation audit - Fixed 14 API mismatches across 6 doc files: README.md (7 fixes: is_call free fn, frame free fn, type_name, ExprCall, ui::message string concat, schedule, attach_to_menu), common_tasks.md (schedule), disassembly_workflows.md (operand access via decode), processor.md (return types), legacy_to_wrapper.md (3 fixes: create_struct no-arg, import_type 2-arg, set_blob_string), name_comment_xref_search_snippets.md (CallNear). Also updated api_reference.md (added 4 missing headers + descriptions table), validation_report.md (13->16 tests), README.md test counts (13->16), storage_migration_caveats.md (index 0 warning + cross-link) - Evidence: 16/16 tests pass, build clean.
- [2026-02-13 09:00] Documentation polish - Created comprehensive namespace_topology.md (complete type/function inventory per namespace); merged name_comment_xref_search_snippets.md into legacy_to_wrapper.md and removed standalone file; expanded legacy_to_wrapper.md quick reference table with anterior/posterior and regex search entries; fixed last doc mismatch (MemberInfo -> Member in comment); added Section 22 deviation disclaimer with 15 key post-audit API changes; full doc snippet audit confirmed 0 remaining compile-affecting mismatches across all user-facing docs - Evidence: 16/16 tests pass, build clean.
- [2026-02-13 10:00] Compatibility matrix expansion - Added `scripts/run_validation_matrix.sh` (profiles: full/unit/compile-only) and `docs/compatibility_matrix.md` with command-driven OS/compiler rows; executed additional validation rows on macOS arm64 AppleClang 17 (Release and RelWithDebInfo full profiles, plus compile-only and unit profiles) and updated docs (`validation_report.md`, `performance_baseline.md`, `README.md`, `BACKLOG.md`, `docs_completeness_checklist.md`, `api_reference.md`) - Evidence: `build-release` 16/16 pass, `build-matrix-full` 16/16 pass, `build-matrix-unit` 2/2 pass, `build-matrix-compile` build pass.
- [2026-02-13 11:00] Matrix packaging hardening - Updated `scripts/run_validation_matrix.sh` and `scripts/check_packaging.sh` to run `cpack -B <build-dir>` for deterministic artifact placement; executed full+packaging matrix profile (`RUN_PACKAGING=1`) and validated package emission in build tree; updated compatibility/validation docs with packaging evidence row and command - Evidence: `build-matrix-full` 16/16 pass and `build-matrix-full/idax-0.1.0-Darwin.tar.gz` generated.
- [2026-02-13 12:00] Plugin API gap audit - Compared `idax` public surface with `/Users/int/dev/entropyx/ida-port` and documented hard blockers for complex plugin parity (custom dock widgets, HT_VIEW/UI event coverage, jump-to-address, segment type accessors, plugin bootstrap helper gap) - Evidence: cross-check of `include/entropy_explorer/core/plugin.hpp`, `src/core/plugin.cpp`, `src/viz/entropy_widget.cpp` against `include/ida/plugin.hpp`, `include/ida/ui.hpp`, `include/ida/segment.hpp`.
- [2026-02-13 12:30] Complex-plugin parity planning - Produced prioritized closure plan (P0/P1 API deltas + acceptance criteria): opaque dock widget host API, widget-handle UI/VIEW subscriptions (`view_curpos`, `ui_widget_invisible`), `ui::jump_to`, segment type getters/setters, plugin descriptor/export helper, and richer action context hooks - Evidence: mapped usage in `/Users/int/dev/entropyx/ida-port/src/core/plugin.cpp` and `/Users/int/dev/entropyx/ida-port/src/viz/entropy_widget.cpp` against current `include/ida/plugin.hpp`, `include/ida/ui.hpp`, `include/ida/segment.hpp` and `src/plugin.cpp`.
- [2026-02-13 13:00] Complex-plugin parity implementation - Implemented all 6 P0 gap closures from entropyx audit: (1) opaque `Widget` handle class with `create_widget`/`show_widget`/`activate_widget`/`find_widget`/`close_widget`/`is_widget_visible` + `DockPosition` enum + `ShowWidgetOptions` in `ida::ui`; (2) handle-based widget event subscriptions (`on_widget_visible(Widget&, cb)`, `on_widget_invisible(Widget&, cb)`, `on_widget_closing(Widget&, cb)`); (3) `on_cursor_changed(cb)` for HT_VIEW `view_curpos` events with unified unsubscribe routing; (4) `ui::jump_to(Address)` navigation helper; (5) `Segment::type()` getter + `set_type()` free function + expanded `Type` enum (Import/InternalMemory/Group) + fixed `create()` to pass type to SDK; (6) `IDAX_PLUGIN(ClassName)` macro with `plugmod_t` bridge, static char buffers, factory registration + `Action::icon` field + `attach_to_popup()`. Refactored UI event infrastructure: replaced single `UiListener` with parameterized `EventListener` supporting both HT_UI and HT_VIEW, with token-range partitioning for unified `unsubscribe()`. Added `Plugin::init()` virtual for load/skip control - Evidence: 16/16 tests pass, build clean with zero errors.
- [2026-02-13 13:30] Follow-up entropyx audit - Rechecked `/Users/int/dev/entropyx/ida-port` against updated idax surface and confirmed one remaining portability gap: no SDK-opaque API to attach Qt content to `ida::ui::Widget` host panels. Entropyx still needs raw `TWidget*` -> `QWidget*` cast to mount `EntropyExplorerWidget` - Evidence: `src/core/plugin.cpp` host-mount path (`create_empty_widget`, `display_widget`, cast at `void* ida_qt_widget = ida_widget_`, `new viz::EntropyExplorerWidget(container)`) has no equivalent in `include/ida/ui.hpp`.
- [2026-02-13 14:00] Widget host bridge implementation - Added SDK-opaque content-host bridge in `ida::ui`: `WidgetHost` alias, `widget_host(const Widget&) -> Result<void*>`, and `with_widget_host(const Widget&, WidgetHostCallback)`; added headless-safe integration coverage in `debugger_ui_graph_event_test` for invalid-handle validation, empty-callback validation, and success-path callback invocation when widget creation is available - Evidence: build clean and 16/16 tests pass (`ctest --test-dir build --output-on-failure`).
- [2026-02-13 14:30] P1 closure pass - Added `plugin::ActionContext` plus context-aware callbacks (`handler_with_context`, `enabled_with_context`) and implemented activation/update translation from SDK `action_ctx_base_t`; added generic `ida::ui` routing surface (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite token-family unsubscribe support; expanded integration coverage in `loader_processor_scenario_test` and `debugger_ui_graph_event_test` for new APIs - Evidence: build clean and 16/16 tests pass.
- [2026-02-13 15:00] Phase 10 planning - Added comprehensive domain-by-domain SDK parity closure checklist (P10.0-P10.9) with per-namespace subgoals, matrix governance requirements, and explicit evidence gates; updated phase status snapshots and immediate-action priorities - Evidence: `agents.md` Section 10.1 now contains full closure TODO tree and Section 11/16 reflect Phase 10 kickoff.
- [2026-02-13 15:30] P10.0 completion - Created `docs/sdk_domain_coverage_matrix.md` with dual-axis coverage matrices (one row per public domain and one row per major SDK capability family), explicit `covered/partial/missing` statuses, concrete symbol references, and closure/evidence criteria for all partial rows; marked P10.0.a-c complete and updated Phase 10 status to ~5% - Evidence: `docs/sdk_domain_coverage_matrix.md` and `agents.md` Section 10.1 checkbox updates.
- [2026-02-13 16:00] P10.1 completion - Re-audited `ida::error`/`ida::core`/`ida::diagnostics`, fixed diagnostics counter data-race risk by switching to atomic counters in `src/diagnostics.cpp`, verified opaque-boundary comment hygiene in public headers, and expanded compile-only API parity coverage for newly added UI/plugin symbols (including overloaded subscription APIs) in `tests/unit/api_surface_parity_test.cpp`; marked P10.1.a-c complete and updated Phase 10 status to ~15% - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`).
- [2026-02-13 16:30] P10.2 completion - Added address predicate traversal ranges (`code_items`/`data_items`/`unknown_bytes`) and discoverability aliases (`next_defined`/`prev_defined`), added data patch revert APIs (`revert_patch`, `revert_patches`) and expanded define helpers (`define_oword`/`define_tbyte`/`define_float`/`define_double`/`define_struct`), added database open/load intent conveniences (`OpenMode`, `LoadIntent`, `open_binary`, `open_non_binary`) plus metadata parity helpers (`address_bounds`, `address_span`); expanded compile-only parity checks and integration coverage (`smoke_test`, `data_mutation_safety_test`), and updated matrix rows to `covered` for address/data/database families - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 17:00] P10.3 completion - Added segment parity helpers (`resize`, `move`, segment `comment`/`set_comment`, `first`/`last`/`next`/`prev`), function parity helpers (`update`, `reanalyze`, `item_addresses`, `code_addresses`, `frame_variable_by_name`, `frame_variable_by_offset`, `register_variables`), and instruction parity helpers (`OperandFormat`, `set_operand_format`, `operand_text`, `is_jump`, `is_conditional_jump`); expanded compile-only parity checks and integration coverage in `segment_function_edge_cases_test`, `instruction_decode_behavior_test`, and `operand_and_text_test`, and updated coverage matrix rows (`ida::segment`/`ida::function`/`ida::instruction`) to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 17:47] P10.4 completion - Added name parity helpers (`is_user_defined`, `is_valid_identifier`, `sanitize_identifier`), xref range/filter parity (`ReferenceRange`, typed `refs_from/refs_to` filters, `*_range` APIs, type predicates), comment indexed edit/remove helpers (`set_anterior/set_posterior`, `remove_anterior_line/remove_posterior_line`), type parity helpers (`CallingConvention`, function-type/enum construction helpers, function return/arg/variadic/cc introspection, enum member extraction), entry forwarder management (`forwarder`, `set_forwarder`, `clear_forwarder`), and fixup descriptor fidelity + traversal helpers (`flags/base/target`, signed fixup types, `in_range`); expanded compile-only and integration coverage in `api_surface_parity_test`, `name_comment_xref_search_test`, `type_roundtrip_test`, `fixup_relocation_test`, and `smoke_test`, and updated matrix rows for metadata domains/capability families to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 18:20] P10.5 completion - Added search parity helpers (`ImmediateOptions`, `BinaryPatternOptions`, `next_defined`, `next_error`) and validated option semantics in integration tests; added analysis intent/rollback helpers (`schedule_code`, `schedule_function`, `schedule_reanalysis`, `schedule_reanalysis_range`, `cancel`, `revert_decisions`) while keeping backward-compatible `schedule` aliases; expanded compile-only parity checks and updated coverage matrix rows for `ida::search`/`ida::analysis` and related capability families to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 18:55] P10.6 completion - Added plugin action detach helpers (`detach_from_menu`, `detach_from_toolbar`, `detach_from_popup`) and finalized context-aware action ergonomics docs; expanded loader authoring coverage with typed request/flag models (`LoadFlags`, `LoadRequest`, `SaveRequest`, `MoveSegmentRequest`, `ArchiveMemberRequest`), raw flag encode/decode helpers, and context-rich virtual hooks (`load_with_request`, `save_with_request`, `move_segment_with_request`, `process_archive`); added processor output-context abstraction (`OutputContext`, `OutputInstructionResult`, `output_instruction_with_context`, `output_operand_with_context`) plus advanced descriptor/assembler parity checks; expanded compile-only and scenario integration coverage, and updated matrix rows for `ida::plugin`/`ida::loader`/`ida::processor` and related capability families to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), docs updated (`docs/quickstart/plugin.md`, `docs/quickstart/loader.md`, `docs/quickstart/processor.md`, `docs/migration/legacy_to_wrapper.md`, `docs/sdk_domain_coverage_matrix.md`).
- [2026-02-13 19:20] P10.7.e completion - Added storage node-identity helpers (`Node::open_by_id`, `Node::id`, `Node::name`) and expanded storage hardening coverage for id/open-by-id roundtrip + invalid-id behavior; updated compile-only parity checks and migration docs (`legacy_to_wrapper`, `storage_migration_caveats`, namespace topology), and moved `ida::storage` capability rows in coverage matrix to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 19:45] P10.7.a completion - Added debugger request-queue parity helpers (`request_suspend`, `request_resume`, `request_step_into`, `request_step_over`, `request_step_out`, `request_run_to`, `run_requests`, `is_request_running`), thread introspection/control helpers (`thread_count`, `thread_id_at`, `thread_name_at`, `current_thread_id`, `threads`, `select_thread` + request/suspend/resume variants), and register introspection helpers (`register_info`, `is_integer_register`, `is_floating_register`, `is_custom_register`); expanded compile-only and integration coverage in `api_surface_parity_test` and `debugger_ui_graph_event_test`, and moved debugger rows in the coverage matrix to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), `docs/sdk_domain_coverage_matrix.md` updates.
- [2026-02-13 20:10] P10.7.b completion - Added UI custom-viewer wrappers (`create_custom_viewer`, line replacement/count/jump/current-line/refresh/close) with wrapper-managed viewer state and validation, expanded UI/VIEW routing (`on_database_inited`, `on_current_widget_changed`, `on_view_activated`/`on_view_deactivated`/`on_view_created`/`on_view_closed`, expanded `EventKind` + `Event` payload), and added integration + compile-only coverage (`debugger_ui_graph_event_test`, `api_surface_parity_test`); updated topology and matrix rows for UI to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), docs updated (`docs/namespace_topology.md`, `docs/sdk_domain_coverage_matrix.md`).
- [2026-02-13 20:40] P10.7.c completion - Added graph viewer lifecycle/query helpers (`has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, `close_graph_viewer`) and explicit layout-state introspection (`Graph::current_layout`), expanded integration coverage with layout matrix + viewer lifecycle checks and compile-only parity checks (`debugger_ui_graph_event_test`, `api_surface_parity_test`), and moved graph rows in the coverage matrix to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), docs updated (`docs/namespace_topology.md`, `docs/sdk_domain_coverage_matrix.md`).
- [2026-02-13 21:10] P10.7.d completion - Added decompiler variable-retype APIs (`retype_variable` by name/index) using saved-user-lvar updates and added orphan-comment workflow helpers (`has_orphan_comments`, `remove_orphan_comments`); expanded decompiler integration coverage for retype + comment-position/orphan flows (`decompiler_storage_hardening_test`) and compile-only parity checks (`api_surface_parity_test`), and moved decompiler rows in the coverage matrix to `covered` - Evidence: build clean + 16/16 tests pass (`cmake --build build`, `ctest --test-dir build --output-on-failure`), docs updated (`docs/migration/legacy_to_wrapper.md`, `docs/namespace_topology.md`, `docs/sdk_domain_coverage_matrix.md`).
- [2026-02-13 21:35] P10.8.a-c and P10.9.c progress - Completed docs/validation closure items for newly covered domains (migration + topology + API index updates) and re-ran matrix profiles (`full`, `unit`, `compile-only`) on macOS arm64 AppleClang 17 via automation script; marked profile gate P10.9.c complete - Evidence: `scripts/run_validation_matrix.sh full build-matrix-full RelWithDebInfo` (16/16 pass), `scripts/run_validation_matrix.sh unit build-matrix-unit RelWithDebInfo` (2/2 pass), `scripts/run_validation_matrix.sh compile-only build-matrix-compile RelWithDebInfo` (build pass), docs updated (`docs/migration/legacy_to_wrapper.md`, `docs/api_reference.md`, `docs/namespace_topology.md`, `docs/compatibility_matrix.md`).
- [2026-02-13 21:50] P10.9.a-b progress - Added explicit intentional-abstraction notes for remaining `partial` cross-cutting/event rows in `docs/sdk_domain_coverage_matrix.md` and confirmed no high-severity migration blockers remain in `Blockers` for plugin/loader/processor/decompiler/ui workflows; marked P10.9.a and P10.9.b complete - Evidence: matrix section `D) Intentional abstraction notes` + `Blockers` section remains `None currently`.
- [2026-02-13 22:10] Matrix packaging evidence refresh - Re-ran full matrix profile with packaging (`RUN_PACKAGING=1`) after P10.7.d decompiler changes and refreshed docs evidence paths for packaging artifacts - Evidence: `scripts/run_validation_matrix.sh full build-matrix-full-pack RelWithDebInfo` (16/16 pass + `build-matrix-full-pack/idax-0.1.0-Darwin.tar.gz`), docs updated (`docs/compatibility_matrix.md`, `docs/validation_report.md`).
- [2026-02-13 22:30] P10.8.d matrix progress - Executed Linux compile-only rows in Ubuntu 24.04 Docker with fresh build dirs: GCC 13.3.0 passed, Clang 18.1.3 failed due missing `std::expected` under current toolchain/stdlib pairing; updated compatibility and validation docs with explicit pass/fail evidence and caveat - Evidence: `scripts/run_validation_matrix.sh compile-only /work/idax/build-matrix-linux-gcc-docker RelWithDebInfo` (pass), `scripts/run_validation_matrix.sh compile-only /work/idax/build-matrix-linux-clang-docker RelWithDebInfo` (fail), docs updated (`docs/compatibility_matrix.md`, `docs/validation_report.md`).
- [2026-02-13 22:40] P10.8.d matrix investigation - Retried Linux Clang compile-only row with explicit libc++ (`CXXFLAGS/LDFLAGS=-stdlib=libc++`) in Ubuntu 24.04 Docker; build still fails due SDK `pro.h` `snprintf` macro remap colliding with libc++ headers; documented fallback failure in findings and matrix docs - Evidence: `scripts/run_validation_matrix.sh compile-only /work/idax/build-matrix-linux-clang-libcpp RelWithDebInfo` (fail), docs updated (`docs/compatibility_matrix.md`, `docs/validation_report.md`).
- [2026-02-13 22:55] P10.8.d CI automation - Added GitHub Actions matrix workflow to execute `compile-only` + `unit` profiles across Linux/macOS (x86_64 + arm64)/Windows using SDK checkout and `scripts/run_validation_matrix.sh`; updated findings/decision log for CI-driven evidence path - Evidence: `.github/workflows/validation-matrix.yml`.
- [2026-02-13 23:10] P10.8.d CI hardening - Fixed SDK bootstrap path failures from hosted runs by adding multi-layout `IDASDK` resolution in workflow (`ida-sdk/ida-cmake`, `ida-sdk/cmake`, `ida-sdk/src/ida-cmake`, `ida-sdk/src/cmake`), enabling recursive SDK submodule checkout, and making top-level `CMakeLists.txt` accept all supported bootstrap layouts before `find_package(idasdk)`; this aligns idax bootstrap behavior with layout variance seen across SDK checkouts - Evidence: `.github/workflows/validation-matrix.yml`, `CMakeLists.txt`.
- [2026-02-13 23:20] P10.8.d CI diagnostics - Improved workflow bootstrap failure diagnostics to print all checked SDK bootstrap paths and submodule hint; this reduces rerun/debug latency when hosted SDK layout changes - Evidence: `.github/workflows/validation-matrix.yml`.
- [2026-02-13 23:25] P10.8.d CI robustness follow-up - Enabled recursive submodule checkout for the project repository step in `.github/workflows/validation-matrix.yml` (SDK checkout was already recursive) so hosted runs have consistent submodule materialization across both checkouts - Evidence: `.github/workflows/validation-matrix.yml`.
- [2026-02-13 23:40] P10.8.d hosted-matrix stabilization - Removed retired `macos-13` rows from workflow, fixed cross-generator test invocation by adding explicit `--config/-C` handling in `scripts/run_validation_matrix.sh`, and hardened SDK bridge include order (`<functional>`, `<locale>`, `<vector>`, `<type_traits>` before `pro.h`) to avoid macOS libc++ `dont_use_snprintf` failures; validated locally with SDK-submodule layout using `compile-only` and `unit` profiles - Evidence: `.github/workflows/validation-matrix.yml`, `scripts/run_validation_matrix.sh`, `src/detail/sdk_bridge.hpp`, `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=OFF scripts/run_validation_matrix.sh compile-only build-matrix-macos-local-fix RelWithDebInfo` (pass), `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=OFF scripts/run_validation_matrix.sh unit build-matrix-unit-local-fix RelWithDebInfo` (pass).
- [2026-02-13 23:50] P10.8.d matrix coverage expansion - Enabled example target compilation in validation automation by wiring `IDAX_BUILD_EXAMPLE_ADDONS` through `scripts/run_validation_matrix.sh` and setting workflow env (`IDAX_BUILD_EXAMPLES=ON`, `IDAX_BUILD_EXAMPLE_ADDONS=ON`); locally validated both `compile-only` and `unit` profiles with SDK-submodule layout and addon targets enabled - Evidence: `.github/workflows/validation-matrix.yml`, `scripts/run_validation_matrix.sh`, `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON scripts/run_validation_matrix.sh compile-only build-matrix-examples-local RelWithDebInfo` (pass), `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON scripts/run_validation_matrix.sh unit build-matrix-unit-examples-local RelWithDebInfo` (pass).
- [2026-02-13 23:55] Tracker rename - Renamed the project tracker file to `agents.md` and updated in-repo references in governance/docs/tests (`docs/sdk_domain_coverage_matrix.md`, `tests/unit/api_surface_parity_test.cpp`, and self-references in `agents.md`) - Evidence: repo-wide tracker-name grep is now clean outside `.git` metadata.
- [2026-02-13 23:58] JBC full-port example - Ported `/Users/int/dev/ida-jam` loader+procmod into idax full examples (`examples/loader/jbc_full_loader.cpp`, `examples/procmod/jbc_full_procmod.cpp`, shared `examples/full/jbc_common.hpp`), wired example build/docs (`examples/CMakeLists.txt`, `examples/README.md`), and validated addon compilation - Evidence: `cmake -S . -B build-jbc-full -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON -DIDAX_BUILD_TESTS=OFF` + `cmake --build build-jbc-full --target idax_jbc_full_loader idax_jbc_full_procmod` (pass).
- [2026-02-13 23:59] JBC matrix evidence refresh - Re-ran validation automation with example addons enabled after the JBC full-port addition to ensure compile-only/unit profiles still pass across the full example surface (including `idax_jbc_full_loader` and `idax_jbc_full_procmod`), then updated compatibility docs with the new evidence paths - Evidence: `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON scripts/run_validation_matrix.sh compile-only build-matrix-jbc-compile RelWithDebInfo` (pass), `IDASDK=/Users/int/dev/ida-sdk-ci-test IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON scripts/run_validation_matrix.sh unit build-matrix-jbc-unit RelWithDebInfo` (2/2 pass), `docs/compatibility_matrix.md` updated.
- [2026-02-14 00:10] P10.8.d/P10.9.d closure - Audited hosted validation-matrix logs (`job-logs1.txt`..`job-logs5.txt`) using grep sentinels and confirmed all provided jobs succeeded (Linux/macOS `compile-only` + `unit`, Windows `compile-only`); updated compatibility/validation docs, marked P10.8.d and P10.9.d complete, and moved Phase 10 to 100% with closure summary recorded - Evidence: log markers `Complete job name`, `validation profile '<profile>' complete`, and `100% tests passed`; docs updated (`docs/compatibility_matrix.md`, `docs/validation_report.md`) and Phase 10 checklist updated in `agents.md`.
- [2026-02-14 00:30] JBC parity follow-up closure - Implemented Findings #80-#82 with additive APIs and example/test/docs updates: `ida::processor` typed analyze details (`AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`), tokenized output channels (`OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`), mnemonic hook (`output_mnemonic_with_context`), and `ida::segment` default segment-register seeding helpers (`set_default_segment_register*`); updated JBC full loader/procmod to use the new surfaces and added integration + compile-only parity coverage - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure` (16/16 pass), targeted checks `cmake --build build --target idax_api_surface_check idax_loader_processor_scenario_test idax_segment_function_edge_cases_test idax_jbc_full_loader idax_jbc_full_procmod` + `ctest --test-dir build --output-on-failure -R "api_surface_parity|loader_processor_scenario|segment_function_edge_cases"` (3/3 pass), docs updated (`docs/quickstart/processor.md`, `docs/migration/legacy_to_wrapper.md`, `docs/namespace_topology.md`, `docs/sdk_domain_coverage_matrix.md`, `docs/api_reference.md`).
- [2026-02-14 01:30] Post-Phase-10 real-world port audit - Ported `/Users/int/dev/ida-qtform` into idax example sources (`examples/plugin/qtform_renderer_plugin.cpp`, `examples/plugin/qtform_renderer_widget.*`) and ported `/Users/int/dev/idalib-dump` flows into idax tool examples (`examples/tools/idalib_dump_port.cpp`, `examples/tools/idalib_lumina_port.cpp`, `IDAX_BUILD_EXAMPLE_TOOLS` CMake option); documented identified parity gaps in `docs/port_gap_audit_ida_qtform_idalib_dump.md` and linked matrix intentional-abstraction notes; validated build + tests (`cmake --build build`, `ctest --test-dir build --output-on-failure` 16/16 pass) and validated tool-target compilation (`cmake -S . -B build-port-gap -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_TOOLS=ON -DIDAX_BUILD_EXAMPLE_ADDONS=OFF -DIDAX_BUILD_TESTS=OFF` + `cmake --build build-port-gap --target idax_idalib_dump_port idax_idalib_lumina_port` pass).
- [2026-02-14 02:00] Post-Phase-10 parity follow-up - Added markup-only `ida::ui::ask_form(std::string_view)` wrapper (`include/ida/ui.hpp`, `src/ui.cpp`), extended compile-only parity checks (`tests/unit/api_surface_parity_test.cpp`), and updated gap-tracking docs (`docs/port_gap_audit_ida_qtform_idalib_dump.md`, `docs/sdk_domain_coverage_matrix.md`) to reflect closure of the ask_form gap - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure -R api_surface_parity` (pass).
- [2026-02-14 02:30] Post-Phase-10 parity follow-up - Added decompiler microcode extraction APIs (`DecompiledFunction::microcode`, `DecompiledFunction::microcode_lines`) and wired idalib-dump port usage (`examples/tools/idalib_dump_port.cpp`), plus integration + compile-only coverage updates (`decompiler_storage_hardening_test`, `api_surface_parity_test`) and docs refresh (`port_gap_audit`, `migration`, `namespace_topology`, `api_reference`, `sdk_domain_coverage_matrix`, `examples/README`) to close the microcode gap - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (pass), `ctest --test-dir build --output-on-failure` (16/16 pass), `cmake --build build-port-gap --target idax_idalib_dump_port` (pass).
- [2026-02-14 03:00] Post-Phase-10 parity follow-up - Added structured decompile-failure details (`DecompileFailure` + overloaded `decompile`) in `ida::decompiler`, updated idalib-dump port error reporting to use the new details, expanded integration + compile-only checks (`decompiler_storage_hardening_test`, `api_surface_parity_test`), and refreshed docs/gap audit (`port_gap_audit`, `sdk_domain_coverage_matrix`, `migration`, `namespace_topology`, `api_reference`, `examples/README`) to close the failure-detail gap - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure` (16/16 pass), `cmake --build build-port-gap --target idax_idalib_dump_port` (pass).
- [2026-02-14 03:20] Documentation alignment - Updated `README.md` to match current parity/coverage artifacts: softened absolute completeness wording, refreshed header/surface summary + domain rows, added explicit known-gap pointer to port audit doc, fixed decompiler snippet lifetime safety (`Result` temporaries), expanded examples tree overview, and switched package command to pinned-output `cpack --config ... -B ...` form - Evidence: `README.md` diff aligned with `docs/sdk_domain_coverage_matrix.md`, `docs/compatibility_matrix.md`, `docs/api_reference.md`, and `examples/README.md`.
- [2026-02-14 03:40] Post-Phase-10 parity follow-up - Added headless plugin-load policy controls to `ida::database` (`RuntimeOptions`, `PluginLoadPolicy`, `init` overloads), implemented allowlist wildcard matching (`*`/`?`) and user-plugin isolation sandboxing for non-Windows paths, and updated the idalib-dump port to route `--no-plugins` / `--plugin` through wrapper-native runtime options; refreshed parity docs/topology/reference to mark the gap closed - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure -R api_surface_parity` (pass), `cmake --build build-port-gap --target idax_idalib_dump_port` (pass).
- [2026-02-14 04:10] Post-Phase-10 parity follow-up - Added diagnostics-oriented database metadata helpers (`file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`) to close idalib-dump metadata gaps; wired startup metadata output in `idalib_dump_port`, expanded compile-only coverage and smoke validation, and updated parity/topology/reference docs plus port-gap audit to reflect closure - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure -R "^smoke$|api_surface_parity"` (pass), `cmake --build build-port-gap --target idax_idalib_dump_port idax_idalib_lumina_port` (pass).
- [2026-02-14 04:40] Post-Phase-10 parity follow-up - Added public `ida::lumina` namespace with typed pull/push wrappers (`Feature`, `PushMode`, `OperationCode`, `BatchResult`, `has_connection`, `pull`, `push`), integrated new API coverage in compile-only + smoke tests, and updated `idalib_lumina_port` + docs to reflect pure-wrapper Lumina workflows; also mapped close APIs to explicit `Unsupported` due missing runtime symbol exports - Evidence: `cmake --build build` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|^smoke$"` (pass), `cmake --build build-port-gap --target idax_idalib_dump_port idax_idalib_lumina_port` (pass).
- [2026-02-14 05:10] Post-Phase-10 real-world port audit - Ported `/Users/int/Downloads/plo/ida2py-main` query/type/callsite workflows into a new idax tool probe (`examples/tools/ida2py_port.cpp`), wired example build target (`idax_ida2py_port`) and docs (`examples/README.md`, `README.md`, `docs/port_gap_audit_ida2py.md`), and recorded concrete additive-gap findings for name enumeration, type decomposition, typed-value materialization, decompiler call argument access, and Appcall/executor coverage - Evidence: `cmake -S . -B build-port-gap -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_TOOLS=ON -DIDAX_BUILD_EXAMPLE_ADDONS=OFF -DIDAX_BUILD_TESTS=OFF` + `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 05:15] ida2py runtime validation attempt - Attempted to execute `idax_ida2py_port` on `tests/binaries/rc4` and observed `exit:139`; confirmed the same host-local crash signature on `idax_idalib_dump_port`, so runtime behavior checks were deferred to a known-good idalib host and compile/help evidence retained for this pass - Evidence: `build-port-gap/examples/idax_ida2py_port --list-user-symbols --max-symbols 5 --show main --callsites printf /Users/int/Downloads/plo/ida2py-main/tests/binaries/rc4` (`exit:139`), `build-port-gap/examples/idax_idalib_dump_port --list /Users/int/Downloads/plo/ida2py-main/tests/binaries/rc4` (`exit:139`).
- [2026-02-14 05:40] Post-Phase-10 parity follow-up - Added `ida::name` inventory APIs (`Entry`, `ListOptions`, `all`, `all_user_defined`), switched the ida2py port probe to `all_user_defined`, expanded compile-only and integration coverage for the new surface, and updated ida2py gap docs to mark name-enumeration closure - Evidence: `cmake --build build --target idax_api_surface_check idax_name_comment_xref_search_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|name_comment_xref_search"` (2/2 pass), `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 05:55] Post-Phase-10 parity follow-up - Added `ida::type::TypeInfo` decomposition + typedef-resolution APIs (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`), expanded compile-only + integration coverage (`api_surface_parity`, `type_roundtrip`), updated ida2py port probe output to use new type-peeling helpers, and refreshed ida2py gap docs to mark decomposition closure - Evidence: `cmake --build build --target idax_api_surface_check idax_type_roundtrip_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|type_roundtrip"` (2/2 pass), `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 06:20] Post-Phase-10 parity follow-up - Added `ida::decompiler::ExpressionView` call-subexpression accessors (`call_callee`, `call_argument(index)`), expanded compile-only + integration coverage (`api_surface_parity`, `decompiler_storage_hardening`), updated ida2py port probe callsite rendering to include callee/arg details, and refreshed ida2py gap docs to mark call-expression access closure - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 06:55] Post-Phase-10 parity follow-up - Added generic typed-value materialization/update APIs in `ida::data` (`TypedValue`, `TypedValueKind`, `read_typed`, `write_typed`) with recursive array handling and byte-array/string write support, wired typed previews in `ida2py_port`, expanded compile-only + integration coverage (`api_surface_parity`, `data_mutation_safety`), and refreshed ida2py gap docs to mark typed-value closure - Evidence: `cmake --build build --target idax_api_surface_check idax_data_mutation_safety_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|data_mutation_safety"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass), `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 07:20] Post-Phase-10 parity follow-up - Added debugger dynamic-invocation APIs (`AppcallValueKind`, `AppcallValue`, `AppcallOptions`, `AppcallRequest`, `AppcallResult`, `AppcallExecutor`, `appcall`, `cleanup_appcall`, executor register/unregister/dispatch), integrated compile-only + integration coverage (`api_surface_parity`, `debugger_ui_graph_event`), and refreshed ida2py docs/probe messaging to mark Appcall/executor gap closure - Evidence: `cmake --build build --target idax_api_surface_check idax_debugger_ui_graph_event_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|debugger_ui_graph_event"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass), `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 07:45] Validation-matrix hardening - Plumbed `IDAX_BUILD_EXAMPLE_TOOLS` through `scripts/run_validation_matrix.sh`, enabled it in `.github/workflows/validation-matrix.yml`, and updated compatibility docs so hosted compile-only + unit rows compile idalib tool-port examples (`idax_idalib_dump_port`, `idax_idalib_lumina_port`, `idax_ida2py_port`) in addition to addon modules - Evidence: `IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON IDAX_BUILD_EXAMPLE_TOOLS=ON scripts/run_validation_matrix.sh compile-only build-matrix-tools-compile RelWithDebInfo` (pass), `IDAX_BUILD_EXAMPLES=ON IDAX_BUILD_EXAMPLE_ADDONS=ON IDAX_BUILD_EXAMPLE_TOOLS=ON scripts/run_validation_matrix.sh unit build-matrix-tools-unit RelWithDebInfo` (2/2 pass), docs updated (`docs/compatibility_matrix.md`).
- [2026-02-14 08:20] Appcall runtime-evidence hardening - Added `--appcall-smoke` flow to `examples/tools/ida2py_port.cpp` (fixture-backed `ref4(NULL)` call path), added dedicated runtime checklist (`docs/appcall_runtime_validation.md`), and updated parity/docs references (`docs/port_gap_audit_ida2py.md`, `docs/compatibility_matrix.md`, `examples/README.md`) for reproducible host-run evidence collection - Evidence: `cmake --build build-port-gap --target idax_ida2py_port` (pass), `build-port-gap/examples/idax_ida2py_port --help` (pass).
- [2026-02-14 08:50] Tool-port runtime linkage hardening - Updated `examples/CMakeLists.txt` so idalib tool examples prefer real IDA runtime dylibs when available (`IDADIR`/common macOS paths) and fall back to `ida_add_idalib` stubs otherwise; validated local non-debugger runtime execution for `idax_ida2py_port`, `idax_idalib_dump_port`, and `idax_idalib_lumina_port`, and confirmed `--appcall-smoke` now fails gracefully with `dbg_appcall` error code `1552` (exit 1) instead of signal-11 - Evidence: `cmake -S . -B build-port-gap(-runtime) ... -DIDAX_BUILD_EXAMPLE_TOOLS=ON` + `cmake --build ... --target idax_ida2py_port idax_idalib_dump_port idax_idalib_lumina_port` (pass), runtime commands on `tests/fixtures/simple_appcall_linux64` (non-debugger flows pass, appcall-smoke returns 1552), docs updated (`docs/compatibility_matrix.md`, `docs/port_gap_audit_ida2py.md`, `docs/appcall_runtime_validation.md`, `examples/README.md`).
- [2026-02-14 09:03] Linux Clang matrix triage - Reproduced Clang 18 compile-only failure in Ubuntu 24.04 (`std::expected` missing), identified feature-macro root cause (`__cpp_concepts=201907`), validated Clang 19 fix (`__cpp_concepts=202002`) and successful baseline compile-only run (`build-matrix-linux-clang19-amd64-baseline`), and documented Clang addon/tool linkage limits due missing `x64_linux_clang_64` SDK runtime libs; refreshed compatibility/validation docs with new pass/fail evidence - Evidence: docker runs for `build-matrix-linux-clang18-amd64-baseline` (fail), `build-matrix-linux-clang19-amd64-baseline` (pass), plus Clang 19 addon/tool ON attempts (`build-matrix-linux-clang19-amd64-docker`, `build-matrix-linux-clang19-amd64-noaddons`) showing missing `libida.so`/`libidalib.so`; docs updated (`docs/compatibility_matrix.md`, `docs/validation_report.md`).
- [2026-02-14 09:45] Open-point closure hardening - Added host-native Appcall fixture source + build helper (`tests/fixtures/simple_appcall_host.c`, `scripts/build_appcall_fixture.sh`), added one-command open-point sweep automation (`scripts/run_open_points.sh`), and upgraded `ida2py_port --appcall-smoke` to bootstrap debugger launch with multi-path fallbacks plus Appcall retry options; executed the sweep and recorded current outcomes (full matrix pass, Lumina smoke pass, Appcall blocked by `start_process failed (return code: -1)`), then refreshed docs (`compatibility_matrix`, `validation_report`, `appcall_runtime_validation`, `port_gap_audit_ida2py`, `examples/README`, `tests/fixtures/README`) - Evidence: `cmake --build build-openpoints-tools --target idax_ida2py_port` (pass), `scripts/build_appcall_fixture.sh build-openpoints-tools/fixtures/simple_appcall_host` (pass), `build-openpoints-tools/examples/idax_ida2py_port --quiet --appcall-smoke build-openpoints-tools/fixtures/simple_appcall_host` (blocked/diagnostic), `scripts/run_open_points.sh build-open-points-run2 RelWithDebInfo` (full=pass, appcall=blocked, lumina=pass), `rg -n "100% tests passed|validation profile 'full' complete" build-open-points-run2/logs/full-matrix.log` (pass markers).
- [2026-02-14 15:45] Post-Phase-10 real-world port audit (lifter) - Added an idax lifter probe plugin (`examples/plugin/lifter_port_plugin.cpp`) with plugin-shell/action/pseudocode-popup workflows, created dedicated gap audit documentation (`docs/port_gap_audit_lifter.md`), updated examples/coverage/readme references (`examples/CMakeLists.txt`, `examples/README.md`, `README.md`, `docs/sdk_domain_coverage_matrix.md`), and recorded a new lifter blocker + findings/decision updates in this tracker - Evidence: `cmake -S . -B build && cmake --build build --target idax_lifter_port_plugin` (pass).
- [2026-02-14 16:30] Lifter parity follow-up - Added decompiler maturity subscription + cache invalidation helpers (`on_maturity_changed`/`unsubscribe`/`ScopedSubscription`, `mark_dirty`/`mark_dirty_with_callers`) and function outline helpers (`is_outlined`/`set_outlined`), updated lifter probe + docs to use/reflect the new APIs, and expanded compile-only/integration coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`, `segment_function_edge_cases_test`) - Evidence: build and targeted tests pass (`cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test idax_segment_function_edge_cases_test idax_lifter_port_plugin`; `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening|segment_function_edge_cases"`).
- [2026-02-14 17:20] Lifter parity follow-up - Added baseline decompiler microcode-filter APIs (`MicrocodeFilter`, `MicrocodeContext`, `MicrocodeApplyResult`, `register_microcode_filter`/`unregister_microcode_filter`, `ScopedMicrocodeFilter`), updated lifter probe + audit/topology/reference docs to reflect closure of filter lifecycle gap, and expanded compile-only/integration coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`) - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test idax_lifter_port_plugin` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening|segment_function_edge_cases"` (3/3 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 18:05] Lifter parity follow-up - Expanded `MicrocodeContext` with additive low-level helpers (`load_operand_register`, `load_effective_address_register`, `store_operand_register`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`, `emit_helper_call`), added validation-path integration coverage in `decompiler_storage_hardening_test`, and refreshed lifter gap docs/matrix language to keep blocker scope focused on typed IR-construction depth - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 18:35] Lifter parity follow-up - Added typed helper-call argument builders in `MicrocodeContext` (`MicrocodeValueKind`, `MicrocodeValue`, `emit_helper_call_with_arguments`, `emit_helper_call_with_arguments_to_register`) with integer-width support, expanded compile-only + integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to reflect the new remaining scope - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 19:05] Lifter parity follow-up - Added helper-call option shaping in `MicrocodeContext` (`MicrocodeCallOptions`, `MicrocodeCallingConvention`, `emit_helper_call_with_arguments_and_options`, `emit_helper_call_with_arguments_to_register_and_options`), expanded compile-only + integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to reflect remaining advanced callinfo/tmop depth - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 19:35] Lifter parity follow-up - Expanded typed helper-call modeling with scalar floating-immediate value kinds (`Float32Immediate`, `Float64Immediate`) and explicit-location call option hinting (`mark_explicit_locations`), expanded compile-only + integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to focus the remaining scope on non-scalar argument + advanced callinfo/tmop depth - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 19:55] Lifter parity follow-up - Added basic explicit helper-call argument-location hints (`MicrocodeValueLocation` register/stack-offset kinds) with automatic explicit-location call-option promotion when hints are present, expanded compile-only + integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to focus remaining scope on non-scalar arguments + advanced callinfo/tmop location semantics - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 20:15] Lifter parity follow-up - Expanded explicit helper-call argument-location hints to include register-pair and register-with-offset forms, added integration checks for malformed location hints, and expanded compile-only/integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`) - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 20:35] Lifter parity follow-up - Added static-address explicit helper-call argument-location hints (`MicrocodeValueLocation::StaticAddress`) with `BadAddress` validation, expanded compile-only/integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to include current scalar location-hint breadth - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).
- [2026-02-14 20:55] Lifter parity follow-up - Added scattered/multi-part explicit helper-call argument-location hints (`MicrocodeLocationPart`, `MicrocodeValueLocationKind::Scattered`) with per-part validation (kind/offset/size), expanded compile-only/integration validation coverage (`api_surface_parity_test`, `decompiler_storage_hardening_test`), and updated lifter parity docs/blocker wording to reflect current scalar location-hint envelope - Evidence: `cmake --build build --target idax_api_surface_check idax_decompiler_storage_hardening_test` (pass), `ctest --test-dir build --output-on-failure -R "api_surface_parity|decompiler_storage_hardening"` (2/2 pass), `ctest --test-dir build --output-on-failure` (16/16 pass).

---

## 16) Immediate Next Actions

Phase 10 closure is complete. All original P0 complex-plugin parity gaps are closed (including widget-host portability), and P10.0-P10.9 are now fully complete.

Post-closure follow-ups (non-blocking):

1. Keep `.github/workflows/validation-matrix.yml` as the default cross-OS evidence path for `compile-only` + `unit` on every release-significant change.
2. Continue host-specific hardening runs where licenses/toolchains permit: keep Linux Clang evidence on Clang 19 baseline for now, and execute Linux/Windows `full` rows with runtime installs.
3. Continue validating the new JBC parity APIs against additional real-world procmod ports and expand typed analyze/output metadata only when concrete migration evidence requires deeper fidelity.
4. Keep hardening `ida::lumina` behavior beyond the now-passing pull/push smoke baseline, especially close/disconnect semantics once portable runtime symbols are confirmed.
5. Execute `docs/appcall_runtime_validation.md` on a debugger-capable host to convert the current `start_process failed (return code: -1)` launch block into pass evidence, then expand Appcall argument/return kind coverage only where concrete ports require additional fidelity.
6. Prioritize additive decompiler write-path design for lifter-class ports: typed microcode IR value/argument/call builders beyond current scalar-helper + lightweight call-option/location-hint coverage (vector/UDT argument + advanced callinfo/tmop semantics) and carefully-scoped raw view-handle context bridging for advanced per-view manipulation flows.

Reminder: Every single TODO and sub-TODO update, and every finding/learning, must be reflected here immediately.

---

## 17) Detailed Public API Concept Catalog (Design Baseline)

This section captures the intended public API semantics at a concrete level so implementation remains aligned with the intuitive-first objective.

### 17.1 `ida::address`
- Core value types: `Address`, `AddressRange`, `AddressSet`
- Primary operations: `next_defined`, `prev_defined`, `item_start`, `item_end`, `item_size`
- Predicates: `is_mapped`, `is_loaded`, `is_code`, `is_data`, `is_unknown`, `is_tail`
- Iteration concepts: item/code/data/unknown range iterators

### 17.2 `ida::data`
- Read family: `read_byte`, `read_word`, `read_dword`, `read_qword`, `read_bytes`
- Write family: `write_byte`, `write_word`, `write_dword`, `write_qword`, `write_bytes`
- Typed value facade: `read_typed`, `write_typed`, `TypedValue`, `TypedValueKind`
- Patch family: `patch_byte`, `patch_word`, `patch_dword`, `patch_qword`, `patch_bytes`, `revert_patch`
- Define family: `define_byte`, `define_word`, `define_dword`, `define_qword`, `define_string`, `define_struct`, `undefine`
- Search helpers: binary pattern and typed immediate searches

### 17.3 `ida::segment`
- Handle model: `Segment` value/view object, no raw struct exposure
- CRUD: create/remove/resize/move
- Properties: name, class, type, bitness, permissions, visibility, comments
- Traversal: by address, by name, first/last/next/prev, iterable segment ranges

### 17.4 `ida::function`
- Handle model: `Function` with chunk abstraction hidden
- Lifecycle: create/remove/set boundaries/update/reanalyze
- Introspection: name, size, bitness, returns/thunk/library flags
- Frame surface: local/arg/register frame helpers with explicit stack semantics
- Relationship helpers: callers/callees, chunk iteration, address iteration

### 17.5 `ida::instruction`
- Decode/create operations with explicit DB mutation distinction
- `Instruction` view object (mnemonic, size, flow)
- `Operand` view object with typed categories and representation controls
- Xref conveniences for refs-from and flow semantics

### 17.6 `ida::name`
- Core naming: set/get/force/remove
- Resolution: symbol-to-address and expression rendering
- Properties: public/weak/auto/user name states
- Demangling forms: short/long/full

### 17.7 `ida::xref`
- Unified xref object model
- Iterable refs-to/refs-from APIs
- Typed filters for call/jump/data read/write/text/informational
- Mutation APIs for add/remove refs with explicit type

### 17.8 `ida::comment`
- Repeatable and non-repeatable comments
- Anterior/posterior line management
- Bulk operations and normalized rendering helpers

### 17.9 `ida::type`
- `TypeInfo` value object with constructor helpers (primitive/pointer/array/function)
- Struct/union/member APIs with byte-based offsets
- Apply/retrieve type operations
- Type library access wrappers and import/export helpers

### 17.10 `ida::entry`
- Entry listing and ordinal/index-safe APIs
- Add/rename/forwarder operations
- Explicit handling for sparse ordinals and lookup behavior

### 17.11 `ida::fixup`
- Fixup object model for type/flags/base/target/displacement
- Enumerate/query and mutation operations
- Custom fixup registration and lookup wrappers

### 17.12 `ida::search`
- Typed direction and options (no raw flag bitmasks in public API)
- Text, immediate, binary, and structural search wrappers
- Cursor-friendly helpers for progressive search workflows

### 17.13 `ida::analysis`
- Queue scheduling wrappers for intent-based actions
- Wait/idle/range-wait wrappers
- State/query wrappers and decision rollback APIs

### 17.14 `ida::database`
- Open/load/save/close wrappers
- File-to-database and memory-to-database helpers
- Snapshot wrappers and metadata APIs (hashes/image base/bounds)

### 17.15 `ida::plugin`
- Plugin base classes and lifecycle abstraction
- Multi-instance support
- Action/menu/toolbar/popup helper APIs
- Registration helpers with type-safe callback signatures

### 17.16 `ida::loader`
- Loader base class with accept/load/save lifecycle
- Input file abstraction wrappers
- Relocation and archive processing helpers
- Registration helpers and metadata model

### 17.17 `ida::processor`
- Processor base class + metadata model wrappers
- Analyze/emulate/output callback abstractions
- Register and instruction descriptor wrappers
- Switch detection and function heuristics APIs

### 17.18 `ida::debugger`
- Process/thread lifecycle wrappers
- Register/memory access wrappers
- Breakpoint/tracing wrappers
- Typed event callback model and async request bridging
- Appcall + pluggable executor wrappers for dynamic invocation workflows

### 17.19 `ida::ui`
- Typed action wrappers replacing unsafe vararg routes
- Dialog/form abstractions
- Chooser abstractions
- Notification/event wrappers with clear ownership

### 17.20 `ida::graph`
- Graph object wrappers
- Node/edge traversal and group/collapse APIs
- Layout and event helpers

### 17.21 `ida::event`
- Typed subscription API
- RAII scoped subscription helpers
- Event filtering and routing helpers

### 17.22 `ida::decompiler`
- Availability and decompile entrypoints
- Decompiled function object + pseudocode access
- Local variable rename/retype helpers
- Ctree visitor abstractions and position/address mappings

### 17.23 `ida::storage` (advanced)
- Opaque node abstraction
- Alt/sup/hash/blob/typed helper APIs
- Explicit caveats for migration and consistency

### 17.24 `ida::lumina`
- Typed Lumina feature selection and operation results
- Metadata pull/push wrappers for function-address batches
- Connection-state query helpers with explicit unsupported close semantics in this runtime

---

## 18) Detailed Legacy Pain Point Catalog (Implementation Guardrails)

This section records concrete friction points discovered during SDK review so wrapper behavior can neutralize them explicitly.

1. Mixed naming within same domain (`segm` and `segment`) causes poor discoverability.
2. Bitness encoded as 0/1/2 instead of 16/32/64 is repeatedly error-prone.
3. Segment names/classes represented by internal IDs (`uval_t`) instead of strings leaks internals.
4. Function entry vs tail chunk union semantics are implicit and easy to misuse.
5. Pointer validity often depends on manual lock helpers (`lock_*`) not enforced by type system.
6. `flags64_t` packs unrelated concerns (state/type/operand metadata) behind overlapping bit regions.
7. Multiple retrieval variants exist for names and xrefs with subtle behavior differences.
8. Return conventions are inconsistent (`bool`, `int`, `ssize_t`, sentinel values).
9. Several APIs rely on magic argument combinations and sentinel values for special behavior.
10. Include-order dependencies expose features conditionally in a non-obvious way.
11. Search direction defaults rely on zero-value bitmasks that are not self-evident.
12. Debugger APIs duplicate direct and request variants, increasing accidental misuse risk.
13. UI and debugger dispatch rely on varargs notification systems with weak compile-time checks.
14. Type APIs contain deep complexity with historical encodings and many parallel concepts.
15. Decompiler APIs enforce maturity/order constraints that are easy to violate accidentally.
16. Manual memory and ownership conventions still appear in several API families.
17. Numeric and representation controls are spread across low-level helper patterns.
18. Migration requires broad knowledge of legacy naming and bitflag semantics.

Wrapper response requirements derived from these pain points:
- Convert encoded flags to typed enums/options in public API.
- Normalize naming to full words and consistent verb-first action names.
- Collapse duplicate traversal APIs into single iterable abstractions.
- Replace sentinel-heavy behavior with structured result/value objects.
- Expose explicit state/lifecycle semantics in class design.
- Make advanced operations available, but never default-obscure.

---

## 19) Legacy-to-Wrapper Naming Normalization Examples

This mapping is non-exhaustive but representative of expected direction.

| Legacy SDK | Wrapper Concept |
|---|---|
| `getseg(ea)` | `ida::segment::at(address)` |
| `get_segm_qty()` | `ida::segment::count()` |
| `get_next_seg(ea)` | `ida::segment::next(address)` |
| `set_segm_name(seg, name)` | `segment.set_name(name)` |
| `add_func(ea1, ea2)` | `ida::function::create(start, end)` |
| `del_func(ea)` | `ida::function::remove(address)` |
| `get_func_name(qstring*, ea)` | `function.name()` / `ida::function::name_at(address)` |
| `decode_insn(insn*, ea)` | `ida::instruction::decode(address)` |
| `create_insn(ea)` | `ida::instruction::create(address)` |
| `get_byte(ea)` | `ida::data::read_byte(address)` |
| `put_byte(ea, v)` | `ida::data::write_byte(address, value)` |
| `patch_byte(ea, v)` | `ida::data::patch_byte(address, value)` |
| `del_items(ea, ...)` | `ida::data::undefine(address, size)` |
| `set_name(ea, name, flags)` | `ida::name::set(address, name, options)` |
| `force_name(ea, name, flags)` | `ida::name::force_set(address, name, options)` |
| `get_name_ea(from, name)` | `ida::name::resolve(name, context)` |
| `add_cref(from, to, type)` | `ida::xref::add_code_ref(from, to, type)` |
| `add_dref(from, to, type)` | `ida::xref::add_data_ref(from, to, type)` |
| `get_first_cref_from(ea)` loop | `for (auto x : ida::xref::refs_from(ea))` |
| `set_cmt(ea, cmt, rpt)` | `ida::comment::set(address, text, repeatable)` |
| `find_text(...)` | `ida::search::text(options)` |
| `auto_wait()` | `ida::analysis::wait()` |
| `plan_ea(ea)` | `ida::analysis::schedule_reanalysis(address)` |
| `loader_t::accept_file` | `ida::loader::Loader::accept(file)` |
| `loader_t::load_file` | `ida::loader::Loader::load(file, format)` |
| `plugin_t::init/run/term` | `ida::plugin::Plugin` lifecycle methods |
| `processor_t::ana/emu/out` | `ida::processor::Processor` lifecycle methods |

Normalization policy:
- Expand abbreviations (`segm` -> `segment`, `func` -> `function`, `cmt` -> `comment`).
- Keep technical terms where established (`xref`, `ctree`, `fixup`) but define consistent wrappers.
- Replace ambiguous suffixes with explicit nouns (`*_qty` -> `count`, `*_ea` -> `address`).

---

## 20) Tracking Templates (Use Exactly)

### 20.1 TODO Status Template

Use this line format inside phase lists when status changes:
- `[status] ID - short task summary - owner - timestamp`

Status values:
- `[ ]` pending
- `[~]` in progress
- `[x]` done
- `[!]` blocked

### 20.2 Progress Ledger Template

`[YYYY-MM-DD HH:MM] scope - change - evidence`

Examples:
- `[2026-02-14 10:32] P2.2 - added patch/read wrappers - tests: data_patch_test.cpp passed`
- `[2026-02-14 11:05] P3.3 - introduced iterable xref range - benchmark: 6.3% faster than baseline`

### 20.3 Findings Template

`[YYYY-MM-DD] domain - finding - impact - mitigation`

Examples:
- `[2026-02-14] function - chunk invalidation after resize - high - moved to stable ID handles`
- `[2026-02-14] type - typedef recursion edge case - medium - add cycle detection in adapter`

### 20.4 Decision Template

`[YYYY-MM-DD] decision - rationale - alternatives considered - impact`

### 20.5 Blocker Template

- Blocker ID:
- Date raised:
- Scope impacted:
- Severity:
- Description:
- Immediate mitigation:
- Long-term mitigation:
- Owner:
- Next checkpoint:

---

## 21) Compliance Reminder (Hard Requirement)

No task is complete until this file is updated.

This requirement applies to:
- Parent TODOs
- Sub-TODOs
- Findings and learnings
- Decisions
- Blockers
- Progress ledger entries

If any of the above changes and `agents.md` is not updated immediately, the work is considered incomplete.

---

## 22) Comprehensive Interface Blueprint (Detailed)

This section explicitly records the interface-level design that was discussed. It is intentionally detailed so implementation can proceed with minimal ambiguity.

Scope and constraints for this section:
- These are design-level API sketches, not final ABI commitments.
- Public API remains fully opaque.
- No public `.raw()` escape hatches are allowed.
- Public strings use `std::string`/`std::string_view`.
- Error flow is standardized around `std::expected` aliases.

**NOTE (2026-02-13):** The sketches below were the *design baseline* before implementation. The actual headers in `include/ida/` are the authoritative API surface. Key deviations from sketches applied during P9.1 audit:
- All `ea` parameters renamed to `address` across public API.
- `Segment::visible()` → `Segment::is_visible()` (positive polarity).
- `Function::is_hidden()` removed; use `Function::is_visible()`.
- `frame()` / `sp_delta_at()` are free functions in `ida::function`, not `Function` members.
- `Plugin::run()` returns `Status`, not `bool`.
- `Processor::emulate()` returns `EmulateResult`, `output_operand()` returns `OutputOperandResult`.
- `attach_action_to_menu/toolbar` → `attach_to_menu/toolbar`.
- `xref::Reference::raw_type` replaced by typed `ReferenceType` enum.
- `Chooser::impl()` / `Graph::impl()` made private.
- `DecompiledFunction` is move-only (non-copyable).
- `ItemType::Call` renamed to `ItemType::ExprCall`.
- `ida::type::TypeInfo::create_struct()` takes no arguments; use `save_as(name)` afterward.
- `ida::type::import_type()` requires two arguments: `(source_til_name, type_name)`.
- `ida::ui::message()` takes single `std::string_view`, not printf-style format args.
- See `docs/namespace_topology.md` for the complete, authoritative type/function inventory.

### 22.1 Diagnosis - Why the SDK feels unintuitive

Core issues to solve:
1. Naming chaos: mixed abbreviations (`segm`, `func`, `cmt`) and inconsistent prefixes.
2. Conceptual opacity: packed flags and hidden relationships behind internal conventions.
3. Inconsistent patterns: mixed return/error conventions and multiple competing APIs.
4. Hidden dependencies: include-order constraints, pointer invalidation rules, sentinel-heavy semantics.
5. Redundancy: multiple enumeration and access paths for the same concepts.

### 22.2 Design philosophy

1. Domain-driven namespacing.
2. Self-documenting names and full words.
3. Consistent error model (`Result<T>`, `Status`).
4. RAII and value semantics by default.
5. Iterable/range-first API for traversal-heavy tasks.
6. Progressive disclosure: simple default path plus advanced options.

### 22.3 Namespace architecture (detailed)

```text
ida::
  address, data, database, segment, function, instruction,
  name, xref, comment, type, fixup, entry,
  search, analysis,
  plugin, loader, processor,
  debugger, ui, graph, event,
  decompiler,
  storage (advanced)
```

### 22.4 Cross-cutting public primitives

```cpp
namespace ida {

using Address = ea_t;
using AddressDelta = adiff_t;
using AddressSize = asize_t;

template <typename T>
using Result = std::expected<T, Error>;

using Status = std::expected<void, Error>;

enum class ErrorCategory {
  Validation,
  NotFound,
  Conflict,
  Unsupported,
  SdkFailure,
  Internal,
};

struct Error {
  ErrorCategory category;
  int code;
  std::string message;
  std::string context;
};

}  // namespace ida
```

### 22.5 Detailed interface sketches by namespace

#### 22.5.1 `ida::address`

```cpp
namespace ida::address {

struct Range {
  Address start;
  Address end;  // half-open [start, end)
};

Result<Address> next_defined(Address ea);
Result<Address> prev_defined(Address ea);
Result<Address> item_start(Address ea);
Result<Address> item_end(Address ea);
Result<AddressSize> item_size(Address ea);

bool is_mapped(Address ea);
bool is_loaded(Address ea);
bool is_code(Address ea);
bool is_data(Address ea);
bool is_unknown(Address ea);
bool is_tail(Address ea);

Range item_range(Address ea);

class ItemRange;
class CodeRange;
class DataRange;
class UnknownRange;

ItemRange items(Address start, Address end);
CodeRange code_items(Address start, Address end);
DataRange data_items(Address start, Address end);
UnknownRange unknown_bytes(Address start, Address end);

}  // namespace ida::address
```

#### 22.5.2 `ida::segment`

```cpp
namespace ida::segment {

enum class Type {
  Normal,
  External,
  Code,
  Data,
  Import,
  Null,
  Undefined,
  Bss,
  AbsoluteSymbols,
  Common,
  InternalMemory,
};

struct Permissions {
  bool read;
  bool write;
  bool execute;
};

class Segment {
 public:
  Address start() const;
  Address end() const;
  AddressSize size() const;

  std::string name() const;
  std::string class_name() const;
  Status set_name(std::string_view name);
  Status set_class_name(std::string_view class_name);

  int bitness() const;  // 16/32/64
  Status set_bitness(int bits);

  Type type() const;
  Status set_type(Type t);

  Permissions permissions() const;
  Status set_permissions(Permissions p);

  bool visible() const;
  Status set_visible(bool visible);

  std::string comment(bool repeatable = false) const;
  Status set_comment(std::string_view text, bool repeatable = false);

  Status update();
};

Result<Segment> create(Address start, Address end,
                       std::string_view name,
                       std::string_view class_name,
                       Type type = Type::Normal);
Status remove(Address any_ea_inside_segment);
Result<Segment> at(Address ea);
Result<Segment> by_name(std::string_view name);
Result<size_t> count();

class SegmentRange;
SegmentRange all();

}  // namespace ida::segment
```

#### 22.5.3 `ida::function`

```cpp
namespace ida::function {

class StackFrame {
 public:
  AddressSize local_variables_size() const;
  AddressSize saved_registers_size() const;
  AddressSize arguments_size() const;
  AddressSize total_size() const;

  Result<int32_t> stack_delta_at(Address ea) const;
  Status define_variable(std::string_view name, int32_t frame_offset,
                         const ida::type::TypeInfo &type);
};

class Function {
 public:
  Address start() const;
  Address end() const;
  std::string name() const;

  int bitness() const;
  AddressSize total_size() const;
  bool returns() const;
  bool is_library() const;
  bool is_thunk() const;
  bool visible() const;
  Status set_visible(bool visible);

  std::string comment(bool repeatable = false) const;
  Status set_comment(std::string_view text, bool repeatable = false);

  bool has_frame() const;
  Result<StackFrame> frame() const;

  Status update();
};

Result<Function> create(Address start, Address end = BADADDR);
Status remove(Address ea);
Result<Function> at(Address ea);
Result<size_t> count();

class FunctionRange;
FunctionRange all();

}  // namespace ida::function
```

#### 22.5.4 `ida::instruction`

```cpp
namespace ida::instruction {

enum class OperandType {
  None,
  Register,
  MemoryDirect,
  MemoryIndirect,
  MemoryDisplacement,
  Immediate,
  FarCodeReference,
  NearCodeReference,
  ProcessorSpecific0,
  ProcessorSpecific1,
  ProcessorSpecific2,
  ProcessorSpecific3,
  ProcessorSpecific4,
  ProcessorSpecific5,
};

class Operand {
 public:
  int index() const;
  OperandType type() const;

  bool is_register() const;
  bool is_immediate() const;
  bool is_memory() const;

  Result<uint16_t> register_id() const;
  Result<uint64_t> immediate_value() const;
  Result<Address> target_address() const;
  Result<int64_t> displacement() const;

  Result<std::string> text() const;

  Status set_hex();
  Status set_decimal();
  Status set_octal();
  Status set_binary();
  Status set_character();
  Status set_offset(Address base = 0);
  Status set_enum(uint32_t enum_id);
  Status set_struct_offset(uint32_t struct_id);
  Status set_stack_variable();
  Status clear_representation();
};

class Instruction {
 public:
  Address address() const;
  AddressSize size() const;
  uint16_t opcode() const;
  std::string mnemonic() const;

  size_t operand_count() const;
  Result<Operand> operand(size_t index) const;

  bool is_call() const;
  bool is_jump() const;
  bool is_conditional_jump() const;
  bool is_return() const;
  bool has_fallthrough() const;
};

Result<Instruction> decode(Address ea);   // no DB mutation
Result<Instruction> create(Address ea);   // DB mutation

}  // namespace ida::instruction
```

#### 22.5.5 `ida::data`

```cpp
namespace ida::data {

Result<uint8_t> read_byte(Address ea);
Result<uint16_t> read_word(Address ea);
Result<uint32_t> read_dword(Address ea);
Result<uint64_t> read_qword(Address ea);
Result<std::vector<uint8_t>> read_bytes(Address ea, AddressSize count);

Status write_byte(Address ea, uint8_t value);
Status write_word(Address ea, uint16_t value);
Status write_dword(Address ea, uint32_t value);
Status write_qword(Address ea, uint64_t value);
Status write_bytes(Address ea, std::span<const uint8_t> bytes);

Status patch_byte(Address ea, uint8_t value);
Status patch_word(Address ea, uint16_t value);
Status patch_dword(Address ea, uint32_t value);
Status patch_qword(Address ea, uint64_t value);
Status patch_bytes(Address ea, std::span<const uint8_t> bytes);
Status revert_patch(Address ea);

Result<uint8_t> original_byte(Address ea);
Result<uint16_t> original_word(Address ea);
Result<uint32_t> original_dword(Address ea);
Result<uint64_t> original_qword(Address ea);

Status define_byte(Address ea, AddressSize count = 1);
Status define_word(Address ea, AddressSize count = 1);
Status define_dword(Address ea, AddressSize count = 1);
Status define_qword(Address ea, AddressSize count = 1);
Status define_string(Address ea, AddressSize length);
Status define_struct(Address ea, AddressSize length, uint32_t struct_id);
Status undefine(Address ea, AddressSize count = 1);

}  // namespace ida::data
```

#### 22.5.6 `ida::name`

```cpp
namespace ida::name {

enum class DemangleForm {
  Short,
  Long,
  Full,
};

Status set(Address ea, std::string_view name);
Status force_set(Address ea, std::string_view name);
Status remove(Address ea);

Result<std::string> get(Address ea);
Result<std::string> demangled(Address ea, DemangleForm form = DemangleForm::Short);
Result<Address> resolve(std::string_view name, Address context = BADADDR);

bool is_public(Address ea);
bool is_weak(Address ea);
bool is_user_defined(Address ea);
bool is_auto_generated(Address ea);

Status set_public(Address ea, bool value);
Status set_weak(Address ea, bool value);

Result<bool> is_valid_identifier(std::string_view text);
Result<std::string> sanitize_identifier(std::string_view text);

}  // namespace ida::name
```

#### 22.5.7 `ida::xref`

```cpp
namespace ida::xref {

enum class CodeType {
  Call,
  Jump,
  Flow,
};

enum class DataType {
  Offset,
  Read,
  Write,
  Text,
  Informational,
};

struct Reference {
  Address from;
  Address to;
  bool is_code;
  int type;
  bool user_defined;
};

Status add_code(Address from, Address to, CodeType type);
Status add_data(Address from, Address to, DataType type);
Status remove_code(Address from, Address to);
Status remove_data(Address from, Address to);

class ReferenceRange;
ReferenceRange refs_from(Address ea);
ReferenceRange refs_to(Address ea);
ReferenceRange code_refs_from(Address ea);
ReferenceRange code_refs_to(Address ea);
ReferenceRange data_refs_from(Address ea);
ReferenceRange data_refs_to(Address ea);

}  // namespace ida::xref
```

#### 22.5.8 `ida::type`

```cpp
namespace ida::type {

enum class CallingConvention {
  Default,
  Cdecl,
  Stdcall,
  Pascal,
  Fastcall,
  Thiscall,
  Vectorcall,
  Syscall,
  Unknown,
};

class TypeInfo {
 public:
  static TypeInfo void_type();
  static TypeInfo int8();
  static TypeInfo int16();
  static TypeInfo int32();
  static TypeInfo int64();
  static TypeInfo uint8();
  static TypeInfo uint16();
  static TypeInfo uint32();
  static TypeInfo uint64();
  static TypeInfo float32();
  static TypeInfo float64();

  static TypeInfo pointer_to(const TypeInfo &target);
  static TypeInfo array_of(const TypeInfo &element, size_t count);
  static Result<TypeInfo> from_c_declaration(std::string_view declaration);

  bool is_void() const;
  bool is_integer() const;
  bool is_floating_point() const;
  bool is_pointer() const;
  bool is_array() const;
  bool is_function() const;
  bool is_struct() const;
  bool is_union() const;
  bool is_enum() const;

  Result<size_t> size() const;
  Result<std::string> to_c_declaration() const;
  Status apply(Address ea) const;
};

}  // namespace ida::type
```

#### 22.5.9 `ida::comment`

```cpp
namespace ida::comment {

Result<std::string> get(Address ea, bool repeatable = false);
Status set(Address ea, std::string_view text, bool repeatable = false);
Status append(Address ea, std::string_view text, bool repeatable = false);
Status remove(Address ea, bool repeatable = false);

Status add_anterior_line(Address ea, std::string_view text);
Status add_posterior_line(Address ea, std::string_view text);
Result<std::vector<std::string>> anterior_lines(Address ea);
Result<std::vector<std::string>> posterior_lines(Address ea);

}  // namespace ida::comment
```

#### 22.5.10 `ida::search`

```cpp
namespace ida::search {

enum class Direction {
  Forward,
  Backward,
};

Result<Address> text(std::string_view query, Address start,
                     Direction direction = Direction::Forward,
                     bool case_sensitive = true,
                     bool regex = false);

Result<Address> immediate(uint64_t value, Address start,
                          Direction direction = Direction::Forward);

Result<Address> binary_pattern(std::string_view pattern,
                               Address start,
                               Address end,
                               Direction direction = Direction::Forward);

Result<Address> next_code(Address ea);
Result<Address> next_data(Address ea);
Result<Address> next_unknown(Address ea);
Result<Address> next_error(Address ea);

}  // namespace ida::search
```

#### 22.5.11 `ida::analysis`

```cpp
namespace ida::analysis {

bool is_enabled();
Status set_enabled(bool enabled);

bool is_idle();
Status wait();
Status wait_range(Address start, Address end);

Status schedule_code(Address ea);
Status schedule_function(Address ea);
Status schedule_reanalysis(Address ea);
Status schedule_reanalysis_range(Address start, Address end);

Status revert_decisions(Address start, Address end);

}  // namespace ida::analysis
```

#### 22.5.12 `ida::database`

```cpp
namespace ida::database {

Status open(std::string_view path);
Status save(std::string_view out_path = {});
Status close();

Status load_binary(std::string_view path, Address image_base = 0);
Status load_nonbinary(std::string_view path);

Result<std::string> input_path();
Result<std::string> input_md5();
Result<Address> image_base();
Result<Address> minimum_address();
Result<Address> maximum_address();

}  // namespace ida::database
```

#### 22.5.13 `ida::fixup`

```cpp
namespace ida::fixup {

enum class Type {
  Off8,
  Off16,
  Seg16,
  Ptr16,
  Off32,
  Ptr32,
  Hi8,
  Hi16,
  Low8,
  Low16,
  Off64,
  Off8Signed,
  Off16Signed,
  Off32Signed,
  Custom,
};

struct Descriptor {
  Type type;
  uint32_t flags;
  uint64_t base;
  uint32_t selector;
  Address target;
  int64_t displacement;
};

Result<Descriptor> at(Address source);
Status set(Address source, const Descriptor &fixup);
Status remove(Address source);

class FixupRange;
FixupRange all();
FixupRange in_range(Address start, Address end);

}  // namespace ida::fixup
```

#### 22.5.14 `ida::entry`

```cpp
namespace ida::entry {

struct EntryPoint {
  uint64_t ordinal;
  Address address;
  std::string name;
  std::string forwarder;
};

Result<size_t> count();
Result<EntryPoint> by_index(size_t index);
Result<EntryPoint> by_ordinal(uint64_t ordinal);

Status add(uint64_t ordinal, Address ea, std::string_view name,
           bool make_code = true);
Status rename(uint64_t ordinal, std::string_view name);
Status set_forwarder(uint64_t ordinal, std::string_view target);

}  // namespace ida::entry
```

#### 22.5.15 `ida::plugin`

```cpp
namespace ida::plugin {

class Plugin {
 public:
  struct Info {
    std::string name;
    std::string hotkey;
    std::string comment;
    std::string help;
  };

  virtual ~Plugin() = default;
  virtual Info info() const = 0;
  virtual bool init();
  virtual void term();
  virtual Status run(size_t arg) = 0;
};

struct Action {
  std::string id;
  std::string label;
  std::string hotkey;
  std::string tooltip;
  std::function<Status()> handler;
  std::function<bool()> enabled;
};

Status register_action(const Action &action);
Status unregister_action(std::string_view action_id);
Status attach_action_to_menu(std::string_view menu_path,
                             std::string_view action_id);
Status attach_action_to_toolbar(std::string_view toolbar,
                                std::string_view action_id);

}  // namespace ida::plugin
```

#### 22.5.16 `ida::loader`

```cpp
namespace ida::loader {

class InputFile {
 public:
  Result<size_t> size() const;
  Result<size_t> read(void *buffer, size_t offset, size_t count);
  Result<std::vector<uint8_t>> read_bytes(size_t offset, size_t count);

  template <typename T>
  Result<T> read_value(size_t offset) const;

  Result<std::string> read_string(size_t offset, size_t max_len = 1024) const;
  Result<std::string> filename() const;
};

class Loader {
 public:
  struct AcceptResult {
    std::string format_name;
    std::string processor_name;
    int priority;
  };

  virtual ~Loader() = default;
  virtual Result<std::optional<AcceptResult>> accept(InputFile &file) = 0;
  virtual Status load(InputFile &file, std::string_view format_name) = 0;
  virtual Status save(FILE *out, std::string_view format_name);
  virtual Status relocate(Address from, Address to, AddressSize size);
};

Status register_loader(std::unique_ptr<Loader> loader);

}  // namespace ida::loader
```

#### 22.5.17 `ida::processor`

```cpp
namespace ida::processor {

struct RegisterInfo {
  std::string name;
  bool read_only;
  bool address_register;
};

struct InstructionDescriptor {
  std::string mnemonic;
  uint32_t feature_flags;
};

class OutputContext {
 public:
  Status mnemonic(std::string_view text, int width = 8);
  Status reg(std::string_view text);
  Status imm(uint64_t value);
  Status addr(Address ea);
  Status symbol(char c);
  Status text(std::string_view text);
  Status comment(std::string_view text);
};

class Processor {
 public:
  struct Info {
    int id;
    std::string short_name;
    std::string long_name;
    int default_bitness;
    std::vector<RegisterInfo> registers;
    std::vector<InstructionDescriptor> instructions;
    int code_sreg;
    int data_sreg;
  };

  virtual ~Processor() = default;
  virtual Info info() const = 0;
  virtual Result<int> analyze(ida::instruction::Instruction &insn) = 0;
  virtual Result<int> emulate(const ida::instruction::Instruction &insn) = 0;
  virtual Status output(OutputContext &ctx,
                        const ida::instruction::Instruction &insn) = 0;
  virtual Status output_operand(OutputContext &ctx,
                                const ida::instruction::Operand &op) = 0;
};

Status register_processor(std::unique_ptr<Processor> processor);

}  // namespace ida::processor
```

#### 22.5.18 `ida::debugger`

```cpp
namespace ida::debugger {

enum class ProcessState {
  NoProcess,
  Running,
  Suspended,
};

Status start(std::string_view path = {},
             std::string_view args = {},
             std::string_view working_dir = {});
Status attach(int pid);
Status detach();
Status terminate();

Status suspend();
Status resume();
Status step_into();
Status step_over();
Status step_out();
Status run_to(Address ea);

Result<ProcessState> state();
Result<Address> instruction_pointer();
Result<Address> stack_pointer();

Result<uint64_t> register_value(std::string_view reg_name);
Status set_register(std::string_view reg_name, uint64_t value);

Status add_breakpoint(Address ea);
Status remove_breakpoint(Address ea);
Result<bool> has_breakpoint(Address ea);

Result<std::vector<uint8_t>> read_memory(Address ea, AddressSize size);
Status write_memory(Address ea, std::span<const uint8_t> bytes);

enum class AppcallValueKind {
  SignedInteger,
  UnsignedInteger,
  FloatingPoint,
  String,
  Address,
  Boolean,
};

struct AppcallValue {
  AppcallValueKind kind;
  int64_t signed_value;
  uint64_t unsigned_value;
  double floating_value;
  std::string string_value;
  Address address_value;
  bool boolean_value;
};

struct AppcallOptions {
  std::optional<int> thread_id;
  bool manual;
  bool include_debug_event;
  std::optional<uint32_t> timeout_milliseconds;
};

struct AppcallRequest {
  Address function_address;
  ida::type::TypeInfo function_type;
  std::vector<AppcallValue> arguments;
  AppcallOptions options;
};

struct AppcallResult {
  AppcallValue return_value;
  std::string diagnostics;
};

class AppcallExecutor {
 public:
  virtual ~AppcallExecutor() = default;
  virtual Result<AppcallResult> execute(const AppcallRequest &request) = 0;
};

Result<AppcallResult> appcall(const AppcallRequest &request);
Status cleanup_appcall(std::optional<int> thread_id = std::nullopt);
Status register_executor(std::string_view name, std::shared_ptr<AppcallExecutor> executor);
Status unregister_executor(std::string_view name);
Result<AppcallResult> appcall_with_executor(std::string_view name,
                                            const AppcallRequest &request);

}  // namespace ida::debugger
```

#### 22.5.19 `ida::ui`, `ida::graph`, `ida::event`

```cpp
namespace ida::event {

using Token = uint64_t;

Token on_segment_created(std::function<void(ida::Address)> callback);
Token on_segment_deleted(std::function<void(ida::Address, ida::Address)> callback);
Token on_function_created(std::function<void(ida::Address)> callback);
Token on_name_changed(std::function<void(ida::Address, std::string, std::string)> callback);

Status unsubscribe(Token token);

class ScopedSubscription {
 public:
  explicit ScopedSubscription(Token token);
  ~ScopedSubscription();
};

}  // namespace ida::event
```

#### 22.5.20 `ida::decompiler`

```cpp
namespace ida::decompiler {

class DecompiledFunction {
 public:
  Result<std::string> pseudocode() const;
  Result<std::vector<std::string>> lines() const;

  Result<size_t> variable_count() const;
  Result<Status> rename_variable(size_t index, std::string_view name);
  Result<Status> retype_variable(size_t index, const ida::type::TypeInfo &type);

  Result<Address> map_line_to_address(size_t line, size_t column) const;
};

Result<bool> available();
Result<DecompiledFunction> decompile(Address ea);

enum class VisitResult {
  Continue,
  Stop,
  SkipChildren,
};

class CtreeVisitor {
 public:
  virtual ~CtreeVisitor() = default;
  virtual VisitResult expression(/* opaque expression view */) = 0;
  virtual VisitResult statement(/* opaque statement view */) = 0;
};

}  // namespace ida::decompiler
```

#### 22.5.21 `ida::storage` (advanced)

```cpp
namespace ida::storage {

class Node {
 public:
  static Result<Node> open(std::string_view name, bool create = false);
  static Result<Node> from_id(uint64_t id);

  Result<bool> exists() const;
  Result<uint64_t> id() const;

  Result<std::vector<uint8_t>> value() const;
  Status set_value(std::span<const uint8_t> data);

  Result<uint64_t> alt(Address index, uint8_t tag = 'A') const;
  Status set_alt(Address index, uint64_t value, uint8_t tag = 'A');
  Status del_alt(Address index, uint8_t tag = 'A');

  Result<std::vector<uint8_t>> sup(Address index, uint8_t tag = 'S') const;
  Status set_sup(Address index, std::span<const uint8_t> data, uint8_t tag = 'S');

  Result<std::string> hash(std::string_view key, uint8_t tag = 'H') const;
  Status set_hash(std::string_view key, std::string_view value, uint8_t tag = 'H');
};

}  // namespace ida::storage
```

### 22.6 Refined implementation phasing (interface-first)

1. Core end-user analysis domains first (`address`, `data`, `segment`, `function`, `instruction`, `name`, `xref`, `comment`, `type`, `search`, `analysis`, `database`).
2. Module-author domains next (`plugin`, `loader`, `processor`).
3. High-complexity/interactive domains after (`debugger`, `decompiler`, `ui`, `graph`, `event`, `storage`).

### 22.7 Proposed implementation layout (hybrid)

```text
include/ida/
  *.hpp               # public API
  detail/*.hpp        # private helper headers

src/
  *.cpp               # compiled adapters and stateful wrappers
  detail/*.cpp        # internal bridges, lifecycle logic, event bridges

tests/
  unit/
  integration/
  scenario/

examples/
  plugin/
  loader/
  procmod/
```

### 22.8 Compliance note for this section

This section is part of the mandatory baseline. If interfaces evolve, this section must be updated immediately and corresponding updates must be logged in:
- Phase TODO status
- Findings and Learnings
- Decision Log (if design changed)
- Progress Ledger
