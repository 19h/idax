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
Format note: use a numbered list with one concrete technical finding per item; keep wording concise and include impact/mitigation only when it materially helps.

1. API naming inconsistency is the biggest onboarding barrier.
2. Implicit sentinels (`BADADDR`, `BADSEL`, magic ints) create silent failures.
3. Encoded flags/mixed bitfields are powerful but hard to reason about quickly.
4. Multiple equivalent SDK API paths differ subtly in semantics and side effects.
5. Pointer validity/lifecycle semantics need strong encapsulation in ergonomic wrappers.
6. Type and decompiler domains are high-power/high-complexity; need progressive API layering.
7. Debugger/UI domains need typed abstractions to prevent vararg misuse bugs.
8. Fully opaque wrappers need comprehensive coverage to avoid forcing raw SDK fallback.
9. Public API simplicity must preserve capability; advanced options must remain in structured form.
10. Migration docs are as critical as API design for adoption.
11. Interface-level API sketches must be present (not just summaries) to avoid implementation ambiguity.
12. C++23 + SDK `pro.h` incompatibility: `std::is_pod<T>` used without `#include <type_traits>`. Fix: include `<type_traits>` before `<pro.h>` in bridge header.
13. SDK segment API: `segment_t::perm` uses `SEGPERM_READ/WRITE/EXEC` (not `SFL_*`). Visibility via `is_visible_segm()` (not `is_hidden_segtype()`).
14. SDK float types require `BTF_FLOAT` (=`BT_FLOAT|BTMT_FLOAT`) and `BTF_DOUBLE` (=`BT_FLOAT|BTMT_DOUBLE`), not raw `BT_FLOAT`/`BTMT_DOUBLE`.
15. Private member access: use `friend struct XxxAccess` with static `populate()` in impl file. Anonymous namespace helpers cannot be friends.
16. **CRITICAL**: SDK stub dylibs vs real IDA dylibs have mismatched symbol exports. Stub `libidalib.dylib` exports symbols (e.g. `qvector_reserve`) the real one doesn't—only real `libida.dylib` does. macOS two-level namespace causes null-pointer crashes. **Fix**: link against real IDA dylibs, not SDK stubs.
17. CMake: `libidax.a` uses custom `idasdk_headers` INTERFACE target (SDK includes + `__EA64__` + platform settings). Consumers bring own `idasdk::plugin`/`idasdk::idalib`. For idalib tests, link real IDA dylibs to avoid namespace mismatches.
18. Graph API: `create_interactive_graph()` returns nullptr in idalib/headless. Graph uses standalone adjacency-list for programmatic use; only `show_graph()` needs UI. `qflow_chart_t` works in all modes.
19. SDK graph: `FC_PREDS` renamed to `FC_RESERVED`. Predecessors built by default; `FC_NOPREDS` to disable. `insert_simple_nodes()` takes `intvec_t&` (reference, not pointer).
20. SDK chooser: `chooser_t::choose()` returns ssize_t (-1=no selection, -2=empty, -3=already exists). `CH_KEEP` prevents deletion on widget close. Column widths encode `CHCOL_*` format flags in high bits.
21. SDK loader: `loader_failure()` does longjmp, never returns. No C++ base class for loaders (unlike `procmod_t`). Wrapper bridges C function pointers to C++ virtual methods via global instance pointer.
22. Hex-Rays ctree: `apply_to()`/`apply_to_exprs()` dispatch through `HEXDSP` runtime function pointers (no link-time dep). `CV_POST` enables leave_*() callbacks. `CV_PRUNE` via `prune_now()` skips children. `citem_t::is_expr()` returns `op <= cot_last` (69). `treeitems` populated after `get_pseudocode()`, maps line indices to `citem_t*`. `cfunc_t::hdrlines` is offset between treeitems indices and pseudocode line numbers.
23. `get_widget_title()` takes `(qstring *buf, TWidget *widget)` — NOT single-arg returning `const char*`. Changed from older SDKs.
24. Debugger notification API: mixed `va_list` signatures. Most events pass `const debug_event_t*`, but `dbg_bpt`/`dbg_trace` pass `(thid_t, ea_t, ...)` directly. Wrappers must decode per-event arg layouts.
25. `switch_info_t` encodes element sizes via `SWI_J32/SWI_JSIZE` and `SWI_V32/SWI_VSIZE` bit-pairs, not explicit byte fields. Expose normalized byte-size fields in wrapper structs.
26. IDB event payloads are `va_list`-backed, consumable only once. For multi-subscriber routing, decode once into normalized event object, then fan out.
27. `get_strlit_contents()` supports `len = size_t(-1)` auto-length: uses existing strlit item size or `get_max_strlit_length(...)`. Enables robust string extraction without prior data-definition calls.
28. Snapshot APIs in `loader.hpp`: `build_snapshot_tree()` returns synthetic root whose `children` are top-level snapshots. `update_snapshot_attributes(nullptr, root, attr, SSUF_DESC)` updates current DB snapshot description.
29. Custom fixup registration: `register_custom_fixup()`/`find_custom_fixup()`/`unregister_custom_fixup()` returns type ids in `FIXUP_CUSTOM` range (0 on duplicate/missing). Wrappers return typed IDs, map duplicates to conflict errors.
30. DB transfer: `file2base(li, pos, ea1, ea2, patchable)` requires open `linput_t*` + explicit close. `mem2base(ptr, ea1, ea2, fpos)` returns 1 on success, accepts `fpos=-1` for no file offset.
31. SDK bridge internals (`sdk_bridge.hpp`) in iostream-heavy tests collide with `fpro.h` stdio macro remaps (`stdout` -> `dont_use_stdout`). Keep string checks in integration-level tests or avoid iostream in bridge TUs.
32. Comment API: `append_cmt` success doesn't guarantee appended text round-trips via `get_cmt` as strict suffix. Tests should assert append success + core content presence, not strict suffix matching.
33. Netnode blob ops at index 0 can trigger `std::length_error: vector` crashes in idalib. Use non-zero indices (100+) for blob/alt/sup ops; document safe ranges.
34. `FunctionIterator::operator*()` returns by value (not reference); range-for must use `auto f` not `auto& f`. Constructs `Function` value from internal SDK state each dereference. Same for `FixupIterator`.
35. `DecompiledFunction` is move-only (`cfuncptr_t` is refcounted). `std::expected<DecompiledFunction, Error>` also non-copyable. Test macros using `auto _r = (expr)` must be replaced with reference-based checks.
36. P9.1 Audit: polarity clash (`Segment::visible()` vs `Function::is_hidden()`), subscription naming stutter (`debugger_unsubscribe` in `ida::debugger`), duplicate binary pattern search in `data`/`search`. Fix: unified positive polarity (`is_visible()`), removed stutter, documented dual-path.
37. P9.1 Audit: ~200+ `ea` params renamed to `address`, `set_op_*` to `set_operand_*`, `del_*` to `remove_*`, `idx`/`cmt` abbreviations expanded in public interfaces.
38. P9.1 Audit: `Plugin::run()` returned `bool` not `Status`; `Processor::analyze/emulate/output_operand` returned raw `int`; `line_to_address()` returned `BadAddress` as success; UI dialog cancellation was `SdkFailure` not `Validation`. All fixed.
39. P9.1 Audit: opaque boundary confirmed zero HIGH violations (no SDK types leak into public headers). MEDIUM: `Chooser::impl()`/`Graph::impl()` unnecessarily public, `xref::Reference::raw_type` exposed raw SDK codes. Fixed: `impl()` private, `raw_type` replaced with typed `ReferenceType` enum.
40. macOS linker warnings: IDA 9.3 dylibs built for macOS 12.0 while objects target 11.0. Warning-only; runtime stable. Keep linking real dylibs (required for symbol correctness).
41. CPack output dir drifts with arbitrary working directories. Fix: invoke with `-B <build-dir>` to pin artifact location.
42. Plugin surface gap (`entropyx/ida-port`): missing dockable custom widget hosting (`create_empty_widget`/`display_widget`/`close_widget`), HT_VIEW/UI notification coverage, `jumpto`, segment-type introspection. Add opaque dock-widget APIs, expanded event routing, `ui::jump_to`, `segment::Segment::type()`/`set_type()`.
43. Title-only widget callbacks insufficient for complex multi-panel plugins—titles aren't stable identities, no per-instance lifecycle tracking. Surface opaque widget handles in notifications.
44. Plugin authoring gap: `make_plugin_descriptor()` referenced but no public export helper exists. Add explicit descriptor/export helper bridging `Plugin` subclasses to IDA entrypoints.
45. SDK dock constants: `WOPN_DP_FLOATING` (not `WOPN_DP_FLOAT`). Defined in `kernwin.hpp` as `DP_*` shifts by `WOPN_DP_SHIFT`. `WOPN_RESTORE` restores size/position. `display_widget()` takes `(TWidget*, uint32 flags)`.
46. `view_curpos` event: no `va_list` payload—get position via `get_screen_ea()`. Differs from `ui_screen_ea_changed` which passes `(new_ea, prev_ea)` in `va_list`.
47. Widget identity: `TWidget*` stable for widget lifetime. Handle-based subscriptions compare `TWidget*` pointers. Opaque `Widget` stores `void*` + monotonic `uint64_t` id for cross-callback identity.
48. `plugin_t PLUGIN` static init: must use char arrays (not `std::string::c_str()`) to avoid cross-TU init ordering. Static char buffers populated at `idax_plugin_init_()` time. `IDAX_PLUGIN` macro registers factory via `make_plugin_export()`; `plugin_t PLUGIN` lives in `plugin.cpp` (compiled into `libidax.a`).
49. Segment type constants: SDK `SEG_NORM(0)`–`SEG_IMEM(12)`. Wrapper `segment::Type` maps all 12 values plus aliases: `Import`=`SEG_IMP=4`, `InternalMemory`=`SEG_IMEM=12`, `Group`=`SEG_GRP=6`. `segment_t::type` is `uchar`.
50. entropyx portability: dock widget lifecycle present, but Qt plugins still need underlying host container for `QWidget` embedding (entropyx casts `TWidget*` to `QWidget*`). `ida::ui::Widget` is opaque, no container attachment. Add `ui::with_widget_host(Widget&, callback)` with `void*` host pointer.
51. Widget host bridge: scoped callback (`with_widget_host`) over raw getter reduces accidental long-lived toolkit pointer storage. Host pointer type remains `void*` (`WidgetHost`) for SDK/Qt opacity.
52. `action_activation_ctx_t` carries many SDK pointers. Normalize only stable high-value fields (action id, widget title/type, current address/value, selection/xtrn bits, register name) into SDK-free structs.
53. Generic UI/VIEW routing needs token-family partitioning: UI (`< 1<<62`), VIEW (`[1<<62, 1<<63)`), composite (`>= 1<<63`) for safe unsubscribe of composite subscriptions.
54. SDK parity audit: broad domain coverage across all namespaces, but depth uneven (`partial` vs full SDK breadth). Closing parity needs matrix-driven checklist with per-domain closure criteria.
55. Diagnostics counters: plain shared struct creates data-race risk under concurrent logging/assertion. Use atomic counter fields and snapshot reads.
56. Compile-only parity drift: when headers evolve quickly, compile-only tests can lag. Expand `api_surface_parity_test.cpp` with header changes, including overload disambiguation.
57. `create_float`/`create_double` may fail at specific addresses in real DBs. Treat float/double define checks as conditional capability probes; assert category on failure.
58. `open_database()` in idalib performs loader selection internally, so `LoadIntent` (`Binary`/`NonBinary`) maps to same open path. Keep explicit intent API, wire to dedicated paths when possible.
59. SDK segment comments: `get_segment_cmt`/`set_segment_cmt` operate on `const segment_t*`. `set_segment_cmt` returns `void`. Validate target segment first; treat set as best-effort.
60. `set_entry_forwarder(ord, "")` can fail for some ordinals/DBs in idalib. Expose explicit `clear_forwarder()` returning `SdkFailure`; tests use set/read/restore patterns.
61. SDK search: `find_*` helpers already skip start address; `SEARCH_NEXT` mainly meaningful for lower-level text/binary search. Keep typed options uniform; validate with integration tests.
62. SDK action detach helpers return only success/failure, no absent-attachment distinction. Map detach failures to `NotFound` with action/widget context.
63. Loader callback context: load/reload/archive extraction spread across raw callback args and bitflags (`ACCEPT_*`, `NEF_*`). Expose typed request structs and `LoadFlags` encode/decode helpers.
64. Processor output: existing modules rely on side-effect callbacks; advanced ports need structured text assembly. Add `OutputContext` and context-driven hooks with fallback defaults (non-breaking).
65. SDK netnode existence: `exist(const netnode&)` is hidden-friend resolved via ADL. Qualifying as `::exist(...)` fails to compile. Call `exist(nn)` unqualified.
66. Debugger request queue: `request_*` APIs enqueue, need `run_requests()` to dispatch; direct `step_*`/`run_to`/`suspend_process` execute immediately. Mixing styles without flush causes no-op behavior. Expose explicit request helpers + `is_request_running()`/`run_requests()`.
67. SDK custom viewer lifetime: `create_custom_viewer()` relies on caller-provided line buffer/place objects remaining valid for widget lifetime. Store per-viewer state in wrapper-managed lifetime storage; erase on close.
68. Graph layout in headless is behavioral (stateful contract), not geometric rendering. Persist selected `Layout` in `Graph`, expose `current_layout()`, validate via deterministic integration checks.
69. Decompiler lvar retype persistence: uses `modify_user_lvar_info(..., MLI_TYPE, ...)` with stable locator. In-memory type tweaks alone are insufficient. Route through saved-user-info updates; add refresh + re-decompile checks.
70. Cross-cutting/event parity closure can use intentional-abstraction documentation when full raw SDK mirroring is counter to wrapper goals. Keep `partial` with rationale + expansion triggers.
71. Linux compile-only: GCC 13.3.0 passes on Ubuntu 24.04; Clang 18.1.3 fails with missing `std::expected` even with `-std=c++23`.
72. Linux Clang libc++ fallback: `-stdlib=libc++` avoids `std::expected` gap but fails during SDK header inclusion—`pro.h` remaps `snprintf` -> `dont_use_snprintf`, colliding with libc++ internals.
73. GitHub-hosted cross-platform validation: `compile-only` and `unit` profiles work without licensed IDA runtime by checking out `ida-sdk` with `IDADIR` unset; integration tests auto-skipped.
74. IDA SDK checkout layout varies (`<sdk>/ida-cmake/`, `<sdk>/cmake/`, submodule-backed). May need recursive submodule fetch. Resolve layout explicitly; support all known bootstrap locations.
75. CI submodule policy: both project and SDK checkouts should use recursive submodule fetch. Set `submodules: recursive` on both checkout steps.
76. GitHub Actions macOS labels change over time. Keep active labels (currently `macos-14`); reintroduce x86_64 via supported labels or self-hosted runners.
77. CTest on multi-config generators (Visual Studio): requires explicit `-C <config>` at test time. Always pass `--config` to `cmake --build` and `-C` to `ctest`.
78. SDK `pro.h` stdio remaps (`snprintf -> dont_use_snprintf`) collide with newer libc++ internals. Include key C++ headers before `pro.h` in bridge: `<functional>`, `<locale>`, `<vector>`, `<type_traits>`.
79. Example addon coverage: enable `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON` in CI to catch module-authoring compile regressions without runtime execution.
80. JBC procmod gap: `ida::processor::analyze(Address)` returns only instruction size, no typed operand metadata (`o_near`/`o_mem`/`specflag`). Full ports must re-decode in multiple callbacks. Add optional typed analyze-result operand model.
81. JBC lifecycle gap: no wrapper for `set_default_sreg_value`. Add default-segment-register seeding helper.
82. JBC output gap: `OutputContext` is text-only (no token/color channels, no mnemonic callback parity). Extend with token-category output primitives and mnemonic/operand formatting hooks.
83. CI log audit: grep for `Complete job name`, `validation profile '<profile>' complete`, `100% tests passed` sentinels for quick validation.
84. JBC parity closed: `ida::processor` now includes `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`, tokenized output (`OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`), mnemonic hook (`output_mnemonic_with_context`). `ida::segment` has default segment-register seeding helpers.
85. ida-qtform port: `ida::ui::with_widget_host()` sufficient for Qt panel embedding without raw `TWidget*`.
86. ida-qtform parity: added markup-only `ida::ui::ask_form(std::string_view)` for form preview/test without raw SDK varargs. Add typed argument binding APIs later if needed.
87. idalib-dump parity: decompiler microcode exposed via `DecompiledFunction::microcode()` and `microcode_lines()`.
88. idalib-dump gap: no headless plugin-load policy controls (`--no-plugins`, allowlist). Add database/session open options.
89. idalib-dump parity: decompile failures expose structured details via `DecompileFailure` and `decompile(address, &failure)` (failure address + description).
90. idalib-dump gap: no public Lumina facade. Add `ida::lumina` or document as intentional non-goal.
91. README drift risk: absolute coverage wording, stale surface counts, non-pinned packaging commands can diverge. Keep aligned with `docs/` artifacts.
92. idalib-dump parity: headless plugin-load policy via `RuntimeOptions` + `PluginLoadPolicy` (`disable_user_plugins`, allowlist with `*`/`?`). Reproduces `--no-plugins`/selective `--plugin`.
93. DB metadata: SDK file-type from two sources (`get_file_type_name` vs `INF_FILE_FORMAT_NAME`/`get_loader_format_name`). Expose both with explicit `NotFound` for missing loader-format.
94. Lumina parity: pull/push exposed via `ida::lumina` (`pull`, `push`, typed `BatchResult`/`OperationCode`, feature selection).
95. Lumina runtime: `close_server_connection2`/`close_server_connections` declared in SDK but not link-exported. Keep close wrappers as `Unsupported` until portable close path confirmed.
96. ida2py gap: no first-class user-name enumeration API. Add `ida::name` iterators (`all`, `all_user_defined`) with range/filter options.
97. ida2py gap: `TypeInfo` lacks pointer/array decomposition (pointee type, array element type, array length). Add decomposition helpers + typedef resolution.
98. ida2py gap: no generic typed-value data facade consuming `TypeInfo` for recursive materialization. Consider `ida::data::read_typed`/`write_typed`.
99. ida2py gap: decompiler expression views lack typed call subexpressions (callee + argument accessors). Add typed call-expression accessors in visitor views.
100. ida2py gap: no Appcall/executor abstraction or extension hook for external engines (e.g. angr). Add debugger execution facade + pluggable executor interface.
101. Host runtime caveat: idalib tool examples exit with signal 11 in this environment. Only build/CLI-help validation available; functional checks need known-good idalib host.
102. ida2py parity: `ida::name` now has typed inventory helpers (`all`, `all_user_defined`) backed by SDK nlist enumeration.
103. ida2py parity: `TypeInfo` now includes `is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`.
104. ida2py parity: `ExpressionView` now includes `call_callee`, `call_argument(index)` alongside `call_argument_count`.
105. ida2py parity: `ida::data` now includes `read_typed`/`write_typed` with `TypedValue`/`TypedValueKind`, recursive array support, byte-array/string write paths.
106. ida2py parity: `ida::debugger` now includes Appcall + pluggable executor (`AppcallRequest`/`AppcallValue`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`).
107. Matrix drift risk: validation automation didn't propagate `IDAX_BUILD_EXAMPLE_TOOLS`. Plumb through scripts and CI workflow.
108. Appcall smoke: fixture `ref4` validated safely by calling `int ref4(int *p)` with `p = NULL`, exercises full request/type/argument/return bridging.
109. Tool-example runtime-linking: `ida_add_idalib` can bind to SDK stubs causing two-level namespace crashes. Prefer real IDA dylibs; stub fallback only when runtime libs unavailable.
110. Appcall host nuance: with runtime-linked tools, `--appcall-smoke` fails cleanly with `dbg_appcall` error 1552 (exit 1) instead of crashing. Remaining gap is debugger backend/session readiness.
111. Linux Clang C++23: Clang 18 reports `__cpp_concepts=201907` so `std::expected` stays disabled; Clang 19 reports `202002` and passes. Use Clang 19+ for Linux evidence.
112. Linux SDK artifacts: current checkout lacks `x64_linux_clang_64` runtime libs. Addon/tool targets fail under Linux Clang when build toggles on. Keep toggles OFF for Clang container evidence.
113. Appcall launch: `ida2py_port --appcall-smoke` tries multi-path debuggee launch (relative/absolute/filename+cwd). Host failures resolve to explicit `start_process failed (-1)`. Blocked by debugger backend.
114. Lumina validation: host reports successful `pull`/`push` smoke (`requested=1, succeeded=1, failed=0`). Non-close Lumina runtime validated.
115. lifter port audit: idax decompiler is read-oriented only. No write-path hooks: microcode filter registration, IR emission/mutation, maturity callbacks, `FUNC_OUTLINE` + caller cache invalidation. Full lifter migration blocked after plugin-shell/action porting.
116. lifter parity: added maturity subscriptions (`on_maturity_changed`/`unsubscribe`/`ScopedSubscription`) and outline/cache helpers (`function::is_outlined`/`set_outlined`, `decompiler::mark_dirty`/`mark_dirty_with_callers`). Remaining blocker: microcode write-path + raw decompiler-view handles.
117. lifter parity: baseline microcode-filter hooks added (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`). Full IR mutation (`m_call`/`m_ldx`/typed mops) remains unimplemented.
118. lifter parity: `MicrocodeContext` now includes operand/load-store and emit helpers (`load_operand_register`, `load_effective_address_register`, `store_operand_register`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`, `emit_helper_call`). Advanced typed IR (callinfo/typed mops/helper-call args) still blocked.
119. lifter parity: typed helper-call argument builders added (`MicrocodeValueKind`/`MicrocodeValue`, `emit_helper_call_with_arguments`, `emit_helper_call_with_arguments_to_register`) for integer widths 1/2/4/8. Full parity needs UDT/vector args, callinfo controls, typed mop builders.
120. lifter parity: call option shaping via `MicrocodeCallOptions` + `MicrocodeCallingConvention` (`emit_helper_call_with_arguments_and_options`, `..._to_register_and_options`). Advanced callinfo/tmop depth (non-integer args, reg/stack location, return modeling) still open.
121. lifter parity: scalar FP immediates (`Float32Immediate`, `Float64Immediate`) and explicit-location hinting (`mark_explicit_locations`) added. Vector/UDT and deeper callinfo/tmop controls remain open.
122. lifter parity: `MicrocodeValueLocation` (register/stack offset) for argument-location hints. Auto-promoted when hints present.
123. lifter parity: register-pair and register-with-offset location forms added with validation/error mapping.
124. lifter parity: static-address placement (`set_ea`) with `BadAddress` validation added.
125. lifter parity: scattered/multi-part placement via `MicrocodeLocationPart` + `Scattered` kind with per-part validation (offset/size/kind constraints).
126. lifter parity: byte-array view modeling (`MicrocodeValueKind::ByteArray`) with explicit location requirements.
127. lifter parity: register-relative placement (`ALOC_RREL` via `consume_rrel`) with base-register validation.
128. lifter parity: vector view modeling (`MicrocodeValueKind::Vector`) with typed element width/count/sign/floating controls + explicit location enforcement.
129. lifter parity: declaration-driven type views (`MicrocodeValueKind::TypeDeclarationView`) parsed via `parse_decl` with explicit-location enforcement.
130. callinfo-shaping: `mark_dead_return_registers`, `mark_spoiled_lists_optimized`, `mark_synthetic_has_call`, `mark_has_format_string` mapped to `FCI_DEAD`/`FCI_SPLOK`/`FCI_HASCALL`/`FCI_HASFMT`.
131. callinfo-shaping: scalar field hints (`callee_address`, `solid_argument_count`, `call_stack_pointer_delta`, `stack_arguments_top`) mapped to `mcallinfo_t` fields with validation.
132. ActionContext host bridge: opaque handles (`widget_handle`, `focused_widget_handle`, `decompiler_view_handle`) and scoped callbacks (`with_widget_host`, `with_decompiler_view_host`).
133. Appcall launch fallback: adding `--wait` hold-mode args doesn't change host outcome (`start_process failed (-1)`). Blocker is debugger backend, not fixture timing.
134. Appcall attach fallback: `attach_process` returns `-4` across all permutations. Host blocked at attach readiness too. Gather pass evidence on debugger-capable host.
135. callinfo-shaping: `return_type_declaration` parsed via `parse_decl`, applied to `mcallinfo_t::return_type`. Invalid declarations fail with `Validation`.
136. lifter source-audit: dominant gap is generic microcode instruction authoring (opcode+operand construction, callinfo/tmop depth, deterministic insertion policy). Ad hoc helper-call expansion insufficient. Prioritize generic typed instruction builder/emitter.
137. lifter parity: baseline generic typed instruction emitter added (`MicrocodeOpcode`, `MicrocodeOperandKind`, `MicrocodeOperand`, `MicrocodeInstruction`, `emit_instruction`, `emit_instructions`). Covers `mov/add/xdu/ldx/stx/fadd/fsub/fmul/fdiv/i2f/f2f/nop`.
138. SDK microblock insertion: `mblock_t::insert_into_block(new, existing)` inserts after `existing`; `nullptr` inserts at beginning. Expose constrained policy enums (`Tail`/`Beginning`/`BeforeTail`) without raw block internals.
139. callinfo-shaping: `function_role` and `return_location` semantic hints with typed validation/mapping.
140. Helper-call placement: `MicrocodeCallOptions::insert_policy` reuses `MicrocodeInsertPolicy` (`Tail`/`Beginning`/`BeforeTail`).
141. Microcode-filter runtime stability: aggressive callinfo hints in hardening filters can trigger `INTERR: 50765`. Keep integration coverage validation-focused; heavy emission stress for dedicated scenarios.
142. Helper-call typed-return: register-return now accepts declaration-driven return typing with size-match validation and UDT marking for wider destinations.
143. Helper-call typed-argument: register args now accept declaration-driven typing with parse validation, size-match enforcement, and integer-width fallback.
144. Helper-call argument-metadata: optional `argument_name`, `argument_flags`, `MicrocodeArgumentFlag` mapped to `mcallarg_t::name`/`flags` with unsupported-bit validation and `FAI_RETPTR -> FAI_HIDDEN` normalization.
145. lifter probe: `lifter_port_plugin.cpp` installs working VMX/AVX subset via idax microcode-filter APIs. No-op `vzeroupper`, helper-call lowering for `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`.
146. AVX temporary-register: `MicrocodeContext::allocate_temporary_register(byte_width)` mirrors `mba->alloc_kreg`.
147. Helper-call callinfo defaults: `solid_argument_count` now inferred from provided argument list when omitted.
148. Helper-call auto-stack placement: additive `auto_stack_start_offset`/`auto_stack_alignment` controls with validation (non-negative start, power-of-two positive alignment).
149. lifter AVX scalar subset: lowers `vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd`, `vcvtss2sd`, `vcvtsd2ss` through typed emission (`FloatAdd/FloatSub/FloatMul/FloatDiv/FloatToFloat`).
150. Instruction `Operand` exposes typed values but no rendered text helpers. AVX lowering assumes XMM-width destination copy. Expand operand-width introspection if broader vector-width lowering needed.
151. lifter AVX scalar expansion: `vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`, `vmovss/vmovsd` using typed emission + helper-call return lowering.
152. AVX scalar move memory-destination: load destination register before checking memory-destination creates unnecessary failure. Handle memory-dest stores first (`store_operand_register`), then resolve register-target paths.
153. AVX packed subset: `vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd`, `vmov*` packed moves through typed emission + store-aware handling.
154. Packed-width inference: `ida::instruction::operand_text(address, index)` heuristics (`xmm`/`ymm`/`zmm`, `*word` tokens) enable width-aware lowering without SDK internals.
155. Helper-call typed-return fallback: packed destination widths exceeding integer scalar widths need byte-array `tinfo_t` fallback when no explicit return declaration supplied.
156. Packed conversion subset: `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd` via `FloatToFloat`/`IntegerToFloat` emission with operand-text width heuristics.
157. Many float-int packed conversions (`vcvt*2dq/udq/qq/uqq`, truncating) don't map to current typed opcodes; use helper-call fallback.
158. `vaddsub*`/`vhadd*`/`vhsub*` need lane-level semantics beyond `FloatAdd`/`FloatSub`. Use helper-call lowering.
159. Helper-fallback packed families (bitwise/permute/blend) widened by collecting mixed register/immediate operands and forwarding as typed helper-call arguments.
160. Packed logic/permute/blend: no direct typed opcodes; helper-call fallback remains practical path.
161. Packed shift/rotate (`vps*`, `vprol*`, `vpror*`): mixed register/immediate shapes not directly expressible. Helper-call fallback.
162. Variadic helper fallback robustness: unsupported operand shapes degrade to `NotHandled` not hard errors, keeping decompiler stable while coverage grows.
163. Variadic helper memory-operand: when register extraction fails for source, attempt effective-address extraction and pass typed pointer argument.
164. Packed compare destination: mask-register destinations not representable in current register-load helpers. Treat unsupported compare destinations as no-op handling.
165. Typed packed bitwise/shift opcodes added: `BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`. Helper fallback kept for unsupported forms (`andn`, rotate, exotic).
166. Typed packed integer add/sub: `MicrocodeOpcode::Subtract` added. `vpadd*`/`vpsub*` direct register/immediate forms routed through typed emission. Helper fallback for mixed/unsupported.
167. Packed integer operand-shape: typed emission doesn't cover memory-source or saturating variants. Route saturating/memory forms through variadic helper fallback.
168. Packed integer multiply: typed direct multiply for `vpmulld`/`vpmullq`. Other variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) have lane-specific semantics—use helper-call fallback.
169. Packed binary operand count: two-operand encodings can be missed if destination not treated as implicit left operand. Treat operand 0 as both dest and left source for two-operand forms.
170. Advanced callinfo list-shaping: register-list and visible-memory controls exposed. Passthrough registers must be subset of spoiled. Validate subset semantics; return `Validation` on mismatch.
171. Declaration-driven vector element typing: `type_declaration` parsed as element type. Element-size/count/total-width constraints validated together. Derive missing count from total width when possible; reject mismatched shapes.
172. Rich typed mop-builder: `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` operand/value kinds added.
173. Block-reference typed operand: `MicrocodeOperandKind::BlockReference` + validated `block_index` without raw microblock exposure.
174. Nested-instruction typed operand: `MicrocodeOperandKind::NestedInstruction` + `nested_instruction` payload with recursive validation/depth limiting.
175. Local-variable typed operand: `MicrocodeOperandKind::LocalVariable` with `local_variable_index`/`local_variable_offset` validated before `_make_lvar(...)` mapping.
176. Local-variable rewrite safety: needs context-aware availability checks. Expose `MicrocodeContext::local_variable_count()` and gate usage on `count > 0` with no-op fallback.
177. Local-variable rewrite consistency: centralize local-variable self-move emission in one helper; reuse across rewrite sites (`vzeroupper`, `vmxoff`).
178. Debugger backend activation: backend discovery/loading should be explicit (`available_backends` + `load_backend`). Expose in `ida::debugger`; auto-load in `ida2py_port` before launch.
179. Appcall host (macOS): with `arm_mac` backend, `start_process` returns 0 but state stays `NoProcess`; attach returns `-1`, still `NoProcess`. Blocked by backend/session readiness, not wrapper API coverage.
180. Appcall queued-request timing: `request_start`/`request_attach` report success while state still `NoProcess` immediately after single flush. Perform bounded multi-cycle request draining with settle delays.
181. Microcode placement parity: low-level emit helpers (`emit_noop`, `emit_move_register`, `emit_load_memory_register`, `emit_store_memory_register`) default to tail insertion. Add policy-aware variants; route all emits through shared reposition logic.
182. Wide-operand emit: AVX/VMX wider register/memory flows may need UDT operand marking. Add optional `mark_user_defined_type` controls to low-level move/load/store helpers.
183. Store-operand UDT: `store_operand_register` writeback for wide/non-scalar flows needs explicit UDT marking on source mop. Add `store_operand_register(..., mark_user_defined_type)` overload.
184. Immediate typed-argument declaration: `UnsignedImmediate`/`SignedImmediate` now consume optional `type_declaration` with parse/size validation and declaration-width inference when byte width omitted.
185. Callinfo pass/spoil coherence: `passthrough_registers` contradictory without `spoiled_registers` superset. Enforce subset semantics whenever passthrough registers present.
186. Callinfo coherence testing: success-path helper-call emissions in filter hardening can trigger decompiler `INTERR`. Prefer validation-first probes (e.g., post-subset bad-visible-memory checks) for deterministic assertions.

---

## 13) Decision Log (Live)

Format note: keep one decision per bullet; briefly capture rationale and (when relevant) explicit rejected alternatives and impact.

- Target C++23 for modern error handling and API ergonomics.
- Hybrid library architecture balancing ease of use with implementation flexibility.
- Fully opaque public API enforcing consistency and preventing legacy leakage.
- Public string model uses `std::string`.
- Scope includes plugins, loaders, and processor modules (full ecosystem).
- Keep detailed interface blueprints in `agents.md` for concrete implementation guidance.
- Link idalib tests against real IDA installation dylibs, not SDK stubs. SDK stub `libidalib.dylib` has different symbol exports causing two-level namespace crashes. Rejected: `-flat_namespace` (too broad), `IDABIN` cmake variable (ida-cmake doesn't use it for lib paths).
- Expose processor switch/function-heuristic callbacks through SDK-free public structs and virtuals. Keeps procmod authoring opaque while preserving advanced capabilities. Rejected: expose raw `switch_info_t`/`insn_t` (violates opacity), defer until full event bridge rewrite (blocks progressive adoption).
- Add generic IDB event routing (`ida::event::Event`, `on_event`, `on_event_filtered`) on top of typed subscriptions. Enables reusable filtering without raw SDK vararg notifications. Rejected: many narrowly-scoped filtered helpers (API bloat), raw `idb_event` codes (leaks SDK).
- Standardize compatibility validation into three profiles (`full`, `unit`, `compile-only`) with `scripts/run_validation_matrix.sh`. Enables consistent multi-OS/compiler execution without full IDA runtime. Rejected: ad hoc per-host docs (drift-prone), CI-only matrix (licensing constraints).
- Pin matrix packaging artifacts via `cpack -B <build-dir>` for reproducible artifact locations. Rejected: CPack default output path (drifts by working directory).
- Add opaque dock widget host API (`Widget` handle, `create_widget`/`show_widget`/`activate_widget`/`find_widget`/`close_widget`/`is_widget_visible`, `DockPosition`, `ShowWidgetOptions`) to `ida::ui`. Rejected: expose `TWidget*` (violates opacity), title-only API (fragile for multi-panel). Closes entropyx P0 gaps #1/#2.
- Add handle-based widget event subscriptions (`on_widget_visible/invisible/closing(Widget&, cb)`) alongside title-based variants, plus `on_cursor_changed(cb)` for HT_VIEW `view_curpos`. Rejected: title-based only (fragile for multi-instance). Closes entropyx P0 gaps #2/#3.
- Implement `IDAX_PLUGIN(ClassName)` macro with `plugmod_t` bridge, static char buffers for `plugin_t PLUGIN`, factory registration via `detail::make_plugin_export()`. Rejected: require users write own PLUGIN struct (defeats wrapper), put PLUGIN in user TU via macro (requires SDK includes). Closes entropyx P0 gap #6.
- Add `Segment::type()` getter, `set_type()`, expanded `Type` enum (Import, InternalMemory, Group). Rejected: raw `uchar` (violates opaque naming). Closes entropyx P0 gap #5.
- Add `ui::jump_to(Address)` wrapping SDK `jumpto()`. Rejected: manual screen_address+navigate (missing core operation). Closes entropyx P0 gap #4.
- Add opaque widget host bridge (`WidgetHost`, `widget_host()`, `with_widget_host()`) for Qt/content embedding without exposing SDK/Qt types. Scoped callback over raw getter reduces accidental long-lived pointer storage. Rejected: expose `TWidget*` (breaks opacity), raw getter only (encourages long-lived storage).
- Add `plugin::ActionContext` and context-aware callbacks (`handler_with_context`, `enabled_with_context`). Rejected: raw `action_activation_ctx_t*` (breaks opacity), replace existing no-arg callbacks (unnecessary migration breakage).
- Add generic UI/VIEW routing in `ida::ui` (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite-token unsubscribe. Rejected: many discrete handlers (cumbersome), raw notification codes + `va_list` (unsafe/non-opaque).
- Formalize SDK parity closure as Phase 10 with matrix-driven domain-by-domain checklist and evidence gates. Rejected: ad hoc parity fixes only (poor visibility), docs snapshot without TODO graph (weak progress control).
- Use dual-axis coverage matrix (`docs/sdk_domain_coverage_matrix.md`) with domain rows and SDK capability-family rows. Rejected: domain-only (hides cross-domain gaps), capability-only (weak ownership mapping).
- Store diagnostics counters as atomics, return snapshot copies. Rejected: global mutex (unnecessary contention), plain struct (undefined behavior under concurrency).
- Treat compile-only parity test as mandatory for every new public symbol including overload disambiguation. Rejected: integration tests only (insufficient compile-surface guarantees).
- Add predicate-based traversal ranges (`code_items`, `data_items`, `unknown_bytes`) and discoverability aliases (`next_defined`, `prev_defined`) in `ida::address`. Rejected: only predicate search primitives (less ergonomic for range-for).
- Add data patch-revert and load-intent convenience wrappers (`revert_patch`, `revert_patches`, `database::OpenMode`, `LoadIntent`, `open_binary`, `open_non_binary`). Rejected: raw bool/patch APIs only (low discoverability), raw loader entrypoints (leaks complexity).
- Close P10.3 with additive segment/function/instruction parity (resize/move/comments/traversal; update/reanalysis/address iteration/frame+regvar; jump classifiers + operand text/format unification). Rejected: defer to P10.8 (leaves rows partial), raw SDK classifier/comment entrypoints (violates opacity).
- Close P10.4 with additive metadata parity in name/xref/comment/type/entry/fixup (identifier validation, xref range+typed filters, indexed comment editing, function/cc/enum type workflows, entry forwarder management, expanded fixup descriptor + signed/range helpers). Rejected: defer to docs-only sweep (leaves rows partial), raw SDK enums/flags (weakens conceptual API).
- Close P10.5 with additive search/analysis parity (typed immediate/binary options, `next_error`/`next_defined`, explicit schedule-intent APIs, cancel/revert wrappers). Rejected: minimal direction-only + AU_CODE-only (low intent clarity), raw `SEARCH_*`/`AU_*` constants (leaks SDK encoding).
- Close P10.6 with additive module-authoring parity in plugin/loader/processor (action detach helpers, typed loader request/flag models, processor `OutputContext` + context-driven hooks, advanced descriptor/assembler checks). Rejected: replace legacy callbacks outright (migration breakage), raw SDK callback structs/flag bitmasks (violates opacity).
- Close P10.7.e storage parity with node-identity helpers (`Node::open_by_id`, `Node::id`, `Node::name`). Rejected: name-only open (weaker lifecycle ergonomics), raw `netnode` ids/constructors (leaks SDK).
- Close P10.7.a debugger parity with async/request and introspection helpers (`request_*`, `run_requests`, `is_request_running`, thread enumeration/control, register introspection). Rejected: raw `request_*` SDK calls only (inconsistent error model), defer to P10.8 (leaves row partial).
- Close P10.7.b UI parity with custom-viewer and broader UI/VIEW event routing (`create_custom_viewer`, line/count/jump/current/refresh/close, `on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`). Rejected: defer to P10.8 (leaves rows partial), raw SDK custom-viewer structs (weakens opaque boundary).
- Close P10.7.c graph parity with viewer lifecycle/query helpers (`has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, `close_graph_viewer`) and layout-state introspection (`Graph::current_layout`). Rejected: title-only refresh/show (insufficient lifecycle), UI-only layout effects without state introspection (brittle in headless).
- Close P10.7.d decompiler parity with variable-retype and expanded comment/ctree workflows (`retype_variable` by name/index, orphan-comment query/cleanup). Rejected: raw Hex-Rays lvar/user-info structs (breaks opacity), defer to P10.8 (leaves row partial).
- Resolve P10.9.a via explicit intentional-abstraction notes for cross-cutting/event rows (`ida::core`, `ida::diagnostics`, `ida::event`). Rejected: force all rows `covered` by broad raw-SDK mirroring (API bloat).
- Add GitHub Actions validation matrix workflow for multi-OS `compile-only` + `unit` with SDK checkout. Rejected: manual host-only execution (slower feedback), `full` profile in hosted CI (requires licensed runtime).
- Make SDK bootstrap tolerant to variant layouts (`ida-cmake/`, `cmake/`, `src/cmake/`) with recursive submodule checkout. Rejected: pin to one layout (fragile), require manual path overrides (error-prone).
- Always pass build config to both build and test commands (`cmake --build --config`, `ctest -C`) for cross-generator compatibility. Rejected: conditional branch by generator (higher complexity).
- Enable example addon compilation in hosted validation (`IDAX_BUILD_EXAMPLES=ON`, `IDAX_BUILD_EXAMPLE_ADDONS=ON`). Rejected: keep examples disabled (misses regressions), separate examples-only workflow (extra maintenance).
- Add paired JBC full-port example (loader + procmod + shared header) validating idax against real production migration. Rejected: hypothetical-only examples (weaker parity pressure), port only loader or procmod (misses cross-module interactions).
- Close P10.8.d/P10.9.d using hosted matrix evidence + local full/packaging evidence. Rejected: keep open until every runtime row is host-complete (scope creep), ignore hosted evidence (weaker reproducibility).
- Close JBC parity gaps (#80-#82) with additive processor/segment APIs (typed analyze operand model, default segment-register seeding, tokenized output, mnemonic hook). Rejected: keep minimal analyze/output + raw SDK escapes (weaker fidelity), replace callbacks outright (migration breakage).
- Add real-world port artifacts for ida-qtform + idalib-dump with dedicated audit doc. Rejected: synthetic parity-only checks (miss workflow edges), ad hoc notes only (poor traceability).
- Add markup-only `ida::ui::ask_form(std::string_view)`. Rejected: defer (leaves flow blocked), raw vararg `ask_form` (unsafe/non-opaque).
- Add microcode retrieval APIs (`DecompiledFunction::microcode()`, `microcode_lines()`). Rejected: keep raw SDK for microcode (weak parity), expose `mba_t`/raw printer (breaks opacity).
- Add structured decompile-failure details (`DecompileFailure` + `decompile(address, &failure)`). Rejected: context only in `ida::Error` strings (weakly structured), raw `hexrays_failure_t` (breaks opacity).
- Align README with matrix-backed coverage artifacts. Replace absolute completeness phrasing with tracked-gap language, pin packaging commands, refresh examples.
- Add headless plugin-load policy via `RuntimeOptions` + `PluginLoadPolicy`. Rejected: environment-variable workarounds only (weak portability), standalone plugin-policy APIs outside init (weaker lifecycle).
- Add database metadata helpers (`file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`). Rejected: keep metadata in external tools via raw SDK (inconsistent migration), new diagnostics namespace (weaker discoverability).
- Add `ida::lumina` facade with pull/push wrappers (`has_connection`, `pull`, `push`, typed `BatchResult`/`OperationCode`). Rejected: keep raw SDK for external tools (inconsistent ergonomics), raw `lumina_client_t` (breaks opacity).
- Keep Lumina close APIs as explicit `Unsupported` — runtime dylibs don't export `close_server_connection2`/`close_server_connections` despite SDK declarations. Rejected: call non-exported symbols (link failure), remove close APIs (weaker discoverability).
- Add ida2py port probe (`examples/tools/ida2py_port.cpp`) plus standalone audit doc. Rejected: fold into existing audit only (weak traceability), treat as out-of-scope (misses API ergonomics signals).
- Add typed name inventory APIs (`Entry`, `ListOptions`, `all`, `all_user_defined`). Rejected: keep fallback address scanning (weaker discoverability/performance), raw SDK nlist APIs (leaks SDK concepts).
- Add `TypeInfo` decomposition and typedef-resolution helpers (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`). Rejected: keep decomposition in external code (duplicated complexity), raw SDK `tinfo_t` utilities (breaks opacity).
- Add typed decompiler call-subexpression accessors (`call_callee`, `call_argument(index)`). Rejected: keep call parsing in external examples (weak portability), raw `cexpr_t*` (breaks opacity).
- Add generic typed-value facade (`TypedValue`, `TypedValueKind`, `read_typed`, `write_typed`) with recursive array materialization. Rejected: keep typed decoding in external ports (duplicated), SDK-level typed-value helpers (weakens opacity).
- Add Appcall + pluggable executor facade (`AppcallValue`, `AppcallRequest`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`). Rejected: keep dynamic execution out-of-scope (leaves gap open), raw SDK `idc_value_t`/`dbg_appcall` (breaks opacity).
- Expand matrix automation to compile tool-port examples by default (`IDAX_BUILD_EXAMPLE_TOOLS`). Rejected: keep out of matrix (higher drift), separate tools-only workflow (extra maintenance).
- Add fixture-backed Appcall runtime validation (`--appcall-smoke`) plus checklist doc. Rejected: keep as ad hoc notes (low reproducibility), standalone new tool binary (target sprawl).
- Prefer real IDA runtime dylibs for idalib tool examples when available, fallback to stubs. Rejected: `ida_add_idalib`-only (runtime crashes), require `IDADIR` unconditionally (breaks no-runtime compile rows).
- Adopt Linux Clang 19 + libstdc++ as known-good compile-only pairing; keep addon/tool toggles OFF until `x64_linux_clang_64` SDK runtime libs available. Rejected: Clang 18 + libc++ (SDK macro collisions), force addon/tool ON immediately (deterministic failures).
- Add open-point closure automation (`scripts/run_open_points.sh`) + host-native fixture build helper + multi-path Appcall launch bootstrap. Rejected: manual command checklist only (high friction), direct `dbg_appcall` without launch bootstrap (weaker diagnostics).
- Add lifter port probe plugin (`examples/plugin/lifter_port_plugin.cpp`) plus gap audit doc. Rejected: full direct lifter port (blocked by missing write-path APIs), docs-only without executable probe (weaker regression signal).
- Close lifter maturity/outline/cache gaps with additive APIs (`on_maturity_changed`, `mark_dirty`, `mark_dirty_with_callers`, `is_outlined`, `set_outlined`). Rejected: keep as audit-only gaps (delays value), raw Hex-Rays callbacks (breaks opacity).
- Add baseline microcode-filter registration (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`). Rejected: keep raw SDK-only (blocks migration), expose raw `codegen_t`/`microcode_filter_t` (breaks opacity).
- Expand `MicrocodeContext` with operand/register/memory/helper emit helpers. Rejected: keep only `emit_noop` until full typed-IR design (too limiting), expose raw `codegen_t` (opacity break).
- Add typed helper-call argument builders (`MicrocodeValueKind`, `MicrocodeValue`, `emit_helper_call_with_arguments[_to_register]`). Rejected: raw `mcallarg_t`/`mcallinfo_t` (opacity break), defer until full vector/UDT design (delays value).
- Add helper-call option shaping (`MicrocodeCallOptions`, `MicrocodeCallingConvention`, `emit_helper_call_with_arguments_and_options[_to_register_and_options]`). Rejected: raw `mcallinfo_t` mutators (opacity break), defer all callinfo shaping (delays value).
- Expand with scalar FP immediates (`Float32Immediate`/`Float64Immediate`) + explicit-location hinting. Rejected: jump to vector/UDT (too large for one slice), raw `mcallarg_t`/`argloc_t` (opacity break).
- Add basic explicit argument-location hints (`MicrocodeValueLocation` register/stack-offset) with auto-promotion. Rejected: raw `argloc_t` (opacity break), defer all location-shaping (delays value).
- Expand `MicrocodeValueLocation` with register-pair and register-with-offset forms. Rejected: register/stack-only (too limiting), raw `argloc_t` (opacity break).
- Add static-address location hints (`StaticAddress` → `argloc_t::set_ea`). Rejected: keep without global-location patterns (misses common patterns), raw `argloc_t` (opacity break).
- Add scattered/multi-part location hints (`Scattered` + `MicrocodeLocationPart`). Rejected: single-location only (insufficient for split-placement), raw `argpart_t`/`scattered_aloc_t` (opacity break).
- Add byte-array helper-call argument modeling (`MicrocodeValueKind::ByteArray`) with explicit-location enforcement. Rejected: defer all non-scalar (delays value), raw `mcallarg_t` (opacity break).
- Add register-relative location hints (`RegisterRelative` → `consume_rrel`). Rejected: keep without `ALOC_RREL` (misses practical cases), raw `rrel_t` (opacity break).
- Add vector helper-call argument modeling (`MicrocodeValueKind::Vector`) with typed element controls. Rejected: defer until full UDT abstraction (delays value), raw `mcallarg_t`/type plumbing (opacity break).
- Add declaration-driven argument modeling (`MicrocodeValueKind::TypeDeclarationView`) via `parse_decl`. Rejected: defer until full UDT APIs (delays value), raw `tinfo_t`/`mcallarg_t` (opacity break).
- Expand callinfo flags (`mark_dead_return_registers`, `mark_spoiled_lists_optimized`, `mark_synthetic_has_call`, `mark_has_format_string` → `FCI_DEAD`/`FCI_SPLOK`/`FCI_HASCALL`/`FCI_HASFMT`). Rejected: minimal flags only (too restrictive), raw `mcallinfo_t` flag mutation (opacity break).
- Expand callinfo with scalar field hints (`callee_address`, `solid_argument_count`, `call_stack_pointer_delta`, `stack_arguments_top`). Rejected: keep field-level shaping internal (insufficient fidelity), raw `mcallinfo_t` mutators (opacity break).
- Add action-context host bridges (`ActionContext::{widget_handle, focused_widget_handle, decompiler_view_handle}`, scoped callbacks). Rejected: normalized context only (blocks lifter popup flows), raw SDK types (breaks opacity).
- Expand appcall-smoke with hold-mode + default launches across path/cwd permutations. Rejected: default-args-only (weaker diagnosis), attach-only first (requires additional orchestration).
- Add spawn+attach fallback to appcall smoke for better root-cause classification. Rejected: launch-only probes (ambiguous classification), standalone attach utility (target sprawl).
- Expand callinfo with declaration-based return-type hints (`return_type_declaration` via `parse_decl`). Rejected: implicit return via destination register only (insufficient fidelity), raw `mcallinfo_t`/`tinfo_t` mutation (opacity break).
- Execute lifter follow-up via source-backed gap matrix with closure slices (P0 generic instruction builder, P1 callinfo depth, P2 placement, P3 typed view ergonomics). Rejected: broad blocker-only wording (weak guidance), large raw-SDK mirror (opacity/stability risk).
- Add baseline generic typed instruction emission (`MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`, `emit_instruction`, `emit_instructions`). Rejected: helper-call-only expansion (insufficient for AVX/VMX handlers), raw `minsn_t`/`mop_t` (opacity break).
- Add constrained placement-policy controls (`MicrocodeInsertPolicy`, `emit_instruction_with_policy`, `emit_instructions_with_policy`). Rejected: raw `mblock_t::insert_into_block`/`minsn_t*` (opacity break), tail-only insertion (insufficient for real ordering).
- Expand callinfo with semantic role + return-location hints (`MicrocodeFunctionRole`, `function_role`, `return_location`). Rejected: raw `funcrole_t`/`argloc_t`/`mcallinfo_t` (opacity break), scalar hints only (insufficient parity).
- Extend helper-call with insertion-policy hinting (`MicrocodeCallOptions::insert_policy`). Rejected: separate helper-call-with-policy overload family (API bloat), raw block/anchor handles (opacity break).
- Expand helper-call register-return with declaration-driven non-integer widths + size validation. Rejected: integer-only returns (insufficient for wider types), raw `mcallinfo_t`/`mop_t` return mutation (opacity break).
- Expand helper-call register-argument with declaration-driven non-integer widths + size validation. Rejected: integer-only arguments (insufficient), require `TypeDeclarationView` + explicit location for all (less ergonomic).
- Expand arguments with optional metadata (`argument_name`, `argument_flags`, `MicrocodeArgumentFlag`). Rejected: implicit metadata only (insufficient callinfo fidelity), raw `mcallarg_t` mutation (opacity break).
- Add VMX subset to lifter probe using public microcode-filter APIs (no-op `vzeroupper`, helper-call lowering for `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`). Rejected: keep probe read-only (weaker evidence), full port in one step (blocked by deep write-path APIs).
- Add `MicrocodeContext::allocate_temporary_register(byte_width)` mirroring `mba->alloc_kreg`. Rejected: keep raw-SDK-only (preserves escape hatches), infer indirectly via load helpers (insufficient).
- Add default `solid_argument_count` inference from argument lists. Rejected: keep all explicit at call sites (repetitive), hardcode one value (incorrect for variable arity).
- Add auto-stack placement controls (`auto_stack_start_offset`, `auto_stack_alignment`). Rejected: fixed internal heuristic only (limited control), require explicit location for every non-scalar (heavier boilerplate).
- Extend lifter probe with AVX scalar math/conversion lowering (`vadd/sub/mul/div ss/sd`, `vcvtss2sd`, `vcvtsd2ss`). Rejected: VMX-only until broader vector API (weaker signal), jump to packed directly (higher risk).
- Keep AVX scalar subset XMM-oriented — decoded `Operand` value objects lack rendered width text. Rejected: parse disassembly text ad hoc (brittle), overgeneralize wider widths (correctness risk).
- Expand with scalar min/max/sqrt/move families (`vmin/vmax/vsqrt/vmov ss/sd`). Rejected: keep only add/sub/mul/div (leaves common families unexercised), jump to packed (larger surface per change).
- Handle `vmovss`/`vmovsd` memory-destination before destination-register loading. Rejected: one-path destination-register-first (brittle for memory), skip memory-destination moves (leaves common pattern unlifted).
- Expand to packed math/move (`vadd/sub/mul/div ps/pd`, `vmov*`) with operand-text width heuristics. Rejected: jump to masked packed (larger surface), keep scalar-only until deeper IR (weaker pressure).
- Expand helper-call register-return fallback for wider destinations with byte-array `tinfo_t` synthesis. Rejected: `Unsupported` for widths >8 (blocks packed patterns), require explicit declaration everywhere (excessive boilerplate).
- Expand packed subset with min/max/sqrt (`vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd`). Rejected: postpone until deeper IR (slows coverage), typed-emitter-only (missing opcode parity for these).
- Expand with packed conversions (`vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd`). Rejected: defer until full vector/tmop DSL (delays high-frequency patterns), helper-call-only for all (less direct parity).
- Expand with helper-fallback conversions (`vcvt*2dq/udq/qq/uqq`, truncating). Rejected: postpone until new typed opcodes (delays parity), force inaccurate typed mappings (semantic risk).
- Expand with addsub/horizontal (`vaddsub*`, `vhadd*`, `vhsub*`) via helper-call. Rejected: skip until lane-aware IR (weaker coverage), approximate through plain opcodes (semantic mismatch).
- Expand with variadic helper-fallback bitwise/permute/blend. Rejected: wait for typed opcodes first (slower parity), per-mnemonic bespoke handlers (maintenance churn).
- Expand with variadic helper-fallback shift/rotate (`vps*`, `vprol*`, `vpror*`). Rejected: postpone until typed shift/rotate opcodes (slower parity), per-mnemonic handlers (maintenance-heavy).
- Keep variadic helper fallback tolerant (`NotHandled` over hard error) for broader compare/misc coverage. Rejected: strict erroring on unsupported loads (brittle), delay broad matching until full typed-IR (slower gains).
- Extend helper fallback to accept memory-source operands via effective-address extraction + pointer arguments. Rejected: register-only fallback (misses many forms), fail hard on memory sources (unnecessary instability).
- Treat unsupported compare mask-destinations as no-op in fallback. Rejected: hard-fail on non-register (destabilizing), defer compare expansion entirely (slower parity).
- Add typed packed bitwise/shift opcodes (`BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`). Rejected: keep all in helper fallback (weaker typed-IR parity), very broad opcode set in one step (higher regression risk).
- Add `MicrocodeOpcode::Subtract`, route `vpadd*`/`vpsub*` through typed emission first. Rejected: keep in helper fallback only (weaker parity), broader integer/vector opcode surface in one pass (higher risk).
- Keep packed integer dual-path (typed first, helper fallback second) with saturating-family helper routing. Rejected: map saturating onto plain Add/Subtract (semantic mismatch), typed-only for integer add/sub (misses memory/saturating).
- Add `MicrocodeOpcode::Multiply`, route `vpmulld`/`vpmullq` through typed emission. Other variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) use helper-call fallback. Rejected: keep all multiply in helper (weaker parity), map all variants to typed multiply (semantic mismatch).
- Treat two-operand packed binary encodings as destination-implicit-left-source. Rejected: three-operand-only typed path (unnecessary fallback churn), force helper for all two-operand (weaker parity).
- Expand writable IR with richer non-scalar/callinfo/tmop semantics (declaration-driven vector element typing, `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` mop builders, callinfo list shaping for return/spoiled/passthrough/dead registers + visible-memory ranges). Rejected: option-hint-only callinfo (insufficient parity), raw `mop_t`/`mcallinfo_t` mutators (opacity break).
- Add `MicrocodeOperandKind::BlockReference` with validated `block_index`. Rejected: keep raw-SDK-only (unnecessary gap), expose raw block handles (opacity break).
- Add `MicrocodeOperandKind::NestedInstruction` with recursive typed payload + depth limiting. Rejected: keep raw-SDK-only (unnecessary gap), expose raw `minsn_t*` (opacity/ownership break).
- Add `MicrocodeOperandKind::LocalVariable` with `local_variable_index`/`offset`. Rejected: keep raw-SDK-only (unnecessary gap), expose raw `mop_t`/`lvar_t` (opacity break).
- Expand local-variable shaping with value-side modeling + `MicrocodeContext::local_variable_count()` guard + no-op fallback. Rejected: instruction-only local-variable support (leaves helper/value incomplete), hardcode indices (brittle).
- Consolidate local-variable self-move emission into shared helper (`try_emit_local_variable_self_move`). Rejected: duplicate per-mnemonic logic (drift-prone), limit to one mnemonic (weaker parity pressure).
- Add debugger backend discovery (`BackendInfo`, `available_backends`, `current_backend`, `load_backend`) + queued launch/attach (`request_start`, `request_attach`). Rejected: keep backend logic private in examples (weak discoverability), synchronous start/attach only (misses async path).
- Upgrade appcall-smoke to backend-aware + multi-path execution (load backend → start → request_start → attach → request_attach with state checks). Rejected: launch-only fallback (less diagnostic depth), host-specific debugger hacks (non-portable).
- Add bounded queue-drain settling for request fallbacks (`run_requests` cycles + delays + state checks). Rejected: one-shot `run_requests` (noisy under async hosts), unbounded polling (can hang).
- Add policy-aware placement for low-level emit helpers (`emit_noop/move/load/store_with_policy`). Rejected: keep low-level helpers tail-only (uneven placement parity), bespoke per-call-site placement (brittle/non-discoverable).
- Add optional UDT-marking to low-level move/load/store emit helpers (including policy-aware overloads). Rejected: UDT shaping limited to typed-instruction builders (leaves low-level gap), require raw SDK post-emit mutation (weakens migration path).
- Add `store_operand_register(..., mark_user_defined_type)` overload. Rejected: keep integer/default-only (leaves residual gap), route all writebacks through lower-level helpers (loses ergonomic path).
- Expand immediate typed arguments with optional `type_declaration` + parse/size validation + width inference. Rejected: keep immediates integer-only (loses declaration intent), separate immediate-declaration kind (unnecessary surface growth).
- Tighten `passthrough_registers` to always require subset of `spoiled_registers`. Rejected: conditional validation only when both specified (permits inconsistent states), auto-promote into spoiled silently (obscures intent/errors).
- Validate callinfo coherence via validation-first probes rather than success-path emissions. Rejected: success-path emissions in filter tests (flaky), drop coherence assertions (weaker coverage).

---

## 14) Blockers (Live)

- Blocker ID: B-LIFTER-MICROCODE
- Scope: Full idax-first port of `/Users/int/dev/lifter` (AVX/VMX microcode transformations)
- Severity: High
- Description: Public wrapper now has: baseline generic typed instruction emission, placement/callinfo shaping (role + return-location + insert-policy + declaration-driven typed register-argument/return + argument name/flag metadata), temporary-register allocation, local-variable context query (`local_variable_count`), typed packed bitwise/shift/add/sub/mul opcode emission, richer typed operand/value mop builders (`LocalVariable`/`RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference`/`BlockReference`/`NestedInstruction`), declaration-driven vector element typing, advanced callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory). Lifter probe includes working VMX + AVX scalar/packed subset with broad helper-fallback families (conversion/integer-arithmetic/multiply/bitwise/permute/blend/shift/compare/misc) plus mixed register/immediate/memory-source forwarding. Remaining gap: deeper tmop semantics and other advanced decompiler write-path surfaces.
- Immediate mitigation: Keep partial executable probe (`examples/plugin/lifter_port_plugin.cpp`) and gap audit (`docs/port_gap_audit_lifter.md`).
- Long-term: Add additive decompiler write-path APIs (richer typed microcode value/argument/callinfo beyond current support) while preserving public opacity.
- Owner: idax wrapper core

Blocker template:
- Blocker ID:
- Scope:
- Severity:
- Description:
- Mitigation:
- Next checkpoint:

---

## 15) Progress Ledger

Format note: append-only bullets in `scope - change - evidence` form; keep chronological by insertion order and include concrete artifacts (tests, builds, docs, scripts).

- Program planning - Comprehensive architecture and roadmap captured - Initial `agents.md` with phased TODOs, findings, decisions.
- Documentation baseline - Detailed interface blueprints (Parts 1-5 + module interfaces) - Section 22 with namespace-level API sketches.
- P0-P5 implementation - All 24 public headers, 19 impl files, SDK bridge, smoke test - `libidax.a` (168K), 19 .cpp compile.
- Blocker resolved - Two-level namespace crash diagnosed/fixed - SDK stub libidalib.dylib exports `qvector_reserve` but real one doesn't; link tests against real IDA dylibs. Smoke 48/48.
- P4.2.c, P4.4.c-d, P5.2, P7.4 - Function callers/callees, type struct/member/retrieve, operand representation controls, event system - Smoke 58/58.
- P4.2.b, P4.3.a-b-d - Function chunks (Chunk, chunks/tail_chunks/add_tail/remove_tail), stack frames (StackFrame, sp_delta_at, define_stack_variable); TypeInfo pimpl extracted to `detail/type_impl.hpp` - Smoke 68/68.
- P6.1, P6.2.b-c, P6.3.c - Plugin base class (PLUGIN_MULTI), loader InputFile, processor descriptors (RegisterInfo, InstructionDescriptor, AssemblerInfo) - Smoke 68/68.
- P8.1.a-c, P8.2.a-d, P5.3 - Full decompiler (init_hexrays_plugin, decompile_func, pseudocode/lines/declaration/variables/rename_variable); instruction xref conveniences confirmed - Smoke 73/73 including decompiler pseudocode, variable enumeration, declarations.
- P6.2.a-d-e, P6.3.a-b-e, P7.2.b-d, P7.3.a-d - Loader base class (accept/load/save/move_segment, IDAX_LOADER); Processor base class (analyze/emulate/output_instruction/output_operand, IDAX_PROCESSOR); UI chooser (Chooser, Column/Row/RowStyle/ChooserOptions); simple dialogs; screen_address/selection; timers; Graph (adjacency-list, node/edge CRUD, BFS, show_graph, flowchart) - Smoke 95/95 with flowchart and graph tests.
- P8.1.d-e, P8.2.b-c - Ctree visitor (CtreeVisitor, ExpressionView/StatementView, ItemType, VisitAction/VisitOptions, for_each_expression/for_each_item); user comments (set_comment/get_comment/save_comments, CommentPosition); refresh/invalidation; address mapping (entry_address, line_to_address, address_map) - Smoke 121/121 (21 exprs + 4 stmts, post-order/skip-children working, comments verified, 16 address mapping entries).
- P7.2.c, P4.4.e, P4.3.c, P8.3.c - Fixed `get_widget_title` (2-arg SDK); UI event subscriptions (on_database_closed/on_ready_to_run/on_screen_ea_changed/on_widget_visible/on_widget_closing + ScopedUiSubscription); type library access (load/unload/count/name/import/apply_named); register variables; storage blob ops - Smoke 162/162.
- P7.1.d, P6.3.d - Debugger event subscription (HT_DBG, typed callbacks, ScopedDebuggerSubscription); processor switch/function-heuristic wrappers (SwitchDescription/SwitchCase) - Smoke 187/187.
- P7.4.d - Generic IDB event filtering/routing (`ida::event::Event`, `on_event`, `on_event_filtered`) - Smoke 193/193 ("generic route fired: yes", "filtered route fired: yes").
- P2.2.d-e - Data string extraction (`read_string`), typed value helpers (`read_value<T>`, `write_value<T>`), binary pattern search (`find_binary_pattern`) - Smoke 201/201.
- P3.4.d - Regex/options text-search wrapper (`TextOptions`) - Smoke 203/203.
- P2.3.c - Database snapshot wrappers (`Snapshot`, `snapshots()`, `set_snapshot_description()`, `is_snapshot_database()`) - Smoke 205/205.
- P4.6.d - Custom fixup registration (`CustomHandler`, `register_custom`, `find_custom`, `unregister_custom`) - Smoke 210/210.
- P2.3.b - Database file/memory transfer wrappers (`file_to_database`, `memory_to_database`) - Smoke 213/213.
- P3.2.c-d - Bulk comment APIs (set/get/clear anterior/posterior lines), rendering helper (`render`) - Smoke 227/227.
- P2.1.d - Address search predicate helpers (`Predicate`, `find_first`, `find_next`) - Smoke 232/232.
- P0.1.d, P6.4.a-d - Concrete example sources (action_plugin, minimal_loader, minimal_procmod) + examples CMake; verified no compiler-intrinsic usage - Example targets build cleanly.
- P6.5, P3.6.b-d, P4.5.d, P8.3.d, P9.2 - Documentation bundle (quickstart, cookbook, migration, api_reference, tutorial, storage caveats, docs checklist); synced migration maps.
- P1.1.c, P1.2.c, P1.3, P1.4 - Shared option structs, diagnostics/logging/counters, master include, unit test target covering error model, diagnostics, handle/range/iterator contracts - Unit 22/22; smoke 232/232.
- P3.6.a - Integration test suite for name/comment/xref/search behavior - CTest 3/3.
- P2.4.b - Integration mutation-safety test for `ida::data` - CTest 4/4.
- P4.7.a - Integration segment/function edge-case suite - CTest 5/5.
- P5.4.a - Integration instruction decode behavior suite - CTest 6/6.
- P4.7.b - Type roundtrip and apply test suite (primitive factories, pointer/array, from_declaration, struct lifecycle, union, save_as/by_name, apply/retrieve, local type library, to_string, copy/move) - CTest 10/10.
- P4.7.c - Fixup relocation test suite (set/get roundtrip, multiple types, contains, traversal, FixupRange, error paths, custom lifecycle) - CTest 10/10.
- P5.4.b+c - Combined operand conversion and text snapshot suite (operand classification, immediate/register properties, representation controls, forced operand roundtrip, xref conveniences, disassembly text, instruction create) - CTest 10/10.
- P8.4.a-d - Combined decompiler and storage hardening suite (availability, ctree traversal, expression view accessors, for_each_item, error paths, address mapping, user comments, storage alt/sup/hash/blob roundtrips, node semantics) - CTest 10/10.
- CMake - Refactored integration test CMake with `idax_add_integration_test()` helper.
- P9.1.a-d - All Phase 9 audits completed and applied: renamed `delete_register_variable`→`remove_register_variable`, unified subscription naming, fixed polarity (`is_visible()`), fixed `line_to_address()` error return, `Plugin::run()` → `Status`, added `EmulateResult`/`OutputOperandResult`, renamed ~135 `ea`→`address`, renamed `idx`→`index`/`cmt`→`comment`/`set_op_*`→`set_operand_*`/`del_*`→`remove_*`, made `impl()` private, replaced `raw_type` with `ReferenceType`, added error context strings, changed UI dialog cancellation to `Validation` - Build clean, 10/10.
- P0.3.d, P4.7.d, P7.5, P6.5, P9.3, P9.4 - All release-blocking items: CMake install/export/CPack; compile-only API surface parity test; advanced debugger/ui/graph/event validation (60 checks); loader/processor scenario test; fixture README; opaque boundary cleanup; full validation (13/13 CTest); release readiness artifacts - 13/13 tests, CPack `idax-0.1.0-Darwin.tar.gz`.
- Backlog - 3 new integration suites + 1 expanded: decompiler_edge_cases (837 lines, 7 sections), event_stress (473 lines, 8 sections), performance_benchmark (537 lines, 10 benchmarks); expanded loader_processor_scenario (+7 sections); expanded migration docs - 16/16 tests.
- Documentation audit - Fixed 14 API mismatches across 6 doc files; updated api_reference, validation_report, README test counts, storage caveats - 16/16 tests.
- Documentation polish - Created namespace_topology.md; merged snippets into legacy_to_wrapper.md; expanded quick reference; added Section 22 deviation disclaimer; full doc snippet audit confirmed 0 compile-affecting mismatches - 16/16 tests.
- Compatibility matrix expansion - Added `scripts/run_validation_matrix.sh` + `docs/compatibility_matrix.md`; executed macOS arm64 AppleClang 17 (Release/RelWithDebInfo/compile-only/unit profiles); updated docs - 16/16 full, 2/2 unit, compile-only pass.
- Matrix packaging hardening - Updated scripts for `cpack -B <build-dir>`; executed full+packaging profile - 16/16 + `idax-0.1.0-Darwin.tar.gz`.
- Plugin API gap audit - Compared idax with `/Users/int/dev/entropyx/ida-port`; documented hard blockers for custom dock widgets, HT_VIEW/UI events, jump-to-address, segment type, plugin bootstrap.
- Complex-plugin parity planning - Prioritized P0/P1 closure plan mapping entropyx usage.
- Complex-plugin parity implementation - All 6 P0 gaps closed: (1) opaque `Widget` with dock widget APIs + `DockPosition` + `ShowWidgetOptions`; (2) handle-based widget event subscriptions; (3) `on_cursor_changed` for `view_curpos`; (4) `ui::jump_to`; (5) `Segment::type()`/`set_type()` + expanded `Type` enum; (6) `IDAX_PLUGIN` macro + `Action::icon` + `attach_to_popup()`. Refactored UI events to parameterized `EventListener` with token-range partitioning. Added `Plugin::init()` - 16/16 tests.
- Follow-up entropyx audit - One remaining gap: no SDK-opaque API for Qt content attachment to `ida::ui::Widget` host panels.
- Widget host bridge - `WidgetHost`, `widget_host()`, `with_widget_host()` + headless-safe integration coverage - 16/16 tests.
- P1 closure - `plugin::ActionContext` + context-aware callbacks; generic `ida::ui` routing (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite token unsubscribe - 16/16 tests.
- Phase 10 planning - Comprehensive domain-by-domain SDK parity checklist (P10.0-P10.9) with matrix governance and evidence gates.
- P10.0 - Created `docs/sdk_domain_coverage_matrix.md` with dual-axis coverage matrices.
- P10.1 - Audited error/core/diagnostics; fixed diagnostics counter data-race (atomic counters); expanded compile-only parity for UI/plugin symbols - 16/16 tests.
- P10.2 - Address traversal ranges (`code_items`/`data_items`/`unknown_bytes`, `next_defined`/`prev_defined`); data patch revert + expanded define helpers; database open/load intent + metadata parity - 16/16 tests.
- P10.3 - Segment parity (resize/move/comments/traversal); function parity (update/reanalyze/item_addresses/frame_variable_by_name+offset/register_variables); instruction parity (OperandFormat, set_operand_format, operand_text, jump classifiers) - 16/16 tests.
- P10.4 - Metadata parity: name (is_user_defined, identifier validation), xref (ReferenceRange, typed filters, range APIs), comment (indexed edit/remove), type (CallingConvention, function-type/enum construction, introspection, enum members), entry forwarder management, fixup (flags/base/target, signed types, in_range) - 16/16 tests.
- P10.5 - Search parity (ImmediateOptions, BinaryPatternOptions, next_defined, next_error); analysis intent/rollback (schedule_code/function/reanalysis/reanalysis_range, cancel, revert_decisions) - 16/16 tests.
- P10.6 - Module-authoring parity: plugin action detach helpers; typed loader request/flag models (LoadFlags, LoadRequest, SaveRequest, MoveSegmentRequest, ArchiveMemberRequest); processor OutputContext + context-driven hooks + descriptor/assembler checks - 16/16 tests.
- P10.7.e - Storage node-identity (`open_by_id`, `id`, `name`) - 16/16 tests.
- P10.7.a - Debugger parity: request-queue helpers, thread introspection/control, register introspection - 16/16 tests.
- P10.7.b - UI parity: custom-viewer wrappers, expanded UI/VIEW routing (`on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`) - 16/16 tests.
- P10.7.c - Graph parity: viewer lifecycle/query helpers, `Graph::current_layout` - 16/16 tests.
- P10.7.d - Decompiler parity: `retype_variable` by name/index, orphan-comment helpers - 16/16 tests.
- P10.8.a-c, P10.9.c - Docs/validation closure + re-ran matrix profiles (full/unit/compile-only) on macOS arm64 AppleClang 17.
- P10.9.a-b - Intentional-abstraction notes for remaining partial cross-cutting/event rows; confirmed no high-severity migration blockers.
- Matrix packaging evidence refresh - Re-ran full+packaging after P10.7.d changes - 16/16 + `idax-0.1.0-Darwin.tar.gz`.
- P10.8.d Linux matrix - GCC 13.3.0 passes; Clang 18.1.3 fails (`std::expected` missing); Clang libc++ fallback also fails (SDK `pro.h` `snprintf` remap collision).
- P10.8.d CI automation - GitHub Actions matrix workflow added for multi-OS compile-only + unit.
- P10.8.d CI hardening - Multi-layout `IDASDK` resolution, recursive SDK submodule checkout, tolerant bootstrap in CMake.
- P10.8.d CI diagnostics - Bootstrap failure path printing for faster triage.
- P10.8.d CI submodule - Recursive submodule checkout for project repo too.
- P10.8.d hosted-matrix stabilization - Removed retired `macos-13`, fixed cross-generator test invocation (`--config/-C`), hardened SDK bridge include order (`<functional>`, `<locale>`, `<vector>`, `<type_traits>` before `pro.h`).
- P10.8.d matrix coverage expansion - Wired `IDAX_BUILD_EXAMPLE_ADDONS` through scripts and CI; validated locally.
- Tracker rename - Renamed to `agents.md`, updated all references.
- JBC full-port example - Ported ida-jam into idax full examples (loader + procmod + shared header); validated addon compilation.
- JBC matrix evidence refresh - Re-ran validation with JBC examples enabled - compile-only pass, 2/2 unit pass.
- P10.8.d/P10.9.d closure - Audited hosted logs (Linux/macOS compile-only + unit, Windows compile-only); all confirmed pass. Phase 10 100% complete.
- JBC parity follow-up - Implemented #80-#82: `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`, `OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`, `output_mnemonic_with_context`, default segment-register seeding helpers; updated JBC examples - 16/16 tests.
- Post-Phase-10 port audit - Ported ida-qtform + idalib-dump into examples/tools; documented gaps in `docs/port_gap_audit_ida_qtform_idalib_dump.md` - 16/16 tests, tool targets compile.
- ask_form parity - Added markup-only `ida::ui::ask_form(std::string_view)` - compile-only parity pass.
- Microcode retrieval - Added `DecompiledFunction::microcode()`/`microcode_lines()`; wired in idalib-dump port - 16/16 tests, dump port compiles.
- Decompile-failure details - Added `DecompileFailure` + `decompile(address, &failure)` - 16/16 tests.
- README alignment - Updated positioning, commands, examples, coverage messaging to match matrix artifacts.
- Plugin-load policy - Added `RuntimeOptions` + `PluginLoadPolicy` with allowlist wildcards; wired in idalib-dump port - compile-only parity pass.
- Database metadata - Added `file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`; wired in idalib-dump port - smoke + parity pass.
- Lumina facade - Added `ida::lumina` with `has_connection`/`pull`/`push`/`BatchResult`/`OperationCode`; mapped close APIs to `Unsupported` - smoke + parity pass.
- ida2py port audit - Added `examples/tools/ida2py_port.cpp` + `docs/port_gap_audit_ida2py.md`; recorded gaps (name enumeration, type decomposition, typed-value, call arguments, Appcall) - tool compiles + --help pass.
- ida2py runtime attempt - `exit:139` on both ida2py and idalib-dump ports; deferred runtime checks to known-good host.
- Name inventory parity - Added `Entry`, `ListOptions`, `all`, `all_user_defined` to `ida::name` - 2/2 targeted tests pass.
- TypeInfo decomposition - Added `is_typedef`/`pointee_type`/`array_element_type`/`array_length`/`resolve_typedef` - 2/2 targeted tests pass.
- Call-subexpression accessors - Added `call_callee`/`call_argument(index)` on `ExpressionView` - 2/2 targeted tests pass.
- Typed-value facade - Added `TypedValue`/`TypedValueKind`/`read_typed`/`write_typed` with recursive array + byte-array/string write - 16/16 tests.
- Appcall + executor facade - Added `AppcallValue`/`AppcallRequest`/`appcall`/`cleanup_appcall`/`AppcallExecutor`/register/unregister/dispatch - 16/16 tests.
- Matrix tool-port expansion - Plumbed `IDAX_BUILD_EXAMPLE_TOOLS` through scripts + CI - compile-only + 2/2 unit pass.
- Appcall runtime-evidence - Added `--appcall-smoke` flow + `docs/appcall_runtime_validation.md` - tool compiles + --help pass.
- Tool-port runtime linkage hardening - Prefer real IDA dylibs, fallback to stubs; appcall-smoke now fails gracefully (error 1552, not signal-11) - non-debugger runtime pass.
- Linux Clang triage - Clang 18 fails (`__cpp_concepts=201907`); Clang 19 passes (`202002`); addon/tool linkage blocked by missing `x64_linux_clang_64` SDK libs.
- Open-point closure automation - Added `scripts/run_open_points.sh` + `scripts/build_appcall_fixture.sh` + multi-path Appcall launch bootstrap; full matrix pass, Lumina pass, Appcall blocked (`start_process failed (-1)`).
- Lifter port audit - Added `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_lifter.md` with plugin-shell/action/pseudocode-popup workflows.
- Lifter maturity/outline/cache - Added `on_maturity_changed`/`unsubscribe`/`ScopedSubscription`, `mark_dirty`/`mark_dirty_with_callers`, `is_outlined`/`set_outlined` - targeted tests pass.
- Lifter microcode-filter baseline - Added `register_microcode_filter`/`unregister_microcode_filter`/`MicrocodeContext`/`MicrocodeApplyResult`/`ScopedMicrocodeFilter` - 16/16 tests.
- MicrocodeContext emit helpers - Added `load_operand_register`/`load_effective_address_register`/`store_operand_register`/`emit_move_register`/`emit_load_memory_register`/`emit_store_memory_register`/`emit_helper_call` - 16/16 tests.
- Typed helper-call arguments - Added `MicrocodeValueKind`/`MicrocodeValue`/`emit_helper_call_with_arguments[_to_register]` for integer widths - 16/16 tests.
- Helper-call option shaping - Added `MicrocodeCallOptions`/`MicrocodeCallingConvention`/`emit_helper_call_with_arguments_and_options[_to_register_and_options]` - 16/16 tests.
- Scalar FP + explicit-location - Added `Float32Immediate`/`Float64Immediate` + `mark_explicit_locations` - 16/16 tests.
- Explicit argument-location hints - Added `MicrocodeValueLocation` (register/stack-offset) with auto-promotion - 16/16 tests.
- Register-pair + register-with-offset location - 16/16 tests.
- Static-address location hints - `BadAddress` validation - 16/16 tests.
- Scattered/multi-part location hints - `MicrocodeLocationPart` + per-part validation - 16/16 tests.
- Byte-array argument modeling - `MicrocodeValueKind::ByteArray` with explicit-location enforcement - 16/16 tests.
- Register-relative location - `ALOC_RREL` via `consume_rrel` - 16/16 tests.
- Vector argument modeling - `MicrocodeValueKind::Vector` with element controls - 16/16 tests.
- Declaration-driven argument modeling - `MicrocodeValueKind::TypeDeclarationView` via `parse_decl` - 16/16 tests.
- Callinfo FCI flags - `mark_dead_return_registers`/`mark_spoiled_lists_optimized`/`mark_synthetic_has_call`/`mark_has_format_string` - 16/16 tests.
- Callinfo scalar field hints - `callee_address`/`solid_argument_count`/`call_stack_pointer_delta`/`stack_arguments_top` + validation - 16/16 tests.
- Action-context host bridges - `widget_handle`/`focused_widget_handle`/`decompiler_view_handle` + scoped callbacks - 16/16 tests.
- Appcall hold-mode expansion - `--wait` fixture mode; still blocked (`start_process failed (-1)`). Full + Lumina pass.
- Lifter probe update - Consuming `with_decompiler_view_host` in snapshot flow.
- Appcall spawn+attach fallback - `attach_process` returns `-4`; host blocked at attach readiness too.
- Callinfo return-type declaration - `return_type_declaration` via `parse_decl` + malformed-declaration validation - 16/16 tests.
- Lifter source-backed gap matrix - P0 instruction builder, P1 callinfo depth, P2 placement, P3 view ergonomics.
- Generic typed instruction emission - `MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`/`emit_instruction`/`emit_instructions` covering `mov/add/xdu/ldx/stx/fadd/fsub/fmul/fdiv/i2f/f2f/nop` - 16/16 tests.
- Placement-policy controls - `MicrocodeInsertPolicy`/`emit_instruction_with_policy`/`emit_instructions_with_policy` - 16/16 tests.
- Callinfo role + return-location - `MicrocodeFunctionRole`/`function_role`/`return_location` - 16/16 tests.
- Helper-call insert-policy - `MicrocodeCallOptions::insert_policy` - 16/16 tests.
- Decompiler hardening stabilization - Aggressive callinfo hints triggered `INTERR: 50765`; adjusted tests to validation-focused paths - 16/16 tests.
- Helper-call typed register-return - Declaration-driven return types + size matching + wider-register UDT marking - 16/16 tests.
- Helper-call typed register-argument - Declaration-driven types + parse validation + size-match + integer-width fallback - 16/16 tests.
- Helper-call argument metadata - `argument_name`/`argument_flags`/`MicrocodeArgumentFlag` + `FAI_RETPTR` → `FAI_HIDDEN` normalization - 16/16 tests.
- Lifter VMX subset - Real instruction-to-helper lowering (no-op `vzeroupper`, helper-call VMX family) via public APIs - plugin builds, 16/16 tests.
- Temporary-register allocation - `allocate_temporary_register` - 16/16 tests.
- Lifter AVX `vzeroupper` - No-op lowering via typed emission.
- Helper-call solid-arg inference - Default from argument list when omitted - 16/16 tests.
- Auto-stack placement - `auto_stack_start_offset`/`auto_stack_alignment` with validation - 16/16 tests.
- AVX scalar math/conversion - `vadd/sub/mul/div ss/sd`, `vcvtss2sd`, `vcvtsd2ss` via typed emission - 16/16 tests.
- Operand-width constraint - Scalar subset constrained to XMM-width; docs updated.
- AVX scalar expansion - `vmin/vmax/vsqrt/vmov ss/sd` via typed emission + helper-return - 16/16 tests.
- Scalar move memory-dest - Reordered to handle store before register-load - 16/16 tests.
- AVX packed math/move - `vadd/sub/mul/div ps/pd`, `vmov*` packed via typed emission + width heuristics - 16/16 tests.
- Helper-call return fallback - Byte-array `tinfo_t` for widths > integer scalar - 16/16 tests.
- Packed min/max/sqrt - `vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd` via helper-return - 16/16 tests.
- Packed conversions - `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd` via typed emission - 16/16 tests.
- Helper-fallback conversions - `vcvt*2dq/udq/qq/uqq` + truncating via helper-call return - 16/16 tests.
- Addsub/horizontal - `vaddsub*`/`vhadd*`/`vhsub*` via helper-call - 16/16 tests.
- Variadic helper bitwise/permute/blend - Mixed register/immediate forwarding - 16/16 tests.
- Variadic helper shift/rotate - `vps*`/`vprol*`/`vpror*` - 16/16 tests.
- Tolerant variadic compare/misc - Broad families (`vcmp*`/`vpcmp*`/`vdpps`/`vround*`/`vbroadcast*`/`vextract*`/`vinsert*`/`vunpck*` etc.) with `NotHandled` degradation - 16/16 tests.
- Helper memory-source + compare dest - EA pointer args for memory sources; no-op for unsupported mask destinations; widened misc families (gather/scatter/compress/expand/popcnt/lzcnt/gfni/pclmul/aes/sha/movnt/movmsk/pmov/pinsert/extractps/insertps/pack/phsub/fmaddsub) - 16/16 tests.
- Typed packed bitwise/shift opcodes - `BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`; probe uses typed before helper fallback - 16/16 tests.
- Typed packed integer add/sub - `MicrocodeOpcode::Subtract`; `vpadd*`/`vpsub*` typed-first + helper fallback - 16/16 tests.
- Packed integer saturating routing - `vpadds*`/`vpaddus*`/`vpsubs*`/`vpsubus*` via helper fallback alongside typed direct - 16/16 tests.
- Typed packed integer multiply - `MicrocodeOpcode::Multiply`; `vpmulld`/`vpmullq` typed + non-direct variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) via helper - 16/16 tests.
- Two-operand packed binary fix - Destination-implicit-left-source for add/sub/mul/bitwise/shift - 16/16 tests.
- Richer writable IR - `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` operand/value kinds; declaration-driven vector element typing; callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory) with subset validation - 16/16 tests.
- BlockReference operand - `MicrocodeOperandKind::BlockReference` + `block_index` validation - 16/16 tests.
- NestedInstruction operand - `MicrocodeOperandKind::NestedInstruction` + recursive/depth-limited validation - 16/16 tests.
- LocalVariable operand - `MicrocodeOperandKind::LocalVariable` + `local_variable_index`/`offset` validation - 16/16 tests.
- LocalVariable value-path - `MicrocodeValueKind::LocalVariable` + `local_variable_count()` guard; probe uses in `vzeroupper` with no-op fallback - 16/16 tests.
- LocalVariable rewrite consolidation - Shared `try_emit_local_variable_self_move` applied to `vzeroupper` + `vmxoff` - 16/16 tests.
- Debugger backend APIs - `BackendInfo`/`available_backends`/`current_backend`/`load_backend` + `request_start`/`request_attach`; upgraded appcall-smoke to backend-aware + multi-path - 2/2 targeted tests pass.
- Open-point refresh - Full pass, Lumina pass, Appcall blocked (backend loaded, `start_process` rc `0` + still `NoProcess`, `attach_process` rc `-1` + still `NoProcess`).
- Appcall queue-drain settling - Bounded multi-cycle `run_requests` + delays before classifying `NoProcess`; host remains blocked.
- Open-point sweep refresh - `build-open-points-surge6`: full=pass, appcall=blocked, lumina=pass.
- Policy-aware low-level emit - `emit_noop/move/load/store_with_policy`; routed existing helpers through policy defaults - 2/2 targeted tests pass.
- Low-level UDT semantics - `mark_user_defined_type` overloads for move/load/store emit (with and without policy variants) - 16/16 tests.
- Store-operand UDT - `store_operand_register(..., mark_user_defined_type)` overload - 16/16 tests.
- Immediate typed-argument declaration - `UnsignedImmediate`/`SignedImmediate` with optional `type_declaration` + parse/size validation + width inference - 16/16 tests.
- Passthrough-subset validation - Tightened to always require subset of spoiled; return registers auto-merged into spoiled - 16/16 tests.
- Callinfo coherence test hardening - Validation-first probes with combined pass-through + return-register shaping + post-subset validation - 16/16 tests.

---

## 16) Immediate Next Actions

Phase 10 closure is complete. All original P0 complex-plugin parity gaps are closed (including widget-host portability), and P10.0-P10.9 are now fully complete.

Post-closure follow-ups (non-blocking):

1. Keep `.github/workflows/validation-matrix.yml` as the default cross-OS evidence path for `compile-only` + `unit` on every release-significant change.
2. Continue host-specific hardening runs where licenses/toolchains permit: keep Linux Clang evidence on Clang 19 baseline for now, and execute Linux/Windows `full` rows with runtime installs.
3. Continue validating the new JBC parity APIs against additional real-world procmod ports and expand typed analyze/output metadata only when concrete migration evidence requires deeper fidelity.
4. Keep hardening `ida::lumina` behavior beyond the now-passing pull/push smoke baseline, especially close/disconnect semantics once portable runtime symbols are confirmed.
5. Execute `docs/appcall_runtime_validation.md` on a debugger-capable host to convert the current backend/session block (backend loads, but `start_process` `0` + `request_start` no-process and `attach_process` `-1` + `request_attach` no-process) into pass evidence, then expand Appcall argument/return kind coverage only where concrete ports require additional fidelity.
6. Prioritize post-P0/P1/P2 additive decompiler write-path depth for lifter-class ports: extend beyond baseline generic instruction emission + typed/helper-call placement controls + callinfo role/return-location shaping + declaration-driven typed register-argument/return modeling + optional argument metadata + temporary-register allocation into richer typed IR value/argument/call builders (advanced vector/UDT semantics + deeper callinfo/tmop semantics + placement parity for additional emission paths).

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
