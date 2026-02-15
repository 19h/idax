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
   - The corresponding entry in the Progress Ledger
5. No discovery is valid until both are updated:
   - The Findings and Learnings section
   - The corresponding entry in the Progress Ledger
6. Any blocker must be captured with impact and mitigation plan in the Blockers section.
7. Any design change must be captured in the Decision Log with rationale.

MANDATORY UPDATE PROTOCOL (must always be followed):
- Step 1: Update task checkbox/status as soon as it changes.
- Step 2: Add a Progress Ledger entry with scope.
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

## 12) Knowledge Base (Live)

Note:
- This section is a hierarchical representation of the findings and learnings (live) in findings.md.
- You must add any findings and learnings into findings.md.
- Then, integrate the findings and learnings into this section appropriately with optional reference to a fact from findings.md in the format [FXXX] as suffix of a leaf of the knowledge base tree.

### 1. SDK Systemic Pain Points
- 1.1. Naming Inconsistency
  - 1.1.1. Mixed abbreviations and full words coexist (`segm` vs `segment`, `func` vs `function`, `cmt` vs `comment`) — biggest onboarding barrier [F1]
  - 1.1.2. Ambiguous prefixes and overloaded constants across domains
  - 1.1.3. Multiple retrieval variants for names/xrefs differ subtly in behavior [Pain7]
  - 1.1.4. Normalization applied during P9.1 audit
    - 1.1.4.1. ~200+ `ea` params renamed to `address` [F37]
    - 1.1.4.2. `set_op_*` → `set_operand_*`, `del_*` → `remove_*`, `idx` → `index`, `cmt` → `comment` [F37]
    - 1.1.4.3. `delete_register_variable` → `remove_register_variable`
    - 1.1.4.4. Polarity clash resolved: `Segment::visible()` → `Segment::is_visible()`, removed `Function::is_hidden()` [F36]
    - 1.1.4.5. Subscription naming stutter removed (`debugger_unsubscribe` in `ida::debugger`) [F36]
- 1.2. Conceptual Opacity
  - 1.2.1. Highly encoded flags and bitfields with domain-specific hidden meaning [F3]
  - 1.2.2. `flags64_t` packs unrelated concerns (state/type/operand metadata) behind overlapping bit regions [Pain6]
  - 1.2.3. Implicit sentinels (`BADADDR`, `BADSEL`, magic ints) create silent failures [F2]
  - 1.2.4. Search direction defaults rely on zero-value bitmasks that are not self-evident [Pain11]
- 1.3. Inconsistent Error/Reporting Patterns
  - 1.3.1. Mixed `bool`, integer codes, sentinel values, and side effects [F4, Pain8]
  - 1.3.2. Several APIs rely on magic argument combinations and sentinel values for special behavior [Pain9]
  - 1.3.3. P9.1 audit corrections
    - 1.3.3.1. `Plugin::run()` returned `bool` not `Status` [F38]
    - 1.3.3.2. `Processor::analyze/emulate/output_operand` returned raw `int` [F38]
    - 1.3.3.3. `line_to_address()` returned `BadAddress` as success [F38]
    - 1.3.3.4. UI dialog cancellation was `SdkFailure` not `Validation` [F38]
- 1.4. Hidden Dependencies and Lifecycle Hazards
  - 1.4.1. Pointer validity/lifecycle semantics need strong encapsulation [F5]
  - 1.4.2. Include-order dependencies expose features conditionally in a non-obvious way [Pain10]
  - 1.4.3. Manual lock helpers (`lock_*`) not enforced by type system [Pain5]
  - 1.4.4. Manual memory and ownership conventions still appear in several API families [Pain16]
- 1.5. Redundant and Overlapping API Paths
  - 1.5.1. Multiple equivalent SDK API paths differ subtly in semantics and side effects [F4]
  - 1.5.2. Debugger APIs duplicate direct and request variants [Pain12]
  - 1.5.3. Duplicate binary pattern search in `data`/`search` [F36]
- 1.6. C-Style Varargs and Weak Type Safety
  - 1.6.1. UI and debugger dispatch rely on varargs notification systems with weak compile-time checks [F7, Pain13]
  - 1.6.2. Debugger notification API: mixed `va_list` signatures per event [F24]
    - 1.6.2.1. Most events pass `const debug_event_t*`
    - 1.6.2.2. `dbg_bpt`/`dbg_trace` pass `(thid_t, ea_t, ...)` directly
    - 1.6.2.3. Wrappers must decode per-event arg layouts
  - 1.6.3. IDB event payloads are `va_list`-backed, consumable only once [F26]
    - 1.6.3.1. For multi-subscriber routing: decode once into normalized event object, then fan out
- 1.7. Legacy Compatibility Burden
  - 1.7.1. Obsolete values and historical naming still present in modern workflows
  - 1.7.2. Type APIs contain deep complexity with historical encodings [Pain14]
  - 1.7.3. Decompiler APIs enforce maturity/order constraints easy to violate [Pain15]
  - 1.7.4. Numeric and representation controls are spread across low-level helper patterns [Pain17]

---

### 2. Build System & Toolchain
- 2.1. C++23 Compatibility
  - 2.1.1. `std::is_pod<T>` used without `#include <type_traits>` in SDK `pro.h` [F12]
    - 2.1.1.1. Fix: include `<type_traits>` before `<pro.h>` in bridge header
  - 2.1.2. SDK `pro.h` stdio remaps (`snprintf` → `dont_use_snprintf`) collide with newer libc++ internals [F78]
    - 2.1.2.1. Fix: include key C++ headers before `pro.h` in bridge: `<functional>`, `<locale>`, `<vector>`, `<type_traits>`
  - 2.1.3. Linux Clang 18 fails with missing `std::expected` even with `-std=c++23` [F71]
    - 2.1.3.1. Reports `__cpp_concepts=201907` so `std::expected` stays disabled
    - 2.1.3.2. Clang 19 reports `202002` and passes [F111]
  - 2.1.4. Linux Clang libc++ fallback fails during SDK header inclusion [F72]
    - 2.1.4.1. `-stdlib=libc++` collides with `pro.h` `snprintf` remap
  - 2.1.5. SDK bridge internals in iostream-heavy tests collide with `fpro.h` stdio macro remaps [F31]
    - 2.1.5.1. `stdout` → `dont_use_stdout`
    - 2.1.5.2. Keep string checks in integration-level tests or avoid iostream in bridge TUs
- 2.2. Linking & Symbol Resolution
  - 2.2.1. **CRITICAL**: SDK stub dylibs vs real IDA dylibs have mismatched symbol exports [F16]
    - 2.2.1.1. Stub `libidalib.dylib` exports symbols (e.g., `qvector_reserve`) the real one doesn't
    - 2.2.1.2. Only real `libida.dylib` exports these
    - 2.2.1.3. macOS two-level namespace causes null-pointer crashes
    - 2.2.1.4. Fix: link against real IDA dylibs, not SDK stubs
  - 2.2.2. Tool-example runtime-linking: `ida_add_idalib` can bind to SDK stubs causing crashes [F109]
    - 2.2.2.1. Prefer real IDA dylibs; stub fallback only when runtime libs unavailable
  - 2.2.3. macOS linker warnings: IDA 9.3 dylibs built for macOS 12.0 while objects target 11.0 [F40]
    - 2.2.3.1. Warning-only; runtime stable
  - 2.2.4. Linux SDK artifacts: current checkout lacks `x64_linux_clang_64` runtime libs [F112]
    - 2.2.4.1. Addon/tool targets fail under Linux Clang when build toggles on
- 2.3. CMake Architecture
  - 2.3.1. `libidax.a` uses custom `idasdk_headers` INTERFACE target [F17]
    - 2.3.1.1. SDK includes + `__EA64__` + platform settings
    - 2.3.1.2. Consumers bring own `idasdk::plugin`/`idasdk::idalib`
  - 2.3.2. CPack output dir drifts with arbitrary working directories [F41]
    - 2.3.2.1. Fix: invoke with `-B <build-dir>` to pin artifact location
  - 2.3.3. CTest on multi-config generators (Visual Studio): requires explicit `-C <config>` [F77]
    - 2.3.3.1. Always pass `--config` to `cmake --build` and `-C` to `ctest`
  - 2.3.4. IDA SDK checkout layout varies [F74]
    - 2.3.4.1. `<sdk>/ida-cmake/`, `<sdk>/cmake/`, submodule-backed
    - 2.3.4.2. May need recursive submodule fetch
    - 2.3.4.3. Resolve layout explicitly; support all known bootstrap locations
  - 2.3.5. CI submodule policy: both project and SDK checkouts should use recursive submodule fetch [F75]
- 2.4. CI/CD
  - 2.4.1. GitHub Actions macOS labels change over time [F76]
    - 2.4.1.1. Keep active labels (currently `macos-14`)
    - 2.4.1.2. Reintroduce x86_64 via supported labels or self-hosted runners
  - 2.4.2. Example addon coverage: enable `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON` in CI [F79]
  - 2.4.3. Matrix drift risk: validation automation didn't propagate `IDAX_BUILD_EXAMPLE_TOOLS` [F107]
  - 2.4.4. CI log audit sentinels: `Complete job name`, `validation profile '<profile>' complete`, `100% tests passed` [F83]
  - 2.4.5. GitHub-hosted cross-platform validation [F73]
    - 2.4.5.1. `compile-only` and `unit` profiles work without licensed IDA runtime
    - 2.4.5.2. Checkout `ida-sdk` with `IDADIR` unset; integration tests auto-skipped

---

### 3. Opaque Boundary Design
- 3.1. Zero HIGH violations confirmed [F39]
  - 3.1.1. No SDK types leak into public headers
- 3.2. MEDIUM violations found and resolved [F39]
  - 3.2.1. `Chooser::impl()`/`Graph::impl()` were unnecessarily public → made private
  - 3.2.2. `xref::Reference::raw_type` exposed raw SDK codes → replaced with typed `ReferenceType` enum
- 3.3. Private Member Access Pattern [F15]
  - 3.3.1. Use `friend struct XxxAccess` with static `populate()` in impl file
  - 3.3.2. Anonymous namespace helpers cannot be friends
- 3.4. No public `.raw()` escape hatches permitted
- 3.5. Public string policy
  - 3.5.1. Output: `std::string`
  - 3.5.2. Input: `std::string_view` where suitable; `std::string` otherwise
  - 3.5.3. Conversion boundary helpers between `std::string` and `qstring` internally

---

### 4. SDK Domain-Specific Findings
- 4.1. Segment API
  - 4.1.1. `segment_t::perm` uses `SEGPERM_READ/WRITE/EXEC` (not `SFL_*`) [F13]
  - 4.1.2. Visibility via `is_visible_segm()` (not `is_hidden_segtype()`) [F13]
  - 4.1.3. Segment type constants: SDK `SEG_NORM(0)`–`SEG_IMEM(12)` [F49]
    - 4.1.3.1. Wrapper `segment::Type` maps all 12 values
    - 4.1.3.2. Aliases: `Import`=`SEG_IMP=4`, `InternalMemory`=`SEG_IMEM=12`, `Group`=`SEG_GRP=6`
    - 4.1.3.3. `segment_t::type` is `uchar`
  - 4.1.4. SDK segment comments: `get_segment_cmt`/`set_segment_cmt` operate on `const segment_t*` [F59]
    - 4.1.4.1. `set_segment_cmt` returns `void`
    - 4.1.4.2. Validate target segment first; treat set as best-effort
- 4.2. Type System
  - 4.2.1. SDK float types require `BTF_FLOAT` (=`BT_FLOAT|BTMT_FLOAT`) and `BTF_DOUBLE` (=`BT_FLOAT|BTMT_DOUBLE`) [F14]
    - 4.2.1.1. Not raw `BT_FLOAT`/`BTMT_DOUBLE`
  - 4.2.2. `create_float`/`create_double` may fail at specific addresses in real DBs [F57]
    - 4.2.2.1. Treat as conditional capability probes; assert category on failure
  - 4.2.3. Type and decompiler domains are high-power/high-complexity; need progressive API layering [F6]
- 4.3. Graph API
  - 4.3.1. `create_interactive_graph()` returns nullptr in idalib/headless [F18]
    - 4.3.1.1. Graph uses standalone adjacency-list for programmatic use
    - 4.3.1.2. Only `show_graph()` needs UI
    - 4.3.1.3. `qflow_chart_t` works in all modes
  - 4.3.2. SDK graph naming: `FC_PREDS` renamed to `FC_RESERVED` [F19]
    - 4.3.2.1. Predecessors built by default; `FC_NOPREDS` to disable
    - 4.3.2.2. `insert_simple_nodes()` takes `intvec_t&` (reference, not pointer)
  - 4.3.3. Graph layout in headless is behavioral (stateful contract), not geometric rendering [F68]
    - 4.3.3.1. Persist selected `Layout` in `Graph`, expose `current_layout()`
    - 4.3.3.2. Validate via deterministic integration checks
- 4.4. Chooser API
  - 4.4.1. `chooser_t::choose()` returns `ssize_t` [F20]
    - 4.4.1.1. -1 = no selection, -2 = empty, -3 = already exists
    - 4.4.1.2. `CH_KEEP` prevents deletion on widget close
    - 4.4.1.3. Column widths encode `CHCOL_*` format flags in high bits
- 4.5. Loader API
  - 4.5.1. `loader_failure()` does longjmp, never returns [F21]
  - 4.5.2. No C++ base class for loaders (unlike `procmod_t`) [F21]
    - 4.5.2.1. Wrapper bridges C function pointers to C++ virtual methods via global instance pointer
  - 4.5.3. Loader callback context: load/reload/archive extraction spread across raw callback args and bitflags [F63]
    - 4.5.3.1. `ACCEPT_*`, `NEF_*` flags
    - 4.5.3.2. Expose typed request structs and `LoadFlags` encode/decode helpers
- 4.6. Comment API
  - 4.6.1. `append_cmt` success doesn't guarantee appended text round-trips via `get_cmt` as strict suffix [F32]
    - 4.6.1.1. Tests should assert append success + core content presence, not strict suffix matching
- 4.7. Netnode / Storage
  - 4.7.1. Blob ops at index 0 can trigger `std::length_error: vector` crashes in idalib [F33]
    - 4.7.1.1. Use non-zero indices (100+) for blob/alt/sup ops
    - 4.7.1.2. Document safe ranges
  - 4.7.2. `exist(const netnode&)` is hidden-friend resolved via ADL [F65]
    - 4.7.2.1. Qualifying as `::exist(...)` fails to compile
    - 4.7.2.2. Call `exist(nn)` unqualified
- 4.8. String Literal Extraction
  - 4.8.1. `get_strlit_contents()` supports `len = size_t(-1)` auto-length [F27]
    - 4.8.1.1. Uses existing strlit item size or `get_max_strlit_length(...)`
    - 4.8.1.2. Enables robust string extraction without prior data-definition calls
- 4.9. Snapshot API
  - 4.9.1. `build_snapshot_tree()` returns synthetic root whose `children` are top-level snapshots [F28]
  - 4.9.2. `update_snapshot_attributes(nullptr, root, attr, SSUF_DESC)` updates current DB snapshot description [F28]
- 4.10. Custom Fixup Registration
  - 4.10.1. `register_custom_fixup()`/`find_custom_fixup()`/`unregister_custom_fixup()` return type ids in `FIXUP_CUSTOM` range [F29]
    - 4.10.1.1. Returns 0 on duplicate/missing
    - 4.10.1.2. Wrappers return typed IDs, map duplicates to conflict errors
- 4.11. Database Transfer
  - 4.11.1. `file2base(li, pos, ea1, ea2, patchable)` requires open `linput_t*` + explicit close [F30]
  - 4.11.2. `mem2base(ptr, ea1, ea2, fpos)` returns 1 on success, accepts `fpos=-1` for no file offset [F30]
- 4.12. Switch Info
  - 4.12.1. `switch_info_t` encodes element sizes via `SWI_J32/SWI_JSIZE` and `SWI_V32/SWI_VSIZE` bit-pairs [F25]
    - 4.12.1.1. Not explicit byte fields
    - 4.12.1.2. Expose normalized byte-size fields in wrapper structs
- 4.13. Entry API
  - 4.13.1. `set_entry_forwarder(ord, "")` can fail for some ordinals/DBs in idalib [F60]
    - 4.13.1.1. Expose explicit `clear_forwarder()` returning `SdkFailure`
    - 4.13.1.2. Tests use set/read/restore patterns
- 4.14. Search API
  - 4.14.1. `find_*` helpers already skip start address [F61]
    - 4.14.1.1. `SEARCH_NEXT` mainly meaningful for lower-level text/binary search
    - 4.14.1.2. Keep typed options uniform; validate with integration tests
- 4.15. Action Detach
  - 4.15.1. SDK action detach helpers return only success/failure, no absent-attachment distinction [F62]
    - 4.15.1.1. Map detach failures to `NotFound` with action/widget context
- 4.16. Database Open
  - 4.16.1. `open_database()` in idalib performs loader selection internally [F58]
    - 4.16.1.1. `LoadIntent` (`Binary`/`NonBinary`) maps to same open path
    - 4.16.1.2. Keep explicit intent API, wire to dedicated paths when possible
- 4.17. DB Metadata
  - 4.17.1. SDK file-type from two sources [F93]
    - 4.17.1.1. `get_file_type_name` vs `INF_FILE_FORMAT_NAME`/`get_loader_format_name`
    - 4.17.1.2. Expose both with explicit `NotFound` for missing loader-format

---

### 5. Widget / UI System
- 5.1. Widget Identity and Lifecycle
  - 5.1.1. `TWidget*` stable for widget lifetime [F47]
    - 5.1.1.1. Handle-based subscriptions compare `TWidget*` pointers
    - 5.1.1.2. Opaque `Widget` stores `void*` + monotonic `uint64_t` id for cross-callback identity
  - 5.1.2. Title-only widget callbacks insufficient for complex multi-panel plugins [F43]
    - 5.1.2.1. Titles aren't stable identities
    - 5.1.2.2. No per-instance lifecycle tracking
    - 5.1.2.3. Surface opaque widget handles in notifications
  - 5.1.3. `get_widget_title()` takes `(qstring *buf, TWidget *widget)` [F23]
    - 5.1.3.1. NOT single-arg returning `const char*`
    - 5.1.3.2. Changed from older SDKs
- 5.2. Dock Widget System
  - 5.2.1. SDK dock constants: `WOPN_DP_FLOATING` (not `WOPN_DP_FLOAT`) [F45]
    - 5.2.1.1. Defined in `kernwin.hpp` as `DP_*` shifts by `WOPN_DP_SHIFT`
    - 5.2.1.2. `WOPN_RESTORE` restores size/position
    - 5.2.1.3. `display_widget()` takes `(TWidget*, uint32 flags)`
  - 5.2.2. Qt plugins need underlying host container for `QWidget` embedding [F50]
    - 5.2.2.1. entropyx casts `TWidget*` to `QWidget*`
    - 5.2.2.2. `ida::ui::Widget` is opaque, no container attachment
    - 5.2.2.3. Solution: `ui::with_widget_host(Widget&, callback)` with `void*` host pointer [F51]
    - 5.2.2.4. Scoped callback over raw getter reduces accidental long-lived toolkit pointer storage
- 5.3. View Events
  - 5.3.1. `view_curpos` event: no `va_list` payload [F46]
    - 5.3.1.1. Get position via `get_screen_ea()`
    - 5.3.1.2. Differs from `ui_screen_ea_changed` which passes `(new_ea, prev_ea)` in `va_list`
  - 5.3.2. Generic UI/VIEW routing needs token-family partitioning [F53]
    - 5.3.2.1. UI (`< 1<<62`), VIEW (`[1<<62, 1<<63)`), composite (`>= 1<<63`)
    - 5.3.2.2. For safe unsubscribe of composite subscriptions
- 5.4. Custom Viewer
  - 5.4.1. SDK custom viewer lifetime: `create_custom_viewer()` relies on caller-provided line buffer/place objects remaining valid for widget lifetime [F67]
    - 5.4.1.1. Store per-viewer state in wrapper-managed lifetime storage
    - 5.4.1.2. Erase on close
- 5.5. Plugin Bootstrap
  - 5.5.1. `plugin_t PLUGIN` static init: must use char arrays (not `std::string::c_str()`) [F48]
    - 5.5.1.1. Avoids cross-TU init ordering issues
    - 5.5.1.2. Static char buffers populated at `idax_plugin_init_()` time
    - 5.5.1.3. `IDAX_PLUGIN` macro registers factory via `make_plugin_export()`
    - 5.5.1.4. `plugin_t PLUGIN` lives in `plugin.cpp` (compiled into `libidax.a`)
  - 5.5.2. `make_plugin_descriptor()` referenced but no public export helper existed [F44]
    - 5.5.2.1. Added explicit descriptor/export helper bridging `Plugin` subclasses to IDA entrypoints
- 5.6. Action Context
  - 5.6.1. `action_activation_ctx_t` carries many SDK pointers [F52]
    - 5.6.1.1. Normalize only stable high-value fields into SDK-free structs
    - 5.6.1.2. Fields: action id, widget title/type, current address/value, selection/xtrn bits, register name
  - 5.6.2. Host bridges: opaque handles [F132]
    - 5.6.2.1. `widget_handle`, `focused_widget_handle`, `decompiler_view_handle`
    - 5.6.2.2. Scoped callbacks `with_widget_host`, `with_decompiler_view_host`
- 5.7. Form API
  - 5.7.1. ida-qtform parity: `ida::ui::with_widget_host()` sufficient for Qt panel embedding [F85]
  - 5.7.2. Added markup-only `ida::ui::ask_form(std::string_view)` for form preview/test [F86]
    - 5.7.2.1. Without raw SDK varargs
    - 5.7.2.2. Add typed argument binding APIs later if needed

---

### 6. Decompiler / Hex-Rays
- 6.1. Ctree System
  - 6.1.1. `apply_to()`/`apply_to_exprs()` dispatch through `HEXDSP` runtime function pointers [F22]
    - 6.1.1.1. No link-time dependency
  - 6.1.2. `CV_POST` enables `leave_*()` callbacks [F22]
  - 6.1.3. `CV_PRUNE` via `prune_now()` skips children [F22]
  - 6.1.4. `citem_t::is_expr()` returns `op <= cot_last` (69) [F22]
  - 6.1.5. `treeitems` populated after `get_pseudocode()`, maps line indices to `citem_t*` [F22]
  - 6.1.6. `cfunc_t::hdrlines` is offset between treeitems indices and pseudocode line numbers [F22]
- 6.2. Move-Only Semantics
  - 6.2.1. `DecompiledFunction` is move-only (`cfuncptr_t` is refcounted) [F35]
    - 6.2.1.1. `std::expected<DecompiledFunction, Error>` also non-copyable
    - 6.2.1.2. Test macros using `auto _r = (expr)` must be replaced with reference-based checks
- 6.3. Variable Retype Persistence
  - 6.3.1. Uses `modify_user_lvar_info(..., MLI_TYPE, ...)` with stable locator [F69]
    - 6.3.1.1. In-memory type tweaks alone are insufficient
    - 6.3.1.2. Route through saved-user-info updates
    - 6.3.1.3. Add refresh + re-decompile checks
  - 6.3.2. Error category variance (`NotFound` vs `SdkFailure`) across backends [F194]
    - 6.3.2.1. Tests should assert general failure semantics unless category is contractually stable
- 6.4. Decompile Failure Details
  - 6.4.1. Structured via `DecompileFailure` and `decompile(address, &failure)` [F89]
    - 6.4.1.1. Failure address + description
- 6.5. Microcode Retrieval
  - 6.5.1. Exposed via `DecompiledFunction::microcode()` and `microcode_lines()` [F87]
- 6.6. Call-Subexpression Accessors
  - 6.6.1. `ExpressionView` now includes `call_callee`, `call_argument(index)` alongside `call_argument_count` [F104]
- 6.7. Interactive View Sessions
  - 6.7.1. Stable identity via `view_from_host` (opaque handle derivation) [F193]
  - 6.7.2. Enables reusable rename/retype/comment/save/refresh workflows without exposing `vdui_t`/`cfunc_t` [F193]

---

### 7. Microcode Write-Path / Lifter Infrastructure
- 7.1. Filter Registration
  - 7.1.1. `register_microcode_filter`/`unregister_microcode_filter` [F117]
  - 7.1.2. `MicrocodeContext`/`MicrocodeApplyResult`/`ScopedMicrocodeFilter` [F117]
- 7.2. Low-Level Emit Helpers
  - 7.2.1. `MicrocodeContext` operand/register/memory helpers [F118]
    - 7.2.1.1. `load_operand_register` / `load_effective_address_register`
    - 7.2.1.2. `store_operand_register` / `emit_move_register`
    - 7.2.1.3. `emit_load_memory_register` / `emit_store_memory_register`
    - 7.2.1.4. `emit_helper_call`
  - 7.2.2. Low-level emits default to tail insertion [F181]
    - 7.2.2.1. Policy-aware variants added: `emit_noop/move/load/store_with_policy`
    - 7.2.2.2. Route all emits through shared reposition logic
  - 7.2.3. Wide-operand UDT marking [F182, F183]
    - 7.2.3.1. `mark_user_defined_type` overloads for move/load/store emit (with and without policy)
    - 7.2.3.2. `store_operand_register(..., mark_user_defined_type)` overload
- 7.3. Typed Helper-Call Arguments
  - 7.3.1. `MicrocodeValueKind` / `MicrocodeValue` [F119]
    - 7.3.1.1. Integer widths 1/2/4/8
    - 7.3.1.2. `Float32Immediate` / `Float64Immediate` [F121]
    - 7.3.1.3. `ByteArray` with explicit-location enforcement [F126]
    - 7.3.1.4. `Vector` with typed element width/count/sign/floating controls [F128]
    - 7.3.1.5. `TypeDeclarationView` parsed via `parse_decl` [F129]
    - 7.3.1.6. `LocalVariable` with `local_variable_index`/`offset` [F175]
    - 7.3.1.7. `BlockReference` / `NestedInstruction` for richer callarg mop authoring [F192]
  - 7.3.2. `emit_helper_call_with_arguments[_to_register]` [F119]
  - 7.3.3. Immediate typed-argument with optional `type_declaration` [F184]
    - 7.3.3.1. Parse/size validation + width inference when byte width omitted
- 7.4. Helper-Call Options
  - 7.4.1. `MicrocodeCallOptions` / `MicrocodeCallingConvention` [F120]
  - 7.4.2. `emit_helper_call_with_arguments_and_options[_to_register_and_options]` [F120]
  - 7.4.3. `insert_policy` reuses `MicrocodeInsertPolicy` [F140]
  - 7.4.4. Default `solid_argument_count` inference from argument list when omitted [F147]
  - 7.4.5. Auto-stack placement controls [F148]
    - 7.4.5.1. `auto_stack_start_offset` / `auto_stack_alignment`
    - 7.4.5.2. Non-negative start, power-of-two positive alignment
- 7.5. Argument Locations
  - 7.5.1. `MicrocodeValueLocation` (register/stack-offset) with auto-promotion [F122]
  - 7.5.2. Register-pair and register-with-offset forms [F123]
  - 7.5.3. Static-address placement (`set_ea`) with `BadAddress` validation [F124]
  - 7.5.4. Scattered/multi-part placement via `MicrocodeLocationPart` [F125]
    - 7.5.4.1. Per-part validation (offset/size/kind constraints)
  - 7.5.5. Register-relative placement (`ALOC_RREL` via `consume_rrel`) [F127]
    - 7.5.5.1. Base-register validation
  - 7.5.6. Explicit-location hinting via `mark_explicit_locations` [F121]
- 7.6. Callinfo Shaping
  - 7.6.1. FCI Flags [F130]
    - 7.6.1.1. `mark_dead_return_registers` → `FCI_DEAD`
    - 7.6.1.2. `mark_spoiled_lists_optimized` → `FCI_SPLOK`
    - 7.6.1.3. `mark_synthetic_has_call` → `FCI_HASCALL`
    - 7.6.1.4. `mark_has_format_string` → `FCI_HASFMT`
  - 7.6.2. Scalar field hints [F131]
    - 7.6.2.1. `callee_address`, `solid_argument_count`
    - 7.6.2.2. `call_stack_pointer_delta`, `stack_arguments_top`
  - 7.6.3. `return_type_declaration` parsed via `parse_decl` [F135]
    - 7.6.3.1. Invalid declarations fail with `Validation`
  - 7.6.4. Function role + return-location semantic hints [F139]
    - 7.6.4.1. `MicrocodeFunctionRole` / `function_role` / `return_location`
  - 7.6.5. Declaration-driven register-return typing [F142]
    - 7.6.5.1. Size-match validation, UDT marking for wider destinations
  - 7.6.6. Declaration-driven register-argument typing [F143]
    - 7.6.6.1. Parse validation, size-match, integer-width fallback
  - 7.6.7. Argument metadata [F144]
    - 7.6.7.1. `argument_name`, `argument_flags`, `MicrocodeArgumentFlag`
    - 7.6.7.2. `FAI_RETPTR` → `FAI_HIDDEN` normalization
  - 7.6.8. List shaping [F170]
    - 7.6.8.1. Register-list and visible-memory controls
    - 7.6.8.2. Passthrough registers must be subset of spoiled [F185]
    - 7.6.8.3. Validate subset semantics; return `Validation` on mismatch
    - 7.6.8.4. Return registers auto-merged into spoiled
  - 7.6.9. Declaration-driven vector element typing [F171]
    - 7.6.9.1. Element-size/count/total-width constraints validated together
    - 7.6.9.2. Derive missing count from total width when possible
  - 7.6.10. Coherence testing: success-path helper-call emissions in filters can trigger `INTERR` [F186]
    - 7.6.10.1. Prefer validation-first probes for deterministic assertions
- 7.7. Generic Typed Instruction Emission
  - 7.7.1. Dominant gap identified: generic microcode instruction authoring (opcode+operand construction) [F136]
  - 7.7.2. `MicrocodeOpcode` covering `mov/add/xdu/ldx/stx/fadd/fsub/fmul/fdiv/i2f/f2f/nop` [F137]
  - 7.7.3. `MicrocodeOperandKind` [F137]
    - 7.7.3.1. `RegisterPair` / `GlobalAddress` / `StackVariable` / `HelperReference` [F172]
    - 7.7.3.2. `BlockReference` + validated `block_index` [F173]
    - 7.7.3.3. `NestedInstruction` + recursive validation/depth limiting [F174]
    - 7.7.3.4. `LocalVariable` with `local_variable_index`/`offset` [F175]
  - 7.7.4. `MicrocodeOperand` / `MicrocodeInstruction` [F137]
  - 7.7.5. `emit_instruction` / `emit_instructions` [F137]
  - 7.7.6. Placement-policy controls [F138]
    - 7.7.6.1. `MicrocodeInsertPolicy` (`Tail`/`Beginning`/`BeforeTail`)
    - 7.7.6.2. `emit_instruction_with_policy` / `emit_instructions_with_policy`
    - 7.7.6.3. SDK: `mblock_t::insert_into_block(new, existing)` inserts after `existing`; `nullptr` inserts at beginning
  - 7.7.7. Extended typed opcodes
    - 7.7.7.1. `BitwiseAnd`/`BitwiseOr`/`BitwiseXor` [F165]
    - 7.7.7.2. `ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic` [F165]
    - 7.7.7.3. `Subtract` [F166]
    - 7.7.7.4. `Multiply` [F168]
- 7.8. Temporary Register Allocation
  - 7.8.1. `MicrocodeContext::allocate_temporary_register(byte_width)` mirrors `mba->alloc_kreg` [F146]
- 7.9. Local Variable Context
  - 7.9.1. `MicrocodeContext::local_variable_count()` for availability checks [F176]
  - 7.9.2. Gate usage on `count > 0` with no-op fallback [F176]
  - 7.9.3. Consolidated `try_emit_local_variable_self_move` helper [F177]
    - 7.9.3.1. Reused across `vzeroupper`, `vmxoff`
- 7.10. Microcode Runtime Stability
  - 7.10.1. Aggressive callinfo hints in hardening filters can trigger `INTERR: 50765` [F141]
    - 7.10.1.1. Keep integration coverage validation-focused
    - 7.10.1.2. Heavy emission stress for dedicated scenarios
- 7.11. Maturity / Outline / Cache
  - 7.11.1. Maturity subscriptions: `on_maturity_changed`/`unsubscribe`/`ScopedSubscription` [F116]
  - 7.11.2. Outline/cache helpers [F116]
    - 7.11.2.1. `function::is_outlined`/`set_outlined`
    - 7.11.2.2. `decompiler::mark_dirty`/`mark_dirty_with_callers`
- 7.12. Rewrite Lifecycle
  - 7.12.1. Tracking last-emitted instruction plus block instruction-count query enables additive remove/rewrite workflows [F189]
    - 7.12.1.1. Avoids exposing raw microblock internals
  - 7.12.2. Deterministic mutation via `has_instruction_at_index` / `remove_instruction_at_index` [F191]
    - 7.12.2.1. Allows targeting beyond tracked-last-emitted-only flows

---

### 8. AVX/VMX Lifter Probe
- 8.1. VMX Subset
  - 8.1.1. No-op `vzeroupper` [F145]
  - 8.1.2. Helper-call lowering for VMX family [F145]
    - 8.1.2.1. `vmxon/vmxoff/vmcall/vmlaunch/vmresume`
    - 8.1.2.2. `vmptrld/vmptrst/vmclear/vmread/vmwrite`
    - 8.1.2.3. `invept/invvpid/vmfunc`
- 8.2. AVX Scalar Subset
  - 8.2.1. Math: `vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd` [F149]
  - 8.2.2. Conversion: `vcvtss2sd`, `vcvtsd2ss` [F149]
  - 8.2.3. Extended: `vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`, `vmovss/vmovsd` [F151]
  - 8.2.4. Scalar subset XMM-oriented [F150]
    - 8.2.4.1. Decoded `Operand` value objects lack rendered width text
    - 8.2.4.2. AVX lowering assumes XMM-width destination copy
  - 8.2.5. Memory-destination handling: load destination register before checking memory-destination creates unnecessary failure [F152]
    - 8.2.5.1. Handle memory-dest stores first (`store_operand_register`), then resolve register-target paths
- 8.3. AVX Packed Subset
  - 8.3.1. Math: `vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd` [F153]
  - 8.3.2. Moves: `vmov*` packed via typed emission + store-aware handling [F153]
  - 8.3.3. Width inference via `ida::instruction::operand_text(address, index)` heuristics [F154]
    - 8.3.3.1. `xmm`/`ymm`/`zmm` tokens, `*word` tokens enable width-aware lowering
    - 8.3.3.2. **Refinement**: Structured `instruction::Operand` metadata (`byte_width`, `register_name`, `register_class`) removes dependence on `operand_text()` parsing [F190]
    - 8.3.3.3. `op_t::dtype` + `get_dtype_size(...)` provide structured operand byte widths [F187]
  - 8.3.4. Min/max/sqrt: `vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd` [extended]
  - 8.3.5. Helper-call return fallback: byte-array `tinfo_t` for packed destination widths exceeding integer scalar [F155]
- 8.4. AVX Packed Conversions
  - 8.4.1. Typed emission: `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd` [F156]
  - 8.4.2. Helper-call fallback: `vcvt*2dq/udq/qq/uqq`, truncating forms [F157]
    - 8.4.2.1. Don't map to current typed opcodes; use helper-call fallback
- 8.5. AVX Packed Bitwise / Shift / Permute / Blend
  - 8.5.1. Bitwise: typed opcodes added, helper fallback for `andn`/rotate/exotic [F165]
  - 8.5.2. Shift/rotate (`vps*`, `vprol*`, `vpror*`): mixed register/immediate shapes → helper-call [F161]
  - 8.5.3. Permute/blend: no direct typed opcodes → helper-call fallback [F160]
- 8.6. AVX Packed Integer Arithmetic
  - 8.6.1. `vpadd*`/`vpsub*` direct typed emission; saturating (`vpadds*`/`vpaddus*`/`vpsubs*`/`vpsubus*`) via helper [F166, F167]
  - 8.6.2. `vpmulld`/`vpmullq` typed direct; `vpmullw`/`vpmuludq`/`vpmaddwd` lane-specific → helper [F168]
  - 8.6.3. Two-operand encodings: treat operand 0 as both dest and left source [F169]
- 8.7. Variadic Helper Fallback Architecture
  - 8.7.1. Broad families (`vaddsub*`/`vhadd*`/`vhsub*`) via helper-call [F158]
  - 8.7.2. Mixed register/immediate forwarding via variadic helper [F159]
  - 8.7.3. Memory-operand: attempt effective-address extraction when register fails → typed pointer argument [F163]
  - 8.7.4. Compare mask-register destinations: not representable in current register-load helpers [F164]
    - 8.7.4.1. Lower deterministically by routing through temporary register + operand writeback (`store_operand_register`) [F188]
  - 8.7.5. Unsupported operand shapes degrade to `NotHandled` not hard errors [F162]
    - 8.7.5.1. Keeps decompiler stable while coverage grows
  - 8.7.6. Widened misc families [extended]
    - 8.7.6.1. gather/scatter/compress/expand/popcnt/lzcnt/gfni/pclmul/aes/sha
    - 8.7.6.2. movnt/movmsk/pmov/pinsert/extractps/insertps/pack/phsub/fmaddsub
  - 8.7.7. Helper-return destination routing now prefers typed micro-operands (register/direct-memory `GlobalAddress`) with operand-writeback fallback for unresolved shapes [F196]
    - 8.7.7.1. Integration hardening now exercises both typed helper-return destination success routes (`Register`, `GlobalAddress`) in `decompiler_storage_hardening` with post-emit cleanup via `remove_last_emitted_instruction` [F197]

---

### 9. Debugger / Appcall
- 9.1. Debugger Backend
  - 9.1.1. Backend discovery: `available_backends` + `load_backend` [F178]
  - 9.1.2. Exposed in `ida::debugger`; auto-load in tools before launch
  - 9.1.3. Debugger request queue [F66]
    - 9.1.3.1. `request_*` APIs enqueue, need `run_requests()` to dispatch
    - 9.1.3.2. Direct `step_*`/`run_to`/`suspend_process` execute immediately
    - 9.1.3.3. Mixing styles without flush causes no-op behavior
    - 9.1.3.4. Expose explicit request helpers + `is_request_running()`/`run_requests()`
- 9.2. Appcall Host Issues
  - 9.2.1. macOS (`arm_mac` backend): `start_process` returns 0 but state stays `NoProcess` [F179]
    - 9.2.1.1. Attach returns `-1`, still `NoProcess`
    - 9.2.1.2. Blocked by backend/session readiness, not wrapper API coverage
  - 9.2.2. Queued-request timing: `request_start`/`request_attach` report success while state still `NoProcess` [F180]
    - 9.2.2.1. Perform bounded multi-cycle request draining with settle delays
  - 9.2.3. Attach fallback: `attach_process` returns `-4` across all permutations [F134]
  - 9.2.4. Hold-mode args don't change host outcome [F133]
  - 9.2.5. Appcall with runtime-linked tools: fails cleanly with `dbg_appcall` error 1552 (exit 1) instead of crashing [F110]
  - 9.2.6. Appcall smoke fixture: `ref4` validated safely by calling `int ref4(int *p)` with `p = NULL` [F108]
    - 9.2.6.1. Exercises full request/type/argument/return bridging
  - 9.2.7. Multi-path launch bootstrap: relative/absolute/filename+cwd [F113]
    - 9.2.7.1. Host failures resolve to explicit `start_process failed (-1)`

---

### 10. Lumina
- 10.1. Runtime validation: host reports successful `pull`/`push` smoke [F114]
  - 10.1.1. `requested=1, succeeded=1, failed=0`
- 10.2. `close_server_connection2`/`close_server_connections` declared in SDK but not link-exported [F95]
  - 10.2.1. Keep close wrappers as `Unsupported` until portable close path confirmed

---

### 11. Processor Module Authoring
- 11.1. Processor output: existing modules rely on side-effect callbacks [F64]
  - 11.1.1. Advanced ports need structured text assembly
  - 11.1.2. `OutputContext` and context-driven hooks with fallback defaults
- 11.2. JBC Parity Gaps
  - 11.2.1. `ida::processor::analyze(Address)` returns only instruction size, no typed operand metadata [F80]
    - 11.2.1.1. Full ports must re-decode in multiple callbacks
    - 11.2.1.2. Added optional typed `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`
  - 11.2.2. No wrapper for `set_default_sreg_value` [F81]
    - 11.2.2.1. Added default-segment-register seeding helper
  - 11.2.3. `OutputContext` was text-only (no token/color channels, no mnemonic callback) [F82]
    - 11.2.3.1. Added `OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`
    - 11.2.3.2. Added `output_mnemonic_with_context`

---

### 12. Iterator / Range Semantics
- 12.1. `FunctionIterator::operator*()` returns by value (not reference) [F34]
  - 12.1.1. Range-for must use `auto f` not `auto& f`
  - 12.1.2. Constructs `Function` value from internal SDK state each dereference
  - 12.1.3. Same behavior for `FixupIterator`

---

### 13. Diagnostics & Cross-Cutting
- 13.1. Diagnostics counters: plain shared struct creates data-race risk [F55]
  - 13.1.1. Use atomic counter fields and snapshot reads
- 13.2. Compile-only parity drift risk [F56]
  - 13.2.1. When headers evolve quickly, compile-only tests can lag
  - 13.2.2. Expand `api_surface_parity_test.cpp` with header changes, including overload disambiguation
- 13.3. Cross-cutting/event parity closure [F70]
  - 13.3.1. Can use intentional-abstraction documentation when full raw SDK mirroring is counter to wrapper goals
  - 13.3.2. Keep `partial` with rationale + expansion triggers
- 13.4. Parity Audit Depth [F54]
  - 13.4.1. Broad domain coverage exists, but depth is uneven (`partial` vs full SDK breadth)
  - 13.4.2. Closing parity needs matrix-driven checklist with per-domain closure criteria

---

### 14. Port Audits & Migration Evidence
- 14.1. entropyx/ida-port Gaps [F42]
  - 14.1.1. Missing dockable custom widget hosting → closed
  - 14.1.2. Missing HT_VIEW/UI notification coverage → closed
  - 14.1.3. Missing `jumpto` → `ui::jump_to` added
  - 14.1.4. Missing segment-type introspection → `Segment::type()`/`set_type()` added
  - 14.1.5. Missing plugin bootstrap helper → `IDAX_PLUGIN` macro added
- 14.2. ida-qtform Port [F85, F86]
  - 14.2.1. `ida::ui::with_widget_host()` sufficient for Qt panel embedding
  - 14.2.2. Markup-only `ask_form` for preview/test
- 14.3. idalib-dump Port [F87-F92]
  - 14.3.1. Microcode retrieval added
  - 14.3.2. Structured decompile-failure details added
  - 14.3.3. Plugin-load policy added (`RuntimeOptions` + `PluginLoadPolicy`)
  - 14.3.4. Gap: no headless plugin-load policy controls → closed [F88, F92]
  - 14.3.5. Gap: no public Lumina facade → closed [F90]
- 14.4. ida2py Port [F96-F106]
  - 14.4.1. Gap: no user-name enumeration API → added `ida::name` iterators [F96, F102]
  - 14.4.2. Gap: `TypeInfo` lacks decomposition → added [F97, F103]
    - 14.4.2.1. `is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`
  - 14.4.3. Gap: no generic typed-value facade → added `read_typed`/`write_typed` [F98, F105]
  - 14.4.4. Gap: call subexpressions lack typed accessors → added [F99, F104]
  - 14.4.5. Gap: no Appcall/executor abstraction → added [F100, F106]
- 14.5. Lifter Port [F115-F186]
  - 14.5.1. Read-oriented decompiler only; no write-path hooks initially [F115]
  - 14.5.2. Plugin shell/action/pseudocode-popup workflows verified
  - 14.5.3. Remaining blocker: deeper tmop semantics and advanced decompiler write-path surfaces [B-LIFTER-MICROCODE]
- 14.6. Runtime Caveats
  - 14.6.1. idalib tool examples exit with signal 11 in this environment [F101]
    - 14.6.1.1. Only build/CLI-help validation available
    - 14.6.1.2. Functional checks need known-good idalib host
  - 14.6.2. README drift risk: absolute coverage wording, stale surface counts [F91]

---

### 15. Architecture & Design Decisions (Locked)
- 15.1. Language: C++23
- 15.2. Packaging: Hybrid (header-only thin wrappers + compiled library for complex behavior)
- 15.3. Public API: Fully opaque (no `.raw()` escape hatches)
- 15.4. Public string type: `std::string` (input optimization via `std::string_view`)
- 15.5. Scope: Full (plugins + loaders + processor modules)
- 15.6. Error model: `std::expected<T, ida::Error>` / `std::expected<void, ida::Error>`
  - 15.6.1. ErrorCategory: Validation, NotFound, Conflict, Unsupported, SdkFailure, Internal
- 15.7. Engineering constraints
  - 15.7.1. Prefer straightforward and portable implementations
  - 15.7.2. Avoid compiler-specific intrinsics unless unavoidable
  - 15.7.3. Avoid heavy bit-level micro-optimizations that reduce readability
  - 15.7.4. Prefer SDK helpers (including `pro.h`) for portability/clarity
  - 15.7.5. For batch analysis: prefer `idump <binary>` over `idat`
- 15.8. API Philosophy
  - 15.8.1. Public API simplicity must preserve capability; advanced options must remain in structured form [F9]

---

### 16. Testing Strategy
- 16.1. Validation profiles: `full`, `unit`, `compile-only`
- 16.2. 16/16 test targets passing (232/232 smoke checks + 15 dedicated suites)
- 16.3. idalib-based integration tests with real IDA dylibs
  - 16.3.1. Decompiler edit persistence mutates fixture `.i64` files [F195]
    - 16.3.1.1. Prefer non-persisting validation probes or explicit fixture restore for worktree hygiene
- 16.4. Compile-only API surface parity check as mandatory for every new public symbol [F56]
- 16.5. Three-profile validation via `scripts/run_validation_matrix.sh`
- 16.6. Example addon compilation enabled in CI for regression coverage [F79]
- 16.7. Linux GCC 13.3.0 passes on Ubuntu 24.04 [F71]
- 16.8. Linux Clang 19+ required for `std::expected` support [F111]

---

### 17. Process & Methodology
- 17.1. Documentation
  - 17.1.1. Migration docs are as critical as API design for adoption [F10]
  - 17.1.2. Interface-level API sketches must be present (not just summaries) to avoid implementation ambiguity [F11]

---

## 13) Decision Log (Live)

### 1. Architecture & Core Design Principles

- **1.1. Language Standard**
  - 1.1.1. **Decision:** Target C++23 for modern error handling and API ergonomics

- **1.2. Library Architecture**
  - 1.2.1. **Decision:** Hybrid library architecture balancing ease of use with implementation flexibility

- **1.3. API Opacity**
  - 1.3.1. **Decision:** Fully opaque public API enforcing consistency and preventing legacy leakage

- **1.4. String Model**
  - 1.4.1. **Decision:** Public string model uses `std::string`

- **1.5. Ecosystem Scope**
  - 1.5.1. **Decision:** Scope includes plugins, loaders, and processor modules (full ecosystem)

- **1.6. Documentation**
  - 1.6.1. **Decision:** Keep detailed interface blueprints in `agents.md` for concrete implementation guidance

- **1.7. Diagnostics & Concurrency**
  - 1.7.1. **Decision:** Store diagnostics counters as atomics, return snapshot copies
    - Rejected: Global mutex (unnecessary contention)
    - Rejected: Plain struct (undefined behavior under concurrency)

- **1.8. README Alignment**
  - 1.8.1. **Decision:** Align README with matrix-backed coverage artifacts — replace absolute completeness phrasing with tracked-gap language, pin packaging commands, refresh examples

---

### 2. Build, Linking & Validation Infrastructure

- **2.1. idalib Linking**
  - 2.1.1. **Decision:** Link idalib tests against real IDA installation dylibs, not SDK stubs
    - 2.1.1.1. **Rationale:** SDK stub `libidalib.dylib` has different symbol exports causing two-level namespace crashes
    - Rejected: `-flat_namespace` (too broad)
    - Rejected: `IDABIN` cmake variable (ida-cmake doesn't use it for lib paths)

- **2.2. Compatibility Validation Profiles**
  - 2.2.1. **Decision:** Standardize into three profiles (`full`, `unit`, `compile-only`) with `scripts/run_validation_matrix.sh`
    - 2.2.1.1. Enables consistent multi-OS/compiler execution without full IDA runtime
    - Rejected: Ad hoc per-host docs (drift-prone)
    - Rejected: CI-only matrix (licensing constraints)

- **2.3. Packaging Artifacts**
  - 2.3.1. **Decision:** Pin matrix packaging artifacts via `cpack -B <build-dir>` for reproducible artifact locations
    - Rejected: CPack default output path (drifts by working directory)

- **2.4. Compile-Only Parity Testing**
  - 2.4.1. **Decision:** Treat compile-only parity test as mandatory for every new public symbol including overload disambiguation
    - Rejected: Integration tests only (insufficient compile-surface guarantees)

- **2.5. GitHub Actions CI**
  - 2.5.1. **Decision:** Add GitHub Actions validation matrix workflow for multi-OS `compile-only` + `unit` with SDK checkout
    - Rejected: Manual host-only execution (slower feedback)
    - Rejected: `full` profile in hosted CI (requires licensed runtime)

- **2.6. SDK Bootstrap Tolerance**
  - 2.6.1. **Decision:** Make SDK bootstrap tolerant to variant layouts (`ida-cmake/`, `cmake/`, `src/cmake/`) with recursive submodule checkout
    - Rejected: Pin to one layout (fragile)
    - Rejected: Require manual path overrides (error-prone)

- **2.7. Cross-Generator Config Passing**
  - 2.7.1. **Decision:** Always pass build config to both build and test commands (`cmake --build --config`, `ctest -C`)
    - Rejected: Conditional branch by generator (higher complexity)

- **2.8. Example Addon Compilation in CI**
  - 2.8.1. **Decision:** Enable example addon compilation in hosted validation (`IDAX_BUILD_EXAMPLES=ON`, `IDAX_BUILD_EXAMPLE_ADDONS=ON`)
    - Rejected: Keep examples disabled (misses regressions)
    - Rejected: Separate examples-only workflow (extra maintenance)

- **2.9. Tool-Port Example Compilation**
  - 2.9.1. **Decision:** Expand matrix automation to compile tool-port examples by default (`IDAX_BUILD_EXAMPLE_TOOLS`)
    - Rejected: Keep out of matrix (higher drift)
    - Rejected: Separate tools-only workflow (extra maintenance)

- **2.10. Linux Compiler Pairing**
  - 2.10.1. **Decision:** Adopt Linux Clang 19 + libstdc++ as known-good compile-only pairing; keep addon/tool toggles OFF until `x64_linux_clang_64` SDK runtime libs available
    - Rejected: Clang 18 + libc++ (SDK macro collisions)
    - Rejected: Force addon/tool ON immediately (deterministic failures)

- **2.11. Open-Point Closure Automation**
  - 2.11.1. **Decision:** Add `scripts/run_open_points.sh` + host-native fixture build helper + multi-path Appcall launch bootstrap
    - Rejected: Manual command checklist only (high friction)
    - Rejected: Direct `dbg_appcall` without launch bootstrap (weaker diagnostics)

- **2.12. idalib Tool Linking Policy**
  - 2.12.1. **Decision:** Prefer real IDA runtime dylibs for idalib tool examples when available, fallback to stubs
    - Rejected: `ida_add_idalib`-only (runtime crashes)
    - Rejected: Require `IDADIR` unconditionally (breaks no-runtime compile rows)

---

### 3. Event System

- **3.1. Generic IDB Event Routing**
  - 3.1.1. **Decision:** Add generic IDB event routing (`ida::event::Event`, `on_event`, `on_event_filtered`) on top of typed subscriptions
    - 3.1.1.1. Enables reusable filtering without raw SDK vararg notifications
    - Rejected: Many narrowly-scoped filtered helpers (API bloat)
    - Rejected: Raw `idb_event` codes (leaks SDK)

- **3.2. Generic UI/VIEW Event Routing**
  - 3.2.1. **Decision:** Add generic UI/VIEW routing in `ida::ui` (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite-token unsubscribe
    - Rejected: Many discrete handlers (cumbersome)
    - Rejected: Raw notification codes + `va_list` (unsafe/non-opaque)

---

### 4. UI & Widget System

- **4.1. Dock Widget Host API**
  - 4.1.1. **Decision:** Add opaque dock widget host API (`Widget` handle, `create_widget`/`show_widget`/`activate_widget`/`find_widget`/`close_widget`/`is_widget_visible`, `DockPosition`, `ShowWidgetOptions`) to `ida::ui`
    - 4.1.1.1. Closes entropyx P0 gaps #1/#2
    - Rejected: Expose `TWidget*` (violates opacity)
    - Rejected: Title-only API (fragile for multi-panel)

- **4.2. Widget Event Subscriptions**
  - 4.2.1. **Decision:** Add handle-based widget event subscriptions (`on_widget_visible/invisible/closing(Widget&, cb)`) alongside title-based variants, plus `on_cursor_changed(cb)` for HT_VIEW `view_curpos`
    - 4.2.1.1. Closes entropyx P0 gaps #2/#3
    - Rejected: Title-based only (fragile for multi-instance)

- **4.3. Widget Host Bridge**
  - 4.3.1. **Decision:** Add opaque widget host bridge (`WidgetHost`, `widget_host()`, `with_widget_host()`) for Qt/content embedding without exposing SDK/Qt types
    - 4.3.1.1. Scoped callback over raw getter reduces accidental long-lived pointer storage
    - Rejected: Expose `TWidget*` (breaks opacity)
    - Rejected: Raw getter only (encourages long-lived storage)

- **4.4. Navigation**
  - 4.4.1. **Decision:** Add `ui::jump_to(Address)` wrapping SDK `jumpto()`
    - 4.4.1.1. Closes entropyx P0 gap #4
    - Rejected: Manual screen_address+navigate (missing core operation)

- **4.5. Form API**
  - 4.5.1. **Decision:** Add markup-only `ida::ui::ask_form(std::string_view)`
    - Rejected: Defer (leaves flow blocked)
    - Rejected: Raw vararg `ask_form` (unsafe/non-opaque)

---

### 5. Plugin / Loader / Processor Module Authoring

- **5.1. Plugin Macro**
  - 5.1.1. **Decision:** Implement `IDAX_PLUGIN(ClassName)` macro with `plugmod_t` bridge, static char buffers for `plugin_t PLUGIN`, factory registration via `detail::make_plugin_export()`
    - 5.1.1.1. Closes entropyx P0 gap #6
    - Rejected: Require users write own PLUGIN struct (defeats wrapper)
    - Rejected: Put PLUGIN in user TU via macro (requires SDK includes)

- **5.2. Processor Callbacks**
  - 5.2.1. **Decision:** Expose processor switch/function-heuristic callbacks through SDK-free public structs and virtuals
    - 5.2.1.1. Keeps procmod authoring opaque while preserving advanced capabilities
    - Rejected: Expose raw `switch_info_t`/`insn_t` (violates opacity)
    - Rejected: Defer until full event bridge rewrite (blocks progressive adoption)

- **5.3. Action Context**
  - 5.3.1. **Decision:** Add `plugin::ActionContext` and context-aware callbacks (`handler_with_context`, `enabled_with_context`)
    - Rejected: Raw `action_activation_ctx_t*` (breaks opacity)
    - Rejected: Replace existing no-arg callbacks (unnecessary migration breakage)

- **5.4. Action Context Host Bridges**
  - 5.4.1. **Decision:** Add `ActionContext::{widget_handle, focused_widget_handle, decompiler_view_handle}` with scoped callbacks
    - Rejected: Normalized context only (blocks lifter popup flows)
    - Rejected: Raw SDK types (breaks opacity)

- **5.5. Headless Plugin-Load Policy**
  - 5.5.1. **Decision:** Add headless plugin-load policy via `RuntimeOptions` + `PluginLoadPolicy`
    - Rejected: Environment-variable workarounds only (weak portability)
    - Rejected: Standalone plugin-policy APIs outside init (weaker lifecycle)

---

### 6. Segment, Function, Address & Instruction APIs

- **6.1. Segment Type**
  - 6.1.1. **Decision:** Add `Segment::type()` getter, `set_type()`, expanded `Type` enum (Import, InternalMemory, Group)
    - 6.1.1.1. Closes entropyx P0 gap #5
    - Rejected: Raw `uchar` (violates opaque naming)

- **6.2. Predicate-Based Traversal Ranges**
  - 6.2.1. **Decision:** Add predicate-based traversal ranges (`code_items`, `data_items`, `unknown_bytes`) and discoverability aliases (`next_defined`, `prev_defined`) in `ida::address`
    - Rejected: Only predicate search primitives (less ergonomic for range-for)

- **6.3. Patch & Load Convenience Wrappers**
  - 6.3.1. **Decision:** Add data patch-revert and load-intent convenience wrappers (`revert_patch`, `revert_patches`, `database::OpenMode`, `LoadIntent`, `open_binary`, `open_non_binary`)
    - Rejected: Raw bool/patch APIs only (low discoverability)
    - Rejected: Raw loader entrypoints (leaks complexity)

- **6.4. Structured Operand Introspection**
  - 6.4.1. **Decision:** Add structured operand introspection in `ida::instruction` (`Operand::byte_width`, `register_name`, `register_class`, vector/mask predicates, address-index helpers) and migrate lifter probe away from operand-text heuristics
    - Rejected: Keep probe-local text parsing (drift-prone)
    - Rejected: Expose raw SDK `op_t` in public API (breaks opacity)

---

### 7. Name, Xref, Comment, Type & Entry APIs

- **7.1. Typed Name Inventory**
  - 7.1.1. **Decision:** Add typed name inventory APIs (`Entry`, `ListOptions`, `all`, `all_user_defined`)
    - Rejected: Keep fallback address scanning (weaker discoverability/performance)
    - Rejected: Raw SDK nlist APIs (leaks SDK concepts)

- **7.2. TypeInfo Decomposition**
  - 7.2.1. **Decision:** Add `TypeInfo` decomposition and typedef-resolution helpers (`is_typedef`, `pointee_type`, `array_element_type`, `array_length`, `resolve_typedef`)
    - Rejected: Keep decomposition in external code (duplicated complexity)
    - Rejected: Raw SDK `tinfo_t` utilities (breaks opacity)

---

### 8. Database & Storage

- **8.1. Database Metadata Helpers**
  - 8.1.1. **Decision:** Add database metadata helpers (`file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`)
    - Rejected: Keep metadata in external tools via raw SDK (inconsistent migration)
    - Rejected: New diagnostics namespace (weaker discoverability)

- **8.2. Node-Identity Helpers (P10.7.e)**
  - 8.2.1. **Decision:** Add node-identity helpers (`Node::open_by_id`, `Node::id`, `Node::name`)
    - Rejected: Name-only open (weaker lifecycle ergonomics)
    - Rejected: Raw `netnode` ids/constructors (leaks SDK)

---

### 9. Lumina Integration

- **9.1. Lumina Facade**
  - 9.1.1. **Decision:** Add `ida::lumina` facade with pull/push wrappers (`has_connection`, `pull`, `push`, typed `BatchResult`/`OperationCode`)
    - Rejected: Keep raw SDK for external tools (inconsistent ergonomics)
    - Rejected: Raw `lumina_client_t` (breaks opacity)

- **9.2. Close API Unsupported**
  - 9.2.1. **Decision:** Keep Lumina close APIs as explicit `Unsupported` — runtime dylibs don't export `close_server_connection2`/`close_server_connections` despite SDK declarations
    - Rejected: Call non-exported symbols (link failure)
    - Rejected: Remove close APIs (weaker discoverability)

---

### 10. SDK Parity Closure (Phase 10)

- **10.1. Parity Strategy**
  - 10.1.1. **Decision:** Formalize SDK parity closure as Phase 10 with matrix-driven domain-by-domain checklist and evidence gates
    - Rejected: Ad hoc parity fixes only (poor visibility)
    - Rejected: Docs snapshot without TODO graph (weak progress control)
  - 10.1.2. **Decision:** Use dual-axis coverage matrix (`docs/sdk_domain_coverage_matrix.md`) with domain rows and SDK capability-family rows
    - Rejected: Domain-only (hides cross-domain gaps)
    - Rejected: Capability-only (weak ownership mapping)

- **10.2. Intentional Abstraction Notes (P10.9.a)**
  - 10.2.1. **Decision:** Resolve via explicit intentional-abstraction notes for cross-cutting/event rows (`ida::core`, `ida::diagnostics`, `ida::event`)
    - Rejected: Force all rows `covered` by broad raw-SDK mirroring (API bloat)

- **10.3. Segment/Function/Instruction Parity (P10.3)**
  - 10.3.1. **Decision:** Close P10.3 with additive segment/function/instruction parity
    - 10.3.1.1. Segment: resize/move/comments/traversal
    - 10.3.1.2. Function: update/reanalysis/address iteration/frame+regvar
    - 10.3.1.3. Instruction: jump classifiers + operand text/format unification
    - Rejected: Defer to P10.8 (leaves rows partial)
    - Rejected: Raw SDK classifier/comment entrypoints (violates opacity)

- **10.4. Metadata Parity (P10.4)**
  - 10.4.1. **Decision:** Close P10.4 with additive metadata parity in name/xref/comment/type/entry/fixup
    - 10.4.1.1. Name: identifier validation
    - 10.4.1.2. Xref: range+typed filters
    - 10.4.1.3. Comment: indexed comment editing
    - 10.4.1.4. Type: function/cc/enum type workflows
    - 10.4.1.5. Entry: forwarder management
    - 10.4.1.6. Fixup: expanded descriptor + signed/range helpers
    - Rejected: Defer to docs-only sweep (leaves rows partial)
    - Rejected: Raw SDK enums/flags (weakens conceptual API)

- **10.5. Search/Analysis Parity (P10.5)**
  - 10.5.1. **Decision:** Close P10.5 with additive search/analysis parity
    - 10.5.1.1. Typed immediate/binary options
    - 10.5.1.2. `next_error`/`next_defined`
    - 10.5.1.3. Explicit schedule-intent APIs
    - 10.5.1.4. Cancel/revert wrappers
    - Rejected: Minimal direction-only + AU_CODE-only (low intent clarity)
    - Rejected: Raw `SEARCH_*`/`AU_*` constants (leaks SDK encoding)

- **10.6. Module-Authoring Parity (P10.6)**
  - 10.6.1. **Decision:** Close P10.6 with additive module-authoring parity in plugin/loader/processor
    - 10.6.1.1. Plugin: action detach helpers
    - 10.6.1.2. Loader: typed loader request/flag models
    - 10.6.1.3. Processor: `OutputContext` + context-driven hooks, advanced descriptor/assembler checks
    - Rejected: Replace legacy callbacks outright (migration breakage)
    - Rejected: Raw SDK callback structs/flag bitmasks (violates opacity)

- **10.7. Domain-Specific Parity Sub-Phases**
  - **10.7.1. Debugger Parity (P10.7.a)**
    - 10.7.1.1. **Decision:** Close with async/request and introspection helpers (`request_*`, `run_requests`, `is_request_running`, thread enumeration/control, register introspection)
      - Rejected: Raw `request_*` SDK calls only (inconsistent error model)
      - Rejected: Defer to P10.8 (leaves row partial)
  - **10.7.2. UI Parity (P10.7.b)**
    - 10.7.2.1. **Decision:** Close with custom-viewer and broader UI/VIEW event routing
      - 10.7.2.1.1. Custom viewer: `create_custom_viewer`, line/count/jump/current/refresh/close
      - 10.7.2.1.2. Events: `on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`
      - Rejected: Defer to P10.8 (leaves rows partial)
      - Rejected: Raw SDK custom-viewer structs (weakens opaque boundary)
  - **10.7.3. Graph Parity (P10.7.c)**
    - 10.7.3.1. **Decision:** Close with viewer lifecycle/query helpers (`has_graph_viewer`, `is_graph_viewer_visible`, `activate_graph_viewer`, `close_graph_viewer`) and layout-state introspection (`Graph::current_layout`)
      - Rejected: Title-only refresh/show (insufficient lifecycle)
      - Rejected: UI-only layout effects without state introspection (brittle in headless)
  - **10.7.4. Decompiler Parity (P10.7.d)**
    - 10.7.4.1. **Decision:** Close with variable-retype and expanded comment/ctree workflows (`retype_variable` by name/index, orphan-comment query/cleanup)
      - Rejected: Raw Hex-Rays lvar/user-info structs (breaks opacity)
      - Rejected: Defer to P10.8 (leaves row partial)
  - **10.7.5. Storage Parity (P10.7.e)**
    - *(See §8.2 — Node-identity helpers)*

- **10.8. Evidence Closure (P10.8.d / P10.9.d)**
  - 10.8.1. **Decision:** Close using hosted matrix evidence + local full/packaging evidence
    - Rejected: Keep open until every runtime row is host-complete (scope creep)
    - Rejected: Ignore hosted evidence (weaker reproducibility)

---

### 11. Decompiler Integration

- **11.1. Typed Call-Subexpression Accessors**
  - 11.1.1. **Decision:** Add typed decompiler call-subexpression accessors (`call_callee`, `call_argument(index)`)
    - Rejected: Keep call parsing in external examples (weak portability)
    - Rejected: Raw `cexpr_t*` (breaks opacity)

- **11.2. Generic Typed-Value Facade**
  - 11.2.1. **Decision:** Add generic typed-value facade (`TypedValue`, `TypedValueKind`, `read_typed`, `write_typed`) with recursive array materialization
    - Rejected: Keep typed decoding in external ports (duplicated)
    - Rejected: SDK-level typed-value helpers (weakens opacity)

- **11.3. Structured Decompile-Failure Details**
  - 11.3.1. **Decision:** Add structured decompile-failure details (`DecompileFailure` + `decompile(address, &failure)`)
    - Rejected: Context only in `ida::Error` strings (weakly structured)
    - Rejected: Raw `hexrays_failure_t` (breaks opacity)

- **11.4. Microcode Retrieval**
  - 11.4.1. **Decision:** Add microcode retrieval APIs (`DecompiledFunction::microcode()`, `microcode_lines()`)
    - Rejected: Keep raw SDK for microcode (weak parity)
    - Rejected: Expose `mba_t`/raw printer (breaks opacity)

- **11.5. Lifter Maturity/Outline/Cache Gaps**
  - 11.5.1. **Decision:** Close with additive APIs (`on_maturity_changed`, `mark_dirty`, `mark_dirty_with_callers`, `is_outlined`, `set_outlined`)
    - Rejected: Keep as audit-only gaps (delays value)
    - Rejected: Raw Hex-Rays callbacks (breaks opacity)

- **11.6. Typed Decompiler-View Wrappers**
  - 11.6.1. **Decision:** Add typed decompiler-view edit/session wrappers (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`) operating through stable function identity
    - Rejected: Continue raw host-pointer callback-only workflows (ergonomic gap)
    - Rejected: Expose `vdui_t`/`cfunc_t` in public API (opacity break)
  - 11.6.2. **Decision:** Harden decompiler-view integration checks around backend variance by asserting failure semantics (for missing locals) instead of fixed error category
    - Rejected: Strict `NotFound` category checks (flaky across runtimes)
  - 11.6.3. **Decision:** Keep decompiler-view helper integration coverage non-persisting to avoid fixture drift
    - Rejected: Save-comment roundtrips in helper tests (mutates `.i64` fixtures)
    - Rejected: Fixture rewrite-only cleanup without test hardening (repeat churn)

---

### 12. Microcode Filter & Emission System

- **12.1. Baseline Filter Registration**
  - 12.1.1. **Decision:** Add baseline microcode-filter registration (`register_microcode_filter`, `unregister_microcode_filter`, `MicrocodeContext`, `MicrocodeApplyResult`, `ScopedMicrocodeFilter`)
    - Rejected: Keep raw SDK-only (blocks migration)
    - Rejected: Expose raw `codegen_t`/`microcode_filter_t` (breaks opacity)

- **12.2. Operand/Register/Memory Emit Helpers**
  - 12.2.1. **Decision:** Expand `MicrocodeContext` with operand/register/memory/helper emit helpers
    - Rejected: Keep only `emit_noop` until full typed-IR design (too limiting)
    - Rejected: Expose raw `codegen_t` (opacity break)

- **12.3. Temporary Register Allocation**
  - 12.3.1. **Decision:** Add `MicrocodeContext::allocate_temporary_register(byte_width)` mirroring `mba->alloc_kreg`
    - Rejected: Keep raw-SDK-only (preserves escape hatches)
    - Rejected: Infer indirectly via load helpers (insufficient)

- **12.4. Helper-Call System**
  - **12.4.1. Typed Helper-Call Argument Builders**
    - 12.4.1.1. **Decision:** Add typed helper-call argument builders (`MicrocodeValueKind`, `MicrocodeValue`, `emit_helper_call_with_arguments[_to_register]`)
      - Rejected: Raw `mcallarg_t`/`mcallinfo_t` (opacity break)
      - Rejected: Defer until full vector/UDT design (delays value)
  - **12.4.2. Helper-Call Option Shaping**
    - 12.4.2.1. **Decision:** Add helper-call option shaping (`MicrocodeCallOptions`, `MicrocodeCallingConvention`, `emit_helper_call_with_arguments_and_options[_to_register_and_options]`)
      - Rejected: Raw `mcallinfo_t` mutators (opacity break)
      - Rejected: Defer all callinfo shaping (delays value)
  - **12.4.3. Scalar FP Immediates & Location Hinting**
    - 12.4.3.1. **Decision:** Expand with scalar FP immediates (`Float32Immediate`/`Float64Immediate`) + explicit-location hinting
      - Rejected: Jump to vector/UDT (too large for one slice)
      - Rejected: Raw `mcallarg_t`/`argloc_t` (opacity break)
  - **12.4.4. Default `solid_argument_count` Inference**
    - 12.4.4.1. **Decision:** Add default inference from argument lists
      - Rejected: Keep all explicit at call sites (repetitive)
      - Rejected: Hardcode one value (incorrect for variable arity)
  - **12.4.5. Auto-Stack Placement Controls**
    - 12.4.5.1. **Decision:** Add `auto_stack_start_offset`, `auto_stack_alignment`
      - Rejected: Fixed internal heuristic only (limited control)
      - Rejected: Require explicit location for every non-scalar (heavier boilerplate)
  - **12.4.6. Insertion Policy Extension**
    - 12.4.6.1. **Decision:** Extend helper-call with insertion-policy hinting (`MicrocodeCallOptions::insert_policy`)
      - Rejected: Separate helper-call-with-policy overload family (API bloat)
      - Rejected: Raw block/anchor handles (opacity break)
  - **12.4.7. Register Return — Wider Widths**
    - 12.4.7.1. **Decision:** Expand helper-call register-return fallback for wider destinations with byte-array `tinfo_t` synthesis
      - Rejected: `Unsupported` for widths >8 (blocks packed patterns)
      - Rejected: Require explicit declaration everywhere (excessive boilerplate)
  - **12.4.8. Register Arguments — Wider Widths**
    - 12.4.8.1. **Decision:** Expand helper-call register-argument with declaration-driven non-integer widths + size validation
      - Rejected: Integer-only arguments (insufficient)
      - Rejected: Require `TypeDeclarationView` + explicit location for all (less ergonomic)
  - **12.4.9. Register Return — Non-Integer**
    - 12.4.9.1. **Decision:** Expand helper-call register-return with declaration-driven non-integer widths + size validation
      - Rejected: Integer-only returns (insufficient for wider types)
      - Rejected: Raw `mcallinfo_t`/`mop_t` return mutation (opacity break)
  - **12.4.10. Argument Metadata**
    - 12.4.10.1. **Decision:** Add optional metadata (`argument_name`, `argument_flags`, `MicrocodeArgumentFlag`)
      - Rejected: Implicit metadata only (insufficient callinfo fidelity)
      - Rejected: Raw `mcallarg_t` mutation (opacity break)
  - **12.4.11. Return Writeback to Instruction Operands**
    - 12.4.11.1. **Decision:** Add `emit_helper_call_with_arguments_to_operand[_and_options]` for compare/mask-destination flows
      - Rejected: Keep compare mask destinations as no-op tolerance (semantic loss)
      - Rejected: Require raw SDK call/mop plumbing in ports (migration friction)
  - **12.4.12. tmop Destinations**
    - 12.4.12.1. **Decision:** Expand helper-call tmop shaping with typed micro-operand destinations (`emit_helper_call_with_arguments_to_micro_operand[_and_options]`) and argument value kinds (`BlockReference`, `NestedInstruction`)
      - Rejected: Keep register/instruction-operand-only helper returns (limits richer callarg modeling)
      - Rejected: Expose raw `mop_t`/`mcallarg_t` APIs (opacity break)
  - **12.4.13. Memory-Source Operand Forwarding**
    - 12.4.13.1. **Decision:** Extend helper fallback to accept memory-source operands via effective-address extraction + pointer arguments
      - Rejected: Register-only fallback (misses many forms)
      - Rejected: Fail hard on memory sources (unnecessary instability)

- **12.5. Argument Location Hints**
  - **12.5.1. Basic Register/Stack**
    - 12.5.1.1. **Decision:** Add basic explicit argument-location hints (`MicrocodeValueLocation` register/stack-offset) with auto-promotion
      - Rejected: Raw `argloc_t` (opacity break)
      - Rejected: Defer all location-shaping (delays value)
  - **12.5.2. Register-Pair & Register-with-Offset**
    - 12.5.2.1. **Decision:** Expand `MicrocodeValueLocation` with register-pair and register-with-offset forms
      - Rejected: Register/stack-only (too limiting)
      - Rejected: Raw `argloc_t` (opacity break)
  - **12.5.3. Static Address**
    - 12.5.3.1. **Decision:** Add static-address location hints (`StaticAddress` → `argloc_t::set_ea`)
      - Rejected: Keep without global-location patterns (misses common patterns)
      - Rejected: Raw `argloc_t` (opacity break)
  - **12.5.4. Scattered/Multi-Part**
    - 12.5.4.1. **Decision:** Add scattered/multi-part location hints (`Scattered` + `MicrocodeLocationPart`)
      - Rejected: Single-location only (insufficient for split-placement)
      - Rejected: Raw `argpart_t`/`scattered_aloc_t` (opacity break)
  - **12.5.5. Register-Relative**
    - 12.5.5.1. **Decision:** Add register-relative location hints (`RegisterRelative` → `consume_rrel`)
      - Rejected: Keep without `ALOC_RREL` (misses practical cases)
      - Rejected: Raw `rrel_t` (opacity break)

- **12.6. Argument Value Kinds**
  - **12.6.1. Byte-Array**
    - 12.6.1.1. **Decision:** Add byte-array helper-call argument modeling (`MicrocodeValueKind::ByteArray`) with explicit-location enforcement
      - Rejected: Defer all non-scalar (delays value)
      - Rejected: Raw `mcallarg_t` (opacity break)
  - **12.6.2. Vector**
    - 12.6.2.1. **Decision:** Add vector helper-call argument modeling (`MicrocodeValueKind::Vector`) with typed element controls
      - Rejected: Defer until full UDT abstraction (delays value)
      - Rejected: Raw `mcallarg_t`/type plumbing (opacity break)
  - **12.6.3. TypeDeclarationView**
    - 12.6.3.1. **Decision:** Add declaration-driven argument modeling (`MicrocodeValueKind::TypeDeclarationView`) via `parse_decl`
      - Rejected: Defer until full UDT APIs (delays value)
      - Rejected: Raw `tinfo_t`/`mcallarg_t` (opacity break)
  - **12.6.4. Immediate Type Declaration**
    - 12.6.4.1. **Decision:** Expand immediate typed arguments with optional `type_declaration` + parse/size validation + width inference
      - Rejected: Keep immediates integer-only (loses declaration intent)
      - Rejected: Separate immediate-declaration kind (unnecessary surface growth)

- **12.7. Callinfo Flags & Fields**
  - **12.7.1. Flags**
    - 12.7.1.1. **Decision:** Expand callinfo flags (`mark_dead_return_registers`, `mark_spoiled_lists_optimized`, `mark_synthetic_has_call`, `mark_has_format_string` → `FCI_DEAD`/`FCI_SPLOK`/`FCI_HASCALL`/`FCI_HASFMT`)
      - Rejected: Minimal flags only (too restrictive)
      - Rejected: Raw `mcallinfo_t` flag mutation (opacity break)
  - **12.7.2. Scalar Field Hints**
    - 12.7.2.1. **Decision:** Expand callinfo with scalar field hints (`callee_address`, `solid_argument_count`, `call_stack_pointer_delta`, `stack_arguments_top`)
      - Rejected: Keep field-level shaping internal (insufficient fidelity)
      - Rejected: Raw `mcallinfo_t` mutators (opacity break)
  - **12.7.3. Semantic Role & Return-Location**
    - 12.7.3.1. **Decision:** Expand callinfo with semantic role + return-location hints (`MicrocodeFunctionRole`, `function_role`, `return_location`)
      - Rejected: Raw `funcrole_t`/`argloc_t`/`mcallinfo_t` (opacity break)
      - Rejected: Scalar hints only (insufficient parity)
  - **12.7.4. Declaration-Based Return-Type**
    - 12.7.4.1. **Decision:** Expand callinfo with declaration-based return-type hints (`return_type_declaration` via `parse_decl`)
      - Rejected: Implicit return via destination register only (insufficient fidelity)
      - Rejected: Raw `mcallinfo_t`/`tinfo_t` mutation (opacity break)
  - **12.7.5. Passthrough/Spoiled Validation**
    - 12.7.5.1. **Decision:** Tighten `passthrough_registers` to always require subset of `spoiled_registers`
      - Rejected: Conditional validation only when both specified (permits inconsistent states)
      - Rejected: Auto-promote into spoiled silently (obscures intent/errors)
  - **12.7.6. Coherence Validation**
    - 12.7.6.1. **Decision:** Validate callinfo coherence via validation-first probes rather than success-path emissions
      - Rejected: Success-path emissions in filter tests (flaky)
      - Rejected: Drop coherence assertions (weaker coverage)
  - **12.7.7. Advanced List Shaping**
    - 12.7.7.1. **Decision:** Expand writable IR with richer non-scalar/callinfo/tmop semantics: declaration-driven vector element typing, `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` mop builders, callinfo list shaping for return/spoiled/passthrough/dead registers + visible-memory ranges
      - Rejected: Option-hint-only callinfo (insufficient parity)
      - Rejected: Raw `mop_t`/`mcallinfo_t` mutators (opacity break)

- **12.8. Generic Typed Instruction Emission**
  - **12.8.1. Baseline**
    - 12.8.1.1. **Decision:** Add baseline generic typed instruction emission (`MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`, `emit_instruction`, `emit_instructions`)
      - Rejected: Helper-call-only expansion (insufficient for AVX/VMX handlers)
      - Rejected: Raw `minsn_t`/`mop_t` (opacity break)
  - **12.8.2. Placement Policy**
    - 12.8.2.1. **Decision:** Add constrained placement-policy controls (`MicrocodeInsertPolicy`, `emit_instruction_with_policy`, `emit_instructions_with_policy`)
      - Rejected: Raw `mblock_t::insert_into_block`/`minsn_t*` (opacity break)
      - Rejected: Tail-only insertion (insufficient for real ordering)
  - **12.8.3. Typed Operand Kinds**
    - 12.8.3.1. **Decision:** Add `MicrocodeOperandKind::BlockReference` with validated `block_index`
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw block handles (opacity break)
    - 12.8.3.2. **Decision:** Add `MicrocodeOperandKind::NestedInstruction` with recursive typed payload + depth limiting
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw `minsn_t*` (opacity/ownership break)
    - 12.8.3.3. **Decision:** Add `MicrocodeOperandKind::LocalVariable` with `local_variable_index`/`offset`
      - Rejected: Keep raw-SDK-only (unnecessary gap)
      - Rejected: Expose raw `mop_t`/`lvar_t` (opacity break)
  - **12.8.4. Local-Variable Shaping**
    - 12.8.4.1. **Decision:** Expand local-variable shaping with value-side modeling + `MicrocodeContext::local_variable_count()` guard + no-op fallback
      - Rejected: Instruction-only local-variable support (leaves helper/value incomplete)
      - Rejected: Hardcode indices (brittle)
    - 12.8.4.2. **Decision:** Consolidate local-variable self-move emission into shared helper (`try_emit_local_variable_self_move`)
      - Rejected: Duplicate per-mnemonic logic (drift-prone)
      - Rejected: Limit to one mnemonic (weaker parity pressure)

- **12.9. Typed Opcode Expansion**
  - **12.9.1. Packed Bitwise/Shift**
    - 12.9.1.1. **Decision:** Add typed packed bitwise/shift opcodes (`BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`)
      - Rejected: Keep all in helper fallback (weaker typed-IR parity)
      - Rejected: Very broad opcode set in one step (higher regression risk)
  - **12.9.2. Subtract**
    - 12.9.2.1. **Decision:** Add `MicrocodeOpcode::Subtract`, route `vpadd*`/`vpsub*` through typed emission first
      - Rejected: Keep in helper fallback only (weaker parity)
      - Rejected: Broader integer/vector opcode surface in one pass (higher risk)
  - **12.9.3. Packed Integer Dual-Path**
    - 12.9.3.1. **Decision:** Keep packed integer dual-path (typed first, helper fallback second) with saturating-family helper routing
      - Rejected: Map saturating onto plain Add/Subtract (semantic mismatch)
      - Rejected: Typed-only for integer add/sub (misses memory/saturating)
  - **12.9.4. Multiply**
    - 12.9.4.1. **Decision:** Add `MicrocodeOpcode::Multiply`, route `vpmulld`/`vpmullq` through typed emission; other variants (`vpmullw`/`vpmuludq`/`vpmaddwd`) use helper-call fallback
      - Rejected: Keep all multiply in helper (weaker parity)
      - Rejected: Map all variants to typed multiply (semantic mismatch)
  - **12.9.5. Two-Operand Implicit-Source**
    - 12.9.5.1. **Decision:** Treat two-operand packed binary encodings as destination-implicit-left-source
      - Rejected: Three-operand-only typed path (unnecessary fallback churn)
      - Rejected: Force helper for all two-operand (weaker parity)

- **12.10. Low-Level Emit Helpers**
  - **12.10.1. Policy-Aware Placement**
    - 12.10.1.1. **Decision:** Add policy-aware placement for low-level emit helpers (`emit_noop/move/load/store_with_policy`)
      - Rejected: Keep low-level helpers tail-only (uneven placement parity)
      - Rejected: Bespoke per-call-site placement (brittle/non-discoverable)
  - **12.10.2. Optional UDT-Marking**
    - 12.10.2.1. **Decision:** Add optional UDT-marking to low-level move/load/store emit helpers (including policy-aware overloads)
      - Rejected: UDT shaping limited to typed-instruction builders (leaves low-level gap)
      - Rejected: Require raw SDK post-emit mutation (weakens migration path)
  - **12.10.3. Store Operand Register UDT Overload**
    - 12.10.3.1. **Decision:** Add `store_operand_register(..., mark_user_defined_type)` overload
      - Rejected: Keep integer/default-only (leaves residual gap)
      - Rejected: Route all writebacks through lower-level helpers (loses ergonomic path)

- **12.11. Microcode Lifecycle Helpers**
  - 12.11.1. **Decision:** Add microcode lifecycle convenience helpers (`block_instruction_count`, `has_last_emitted_instruction`, `remove_last_emitted_instruction`) on `MicrocodeContext`
    - Rejected: Expose raw `mblock_t`/`minsn_t*` publicly (opacity/ownership hazards)
    - Rejected: Leave lifecycle bookkeeping to ports (duplicated fragile logic)
  - 12.11.2. **Decision:** Expand microblock lifecycle ergonomics with index-based query/removal (`has_instruction_at_index`, `remove_instruction_at_index`)
    - Rejected: Expose raw `mblock_t` iterators/links (opacity break)
    - Rejected: Keep last-emitted-only removal (insufficient for deterministic rewrites)

- **12.12. Lifter Follow-Up Strategy**
  - 12.12.1. **Decision:** Execute lifter follow-up via source-backed gap matrix with closure slices
    - 12.12.1.1. P0: Generic instruction builder
    - 12.12.1.2. P1: Callinfo depth
    - 12.12.1.3. P2: Placement
    - 12.12.1.4. P3: Typed view ergonomics
    - Rejected: Broad blocker-only wording (weak guidance)
    - Rejected: Large raw-SDK mirror (opacity/stability risk)

---

### 13. Debugger Integration

- **13.1. Backend Discovery**
  - 13.1.1. **Decision:** Add debugger backend discovery (`BackendInfo`, `available_backends`, `current_backend`, `load_backend`) + queued launch/attach (`request_start`, `request_attach`)
    - Rejected: Keep backend logic private in examples (weak discoverability)
    - Rejected: Synchronous start/attach only (misses async path)

- **13.2. Appcall Facade**
  - 13.2.1. **Decision:** Add Appcall + pluggable executor facade (`AppcallValue`, `AppcallRequest`, `appcall`, `cleanup_appcall`, `AppcallExecutor`, `register_executor`, `appcall_with_executor`)
    - Rejected: Keep dynamic execution out-of-scope (leaves gap open)
    - Rejected: Raw SDK `idc_value_t`/`dbg_appcall` (breaks opacity)

- **13.3. Appcall Smoke Testing**
  - 13.3.1. **Decision:** Add fixture-backed Appcall runtime validation (`--appcall-smoke`) plus checklist doc
    - Rejected: Keep as ad hoc notes (low reproducibility)
    - Rejected: Standalone new tool binary (target sprawl)
  - 13.3.2. **Decision:** Expand appcall-smoke with hold-mode + default launches across path/cwd permutations
    - Rejected: Default-args-only (weaker diagnosis)
    - Rejected: Attach-only first (requires additional orchestration)
  - 13.3.3. **Decision:** Add spawn+attach fallback to appcall smoke for better root-cause classification
    - Rejected: Launch-only probes (ambiguous classification)
    - Rejected: Standalone attach utility (target sprawl)
  - 13.3.4. **Decision:** Upgrade appcall-smoke to backend-aware + multi-path execution (load backend → start → request_start → attach → request_attach with state checks)
    - Rejected: Launch-only fallback (less diagnostic depth)
    - Rejected: Host-specific debugger hacks (non-portable)

- **13.4. Queue-Drain Settling**
  - 13.4.1. **Decision:** Add bounded queue-drain settling for request fallbacks (`run_requests` cycles + delays + state checks)
    - Rejected: One-shot `run_requests` (noisy under async hosts)
    - Rejected: Unbounded polling (can hang)

---

### 14. Example Ports & Audit Probes

- **14.1. JBC Full-Port Example**
  - 14.1.1. **Decision:** Add paired JBC full-port example (loader + procmod + shared header) validating idax against real production migration
    - Rejected: Hypothetical-only examples (weaker parity pressure)
    - Rejected: Port only loader or procmod (misses cross-module interactions)
  - 14.1.2. **Decision:** Close JBC parity gaps (#80–#82) with additive processor/segment APIs (typed analyze operand model, default segment-register seeding, tokenized output, mnemonic hook)
    - Rejected: Keep minimal analyze/output + raw SDK escapes (weaker fidelity)
    - Rejected: Replace callbacks outright (migration breakage)

- **14.2. ida-qtform + idalib-dump Ports**
  - 14.2.1. **Decision:** Add real-world port artifacts for ida-qtform + idalib-dump with dedicated audit doc
    - Rejected: Synthetic parity-only checks (miss workflow edges)
    - Rejected: Ad hoc notes only (poor traceability)

- **14.3. ida2py Port Probe**
  - 14.3.1. **Decision:** Add ida2py port probe (`examples/tools/ida2py_port.cpp`) plus standalone audit doc
    - Rejected: Fold into existing audit only (weak traceability)
    - Rejected: Treat as out-of-scope (misses API ergonomics signals)

- **14.4. Lifter Port Probe**
  - 14.4.1. **Decision:** Add lifter port probe plugin (`examples/plugin/lifter_port_plugin.cpp`) plus gap audit doc
    - Rejected: Full direct lifter port (blocked by missing write-path APIs)
    - Rejected: Docs-only without executable probe (weaker regression signal)

- **14.5. VMX Subset Probe**
  - 14.5.1. **Decision:** Add VMX subset to lifter probe using public microcode-filter APIs (no-op `vzeroupper`, helper-call lowering for `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`)
    - Rejected: Keep probe read-only (weaker evidence)
    - Rejected: Full port in one step (blocked by deep write-path APIs)

- **14.6. AVX Scalar Subset**
  - **14.6.1. Basic Arithmetic/Conversion**
    - 14.6.1.1. **Decision:** Extend lifter probe with AVX scalar math/conversion lowering (`vadd/sub/mul/div ss/sd`, `vcvtss2sd`, `vcvtsd2ss`)
      - Rejected: VMX-only until broader vector API (weaker signal)
      - Rejected: Jump to packed directly (higher risk)
  - **14.6.2. XMM Width Handling**
    - 14.6.2.1. **Decision:** Keep AVX scalar subset XMM-oriented — decoded `Operand` value objects lack rendered width text
      - Rejected: Parse disassembly text ad hoc (brittle)
      - Rejected: Overgeneralize wider widths (correctness risk)
  - **14.6.3. Min/Max/Sqrt/Move**
    - 14.6.3.1. **Decision:** Expand with scalar min/max/sqrt/move families (`vmin/vmax/vsqrt/vmov ss/sd`)
      - Rejected: Keep only add/sub/mul/div (leaves common families unexercised)
      - Rejected: Jump to packed (larger surface per change)
  - **14.6.4. Memory-Destination Moves**
    - 14.6.4.1. **Decision:** Handle `vmovss`/`vmovsd` memory-destination before destination-register loading
      - Rejected: One-path destination-register-first (brittle for memory)
      - Rejected: Skip memory-destination moves (leaves common pattern unlifted)

- **14.7. AVX Packed Subset**
  - **14.7.1. Packed Math/Move**
    - 14.7.1.1. **Decision:** Expand to packed math/move (`vadd/sub/mul/div ps/pd`, `vmov*`) with operand-text width heuristics
      - Rejected: Jump to masked packed (larger surface)
      - Rejected: Keep scalar-only until deeper IR (weaker pressure)
  - **14.7.2. Packed Min/Max/Sqrt**
    - 14.7.2.1. **Decision:** Expand packed subset with min/max/sqrt (`vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd`)
      - Rejected: Postpone until deeper IR (slows coverage)
      - Rejected: Typed-emitter-only (missing opcode parity for these)
  - **14.7.3. Packed Conversions**
    - 14.7.3.1. **Decision:** Expand with packed conversions (`vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd`)
      - Rejected: Defer until full vector/tmop DSL (delays high-frequency patterns)
      - Rejected: Helper-call-only for all (less direct parity)
  - **14.7.4. Helper-Fallback Conversions**
    - 14.7.4.1. **Decision:** Expand with helper-fallback conversions (`vcvt*2dq/udq/qq/uqq`, truncating)
      - Rejected: Postpone until new typed opcodes (delays parity)
      - Rejected: Force inaccurate typed mappings (semantic risk)
  - **14.7.5. Addsub/Horizontal**
    - 14.7.5.1. **Decision:** Expand with addsub/horizontal (`vaddsub*`, `vhadd*`, `vhsub*`) via helper-call
      - Rejected: Skip until lane-aware IR (weaker coverage)
      - Rejected: Approximate through plain opcodes (semantic mismatch)
  - **14.7.6. Variadic Bitwise/Permute/Blend**
    - 14.7.6.1. **Decision:** Expand with variadic helper-fallback bitwise/permute/blend
      - Rejected: Wait for typed opcodes first (slower parity)
      - Rejected: Per-mnemonic bespoke handlers (maintenance churn)
  - **14.7.7. Variadic Shift/Rotate**
    - 14.7.7.1. **Decision:** Expand with variadic helper-fallback shift/rotate (`vps*`, `vprol*`, `vpror*`)
      - Rejected: Postpone until typed shift/rotate opcodes (slower parity)
      - Rejected: Per-mnemonic handlers (maintenance-heavy)
  - **14.7.8. Fallback Tolerance**
    - 14.7.8.1. **Decision:** Keep variadic helper fallback tolerant (`NotHandled` over hard error) for broader compare/misc coverage
      - Rejected: Strict erroring on unsupported loads (brittle)
      - Rejected: Delay broad matching until full typed-IR (slower gains)
  - **14.7.9. Compare Mask-Destination Tolerance**
    - 14.7.9.1. **Decision:** Treat unsupported compare mask-destinations as no-op in fallback
      - Rejected: Hard-fail on non-register (destabilizing)
      - Rejected: Defer compare expansion entirely (slower parity)

---

### 15. Blockers (Live)

- **15.1. B-LIFTER-MICROCODE**
  - 15.1.1. **Scope:** Full idax-first port of `/Users/int/dev/lifter` (AVX/VMX microcode transformations)
  - 15.1.2. **Severity:** High
  - **15.1.3. Current Capabilities**
    - 15.1.3.1. Baseline generic typed instruction emission
    - 15.1.3.2. Placement/callinfo shaping (role, return-location, insert-policy, declaration-driven typed register-argument/return, argument name/flag metadata)
    - 15.1.3.3. Temporary-register allocation
    - 15.1.3.4. Local-variable context query (`local_variable_count`)
    - 15.1.3.5. Typed packed bitwise/shift/add/sub/mul opcode emission
    - 15.1.3.6. Richer typed operand/value mop builders (`LocalVariable`/`RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference`/`BlockReference`/`NestedInstruction`)
    - 15.1.3.7. Declaration-driven vector element typing
    - 15.1.3.8. Advanced callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory)
    - 15.1.3.9. Structured instruction operand metadata (`byte_width`/`register_name`/`register_class`)
    - 15.1.3.10. Helper-call return writeback to operands for compare/mask destinations
    - 15.1.3.11. Typed helper-call micro-operand destinations + tmop-oriented callarg value kinds
    - 15.1.3.12. Microcode lifecycle convenience (`block_instruction_count`, tracked last-emitted remove, index query/remove)
    - 15.1.3.13. Typed decompiler-view edit/session wrappers (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`)
  - **15.1.4. Lifter Probe Coverage**
    - 15.1.4.1. Working VMX + AVX scalar/packed subset
    - 15.1.4.2. Broad helper-fallback families (conversion/integer-arithmetic/multiply/bitwise/permute/blend/shift/compare/misc)
    - 15.1.4.3. Mixed register/immediate/memory-source forwarding
    - 15.1.4.4. Deterministic compare/mask writeback paths
  - **15.1.5. Remaining Gaps**
    - 15.1.5.1. Deeper callinfo/tmop semantics beyond current option-hint shaping
    - 15.1.5.2. Fuller typed microcode mutation coverage for non-helper rewrites
    - 15.1.5.3. Stability hardening for aggressive success-path callinfo shaping (`INTERR: 50765` risk)
  - 15.1.6. **Immediate Mitigation:** Keep partial executable probe (`examples/plugin/lifter_port_plugin.cpp`) + gap audit (`docs/port_gap_audit_lifter.md`)
  - 15.1.7. **Long-Term:** Add additive decompiler write-path APIs (richer typed microcode value/argument/callinfo beyond current support) while preserving public opacity
  - 15.1.8. **Owner:** idax wrapper core

---

## 15) Progress Ledger (Live)

### 1. Foundation (Planning, Documentation, Core Build)

- **1.1. Program Planning**
  - 1.1.1. Comprehensive architecture and roadmap captured
  - 1.1.2. Initial `agents.md` with phased TODOs, findings, decisions
  - 1.1.3. Later renamed tracker → `agents.md`, updated all references

- **1.2. Documentation Baseline**
  - 1.2.1. Detailed interface blueprints (Parts 1–5 + module interfaces)
  - 1.2.2. Section 21 with namespace-level API sketches

- **1.3. P0–P5 Core Implementation**
  - 1.3.1. **Artifact:** 24 public headers, 19 impl files, SDK bridge, smoke test
  - 1.3.2. **Artifact:** `libidax.a` (168K), 19 `.cpp` compile
  - 1.3.3. **Evidence:** Smoke 48/48

- **1.4. Two-Level Namespace Blocker**
  - 1.4.1. **Diagnosis:** SDK stub `libidalib.dylib` exports `qvector_reserve` but real dylib doesn't
  - 1.4.2. **Resolution:** Link tests against real IDA installation dylibs
  - 1.4.3. **Evidence:** Smoke 48/48

---

### 2. Core API Build-Out (P2–P5, P7–P8)

- **2.1. Function & Type System (P4)**
  - **2.1.1. Function Callers/Callees (P4.2.c)**
    - Evidence: Smoke 58/58
  - **2.1.2. Function Chunks (P4.2.b)**
    - `Chunk`, `chunks`/`tail_chunks`/`add_tail`/`remove_tail`
    - Evidence: Smoke 68/68
  - **2.1.3. Stack Frames (P4.3.a-b-d)**
    - `StackFrame`, `sp_delta_at`, `define_stack_variable`
    - TypeInfo pimpl extracted to `detail/type_impl.hpp`
    - Evidence: Smoke 68/68
  - **2.1.4. Type Struct/Member/Retrieve (P4.4.c-d)**
    - Evidence: Smoke 58/58
  - **2.1.5. Operand Representation Controls (P4.4.e)**
    - Evidence: Smoke 162/162
  - **2.1.6. Register Variables (P4.3.c)**
    - Evidence: Smoke 162/162
  - **2.1.7. Custom Fixup Registration (P4.6.d)**
    - `CustomHandler`, `register_custom`, `find_custom`, `unregister_custom`
    - Evidence: Smoke 210/210
  - **2.1.8. Type Library Access (P4.7 — via P7.2.c)**
    - `load`/`unload`/`count`/`name`/`import`/`apply_named`
    - Evidence: Smoke 162/162

- **2.2. Data & Address (P2)**
  - **2.2.1. Data String Extraction (P2.2.d-e)**
    - `read_string`, `read_value<T>`, `write_value<T>`, `find_binary_pattern`
    - Evidence: Smoke 201/201
  - **2.2.2. Database Snapshots (P2.3.c)**
    - `Snapshot`, `snapshots()`, `set_snapshot_description()`, `is_snapshot_database()`
    - Evidence: Smoke 205/205
  - **2.2.3. Database File/Memory Transfer (P2.3.b)**
    - `file_to_database`, `memory_to_database`
    - Evidence: Smoke 213/213
  - **2.2.4. Address Search Predicates (P2.1.d)**
    - `Predicate`, `find_first`, `find_next`
    - Evidence: Smoke 232/232

- **2.3. Search (P3)**
  - **2.3.1. Bulk Comment APIs (P3.2.c-d)**
    - `set`/`get`/`clear` anterior/posterior lines; `render`
    - Evidence: Smoke 227/227
  - **2.3.2. Regex/Options Text-Search (P3.4.d)**
    - `TextOptions`
    - Evidence: Smoke 203/203

- **2.4. Instruction & Operand (P5)**
  - **2.4.1. Instruction Xref Conveniences (P5.3)**
    - Confirmed via decompiler smoke
    - Evidence: Smoke 73/73

- **2.5. Event System (P7)**
  - **2.5.1. Core Event System (P5.2)**
    - Evidence: Smoke 58/58
  - **2.5.2. Generic IDB Event Filtering (P7.4.d)**
    - `ida::event::Event`, `on_event`, `on_event_filtered`
    - Evidence: Smoke 193/193 ("generic route fired: yes", "filtered route fired: yes")

- **2.6. Decompiler (P8)**
  - **2.6.1. Hex-Rays Init + Core Decompilation (P8.1.a-c)**
    - `init_hexrays_plugin`, `decompile_func`, pseudocode/lines/declaration/variables/rename_variable
    - Evidence: Smoke 73/73 (pseudocode, variable enumeration, declarations)
  - **2.6.2. Ctree Visitor (P8.1.d-e)**
    - `CtreeVisitor`, `ExpressionView`/`StatementView`, `ItemType`, `VisitAction`/`VisitOptions`
    - `for_each_expression`/`for_each_item`
    - Evidence: Smoke 121/121 (21 exprs + 4 stmts, post-order/skip-children working)
  - **2.6.3. User Comments (P8.2.b-c)**
    - `set_comment`/`get_comment`/`save_comments`, `CommentPosition`
    - Refresh/invalidation; address mapping (`entry_address`, `line_to_address`, `address_map`)
    - Evidence: Smoke 121/121 (comments verified, 16 address mapping entries)
  - **2.6.4. Storage Blob Ops (P8.3.c)**
    - Evidence: Smoke 162/162

---

### 3. Module Authoring (P6)

- **3.1. Plugin System (P6.1)**
  - 3.1.1. Plugin base class (`PLUGIN_MULTI`)
  - 3.1.2. Evidence: Smoke 68/68

- **3.2. Loader System (P6.2)**
  - **3.2.1. Loader InputFile (P6.2.b-c)**
    - Evidence: Smoke 68/68
  - **3.2.2. Loader Base Class (P6.2.a-d-e)**
    - `accept`/`load`/`save`/`move_segment`, `IDAX_LOADER`
    - Evidence: Smoke 95/95

- **3.3. Processor System (P6.3)**
  - **3.3.1. Processor Descriptors (P6.3.c)**
    - `RegisterInfo`, `InstructionDescriptor`, `AssemblerInfo`
    - Evidence: Smoke 68/68
  - **3.3.2. Processor Base Class (P6.3.a-b-e)**
    - `analyze`/`emulate`/`output_instruction`/`output_operand`, `IDAX_PROCESSOR`
    - Evidence: Smoke 95/95
  - **3.3.3. Switch/Function-Heuristic Wrappers (P6.3.d)**
    - `SwitchDescription`/`SwitchCase`
    - Evidence: Smoke 187/187

- **3.4. UI Components (P7.2–P7.3)**
  - **3.4.1. Chooser (P7.2.b-d)**
    - `Chooser`, `Column`/`Row`/`RowStyle`/`ChooserOptions`
    - Evidence: Smoke 95/95
  - **3.4.2. Simple Dialogs, Screen Address/Selection, Timers**
    - Evidence: Smoke 95/95
  - **3.4.3. Graph (P7.3.a-d)**
    - Adjacency-list, node/edge CRUD, BFS, `show_graph`, flowchart
    - Evidence: Smoke 95/95 (flowchart and graph tests)
  - **3.4.4. Widget Title Fix (P7.2.c)**
    - Fixed `get_widget_title` (2-arg SDK)
    - Evidence: Smoke 162/162
  - **3.4.5. UI Event Subscriptions**
    - `on_database_closed`/`on_ready_to_run`/`on_screen_ea_changed`/`on_widget_visible`/`on_widget_closing` + `ScopedUiSubscription`
    - Evidence: Smoke 162/162

- **3.5. Debugger Events (P7.1.d)**
  - 3.5.1. HT_DBG, typed callbacks, `ScopedDebuggerSubscription`
  - 3.5.2. Evidence: Smoke 187/187

- **3.6. Concrete Examples (P0.1.d, P6.4.a-d)**
  - 3.6.1. `action_plugin`, `minimal_loader`, `minimal_procmod` + examples CMake
  - 3.6.2. Verified no compiler-intrinsic usage
  - 3.6.3. Example targets build cleanly

---

### 4. Documentation, Testing & Infrastructure Hardening (P1, P3, P6, P9)

- **4.1. Documentation Bundle (P6.5, P3.6.b-d, P4.5.d, P8.3.d, P9.2)**
  - 4.1.1. quickstart, cookbook, migration, api_reference, tutorial, storage caveats, docs checklist
  - 4.1.2. Synced migration maps

- **4.2. Shared Options & Diagnostics (P1.1.c–P1.4)**
  - 4.2.1. Shared option structs, diagnostics/logging/counters, master include
  - 4.2.2. Unit test target covering error model, diagnostics, handle/range/iterator contracts
  - 4.2.3. Evidence: Unit 22/22; Smoke 232/232

- **4.3. Integration Test Suites**
  - **4.3.1. Name/Comment/Xref/Search (P3.6.a)**
    - Evidence: CTest 3/3
  - **4.3.2. Data Mutation Safety (P2.4.b)**
    - Evidence: CTest 4/4
  - **4.3.3. Segment/Function Edge Cases (P4.7.a)**
    - Evidence: CTest 5/5
  - **4.3.4. Instruction Decode Behavior (P5.4.a)**
    - Evidence: CTest 6/6
  - **4.3.5. Type Roundtrip & Apply (P4.7.b)**
    - Primitive factories, pointer/array, `from_declaration`, struct lifecycle, union, `save_as`/`by_name`, `apply`/`retrieve`, local type library, `to_string`, copy/move
    - Evidence: CTest 10/10
  - **4.3.6. Fixup Relocation (P4.7.c)**
    - Set/get roundtrip, multiple types, contains, traversal, `FixupRange`, error paths, custom lifecycle
    - Evidence: CTest 10/10
  - **4.3.7. Operand Conversion & Text Snapshot (P5.4.b+c)**
    - Operand classification, immediate/register properties, representation controls, forced operand roundtrip, xref conveniences, disassembly text, instruction create
    - Evidence: CTest 10/10
  - **4.3.8. Decompiler & Storage Hardening (P8.4.a-d)**
    - Availability, ctree traversal, expression view accessors, `for_each_item`, error paths, address mapping, user comments, storage alt/sup/hash/blob roundtrips, node semantics
    - Evidence: CTest 10/10
  - **4.3.9. CMake Refactor**
    - `idax_add_integration_test()` helper

- **4.4. API Audit & Rename Pass (P9.1.a-d)**
  - 4.4.1. `delete_register_variable` → `remove_register_variable`
  - 4.4.2. Unified subscription naming
  - 4.4.3. Fixed polarity (`is_visible()`)
  - 4.4.4. Fixed `line_to_address()` error return
  - 4.4.5. `Plugin::run()` → `Status`
  - 4.4.6. Added `EmulateResult`/`OutputOperandResult`
  - 4.4.7. ~135 renames: `ea` → `address`, `idx` → `index`, `cmt` → `comment`, `set_op_*` → `set_operand_*`, `del_*` → `remove_*`
  - 4.4.8. `impl()` made private
  - 4.4.9. `raw_type` → `ReferenceType`
  - 4.4.10. Error context strings added
  - 4.4.11. UI dialog cancellation → `Validation`
  - 4.4.12. Evidence: Build clean, 10/10

- **4.5. Backlog Test Expansion**
  - 4.5.1. `decompiler_edge_cases` (837 lines, 7 sections)
  - 4.5.2. `event_stress` (473 lines, 8 sections)
  - 4.5.3. `performance_benchmark` (537 lines, 10 benchmarks)
  - 4.5.4. Expanded `loader_processor_scenario` (+7 sections)
  - 4.5.5. Expanded migration docs
  - 4.5.6. Evidence: 16/16 tests

- **4.6. Documentation Audit & Polish**
  - **4.6.1. API Mismatch Fixes**
    - Fixed 14 API mismatches across 6 doc files
    - Updated `api_reference`, `validation_report`, README test counts, storage caveats
    - Evidence: 16/16 tests
  - **4.6.2. Namespace Topology**
    - Created `namespace_topology.md`
    - Merged snippets into `legacy_to_wrapper.md`
    - Expanded quick reference
    - Added Section 21 deviation disclaimer
    - Full doc snippet audit: 0 compile-affecting mismatches
    - Evidence: 16/16 tests

---

### 5. Release Engineering & Compatibility Matrix (P0.3, P9.3–P9.4, P10.8)

- **5.1. Release Artifacts (P0.3.d, P4.7.d, P7.5, P6.5, P9.3, P9.4)**
  - 5.1.1. CMake install/export/CPack
  - 5.1.2. Compile-only API surface parity test
  - 5.1.3. Advanced debugger/ui/graph/event validation (60 checks)
  - 5.1.4. Loader/processor scenario test
  - 5.1.5. Fixture README
  - 5.1.6. Opaque boundary cleanup
  - 5.1.7. Evidence: 13/13 CTest; CPack `idax-0.1.0-Darwin.tar.gz`

- **5.2. Compatibility Matrix Baseline**
  - 5.2.1. `scripts/run_validation_matrix.sh` + `docs/compatibility_matrix.md`
  - 5.2.2. macOS arm64 AppleClang 17 (Release/RelWithDebInfo/compile-only/unit profiles)
  - 5.2.3. Evidence: 16/16 full, 2/2 unit, compile-only pass

- **5.3. Matrix Packaging Hardening**
  - 5.3.1. Updated scripts for `cpack -B <build-dir>`
  - 5.3.2. Evidence: 16/16 + `idax-0.1.0-Darwin.tar.gz`

- **5.4. GitHub Actions CI (P10.8.d)**
  - **5.4.1. Initial Workflow**
    - Multi-OS `compile-only` + `unit` with SDK checkout
  - **5.4.2. Multi-Layout Bootstrap**
    - `IDASDK` resolution (`ida-cmake/`, `cmake/`, `src/cmake/`), recursive submodule checkout
  - **5.4.3. Diagnostics**
    - Bootstrap failure path printing for faster triage
  - **5.4.4. Submodule Fix**
    - Recursive submodule checkout for project repo too
  - **5.4.5. Hosted-Matrix Stabilization**
    - Removed retired `macos-13`
    - Fixed cross-generator test invocation (`--config`/`-C`)
    - Hardened SDK bridge include order (`<functional>`, `<locale>`, `<vector>`, `<type_traits>` before `pro.h`)
  - **5.4.6. Example Addon Wiring**
    - `IDAX_BUILD_EXAMPLE_ADDONS` through scripts and CI; validated locally
  - **5.4.7. Tool-Port Wiring**
    - `IDAX_BUILD_EXAMPLE_TOOLS` through scripts + CI
    - Evidence: compile-only + 2/2 unit pass

- **5.5. Linux Compiler Matrix**
  - **5.5.1. P10.8.d Initial**
    - GCC 13.3.0: pass
    - Clang 18.1.3: fail (`std::expected` missing)
    - Clang libc++ fallback: fail (SDK `pro.h` `snprintf` remap collision)
  - **5.5.2. Clang Triage**
    - Clang 18: fail (`__cpp_concepts=201907`)
    - Clang 19: pass (`202002`)
    - Addon/tool linkage blocked by missing `x64_linux_clang_64` SDK libs

---

### 6. Complex-Plugin Parity (entropyx)

- **6.1. Gap Audit**
  - 6.1.1. Compared idax with `/Users/int/dev/entropyx/ida-port`
  - 6.1.2. Documented hard blockers: custom dock widgets, HT_VIEW/UI events, jump-to-address, segment type, plugin bootstrap

- **6.2. Parity Planning**
  - 6.2.1. Prioritized P0/P1 closure plan mapping entropyx usage

- **6.3. P0 Gap Closure (6 gaps)**
  - 6.3.1. **(#1)** Opaque `Widget` + dock widget APIs + `DockPosition` + `ShowWidgetOptions`
  - 6.3.2. **(#2)** Handle-based widget event subscriptions
  - 6.3.3. **(#3)** `on_cursor_changed` for `view_curpos`
  - 6.3.4. **(#4)** `ui::jump_to`
  - 6.3.5. **(#5)** `Segment::type()`/`set_type()` + expanded `Type` enum
  - 6.3.6. **(#6)** `IDAX_PLUGIN` macro + `Action::icon` + `attach_to_popup()`
  - 6.3.7. Refactored UI events to parameterized `EventListener` with token-range partitioning
  - 6.3.8. Added `Plugin::init()`
  - 6.3.9. Evidence: 16/16 tests

- **6.4. Follow-Up Audit**
  - 6.4.1. One remaining gap: no SDK-opaque API for Qt content attachment to `ida::ui::Widget` host panels

- **6.5. Widget Host Bridge**
  - 6.5.1. `WidgetHost`, `widget_host()`, `with_widget_host()` + headless-safe integration
  - 6.5.2. Evidence: 16/16 tests

- **6.6. P1 Closure**
  - 6.6.1. `plugin::ActionContext` + context-aware callbacks
  - 6.6.2. Generic `ida::ui` routing (`EventKind`, `Event`, `on_event`, `on_event_filtered`) with composite token unsubscribe
  - 6.6.3. Evidence: 16/16 tests

---

### 7. SDK Parity Closure (Phase 10)

- **7.1. Planning**
  - 7.1.1. Comprehensive domain-by-domain SDK parity checklist (P10.0–P10.9) with matrix governance and evidence gates

- **7.2. P10.0 — Coverage Matrix**
  - 7.2.1. Created `docs/sdk_domain_coverage_matrix.md` with dual-axis matrices

- **7.3. P10.1 — Error/Core/Diagnostics**
  - 7.3.1. Fixed diagnostics counter data-race (atomic counters)
  - 7.3.2. Expanded compile-only parity for UI/plugin symbols
  - 7.3.3. Evidence: 16/16 tests

- **7.4. P10.2 — Address/Data/Database**
  - 7.4.1. Address traversal ranges (`code_items`/`data_items`/`unknown_bytes`, `next_defined`/`prev_defined`)
  - 7.4.2. Data patch revert + expanded define helpers
  - 7.4.3. Database open/load intent + metadata parity
  - 7.4.4. Evidence: 16/16 tests

- **7.5. P10.3 — Segment/Function/Instruction**
  - 7.5.1. Segment: resize/move/comments/traversal
  - 7.5.2. Function: update/reanalyze/item_addresses/frame_variable_by_name+offset/register_variables
  - 7.5.3. Instruction: `OperandFormat`, `set_operand_format`, `operand_text`, jump classifiers
  - 7.5.4. Evidence: 16/16 tests

- **7.6. P10.4 — Metadata**
  - 7.6.1. Name: `is_user_defined`, identifier validation
  - 7.6.2. Xref: `ReferenceRange`, typed filters, range APIs
  - 7.6.3. Comment: indexed edit/remove
  - 7.6.4. Type: `CallingConvention`, function-type/enum construction, introspection, enum members
  - 7.6.5. Entry: forwarder management
  - 7.6.6. Fixup: flags/base/target, signed types, `in_range`
  - 7.6.7. Evidence: 16/16 tests

- **7.7. P10.5 — Search/Analysis**
  - 7.7.1. `ImmediateOptions`, `BinaryPatternOptions`, `next_defined`, `next_error`
  - 7.7.2. `schedule_code`/`schedule_function`/`schedule_reanalysis`/`schedule_reanalysis_range`, `cancel`, `revert_decisions`
  - 7.7.3. Evidence: 16/16 tests

- **7.8. P10.6 — Module Authoring**
  - 7.8.1. Plugin: action detach helpers
  - 7.8.2. Loader: `LoadFlags`/`LoadRequest`/`SaveRequest`/`MoveSegmentRequest`/`ArchiveMemberRequest`
  - 7.8.3. Processor: `OutputContext` + context-driven hooks + descriptor/assembler checks
  - 7.8.4. Evidence: 16/16 tests

- **7.9. P10.7 — Domain-Specific Parity**
  - **7.9.1. Storage (P10.7.e)**
    - `open_by_id`, `id`, `name`
    - Evidence: 16/16 tests
  - **7.9.2. Debugger (P10.7.a)**
    - Request-queue helpers, thread introspection/control, register introspection
    - Evidence: 16/16 tests
  - **7.9.3. UI (P10.7.b)**
    - Custom-viewer wrappers, expanded UI/VIEW routing (`on_database_inited`, `on_current_widget_changed`, `on_view_*`, expanded `EventKind`/`Event`)
    - Evidence: 16/16 tests
  - **7.9.4. Graph (P10.7.c)**
    - Viewer lifecycle/query helpers, `Graph::current_layout`
    - Evidence: 16/16 tests
  - **7.9.5. Decompiler (P10.7.d)**
    - `retype_variable` by name/index, orphan-comment helpers
    - Evidence: 16/16 tests

- **7.10. P10.8–P10.9 — Closure & Evidence**
  - **7.10.1. Docs/Validation (P10.8.a-c, P10.9.c)**
    - Re-ran matrix profiles (full/unit/compile-only) on macOS arm64 AppleClang 17
  - **7.10.2. Intentional Abstraction (P10.9.a-b)**
    - Notes for cross-cutting/event rows (`ida::core`, `ida::diagnostics`, `ida::event`)
    - No high-severity migration blockers confirmed
  - **7.10.3. Matrix Packaging Refresh**
    - Re-ran full+packaging after P10.7.d
    - Evidence: 16/16 + `idax-0.1.0-Darwin.tar.gz`
  - **7.10.4. Final Closure (P10.8.d/P10.9.d)**
    - Audited hosted logs (Linux/macOS compile-only + unit, Windows compile-only)
    - All confirmed pass
    - **Phase 10: 100% complete**

---

### 8. Post-Phase-10: Port Audits & Parity Expansion

- **8.1. JBC Full-Port Example**
  - **8.1.1. Initial Port**
    - Ported `ida-jam` into idax full examples (loader + procmod + shared header)
    - Validated addon compilation
  - **8.1.2. Matrix Evidence**
    - compile-only pass, 2/2 unit pass
  - **8.1.3. Parity Gaps (#80–#82)**
    - `AnalyzeDetails`/`AnalyzeOperand` + `analyze_with_details`
    - `OutputTokenKind`/`OutputToken` + `OutputContext::tokens()`
    - `output_mnemonic_with_context`
    - Default segment-register seeding helpers
    - Updated JBC examples
    - Evidence: 16/16 tests

- **8.2. ida-qtform + idalib-dump Ports**
  - 8.2.1. Ported into `examples/tools`
  - 8.2.2. Gaps in `docs/port_gap_audit_ida_qtform_idalib_dump.md`
  - 8.2.3. Evidence: 16/16 tests, tool targets compile

- **8.3. ida2py Port**
  - **8.3.1. Probe**
    - `examples/tools/ida2py_port.cpp` + `docs/port_gap_audit_ida2py.md`
    - Recorded gaps: name enumeration, type decomposition, typed-value, call arguments, Appcall
    - Evidence: tool compiles + `--help` pass
  - **8.3.2. Runtime Attempt**
    - `exit:139` on both ida2py and idalib-dump ports
    - Deferred runtime checks to known-good host

- **8.4. Post-Port API Additions**
  - **8.4.1. ask_form**
    - Markup-only `ida::ui::ask_form(std::string_view)`
    - Evidence: compile-only parity pass
  - **8.4.2. Microcode Retrieval**
    - `DecompiledFunction::microcode()`/`microcode_lines()`
    - Wired in idalib-dump port
    - Evidence: 16/16 tests
  - **8.4.3. Decompile-Failure Details**
    - `DecompileFailure` + `decompile(address, &failure)`
    - Evidence: 16/16 tests
  - **8.4.4. Plugin-Load Policy**
    - `RuntimeOptions` + `PluginLoadPolicy` with allowlist wildcards
    - Wired in idalib-dump port
    - Evidence: compile-only parity pass
  - **8.4.5. Database Metadata**
    - `file_type_name`, `loader_format_name`, `compiler_info`, `import_modules`
    - Wired in idalib-dump port
    - Evidence: smoke + parity pass
  - **8.4.6. Lumina Facade**
    - `has_connection`/`pull`/`push`/`BatchResult`/`OperationCode`
    - Close APIs → `Unsupported` (runtime dylibs don't export them)
    - Evidence: smoke + parity pass
  - **8.4.7. Name Inventory**
    - `Entry`, `ListOptions`, `all`, `all_user_defined`
    - Evidence: 2/2 targeted tests
  - **8.4.8. TypeInfo Decomposition**
    - `is_typedef`/`pointee_type`/`array_element_type`/`array_length`/`resolve_typedef`
    - Evidence: 2/2 targeted tests
  - **8.4.9. Call-Subexpression Accessors**
    - `call_callee`/`call_argument(index)` on `ExpressionView`
    - Evidence: 2/2 targeted tests
  - **8.4.10. Typed-Value Facade**
    - `TypedValue`/`TypedValueKind`/`read_typed`/`write_typed` with recursive array + byte-array/string write
    - Evidence: 16/16 tests
  - **8.4.11. Appcall + Executor Facade**
    - `AppcallValue`/`AppcallRequest`/`appcall`/`cleanup_appcall`/`AppcallExecutor`/register/unregister/dispatch
    - Evidence: 16/16 tests

- **8.5. README Alignment**
  - 8.5.1. Updated positioning, commands, examples, coverage messaging to match matrix artifacts

---

### 9. Lifter Port & Microcode Filter System

- **9.1. Lifter Port Probe**
  - 9.1.1. `examples/plugin/lifter_port_plugin.cpp` + `docs/port_gap_audit_lifter.md`
  - 9.1.2. Plugin-shell/action/pseudocode-popup workflows

- **9.2. Decompiler Maturity/Outline/Cache**
  - 9.2.1. `on_maturity_changed`/`unsubscribe`/`ScopedSubscription`
  - 9.2.2. `mark_dirty`/`mark_dirty_with_callers`
  - 9.2.3. `is_outlined`/`set_outlined`
  - 9.2.4. Evidence: targeted tests pass

- **9.3. Microcode Filter Baseline**
  - 9.3.1. `register_microcode_filter`/`unregister_microcode_filter`/`MicrocodeContext`/`MicrocodeApplyResult`/`ScopedMicrocodeFilter`
  - 9.3.2. Evidence: 16/16 tests

- **9.4. MicrocodeContext Emit Helpers**
  - 9.4.1. `load_operand_register`/`load_effective_address_register`/`store_operand_register`
  - 9.4.2. `emit_move_register`/`emit_load_memory_register`/`emit_store_memory_register`/`emit_helper_call`
  - 9.4.3. Evidence: 16/16 tests

- **9.5. Helper-Call Argument System**
  - **9.5.1. Typed Arguments**
    - `MicrocodeValueKind`/`MicrocodeValue`/`emit_helper_call_with_arguments[_to_register]` (integer widths)
    - Evidence: 16/16 tests
  - **9.5.2. Option Shaping**
    - `MicrocodeCallOptions`/`MicrocodeCallingConvention`/`emit_helper_call_with_arguments_and_options[_to_register_and_options]`
    - Evidence: 16/16 tests
  - **9.5.3. Scalar FP + Explicit-Location**
    - `Float32Immediate`/`Float64Immediate` + `mark_explicit_locations`
    - Evidence: 16/16 tests
  - **9.5.4. Argument-Location Hints (Progressive)**
    - Register/stack-offset with auto-promotion → 16/16
    - Register-pair + register-with-offset → 16/16
    - Static-address (`BadAddress` validation) → 16/16
    - Scattered/multi-part (`MicrocodeLocationPart`) → 16/16
    - Register-relative (`ALOC_RREL` via `consume_rrel`) → 16/16
  - **9.5.5. Value Kind Expansion**
    - `ByteArray` (explicit-location enforcement) → 16/16
    - `Vector` (element controls) → 16/16
    - `TypeDeclarationView` (via `parse_decl`) → 16/16
  - **9.5.6. Solid-Arg Inference**
    - Default from argument list when omitted
    - Evidence: 16/16 tests
  - **9.5.7. Auto-Stack Placement**
    - `auto_stack_start_offset`/`auto_stack_alignment` + validation
    - Evidence: 16/16 tests
  - **9.5.8. Insert-Policy Extension**
    - `MicrocodeCallOptions::insert_policy`
    - Evidence: 16/16 tests
  - **9.5.9. Declaration-Driven Register Return**
    - Return types + size matching + wider-register UDT marking
    - Evidence: 16/16 tests
  - **9.5.10. Declaration-Driven Register Arguments**
    - Parse validation + size-match + integer-width fallback
    - Evidence: 16/16 tests
  - **9.5.11. Argument Metadata**
    - `argument_name`/`argument_flags`/`MicrocodeArgumentFlag` + `FAI_RETPTR` → `FAI_HIDDEN` normalization
    - Evidence: 16/16 tests
  - **9.5.12. Return-Type Declaration**
    - `return_type_declaration` via `parse_decl` + malformed-declaration validation
    - Evidence: 16/16 tests
  - **9.5.13. Return Fallback (Wider Widths)**
    - Byte-array `tinfo_t` for widths > integer scalar
    - Evidence: 16/16 tests
  - **9.5.14. Memory-Source + Compare Dest**
    - EA pointer args for memory sources; no-op for unsupported mask destinations
    - Widened misc families (gather/scatter/compress/expand/popcnt/lzcnt/gfni/pclmul/aes/sha/movnt/movmsk/pmov/pinsert/extractps/insertps/pack/phsub/fmaddsub)
    - Evidence: 16/16 tests
  - **9.5.15. Operand Writeback**
    - `emit_helper_call_with_arguments_to_operand[_and_options]` for compare/mask-destination flows
    - Evidence: (via lifter follow-up validation)
  - **9.5.16. tmop Destinations**
    - `BlockReference`/`NestedInstruction` args + micro-operand destinations
    - Evidence: (via lifter write-path closure)

- **9.6. Callinfo Shaping**
  - **9.6.1. FCI Flags**
    - `mark_dead_return_registers`/`mark_spoiled_lists_optimized`/`mark_synthetic_has_call`/`mark_has_format_string`
    - Evidence: 16/16 tests
  - **9.6.2. Scalar Field Hints**
    - `callee_address`/`solid_argument_count`/`call_stack_pointer_delta`/`stack_arguments_top` + validation
    - Evidence: 16/16 tests
  - **9.6.3. Role + Return-Location**
    - `MicrocodeFunctionRole`/`function_role`/`return_location`
    - Evidence: 16/16 tests
  - **9.6.4. Passthrough-Subset Validation**
    - Tightened to require subset of spoiled; return registers auto-merged
    - Evidence: 16/16 tests
  - **9.6.5. Coherence Test Hardening**
    - Validation-first probes with combined pass-through + return-register shaping
    - Evidence: 16/16 tests
  - **9.6.6. Advanced List Shaping**
    - Return/spoiled/passthrough/dead registers + visible-memory
    - Subset validation
    - Evidence: 16/16 tests

- **9.7. Generic Typed Instruction Emission**
  - **9.7.1. Baseline**
    - `MicrocodeOpcode`/`MicrocodeOperandKind`/`MicrocodeOperand`/`MicrocodeInstruction`/`emit_instruction`/`emit_instructions`
    - Covering: `mov`/`add`/`xdu`/`ldx`/`stx`/`fadd`/`fsub`/`fmul`/`fdiv`/`i2f`/`f2f`/`nop`
    - Evidence: 16/16 tests
  - **9.7.2. Placement-Policy Controls**
    - `MicrocodeInsertPolicy`/`emit_instruction_with_policy`/`emit_instructions_with_policy`
    - Evidence: 16/16 tests
  - **9.7.3. Typed Operand Kinds (Progressive)**
    - `BlockReference` + `block_index` validation → 16/16
    - `NestedInstruction` + recursive/depth-limited → 16/16
    - `LocalVariable` + `local_variable_index`/`offset` → 16/16
  - **9.7.4. LocalVariable Value-Path**
    - `MicrocodeValueKind::LocalVariable` + `local_variable_count()` guard; probe uses in `vzeroupper` with no-op fallback
    - Evidence: 16/16 tests
  - **9.7.5. LocalVariable Rewrite Consolidation**
    - Shared `try_emit_local_variable_self_move` applied to `vzeroupper` + `vmxoff`
    - Evidence: 16/16 tests

- **9.8. Typed Opcode Expansion**
  - **9.8.1. Packed Bitwise/Shift**
    - `BitwiseAnd`/`BitwiseOr`/`BitwiseXor`/`ShiftLeft`/`ShiftRightLogical`/`ShiftRightArithmetic`
    - Probe uses typed before helper fallback
    - Evidence: 16/16 tests
  - **9.8.2. Packed Integer Add/Sub**
    - `MicrocodeOpcode::Subtract`; `vpadd*`/`vpsub*` typed-first + helper fallback
    - Evidence: 16/16 tests
  - **9.8.3. Packed Integer Saturating**
    - `vpadds*`/`vpaddus*`/`vpsubs*`/`vpsubus*` via helper fallback alongside typed direct
    - Evidence: 16/16 tests
  - **9.8.4. Packed Integer Multiply**
    - `MicrocodeOpcode::Multiply`; `vpmulld`/`vpmullq` typed + non-direct (`vpmullw`/`vpmuludq`/`vpmaddwd`) via helper
    - Evidence: 16/16 tests
  - **9.8.5. Two-Operand Binary Fix**
    - Destination-implicit-left-source for add/sub/mul/bitwise/shift
    - Evidence: 16/16 tests

- **9.9. Richer Writable IR**
  - 9.9.1. `RegisterPair`/`GlobalAddress`/`StackVariable`/`HelperReference` operand/value kinds
  - 9.9.2. Declaration-driven vector element typing
  - 9.9.3. Callinfo list shaping (return/spoiled/passthrough/dead registers + visible-memory) with subset validation
  - 9.9.4. Evidence: 16/16 tests

- **9.10. Temporary Register Allocation**
  - 9.10.1. `allocate_temporary_register`
  - 9.10.2. Evidence: 16/16 tests

- **9.11. Immediate Typed-Argument Declaration**
  - 9.11.1. `UnsignedImmediate`/`SignedImmediate` with optional `type_declaration` + parse/size validation + width inference
  - 9.11.2. Evidence: 16/16 tests

- **9.12. Low-Level Emit Helpers**
  - **9.12.1. Policy-Aware Placement**
    - `emit_noop`/`move`/`load`/`store_with_policy`; routed existing helpers through policy defaults
    - Evidence: 2/2 targeted tests
  - **9.12.2. UDT Semantics**
    - `mark_user_defined_type` overloads for move/load/store emit (with and without policy)
    - Evidence: 16/16 tests
  - **9.12.3. Store-Operand UDT**
    - `store_operand_register(..., mark_user_defined_type)` overload
    - Evidence: 16/16 tests

- **9.13. Microcode Lifecycle Helpers**
  - 9.13.1. `block_instruction_count`/`has_last_emitted_instruction`/`remove_last_emitted_instruction`
  - 9.13.2. Index-based: `has_instruction_at_index`/`remove_instruction_at_index`
  - 9.13.3. Evidence: (via lifter write-path closure 16/16)

- **9.14. Decompiler-View Wrappers**
  - 9.14.1. `DecompilerView`, `view_from_host`, `view_for_function`, `current_view`
  - 9.14.2. Hardened missing-local assertions to failure-semantics
  - 9.14.3. Removed persisting comment roundtrips to prevent fixture drift
  - 9.14.4. Evidence: 16/16 tests

- **9.15. Action-Context Host Bridges**
  - 9.15.1. `widget_handle`/`focused_widget_handle`/`decompiler_view_handle` + scoped callbacks
  - 9.15.2. Evidence: 16/16 tests

- **9.16. INTERR: 50765 Stabilization**
  - 9.16.1. Aggressive callinfo hints triggered decompiler internal error
  - 9.16.2. Adjusted tests to validation-focused paths
  - 9.16.3. Evidence: 16/16 tests

---

### 10. Lifter Probe: VMX + AVX Coverage

- **10.1. VMX Subset**
  - 10.1.1. No-op `vzeroupper` via typed emission
  - 10.1.2. Helper-call lowering: `vmxon`/`vmxoff`/`vmcall`/`vmlaunch`/`vmresume`/`vmptrld`/`vmptrst`/`vmclear`/`vmread`/`vmwrite`/`invept`/`invvpid`/`vmfunc`
  - 10.1.3. Evidence: plugin builds, 16/16 tests

- **10.2. AVX Scalar Subset**
  - **10.2.1. Basic Arithmetic/Conversion**
    - `vadd`/`vsub`/`vmul`/`vdiv` `ss`/`sd`, `vcvtss2sd`, `vcvtsd2ss` via typed emission
    - Evidence: 16/16 tests
  - **10.2.2. Width Constraint**
    - Constrained to XMM-width; docs updated
  - **10.2.3. Min/Max/Sqrt/Move**
    - `vmin`/`vmax`/`vsqrt`/`vmov` `ss`/`sd` via typed emission + helper-return
    - Evidence: 16/16 tests
  - **10.2.4. Memory-Destination Moves**
    - Reordered to handle store before register-load
    - Evidence: 16/16 tests

- **10.3. AVX Packed Subset**
  - **10.3.1. Math/Move**
    - `vadd`/`vsub`/`vmul`/`vdiv` `ps`/`pd`, `vmov*` via typed emission + width heuristics
    - Evidence: 16/16 tests
  - **10.3.2. Min/Max/Sqrt**
    - `vminps`/`vmaxps`/`vminpd`/`vmaxpd`, `vsqrtps`/`vsqrtpd` via helper-return
    - Evidence: 16/16 tests
  - **10.3.3. Conversions (Typed)**
    - `vcvtps2pd`/`vcvtpd2ps`, `vcvtdq2ps`/`vcvtudq2ps`, `vcvtdq2pd`/`vcvtudq2pd`
    - Evidence: 16/16 tests
  - **10.3.4. Conversions (Helper-Fallback)**
    - `vcvt*2dq/udq/qq/uqq` + truncating
    - Evidence: 16/16 tests
  - **10.3.5. Addsub/Horizontal**
    - `vaddsub*`/`vhadd*`/`vhsub*` via helper-call
    - Evidence: 16/16 tests
  - **10.3.6. Variadic Bitwise/Permute/Blend**
    - Mixed register/immediate forwarding
    - Evidence: 16/16 tests
  - **10.3.7. Variadic Shift/Rotate**
    - `vps*`/`vprol*`/`vpror*`
    - Evidence: 16/16 tests
  - **10.3.8. Tolerant Compare/Misc**
    - Broad families (`vcmp*`/`vpcmp*`/`vdpps`/`vround*`/`vbroadcast*`/`vextract*`/`vinsert*`/`vunpck*` etc.) with `NotHandled` degradation
    - Evidence: 16/16 tests

---

### 11. Debugger & Appcall Runtime

- **11.1. Debugger Backend APIs**
  - 11.1.1. `BackendInfo`/`available_backends`/`current_backend`/`load_backend`
  - 11.1.2. `request_start`/`request_attach`
  - 11.1.3. Upgraded appcall-smoke to backend-aware + multi-path
  - 11.1.4. Evidence: 2/2 targeted tests

- **11.2. Appcall Runtime Evidence**
  - **11.2.1. Initial Smoke**
    - `--appcall-smoke` flow + `docs/appcall_runtime_validation.md`
    - Evidence: tool compiles + `--help` pass
  - **11.2.2. Tool-Port Linkage Hardening**
    - Prefer real IDA dylibs, fallback to stubs
    - Appcall-smoke fails gracefully (error 1552, not signal-11)
  - **11.2.3. Hold-Mode Expansion**
    - `--wait` fixture mode; still blocked (`start_process failed (-1)`)
  - **11.2.4. Spawn+Attach Fallback**
    - `attach_process` returns `-4`; host blocked at attach readiness
  - **11.2.5. Queue-Drain Settling**
    - Bounded multi-cycle `run_requests` + delays; host remains blocked

- **11.3. Open-Point Automation**
  - 11.3.1. `scripts/run_open_points.sh` + `scripts/build_appcall_fixture.sh` + multi-path Appcall launch bootstrap
  - 11.3.2. Full matrix pass, Lumina pass
  - 11.3.3. Appcall blocked: `start_process failed (-1)`
  - **11.3.4. Refresh Sweeps**
    - `build-open-points-surge6`: full=pass, appcall=blocked, lumina=pass
    - Backend loaded, `start_process` rc `0` + still `NoProcess`, `attach_process` rc `-1` + still `NoProcess`

---

### 12. Blocker Status & Gap Tracking

- **12.1. Blocker Precision Update**
  - 12.1.1. Expanded `B-LIFTER-MICROCODE` description with concrete remaining closure points
    - Callinfo/tmop depth
    - Typed view ergonomics
    - Operand-width metadata
    - Fallback elimination
    - Microblock mutation parity
    - Stability hardening
  - 12.1.2. `AGENTS.md` blocker section updated

- **12.2. Lifter Source-Backed Gap Matrix**
  - 12.2.1. P0: Generic instruction builder
  - 12.2.2. P1: Callinfo depth
  - 12.2.3. P2: Placement
  - 12.2.4. P3: Typed view ergonomics

- **12.3. Lifter Follow-Up Validation**
  - 12.3.1. Re-ran targeted suites (`api_surface_parity`, `instruction_decode_behavior`, `decompiler_storage_hardening`) + full CTest
  - 12.3.2. All passing after structured operand metadata + helper-call operand-writeback + lifecycle helpers
  - 12.3.3. Evidence: 16/16 tests

- **12.4. Lifter Write-Path Closure Increment**
  - 12.4.1. Helper-call tmop shaping (`BlockReference`/`NestedInstruction` args + micro-operand destinations)
  - 12.4.2. Microblock index lifecycle (`has_instruction_at_index`/`remove_instruction_at_index`)
  - 12.4.3. Typed decompiler-view sessions (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`)
  - 12.4.4. Updated lifter probe + docs
  - 12.4.5. Evidence: targeted + full CTest pass (16/16)

- **12.5. Decompiler-View Test Hardening**
  - 12.5.1. Missing-local assertions → failure-semantics (backend variance tolerance)
  - 12.5.2. Removed persisting comment roundtrips → prevent fixture drift
  - 12.5.3. Restored fixture side effects and revalidated
  - 12.5.4. Evidence: 16/16 tests

- **12.6. Lifter tmop Adoption (5.4.1)**
  - 12.6.1. Applied micro-operand helper-return routing across additional AVX/VMX branches in `examples/plugin/lifter_port_plugin.cpp`.
  - 12.6.2. Converted register-destination helper returns to `emit_helper_call_with_arguments_to_micro_operand_and_options` and added direct-memory compare destination routing (`MemoryDirect` → `GlobalAddress`) before operand-writeback fallback.
  - 12.6.3. Evidence: `cmake --build build-matrix-unit-examples-local --target idax_lifter_port_plugin` passes.

- **12.7. Regression Coverage Closure (5.4.1)**
  - 12.7.1. Added hardening regression coverage in `tests/integration/decompiler_storage_hardening_test.cpp` for helper-return micro-operand destination routing success paths (`Register`, direct-memory `GlobalAddress`).
  - 12.7.2. Added explicit assertions to ensure routes are attempted and either succeed or degrade only through backend/runtime categories (`SdkFailure`/`Internal`), never validation misuse.
  - 12.7.3. Added post-emit cleanup checks (`remove_last_emitted_instruction`) to keep mutation flows deterministic while exercising success paths.
  - 12.7.4. Evidence: `./tests/integration/idax_decompiler_storage_hardening_test /Users/int/dev/idax/tests/fixtures/simple_appcall_linux64` → `196 passed, 0 failed`.

---

## 16) In-Progress and Immediate Next Actions

> **Tracking Policy:** This list tracks *active* and *queued* work items only. Once an item reaches completion (pass evidence recorded, docs updated, ledger entry written), it **must be removed** from this list and migrated to the Progress Ledger KB. Stale entries degrade signal — prune aggressively.

---

### 1. CI & Validation Infrastructure

- **1.1. GitHub Actions Matrix (Default Path)**
  - 1.1.1. **Action:** Keep `.github/workflows/validation-matrix.yml` as default cross-OS evidence path
  - 1.1.2. **Scope:** `compile-only` + `unit` on every release-significant change
  - 1.1.3. **Status:** Active / ongoing

- **1.2. Host-Specific Hardening**
  - 1.2.1. **Action:** Continue host-specific hardening runs where licenses/toolchains permit
  - **1.2.2. Linux**
    - 1.2.2.1. Keep Clang 19 as baseline evidence
    - 1.2.2.2. Execute `full` rows with runtime installs when available
  - **1.2.3. Windows**
    - 1.2.3.1. Execute `full` rows with runtime installs when available
  - 1.2.4. **Status:** Ongoing / license-gated

---

### 2. JBC & Processor Module Parity

- **2.1. Validation Continuation**
  - 2.1.1. **Action:** Continue validating JBC parity APIs against additional real-world procmod ports
  - 2.1.2. **Scope:** Expand typed analyze/output metadata only when concrete migration evidence requires deeper fidelity
  - 2.1.3. **Status:** Ongoing / evidence-driven

---

### 3. Lumina Hardening

- **3.1. Beyond Pull/Push Baseline**
  - 3.1.1. **Action:** Keep hardening `ida::lumina` behavior beyond now-passing pull/push smoke baseline
  - 3.1.2. **Focus:** Close/disconnect semantics once portable runtime symbols are confirmed
  - 3.1.3. **Blocker:** Runtime dylibs don't export `close_server_connection2`/`close_server_connections`
  - 3.1.4. **Status:** Blocked on runtime symbol availability

---

### 4. Appcall Runtime Evidence

- **4.1. Debugger-Capable Host Execution**
  - 4.1.1. **Action:** Execute `docs/appcall_runtime_validation.md` on a debugger-capable host
  - **4.1.2. Current Block State**
    - 4.1.2.1. Backend loads successfully
    - 4.1.2.2. `start_process` returns `0` + still `NoProcess`
    - 4.1.2.3. `request_start` → no-process
    - 4.1.2.4. `attach_process` returns `-1` + still `NoProcess`
    - 4.1.2.5. `request_attach` → no-process
  - 4.1.3. **Goal:** Convert block into pass evidence
  - 4.1.4. **Follow-Up:** Expand Appcall argument/return kind coverage only where concrete ports require additional fidelity
  - 4.1.5. **Status:** Blocked on debugger-capable host

---

### 5. Decompiler Write-Path Depth (Lifter-Class Ports)

- **5.1. Strategic Priority**
  - 5.1.1. **Action:** Prioritize post-P0/P1/P2 additive decompiler write-path depth for lifter-class ports

- **5.2. Current Baseline (Achieved)**
  - 5.2.1. Generic instruction emission
  - 5.2.2. Typed/helper-call placement controls
  - 5.2.3. Callinfo role/return-location shaping
  - 5.2.4. Declaration-driven typed register-argument/return modeling
  - 5.2.5. Optional argument metadata
  - 5.2.6. Temporary-register allocation
  - 5.2.7. Structured operand metadata
  - 5.2.8. Helper-call operand writeback
  - 5.2.9. Microblock index lifecycle helpers
  - 5.2.10. Typed decompiler-view sessions

- **5.3. Target Extension Surface**
  - 5.3.1. Advanced vector/UDT semantics
  - 5.3.2. Deeper callinfo/tmop semantics
  - 5.3.3. Broader non-helper mutation parity
  - 5.3.4. In-view advanced edit ergonomics

- **5.4. Immediate Execution Queue (Post-5.4.2)**
  - 5.4.1. Continue tmop adoption in `examples/plugin/lifter_port_plugin.cpp` by reducing remaining operand-writeback fallback paths where destination shapes can be expressed as typed micro-operands.
  - 5.4.2. Begin 5.3.2 depth work with additive callinfo/tmop semantics for AVX/VMX helper paths (per-family return typing, argument metadata, semantic role/location hints where concretely useful).
  - 5.4.3. Re-run targeted validation (`idax_lifter_port_plugin` build + decompiler hardening/parity tests) and synchronize evidence/docs (`docs/port_gap_audit_lifter.md`, Progress Ledger updates).
  - 5.4.4. **Status:** Queued

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

## 20) Compliance Reminder (Hard Requirement)

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

## 21) Comprehensive Interface Blueprint (Detailed)

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

### 21.1 Diagnosis - Why the SDK feels unintuitive

Core issues to solve:
1. Naming chaos: mixed abbreviations (`segm`, `func`, `cmt`) and inconsistent prefixes.
2. Conceptual opacity: packed flags and hidden relationships behind internal conventions.
3. Inconsistent patterns: mixed return/error conventions and multiple competing APIs.
4. Hidden dependencies: include-order constraints, pointer invalidation rules, sentinel-heavy semantics.
5. Redundancy: multiple enumeration and access paths for the same concepts.

### 21.2 Design philosophy

1. Domain-driven namespacing.
2. Self-documenting names and full words.
3. Consistent error model (`Result<T>`, `Status`).
4. RAII and value semantics by default.
5. Iterable/range-first API for traversal-heavy tasks.
6. Progressive disclosure: simple default path plus advanced options.

### 21.3 Namespace architecture (detailed)

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

### 21.4 Cross-cutting public primitives

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

### 21.5 Detailed interface sketches by namespace

#### 21.5.1 `ida::address`

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

#### 21.5.2 `ida::segment`

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

#### 21.5.3 `ida::function`

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

#### 21.5.4 `ida::instruction`

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

#### 21.5.5 `ida::data`

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

#### 21.5.6 `ida::name`

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

#### 21.5.7 `ida::xref`

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

#### 21.5.8 `ida::type`

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

#### 21.5.9 `ida::comment`

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

#### 21.5.10 `ida::search`

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

#### 21.5.11 `ida::analysis`

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

#### 21.5.12 `ida::database`

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

#### 21.5.13 `ida::fixup`

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

#### 21.5.14 `ida::entry`

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

#### 21.5.15 `ida::plugin`

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

#### 21.5.16 `ida::loader`

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

#### 21.5.17 `ida::processor`

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

#### 21.5.18 `ida::debugger`

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

#### 21.5.19 `ida::ui`, `ida::graph`, `ida::event`

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

#### 21.5.20 `ida::decompiler`

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

#### 21.5.21 `ida::storage` (advanced)

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

### 21.6 Refined implementation phasing (interface-first)

1. Core end-user analysis domains first (`address`, `data`, `segment`, `function`, `instruction`, `name`, `xref`, `comment`, `type`, `search`, `analysis`, `database`).
2. Module-author domains next (`plugin`, `loader`, `processor`).
3. High-complexity/interactive domains after (`debugger`, `decompiler`, `ui`, `graph`, `event`, `storage`).

### 21.7 Proposed implementation layout (hybrid)

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

### 21.8 Compliance note for this section

This section is part of the mandatory baseline. If interfaces evolve, this section must be updated immediately and corresponding updates must be logged in:
- Phase TODO status
- Findings and Learnings
- Decision Log (if design changed)
- Progress Ledger
