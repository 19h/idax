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
