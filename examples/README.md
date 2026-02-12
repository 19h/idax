# idax examples

This directory contains reference addon implementations using the idax wrapper API,
ranging from minimal quick-start skeletons to comprehensive advanced examples that
exercise every domain of the API surface.

## Minimal examples (quick-start)

- `plugin/action_plugin.cpp`: sample action-oriented plugin code.
- `loader/minimal_loader.cpp`: minimal custom loader implemented with `ida::loader::Loader`.
- `procmod/minimal_procmod.cpp`: minimal processor module implemented with `ida::processor::Processor`.

## Advanced examples (comprehensive API coverage)

### `plugin/deep_analysis_plugin.cpp` — Cross-domain analysis

Exercises **all core analysis domains** in a single plugin:
segments, functions (callers/callees/chunks/frames/register variables),
instructions (decode/operand types/representation controls/forced operands),
types (primitives/pointers/arrays/structs/unions/type library),
names (set/force/resolve/demangle/public/weak), xrefs (all reference types),
comments (regular/repeatable/anterior/posterior/bulk/render),
search (text/regex/binary/immediate), data (read/write/patch/typed/original),
fixups (traversal/custom registration), entry points, address predicates,
and analysis scheduling.

### `plugin/decompiler_plugin.cpp` — Hex-Rays decompiler integration

Exercises the **full decompiler surface**:
availability check, function decompilation (move-only result handling),
pseudocode/lines/declaration extraction, variable enumeration and rename,
custom CtreeVisitor with all visit modes (pre-order/post-order/expressions-only/
early-stop/skip-children), functional-style visitors (`for_each_expression`,
`for_each_item`), ExpressionView/StatementView accessor edge cases
(number\_value, call\_argument\_count, variable\_index, string\_value,
member\_offset, to\_string, wrong-type error paths), user comment management
(set/get/save/remove with multiple CommentPositions), pseudocode refresh,
address mapping (line\_to\_address, address\_map, out-of-range), and
flow chart generation.

### `plugin/event_monitor_plugin.cpp` — Multi-domain event monitoring

Exercises **all three event domains** simultaneously:
IDB events (segment/function/rename/byte\_patched/comment\_changed),
UI events (database\_closed/ready\_to\_run/screen\_ea\_changed/widget),
debugger events (all 11 typed subscriptions across 3 tiers),
generic event routing with predicate filtering,
RAII ScopedSubscription lifecycle in all three namespaces,
timer registration/unregistration,
Chooser subclass with dynamic data and column formatting,
Graph construction with groups/layout/path queries,
and UI dialog exercises.

### `plugin/storage_metadata_plugin.cpp` — Netnode persistence and metadata

Exercises **storage, metadata, and cross-cutting concerns**:
netnode alt/sup/hash/blob operations with multiple tags,
blob lifecycle (create/read/overwrite/size/string/remove),
Node copy/move semantics, error paths (nonexistent/default-constructed),
database metadata (path/MD5/base/bounds), snapshot management,
batch annotation (segments/entries/types),
fixup statistics and custom handler registration lifecycle,
analysis control (enable/disable/schedule/wait),
diagnostics API (log levels/performance counters/enrichment/assertions),
and address range statistics with predicate search.

### `loader/advanced_loader.cpp` — Complex format loader

Exercises the **full loader surface** with a hypothetical "XBIN" format:
InputFile (size/tell/seek/read\_bytes/read\_bytes\_at/read\_string/filename/handle),
AcceptResult with priority and processor hint,
LoaderOptions (supports\_reload, requires\_processor),
multi-segment creation with varied types/bitness/permissions,
file\_to\_database and memory\_to\_database,
BSS gap filling, overlapping segment detection,
entry point registration with type application,
fixup injection for relocatable binaries,
save callback (capability query + write),
and move/rebase callback (program-wide + single segment).

### `procmod/advanced_procmod.cpp` — Full ISA processor module

Exercises the **full processor surface** with a hypothetical "XRISC-32" ISA:
16 registers with segment register assignment,
complete instruction descriptor table with InstructionFeature flags,
AssemblerInfo with directive set, ProcessorFlag bitmask construction,
analyze() with instruction decode and operand classification,
emulate() with xref creation/flow analysis/data refs,
output\_instruction() and output\_operand(),
**all 15 optional callbacks**: is\_call, is\_return, may\_be\_function,
is\_sane\_instruction, is\_indirect\_jump, is\_basic\_block\_end,
create\_function\_frame, adjust\_function\_bounds,
analyze\_function\_prolog, calculate\_stack\_pointer\_delta,
get\_return\_address\_size, detect\_switch with SwitchDescription,
calculate\_switch\_cases with SwitchCase, create\_switch\_references,
and on\_new\_file/on\_old\_file notifications.

## Building

By default, examples are listed as source-only targets. To build addon binaries:

```bash
cmake -S . -B build -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON
cmake --build build
```
