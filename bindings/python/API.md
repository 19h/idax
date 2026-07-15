# IDAX Python API reference

Import domains from the package root (`from idax import database, function`) or
from their stable module paths. Exact callable overloads, properties, callback
protocols, and enum members are defined by the shipped `.pyi` files and are
checked with strict mypy.

| Domain | Functions | Types | Primary surface |
|---|---:|---:|---|
| `address` | 24 | 4 | Address classification, item bounds, navigation, searches, lazy ranges. |
| `analysis` | 13 | 0 | Auto-analysis state, scheduling, waiting, cancellation, decision reset. |
| `comment` | 19 | 0 | Ordinary/repeatable and anterior/posterior comments. |
| `data` | 70 | 12 | Bytes, patches, typed values, strings, custom data type/format callbacks. |
| `database` | 32 | 10 | Runtime lifecycle, open/save/close, metadata, processors, snapshots, imports. |
| `debugger` | 65 | 14 | Backends, processes/threads, memory/registers, breakpoints, appcalls, events. |
| `decompiler` | 32 | 56 | Hex-Rays sessions, pseudocode, ctree, local variables, microcode, events. |
| `diagnostics` | 7 | 2 | Logging, enriched errors, invariants, performance counters. |
| `entry` | 8 | 1 | Entry-point inventory and mutation. |
| `event` | 19 | 10 | Typed IDB subscriptions and scoped unsubscription. |
| `fixup` | 13 | 5 | Relocation lookup/traversal and custom handlers. |
| `function` | 38 | 6 | Functions, chunks, frames, callers/callees, attributes, mutation. |
| `graph` | 9 | 9 | In-memory graphs, flow charts, switch tables, graph viewers. |
| `instruction` | 39 | 7 | Decode, operands, text, register effects, xrefs, assembly/mutation. |
| `lines` | 9 | 2 | Source mappings and IDA tagged-text processing. |
| `loader` | 7 | 11 | Python loader subclasses, input/output adapters, database ingestion. |
| `lumina` | 5 | 4 | Connection query and metadata pull/push. |
| `name` | 16 | 3 | Name lookup/mutation, demangling, inventory, properties. |
| `path` | 3 | 0 | Portable `os.PathLike`-aware path operations. |
| `plugin` | 14 | 8 | Plugin subclasses, actions, hotkeys, opaque action/host contexts. |
| `processor` | 0 | 19 | Processor descriptors, flags/features, output context, subclass callbacks. |
| `search` | 8 | 4 | Text, immediate, binary-pattern, code/data/defined searches. |
| `segment` | 22 | 4 | Segment snapshots, lookup, traversal, selectors, mutation. |
| `storage` | 0 | 1 | Opaque persistent node alt/sup/hash/blob storage. |
| `type` | 15 | 17 | Type construction, parsing, introspection, rendering, application. |
| `ui` | 65 | 26 | Dialogs, forms, messages, widgets, choosers, viewers, timers, events. |
| `xref` | 22 | 5 | Code/data cross-reference descriptors, queries, iteration, mutation. |

Shared modules:

- `idax.core`: `BAD_ADDRESS`, address ranges, search/demangle options, and
  processor identifiers/profiles.
- `idax.error`: `IdaxError`, category-specific subclasses, `Error`, and
  `ErrorCategory`.

## Resource and callback rules

- Use resources such as scoped subscriptions, hotkeys, decompiled functions,
  wait boxes, choosers, and timers as context managers where available.
- Explicitly unregister global callbacks before unloading the owning Python
  extension or plugin.
- Do not retain callback-scoped contexts for later use; checked access raises
  `ConflictError` after callback return.
- Do not close a database while decompiler-owned results remain live.
- External idalib code must call IDAX from its initializing process thread.

## Authoring boundaries

Python can subclass `plugin.Plugin`, `loader.Loader`, `processor.Processor`,
`debugger.AppcallExecutor`, `decompiler.MicrocodeFilter`, graph viewer
interfaces, and UI chooser/viewer interfaces. Native registrations retain the
Python instance until deterministic teardown.

The C++ `IDAX_PLUGIN`, `IDAX_LOADER`, and `IDAX_PROCESSOR` macros create binary
entry points at compile time and therefore have no runtime Python equivalent.
Python-hosted authoring uses the exposed classes and registration functions;
shipping a standalone native IDA binary entry point remains a C++ packaging
operation.

## Optional capabilities

Debugger backends, Lumina service access, Hex-Rays decompilers, GUI widgets,
clipboard backends, and modal dialogs depend on the installed IDA product,
license, process mode, and host environment. Capability queries return the
observed state; absence does not authorize an ABI fallback.
