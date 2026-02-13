# idax Namespace Topology

This document shows the complete public API surface organized by namespace, with type and function counts for orientation.

## Visual Overview

```
ida::                                     (root: type aliases, error model, options)
 |
 |-- ida::address        Predicates, traversal, range iteration          [1 struct, 1 enum, 2 classes, ~12 free fns]
 |-- ida::data           Read/write/patch/define bytes, patterns         [~30 free fns, 2 templates]
 |-- ida::database       Open/save/close, metadata, snapshots            [6 structs, ~19 free fns]
 |
 |-- ida::segment        CRUD, properties, permissions                   [1 enum, 1 struct, 3 classes, ~13 free fns]
 |-- ida::function       CRUD, chunks, frames, register variables        [3 structs, 4 classes, ~25 free fns]
 |-- ida::instruction    Decode/create, operands, representation         [1 enum, 2 classes, ~25 free fns]
 |
 |-- ida::name           Set/get/force/remove, demangling                [1 enum, ~11 free fns]
 |-- ida::xref           Unified refs, typed code/data categories        [3 enums, 1 struct, ~10 free fns]
 |-- ida::comment        Regular/repeatable, anterior/posterior           [~15 free fns]
 |
 |-- ida::type           Type construction, structs/unions, libraries     [1 struct, 1 class, ~9 free fns]
 |-- ida::entry          Entry points: list, add, rename                 [1 struct, ~5 free fns]
 |-- ida::fixup          Fixup descriptors, traversal, custom handlers   [2 enums, 2 structs, 2 classes, ~11 free fns]
 |
 |-- ida::search         Text/immediate/binary pattern search            [1 enum, 1 struct, ~7 free fns]
 |-- ida::analysis       Auto-analysis control, scheduling               [~7 free fns]
 |-- ida::lumina         Lumina pull/push and connection control         [3 enums, 1 struct, ~8 free fns]
 |
 |-- ida::event          Typed IDB subscriptions, generic routing        [1 enum, 1 struct, 1 class, ~10 free fns]
 |-- ida::plugin         Plugin base, actions, menu/toolbar              [2 structs, 1 class, ~4 free fns]
 |-- ida::loader         Loader base, InputFile, registration macro      [2 structs, 2 classes, ~5 free fns]
 |-- ida::processor      Processor base, descriptors, typed analysis/output [8 enums, 9 structs, 2 classes, IDAX_PROCESSOR]
 |
 |-- ida::debugger       Process/thread control, request queue, events    [2 enums, 4 structs, 1 class, ~40 free fns]
|-- ida::decompiler     Decompile, pseudocode/microcode, ctree, variable retype/comments [3 enums, 3 structs, 4 classes, ~4 free fns]
|-- ida::ui             Messages, dialogs, widgets, custom viewers       [1 enum, 4 structs, 2 classes, ~30 free fns]
|-- ida::graph          Graph objects, viewers, flow charts, layouts     [2 enums, 4 structs, 2 classes, ~9 free fns]
 |
 |-- ida::storage        Netnode abstraction, id/open-by-id, alt/sup/hash/blob [1 class (Node), ~18 methods]
 |-- ida::diagnostics    Logging, counters, diagnostic messages          [1 enum, ~5 free fns]
```

## Namespace Groupings by Domain

### Core Primitives (root `ida::`)

Defined across `error.hpp`, `address.hpp`, and `core.hpp`:

| Symbol | Kind | Header |
|--------|------|--------|
| `Address` | type alias (`uint64_t`) | `address.hpp` |
| `AddressDelta` | type alias (`int64_t`) | `address.hpp` |
| `AddressSize` | type alias (`uint64_t`) | `address.hpp` |
| `BadAddress` | constant | `address.hpp` |
| `Result<T>` | alias (`std::expected<T, Error>`) | `error.hpp` |
| `Status` | alias (`std::expected<void, Error>`) | `error.hpp` |
| `Error` | struct | `error.hpp` |
| `ErrorCategory` | enum | `error.hpp` |
| `ok()` | free function | `error.hpp` |
| `OperationOptions` | struct | `core.hpp` |
| `RangeOptions` | struct | `core.hpp` |
| `WaitOptions` | struct | `core.hpp` |

### Analysis Domains (read-heavy)

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::address` | Navigation and predicates | `Range`, `ItemRange`, `Predicate` |
| `ida::data` | Byte-level access | (free functions only) |
| `ida::database` | Database lifecycle | `Snapshot`, `RuntimeOptions`, `PluginLoadPolicy`, `CompilerInfo`, `ImportModule`, `ImportSymbol` |
| `ida::segment` | Segment management | `Segment`, `Permissions`, `Type` (+ default segment-register seeding helpers) |
| `ida::function` | Function analysis | `Function`, `StackFrame`, `Chunk` |
| `ida::instruction` | Instruction decoding | `Instruction`, `Operand`, `OperandType` |

### Metadata Domains (read/write)

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::name` | Symbol naming | `DemangleForm` |
| `ida::xref` | Cross-references | `Reference`, `CodeType`, `DataType` |
| `ida::comment` | Comments | (free functions only) |
| `ida::type` | Type system | `TypeInfo`, `Member` |
| `ida::entry` | Entry points | `EntryPoint` |
| `ida::fixup` | Relocations | `Descriptor`, `CustomHandler`, `Type` |

### Search and Analysis

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::search` | Pattern matching | `Direction`, `TextOptions` |
| `ida::analysis` | Auto-analysis | (free functions only) |
| `ida::lumina` | Lumina metadata sync | `Feature`, `PushMode`, `OperationCode`, `BatchResult` |

### Module Authoring

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::plugin` | Plugin development | `Plugin`, `Action`, `Info` |
| `ida::loader` | Loader development | `Loader`, `InputFile`, `AcceptResult` |
| `ida::processor` | Processor modules | `Processor`, `ProcessorInfo`, `AnalyzeDetails`, `OutputContext` |

### Interactive and Advanced

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::debugger` | Debugging | `ProcessState`, `ThreadInfo`, `RegisterInfo`, `ScopedSubscription` |
| `ida::decompiler` | Decompilation | `DecompiledFunction` (pseudocode+microcode), `DecompileFailure`, `CtreeVisitor`, `ExpressionView` |
| `ida::ui` | User interface | `Widget`, `Chooser`, `Event`, `ShowWidgetOptions`, `ScopedSubscription` |
| `ida::graph` | Graph visualization | `Graph`, `BasicBlock`, `GraphCallback` |
| `ida::event` | IDB event routing | `Event`, `EventKind`, `ScopedSubscription` |
| `ida::storage` | Persistent key-value | `Node` |

## Header Dependency Map

No public header includes any SDK header. The only internal dependency is:

- `function.hpp` forward-declares `ida::type::TypeInfo`
- All other public headers are self-contained (depend only on `error.hpp` / `address.hpp`)

The internal bridge (`src/detail/sdk_bridge.hpp`) is the single point where SDK headers are included. It is never exposed in any public header.
