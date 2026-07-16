# idax Namespace Topology

This document shows the complete public API surface organized by namespace, with type and function counts for orientation.

## Visual Overview

```
ida::                                     (root: type aliases, error model, options)
 |
 |-- ida::address        Predicates, traversal, range iteration          [1 struct, 1 enum, 2 classes, ~12 free fns]
 |-- ida::data           Read/write/patch/define/custom data, strings   [1 enum, 11 structs, ~60 free fns, 2 templates]
 |-- ida::database       Open/save/close, metadata, snapshots            [1 enum, 6 structs, ~25 free fns]
 |-- ida::path           Portable path splitting and directory checks    [~3 free fns]
 |
 |-- ida::segment        CRUD, properties, permissions                   [1 enum, 1 struct, 3 classes, ~13 free fns]
|-- ida::function       CRUD, chunks, frames, register variables        [3 structs, 4 classes, ~29 free fns]
 |-- ida::instruction    Decode/create, opaque operand representation    [3 enums, 2 structs, 2 classes, free-fn surface]
 |
 |-- ida::name           Set/get/force/remove, inventories, demangling   [1 enum, 2 structs, ~13 free fns]
 |-- ida::xref           Unified refs, typed code/data categories        [3 enums, 1 struct, ~10 free fns]
 |-- ida::comment        Regular/repeatable, anterior/posterior           [~15 free fns]
 |
 |-- ida::type           Type construction, rich layout metadata, libraries [8 structs, 3 enums, 1 class, ~9 free fns]
 |-- ida::entry          Entry points: list, add, rename                 [1 struct, ~5 free fns]
 |-- ida::fixup          Fixup descriptors, traversal, custom handlers   [2 enums, 2 structs, 2 classes, ~11 free fns]
 |
 |-- ida::search         Text/immediate/binary pattern search            [1 enum, 1 struct, ~7 free fns]
 |-- ida::analysis       Auto-analysis control, scheduling               [~7 free fns]
 |-- ida::problem        Typed analysis-problem lists                    [1 enum, 6 free fns]
 |-- ida::exception      Opaque C++/SEH exception regions                [3 enums, 7 structs, 5 free fns]
 |-- ida::parser         Third-party source parsing and type ingestion   [2 enums, 2 structs, 9 free fns]
 |-- ida::directory      Built-in database organization trees            [3 enums, 3 structs, 1 class]
 |-- ida::registry       Scoped persistent plugin configuration           [1 enum, 1 struct, 1 class]
 |-- ida::registers      Named register-value tracking                    [2 enums, 4 structs, 8 free fns]
 |-- ida::lumina         Lumina pull/push and connection control         [3 enums, 1 struct, ~8 free fns]
 |-- ida::undo           Named restore points and undo/redo state        [5 free fns]
 |
 |-- ida::event          Typed IDB change snapshots, generic routing     [3 enums, 6 structs, 1 class, ~19 free fns]
 |-- ida::plugin         Plugin base, actions, scoped hotkeys, attachments [5 structs, 2 classes, ~14 free fns]
 |-- ida::loader         Loader base, InputFile, registration macro      [2 structs, 2 classes, ~5 free fns]
 |-- ida::processor      Loadable processor bridge, descriptors, typed analysis/output [9 enums, 9 structs, 2 classes, IDAX_PROCESSOR]
 |
 |-- ida::debugger       Process/thread control, backend routing, request queue, events [2 enums, 5 structs, 1 class, ~42 free fns]
|-- ida::decompiler     Decompile, owned/call-analyzed microcode graphs, ctree, events/cache/helpers [16 enums, 19 structs, 9 classes, event/free-fn surface]
 |-- ida::lines          Tagged text plus source-file address mappings     [1 enum, 1 struct, ~9 free fns, constants]
|-- ida::ui             Messages, dialogs, wait boxes, widgets/viewers   [1 enum, 5 structs, 3 classes, widget/event free-fn surface]
|-- ida::graph          Graph objects, viewers, flow charts, layouts     [2 enums, 5 structs, 2 classes, ~10 free fns]
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
| `ida::data` | Byte-level, registered custom-data, and string-inventory access | `TypedValue`, `StringListOptions`, `StringLiteral`, `CustomDataTypeId`, `CustomDataFormatId`, owned definitions, copied metadata/item snapshots |
| `ida::database` | Database lifecycle and normalized target metadata | `ProcessorId`, `ProcessorProfile`, `Snapshot`, `RuntimeOptions`, `PluginLoadPolicy`, `CompilerInfo`, `ImportModule`, `ImportSymbol` |
| `ida::path` | Portable path helpers | (free functions only) |
| `ida::segment` | Segment management | `Segment`, `Permissions`, `Type` (+ default segment-register seeding helpers) |
| `ida::function` | Function analysis, printable prototype readback, and conservative prototype application | `Function`, `StackFrame`, `Chunk` |
| `ida::instruction` | Instruction decoding, processor-reported access modes and encoded-value byte positions, opaque named enum representations, and copied root/member-name struct-offset paths | `Instruction`, `Operand`, `OperandType`, `OperandFormat`, `RegisterCategory`, `OperandEnum`, `StructOffsetPath` |

### Metadata Domains (read/write)

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::name` | Symbol naming, filtered inventories, and address-free demangling | `ListOptions`, `Entry`, `DemangleForm` |
| `ida::xref` | Cross-references | `Reference`, `CodeType`, `DataType` |
| `ida::comment` | Comments | (free functions only) |
| `ida::type` | Type system, including copied shifted-pointer metadata, explicit forward classification/ordinal-preserving replacement, opaque exact-member persistent references, metadata-preserving pointer/prototype edits, and UDT semantic mutation | `TypeInfo`, `PointerDetails`, `TypeKind`, `EnumRadix`, `Member`, `FunctionDetails`, `EnumDetails`, `UdtDetails` |
| `ida::entry` | Entry points | `EntryPoint` |
| `ida::fixup` | Relocations | `Descriptor`, `CustomHandler`, `Type` |

### Search and Analysis

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::search` | Pattern matching | `Direction`, `TextOptions` |
| `ida::analysis` | Auto-analysis | (free functions only) |
| `ida::problem` | Typed analysis-problem lists | `Kind` |
| `ida::exception` | Architecture-independent exception regions | `BlockDefinition`, `Block`, `CatchHandler`, `SehHandler`, `Location` |
| `ida::parser` | Third-party parser selection/configuration and local-type ingestion | `Language`, `InputKind`, `ParseOptions`, `ParseReport` |
| `ida::directory` | Built-in database organization trees | `Kind`, `Entry`, `BulkReport`, `Tree` |
| `ida::registry` | Scoped persistent plugin configuration | `ValueKind`, `StringListUpdate`, `Store` |
| `ida::registers` | Backward register-value analysis | `TrackingState`, `ValueOrigin`, `ValueCandidate`, `TrackedValue`, `NearestValue` |
| `ida::lumina` | Lumina metadata sync | `Feature`, `PushMode`, `OperationCode`, `BatchResult` |
| `ida::undo` | Named restore points and undo/redo state | (free functions only) |

### Module Authoring

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::plugin` | Plugin development | `Plugin`, `Action`, `ActionContext`, `ScopedHotkey`, `Info` |
| `ida::loader` | Loader development | `Loader`, `InputFile`, `AcceptResult` |
| `ida::processor` | Processor modules | `Processor`, `ProcessorInfo`, `ProcessorFlag2`, `AnalyzeDetails`, `OutputContext` |

### Interactive and Advanced

| Namespace | Primary Focus | Key Types |
|-----------|---------------|-----------|
| `ida::debugger` | Debugging | `ProcessState`, `BackendInfo`, `ThreadInfo`, `RegisterInfo`, `AppcallRequest`, `AppcallValue`, `AppcallExecutor`, `ScopedSubscription` |
| `ida::decompiler` | Decompilation, semantic persisted comments, pseudocode-switch events, and owned graphs with copied register identities plus destination-modification semantics | `ScopedSession`, `DecompiledFunction` (pseudocode+formatted microcode), `CommentPosition`, `PseudocodeComment`, `LvarSnapshot`, `DecompileFailure`, `MaturityEvent`, `PseudocodeEvent`, `PopulatingPopupEvent`, `MicrocodeOpcode`, `MicrocodeOperandKind`, `MicrocodeOperand`, `MicrocodeInstruction`, `MicrocodeMaturity`, `MicrocodeGenerationOptions`, `MicrocodeFunctionArgument`, `MicrocodeBlock`, `MicrocodeFunction`, `MicrocodeInsertPolicy`, `MicrocodeFunctionRole`, `MicrocodeArgumentFlag`, `MicrocodeValue`, `MicrocodeLocationPart`, `MicrocodeValueLocation`, `MicrocodeRegisterRange`, `MicrocodeMemoryRange`, `MicrocodeCallOptions`, `MicrocodeFilter`, `MicrocodeContext`, `ScopedSubscription`, `ScopedMicrocodeFilter` |
| `ida::lines` | Tagged text/color plus source mappings | `SourceFile`, `Color`, `kColorOn`, `kColorOff`, `kColorEsc`, `kColorInv`, `kColorAddr`, `kColorAddrSize` |
| `ida::ui` | User interface and current-widget polling | `Widget`, `Chooser`, `WaitBox`, `Progress`, `FormBuilder`, typed form bindings, `Event`, `ShowWidgetOptions`, `ScopedSubscription` |
| `ida::graph` | Graph visualization | `Graph`, `BasicBlock`, `GraphCallback` |
| `ida::event` | Mutation-safe IDB event routing | `Event`, `EventKind`, `SegmentMovedEvent`, `ItemCreatedEvent`, `ItemsDestroyedEvent`, `ExtraCommentChangedEvent`, `LocalTypesChangedEvent`, `ScopedSubscription` |
| `ida::storage` | Persistent key-value | `Node` |

## Header Dependency Map

Most public headers avoid SDK includes. `include/ida/ui.hpp` is the deliberate
exception for typed `ask_form`: the SDK consumes a true C vararg pointer pack,
so the forwarding template must see the SDK form types and inline
`ask_form(...)` declaration. The header defines `USE_DANGEROUS_FUNCTIONS`
only while including the SDK headers to avoid exporting the SDK's dangerous C
function macro rewrites through `ida/idax.hpp`.

- `function.hpp` forward-declares `ida::type::TypeInfo`
- All other public headers are self-contained (depend only on `error.hpp` / `address.hpp`)

The internal bridge (`src/detail/sdk_bridge.hpp`) remains the common
implementation-side SDK include point for non-template wrapper code.
