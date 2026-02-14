# idax API Reference Index

Public headers:

| Header | Description |
|--------|-------------|
| `include/ida/idax.hpp` | Master include — pulls in all domain headers |
| `include/ida/error.hpp` | Error model: `Result<T>`, `Status`, `Error`, `ErrorCategory` |
| `include/ida/core.hpp` | Shared option structs and cross-cutting type aliases |
| `include/ida/diagnostics.hpp` | Logging levels, counters, diagnostic message helpers |
| `include/ida/address.hpp` | Address predicates, item traversal, range iteration, predicate search |
| `include/ida/data.hpp` | Read/write/patch/define bytes, typed values, string extraction, binary pattern search |
| `include/ida/database.hpp` | Open/save/close, runtime/plugin policy init options, metadata (file type/compiler/imports), snapshots, file/memory transfer |
| `include/ida/segment.hpp` | Segment CRUD, properties, permissions, iteration, default segment-register seeding |
| `include/ida/function.hpp` | Function CRUD, chunks, frames, register variables, callers/callees, outlined-flag helpers |
| `include/ida/instruction.hpp` | Decode/create, operand access, representation controls, xref conveniences |
| `include/ida/name.hpp` | Set/get/force/remove names, demangling, resolution, properties |
| `include/ida/xref.hpp` | Unified reference model, typed code/data refs, add/remove/enumerate |
| `include/ida/comment.hpp` | Regular/repeatable comments, anterior/posterior lines, bulk operations |
| `include/ida/search.hpp` | Text (with regex), immediate, binary pattern, structural search |
| `include/ida/analysis.hpp` | Auto-analysis control, scheduling, waiting |
| `include/ida/lumina.hpp` | Lumina connection helpers and metadata pull/push wrappers |
| `include/ida/type.hpp` | Type construction, structs/unions/members, apply/retrieve, type libraries |
| `include/ida/entry.hpp` | Entry point enumeration, add/rename, forwarders |
| `include/ida/fixup.hpp` | Fixup descriptors, traversal, custom fixup handlers |
| `include/ida/plugin.hpp` | Plugin base class, action registration, menu/toolbar attachment |
| `include/ida/loader.hpp` | Loader base class, InputFile abstraction, registration macro |
| `include/ida/processor.hpp` | Processor base class, typed analysis details, tokenized output context, switch detection |
| `include/ida/debugger.hpp` | Process lifecycle, breakpoints, memory, registers, appcall/executor APIs, typed event subscriptions |
| `include/ida/ui.hpp` | Messages, dialogs, choosers, timers, UI event subscriptions |
| `include/ida/graph.hpp` | Graph objects, node/edge CRUD, flow charts, basic blocks |
| `include/ida/event.hpp` | Typed IDB subscriptions, generic filtering/routing, RAII guards |
| `include/ida/decompiler.hpp` | Decompile (including structured failure details), pseudocode/microcode extraction, maturity subscriptions, cache-dirty helpers, microcode-filter registration, typed microcode context/helper-call builders (integer + float immediates) + call options/location hints (register/pair/offset/stack/static/scattered), variable rename/retype, ctree visitor, comment/orphan workflows, address mapping |
| `include/ida/storage.hpp` | Netnode abstraction, alt/sup/hash/blob operations |

See also:

- `docs/quickstart/` — Plugin, loader, processor module skeletons
- `docs/cookbook/` — Common task recipes and disassembly workflows
- `docs/migration/` — Legacy SDK to idax migration map and snippets
- `docs/tutorial/first_contact.md` — 5-step beginner walkthrough
- `docs/namespace_topology.md` — Complete namespace/type inventory map
- `docs/compatibility_matrix.md` — OS/compiler validation matrix and commands
- `docs/storage_migration_caveats.md` — Netnode migration safety notes
