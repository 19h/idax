# idax API Reference Index

Public headers:

| Header | Description |
|--------|-------------|
| `include/ida/idax.hpp` | Master include — pulls in all domain headers |
| `include/ida/error.hpp` | Error model: `Result<T>`, `Status`, `Error`, `ErrorCategory` |
| `include/ida/core.hpp` | Shared option structs and cross-cutting type aliases |
| `include/ida/diagnostics.hpp` | Logging levels, counters, diagnostic message helpers |
| `include/ida/address.hpp` | Address predicates, item traversal, range iteration, predicate search |
| `include/ida/data.hpp` | Read/write/patch/define bytes, typed values, owned custom type/format lifecycle and creation, configurable copied string-list inventory, binary pattern search |
| `include/ida/database.hpp` | Open/save/close, runtime/plugin policy init options, metadata (input path, IDB path, file type/compiler/imports, raw/verified processor identity, normalized processor profile), snapshots, file/memory transfer |
| `include/ida/path.hpp` | Portable path helpers (`basename`, `dirname`, `is_directory`) for plugin-side file/path UI workflows |
| `include/ida/segment.hpp` | Segment CRUD, properties, permissions, iteration, default segment-register seeding |
| `include/ida/function.hpp` | Function CRUD, chunks, frames, register variables, callers/callees, outlined-flag helpers, prototype export/application |
| `include/ida/instruction.hpp` | Decode/create, operand access + structured operand metadata (`byte_width`, `register_name`, `register_category`, `is_read`, `is_written`), representation controls including opaque named enum apply/readback and copied root/member-name struct-offset paths, conflict-safe exact-member path ensure, xref conveniences; Node and Rust snapshots preserve both access-mode booleans |
| `include/ida/name.hpp` | Set/get/force/remove names, filtered copied inventories, address-based and arbitrary-symbol demangling, resolution, properties |
| `include/ida/xref.hpp` | Unified reference model, typed code/data refs, add/remove/enumerate |
| `include/ida/comment.hpp` | Regular/repeatable comments, anterior/posterior lines, bulk operations |
| `include/ida/search.hpp` | Text (with regex), immediate, binary pattern, structural search |
| `include/ida/analysis.hpp` | Auto-analysis control, scheduling, waiting |
| `include/ida/problem.hpp` | Typed analysis-problem kinds, copied optional descriptions, ordered lookup, names, recording, removal, and presence |
| `include/ida/exception.hpp` | Opaque architecture-independent C++/SEH regions with fragmented ranges, semantic handlers, membership, and mutation |
| `include/ida/lumina.hpp` | Lumina connection helpers and metadata pull/push wrappers |
| `include/ida/undo.hpp` | Opaque named restore points, copied optional action labels, and undo/redo execution |
| `include/ida/type.hpp` | Type construction, copied pointer details and metadata-preserving shifted-parent copies, explicit forward-declaration classification and ordinal-preserving complete-UDT replacement, structs/unions/members, opaque exact-member persistent informational-reference ensure/readback, metadata-preserving function-argument and return replacement, apply/retrieve, bulk declaration import/rendering, dependency-ordered declaration snapshots, used-member trimming, DOT type graph rendering, type libraries (`ensure_named_type`, import/apply named helpers) |
| `include/ida/parser.hpp` | Third-party source-parser selection by name/language, copied identity and options, arguments, source/file ingestion, and semantic parse reports/options |
| `include/ida/directory.hpp` | Opaque access to all eight standard database trees with copied entries, directory/item mutation, ordering, search, folding, and deterministic partial bulk reports |
| `include/ida/registry.hpp` | Copyable scoped persistent-store identities; typed string, binary, signed 32-bit integer, and boolean values; copied child/value inventories; ordered string lists; value/key/tree deletion |
| `include/ida/registers.hpp` | Named register-value tracking with closed states, copied candidates/origins, constants, stack deltas, nearest-of-two selection, and semantic cache notifications |
| `include/ida/entry.hpp` | Entry point enumeration, add/rename, forwarders |
| `include/ida/fixup.hpp` | Fixup descriptors, traversal, custom fixup handlers |
| `include/ida/plugin.hpp` | Plugin base class, wrapper-owned action registration/activation, move-only `ScopedHotkey`, counted wrapper-managed menu/toolbar attachment with deterministic detach errors, popup attachment, action-context host bridges, Local Types `TypeRef` snapshots |
| `include/ida/loader.hpp` | Loader base class, InputFile abstraction, registration macro |
| `include/ida/processor.hpp` | Processor base class, typed analysis details, tokenized output context, switch detection |
| `include/ida/debugger.hpp` | Process lifecycle, backend discovery/selection, breakpoints, memory, registers, appcall/executor APIs, typed event subscriptions |
| `include/ida/ui.hpp` | Messages, dialogs (`ask_text`, markup-only and typed `ask_form`, `FormBuilder`; fixed-shape Node/Rust typed-form entrypoints for audited dialog packs), clipboard helpers using Qt when enabled or external host commands otherwise, wait-box progress UI, current-widget polling, choosers, timers, UI event subscriptions, popup-ready attachment helpers for dynamic and already-registered actions |
| `include/ida/graph.hpp` | Graph objects, node/edge CRUD, flow charts, basic blocks, switch-table metadata |
| `include/ida/event.hpp` | Typed IDB subscriptions, generic filtering/routing, RAII guards |
| `include/ida/decompiler.hpp` | Decompile (with structured failure details), referenced-type collection (`collect_referenced_types`), scoped Hex-Rays ownership (`initialize`, `ScopedSession`), pseudocode/microcode extraction, semantic persisted pseudocode comments (`CommentPosition`, copied `PseudocodeComment` enumeration, explicit save/orphan lifecycle), owned maturity-explicit function graphs with opt-in direct-call analysis and copied processor-register evidence for register operands, maturity/pseudocode-switch/popup subscriptions (`on_switch_pseudocode`, `on_populating_popup`), cache-dirty helpers, typed decompiler-view sessions (`DecompilerView`, `view_from_host`, `view_for_function`, `current_view`), read-only ctree helpers (`ExpressionView::helper_name`, `type_declaration`, `type_byte_width`, `pointed_type_byte_width`, `member_name`, `third`, `is_assignment_lhs`, parent-chain snapshots, stable `LocalVariable::index` and direct variable lookup), lvar user-settings snapshots, serializable lvar user settings (`LocalVariableUserSetting`, `saved_user_lvar_settings`, `apply_user_lvar_setting`), variable comment writeback, microcode-filter registration, typed instruction/operand emission (including nested/block/local-variable forms), policy-aware low-level emits, microblock lifecycle helpers (`block_instruction_count`, `has_instruction_at_index`, `remove_instruction_at_index`, tracked last-emitted query/remove), microcode introspection (`instruction`, `instruction_at_index`, `last_emitted_instruction`), typed helper-call builders (register/operand/micro-operand destinations), and advanced call-shaping/location hints (calling convention, role, return location/type, register-list + visible-memory controls). |
| `include/ida/lines.hpp` | Tagged text/color helpers plus copied source-file metadata with checked half-open range add/query/remove operations |
| `include/ida/storage.hpp` | Netnode abstraction, alt/sup/hash/blob operations |

See also:

- `docs/quickstart/` — Plugin, loader, processor module skeletons
- `docs/cookbook/` — Common task recipes and disassembly workflows
- `docs/cookbook/microcode_lifting.md` — Custom microcode lifting and Hex-Rays filters
- `docs/cookbook/undo_redo.md` — Named restore points and cross-binding undo/redo semantics
- `docs/cookbook/analysis_problems.md` — Typed analysis-problem recording and traversal
- `docs/cookbook/exception_regions.md` — Architecture-independent C++/SEH metadata round trips
- `docs/cookbook/source_parsers.md` — Third-party parser selection, configuration, and type ingestion
- `docs/cookbook/directory_trees.md` — Built-in tree traversal, organization, ordering, and partial bulk operations
- `docs/cookbook/persistent_registry.md` — Scoped typed plugin configuration, ordered lists, and cleanup
- `docs/cookbook/register_tracking.md` — Backward register values, stack-relative candidates, nearest selection, and cache coherence
- `docs/migration/` — Legacy SDK to idax migration map and snippets
- `docs/tutorial/first_contact.md` — 5-step beginner walkthrough
- `docs/tutorial/function_discovery_events.md` — event-hook lifecycle for new-function workflows
- `docs/tutorial/rust_plugin_refs_to.md` — Rust plugin action wiring for incoming-xref analysis
- `docs/tutorial/call_graph_traversal.md` — transitive caller traversal patterns
- `docs/tutorial/multi_binary_signature_generation.md` — multi-sample signature generation pipeline
- `docs/tutorial/distributed_analysis_consistency.md` — distributed consistency and merge design
- `docs/tutorial/safety_performance_tradeoffs.md` — idax-wrapper vs raw-SDK trade-offs and recovery
- `docs/surface_selection_guide.md` — choose between C++ wrapper, safe Rust, and raw FFI
- `docs/namespace_topology.md` — Complete namespace/type inventory map
- `docs/compatibility_matrix.md` — OS/compiler validation matrix and commands
- `docs/storage_migration_caveats.md` — Netnode migration safety notes
- `docs/port_gap_audit_examples.md` — consolidated real-world port audits and remaining parity gaps
- `docs/codedump_migration_checklist.md` — ida-cdump gap-to-idax migration checklist and remaining Phase 22 tasks
