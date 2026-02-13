# SDK Domain Coverage Matrix

Date: 2026-02-13 (initial Phase 10 baseline)

This document tracks wrapper parity against the IDA SDK by two axes:

1. Public `idax` domain namespaces (`ida::segment`, `ida::function`, ...)
2. Major SDK capability families (segment management, decompiler workflows, debugger control, ...)

Status values:

- `covered`: high-confidence parity for the intended family scope, with supporting tests/docs.
- `partial`: meaningful support exists, but migration still requires additional APIs or behavioral hardening.
- `missing`: no intentional wrapper surface yet.

Tracking rules:

- Every row must include concrete symbol references.
- Every `partial`/`missing` row must define closure criteria and required evidence.
- Any row status changes must also update `claude.md` TODO state + Progress Ledger + Findings/Decision logs as applicable.

## A) Domain Coverage Matrix (one row per public domain)

| Domain | Status | Concrete idax symbol references | Primary SDK families | Closure criteria (`partial`/`missing`) | Required evidence |
|---|---|---|---|---|---|
| `ida::error` | `covered` | `ida::Error`, `ida::ErrorCategory`, `ida::Result<T>`, `ida::Status`, `ida::ok()` | Cross-cutting error transport | Maintain model invariants and category usage for all new APIs | `tests/unit/idax_unit_test`, `tests/unit/api_surface_parity_test.cpp` |
| `ida::core` | `partial` | `ida::OperationOptions`, `ida::RangeOptions`, `ida::WaitOptions` | Cross-cutting option semantics | Normalize adoption across long-running and range-based APIs; document policy usage per domain | Unit tests for option propagation + docs updates |
| `ida::diagnostics` | `partial` | `ida::diagnostics::log`, `set_log_level`, `assert_invariant`, `performance_counters` | Cross-cutting diagnostics | Expand integration points from local helpers to wrapper-wide consistency checks | Unit coverage + explicit diagnostics usage in adapter hot paths |
| `ida::address` | `covered` | `item_start`, `item_end`, `item_size`, `next_head`, `prev_head`, `next_defined`, `prev_defined`, `find_first`, `find_next`, `items`, `code_items`, `data_items`, `unknown_bytes` | Address flags/navigation (`ida.hpp`, `bytes.hpp`) | Closed in P10.2 (predicate ranges + discoverability aliases) | `smoke_test`, `tests/unit/api_surface_parity_test.cpp` |
| `ida::data` | `covered` | `read_*`, `write_*`, `patch_*`, `revert_patch`, `revert_patches`, `original_*`, `define_*`, `define_oword`, `define_tbyte`, `define_float`, `define_double`, `define_struct`, `undefine`, `read_string`, `read_value<T>`, `find_binary_pattern` | Byte IO + item definition (`bytes.hpp`, `offset.hpp`) | Closed in P10.2 (explicit patch revert + expanded define helpers) | `data_mutation_safety_test`, `tests/unit/api_surface_parity_test.cpp` |
| `ida::database` | `covered` | `init`, `open` (bool + `OpenMode` + `LoadIntent`), `open_binary`, `open_non_binary`, `save`, `close`, `file_to_database`, `memory_to_database`, `address_bounds`, `address_span`, `snapshots`, `set_snapshot_description` | Database lifecycle + loading (`idalib.hpp`, `loader.hpp`) | Closed in P10.2 (open/load intent convenience wrappers + metadata parity helpers) | `smoke_test`, `tests/unit/api_surface_parity_test.cpp` |
| `ida::segment` | `partial` | `create`, `remove`, `at`, `by_name`, `set_type`, `set_permissions`, `all`, `Segment::type` | Segment CRUD/properties (`segment.hpp`) | Add resize/move wrappers, segment comments, and first/last/next/prev traversal helpers | `segment_function_edge_cases_test`, added segment parity suite |
| `ida::function` | `partial` | `create`, `remove`, `chunks`, `tail_chunks`, `frame`, `sp_delta_at`, `define_stack_variable`, register-variable APIs | Function/frame/chunks (`funcs.hpp`, `frame.hpp`) | Add explicit reanalysis/update intent APIs and additional function-address iteration ergonomics | `segment_function_edge_cases_test`, expanded function parity tests |
| `ida::instruction` | `partial` | `decode`, `create`, `text`, `set_operand_*`, `get_forced_operand`, `code_refs_from`, `is_call`, `is_return` | Decode/output/operand representation (`ua.hpp`, `lines.hpp`) | Add missing classifiers (`is_jump`, `is_conditional_jump`) and richer operand text/format helpers | `instruction_decode_behavior_test`, `operand_and_text_test` |
| `ida::name` | `partial` | `set`, `force_set`, `remove`, `get`, `demangled`, `resolve`, `is_public`, `is_auto_generated` | Symbol naming/demangle (`name.hpp`) | Add identifier validation/sanitization and explicit user-defined vs auto naming introspection | `name_comment_xref_search_test`, new name parity tests |
| `ida::xref` | `partial` | `add_code`, `add_data`, `remove_code`, `refs_from`, `refs_to`, `ReferenceType` | Cross-reference mutation/enumeration (`xref.hpp`) | Add iterator/range-style traversal and richer typed filters | `name_comment_xref_search_test`, expanded xref behavior tests |
| `ida::comment` | `partial` | `get`, `set`, `append`, `remove`, `set_anterior_lines`, `set_posterior_lines`, `render` | Regular + extra-line comments (`lines.hpp`) | Add indexed line edit/remove helpers and lock render parity behaviors | `name_comment_xref_search_test`, comment render parity tests |
| `ida::type` | `partial` | `TypeInfo::from_declaration`, `create_struct`, `add_member`, `save_as`, `retrieve`, `apply_named_type`, `import_type` | Type system + local TIL (`typeinf.hpp`) | Expand function-type/calling-convention/enum workflows and higher-level construction helpers | `type_roundtrip_test`, additional type workflow integration |
| `ida::entry` | `partial` | `count`, `by_index`, `by_ordinal`, `add`, `rename` | Entry/ordinal management (`entry.hpp`) | Add forwarder management parity helpers | `smoke_test`, dedicated entry parity tests |
| `ida::fixup` | `partial` | `at`, `set`, `remove`, `first/next/prev`, `register_custom`, `find_custom`, `unregister_custom` | Relocations/fixups (`fixup.hpp`) | Expand descriptor fidelity (flags/base/signed variants) and range traversal helpers | `fixup_relocation_test`, custom fixup lifecycle tests |
| `ida::search` | `partial` | `text` (+ `TextOptions`), `immediate`, `binary_pattern`, `next_code`, `next_data`, `next_unknown` | Text/immediate/binary find (`search.hpp`) | Add missing direction/options parity and `next_error` helper | `name_comment_xref_search_test`, new search-option validation tests |
| `ida::analysis` | `partial` | `is_enabled`, `set_enabled`, `is_idle`, `wait`, `wait_range`, `schedule`, `schedule_range` | Auto-analysis queue control (`auto.hpp`) | Add explicit schedule-intent APIs (`schedule_code`, `schedule_function`, ...) and rollback wrappers | `smoke_test`, new analysis-control scenario tests |
| `ida::event` | `partial` | `on_segment_added`, `on_function_added`, `on_renamed`, `on_event`, `on_event_filtered`, `unsubscribe` | IDB event routing (`HT_IDB`) | Expand normalized event set and event-kind parity against migration needs | `event_stress_test`, typed+generic coexistence checks |
| `ida::plugin` | `partial` | `Plugin`, `register_action`, `attach_to_menu`, `attach_to_toolbar`, `attach_to_popup`, `ActionContext`, `IDAX_PLUGIN` | Plugin lifecycle + actions (`loader/plugin` + `kernwin.hpp`) | Add action detach helpers and finalize context-aware ergonomics/docs | `loader_processor_scenario_test`, plugin examples/doc parity |
| `ida::loader` | `partial` | `InputFile`, `Loader::accept/load/save/move_segment`, `file_to_database`, `memory_to_database`, `IDAX_LOADER` | Loader module authoring (`loader.hpp`) | Expand archive/member/reload/save advanced scenarios | `loader_processor_scenario_test`, loader scenario expansion |
| `ida::processor` | `partial` | `ProcessorInfo`, `InstructionDescriptor`, `Processor` optional hooks, `SwitchDescription`, `IDAX_PROCESSOR` | Processor module authoring (`idp.hpp`, `ua.hpp`) | Add output-context abstraction and deeper descriptor/assembler parity checks | `loader_processor_scenario_test`, processor scenario expansion |
| `ida::debugger` | `partial` | process control APIs, register/memory APIs, `on_process_*`, `on_breakpoint_*`, `on_exception` | Debugger runtime/events (`dbg.hpp`, `idd.hpp`) | Expand async/request parity and thread/register introspection helpers | `debugger_ui_graph_event_test`, debugger stress coverage |
| `ida::ui` | `partial` | dialogs, `jump_to`, `Widget` lifecycle APIs, `widget_host`/`with_widget_host`, chooser, timer, typed and generic UI/VIEW events | UI + view notifications (`kernwin.hpp`, `HT_UI`, `HT_VIEW`) | Add additional forms/custom-viewer coverage and broaden generic event mapping | `debugger_ui_graph_event_test`, UI behavior integration tests |
| `ida::graph` | `partial` | `Graph` node/edge/group/layout APIs, `show_graph`, `flowchart`, `flowchart_for_ranges` | Graph/viewer + CFG (`graph.hpp`, `gdl.hpp`) | Add viewer lifecycle/query parity helpers and layout behavior matrix validation | `debugger_ui_graph_event_test`, graph-specific parity tests |
| `ida::decompiler` | `partial` | `available`, `decompile`, `DecompiledFunction`, ctree visitors, comments, mapping APIs | Hex-Rays facade (`hexrays.hpp`) | Add variable retype and broader ctree/comment workflow parity | `decompiler_storage_hardening_test`, `decompiler_edge_cases_test` |
| `ida::storage` | `partial` | `Node::open`, `alt/sup/hash/blob` families | Netnode storage (`netnode.hpp`) | Add node-id/open-by-id metadata helpers and safe-index guidance | `decompiler_storage_hardening_test`, storage docs updates |

## B) SDK Capability Family Matrix (one row per major capability family)

| SDK capability family | Primary SDK headers | Current idax domain(s) | Status | Closure criteria | Required evidence |
|---|---|---|---|---|---|
| Error transport + result model | N/A (cross-cutting) | `ida::error` | `covered` | Preserve category/code/message/context consistency | Unit + compile-only parity checks |
| Shared options + diagnostics | N/A (cross-cutting) | `ida::core`, `ida::diagnostics` | `partial` | Audit and normalize wrapper-wide usage patterns | Unit tests + docs conventions |
| Address flags/navigation | `ida.hpp`, `bytes.hpp` | `ida::address` | `covered` | Closed in P10.2 (predicate ranges + defined aliases) | `smoke_test`, compile-only parity checks |
| Byte read/write/patch | `bytes.hpp` | `ida::data` | `covered` | Closed in P10.2 (explicit revert APIs + mutation safety validation) | `data_mutation_safety_test` |
| Data definition/undefinition | `bytes.hpp`, `offset.hpp` | `ida::data` | `covered` | Closed in P10.2 (expanded define helpers incl. struct) | `data_mutation_safety_test`, compile-only parity checks |
| Database lifecycle/open/save/close | `idalib.hpp` | `ida::database` | `covered` | Closed in P10.2 (open mode + load intent wrappers) | `smoke_test`, compile-only parity checks |
| File/memory ingestion + snapshots | `loader.hpp`, `loader API` | `ida::database` | `covered` | Closed in P10.2 (metadata parity helpers + validated ingestion paths) | `smoke_test` |
| Segment management | `segment.hpp` | `ida::segment` | `partial` | Add resize/move/comment/traversal parity helpers | Segment edge-case tests |
| Function/chunks/frame/register vars | `funcs.hpp`, `frame.hpp` | `ida::function` | `partial` | Add reanalysis/update intent APIs + migration ergonomics | Function edge-case tests |
| Instruction decode/text/operand formatting | `ua.hpp`, `lines.hpp` | `ida::instruction` | `partial` | Add jump/conditional classifiers + operand text parity | Instruction + operand tests |
| Naming/demangling + identifier hygiene | `name.hpp` | `ida::name` | `partial` | Add identifier validation/sanitization + user/auto introspection | Name behavior tests |
| Cross-reference mutation/enumeration | `xref.hpp` | `ida::xref` | `partial` | Add range-style iteration + richer filters | Xref behavior tests |
| Comment pipelines (regular/anterior/posterior/render) | `lines.hpp` | `ida::comment` | `partial` | Add indexed line edits/removals + render parity checks | Comment integration tests |
| Type system + local TIL workflows | `typeinf.hpp` | `ida::type` | `partial` | Expand function-type/calling-convention/enum workflows | Type roundtrip + docs migration updates |
| Entry point + forwarder workflows | `entry.hpp` | `ida::entry` | `partial` | Add forwarder management helpers | Entry parity tests |
| Fixup/relocation + custom handlers | `fixup.hpp` | `ida::fixup` | `partial` | Expand descriptor fidelity + traversal helpers | Fixup relocation tests |
| Search (text/immediate/binary + cursor helpers) | `search.hpp` | `ida::search` | `partial` | Add missing direction/options and `next_error` parity | Search options tests |
| Auto-analysis scheduling/waiting/revert | `auto.hpp` | `ida::analysis` | `partial` | Add schedule-intent APIs + rollback wrappers | Analysis scenario tests |
| IDB event notifications | `event_listener_t` / `HT_IDB` | `ida::event` | `partial` | Expand normalized event coverage and filtering utilities | Event stress tests |
| Plugin authoring and action system | plugin API + `kernwin.hpp` | `ida::plugin` | `partial` | Add detach helpers and finalize context-aware docs | Loader/processor scenario + examples |
| Loader authoring (accept/load/save/move) | `loader.hpp` | `ida::loader` | `partial` | Add archive/member/reload/save path parity | Loader scenario tests |
| Processor authoring | `idp.hpp`, `ua.hpp` | `ida::processor` | `partial` | Add output context abstraction and advanced descriptor parity | Processor scenario tests |
| Debugger control and notifications | `dbg.hpp`, `idd.hpp` | `ida::debugger` | `partial` | Expand request async parity + richer introspection helpers | Debugger integration tests |
| UI/dialog/widget/view lifecycle | `kernwin.hpp` | `ida::ui` | `partial` | Add forms/custom-viewer parity and broaden event mapping | UI integration tests |
| Graph object/viewer/flowchart | `graph.hpp`, `gdl.hpp` | `ida::graph` | `partial` | Add viewer lifecycle/query parity and layout matrix validation | Graph integration tests |
| Decompiler pseudocode/ctree/comment workflows | `hexrays.hpp` | `ida::decompiler` | `partial` | Add variable retype + broader workflow parity | Decompiler hardening/edge-case tests |
| Persistent storage (netnode) | `netnode.hpp` | `ida::storage` | `partial` | Add node-id/open-by-id metadata helpers + safe-index guidance | Storage hardening tests + docs |

## C) Execution notes for Phase 10

1. This matrix is the canonical closure artifact for `P10.0`.
2. Status updates must happen in lockstep with:
   - `claude.md` TODO checkboxes,
   - `claude.md` Progress Ledger,
   - `claude.md` Findings/Decision/Blockers sections when applicable.
3. No row transitions to `covered` without both:
   - passing tests in changed profiles (`full`, `unit`, `compile-only`), and
   - docs evidence updates (`docs/migration/*`, `docs/namespace_topology.md`, API reference).
