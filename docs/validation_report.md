# Validation Report

Date: 2026-02-13 (updated)

## Test suite summary

- Unit: `idax_unit_test` -> pass (22/22)
- API surface parity: `idax_api_surface_check` -> pass (compile-time, 26 namespaces verified)
- Integration smoke: `idax_smoke_test` -> pass (232/232)
- Debugger/UI/graph/event: `idax_debugger_ui_graph_event_test` -> pass (60/60)
- Loader/processor scenario: `idax_loader_processor_scenario_test` -> pass (all checks)
- Name/comment/xref/search behavior: pass
- Data mutation safety: pass
- Segment/function edge cases: pass
- Instruction decode behavior: pass
- Type roundtrip: pass
- Fixup relocation: pass
- Operand and text: pass
- Decompiler/storage hardening: pass
- Consistency audit: 0 SDK type leaks in public headers
- Packaging check: `idax-0.1.0-Darwin.tar.gz` (lib + headers + cmake config)

**Total: 13/13 CTest targets pass**

## Scenario coverage highlights

- Address/data/database flows
- Name/comment/xref/search behaviors
- Segment/function/type/fixup traversals and mutations
- Instruction decode/render/operand representation
- Loader base class, helper functions, value types
- Processor base class, metadata, switch detection types, optional callbacks
- Plugin action types and handler execution
- Loader/procmod/plugin example addon builds
- Debugger event subscription lifecycle (all 11 event types)
- UI event subscriptions (5 event types + ScopedSubscription RAII)
- Graph object operations (node/edge/group/path/clear/move semantics)
- Flowchart generation from function addresses
- Event typed subscriptions + generic routing + filtered routing
- Decompiler pseudocode/ctree/comment/address mapping scenarios
- Storage alt/sup/hash/blob operations

## Platform/compiler matrix (current pass)

- macOS arm64, Clang, C++23: pass

Follow-up matrix expansion remains recommended for Linux/Windows toolchains.
