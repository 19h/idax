# Decompiler / Debugger Test Fixtures

## Current baseline

- Reuses `../simple_appcall_linux64` for decompiler pseudocode, ctree traversal, and address-mapping tests.
- Headless idalib runs validate subscription lifecycle (register/unregister/RAII) without requiring an active live debug session.

## Planned additions

- **synthetic binary with richer local variable patterns**: For decompiler mutation tests
- **debugger event replay fixture**: Deterministic callback verification
- **complex_control_flow**: Nested loops, switch-case, goto for ctree visitor depth
- **optimized_O2**: Inlined functions for variable tracking edge cases
- **multi_threaded**: Thread lifecycle event testing

## Test coverage

| API | Covered by |
|---|---|
| Decompiler availability / decompile | decompiler_storage_hardening_test, smoke_test |
| Pseudocode lines / variables / rename | decompiler_storage_hardening_test |
| Ctree visitor (expression/statement/post-order/skip) | decompiler_storage_hardening_test |
| User comments (set/get/save/remove) | decompiler_storage_hardening_test, smoke_test |
| Address mapping (line_to_address, address_map) | decompiler_storage_hardening_test |
| Debugger event subscriptions (all 11 event types) | debugger_ui_graph_event_test |
| Debugger ScopedSubscription RAII | debugger_ui_graph_event_test |
| UI event subscriptions (5 event types) | debugger_ui_graph_event_test |
| UI ScopedSubscription RAII | debugger_ui_graph_event_test |
| Graph object operations (node/edge/group/path/clear) | debugger_ui_graph_event_test |
| Flowchart generation | debugger_ui_graph_event_test |
| Storage Node alt/sup/hash/blob | decompiler_storage_hardening_test |
