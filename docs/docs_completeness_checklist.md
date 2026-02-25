# Documentation Completeness Checklist

- [x] Plugin quickstart
- [x] Loader quickstart
- [x] Processor quickstart
- [x] Migration map (legacy -> wrapper)
- [x] Domain cookbook (common tasks)
- [x] Disassembly workflow cookbook
- [x] Storage migration caveats
- [x] API reference index
- [x] Namespace topology map
- [x] Compatibility validation matrix
- [x] First-time tutorial path
- [x] Function-discovery event-hook tutorial
- [x] Rust refs_to plugin-action tutorial
- [x] Call-graph traversal tutorial
- [x] Multi-binary signature-generation tutorial
- [x] Distributed-analysis consistency tutorial
- [x] Wrapper-vs-raw-SDK safety/performance tutorial
- [x] Consolidated example-port gap audit

Validation pass:

- [x] All quickstart files resolve to existing paths.
- [x] Examples referenced in docs exist in `examples/`.
- [x] Migration snippets compile conceptually against current public API names.
- [x] Port audit index includes all maintained real-world ports.

Scenario acceptance map (Phase 18):

- [x] Case 1 (list functions/addresses) -> `docs/cookbook/common_tasks.md`
- [x] Case 2 (mnemonic at address) -> `docs/cookbook/disassembly_workflows.md`
- [x] Case 3 (Rust plugin `refs_to`) -> `docs/tutorial/rust_plugin_refs_to.md`
- [x] Case 4 (string extraction/processing) -> `docs/cookbook/common_tasks.md`
- [x] Case 5 (rename functions/variables in Rust) -> `docs/cookbook/common_tasks.md`
- [x] Case 6 (transitive call-graph traversal) -> `docs/tutorial/call_graph_traversal.md`
- [x] Case 7 (multi-binary signature generation) -> `docs/tutorial/multi_binary_signature_generation.md`
- [x] Case 8 (analysis event hook for new functions) -> `docs/tutorial/function_discovery_events.md`
- [x] Case 9 (distributed parallel analysis consistency) -> `docs/tutorial/distributed_analysis_consistency.md`
- [x] Case 10 (idax wrapper vs raw SDK + inconsistent-state handling) -> `docs/tutorial/safety_performance_tradeoffs.md`

Scenario acceptance criteria:

- [x] Every mapped scenario document includes runnable or near-runnable end-to-end flow.
- [x] Every mapped scenario document includes explicit error/edge-case handling guidance.
- [x] Every mapped scenario document is discoverable from top-level index surfaces (`README.md` and `docs/api_reference.md`).
