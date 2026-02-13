# Post-Release Backlog

## High Priority

- ~~Add richer fixture corpus for loader/procmod/decompiler/debugger edge cases.~~ DONE: decompiler_edge_cases_test (837 lines, 7 test sections), expanded loader_processor_scenario_test (+7 sections covering all optional callbacks, switch edge cases, feature flags, assembler validation, accept rejection)
- Expand compatibility validation matrix (Linux/Windows, compiler variants).
- ~~Add deeper performance benchmarks for decode/search/decompiler-heavy paths.~~ DONE: performance_benchmark_test (537 lines, 10 benchmarks covering decode throughput, function iteration, pattern search, item scan, xref enumeration, name resolution, decompile latency, data read, comment I/O, type creation)

## Medium Priority

- ~~Increase scenario-test depth for UI chooser interactions and event storms.~~ DONE: event_stress_test (473 lines, 8 test sections covering concurrent subscribers, rapid sub/unsub cycles, multi-event fan-out with real firing, scoped batch, filtered routing specificity, generic+typed coexistence, double-unsubscribe safety, debugger multi-subscribe)
- ~~Add additional migration examples for complex type and storage transitions.~~ DONE: expanded legacy_to_wrapper.md with complete type system migration (primitives, composites, structs, apply/retrieve, type library, roundtrip), storage/netnode migration (open, alt, sup, hash, blob, multi-tag, copy/move, pitfalls), and decompiler migration (availability, decompile, variables, ctree visitor, comments, address mapping, post-order)

## Low Priority

- Polish docs formatting and add visual diagrams for namespace topology.
