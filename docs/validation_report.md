# Validation Report

Date: 2026-02-14 (updated after open-point closure automation run)

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
- Decompiler edge cases: pass
- Event stress: pass
- Performance benchmark: pass
- Matrix automation script: `full`, `unit`, and `compile-only` profiles pass on macOS arm64
- Matrix example addon compile coverage: `IDAX_BUILD_EXAMPLES=ON` + `IDAX_BUILD_EXAMPLE_ADDONS=ON` validated locally for `compile-only` and `unit`
- Hosted validation matrix (provided log bundle): all jobs passed for Linux/macOS `compile-only` + `unit`, plus Windows `compile-only`
- Matrix full+packaging profile: pass (`build-matrix-full-pack/idax-0.1.0-Darwin.tar.gz`)
- Open-point closure sweep (`scripts/run_open_points.sh`): full matrix pass,
  lumina smoke pass, appcall smoke blocked by debugger backend readiness
  (`build-open-points-run2/logs/*`)
- Consistency audit: 0 SDK type leaks in public headers
- Packaging check: `idax-0.1.0-Darwin.tar.gz` (lib + headers + cmake config)

**Total: 16/16 CTest targets pass**

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
- Decompiler edge cases: multi-function, variable classification, ctree diversity, rename roundtrip
- Storage alt/sup/hash/blob operations
- Event stress: concurrent subscribers, rapid sub/unsub, multi-event fan-out
- Performance benchmarks: decode throughput, function iteration, pattern search, decompile latency

## Platform/compiler matrix (current pass)

- macOS arm64, AppleClang 17, default profile: pass (16/16)
- macOS arm64, AppleClang 17, RelWithDebInfo profile: pass (16/16)
- macOS arm64, AppleClang 17, Release profile: pass (16/16)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs1.txt`)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo unit (GitHub Actions): pass, 2/2 (`job-logs4.txt`)
- macOS arm64, AppleClang 15.0.0.15000309, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs2.txt`)
- macOS arm64, AppleClang 15.0.0.15000309, RelWithDebInfo unit (GitHub Actions): pass, 2/2 (`job-logs5.txt`)
- Windows x64, MSVC 19.44.35222.0, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs3.txt`)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo compile-only: pass (`build-matrix-linux-gcc-docker/`)
- Linux x86_64, Clang 18.1.3, RelWithDebInfo compile-only: fail (baseline container run fails because `std::expected` is unavailable with this compiler/libstdc++ pairing; see `build-matrix-linux-clang18-amd64-baseline/`)
- Linux x86_64, Clang 19.1.1, RelWithDebInfo compile-only: pass (baseline container run with `IDAX_BUILD_EXAMPLE_ADDONS=OFF` and `IDAX_BUILD_EXAMPLE_TOOLS=OFF`; see `build-matrix-linux-clang19-amd64-baseline/`)

Remaining runtime-dependent `full` Linux/Windows rows and command profiles are
tracked in `docs/compatibility_matrix.md`.
