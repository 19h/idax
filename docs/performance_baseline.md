# Performance Baseline

Date: 2026-02-13 (updated)

## Baseline workflow

1. Build all targets in default (Debug) mode.
2. Run full CTest suite end-to-end.
3. Record elapsed wall-clock.

## Current baseline snapshot

- Full CTest suite (13 tests): `real 7.54s` (macOS arm64)
- Smoke test (232 checks): `real 0.70s`
- Largest integration test: `decompiler_storage_hardening` at `0.71s`
- New tests: `debugger_ui_graph_event` at `0.66s`, `loader_processor_scenario` at `0.66s`
- Unit tests: `0.00s` (pure logic, no IDA runtime)
- API surface parity: `0.00s` (compile-only check)

## Library size

- `libidax.a`: ~3.1 MB (23 object files, arm64 static archive)
- Package: `idax-0.1.0-Darwin.tar.gz` (~1 MB compressed)

## Next increments

- Add repeated-run median timing for decode/search/comment-heavy sections.
- Track regression threshold (+/- 10%) across release candidates.
- Profile Release-mode builds for production baseline.
