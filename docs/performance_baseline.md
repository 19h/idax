# Performance Baseline

Date: 2026-02-13 (updated)

## Baseline workflow

1. Build all targets in default single-config mode and Release mode.
2. Run full CTest suite end-to-end.
3. Record elapsed wall-clock.

## Current baseline snapshot

- Full CTest suite (16 tests, default build): `real 9.42s` (macOS arm64)
- Full CTest suite (16 tests, RelWithDebInfo build): `real 9.73s` (macOS arm64)
- Full CTest suite (16 tests, Release build): `real 9.77s` (macOS arm64)
- Smoke test (232 checks): `real 0.67s`
- Largest integration test: `decompiler_edge_cases` at `0.69s`
- New tests: `event_stress` at `0.67s`, `performance_benchmark` at `0.68s`
- Unit tests: `0.00s` (pure logic, no IDA runtime)
- API surface parity: `0.00s` (compile-only check)

## Library size

- `libidax.a`: ~3.1 MB (23 object files, arm64 static archive)
- Package: `idax-0.1.0-Darwin.tar.gz` (~1 MB compressed)

## Next increments

- Add repeated-run median timing for decode/search/comment-heavy sections.
- Track regression threshold (+/- 10%) across release candidates.
- Add Linux/Windows matrix baselines once those rows are executed.
