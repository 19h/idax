# Performance Baseline

Date: 2026-02-13

## Baseline workflow

1. Build `idax_smoke_test` in Release mode.
2. Run smoke fixture end-to-end.
3. Record elapsed wall-clock and selected counters.

## Current baseline snapshot

- Smoke test functional result: pass (232/232)
- Smoke test wall clock (single run, macOS arm64): `real 0.72s`
- Profiling harness: `scripts/run_idump_validation.sh`
- Notes: establish per-domain micro-benchmarks as APIs stabilize.

## Next increments

- Add repeated-run median timing for decode/search/comment-heavy sections.
- Track regression threshold (+/- 10%) across release candidates.
