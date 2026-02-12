# Validation Report

Date: 2026-02-13

## Test suite summary

- Unit: `tests/unit/idax_unit_test` -> pass (22/22)
- Integration: `tests/integration/idax_smoke_test` -> pass (232/232)
- Batch dump validation: `scripts/run_idump_validation.sh` -> pass (1288 lines)
- Packaging check: `scripts/check_packaging.sh` -> pass (`idax-0.1.0-Darwin.tar.gz`)

## Scenario coverage highlights

- Address/data/database flows
- Name/comment/xref/search behaviors
- Segment/function/type/fixup traversals and mutations
- Instruction decode/render/operand representation
- Loader/procmod/plugin example addon builds
- Debugger/UI/event subscription lifecycle scenarios
- Decompiler pseudocode/ctree/comment/address mapping scenarios

## Platform/compiler matrix (current pass)

- macOS arm64, Clang, C++23: pass

Follow-up matrix expansion remains recommended for Linux/Windows toolchains.
