# Processor Module Test Fixtures

## Current baseline

- Reuses `../simple_appcall_linux64` for instruction decode/emulation callback smoke coverage.
- Processor base class, metadata types, and switch descriptors validated via `loader_processor_scenario_test`.

## Planned additions

- **compact switch-table sample**: Sparse and dense case layouts
- **architecture-specific prolog/epilog heuristics fixture**: For `analyze_function_prolog` testing
- **synthetic_isa**: Minimal binary for a custom 32-bit RISC ISA
- **delay_slot_binary**: Exercises delay-slot semantics for `is_basic_block_end` testing

## Test coverage

| API | Covered by |
|---|---|
| `ProcessorInfo` metadata construction | loader_processor_scenario_test |
| `RegisterInfo` / `InstructionDescriptor` / `AssemblerInfo` | loader_processor_scenario_test |
| `Processor` base class virtuals (analyze/emulate/output) | loader_processor_scenario_test |
| Optional callbacks (is_call/is_return/may_be_function/etc.) | loader_processor_scenario_test |
| `SwitchDescription` / `SwitchCase` | loader_processor_scenario_test |
| `EmulateResult` / `OutputOperandResult` enums | loader_processor_scenario_test |
| `IDAX_PROCESSOR` macro | examples/procmod/minimal_procmod.cpp (build only) |
