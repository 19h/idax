# Processor Module Quickstart (idax)

Create a processor module by subclassing `ida::processor::Processor`.

## Required overrides

- `info()`
- `analyze(Address)`
- `emulate(Address)`
- `output_instruction(Address)`
- `output_operand(Address, int)`

## Skeleton

```cpp
class MyProcessor : public ida::processor::Processor {
public:
  ida::processor::ProcessorInfo info() const override;
  ida::Result<int> analyze(ida::Address address) override;
  ida::processor::EmulateResult emulate(ida::Address address) override;
  void output_instruction(ida::Address address) override;
  ida::processor::OutputOperandResult output_operand(ida::Address address, int operand) override;
};

IDAX_PROCESSOR(MyProcessor)
```

## Advanced hooks

Optional virtual hooks cover:

- function boundary heuristics (`may_be_function`, `adjust_function_bounds`)
- stack behavior (`calculate_stack_pointer_delta`)
- switch idioms (`detect_switch`, `calculate_switch_cases`, `create_switch_references`)

## Output context abstraction

For SDK-opaque text rendering, use `ida::processor::OutputContext`:

```cpp
ida::processor::OutputInstructionResult
output_instruction_with_context(ida::Address address,
                                ida::processor::OutputContext& out) override {
  out.mnemonic("mov").space().register_name("r0").comma().space().immediate(1);
  return ida::processor::OutputInstructionResult::Success;
}

ida::processor::OutputOperandResult
output_operand_with_context(ida::Address address,
                            int operand_index,
                            ida::processor::OutputContext& out) override {
  if (operand_index == 0) {
    out.register_name("r0");
    return ida::processor::OutputOperandResult::Success;
  }
  return ida::processor::OutputOperandResult::Hidden;
}
```

See `examples/procmod/minimal_procmod.cpp`.
