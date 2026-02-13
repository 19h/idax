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

- typed operand analysis (`analyze_with_details`)
- function boundary heuristics (`may_be_function`, `adjust_function_bounds`)
- stack behavior (`calculate_stack_pointer_delta`)
- switch idioms (`detect_switch`, `calculate_switch_cases`, `create_switch_references`)
- mnemonic-specific output (`output_mnemonic_with_context`)

## Output context abstraction

For SDK-opaque text rendering, use `ida::processor::OutputContext`:

```cpp
ida::processor::OutputInstructionResult
output_instruction_with_context(ida::Address address,
                                ida::processor::OutputContext& out) override {
  out.mnemonic("mov").space().register_name("r0").comma().space().immediate(1);
  return ida::processor::OutputInstructionResult::Success;
}

ida::processor::OutputInstructionResult
output_mnemonic_with_context(ida::Address address,
                             ida::processor::OutputContext& out) override {
  out.mnemonic("mov");
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

`OutputContext` also exposes tokenized channels (`token`, `tokens`,
`symbol`, `keyword`, `comment`, `punctuation`, `whitespace`) so advanced
procmods can retain richer formatting intent while remaining SDK-opaque.

## Segment-register defaults

For processors that need per-segment default register values (SDK
`set_default_sreg_value` workflows), use segment helpers:

```cpp
ida::segment::set_default_segment_register_for_all(kRegisterCs, 0);
ida::segment::set_default_segment_register_for_all(kRegisterDs, 0);
```

See `examples/procmod/minimal_procmod.cpp` and
`examples/procmod/jbc_full_procmod.cpp`.
