# Processor Module Quickstart (idax)

Create a processor module by subclassing `ida::processor::Processor`.

## Required overrides

- `info()`
- `analyze(Address)`
- `emulate(Address)`
- `output_instruction(Address)`
- `output_operand(Address, int)`

`IDAX_PROCESSOR` now emits the real SDK `LPH` descriptor and an SDK-private
`procmod_t` event dispatcher. For any instruction set with more than one
instruction code, also override `analyze_with_details(Address)` and set both
`AnalyzeDetails::instruction_code` and `AnalyzeDetails::size`; the bridge
materializes those values as `insn_t::itype` and `insn_t::size`.

## Skeleton

```cpp
class MyProcessor : public ida::processor::Processor {
public:
  ida::processor::ProcessorInfo info() const override;
  ida::Result<int> analyze(ida::Address address) override;
  ida::Result<ida::processor::AnalyzeDetails>
  analyze_with_details(ida::Address address) override;
  ida::processor::EmulateResult emulate(ida::Address address) override;
  void output_instruction(ida::Address address) override;
  ida::processor::OutputOperandResult output_operand(ida::Address address, int operand) override;
};

IDAX_PROCESSOR(MyProcessor)
```

The first `ProcessorInfo::short_names` entry is the installable processor name.
Name the built module accordingly (for example, `jbc.dll`, `jbc.dylib`, or
`jbc.so`) so `set_processor("jbc")` and `-pjbc` can discover it. The bundled
CMake examples retain descriptive target names while setting their output
names to `idaxmini`, `xrisc32`, and `jbc`.

## Typed analysis

```cpp
ida::Result<ida::processor::AnalyzeDetails>
analyze_with_details(ida::Address address) override {
  ida::processor::AnalyzeDetails details;
  details.instruction_code = 1; // index into ProcessorInfo::instructions
  details.size = 4;             // decoded byte count

  ida::processor::AnalyzeOperand destination;
  destination.index = 0;
  destination.kind = ida::processor::AnalyzeOperandKind::Register;
  destination.has_register = true;
  destination.register_index = 0;
  destination.data_type_code = 2; // SDK-independent numeric code for 32-bit data
  details.operands.push_back(destination);
  return details;
}
```

The bridge rejects zero/negative sizes, instruction codes outside the declared
instruction table, duplicate or out-of-range operand indexes, invalid data-type
codes, and incomplete operand payloads. It supports all eight IDA operands and
contains C++ exceptions before they cross the IDA ABI.

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
The mnemonic callback handles only the mnemonic. If the complete instruction
callback returns `NotImplemented`, IDAX invokes the SDK's canonical mnemonic
and operand pipeline, including the mnemonic callback and
`output_operand_with_context`; returning `Success` from the complete callback
means its tokens contain the entire instruction line.

`ProcessorFlag`, `ProcessorFlag2`, and `InstructionFeature` use the exact IDA
9.4 `PR_*`, `PR2_*`, and `CF_*` numeric values. Hexadecimal representation is
the zero-valued default (`ProcessorFlag::HexNumbers`); it is not an independent
bit to combine.

## Segment-register defaults

For processors that need per-segment default register values (SDK
`set_default_sreg_value` workflows), use segment helpers:

```cpp
ida::segment::set_default_segment_register_for_all("cs", 0);
ida::segment::set_default_segment_register_for_all("ds", 0);
```

The active processor supplies the canonical names. Use
`segment_registers()` when a consumer must discover them dynamically; the
numeric overloads remain only for source compatibility.

See `examples/procmod/minimal_procmod.cpp` and
`examples/procmod/jbc_full_procmod.cpp`.

The validation matrix checks the exported `LPH` symbol on Linux, macOS, and
Windows and runs the minimal module through a licensed IDA 9.4 batch analysis
and rendering cycle.
