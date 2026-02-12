# Cookbook: Disassembly Workflows

## Decode and inspect instruction

```cpp
auto insn = ida::instruction::decode(ea);
if (insn) {
  auto mnem = insn->mnemonic();
  auto size = insn->size();
}
```

## Operand representation controls

```cpp
auto op0 = ida::instruction::operand(ea, 0);
if (op0) {
  ida::instruction::set_operand_hex(ea, 0);
  ida::instruction::set_operand_offset(ea, 0, ida::database::image_base().value_or(0));
}
```

## Follow refs-from at instruction level

```cpp
auto code_refs = ida::instruction::code_refs_from(ea);
auto data_refs = ida::instruction::data_refs_from(ea);
```

## Text snapshots for regressions

For snapshot-style tests, capture:

- `ida::instruction::text(ea)`
- mnemonic + operand count
- normalized operand renderings

Compare against a known fixture binary in CI.
