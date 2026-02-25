# Cookbook: Disassembly Workflows

## End-to-end: inspect mnemonic at a specific address (C++)

This recipe is the full workflow (init -> open -> wait -> decode -> inspect -> close)
for the common question "what mnemonic is at this address?".

```cpp
#include <ida/idax.hpp>

#include <cstdlib>
#include <iomanip>
#include <iostream>

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "usage: mnemonic_inspect <binary-or-idb-path> <hex-address>\n";
    return 1;
  }

  char* end = nullptr;
  const auto parsed = std::strtoull(argv[2], &end, 16);
  if (end == argv[2] || *end != '\0') {
    std::cerr << "invalid hex address: " << argv[2] << "\n";
    return 1;
  }
  const auto address = static_cast<ida::Address>(parsed);

  if (auto s = ida::database::init(argc, argv); !s) {
    std::cerr << "database::init failed: " << s.error().message << "\n";
    return 1;
  }
  if (auto s = ida::database::open(argv[1], true); !s) {
    std::cerr << "database::open failed: " << s.error().message << "\n";
    return 1;
  }

  auto close_database = []() {
    (void) ida::database::close(false);
  };

  if (auto s = ida::analysis::wait(); !s) {
    std::cerr << "analysis::wait failed: " << s.error().message << "\n";
    close_database();
    return 1;
  }

  auto insn = ida::instruction::decode(address);
  if (!insn) {
    if (insn.error().category == ida::ErrorCategory::NotFound) {
      std::cerr << "no instruction decoded at " << std::hex << address << "\n";
    } else {
      std::cerr << "instruction::decode failed: " << insn.error().message << "\n";
    }
    close_database();
    return 1;
  }

  std::cout << std::hex << insn->address() << ": "
            << insn->mnemonic()
            << " (" << std::dec << insn->size() << " bytes)\n";

  for (std::size_t i = 0; i < insn->operand_count(); ++i) {
    auto operand = insn->operand(i);
    if (!operand) continue;

    auto rendered = ida::instruction::operand_text(address, static_cast<int>(i));
    std::cout << "  op" << i << ": "
              << (rendered ? *rendered : "<unavailable>");

    if (operand->is_register()) {
      std::cout << " [reg=" << operand->register_name() << "]";
    } else if (operand->is_immediate()) {
      std::cout << " [imm=0x" << std::hex << operand->value() << "]";
    }
    std::cout << "\n";
  }

  close_database();
  return 0;
}
```

## End-to-end: inspect mnemonic at a specific address (Rust)

```rust
use idax::error::ErrorCategory;
use idax::{analysis, database, instruction};

struct DatabaseSession;

impl Drop for DatabaseSession {
    fn drop(&mut self) {
        let _ = database::close(false);
    }
}

fn inspect(path: &str, address: u64) -> idax::Result<()> {
    database::init()?;
    database::open(path, true)?;
    let _session = DatabaseSession;

    analysis::wait()?;

    match instruction::decode(address) {
        Ok(insn) => {
            println!("{:#x}: {} ({} bytes)", insn.address(), insn.mnemonic(), insn.size());
            for (i, op) in insn.operands().iter().enumerate() {
                let rendered = instruction::operand_text(address, i as i32)
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                println!("  op{i}: {rendered} ({:?})", op.op_type());
            }
            Ok(())
        }
        Err(e) if e.category == ErrorCategory::NotFound => {
            println!("no instruction decoded at {address:#x}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}
```

## Operand representation controls

```cpp
auto insn = ida::instruction::decode(ea);
if (insn && insn->operand_count() > 0) {
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
