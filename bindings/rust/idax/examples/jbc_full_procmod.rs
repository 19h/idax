mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{comment, database, data, Error, Result, segment};
use idax::address::BAD_ADDRESS;

const MAGIC_V1: u32 = 0x0043424a;
const MAGIC_V2: u32 = 0x0143424a;

#[derive(Debug, Clone, Copy)]
enum OperandKind {
    None,
    Address,
    Immediate,
    StringOffset,
}

#[derive(Debug, Clone, Copy)]
struct InstructionDef {
    mnemonic: &'static str,
    argc: usize,
    op0: OperandKind,
}

fn lookup(opcode: u8) -> Option<InstructionDef> {
    match opcode {
        0x00 => Some(InstructionDef {
            mnemonic: "nop",
            argc: 0,
            op0: OperandKind::None,
        }),
        0x01 => Some(InstructionDef {
            mnemonic: "jmp",
            argc: 1,
            op0: OperandKind::Address,
        }),
        0x02 => Some(InstructionDef {
            mnemonic: "call",
            argc: 1,
            op0: OperandKind::Address,
        }),
        0x03 => Some(InstructionDef {
            mnemonic: "loads",
            argc: 1,
            op0: OperandKind::StringOffset,
        }),
        0x04 => Some(InstructionDef {
            mnemonic: "pushi",
            argc: 1,
            op0: OperandKind::Immediate,
        }),
        0x11 => Some(InstructionDef {
            mnemonic: "ret",
            argc: 0,
            op0: OperandKind::None,
        }),
        _ => None,
    }
}

fn instruction_size(opcode: u8) -> usize {
    1 + lookup(opcode).map(|d| d.argc * 4).unwrap_or(0)
}

fn format_operand(kind: OperandKind, value: u32) -> String {
    match kind {
        OperandKind::None => String::new(),
        OperandKind::Address => format!("loc_{value:08x}"),
        OperandKind::Immediate => format!("0x{value:08x}"),
        OperandKind::StringOffset => format!("str_{value:08x}"),
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<jbc_bytecode_file> [--max <instruction_count>]");
        return Err(Error::validation("missing jbc_bytecode_file argument"));
    }

    let max_count = args
        .windows(2)
        .find(|window| window[0] == "--max")
        .and_then(|window| window[1].parse::<usize>().ok())
        .unwrap_or(64);

    let input_path = &args[1];
    
    // We open a session and try to decode from within the database instead of from argv
    let _session = DatabaseSession::open(input_path, true)?;

    println!("processor_id=0x8bc0");
    println!("short_name=jbc");

    // Search for code segment. It's either explicitly named CODE, or we fallback to the first execution-capable segment, or min_address.
    let mut offset = database::min_address().unwrap_or(BAD_ADDRESS);
    
    // Attempt to locate a segment named "CODE" or similar
    if let Ok(seg) = segment::by_name("CODE") {
        offset = seg.start();
        println!("disassembling from discovered CODE segment offset: 0x{offset:08x}");
    } else {
        // Fallback to first segment
        if let Ok(seg) = segment::first() {
            offset = seg.start();
            println!("disassembling from first segment offset: 0x{offset:08x}");
        }
    }
    
    if offset == BAD_ADDRESS {
         return Err(Error::internal("Could not find start address in database"));
    }

    let mut count = 0usize;
    while count < max_count {
        if segment::at(offset).is_err() {
            break; // left segment bounds
        }

        if let Ok(opcode) = data::read_byte(offset) {
            if let Some(def) = lookup(opcode) {
                let size = instruction_size(opcode);

                if def.argc == 0 {
                    println!("0x{:08x}: {}", offset, def.mnemonic);
                    let _ = comment::set(offset, def.mnemonic, false);
                } else {
                    if let Ok(arg) = data::read_dword(offset + 1) {
                        let render = format!("{} {}", def.mnemonic, format_operand(def.op0, arg));
                        println!("0x{:08x}: {}", offset, render);
                        let _ = comment::set(offset, &render, false);
                    } else {
                        println!("0x{:08x}: <truncated {}>", offset, def.mnemonic);
                        break;
                    }
                }
                offset += size as u64;
            } else {
                println!("0x{:08x}: db 0x{:02x}", offset, opcode);
                offset += 1;
            }
            count += 1;
        } else {
            break;
        }
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
