mod common;

use common::{format_error, print_usage};
use idax::processor;
use idax::processor::Processor;
use idax::{Error, Result};

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

fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn format_operand(kind: OperandKind, value: u32) -> String {
    match kind {
        OperandKind::None => String::new(),
        OperandKind::Address => format!("loc_{value:08x}"),
        OperandKind::Immediate => format!("0x{value:08x}"),
        OperandKind::StringOffset => format!("str_{value:08x}"),
    }
}

struct JbcProcessor;

impl processor::Processor for JbcProcessor {
    fn info(&self) -> processor::ProcessorInfo {
        processor::ProcessorInfo {
            id: 0x8bc0,
            short_names: vec!["jbc".to_string()],
            long_names: vec!["JAM Byte-Code (Rust adaptation)".to_string()],
            default_bitness: 32,
            ..processor::ProcessorInfo::default()
        }
    }

    fn analyze(&mut self, _address: u64) -> Result<i32> {
        Ok(1)
    }

    fn emulate(&mut self, _address: u64) -> processor::EmulateResult {
        processor::EmulateResult::Success
    }

    fn output_instruction(&mut self, _address: u64) {}

    fn output_operand(
        &mut self,
        _address: u64,
        _operand_index: i32,
    ) -> processor::OutputOperandResult {
        processor::OutputOperandResult::NotImplemented
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

    let bytes = std::fs::read(&args[1])
        .map_err(|err| Error::internal(format!("failed reading '{}': {err}", args[1])))?;

    let processor = JbcProcessor;
    let info = processor.info();
    println!("processor_id=0x{:x}", info.id);
    println!(
        "short_name={}",
        info.short_names.first().cloned().unwrap_or_default()
    );

    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < bytes.len() && count < max_count {
        let opcode = bytes[offset];
        if let Some(def) = lookup(opcode) {
            let size = instruction_size(opcode);
            if offset + size > bytes.len() {
                println!("0x{offset:08x}: <truncated {}>", def.mnemonic);
                break;
            }

            if def.argc == 0 {
                println!("0x{offset:08x}: {}", def.mnemonic);
            } else {
                let arg = read_be_u32(&bytes[offset + 1..offset + 5]);
                println!(
                    "0x{offset:08x}: {} {}",
                    def.mnemonic,
                    format_operand(def.op0, arg)
                );
            }
            offset += size;
        } else {
            println!("0x{offset:08x}: db 0x{opcode:02x}");
            offset += 1;
        }
        count += 1;
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
