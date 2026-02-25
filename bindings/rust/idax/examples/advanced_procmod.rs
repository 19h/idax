mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::processor;
use idax::processor::Processor;
use idax::{comment, database, data, Error, Result, segment};
use idax::address::BAD_ADDRESS;

#[derive(Debug, Clone, Copy)]
struct Decoded {
    opcode: u8,
    rd: u8,
    rs1: u8,
    rs2: u8,
    imm16: i16,
}

fn decode(word: u32) -> Decoded {
    Decoded {
        opcode: ((word >> 28) & 0x0f) as u8,
        rd: ((word >> 24) & 0x0f) as u8,
        rs1: ((word >> 20) & 0x0f) as u8,
        rs2: ((word >> 16) & 0x0f) as u8,
        imm16: (word & 0xffff) as i16,
    }
}

fn mnemonic(opcode: u8) -> &'static str {
    match opcode {
        0x0 => "nop",
        0x1 => "mov",
        0x2 => "ldi",
        0x3 => "add",
        0x4 => "sub",
        0x5 => "and",
        0x6 => "or",
        0x7 => "xor",
        0x8 => "ld",
        0x9 => "st",
        0xa => "beq",
        0xb => "bne",
        0xc => "jmp",
        0xd => "call",
        0xe => "ret",
        0xf => "halt",
        _ => "invalid",
    }
}

fn render(decoded: Decoded) -> String {
    match decoded.opcode {
        0x0 | 0xe | 0xf => mnemonic(decoded.opcode).to_string(),
        0x1 => format!("mov r{}, r{}", decoded.rd, decoded.rs1),
        0x2 => format!("ldi r{}, {}", decoded.rd, decoded.imm16),
        0x3..=0x7 => format!(
            "{} r{}, r{}, r{}",
            mnemonic(decoded.opcode),
            decoded.rd,
            decoded.rs1,
            decoded.rs2
        ),
        0x8 => format!("ld r{}, [r{} + {}]", decoded.rd, decoded.rs1, decoded.imm16),
        0x9 => format!(
            "st r{}, [r{} + {}]",
            decoded.rs2, decoded.rs1, decoded.imm16
        ),
        0xa | 0xb => format!(
            "{} r{}, r{}, {}",
            mnemonic(decoded.opcode),
            decoded.rs1,
            decoded.rs2,
            decoded.imm16
        ),
        0xc | 0xd => format!("{} {}", mnemonic(decoded.opcode), decoded.imm16),
        _ => format!("db 0x{:08x}", encode(decoded)),
    }
}

fn encode(decoded: Decoded) -> u32 {
    ((decoded.opcode as u32) << 28)
        | ((decoded.rd as u32) << 24)
        | ((decoded.rs1 as u32) << 20)
        | ((decoded.rs2 as u32) << 16)
        | (decoded.imm16 as u16 as u32)
}

struct XriscProcessor;

impl processor::Processor for XriscProcessor {
    fn info(&self) -> processor::ProcessorInfo {
        let mut info = processor::ProcessorInfo {
            id: 0x8100,
            short_names: vec!["xrisc32".to_string()],
            long_names: vec!["XRISC-32 Advanced RISC Processor (Rust adaptation)".to_string()],
            default_bitness: 32,
            ..processor::ProcessorInfo::default()
        };

        info.registers = (0..13)
            .map(|i| processor::RegisterInfo {
                name: format!("r{i}"),
                read_only: false,
            })
            .collect();
        info.registers.extend([
            processor::RegisterInfo {
                name: "sp".to_string(),
                read_only: false,
            },
            processor::RegisterInfo {
                name: "lr".to_string(),
                read_only: false,
            },
            processor::RegisterInfo {
                name: "pc".to_string(),
                read_only: true,
            },
        ]);

        info.instructions = (0u8..=0x0f)
            .map(|opcode| processor::InstructionDescriptor {
                mnemonic: mnemonic(opcode).to_string(),
                feature_flags: 0,
                operand_count: 3,
                description: "xrisc opcode".to_string(),
                privileged: false,
            })
            .collect();

        info.return_icode = 0x0e;
        info
    }

    fn analyze(&mut self, _address: u64) -> Result<i32> {
        Ok(4)
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
        processor::OutputOperandResult::Success
    }
}

fn parse_word(token: &str) -> Result<u32> {
    let trimmed = token.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(trimmed, 16).map_err(|_| Error::validation("invalid 32-bit hex word"))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(
            &args[0],
            "<idb_file_or_binary> [start_ea]",
        );
        return Err(Error::validation("missing target file"));
    }

    let input_path = &args[1];
    
    // We open a session and try to decode from within the database instead of from argv
    let _session = DatabaseSession::open(input_path, true)?;

    let processor = XriscProcessor;
    let info = processor.info();
    println!("processor_id=0x{:x}", info.id);
    println!(
        "short_name={}",
        info.short_names.first().cloned().unwrap_or_default()
    );

    // Either user provides start address, or we start from image base/min address
    let mut ea = if args.len() >= 3 {
        parse_word(&args[2])? as u64
    } else {
        database::image_base().unwrap_or(database::min_address().unwrap_or(BAD_ADDRESS))
    };

    if ea == BAD_ADDRESS {
        return Err(Error::internal("Could not find start address in database"));
    }
    
    // We just limit our iteration to 20 instructions or end of segment
    println!("Disassembling at address 0x{:08x}:", ea);

    let mut instructions_decoded = 0;
    while instructions_decoded < 20 {
        if segment::at(ea).is_err() {
            println!("0x{:08x}: <end of segment>", ea);
            break;
        }

        if let Ok(word) = data::read_dword(ea) {
            let decoded = decode(word);
            println!(
                "0x{:08x}: {:<20} ; op={} rd={} rs1={} rs2={} imm16={}",
                ea,
                render(decoded),
                decoded.opcode,
                decoded.rd,
                decoded.rs1,
                decoded.rs2,
                decoded.imm16
            );
            
            // We can also try to add an IDA comment with the mock disassembled form
            let _ = comment::set(ea, &render(decoded), false);
            
            ea += 4;
        } else {
            println!("0x{:08x}: <read error>", ea);
            break;
        }
        instructions_decoded += 1;
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
