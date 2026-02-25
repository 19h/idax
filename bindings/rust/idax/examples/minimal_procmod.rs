mod common;

use common::{format_error, print_usage};
use idax::processor;
use idax::processor::Processor;
use idax::{Error, Result};

struct MinimalProcessor;

impl processor::Processor for MinimalProcessor {
    fn info(&self) -> processor::ProcessorInfo {
        let mut info = processor::ProcessorInfo {
            id: 0x8001,
            short_names: vec!["idaxmini".to_string()],
            long_names: vec!["idax Minimal Processor (Rust adaptation)".to_string()],
            default_bitness: 64,
            ..processor::ProcessorInfo::default()
        };

        info.registers = vec![
            processor::RegisterInfo {
                name: "r0".to_string(),
                read_only: false,
            },
            processor::RegisterInfo {
                name: "sp".to_string(),
                read_only: false,
            },
            processor::RegisterInfo {
                name: "pc".to_string(),
                read_only: false,
            },
        ];

        info.instructions = vec![processor::InstructionDescriptor {
            mnemonic: "nop".to_string(),
            feature_flags: processor::InstructionFeature::None as u32,
            operand_count: 0,
            description: "demo no-op".to_string(),
            privileged: false,
        }];
        info.return_icode = 0;
        info
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
        print_usage(&args[0], "<byte_value_hex>");
        return Err(Error::validation("missing byte_value_hex argument"));
    }

    let opcode = u8::from_str_radix(args[1].trim_start_matches("0x"), 16)
        .map_err(|_| Error::validation("invalid hex byte"))?;

    let mut processor = MinimalProcessor;
    let info = processor.info();
    let size = processor.analyze(0)?;
    let emulate = processor.emulate(0);

    println!("processor_id=0x{:x}", info.id);
    println!(
        "short_name={}",
        info.short_names.first().cloned().unwrap_or_default()
    );
    println!("decoded_opcode=0x{opcode:02x}");
    println!("analyze_size={size}");
    println!("emulate_result={emulate:?}");

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
