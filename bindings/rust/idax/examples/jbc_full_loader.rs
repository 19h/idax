mod common;

use common::{format_error, print_usage, write_output};
use idax::{Error, Result};

const MAGIC_V1: u32 = 0x0043424a;
const MAGIC_V2: u32 = 0x0143424a;

fn read_be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::validation(format!("truncated u32 at offset {offset}")))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<jbc_file> [--emit-plan <output_file>]");
        return Err(Error::validation("missing jbc_file argument"));
    }

    let input_path = &args[1];
    let data = std::fs::read(input_path)
        .map_err(|err| Error::internal(format!("failed reading '{input_path}': {err}")))?;
    if data.len() < 64 {
        return Err(Error::validation("file too small for JBC header"));
    }

    let magic = read_be_u32(&data, 0)?;
    if magic != MAGIC_V1 && magic != MAGIC_V2 {
        return Err(Error::unsupported(
            "input is not a JAM Byte-Code (JBC) file",
        ));
    }

    let version = (magic & 1) as u32 + 1;
    let delta = ((version - 1) * 8) as usize;

    let action_table = read_be_u32(&data, 4)?;
    let proc_table = read_be_u32(&data, 8)?;
    let string_table = read_be_u32(&data, 4 + delta)?;
    let symbol_table = read_be_u32(&data, 16 + delta)?;
    let data_section = read_be_u32(&data, 20 + delta)?;
    let code_section = read_be_u32(&data, 24 + delta)?;
    let debug_section = read_be_u32(&data, 28 + delta)?;
    let action_count = read_be_u32(&data, 40 + delta)?;
    let proc_count = read_be_u32(&data, 44 + delta)?;

    let string_size = if symbol_table > string_table {
        symbol_table - string_table
    } else if data_section > string_table {
        data_section - string_table
    } else {
        0
    };

    let code_size = if data_section > code_section {
        data_section - code_section
    } else {
        (data.len() as u32).saturating_sub(code_section)
    };

    let data_size = if data_section > 0 {
        (data.len() as u32).saturating_sub(data_section)
    } else {
        0
    };

    let mut report = String::new();
    report.push_str("JBC full loader plan (Rust adaptation)\n");
    report.push_str(&format!("input: {input_path}\n"));
    report.push_str(&format!("version: {version}\n"));
    report.push_str(&format!("magic_be: 0x{magic:08x}\n\n"));

    report.push_str("Header fields\n");
    report.push_str("-------------\n");
    report.push_str(&format!("action_table: 0x{action_table:08x}\n"));
    report.push_str(&format!("proc_table: 0x{proc_table:08x}\n"));
    report.push_str(&format!(
        "string_table: 0x{string_table:08x} (size={string_size})\n"
    ));
    report.push_str(&format!("symbol_table: 0x{symbol_table:08x}\n"));
    report.push_str(&format!(
        "code_section: 0x{code_section:08x} (size={code_size})\n"
    ));
    report.push_str(&format!(
        "data_section: 0x{data_section:08x} (size={data_size})\n"
    ));
    report.push_str(&format!("debug_section: 0x{debug_section:08x}\n"));
    report.push_str(&format!("action_count: {action_count}\n"));
    report.push_str(&format!("proc_count: {proc_count}\n\n"));

    report.push_str("Planned IDA layout\n");
    report.push_str("------------------\n");
    report.push_str("- processor: jbc\n");
    report.push_str(
        "- segments: STRINGS @ 0x10000 (if present), CODE after STRINGS, DATA after CODE\n",
    );
    report
        .push_str("- defaults: CS/DS set for all segments, string entries defined as C-strings\n");
    report.push_str("- symbol pass: names from symbol table applied where offsets resolve\n");

    let output = args
        .windows(2)
        .find(|window| window[0] == "--emit-plan")
        .map(|window| window[1].as_str());
    write_output(output, &report)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
