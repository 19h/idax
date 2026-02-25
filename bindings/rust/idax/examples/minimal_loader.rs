mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{loader, segment, Error, Result};

fn is_elf(path: &str) -> std::io::Result<bool> {
    let bytes = std::fs::read(path)?;
    Ok(bytes.len() >= 4
        && bytes[0] == 0x7f
        && bytes[1] == b'E'
        && bytes[2] == b'L'
        && bytes[3] == b'F')
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<binary_file>");
        return Err(Error::validation("missing binary_file argument"));
    }

    let input = &args[1];
    let accepted =
        is_elf(input).map_err(|err| Error::internal(format!("failed to read '{input}': {err}")))?;

    if !accepted {
        return Err(Error::unsupported(
            "minimal_loader adaptation accepts ELF-like files only",
        ));
    }

    println!("accepted format: idax minimal ELF (processor=metapc)");

    let _session = DatabaseSession::open(input, false)?;
    
    // Clear auto-created segments
    for seg in segment::all().collect::<Vec<_>>() {
        segment::remove(seg.start())?;
    }
    
    loader::set_processor("metapc")?;
    loader::create_filename_comment()?;
    
    // Minimal mock segment loading
    let file_data = std::fs::read(input).unwrap();
    let start = 0x10000;
    let end = start + file_data.len() as u64;
    segment::create(start, end, "LOAD", "CODE", segment::Type::Code)?;
    loader::memory_to_database(&file_data, start, file_data.len() as u64)?;
    
    println!("applied loader actions in opened database session: processor set, comment created, data loaded.");

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
