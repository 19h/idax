mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{loader, Error, Result};

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
        print_usage(&args[0], "<binary_file> [--apply-loader-actions]");
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

    if args.iter().any(|arg| arg == "--apply-loader-actions") {
        let _session = DatabaseSession::open(input, true)?;
        loader::set_processor("metapc")?;
        loader::create_filename_comment()?;
        println!("applied loader actions in opened database session");
    } else {
        println!("use --apply-loader-actions to run set_processor/create_filename_comment");
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
