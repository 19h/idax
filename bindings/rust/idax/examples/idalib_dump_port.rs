mod common;

use common::{format_error, print_usage, write_output, DatabaseSession};
use idax::{database, decompiler, function, instruction, Error, Result};

#[derive(Debug, Clone)]
struct Options {
    input: String,
    output: Option<String>,
    filter: Option<String>,
    function_names: Vec<String>,
    list_only: bool,
    show_assembly: bool,
    show_pseudocode: bool,
    show_microcode: bool,
    no_summary: bool,
    max_asm_lines: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            output: None,
            filter: None,
            function_names: Vec::new(),
            list_only: false,
            show_assembly: true,
            show_pseudocode: true,
            show_microcode: false,
            no_summary: false,
            max_asm_lines: 120,
        }
    }
}

fn parse_options(args: &[String]) -> Result<Options> {
    if args.len() < 2 {
        return Err(Error::validation("missing binary_file argument"));
    }

    let mut options = Options {
        input: args[1].clone(),
        ..Options::default()
    };

    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print_usage(
                    &args[0],
                    "<binary_file> [--list] [--asm] [--pseudo] [--microcode] [--asm-only] [--pseudo-only] [--microcode-only] [--filter <text>] [--function <name>] [--output <path>] [--max-asm-lines <count>] [--no-summary]",
                );
                std::process::exit(0);
            }
            "--list" | "-l" => {
                options.list_only = true;
            }
            "--asm" => options.show_assembly = true,
            "--pseudo" => options.show_pseudocode = true,
            "--microcode" | "--mc" => options.show_microcode = true,
            "--asm-only" => {
                options.show_assembly = true;
                options.show_pseudocode = false;
                options.show_microcode = false;
            }
            "--pseudo-only" => {
                options.show_assembly = false;
                options.show_pseudocode = true;
                options.show_microcode = false;
            }
            "--microcode-only" | "--mc-only" => {
                options.show_assembly = false;
                options.show_pseudocode = false;
                options.show_microcode = true;
            }
            "--filter" | "-f" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--filter requires a value"));
                }
                options.filter = Some(args[index].clone());
            }
            "--function" | "-F" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--function requires a value"));
                }
                options.function_names.push(args[index].clone());
            }
            "--output" | "-o" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--output requires a path"));
                }
                options.output = Some(args[index].clone());
            }
            "--max-asm-lines" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--max-asm-lines requires a value"));
                }
                options.max_asm_lines = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-asm-lines value"))?;
            }
            "--no-summary" => options.no_summary = true,
            unknown => {
                return Err(Error::validation(format!("unknown option: {unknown}")));
            }
        }
        index += 1;
    }

    if !options.list_only
        && !options.show_assembly
        && !options.show_pseudocode
        && !options.show_microcode
    {
        options.show_assembly = true;
        options.show_pseudocode = true;
    }

    Ok(options)
}

fn function_matches(function_name: &str, options: &Options) -> bool {
    if !options.function_names.is_empty() {
        let exact = options
            .function_names
            .iter()
            .any(|candidate| candidate == function_name);
        if !exact {
            return false;
        }
    }
    if let Some(pattern) = &options.filter {
        return function_name.contains(pattern);
    }
    true
}

fn format_hex(address: u64) -> String {
    format!("0x{address:x}")
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;
    let decompiler_available = decompiler::available().unwrap_or(false);

    let mut selected = Vec::new();
    for function in function::all() {
        if function_matches(function.name(), &options) {
            selected.push(function);
        }
    }

    let mut output = String::new();
    let mut decompile_failures: Vec<(u64, String, String)> = Vec::new();

    if options.list_only {
        output.push_str("Address              Size      Name\n");
        output.push_str("---------------------------------------------\n");
        for function in &selected {
            output.push_str(&format!(
                "{:<20} {:<9} {}\n",
                format_hex(function.start()),
                function.size(),
                function.name()
            ));
        }
    } else {
        for function in &selected {
            output.push_str(&format!(
                "============================================================\nFunction: {} @ {} (size={})\n============================================================\n",
                function.name(),
                format_hex(function.start()),
                function.size()
            ));

            if options.show_assembly {
                output.push_str("\n-- Assembly --\n");
                let addresses = function::code_addresses(function.start())?;
                for (index, address) in addresses.iter().take(options.max_asm_lines).enumerate() {
                    match instruction::text(*address) {
                        Ok(text) => {
                            output.push_str(&format!(
                                "{:04}  {}  {}\n",
                                index,
                                format_hex(*address),
                                text
                            ));
                        }
                        Err(error) => {
                            output.push_str(&format!(
                                "{:04}  {}  <decode error: {}>\n",
                                index,
                                format_hex(*address),
                                format_error(&error)
                            ));
                        }
                    }
                }
            }

            if options.show_pseudocode || options.show_microcode {
                if decompiler_available {
                    match decompiler::decompile(function.start()) {
                        Ok(decompiled) => {
                            if options.show_pseudocode {
                                output.push_str("\n-- Pseudocode --\n");
                                match decompiled.pseudocode() {
                                    Ok(text) => {
                                        output.push_str(&text);
                                        output.push('\n');
                                    }
                                    Err(error) => {
                                        output.push_str(&format!(
                                            "<pseudocode error: {}>\n",
                                            format_error(&error)
                                        ));
                                    }
                                }
                            }
                            if options.show_microcode {
                                output.push_str("\n-- Microcode --\n");
                                match decompiled.microcode() {
                                    Ok(text) => {
                                        output.push_str(&text);
                                        output.push('\n');
                                    }
                                    Err(error) => {
                                        output.push_str(&format!(
                                            "<microcode error: {}>\n",
                                            format_error(&error)
                                        ));
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            decompile_failures.push((
                                function.start(),
                                function.name().to_string(),
                                format_error(&error),
                            ));
                        }
                    }
                } else {
                    output.push_str("\n-- Decompiler --\n<Hex-Rays unavailable on this host>\n");
                }
            }

            output.push('\n');
        }
    }

    if !options.no_summary {
        let total_functions = function::count()?;
        output.push_str("\n================ Summary ================\n");
        output.push_str(&format!(
            "Input: {}\nTotal functions: {}\nSelected functions: {}\nDecompiler failures: {}\n",
            options.input,
            total_functions,
            selected.len(),
            decompile_failures.len(),
        ));
        if !decompile_failures.is_empty() {
            output.push_str("\nDecompiler failures:\n");
            for (address, name, reason) in &decompile_failures {
                output.push_str(&format!(
                    "  - {} {}: {}\n",
                    format_hex(*address),
                    name,
                    reason
                ));
            }
        }
    }

    write_output(options.output.as_deref(), &output)?;

    if !decompile_failures.is_empty() {
        return Err(Error::sdk(format!(
            "{} function(s) failed to decompile",
            decompile_failures.len()
        )));
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
