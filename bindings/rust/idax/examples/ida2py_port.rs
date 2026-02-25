mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, DatabaseSession};
use idax::address::BAD_ADDRESS;
use idax::{data, database, function, instruction, name, types, xref, Error, Result};

#[derive(Debug, Clone)]
struct CastRequest {
    target: String,
    declaration: String,
}

#[derive(Debug, Clone)]
struct Options {
    input: String,
    quiet: bool,
    list_user_symbols: bool,
    show_targets: Vec<String>,
    casts: Vec<CastRequest>,
    callsites: Vec<String>,
    appcall_smoke: bool,
    max_symbols: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            quiet: false,
            list_user_symbols: false,
            show_targets: Vec::new(),
            casts: Vec::new(),
            callsites: Vec::new(),
            appcall_smoke: false,
            max_symbols: 200,
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
                    "<binary_file> [--list-user-symbols] [--show <name|ea>] [--cast <name|ea> <cdecl>] [--callsites <name|ea>] [--max-symbols <n>] [--appcall-smoke] [-q|--quiet]",
                );
                std::process::exit(0);
            }
            "-q" | "--quiet" => options.quiet = true,
            "--list-user-symbols" => options.list_user_symbols = true,
            "--show" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--show requires an argument"));
                }
                options.show_targets.push(args[index].clone());
            }
            "--cast" => {
                if index + 2 >= args.len() {
                    return Err(Error::validation(
                        "--cast requires <name|ea> <cdecl> arguments",
                    ));
                }
                options.casts.push(CastRequest {
                    target: args[index + 1].clone(),
                    declaration: args[index + 2].clone(),
                });
                index += 2;
            }
            "--callsites" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--callsites requires an argument"));
                }
                options.callsites.push(args[index].clone());
            }
            "--max-symbols" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--max-symbols requires a numeric value"));
                }
                options.max_symbols = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-symbols value"))?;
            }
            "--appcall-smoke" => options.appcall_smoke = true,
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        index += 1;
    }

    if !options.list_user_symbols
        && options.show_targets.is_empty()
        && options.casts.is_empty()
        && options.callsites.is_empty()
        && !options.appcall_smoke
    {
        options.list_user_symbols = true;
    }

    Ok(options)
}

fn list_user_symbols(max_symbols: usize, output: &mut String) -> Result<()> {
    let entries = name::all_user_defined(BAD_ADDRESS, BAD_ADDRESS)?;
    output.push_str("\n== User-defined Symbols ==\n");
    output.push_str("Address              Name                                Type\n");
    output.push_str("--------------------------------------------------------------------------\n");

    for entry in entries.iter().take(max_symbols) {
        let type_name = types::retrieve(entry.address)
            .ok()
            .and_then(|ty| ty.to_string().ok())
            .unwrap_or_else(|| "<none>".to_string());
        output.push_str(&format!(
            "{:<20} {:<34} {}\n",
            format!("0x{:x}", entry.address),
            entry.name,
            type_name
        ));
    }
    Ok(())
}

fn inspect_symbol(target: &str, output: &mut String) -> Result<()> {
    let address = resolve_symbol_or_address(target)?;
    let symbol_name = name::get(address).unwrap_or_else(|_| "<unnamed>".to_string());
    let demangled = name::demangled(address, name::DemangleForm::Short).unwrap_or_default();
    let refs_to = xref::refs_to(address).unwrap_or_default();
    let refs_from = xref::refs_from(address).unwrap_or_default();
    let bytes = data::read_bytes(address, 16).unwrap_or_default();

    output.push_str(&format!("\n== Show: {target} ==\n"));
    output.push_str(&format!("address: 0x{:x}\n", address));
    output.push_str(&format!("name: {symbol_name}\n"));
    if !demangled.is_empty() {
        output.push_str(&format!("demangled: {demangled}\n"));
    }

    if let Ok(function_info) = function::at(address) {
        output.push_str(&format!(
            "function: {} [{} - {})\n",
            function_info.name(),
            format!("0x{:x}", function_info.start()),
            format!("0x{:x}", function_info.end())
        ));
    }

    if let Ok(ty) = types::retrieve(address)
        && let Ok(ty_text) = ty.to_string()
    {
        output.push_str(&format!("type: {ty_text}\n"));
    }

    let preview = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ");
    output.push_str(&format!("bytes[16]: {preview}\n"));
    output.push_str(&format!("xrefs_to: {}\n", refs_to.len()));
    output.push_str(&format!("xrefs_from: {}\n", refs_from.len()));
    Ok(())
}

fn apply_cast(request: &CastRequest, output: &mut String) -> Result<()> {
    let address = resolve_symbol_or_address(&request.target)?;
    let parsed = types::TypeInfo::from_declaration(&request.declaration)?;
    parsed.apply(address)?;
    let roundtrip = types::retrieve(address)?.to_string()?;

    output.push_str(&format!("\n== Cast: {} ==\n", request.target));
    output.push_str(&format!("address: 0x{:x}\n", address));
    output.push_str(&format!("applied: {}\n", request.declaration));
    output.push_str(&format!("retrieved: {roundtrip}\n"));
    Ok(())
}

fn show_callsites(target: &str, output: &mut String) -> Result<()> {
    let target_address = resolve_symbol_or_address(target)?;
    let references = xref::refs_to(target_address)?;

    output.push_str(&format!("\n== Callsites: {target} ==\n"));
    output.push_str(&format!("target: 0x{:x}\n", target_address));

    let mut call_count = 0usize;
    for reference in references {
        if !reference.is_code || !xref::is_call(reference.ref_type) {
            continue;
        }
        call_count += 1;
        let caller = function::at(reference.from)
            .map(|f| f.name().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let line = instruction::text(reference.from).unwrap_or_else(|_| "<decode failed>".to_string());
        output.push_str(&format!(
            "  from 0x{:x} ({caller}) -> 0x{:x} : {line}\n",
            reference.from, reference.to
        ));
    }
    output.push_str(&format!("callsites: {call_count}\n"));
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;

    let mut output = String::new();
    if !options.quiet {
        output.push_str("== ida2py_port (Rust adaptation) ==\n");
        output.push_str(&format!("input: {}\n", options.input));
        output.push_str(&format!(
            "processor: {}\n",
            database::processor_name().unwrap_or_else(|_| "<unknown>".to_string())
        ));
        output.push_str(&format!(
            "address_bitness: {}\n",
            database::address_bitness().unwrap_or_default()
        ));
    }

    if options.list_user_symbols {
        list_user_symbols(options.max_symbols, &mut output)?;
    }

    for target in &options.show_targets {
        inspect_symbol(target, &mut output)?;
    }

    for cast in &options.casts {
        apply_cast(cast, &mut output)?;
    }

    for target in &options.callsites {
        show_callsites(target, &mut output)?;
    }

    if options.appcall_smoke {
        output.push_str(
            "\n== Appcall smoke ==\nAppcall smoke is not exposed in this safe Rust example surface yet; use C++ idax tool examples for debugger-backed appcall validation.\n",
        );
    }

    print!("{output}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
