mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, DatabaseSession};
use idax::{comment, function, name, Error, Result};

#[derive(Debug, Clone)]
struct Options {
    input: String,
    targets: Vec<String>,
    limit: usize,
    include_thunks: bool,
    include_libraries: bool,
    apply_comments: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            targets: Vec::new(),
            limit: 20,
            include_thunks: false,
            include_libraries: false,
            apply_comments: false,
        }
    }
}

#[derive(Debug, Clone)]
struct TitleRecord {
    start: u64,
    end: u64,
    raw_name: String,
    title: String,
    source: &'static str,
}

fn shorten_name(text: &str) -> String {
    let trimmed = text.trim();
    if let Some((head, _)) = trimmed.split_once('(') {
        return head.trim().to_string();
    }
    trimmed.to_string()
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
                    "<binary_file> [--target <name|ea>] [--limit <n>] [--include-thunks] [--include-libraries] [--apply-comments]",
                );
                std::process::exit(0);
            }
            "--target" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--target requires an argument"));
                }
                options.targets.push(args[index].clone());
            }
            "--limit" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--limit requires a numeric value"));
                }
                options.limit = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --limit value"))?;
            }
            "--include-thunks" => options.include_thunks = true,
            "--include-libraries" => options.include_libraries = true,
            "--apply-comments" => options.apply_comments = true,
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        index += 1;
    }

    Ok(options)
}

fn containing_function(ea: u64) -> Result<function::Function> {
    if let Ok(found) = function::at(ea) {
        return Ok(found);
    }

    for candidate in function::all() {
        if ea >= candidate.start() && ea < candidate.end() {
            return Ok(candidate);
        }
    }

    Err(Error::not_found(format!(
        "no function contains address 0x{ea:x}"
    )))
}

fn build_record(func: &function::Function) -> Result<TitleRecord> {
    let demangled = name::demangled(func.start(), name::DemangleForm::Short).unwrap_or_default();
    let shortened = shorten_name(&demangled);

    let (title, source) = if !shortened.is_empty() {
        (shortened, "demangled")
    } else {
        (func.name().to_string(), "raw")
    };

    Ok(TitleRecord {
        start: func.start(),
        end: func.end(),
        raw_name: func.name().to_string(),
        title,
        source,
    })
}

fn collect_records(options: &Options) -> Result<Vec<TitleRecord>> {
    let mut records = Vec::new();

    if !options.targets.is_empty() {
        for token in &options.targets {
            let ea = resolve_symbol_or_address(token)?;
            let func = containing_function(ea)?;
            records.push(build_record(&func)?);
        }
    } else {
        for func in function::all() {
            if !options.include_thunks && func.is_thunk() {
                continue;
            }
            if !options.include_libraries && func.is_library() {
                continue;
            }
            records.push(build_record(&func)?);
        }
        records.sort_by_key(|entry| entry.start);
        records.truncate(options.limit);
    }

    Ok(records)
}

fn apply_comments(records: &[TitleRecord]) -> Result<usize> {
    let mut applied = 0usize;
    for entry in records {
        let text = format!("[IDA-names title] {}", entry.title);
        if comment::set(entry.start, &text, true).is_ok() {
            applied += 1;
        }
    }
    Ok(applied)
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;
    let records = collect_records(&options)?;

    println!("== ida_names_port_plugin (Rust adaptation) ==");
    println!("input: {}", options.input);
    println!(
        "mode: {}",
        if options.targets.is_empty() {
            "function listing"
        } else {
            "targeted lookup"
        }
    );
    println!("records: {}", records.len());
    println!(
        "{:<18} {:<18} {:<10} {:<34} Title",
        "Function", "End", "Source", "Raw Name"
    );
    println!(
        "----------------------------------------------------------------------------------------------"
    );
    for entry in &records {
        println!(
            "{:<18} {:<18} {:<10} {:<34} {}",
            format!("0x{:x}", entry.start),
            format!("0x{:x}", entry.end),
            entry.source,
            entry.raw_name,
            entry.title
        );
    }

    if options.apply_comments {
        let applied = apply_comments(&records)?;
        println!("applied repeatable title comments: {applied}");
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
