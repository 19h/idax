mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::address::BAD_ADDRESS;
use idax::{comment, database, function, instruction, name, Error, Result};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy)]
enum DriverType {
    Wdf,
    StreamMiniDriver,
    Wdm,
}

impl DriverType {
    fn as_str(self) -> &'static str {
        match self {
            DriverType::Wdf => "WDF",
            DriverType::StreamMiniDriver => "Stream Minidriver",
            DriverType::Wdm => "WDM",
        }
    }
}

#[derive(Debug, Clone)]
struct DispatchCandidate {
    address: u64,
    name: String,
    reason: &'static str,
}

#[derive(Debug, Clone)]
struct IoctlHit {
    value: u32,
    address: u64,
    function_name: String,
}

#[derive(Debug, Clone)]
struct Options {
    input: String,
    max_scan: usize,
    show_top: usize,
    annotate: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            max_scan: 80_000,
            show_top: 20,
            annotate: false,
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
                    "<binary_file> [--max-scan <count>] [--top <n>] [--annotate]",
                );
                std::process::exit(0);
            }
            "--max-scan" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--max-scan requires a value"));
                }
                options.max_scan = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-scan value"))?;
            }
            "--top" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--top requires a value"));
                }
                options.show_top = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --top value"))?;
            }
            "--annotate" => {
                options.annotate = true;
            }
            unknown => {
                return Err(Error::validation(format!("unknown option: {unknown}")));
            }
        }
        index += 1;
    }

    Ok(options)
}

fn collect_imports() -> Result<HashSet<String>> {
    let modules = database::import_modules()?;
    let mut imports = HashSet::new();
    for module in modules {
        for symbol in module.symbols {
            if !symbol.name.is_empty() {
                imports.insert(symbol.name.to_ascii_lowercase());
            }
        }
    }
    Ok(imports)
}

fn detect_driver_type(imports: &HashSet<String>) -> DriverType {
    if imports.contains("wdfdrivercreate")
        || imports.contains("wdfversionbind")
        || imports.contains("wdfdevicecreate")
    {
        return DriverType::Wdf;
    }
    if imports.contains("streamclassregisterminidriver") {
        return DriverType::StreamMiniDriver;
    }
    DriverType::Wdm
}

fn resolve_driver_entry() -> Result<u64> {
    for candidate in ["DriverEntry", "GsDriverEntry", "driverentry"] {
        if let Ok(address) = name::resolve(candidate, BAD_ADDRESS)
            && address != BAD_ADDRESS
        {
            return Ok(address);
        }
    }

    function::by_index(0)
        .map(|func| func.start())
        .map_err(|_| Error::not_found("unable to resolve driver entry"))
}

fn collect_dispatch_candidates(driver_entry: u64) -> Vec<DispatchCandidate> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let mut push = |address: u64, name_text: String, reason: &'static str| {
        if seen.insert(address) {
            out.push(DispatchCandidate {
                address,
                name: name_text,
                reason,
            });
        }
    };

    for func in function::all() {
        let lowered = func.name().to_ascii_lowercase();
        if lowered.contains("dispatch") || lowered.contains("ioctl") {
            push(func.start(), func.name().to_string(), "name-pattern");
        }
    }

    if let Ok(callees) = function::callees(driver_entry) {
        for callee in callees {
            let callee_name = function::name_at(callee).unwrap_or_else(|_| "<unknown>".to_string());
            let lowered = callee_name.to_ascii_lowercase();
            if lowered.contains("dispatch") || lowered.contains("ioctl") {
                push(callee, callee_name, "callee-of-driver-entry");
            }
        }
    }

    out.sort_by_key(|entry| entry.address);
    out
}

fn decode_ioctl(value: u32) -> (u16, u16, u16, u16) {
    let device = ((value >> 16) & 0xffff) as u16;
    let access = ((value >> 14) & 0x3) as u16;
    let function_code = ((value >> 2) & 0x0fff) as u16;
    let method = (value & 0x3) as u16;
    (device, access, function_code, method)
}

fn ioctl_method_name(method: u16) -> &'static str {
    match method {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        3 => "METHOD_NEITHER",
        _ => "METHOD_UNKNOWN",
    }
}

fn ioctl_access_name(access: u16) -> &'static str {
    match access {
        0 => "FILE_ANY_ACCESS",
        1 => "FILE_READ_ACCESS",
        2 => "FILE_WRITE_ACCESS",
        3 => "FILE_READ_WRITE_ACCESS",
        _ => "FILE_ACCESS_UNKNOWN",
    }
}

fn likely_ioctl(value: u64) -> bool {
    if value < 0x0001_0000 || value > u32::MAX as u64 {
        return false;
    }
    let raw = value as u32;
    let (device, _, function_code, method) = decode_ioctl(raw);
    device != 0 && function_code != 0 && method <= 3
}

fn scan_ioctls(max_scan: usize) -> (Vec<IoctlHit>, usize) {
    let mut inspected = 0usize;
    let mut hits = BTreeMap::<u32, IoctlHit>::new();

    'outer: for func in function::all() {
        let function_name = func.name().to_string();
        let addresses = match function::code_addresses(func.start()) {
            Ok(list) => list,
            Err(_) => continue,
        };

        for ea in addresses {
            if inspected >= max_scan {
                break 'outer;
            }
            inspected += 1;

            let decoded = match instruction::decode(ea) {
                Ok(value) => value,
                Err(_) => continue,
            };

            for operand in decoded.operands() {
                if !operand.is_immediate() {
                    continue;
                }
                let value = operand.value();
                if !likely_ioctl(value) {
                    continue;
                }

                let raw = value as u32;
                hits.entry(raw).or_insert(IoctlHit {
                    value: raw,
                    address: ea,
                    function_name: function_name.clone(),
                });
            }
        }
    }

    (hits.into_values().collect(), inspected)
}

fn annotate_hits(hits: &[IoctlHit]) -> usize {
    let mut applied = 0usize;
    for hit in hits {
        let (device, access, function_code, method) = decode_ioctl(hit.value);
        let text = format!(
            "[DriverBuddy] IOCTL 0x{:08x} dev=0x{:04x} fn=0x{:03x} {} {}",
            hit.value,
            device,
            function_code,
            ioctl_access_name(access),
            ioctl_method_name(method)
        );
        if comment::set(hit.address, &text, false).is_ok() {
            applied += 1;
        }
    }
    applied
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;

    let imports = collect_imports()?;
    let driver_type = detect_driver_type(&imports);
    let driver_entry = resolve_driver_entry()?;
    let dispatch = collect_dispatch_candidates(driver_entry);
    let (ioctls, inspected) = scan_ioctls(options.max_scan);

    println!("DriverBuddy port (Rust adaptation)");
    println!("input: {}", options.input);
    println!("driver_type: {}", driver_type.as_str());
    println!("driver_entry: 0x{:x}", driver_entry);
    println!("imports_indexed: {}", imports.len());
    println!("instructions_scanned: {}", inspected);
    println!("ioctl_constants_found: {}", ioctls.len());

    println!("\nDispatch candidates (top {}):", options.show_top);
    if dispatch.is_empty() {
        println!("  <none>");
    } else {
        for candidate in dispatch.iter().take(options.show_top) {
            println!(
                "  - 0x{:x} {} ({})",
                candidate.address, candidate.name, candidate.reason
            );
        }
    }

    println!("\nDecoded IOCTL candidates (top {}):", options.show_top);
    if ioctls.is_empty() {
        println!("  <none>");
    } else {
        for hit in ioctls.iter().take(options.show_top) {
            let (device, access, function_code, method) = decode_ioctl(hit.value);
            println!(
                "  - 0x{:08x} @ 0x{:x} ({}) dev=0x{:04x} fn=0x{:03x} {} {}",
                hit.value,
                hit.address,
                hit.function_name,
                device,
                function_code,
                ioctl_access_name(access),
                ioctl_method_name(method)
            );
        }
    }

    if options.annotate {
        let applied = annotate_hits(&ioctls);
        println!("\nannotations_applied: {}", applied);
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
