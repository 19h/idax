mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, write_output, DatabaseSession};
use idax::{database, function, Error, Result};

#[derive(Debug, Clone)]
struct Options {
    input: String,
    target: Option<String>,
    output: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            target: None,
            output: None,
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
                    "<binary_file> [--function <name|ea>] [--output <path>]",
                );
                std::process::exit(0);
            }
            "--function" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--function requires an argument"));
                }
                options.target = Some(args[index].clone());
            }
            "--output" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--output requires a file path"));
                }
                options.output = Some(args[index].clone());
            }
            unknown => {
                return Err(Error::validation(format!("unknown option: {unknown}")));
            }
        }
        index += 1;
    }

    Ok(options)
}

fn containing_function(address: u64) -> Result<function::Function> {
    if let Ok(found) = function::at(address) {
        return Ok(found);
    }

    for candidate in function::all() {
        if address >= candidate.start() && address < candidate.end() {
            return Ok(candidate);
        }
    }

    Err(Error::not_found(format!(
        "no function contains address 0x{address:x}"
    )))
}

fn choose_target_function(options: &Options) -> Result<function::Function> {
    if let Some(target) = &options.target {
        let ea = resolve_symbol_or_address(target)?;
        return containing_function(ea);
    }

    for candidate in function::all() {
        if candidate.is_library() || candidate.is_thunk() {
            continue;
        }
        if candidate.size() < 16 {
            continue;
        }
        return Ok(candidate);
    }

    function::by_index(0)
}

struct ProcessorContext {
    processor_id: i32,
    processor_name: String,
    bitness: i32,
    big_endian: bool,
    abi_name: String,
}

fn build_processor_context(function: &function::Function) -> Result<ProcessorContext> {
    let processor_id = database::processor_id()?;
    let processor_name = database::processor_name()?;
    let big_endian = database::is_big_endian()?;

    let mut bitness = function.bitness();
    if bitness != 16 && bitness != 32 && bitness != 64 {
        bitness = database::address_bitness()?;
    }

    let abi_name = database::abi_name()?;

    Ok(ProcessorContext {
        processor_id,
        processor_name,
        bitness,
        big_endian,
        abi_name,
    })
}

struct SpecChoice {
    sla_file: String,
    pspec_file: Option<String>,
}

fn choose_spec(context: &ProcessorContext) -> Result<SpecChoice> {
    let _processor = context.processor_id;
    let abi_lower = context.abi_name.to_lowercase();

    // Processor IDs match idax::database::ProcessorId enum
    // (15 = IntelX86, 73 = Arm, etc - simplified mapping)
    // Actually we just map by string name since ID mapping might vary
    let pname = context.processor_name.to_lowercase();

    if pname.starts_with("metapc") || pname.starts_with("80x86") || pname.starts_with("x86") {
        return Ok(SpecChoice {
            sla_file: if context.bitness == 64 {
                "x86-64.sla".into()
            } else {
                "x86.sla".into()
            },
            pspec_file: None,
        });
    } else if pname.starts_with("arm") {
        if context.bitness == 64 {
            return Ok(SpecChoice {
                sla_file: if context.big_endian {
                    "AARCH64BE.sla".into()
                } else {
                    "AARCH64.sla".into()
                },
                pspec_file: None,
            });
        }
        return Ok(SpecChoice {
            sla_file: if context.big_endian {
                "ARM7_be.sla".into()
            } else {
                "ARM7_le.sla".into()
            },
            pspec_file: None,
        });
    } else if pname.starts_with("mips") {
        if context.bitness == 64 || abi_lower.contains("n32") {
            return Ok(SpecChoice {
                sla_file: if context.big_endian {
                    "mips64be.sla".into()
                } else {
                    "mips64le.sla".into()
                },
                pspec_file: None,
            });
        }
        return Ok(SpecChoice {
            sla_file: if context.big_endian {
                "mips32be.sla".into()
            } else {
                "mips32le.sla".into()
            },
            pspec_file: None,
        });
    } else if pname.starts_with("ppc") {
        if context.bitness == 64 {
            if abi_lower.contains("xbox") {
                return Ok(SpecChoice {
                    sla_file: if context.big_endian {
                        "ppc_64_isa_altivec_be.sla".into()
                    } else {
                        "ppc_64_isa_altivec_le.sla".into()
                    },
                    pspec_file: None,
                });
            }
            return Ok(SpecChoice {
                sla_file: if context.big_endian {
                    "ppc_64_be.sla".into()
                } else {
                    "ppc_64_le.sla".into()
                },
                pspec_file: None,
            });
        }
        return Ok(SpecChoice {
            sla_file: if context.big_endian {
                "ppc_32_be.sla".into()
            } else {
                "ppc_32_le.sla".into()
            },
            pspec_file: None,
        });
    }

    Err(Error::unsupported(&format!(
        "No Sleigh mapping for active processor: name={} bits={} endian={}",
        context.processor_name,
        context.bitness,
        if context.big_endian { "BE" } else { "LE" }
    )))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;

    let target = choose_target_function(&options)?;
    let target_name = target.name().to_string();

    let mut report = String::new();
    report.push_str("idapcode_headless_port (Rust adaptation)\n");
    report.push_str(&format!("input: {}\n", options.input));
    report.push_str(&format!(
        "target: {} (0x{:x})\n\n",
        target_name,
        target.start()
    ));

    match build_processor_context(&target) {
        Ok(context) => {
            report.push_str("Processor Context\n");
            report.push_str("-----------------\n");
            report.push_str(&format!("Processor ID: {}\n", context.processor_id));
            report.push_str(&format!("Processor Name: {}\n", context.processor_name));
            report.push_str(&format!("Bitness: {}\n", context.bitness));
            report.push_str(&format!(
                "Endianness: {}\n",
                if context.big_endian { "Big" } else { "Little" }
            ));
            report.push_str(&format!(
                "ABI Name: {}\n",
                if context.abi_name.is_empty() {
                    "<none>"
                } else {
                    &context.abi_name
                }
            ));
            report.push_str("\n");

            match choose_spec(&context) {
                Ok(spec) => {
                    report.push_str("Sleigh Spec Resolution\n");
                    report.push_str("----------------------\n");
                    report.push_str(&format!("SLA File: {}\n", spec.sla_file));
                    if let Some(pspec) = spec.pspec_file {
                        report.push_str(&format!("PSPEC File: {}\n", pspec));
                    }
                }
                Err(e) => {
                    report.push_str("Sleigh Spec Resolution\n");
                    report.push_str("----------------------\n");
                    report.push_str(&format!("Error: {}\n", e.message));
                }
            }
        }
        Err(e) => {
            report.push_str("Processor Context\n");
            report.push_str("-----------------\n");
            report.push_str(&format!(
                "Failed to build processor context: {}\n",
                e.message
            ));
        }
    }

    write_output(options.output.as_deref(), &report)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
