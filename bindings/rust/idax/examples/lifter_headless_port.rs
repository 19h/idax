mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, write_output, DatabaseSession};
use idax::{function, instruction, Error, Result};
use std::collections::HashMap;

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

fn choose_target_functions(options: &Options) -> Result<Vec<function::Function>> {
    if let Some(target) = &options.target {
        let ea = resolve_symbol_or_address(target)?;
        return Ok(vec![containing_function(ea)?]);
    }

    Ok(function::all()
        .filter(|candidate| {
            !candidate.is_library() && !candidate.is_thunk() && candidate.size() >= 16
        })
        .collect())
}

fn is_sse_passthrough_mnemonic(mnemonic: &str) -> bool {
    let passthrough = [
        "vcomiss",
        "vcomisd",
        "vucomiss",
        "vucomisd",
        "vpextrb",
        "vpextrw",
        "vpextrd",
        "vpextrq",
        "vcvttss2si",
        "vcvttsd2si",
        "vcvtsd2si",
        "vcvtsi2ss",
        "vcvtsi2sd",
    ];
    passthrough.contains(&mnemonic)
}

fn is_k_register_manipulation_mnemonic(mnemonic: &str) -> bool {
    mnemonic.starts_with("kmov")
        || mnemonic.starts_with("kadd")
        || mnemonic.starts_with("kand")
        || mnemonic.starts_with("kor")
        || mnemonic.starts_with("kxor")
        || mnemonic.starts_with("kxnor")
        || mnemonic.starts_with("knot")
        || mnemonic.starts_with("kshift")
        || mnemonic.starts_with("kunpck")
        || mnemonic.starts_with("ktest")
}

fn is_supported_vmx_mnemonic(mnemonic: &str) -> bool {
    let supported = [
        "vzeroupper",
        "vmxon",
        "vmxoff",
        "vmcall",
        "vmlaunch",
        "vmresume",
        "vmptrld",
        "vmptrst",
        "vmclear",
        "vmread",
        "vmwrite",
        "invept",
        "invvpid",
        "vmfunc",
    ];
    supported.contains(&mnemonic)
}

fn is_supported_avx_scalar_mnemonic(mnemonic: &str) -> bool {
    let supported = [
        "vaddss",
        "vsubss",
        "vmulss",
        "vdivss",
        "vaddsd",
        "vsubsd",
        "vmulsd",
        "vdivsd",
        "vminss",
        "vmaxss",
        "vminsd",
        "vmaxsd",
        "vsqrtss",
        "vsqrtsd",
        "vcvtss2sd",
        "vcvtsd2ss",
        "vmovss",
        "vmovsd",
        "vaddsh",
        "vsubsh",
        "vmulsh",
        "vdivsh",
        "vminsh",
        "vmaxsh",
        "vsqrtsh",
    ];
    supported.contains(&mnemonic)
}

fn is_supported_avx_packed_mnemonic(mnemonic: &str) -> bool {
    if mnemonic.starts_with("vcmp")
        || mnemonic.starts_with("vpcmp")
        || mnemonic.starts_with("vpcmpeq")
        || mnemonic.starts_with("vpcmpgt")
    {
        return true;
    }
    let supported = [
        "vandps",
        "vandpd",
        "vandnps",
        "vandnpd",
        "vorps",
        "vorpd",
        "vxorps",
        "vxorpd",
        "vpand",
        "vpandd",
        "vpandq",
        "vpandn",
        "vpandnd",
        "vpandnq",
        "vpor",
        "vpord",
        "vporq",
        "vpxor",
        "vpxord",
        "vpxorq",
        "vblendps",
        "vblendpd",
        "vblendvps",
        "vblendvpd",
        "vpblendd",
        "vpblendw",
        "vpblendvb",
        "vshufps",
        "vshufpd",
        "vpermilps",
        "vpermilpd",
        "vpermq",
        "vpermd",
        "vperm2f128",
        "vperm2i128",
        "vpsllw",
        "vpslld",
        "vpsllq",
        "vpsrlw",
        "vpsrld",
        "vpsrlq",
        "vpsraw",
        "vpsrad",
        "vpsraq",
        "vaddps",
        "vsubps",
        "vmulps",
        "vdivps",
        "vaddpd",
        "vsubpd",
        "vmulpd",
        "vdivpd",
        "vpaddb",
        "vpaddw",
        "vpaddd",
        "vpaddq",
        "vpsubb",
        "vpsubw",
        "vpsubd",
        "vpsubq",
        "vmovaps",
        "vmovups",
        "vmovapd",
        "vmovupd",
        "vmovdqa",
        "vmovdqu",
        "vmovdqa32",
        "vmovdqa64",
        "vmovdqu8",
        "vmovdqu16",
        "vmovdqu32",
        "vmovdqu64",
        "vmovd",
        "vmovq",
    ];
    supported.contains(&mnemonic)
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;

    let targets = choose_target_functions(&options)?;

    let mut report = String::new();
    report.push_str("lifter_headless_port (Rust adaptation)\n");
    report.push_str(&format!("input: {}\n", options.input));
    report.push_str(&format!("target functions: {}\n\n", targets.len()));

    let mut stats = HashMap::new();
    let mut vmx_count = 0;
    let mut avx_scalar_count = 0;
    let mut avx_packed_count = 0;
    let mut passthrough_count = 0;
    let mut kreg_count = 0;
    let mut total_instructions = 0;

    for target in &targets {
        if let Ok(addresses) = function::code_addresses(target.start()) {
            for address in addresses {
                if let Ok(inst) = instruction::decode(address) {
                    total_instructions += 1;
                    let mnemonic = inst.mnemonic().to_lowercase();

                    if is_sse_passthrough_mnemonic(&mnemonic) {
                        passthrough_count += 1;
                    } else if is_k_register_manipulation_mnemonic(&mnemonic) {
                        kreg_count += 1;
                    } else if is_supported_vmx_mnemonic(&mnemonic) {
                        vmx_count += 1;
                        *stats.entry(mnemonic.clone()).or_insert(0) += 1;
                    } else if is_supported_avx_scalar_mnemonic(&mnemonic) {
                        avx_scalar_count += 1;
                        *stats.entry(mnemonic.clone()).or_insert(0) += 1;
                    } else if is_supported_avx_packed_mnemonic(&mnemonic) {
                        avx_packed_count += 1;
                        *stats.entry(mnemonic.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    report.push_str("AVX/VMX Lifter Pre-Analysis Report\n");
    report.push_str("----------------------------------\n");
    report.push_str(&format!(
        "Total Instructions Scanned: {}\n",
        total_instructions
    ));
    report.push_str(&format!("Supported VMX Instructions: {}\n", vmx_count));
    report.push_str(&format!(
        "Supported AVX Scalar Instructions: {}\n",
        avx_scalar_count
    ));
    report.push_str(&format!(
        "Supported AVX Packed Instructions: {}\n",
        avx_packed_count
    ));
    report.push_str(&format!(
        "SSE Passthrough Instructions (IDA Native): {}\n",
        passthrough_count
    ));
    report.push_str(&format!(
        "K-Register Manipulation Instructions (NOP'd): {}\n\n",
        kreg_count
    ));

    if !stats.is_empty() {
        report.push_str("Instruction Distribution:\n");
        let mut sorted_stats: Vec<_> = stats.into_iter().collect();
        sorted_stats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        for (mnemonic, count) in sorted_stats {
            report.push_str(&format!("  {:12}: {}\n", mnemonic, count));
        }
    } else {
        report.push_str("No supported AVX/VMX instructions found in the target set.\n");
    }

    write_output(options.output.as_deref(), &report)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
