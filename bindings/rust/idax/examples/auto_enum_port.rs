#[allow(dead_code)]
mod common;

// Adapted from Auto Enum; upstream copyright/license is retained in
// examples/plugin/auto_enum_port_LICENSE.txt at the repository root.

use common::{DatabaseSession, format_error, print_usage};
use idax::error::ErrorCategory;
use idax::types::{EnumMember, FunctionDetails, TypeInfo};
use idax::{Error, Result, database, types};
use std::collections::HashSet;

#[derive(Debug, Clone)]
struct Options {
    input: String,
    apply: bool,
    show: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            apply: false,
            show: 20,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MemberSpec {
    name: &'static str,
    value: u64,
}

#[derive(Debug, Clone, Copy)]
struct EnumSpec {
    id: &'static str,
    members: &'static [MemberSpec],
}

#[derive(Debug, Clone, Copy)]
struct ArgumentSpec {
    name: &'static str,
    enum_id: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct FunctionSpec {
    name: &'static str,
    arguments: &'static [ArgumentSpec],
}

#[derive(Debug, Clone)]
struct Candidate {
    address: u64,
    function_name: String,
    argument_names: Vec<String>,
}

#[derive(Debug, Default)]
struct Summary {
    imports: usize,
    matched_functions: usize,
    candidate_functions: usize,
    candidate_arguments: usize,
    changed_functions: usize,
    changed_arguments: usize,
    ineligible_arguments: usize,
    recoverable_failures: usize,
}

const OPEN_FLAGS: &[MemberSpec] = &[
    MemberSpec {
        name: "RSYNC",
        value: 1_052_672,
    },
    MemberSpec {
        name: "WRONLY",
        value: 1,
    },
    MemberSpec {
        name: "DIRECT",
        value: 16_384,
    },
    MemberSpec {
        name: "DIRECTORY",
        value: 65_536,
    },
    MemberSpec {
        name: "DSYNC",
        value: 4_096,
    },
    MemberSpec {
        name: "RDONLY",
        value: 0,
    },
    MemberSpec {
        name: "CREAT",
        value: 64,
    },
    MemberSpec {
        name: "TRUNC",
        value: 512,
    },
    MemberSpec {
        name: "RDWR",
        value: 2,
    },
    MemberSpec {
        name: "CLOEXEC",
        value: 524_288,
    },
    MemberSpec {
        name: "NOFOLLOW",
        value: 131_072,
    },
    MemberSpec {
        name: "APPEND",
        value: 1_024,
    },
    MemberSpec {
        name: "LARGEFILE",
        value: 32_768,
    },
    MemberSpec {
        name: "ASYNC",
        value: 8_192,
    },
    MemberSpec {
        name: "NDELAY",
        value: 2_048,
    },
    MemberSpec {
        name: "TMPFILE",
        value: 4_259_840,
    },
    MemberSpec {
        name: "NOATIME",
        value: 262_144,
    },
    MemberSpec {
        name: "EXCL",
        value: 128,
    },
    MemberSpec {
        name: "PATH",
        value: 2_097_152,
    },
    MemberSpec {
        name: "NOCTTY",
        value: 256,
    },
];

const ADDRESS_FAMILIES: &[MemberSpec] = &[
    MemberSpec {
        name: "MPLS",
        value: 28,
    },
    MemberSpec {
        name: "UNIX",
        value: 1,
    },
    MemberSpec {
        name: "BLUETOOTH",
        value: 31,
    },
    MemberSpec {
        name: "INET6",
        value: 10,
    },
    MemberSpec {
        name: "INET",
        value: 2,
    },
    MemberSpec {
        name: "KEY",
        value: 15,
    },
    MemberSpec {
        name: "IB",
        value: 27,
    },
    MemberSpec {
        name: "RDS",
        value: 21,
    },
    MemberSpec {
        name: "TIPC",
        value: 30,
    },
    MemberSpec {
        name: "NETLINK",
        value: 16,
    },
    MemberSpec {
        name: "VSOCK",
        value: 40,
    },
    MemberSpec {
        name: "CAN",
        value: 29,
    },
    MemberSpec {
        name: "KCM",
        value: 41,
    },
    MemberSpec {
        name: "X25",
        value: 9,
    },
    MemberSpec {
        name: "AX25",
        value: 3,
    },
    MemberSpec {
        name: "IPX",
        value: 4,
    },
    MemberSpec {
        name: "DECnet",
        value: 12,
    },
    MemberSpec {
        name: "PACKET",
        value: 17,
    },
    MemberSpec {
        name: "ALG",
        value: 38,
    },
    MemberSpec {
        name: "APPLETALK",
        value: 5,
    },
    MemberSpec {
        name: "PPPOX",
        value: 24,
    },
    MemberSpec {
        name: "XDP",
        value: 44,
    },
    MemberSpec {
        name: "LLC",
        value: 26,
    },
];

const SOCKET_TYPES: &[MemberSpec] = &[
    MemberSpec {
        name: "SEQPACKET",
        value: 5,
    },
    MemberSpec {
        name: "PACKET",
        value: 10,
    },
    MemberSpec {
        name: "NONBLOCK",
        value: 2_048,
    },
    MemberSpec {
        name: "CLOEXEC",
        value: 524_288,
    },
    MemberSpec {
        name: "RDM",
        value: 4,
    },
    MemberSpec {
        name: "DGRAM",
        value: 2,
    },
    MemberSpec {
        name: "RAW",
        value: 3,
    },
    MemberSpec {
        name: "STREAM",
        value: 1,
    },
];

const PROTECTION_FLAGS: &[MemberSpec] = &[
    MemberSpec {
        name: "WRITE",
        value: 2,
    },
    MemberSpec {
        name: "EXEC",
        value: 4,
    },
    MemberSpec {
        name: "NONE",
        value: 0,
    },
    MemberSpec {
        name: "READ",
        value: 1,
    },
];

const MAP_FLAGS: &[MemberSpec] = &[
    MemberSpec {
        name: "NORESERVE",
        value: 16_384,
    },
    MemberSpec {
        name: "NONBLOCK",
        value: 65_536,
    },
    MemberSpec {
        name: "FIXED",
        value: 16,
    },
    MemberSpec {
        name: "FIXED_NOREPLACE",
        value: 1_048_576,
    },
    MemberSpec {
        name: "PRIVATE",
        value: 2,
    },
    MemberSpec {
        name: "32BIT",
        value: 64,
    },
    MemberSpec {
        name: "GROWSDOWN",
        value: 256,
    },
    MemberSpec {
        name: "LOCKED",
        value: 8_192,
    },
    MemberSpec {
        name: "EXECUTABLE",
        value: 4_096,
    },
    MemberSpec {
        name: "ANON",
        value: 32,
    },
    MemberSpec {
        name: "SYNC",
        value: 524_288,
    },
    MemberSpec {
        name: "STACK",
        value: 131_072,
    },
    MemberSpec {
        name: "HUGETLB",
        value: 262_144,
    },
    MemberSpec {
        name: "DENYWRITE",
        value: 2_048,
    },
    MemberSpec {
        name: "POPULATE",
        value: 32_768,
    },
    MemberSpec {
        name: "HUGE_2MB",
        value: 1_409_286_144,
    },
    MemberSpec {
        name: "FILE",
        value: 0,
    },
    MemberSpec {
        name: "SHARED",
        value: 1,
    },
];

const PRCTL_OPTIONS: &[MemberSpec] = &[
    MemberSpec {
        name: "SET_PDEATHSIG",
        value: 1,
    },
    MemberSpec {
        name: "GET_PDEATHSIG",
        value: 2,
    },
    MemberSpec {
        name: "GET_DUMPABLE",
        value: 3,
    },
    MemberSpec {
        name: "SET_DUMPABLE",
        value: 4,
    },
    MemberSpec {
        name: "GET_UNALIGN",
        value: 5,
    },
    MemberSpec {
        name: "SET_UNALIGN",
        value: 6,
    },
    MemberSpec {
        name: "GET_KEEPCAPS",
        value: 7,
    },
    MemberSpec {
        name: "SET_KEEPCAPS",
        value: 8,
    },
    MemberSpec {
        name: "SET_NAME",
        value: 15,
    },
    MemberSpec {
        name: "GET_NAME",
        value: 16,
    },
    MemberSpec {
        name: "GET_SECCOMP",
        value: 21,
    },
    MemberSpec {
        name: "SET_SECCOMP",
        value: 22,
    },
    MemberSpec {
        name: "CAPBSET_READ",
        value: 23,
    },
    MemberSpec {
        name: "CAPBSET_DROP",
        value: 24,
    },
    MemberSpec {
        name: "SET_NO_NEW_PRIVS",
        value: 38,
    },
    MemberSpec {
        name: "GET_NO_NEW_PRIVS",
        value: 39,
    },
];

const ACCESS_MODES: &[MemberSpec] = &[
    MemberSpec {
        name: "F_OK",
        value: 0,
    },
    MemberSpec {
        name: "R_OK",
        value: 4,
    },
    MemberSpec {
        name: "W_OK",
        value: 2,
    },
    MemberSpec {
        name: "X_OK",
        value: 1,
    },
];

const SOCKET_LEVELS: &[MemberSpec] = &[
    MemberSpec {
        name: "SOL_IP",
        value: 0,
    },
    MemberSpec {
        name: "SOL_SOCKET",
        value: 1,
    },
    MemberSpec {
        name: "SOL_TCP",
        value: 6,
    },
    MemberSpec {
        name: "SOL_UDP",
        value: 17,
    },
    MemberSpec {
        name: "SOL_IPV6",
        value: 41,
    },
    MemberSpec {
        name: "SOL_ICMPV6",
        value: 58,
    },
    MemberSpec {
        name: "SOL_SCTP",
        value: 132,
    },
    MemberSpec {
        name: "SOL_RAW",
        value: 255,
    },
];

const PROCESS_ACCESS: &[MemberSpec] = &[
    MemberSpec {
        name: "ALL_ACCESS",
        value: 65_535,
    },
    MemberSpec {
        name: "CREATE_PROCESS",
        value: 128,
    },
    MemberSpec {
        name: "CREATE_THREAD",
        value: 2,
    },
    MemberSpec {
        name: "DUP_HANDLE",
        value: 64,
    },
    MemberSpec {
        name: "QUERY_INFORMATION",
        value: 1_024,
    },
    MemberSpec {
        name: "QUERY_LIMITED_INFORMATION",
        value: 4_096,
    },
    MemberSpec {
        name: "SET_INFORMATION",
        value: 512,
    },
    MemberSpec {
        name: "SET_QUOTA",
        value: 256,
    },
    MemberSpec {
        name: "SUSPEND_RESUME",
        value: 2_048,
    },
    MemberSpec {
        name: "TERMINATE",
        value: 1,
    },
    MemberSpec {
        name: "VM_OPERATION",
        value: 8,
    },
    MemberSpec {
        name: "VM_READ",
        value: 16,
    },
    MemberSpec {
        name: "VM_WRITE",
        value: 32,
    },
];

const ENUMS: &[EnumSpec] = &[
    EnumSpec {
        id: "O_2",
        members: OPEN_FLAGS,
    },
    EnumSpec {
        id: "AF_1",
        members: ADDRESS_FAMILIES,
    },
    EnumSpec {
        id: "SOCK_1",
        members: SOCKET_TYPES,
    },
    EnumSpec {
        id: "PROT",
        members: PROTECTION_FLAGS,
    },
    EnumSpec {
        id: "PROT_1",
        members: PROTECTION_FLAGS,
    },
    EnumSpec {
        id: "MAP",
        members: MAP_FLAGS,
    },
    EnumSpec {
        id: "PR",
        members: PRCTL_OPTIONS,
    },
    EnumSpec {
        id: "53482",
        members: ACCESS_MODES,
    },
    EnumSpec {
        id: "31061",
        members: SOCKET_LEVELS,
    },
    EnumSpec {
        id: "PROCESS",
        members: PROCESS_ACCESS,
    },
];

const OPEN_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "pathname",
        enum_id: "",
    },
    ArgumentSpec {
        name: "oflag",
        enum_id: "O_2",
    },
    ArgumentSpec {
        name: "mode",
        enum_id: "",
    },
];
const SOCKET_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "domain",
        enum_id: "AF_1",
    },
    ArgumentSpec {
        name: "type",
        enum_id: "SOCK_1",
    },
    ArgumentSpec {
        name: "protocol",
        enum_id: "",
    },
];
const MMAP_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "addr",
        enum_id: "",
    },
    ArgumentSpec {
        name: "length",
        enum_id: "",
    },
    ArgumentSpec {
        name: "prot",
        enum_id: "PROT",
    },
    ArgumentSpec {
        name: "flags",
        enum_id: "MAP",
    },
    ArgumentSpec {
        name: "fd",
        enum_id: "",
    },
    ArgumentSpec {
        name: "offset",
        enum_id: "",
    },
];
const MPROTECT_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "addr",
        enum_id: "",
    },
    ArgumentSpec {
        name: "len",
        enum_id: "",
    },
    ArgumentSpec {
        name: "prot",
        enum_id: "PROT_1",
    },
];
const PRCTL_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "option",
        enum_id: "PR",
    },
    ArgumentSpec {
        name: "arg2",
        enum_id: "",
    },
    ArgumentSpec {
        name: "arg3",
        enum_id: "",
    },
    ArgumentSpec {
        name: "arg4",
        enum_id: "",
    },
    ArgumentSpec {
        name: "arg5",
        enum_id: "",
    },
];
const ACCESS_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "pathname",
        enum_id: "",
    },
    ArgumentSpec {
        name: "mode",
        enum_id: "53482",
    },
];
const SETSOCKOPT_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "fd",
        enum_id: "",
    },
    ArgumentSpec {
        name: "level",
        enum_id: "31061",
    },
    ArgumentSpec {
        name: "optname",
        enum_id: "",
    },
    ArgumentSpec {
        name: "optval",
        enum_id: "",
    },
    ArgumentSpec {
        name: "optlen",
        enum_id: "",
    },
];
const OPEN_PROCESS_ARGS: &[ArgumentSpec] = &[
    ArgumentSpec {
        name: "dwDesiredAccess",
        enum_id: "PROCESS",
    },
    ArgumentSpec {
        name: "bInheritHandle",
        enum_id: "",
    },
];

const FUNCTIONS: &[FunctionSpec] = &[
    FunctionSpec {
        name: "open",
        arguments: OPEN_ARGS,
    },
    FunctionSpec {
        name: "open64",
        arguments: OPEN_ARGS,
    },
    FunctionSpec {
        name: "socket",
        arguments: SOCKET_ARGS,
    },
    FunctionSpec {
        name: "mmap",
        arguments: MMAP_ARGS,
    },
    FunctionSpec {
        name: "mmap64",
        arguments: MMAP_ARGS,
    },
    FunctionSpec {
        name: "mprotect",
        arguments: MPROTECT_ARGS,
    },
    FunctionSpec {
        name: "prctl",
        arguments: PRCTL_ARGS,
    },
    FunctionSpec {
        name: "access",
        arguments: ACCESS_ARGS,
    },
    FunctionSpec {
        name: "setsockopt",
        arguments: SETSOCKOPT_ARGS,
    },
    FunctionSpec {
        name: "OpenProcess",
        arguments: OPEN_PROCESS_ARGS,
    },
];

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
                print_usage(&args[0], "<binary_file> [--apply] [--show <count>]");
                std::process::exit(0);
            }
            "--apply" => options.apply = true,
            "--show" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--show requires a value"));
                }
                options.show = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --show value"))?;
            }
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        index += 1;
    }
    Ok(options)
}

fn normalize_import_name(input: &str) -> String {
    let mut name = input.strip_prefix("__imp_").unwrap_or(input);
    if name.starts_with(['.', '_']) {
        name = &name[1..];
    }
    name.split('@').next().unwrap_or(name).to_owned()
}

fn find_function(name: &str) -> Option<&'static FunctionSpec> {
    FUNCTIONS.iter().find(|spec| spec.name == name)
}

fn enum_name(id: &str) -> String {
    format!("ENUM_{id}")
}

fn ensure_enum(id: &str) -> Result<TypeInfo> {
    let name = enum_name(id);
    match TypeInfo::by_name(&name) {
        Ok(existing) if existing.is_enum() => return Ok(existing),
        Ok(_) => return Err(Error::conflict(format!("{name} is not an enum type"))),
        Err(error) if error.category == ErrorCategory::NotFound => {}
        Err(error) => return Err(error),
    }
    let source = ENUMS
        .iter()
        .find(|spec| spec.id == id)
        .ok_or_else(|| Error::not_found(format!("enum corpus entry not found: {id}")))?;
    let preserve_names = id.bytes().all(|value| value.is_ascii_digit());
    let members = source
        .members
        .iter()
        .map(|member| EnumMember {
            name: if member.value == 0 {
                "NULL".to_owned()
            } else if preserve_names {
                member.name.to_owned()
            } else {
                format!("{id}_{}", member.name)
            },
            value: member.value,
            comment: String::new(),
        })
        .collect::<Vec<_>>();
    let created = TypeInfo::enum_type(&members, 4, false)?;
    created.save_as(&name)?;
    TypeInfo::by_name(&name)
}

fn select_argument(
    details: &FunctionDetails,
    wanted: ArgumentSpec,
    fallback: usize,
    used: &HashSet<usize>,
) -> Option<usize> {
    if !wanted.name.is_empty() {
        if let Some(index) = details
            .arguments
            .iter()
            .enumerate()
            .find_map(|(index, argument)| {
                (!used.contains(&index) && argument.name == wanted.name).then_some(index)
            })
        {
            return Some(index);
        }
    }
    (fallback < details.arguments.len() && !used.contains(&fallback)).then_some(fallback)
}

fn enrich(options: &Options) -> Result<(Summary, Vec<Candidate>)> {
    let modules = database::import_modules()?;
    let mut summary = Summary::default();
    let mut candidates = Vec::new();
    for module in modules {
        for symbol in module.symbols {
            summary.imports += 1;
            let normalized = normalize_import_name(&symbol.name);
            let Some(spec) = find_function(&normalized) else {
                continue;
            };
            summary.matched_functions += 1;
            let original = match types::retrieve(symbol.address) {
                Ok(value) => value,
                Err(_) => {
                    summary.recoverable_failures += 1;
                    continue;
                }
            };
            let details = match original.function_details() {
                Ok(value) => value,
                Err(_) => {
                    summary.recoverable_failures += 1;
                    continue;
                }
            };

            let mut updated = original.clone();
            let mut used = HashSet::new();
            let mut argument_names = Vec::new();
            let mut changed_here = 0usize;
            for (position, wanted) in spec.arguments.iter().copied().enumerate() {
                if wanted.enum_id.is_empty() {
                    continue;
                }
                let Some(selected) = select_argument(&details, wanted, position, &used) else {
                    summary.recoverable_failures += 1;
                    continue;
                };
                used.insert(selected);
                let current = &details.arguments[selected].r#type;
                if !current.is_integer() || current.is_enum() || current.is_pointer() {
                    summary.ineligible_arguments += 1;
                    continue;
                }
                let display_name = if details.arguments[selected].name.is_empty() {
                    wanted.name
                } else {
                    &details.arguments[selected].name
                };
                argument_names.push(format!("{display_name}:{}", enum_name(wanted.enum_id)));
                if options.apply {
                    match ensure_enum(wanted.enum_id).and_then(|replacement| {
                        updated.with_function_argument_type(selected, &replacement)
                    }) {
                        Ok(next) => {
                            updated = next;
                            changed_here += 1;
                        }
                        Err(_) => summary.recoverable_failures += 1,
                    }
                }
            }

            if argument_names.is_empty() {
                continue;
            }
            summary.candidate_functions += 1;
            summary.candidate_arguments += argument_names.len();
            candidates.push(Candidate {
                address: symbol.address,
                function_name: normalized,
                argument_names,
            });
            if options.apply && changed_here > 0 {
                match updated.apply(symbol.address) {
                    Ok(()) => {
                        summary.changed_functions += 1;
                        summary.changed_arguments += changed_here;
                    }
                    Err(_) => summary.recoverable_failures += 1,
                }
            }
        }
    }
    Ok((summary, candidates))
}

fn print_report(options: &Options, summary: &Summary, candidates: &[Candidate]) {
    println!("Auto Enum port (Rust headless adaptation)");
    println!("input: {}", options.input);
    println!("mode: {}", if options.apply { "apply" } else { "report" });
    println!("imports_scanned: {}", summary.imports);
    println!("matched_functions: {}", summary.matched_functions);
    println!("candidate_functions: {}", summary.candidate_functions);
    println!("candidate_arguments: {}", summary.candidate_arguments);
    println!("changed_functions: {}", summary.changed_functions);
    println!("changed_arguments: {}", summary.changed_arguments);
    println!("ineligible_arguments: {}", summary.ineligible_arguments);
    println!("recoverable_failures: {}", summary.recoverable_failures);
    println!("candidates_shown: {}", candidates.len().min(options.show));
    for candidate in candidates.iter().take(options.show) {
        println!(
            "  0x{:x} {} {}",
            candidate.address,
            candidate.function_name,
            candidate.argument_names.join(",")
        );
    }
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let options = parse_options(&args)?;
    let _session = DatabaseSession::open(&options.input, true)?;
    let (summary, candidates) = enrich(&options)?;
    if options.apply {
        database::save()?;
    }
    print_report(&options, &summary, &candidates);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_import_decorations() {
        assert_eq!(normalize_import_name("__imp_socket@12"), "socket");
        assert_eq!(normalize_import_name("_mmap"), "mmap");
    }

    #[test]
    fn preserves_original_enum_member_naming_rule() {
        assert_eq!(enum_name("O_2"), "ENUM_O_2");
        assert!(ENUMS.iter().any(|spec| spec.id == "31061"));
        assert!(ENUMS.iter().any(|spec| spec.id == "PROCESS"));
        assert_eq!(find_function("OpenProcess").unwrap().arguments.len(), 2);
        assert_eq!(ACCESS_MODES[0].value, 0);
    }
}
