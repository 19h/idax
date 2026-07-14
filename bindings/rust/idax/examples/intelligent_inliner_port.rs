#[allow(dead_code)]
mod common;

use common::{DatabaseSession, format_error, print_usage};
use idax::error::ErrorCategory;
use idax::instruction::OperandType;
use idax::{Error, Result, database, decompiler, function, graph, instruction, types, xref};

const STRICT_INSTRUCTION_THRESHOLD: usize = 7;
const SCORE_THRESHOLD: i32 = 5;

#[derive(Debug, Clone)]
struct Options {
    input: String,
    apply: bool,
    maximum_callers: usize,
    show: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            apply: false,
            maximum_callers: 0,
            show: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Features {
    instruction_count: usize,
    call_count: usize,
    memory_writes: usize,
    has_indirect_call: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionReason {
    StrictSize,
    Score,
}

impl SelectionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::StrictSize => "strict-size",
            Self::Score => "score",
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    address: u64,
    name: String,
    instruction_count: usize,
    score: i32,
    reason: SelectionReason,
    already_outlined: bool,
}

#[derive(Debug, Default)]
struct Summary {
    total: usize,
    processed: usize,
    selected: usize,
    selected_by_strict_size: usize,
    selected_by_score: usize,
    changed: usize,
    already_outlined: usize,
    skipped_flags: usize,
    skipped_variadic: usize,
    skipped_callers: usize,
    analysis_failures: usize,
    mutation_failures: usize,
    cache_invalidation_failures: usize,
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
                    "<binary_file> [--apply] [--max-callers <count>] [--show <count>]",
                );
                std::process::exit(0);
            }
            "--apply" => options.apply = true,
            "--max-callers" => {
                index += 1;
                if index >= args.len() {
                    return Err(Error::validation("--max-callers requires a value"));
                }
                options.maximum_callers = args[index]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-callers value"))?;
            }
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

fn direct_call_operand(decoded: &instruction::Instruction) -> bool {
    decoded.operand(0).is_ok_and(|operand| {
        matches!(
            operand.op_type(),
            OperandType::NearAddress | OperandType::FarAddress
        )
    })
}

fn extract_features(function_address: u64) -> Result<Features> {
    let addresses = function::code_addresses(function_address)?;
    let mut features = Features {
        instruction_count: addresses.len(),
        ..Features::default()
    };

    for address in addresses {
        let is_call = instruction::is_call(address);
        let decoded = instruction::decode(address).ok();
        if is_call {
            features.call_count += 1;
            if decoded
                .as_ref()
                .is_none_or(|value| !direct_call_operand(value))
            {
                features.has_indirect_call = true;
            }
        }
        if decoded.as_ref().is_some_and(|value| {
            value
                .operands()
                .iter()
                .any(|operand| operand.is_memory() && operand.is_written())
        }) {
            features.memory_writes += 1;
        }
    }
    Ok(features)
}

fn is_variadic(function_address: u64) -> bool {
    if let Ok(value) = types::retrieve(function_address) {
        if value.is_variadic_function().unwrap_or(false) {
            return true;
        }
        return value
            .declaration(None)
            .is_ok_and(|declaration| declaration.contains("..."));
    }
    false
}

fn basic_block_count(function_address: u64) -> usize {
    graph::flowchart(function_address)
        .map(|blocks| blocks.len())
        .unwrap_or(0)
}

fn has_data_references(function_address: u64) -> bool {
    xref::data_refs_to(function_address).is_ok_and(|references| !references.is_empty())
}

fn inlining_score(features: Features, block_count: usize, has_data_refs: bool) -> i32 {
    let mut score = 0;
    if features.instruction_count < 4 {
        score += 2;
    }
    if block_count == 1 {
        score += 1;
    }
    if features.memory_writes == 0 {
        score += 1;
    }
    if features.call_count == 0 {
        score += 1;
    }
    if features.call_count == 1 && !features.has_indirect_call {
        score += 1;
    }
    if !features.has_indirect_call {
        score += 1;
    }
    if !has_data_refs {
        score += 1;
    }
    score
}

fn select_reason(instruction_count: usize, score: i32) -> Option<SelectionReason> {
    if instruction_count < STRICT_INSTRUCTION_THRESHOLD {
        Some(SelectionReason::StrictSize)
    } else if score >= SCORE_THRESHOLD {
        Some(SelectionReason::Score)
    } else {
        None
    }
}

fn analyze(options: &Options) -> (Summary, Vec<Candidate>) {
    let functions: Vec<_> = function::all().collect();
    let mut summary = Summary {
        total: functions.len(),
        ..Summary::default()
    };
    let mut candidates = Vec::new();

    for current in functions {
        if current.is_thunk() || current.is_library() || !current.returns() {
            summary.skipped_flags += 1;
            summary.processed += 1;
            continue;
        }
        if is_variadic(current.start()) {
            summary.skipped_variadic += 1;
            summary.processed += 1;
            continue;
        }
        if options.maximum_callers > 0
            && xref::code_refs_to(current.start())
                .map(|references| references.len())
                .unwrap_or(0)
                > options.maximum_callers
        {
            summary.skipped_callers += 1;
            summary.processed += 1;
            continue;
        }

        let outlined = match function::is_outlined(current.start()) {
            Ok(value) => value,
            Err(_) => {
                summary.analysis_failures += 1;
                summary.processed += 1;
                continue;
            }
        };
        if outlined {
            summary.already_outlined += 1;
        }

        let features = match extract_features(current.start()) {
            Ok(value) => value,
            Err(_) => {
                summary.analysis_failures += 1;
                summary.processed += 1;
                continue;
            }
        };
        let score = inlining_score(
            features,
            basic_block_count(current.start()),
            has_data_references(current.start()),
        );
        if let Some(reason) = select_reason(features.instruction_count, score) {
            summary.selected += 1;
            match reason {
                SelectionReason::StrictSize => summary.selected_by_strict_size += 1,
                SelectionReason::Score => summary.selected_by_score += 1,
            }
            candidates.push(Candidate {
                address: current.start(),
                name: current.name().to_string(),
                instruction_count: features.instruction_count,
                score,
                reason,
                already_outlined: outlined,
            });
        }
        summary.processed += 1;
    }
    (summary, candidates)
}

fn apply_candidates(summary: &mut Summary, candidates: &[Candidate]) {
    for candidate in candidates.iter().filter(|value| !value.already_outlined) {
        if function::set_outlined(candidate.address, true).is_err() {
            summary.mutation_failures += 1;
            continue;
        }
        summary.changed += 1;
        if let Err(error) = decompiler::mark_dirty_with_callers(candidate.address, false)
            && error.category != ErrorCategory::Unsupported
        {
            summary.cache_invalidation_failures += 1;
        }
    }
}

fn print_report(options: &Options, summary: &Summary, candidates: &[Candidate]) {
    println!("Intelligent Function Inliner port (Rust adaptation)");
    println!("input: {}", options.input);
    println!("mode: {}", if options.apply { "apply" } else { "report" });
    println!("total_functions: {}", summary.total);
    println!("processed: {}", summary.processed);
    println!("selected_total: {}", summary.selected);
    println!("selected_strict_size: {}", summary.selected_by_strict_size);
    println!("selected_score: {}", summary.selected_by_score);
    println!("changed: {}", summary.changed);
    println!("already_outlined: {}", summary.already_outlined);
    println!("skipped_flags: {}", summary.skipped_flags);
    println!("skipped_variadic: {}", summary.skipped_variadic);
    println!("skipped_callers: {}", summary.skipped_callers);
    println!("analysis_failures: {}", summary.analysis_failures);
    println!("mutation_failures: {}", summary.mutation_failures);
    println!(
        "cache_invalidation_failures: {}",
        summary.cache_invalidation_failures
    );

    println!("candidates_shown: {}", candidates.len().min(options.show));
    for candidate in candidates.iter().take(options.show) {
        println!(
            "  0x{:x} {} instructions={} score={} reason={} state={}",
            candidate.address,
            candidate.name,
            candidate.instruction_count,
            candidate.score,
            candidate.reason.as_str(),
            if candidate.already_outlined {
                "already-outlined"
            } else {
                "new"
            }
        );
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;
    let _session = DatabaseSession::open(&options.input, true)?;

    let (mut summary, candidates) = analyze(&options);
    if options.apply {
        apply_candidates(&mut summary, &candidates);
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
    fn scoring_and_selection_match_original_thresholds() {
        assert_eq!(select_reason(6, 0), Some(SelectionReason::StrictSize));
        assert_eq!(select_reason(7, 5), Some(SelectionReason::Score));
        assert_eq!(select_reason(7, 4), None);

        let no_side_effects = Features {
            instruction_count: 3,
            call_count: 0,
            memory_writes: 0,
            has_indirect_call: false,
        };
        assert_eq!(inlining_score(no_side_effects, 1, false), 7);
        assert_eq!(inlining_score(no_side_effects, 1, true), 6);

        let direct_wrapper = Features {
            instruction_count: 7,
            call_count: 1,
            memory_writes: 0,
            has_indirect_call: false,
        };
        assert_eq!(inlining_score(direct_wrapper, 1, false), 5);

        let indirect_wrapper = Features {
            has_indirect_call: true,
            ..direct_wrapper
        };
        assert_eq!(inlining_score(indirect_wrapper, 1, false), 3);
    }
}
