mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::decompiler::{self, ItemType, VisitAction};
use idax::{comment, function, Error, Result};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct FunctionMetrics {
    address: u64,
    name: String,
    line_count: usize,
    variable_count: usize,
    decision_points: usize,
    cyclomatic_complexity: usize,
    calls: usize,
    assignments: usize,
    numeric_constants: usize,
    max_indent_level: usize,
}

#[derive(Debug, Default)]
struct VisitorCounts {
    decision_points: usize,
    calls: usize,
    assignments: usize,
    numeric_constants: usize,
}

#[derive(Debug, Clone)]
struct Options {
    input: String,
    top: usize,
    annotate: bool,
    rename_vars: bool,
}

fn parse_options(args: &[String]) -> Result<Options> {
    if args.len() < 2 {
        return Err(Error::validation("missing binary_file argument"));
    }
    let mut options = Options {
        input: args[1].clone(),
        top: 20,
        annotate: false,
        rename_vars: false,
    };

    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(
                    &args[0],
                    "<binary_file> [--top <count>] [--annotate] [--rename-vars]",
                );
                std::process::exit(0);
            }
            "--top" => {
                i += 1;
                if i >= args.len() {
                    return Err(Error::validation("--top requires a value"));
                }
                options.top = args[i]
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --top value"))?;
            }
            "--annotate" => options.annotate = true,
            "--rename-vars" => options.rename_vars = true,
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        i += 1;
    }
    Ok(options)
}

fn max_indent_level(lines: &[String]) -> usize {
    lines
        .iter()
        .map(|line| {
            line.chars()
                .take_while(|ch| ch.is_ascii_whitespace())
                .count()
                / 4
        })
        .max()
        .unwrap_or(0)
}

fn maybe_rename_simple_variables(
    decompiled: &decompiler::DecompiledFunction,
    max_renames: usize,
) -> Result<usize> {
    let mut renamed = 0usize;
    let variables = decompiled.variables()?;
    for (index, variable) in variables.iter().enumerate() {
        if renamed >= max_renames {
            break;
        }
        let old = variable.name.trim();
        let single = old.len() == 1
            && old
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false);
        if single {
            let new_name = format!("v_{index}");
            if decompiled.rename_variable(old, &new_name).is_ok() {
                renamed += 1;
            }
        }
    }
    Ok(renamed)
}

fn analyze_function(address: u64, rename_vars: bool) -> Result<Option<FunctionMetrics>> {
    let decompiled = match decompiler::decompile(address) {
        Ok(df) => df,
        Err(_) => return Ok(None),
    };

    let lines = decompiled.lines()?;
    let variable_count = decompiled.variable_count()?;
    let counts = Arc::new(Mutex::new(VisitorCounts::default()));

    {
        let counts = Arc::clone(&counts);
        decompiled.for_each_expression(move |expr| {
            if let Ok(mut locked) = counts.lock() {
                match expr.item_type {
                    ItemType::ExprCall => locked.calls += 1,
                    ItemType::ExprAssign => locked.assignments += 1,
                    ItemType::ExprNumber => locked.numeric_constants += 1,
                    _ => {}
                }
            }
            VisitAction::Continue
        })?;
    }

    {
        let counts = Arc::clone(&counts);
        decompiled.for_each_item(
            |_| VisitAction::Continue,
            move |stmt| {
                if let Ok(mut locked) = counts.lock() {
                    match stmt.item_type {
                        ItemType::StmtIf
                        | ItemType::StmtFor
                        | ItemType::StmtWhile
                        | ItemType::StmtDo
                        | ItemType::StmtSwitch => locked.decision_points += 1,
                        _ => {}
                    }
                }
                VisitAction::Continue
            },
        )?;
    }

    if rename_vars {
        let _ = maybe_rename_simple_variables(&decompiled, 3)?;
    }

    let counts = counts
        .lock()
        .map_err(|_| Error::internal("visitor counts mutex poisoned"))?;
    let function_name = function::name_at(address)?;

    Ok(Some(FunctionMetrics {
        address,
        name: function_name,
        line_count: lines.len(),
        variable_count,
        decision_points: counts.decision_points,
        cyclomatic_complexity: counts.decision_points + 1,
        calls: counts.calls,
        assignments: counts.assignments,
        numeric_constants: counts.numeric_constants,
        max_indent_level: max_indent_level(&lines),
    }))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options = parse_options(&args)?;

    let _session = DatabaseSession::open(&options.input, true)?;

    if !decompiler::available()? {
        return Err(Error::unsupported(
            "Hex-Rays decompiler is unavailable on this host",
        ));
    }

    let mut metrics = Vec::new();
    for func in function::all() {
        if func.is_library() || func.is_thunk() || func.size() < 32 {
            continue;
        }
        if let Some(entry) = analyze_function(func.start(), options.rename_vars)? {
            metrics.push(entry);
        }
    }

    metrics.sort_by(|a, b| {
        b.cyclomatic_complexity
            .cmp(&a.cyclomatic_complexity)
            .then_with(|| b.calls.cmp(&a.calls))
            .then_with(|| b.line_count.cmp(&a.line_count))
    });

    println!("Complexity Metrics (Rust adaptation)");
    println!("functions analyzed: {}", metrics.len());
    println!(
        "{:<18} {:<7} {:<7} {:<7} {:<7} {:<7} Name",
        "Address", "CC", "Lines", "Vars", "Calls", "Depth"
    );
    println!("--------------------------------------------------------------------------------");

    for entry in metrics.iter().take(options.top) {
        println!(
            "{:<18} {:<7} {:<7} {:<7} {:<7} {:<7} {}",
            format!("0x{:x}", entry.address),
            entry.cyclomatic_complexity,
            entry.line_count,
            entry.variable_count,
            entry.calls,
            entry.max_indent_level,
            entry.name
        );
    }

    if options.annotate {
        for entry in metrics.iter().take(options.top) {
            let summary = format!(
                "[Complexity] cc={} decisions={} calls={} assigns={} nums={}",
                entry.cyclomatic_complexity,
                entry.decision_points,
                entry.calls,
                entry.assignments,
                entry.numeric_constants
            );
            let _ = comment::set(entry.address, &summary, true);
        }
        println!(
            "annotated top {} function(s) with repeatable comments",
            options.top.min(metrics.len())
        );
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
