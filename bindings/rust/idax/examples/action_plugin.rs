mod common;

use common::{format_error, print_usage, resolve_symbol_or_address, DatabaseSession};
use idax::{address, comment, function, Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

static BOOKMARK_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn mark_reviewed(target: u64) -> Result<()> {
    let existing = comment::get(target, true).unwrap_or_default();
    if existing.contains("[REVIEWED]") {
        println!("already reviewed: 0x{target:x}");
        return Ok(());
    }

    let reviewed = if existing.is_empty() {
        "[REVIEWED]".to_string()
    } else {
        format!("[REVIEWED] {existing}")
    };
    comment::set(target, &reviewed, true)?;
    println!("marked reviewed: 0x{target:x}");
    Ok(())
}

fn add_bookmark(target: u64, custom_label: Option<&str>) -> Result<()> {
    let next = BOOKMARK_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    let label = custom_label
        .map(str::to_string)
        .unwrap_or_else(|| format!("[BM#{next}]"));
    comment::append(target, &label, false)?;
    println!("added bookmark at 0x{target:x}: {label}");
    Ok(())
}

fn clear_marks(target: u64) -> Result<()> {
    let (start, end) = match function::at(target) {
        Ok(func) => (func.start(), func.end()),
        Err(_) => (target, target.saturating_add(1)),
    };

    let mut cleared = 0usize;
    for ea in address::items(start, end) {
        if let Ok(rep) = comment::get(ea, true)
            && rep.contains("[REVIEWED]")
        {
            let cleaned = rep
                .replace("[REVIEWED] ", "")
                .replace("[REVIEWED]", "")
                .trim()
                .to_string();
            if cleaned.is_empty() {
                comment::remove(ea, true)?;
            } else {
                comment::set(ea, &cleaned, true)?;
            }
            cleared += 1;
        }

        if let Ok(reg) = comment::get(ea, false)
            && reg.contains("[BM#")
        {
            comment::remove(ea, false)?;
            cleared += 1;
        }
    }

    println!(
        "cleared {cleared} plugin annotation(s) in [0x{start:x}, 0x{end:x})"
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        print_usage(
            &args[0],
            "<binary_file> <mark-reviewed|add-bookmark|clear-marks> <address|symbol> [--label <text>]",
        );
        return Err(Error::validation("missing required arguments"));
    }

    let input = &args[1];
    let command = &args[2];
    let target = resolve_symbol_or_address(&args[3])?;
    let custom_label = args
        .windows(2)
        .find(|window| window[0] == "--label")
        .map(|window| window[1].as_str());

    let _session = DatabaseSession::open(input, true)?;

    match command.as_str() {
        "mark-reviewed" => mark_reviewed(target),
        "add-bookmark" => add_bookmark(target, custom_label),
        "clear-marks" => clear_marks(target),
        _ => Err(Error::validation(format!("unknown command: {command}"))),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
