mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{comment, data, event, function, name, storage, Error, Result};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone)]
struct ChangeRecord {
    timestamp_ms: u64,
    domain: String,
    kind: String,
    description: String,
    address: Option<u64>,
}

type SharedLog = Arc<Mutex<Vec<ChangeRecord>>>;

fn add_record(
    log: &SharedLog,
    start: Instant,
    domain: &str,
    kind: &str,
    description: String,
    address: Option<u64>,
) {
    let elapsed = start.elapsed().as_millis() as u64;
    if let Ok(mut guard) = log.lock() {
        guard.push(ChangeRecord {
            timestamp_ms: elapsed,
            domain: domain.to_string(),
            kind: kind.to_string(),
            description: description.clone(),
            address,
        });
    }
    if let Some(ea) = address {
        println!("  [{elapsed}ms] [{domain}] {kind}: {description} @ 0x{ea:x}");
    } else {
        println!("  [{elapsed}ms] [{domain}] {kind}: {description}");
    }
}

fn start_tracking(log: SharedLog, start: Instant) -> Result<(Vec<event::Token>, Arc<AtomicUsize>)> {
    let mut tokens = Vec::new();
    let generic_count = Arc::new(AtomicUsize::new(0));

    {
        let log = Arc::clone(&log);
        tokens.push(event::on_segment_added(move |ea| {
            add_record(
                &log,
                start,
                "IDB",
                "segment_add",
                format!("segment added"),
                Some(ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_segment_deleted(move |start_ea, end_ea| {
            add_record(
                &log,
                start,
                "IDB",
                "segment_del",
                format!("segment removed [0x{start_ea:x}, 0x{end_ea:x})"),
                Some(start_ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_function_added(move |ea| {
            add_record(
                &log,
                start,
                "IDB",
                "func_add",
                "function added".to_string(),
                Some(ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_function_deleted(move |ea| {
            add_record(
                &log,
                start,
                "IDB",
                "func_del",
                "function removed".to_string(),
                Some(ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_renamed(move |ea, new_name, old_name| {
            add_record(
                &log,
                start,
                "IDB",
                "rename",
                format!("'{old_name}' -> '{new_name}'"),
                Some(ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_byte_patched(move |ea, old_value| {
            add_record(
                &log,
                start,
                "IDB",
                "patch",
                format!("patched byte (old=0x{old_value:02x})"),
                Some(ea),
            );
        })?);
    }
    {
        let log = Arc::clone(&log);
        tokens.push(event::on_comment_changed(move |ea, repeatable| {
            add_record(
                &log,
                start,
                "IDB",
                "comment",
                if repeatable {
                    "repeatable comment changed".to_string()
                } else {
                    "regular comment changed".to_string()
                },
                Some(ea),
            );
        })?);
    }
    {
        let generic_count = Arc::clone(&generic_count);
        tokens.push(event::on_event(move |_ev| {
            generic_count.fetch_add(1, Ordering::Relaxed);
        })?);
    }

    Ok((tokens, generic_count))
}

fn stop_tracking(tokens: Vec<event::Token>) {
    for token in tokens {
        let _ = event::unsubscribe(token);
    }
}

fn perform_scripted_modifications() -> Result<()> {
    if function::count()? == 0 {
        println!("no functions found; skipping modification script");
        return Ok(());
    }

    let first = function::by_index(0)?;
    let original_name = first.name().to_string();

    name::force_set(first.start(), "idax_tracker_test_rename")?;
    name::force_set(first.start(), &original_name)?;

    comment::set(first.start(), "change tracker test comment", false)?;
    comment::remove(first.start(), false)?;

    let original = data::read_byte(first.start())?;
    data::patch_byte(first.start(), original ^ 0xff)?;
    data::revert_patch(first.start())?;

    if function::count()? >= 2 {
        let second = function::by_index(1)?;
        comment::set(second.start(), "repeatable tracker annotation", true)?;
        comment::remove(second.start(), true)?;
    }

    Ok(())
}

fn persist_summary(records: &[ChangeRecord]) -> Result<()> {
    let node = storage::Node::open("idax_change_tracker", true)?;
    let total = records.len() as u64;
    node.set_alt(100, total, b'A')?;
    node.set_hash("last_session_changes", &total.to_string(), b'H')?;

    let mut domain_counts: HashMap<&str, u64> = HashMap::new();
    for record in records {
        *domain_counts.entry(record.domain.as_str()).or_insert(0) += 1;
    }
    for (domain, count) in domain_counts {
        node.set_hash(&format!("domain_{domain}"), &count.to_string(), b'H')?;
    }

    let read_back = node.alt(100, b'A')?;
    println!("persisted {total} change(s) to storage node; read_back={read_back}");
    Ok(())
}

fn print_report(records: &[ChangeRecord], generic_count: usize) {
    println!("\n=== Change Tracker Summary ===");
    println!("total changes recorded: {}", records.len());
    println!("generic event callbacks: {generic_count}");

    let mut kind_counts: HashMap<&str, usize> = HashMap::new();
    let mut affected = HashSet::new();
    for record in records {
        *kind_counts.entry(record.kind.as_str()).or_insert(0) += 1;
        if let Some(ea) = record.address {
            affected.insert(ea);
        }
    }

    println!("\nby kind:");
    let mut kinds = kind_counts.into_iter().collect::<Vec<_>>();
    kinds.sort_by(|a, b| b.1.cmp(&a.1));
    for (kind, count) in kinds {
        println!("  {kind}: {count}");
    }

    println!("\nunique addresses affected: {}", affected.len());
    if let (Some(first), Some(last)) = (records.first(), records.last()) {
        println!(
            "timeline: {}ms -> {}ms",
            first.timestamp_ms, last.timestamp_ms
        );
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<binary_file>");
        return Err(Error::validation("missing binary_file argument"));
    }

    let _session = DatabaseSession::open(&args[1], true)?;
    let start = Instant::now();
    let log: SharedLog = Arc::new(Mutex::new(Vec::new()));

    println!("subscribing to events...");
    let (tokens, generic_count) = start_tracking(Arc::clone(&log), start)?;

    println!("running scripted modifications...");
    perform_scripted_modifications()?;

    stop_tracking(tokens);

    let records = log
        .lock()
        .map_err(|_| Error::internal("event log mutex poisoned"))?
        .clone();
    persist_summary(&records)?;
    print_report(&records, generic_count.load(Ordering::Relaxed));

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
