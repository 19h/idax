mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{
    address, comment, data, database, entry, fixup, function, instruction, segment, Error, Result,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct WxViolation {
    start: u64,
    end: u64,
    name: String,
}

#[derive(Debug, Clone)]
struct LargeFrameEntry {
    address: u64,
    name: String,
    frame_size: u64,
    variable_count: usize,
}

#[derive(Debug, Clone, Default)]
struct AuditReport {
    binary_path: String,
    binary_md5: String,
    image_base: u64,
    addr_min: u64,
    addr_max: u64,
    segment_count: usize,
    function_count: usize,
    entry_point_count: usize,
    fixup_count: usize,
    wx_violations: Vec<WxViolation>,
    large_frames: Vec<LargeFrameEntry>,
    suspicious_instructions: Vec<u64>,
    string_locations: Vec<u64>,
    xref_hotspots: Vec<(String, usize)>,
}

fn collect_metadata(report: &mut AuditReport) {
    report.binary_path = database::input_file_path().unwrap_or_default();
    report.binary_md5 = database::input_md5().unwrap_or_default();
    report.image_base = database::image_base().unwrap_or_default();
    report.addr_min = database::min_address().unwrap_or_default();
    report.addr_max = database::max_address().unwrap_or_default();
    report.entry_point_count = entry::count().unwrap_or(0);
}

fn audit_segments(report: &mut AuditReport) {
    report.segment_count = segment::count().unwrap_or(0);
    for seg in segment::all() {
        let perms = seg.permissions();
        if perms.write && perms.execute {
            report.wx_violations.push(WxViolation {
                start: seg.start(),
                end: seg.end(),
                name: seg.name().to_string(),
            });
        }
    }
}

fn audit_functions(report: &mut AuditReport) {
    report.function_count = function::count().unwrap_or(0);
    let mut hotspots: HashMap<String, usize> = HashMap::new();

    for func in function::all() {
        if let Ok(frame) = function::frame(func.start())
            && frame.total_size() >= 1024
        {
            report.large_frames.push(LargeFrameEntry {
                address: func.start(),
                name: func.name().to_string(),
                frame_size: frame.total_size(),
                variable_count: frame.variables().len(),
            });
        }

        if let Ok(callers) = function::callers(func.start())
            && callers.len() >= 10
        {
            hotspots.insert(func.name().to_string(), callers.len());
        }
    }

    report.xref_hotspots = hotspots.into_iter().collect();
    report
        .xref_hotspots
        .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
}

fn scan_suspicious_instructions(report: &mut AuditReport, max_scan: usize) {
    if report.addr_max <= report.addr_min {
        return;
    }

    let scan_end = (report.addr_min + 0x20000).min(report.addr_max);
    for ea in address::code_items(report.addr_min, scan_end).take(max_scan) {
        let text = instruction::text(ea).unwrap_or_default().to_ascii_lowercase();
        if text.contains("int3") || text.contains("hlt") {
            report.suspicious_instructions.push(ea);
            continue;
        }

        if text.contains("nop") {
            let bytes = data::read_bytes(ea, 8).unwrap_or_default();
            if bytes.starts_with(&[0x90, 0x90, 0x90]) {
                report.suspicious_instructions.push(ea);
            }
        }
    }
}

fn scan_strings(report: &mut AuditReport, max_per_segment: usize) {
    for seg in segment::all() {
        if seg.permissions().execute {
            continue;
        }
        for ea in address::data_items(seg.start(), seg.end()).take(max_per_segment) {
            let Ok(text) = data::read_string(ea, 0) else {
                continue;
            };
            if text.len() >= 8 {
                report.string_locations.push(ea);
            }
        }
    }
}

fn count_fixups(report: &mut AuditReport) {
    let mut count = 0usize;
    for _ in fixup::all() {
        count += 1;
        if count >= 100_000 {
            break;
        }
    }
    report.fixup_count = count;
}

fn annotate_report(report: &AuditReport) {
    for wx in &report.wx_violations {
        let _ = comment::set(
            wx.start,
            &format!("[Audit] W+X segment {} [0x{:x},0x{:x})", wx.name, wx.start, wx.end),
            true,
        );
    }

    for frame in report.large_frames.iter().take(20) {
        let _ = comment::set(
            frame.address,
            &format!(
                "[Audit] large frame: {} bytes, {} vars",
                frame.frame_size, frame.variable_count
            ),
            true,
        );
    }

    for ea in report.suspicious_instructions.iter().take(20) {
        let _ = comment::set(*ea, "[Audit] suspicious instruction pattern", false);
    }
}

fn print_report(report: &AuditReport) {
    println!("Binary Audit Report (Rust adaptation)");
    println!("input: {}", report.binary_path);
    println!("md5: {}", report.binary_md5);
    println!(
        "range: [0x{:x}, 0x{:x}) image_base=0x{:x}",
        report.addr_min, report.addr_max, report.image_base
    );
    println!(
        "segments={} functions={} entries={} fixups={}",
        report.segment_count, report.function_count, report.entry_point_count, report.fixup_count
    );

    println!("\nW+X segments: {}", report.wx_violations.len());
    for wx in report.wx_violations.iter().take(10) {
        println!("  - {} [0x{:x}, 0x{:x})", wx.name, wx.start, wx.end);
    }

    println!("\nLarge frames: {}", report.large_frames.len());
    for frame in report.large_frames.iter().take(10) {
        println!(
            "  - 0x{:x} {} size={} vars={}",
            frame.address, frame.name, frame.frame_size, frame.variable_count
        );
    }

    println!(
        "\nSuspicious instructions: {} (showing up to 20)",
        report.suspicious_instructions.len()
    );
    for ea in report.suspicious_instructions.iter().take(20) {
        println!("  - 0x{:x}", ea);
    }

    println!("\nXref hotspots: {}", report.xref_hotspots.len());
    for (name, count) in report.xref_hotspots.iter().take(10) {
        println!("  - {name}: {count} callers");
    }

    println!("\nRecovered strings: {}", report.string_locations.len());
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<binary_file> [--annotate] [--max-scan <count>]");
        return Err(Error::validation("missing binary_file argument"));
    }

    let annotate = args.iter().any(|arg| arg == "--annotate");
    let max_scan = args
        .windows(2)
        .find(|window| window[0] == "--max-scan")
        .and_then(|window| window[1].parse::<usize>().ok())
        .unwrap_or(80_000);

    let _session = DatabaseSession::open(&args[1], true)?;

    let mut report = AuditReport::default();
    collect_metadata(&mut report);
    audit_segments(&mut report);
    audit_functions(&mut report);
    count_fixups(&mut report);
    scan_suspicious_instructions(&mut report, max_scan);
    scan_strings(&mut report, 25_000);

    print_report(&report);

    if annotate {
        annotate_report(&report);
        println!("\nannotations applied");
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
