mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{address, data, database, entry, fixup, function, segment, storage, Error, Result};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Default)]
struct FunctionHistogram {
    total: usize,
    thunks: usize,
    library: usize,
    tiny: usize,
    small: usize,
    medium: usize,
    large: usize,
}

#[derive(Debug, Clone, Default)]
struct Fingerprint {
    binary_path: String,
    binary_md5: String,
    image_base: u64,
    range_min: u64,
    range_max: u64,
    segment_count: usize,
    function_histogram: FunctionHistogram,
    entry_count: usize,
    fixup_count: usize,
    code_items: usize,
    data_items: usize,
    unknown_items: usize,
    string_count: usize,
    avg_string_length: usize,
}

fn is_printable(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
}

fn collect_identity(fp: &mut Fingerprint) {
    fp.binary_path = database::input_file_path().unwrap_or_default();
    fp.binary_md5 = database::input_md5().unwrap_or_default();
    fp.image_base = database::image_base().unwrap_or_default();
    fp.range_min = database::min_address().unwrap_or_default();
    fp.range_max = database::max_address().unwrap_or_default();
}

fn digest_segments(fp: &mut Fingerprint) {
    fp.segment_count = segment::count().unwrap_or(0);
}

fn histogram_functions(fp: &mut Fingerprint) {
    let mut histogram = FunctionHistogram::default();
    for func in function::all() {
        histogram.total += 1;
        if func.is_thunk() {
            histogram.thunks += 1;
        }
        if func.is_library() {
            histogram.library += 1;
        }
        let size = func.size();
        if size < 32 {
            histogram.tiny += 1;
        } else if size < 256 {
            histogram.small += 1;
        } else if size < 4096 {
            histogram.medium += 1;
        } else {
            histogram.large += 1;
        }
    }
    fp.function_histogram = histogram;
}

fn profile_fixups(fp: &mut Fingerprint) {
    let mut count = 0usize;
    let mut _type_counts: HashMap<i32, usize> = HashMap::new();
    for descriptor in fixup::all() {
        count += 1;
        *_type_counts
            .entry(descriptor.fixup_type as i32)
            .or_insert(0) += 1;
        if count >= 50_000 {
            break;
        }
    }
    fp.fixup_count = count;
}

fn measure_coverage(fp: &mut Fingerprint) {
    if fp.range_min == 0 && fp.range_max == 0 {
        return;
    }
    let end = if fp.range_max > fp.range_min {
        (fp.range_min + 0x10000).min(fp.range_max)
    } else {
        fp.range_min.saturating_add(0x10000)
    };

    fp.code_items = address::code_items(fp.range_min, end).take(50_000).count();
    fp.data_items = address::data_items(fp.range_min, end).take(50_000).count();
    fp.unknown_items = address::unknown_bytes(fp.range_min, end)
        .take(50_000)
        .count();
}

fn count_strings(fp: &mut Fingerprint) {
    let mut total_len = 0usize;
    let mut count = 0usize;

    for seg in segment::all() {
        if seg.permissions().execute {
            continue;
        }
        for ea in address::data_items(seg.start(), seg.end()).take(20_000) {
            let Ok(value) = data::read_string(ea, 0) else {
                continue;
            };
            if value.len() < 4 || !is_printable(&value) {
                continue;
            }
            count += 1;
            total_len += value.len();
        }
    }

    fp.string_count = count;
    fp.avg_string_length = if count > 0 { total_len / count } else { 0 };
}

fn summarize(fp: &Fingerprint) -> String {
    format!(
        "path={}\nmd5={}\nimage_base=0x{:x}\nrange=[0x{:x},0x{:x})\nsegments={}\nfunc_total={} thunk={} lib={} tiny={} small={} medium={} large={}\nentries={}\nfixups={}\ncoverage code={} data={} unknown={}\nstrings={} avg_len={}\n",
        fp.binary_path,
        fp.binary_md5,
        fp.image_base,
        fp.range_min,
        fp.range_max,
        fp.segment_count,
        fp.function_histogram.total,
        fp.function_histogram.thunks,
        fp.function_histogram.library,
        fp.function_histogram.tiny,
        fp.function_histogram.small,
        fp.function_histogram.medium,
        fp.function_histogram.large,
        fp.entry_count,
        fp.fixup_count,
        fp.code_items,
        fp.data_items,
        fp.unknown_items,
        fp.string_count,
        fp.avg_string_length
    )
}

fn digest(summary: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    summary.hash(&mut hasher);
    hasher.finish()
}

fn persist(fp: &Fingerprint, summary: &str, digest_value: u64) -> Result<()> {
    let node = storage::Node::open("idax_fingerprint", true)?;
    let previous = node.hash_default("last_digest").unwrap_or_default();

    node.set_hash_default("last_path", &fp.binary_path)?;
    node.set_hash_default("last_md5", &fp.binary_md5)?;
    node.set_hash_default("last_digest", &format!("{digest_value:016x}"))?;
    node.set_alt_default(100, digest_value)?;
    node.set_blob_default(100, summary.as_bytes())?;

    let read_back = node.alt_default(100)?;
    println!("persisted fingerprint digest=0x{digest_value:016x} read_back=0x{read_back:016x}");
    if !previous.is_empty() {
        println!("previous digest: {previous}");
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<binary_file>");
        return Err(Error::validation("missing binary_file argument"));
    }

    let _session = DatabaseSession::open(&args[1], true)?;
    let mut fp = Fingerprint::default();

    collect_identity(&mut fp);
    digest_segments(&mut fp);
    histogram_functions(&mut fp);
    fp.entry_count = entry::count().unwrap_or(0);
    profile_fixups(&mut fp);
    measure_coverage(&mut fp);
    count_strings(&mut fp);

    let summary = summarize(&fp);
    let digest_value = digest(&summary);

    println!("Binary Fingerprint (Rust adaptation)");
    println!("{}", summary);
    println!("digest: 0x{digest_value:016x}");

    persist(&fp, &summary, digest_value)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
