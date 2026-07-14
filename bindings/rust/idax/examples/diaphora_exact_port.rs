#[allow(dead_code)]
mod common;

// Adapted from Diaphora 3.4.0. Upstream copyright and AGPL-3.0-or-later
// notice are retained in examples/plugin/diaphora_port_LICENSE.txt.

use common::{DatabaseSession, format_error, print_usage};
use idax::error::ErrorCategory;
use idax::instruction::OperandType;
use idax::{Error, Result, data, database, function, graph, instruction, name, segment};
use std::collections::{HashMap, HashSet};

const HEADER: &str = "IDAX_DIAPHORA_EXACT\t1\tcanonical-cfg";
const DECLARATION_PLACEHOLDER: &str = "__idax_diaphora_function";

#[derive(Debug, Clone)]
struct Options {
    input: String,
    manifest: String,
    mode: Mode,
    apply: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Export,
    Compare,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionRecord {
    address: u64,
    ordinal: usize,
    rva: u64,
    segment_rva: u64,
    nodes: usize,
    edges: usize,
    complexity: i64,
    instructions: usize,
    byte_size: u64,
    full_md5: String,
    relocation_md5: String,
    name: String,
    declaration: String,
    repeatable_comment: String,
    mnemonics: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
enum MatchTier {
    SameRvaBothHashes = 0,
    BothHashes = 1,
    FullHash = 2,
    RelocationHashAndInstructionCount = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Match {
    baseline: usize,
    current: usize,
    tier: MatchTier,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MatchSummary {
    matches: Vec<Match>,
    ambiguous: usize,
    unmatched: usize,
    tiers: [usize; 4],
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ApplySummary {
    renamed: usize,
    declarations: usize,
    comments: usize,
    preserved: usize,
    failures: usize,
}

struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    block_size: usize,
    bit_count: u64,
}

impl Md5 {
    const SHIFT: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const CONSTANT: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            block: [0; 64],
            block_size: 0,
            bit_count: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.bit_count = self
            .bit_count
            .wrapping_add((data.len() as u64).wrapping_mul(8));
        while !data.is_empty() {
            let count = data.len().min(self.block.len() - self.block_size);
            self.block[self.block_size..self.block_size + count].copy_from_slice(&data[..count]);
            self.block_size += count;
            data = &data[count..];
            if self.block_size == self.block.len() {
                let block = self.block;
                self.transform(&block);
                self.block_size = 0;
            }
        }
    }

    fn finish_hex(mut self) -> String {
        let original_bits = self.bit_count;
        self.update(&[0x80]);
        while self.block_size != 56 {
            self.update(&[0]);
        }
        self.update(&original_bits.to_le_bytes());
        let mut output = String::with_capacity(32);
        for word in self.state {
            for byte in word.to_le_bytes() {
                output.push_str(&format!("{byte:02x}"));
            }
        }
        output
    }

    fn transform(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        }
        let [mut a, mut b, mut c, mut d] = self.state;
        for index in 0..64u32 {
            let (function_value, word_index) = if index < 16 {
                ((b & c) | (!b & d), index)
            } else if index < 32 {
                ((d & b) | (!d & c), (5 * index + 1) % 16)
            } else if index < 48 {
                (b ^ c ^ d, (3 * index + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * index) % 16)
            };
            let next_d = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(function_value)
                    .wrapping_add(Self::CONSTANT[index as usize])
                    .wrapping_add(words[word_index as usize])
                    .rotate_left(Self::SHIFT[index as usize]),
            );
            a = next_d;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

fn parse_options() -> Result<Options> {
    let mut arguments = std::env::args().skip(1);
    let input = arguments
        .next()
        .ok_or_else(|| Error::validation("missing input database or binary"))?;
    let mode_token = arguments
        .next()
        .ok_or_else(|| Error::validation("missing --export or --compare"))?;
    let manifest = arguments
        .next()
        .ok_or_else(|| Error::validation("missing manifest path"))?;
    let mode = match mode_token.as_str() {
        "--export" => Mode::Export,
        "--compare" => Mode::Compare,
        _ => return Err(Error::validation("expected --export or --compare")),
    };
    let mut apply = false;
    for argument in arguments {
        if argument == "--apply" && mode == Mode::Compare {
            apply = true;
        } else {
            return Err(Error::validation(format!(
                "unexpected argument: {argument}"
            )));
        }
    }
    Ok(Options {
        input,
        manifest,
        mode,
        apply,
    })
}

fn hex_encode(input: &str) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input.as_bytes() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn hex_decode(input: &str) -> Result<String> {
    let input = input.as_bytes();
    if input.len() % 2 != 0 {
        return Err(Error::validation("odd-length hex string"));
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(Error::validation("invalid hex string")),
        };
        bytes.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    String::from_utf8(bytes).map_err(|_| Error::validation("manifest string is not UTF-8"))
}

fn format_record(record: &FunctionRecord) -> String {
    format!(
        "F\t{}\t{:x}\t{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.ordinal,
        record.rva,
        record.segment_rva,
        record.nodes,
        record.edges,
        record.complexity,
        record.instructions,
        record.byte_size,
        record.full_md5,
        record.relocation_md5,
        hex_encode(&record.name),
        hex_encode(&record.declaration),
        hex_encode(&record.repeatable_comment),
        hex_encode(&record.mnemonics),
    )
}

fn format_manifest(records: &[FunctionRecord]) -> String {
    let mut output = format!("{HEADER}\n");
    for record in records {
        output.push_str(&format_record(record));
        output.push('\n');
    }
    output
}

fn valid_md5(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_manifest(text: &str) -> Result<Vec<FunctionRecord>> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(Error::validation(
            "unsupported Diaphora exact manifest header",
        ));
    }
    let mut records = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 15 || fields[0] != "F" {
            return Err(Error::validation(
                "malformed Diaphora exact manifest record",
            ));
        }
        let parse_decimal = |field: &str| {
            field
                .parse::<u64>()
                .map_err(|_| Error::validation("invalid numeric manifest field"))
        };
        let full_md5 = fields[9].to_ascii_lowercase();
        let relocation_md5 = fields[10].to_ascii_lowercase();
        if !valid_md5(&full_md5) || !valid_md5(&relocation_md5) {
            return Err(Error::validation("invalid manifest MD5 field"));
        }
        records.push(FunctionRecord {
            address: u64::MAX,
            ordinal: usize::try_from(parse_decimal(fields[1])?)
                .map_err(|_| Error::validation("manifest ordinal overflows usize"))?,
            rva: u64::from_str_radix(fields[2], 16)
                .map_err(|_| Error::validation("invalid manifest RVA"))?,
            segment_rva: u64::from_str_radix(fields[3], 16)
                .map_err(|_| Error::validation("invalid manifest segment RVA"))?,
            nodes: usize::try_from(parse_decimal(fields[4])?)
                .map_err(|_| Error::validation("manifest node count overflows usize"))?,
            edges: usize::try_from(parse_decimal(fields[5])?)
                .map_err(|_| Error::validation("manifest edge count overflows usize"))?,
            complexity: fields[6]
                .parse::<i64>()
                .map_err(|_| Error::validation("invalid manifest complexity"))?,
            instructions: usize::try_from(parse_decimal(fields[7])?)
                .map_err(|_| Error::validation("manifest instruction count overflows usize"))?,
            byte_size: parse_decimal(fields[8])?,
            full_md5,
            relocation_md5,
            name: hex_decode(fields[11])?,
            declaration: hex_decode(fields[12])?,
            repeatable_comment: hex_decode(fields[13])?,
            mnemonics: hex_decode(fields[14])?,
        });
    }
    Ok(records)
}

fn normalized_operand_type(op_type: OperandType) -> bool {
    matches!(
        op_type,
        OperandType::MemoryDirect
            | OperandType::Immediate
            | OperandType::FarAddress
            | OperandType::NearAddress
            | OperandType::MemoryDisplacement
    )
}

fn normalized_prefix_size(
    instruction_size: usize,
    operands: &[(bool, Option<usize>, Option<usize>)],
) -> Result<usize> {
    if instruction_size == 0 {
        return Err(Error::validation("decoded zero-byte instruction"));
    }
    let mut normalized_size = instruction_size;
    for (normalizable, primary, secondary) in operands.iter().take(2) {
        for offset in [primary, secondary].into_iter().flatten() {
            if *offset >= instruction_size {
                return Err(Error::validation(
                    "encoded operand byte position is outside its instruction",
                ));
            }
        }
        if *normalizable && let Some(offset) = primary {
            normalized_size = if normalized_size > *offset {
                normalized_size - *offset
            } else {
                1
            };
        }
    }
    Ok(normalized_size.max(1))
}

fn canonical_complexity(nodes: usize, edges: usize) -> i64 {
    edges as i64 - nodes as i64 + 2
}

fn optional_text(result: Result<String>) -> Result<String> {
    match result {
        Ok(text) => Ok(text),
        Err(error) if error.category == ErrorCategory::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn extract_record(
    function_value: &function::Function,
    ordinal: usize,
    image_base: u64,
) -> Result<FunctionRecord> {
    let address = function_value.start();
    let rva = address
        .checked_sub(image_base)
        .ok_or_else(|| Error::validation("function entry precedes image base"))?;
    let function_segment = segment::at(address)?;
    let segment_rva = address
        .checked_sub(function_segment.start())
        .ok_or_else(|| Error::validation("function entry precedes segment start"))?;
    let blocks = graph::flowchart(address)?;
    let nodes = blocks.len();
    let edges = blocks.iter().map(|block| block.successors.len()).sum();

    let exported_name = if name::is_auto_generated(address) {
        String::new()
    } else {
        function_value.name().to_owned()
    };
    let declaration = optional_text(function::declaration(
        address,
        Some(DECLARATION_PLACEHOLDER),
    ))?;
    let repeatable_comment = optional_text(function::comment(address, true))?;

    let mut addresses = function::code_addresses(address)?;
    addresses.sort_unstable();
    let mut full_hash = Md5::new();
    let mut relocation_hash = Md5::new();
    let mut byte_size = 0u64;
    let mut mnemonics = Vec::with_capacity(addresses.len());
    for instruction_address in addresses.iter().copied() {
        let decoded = instruction::decode(instruction_address)?;
        let instruction_size = usize::try_from(decoded.size())
            .map_err(|_| Error::validation("instruction size overflows usize"))?;
        let bytes = data::read_bytes(instruction_address, decoded.size())?;
        if bytes.len() != instruction_size {
            return Err(Error::sdk("instruction byte read was truncated"));
        }
        let operand_offsets: Vec<_> = decoded
            .operands()
            .iter()
            .take(2)
            .map(|operand| {
                (
                    normalized_operand_type(operand.op_type()),
                    operand.encoded_value_byte_offset(),
                    operand.secondary_encoded_value_byte_offset(),
                )
            })
            .collect();
        let prefix_size = normalized_prefix_size(instruction_size, &operand_offsets)?;
        full_hash.update(&bytes);
        relocation_hash.update(&bytes[..prefix_size]);
        byte_size = byte_size
            .checked_add(decoded.size())
            .ok_or_else(|| Error::validation("function byte size overflow"))?;
        mnemonics.push(decoded.mnemonic().to_owned());
    }

    Ok(FunctionRecord {
        address,
        ordinal,
        rva,
        segment_rva,
        nodes,
        edges,
        complexity: canonical_complexity(nodes, edges),
        instructions: addresses.len(),
        byte_size,
        full_md5: full_hash.finish_hex(),
        relocation_md5: relocation_hash.finish_hex(),
        name: exported_name,
        declaration,
        repeatable_comment,
        mnemonics: mnemonics.join(","),
    })
}

fn extract_manifest() -> Result<Vec<FunctionRecord>> {
    let image_base = database::image_base()?;
    let mut functions: Vec<_> = function::all().collect();
    functions.sort_by_key(function::Function::start);
    functions
        .iter()
        .enumerate()
        .map(|(ordinal, function_value)| extract_record(function_value, ordinal, image_base))
        .collect()
}

fn match_key(record: &FunctionRecord, tier: MatchTier) -> String {
    let fields = match tier {
        MatchTier::SameRvaBothHashes => vec![
            record.rva.to_string(),
            record.full_md5.clone(),
            record.relocation_md5.clone(),
        ],
        MatchTier::BothHashes => vec![record.full_md5.clone(), record.relocation_md5.clone()],
        MatchTier::FullHash => vec![record.full_md5.clone()],
        MatchTier::RelocationHashAndInstructionCount => vec![
            record.relocation_md5.clone(),
            record.instructions.to_string(),
        ],
    };
    fields
        .into_iter()
        .map(|field| format!("{}:{field}", field.len()))
        .collect()
}

fn compare_records(baseline: &[FunctionRecord], current: &[FunctionRecord]) -> MatchSummary {
    let tiers = [
        MatchTier::SameRvaBothHashes,
        MatchTier::BothHashes,
        MatchTier::FullHash,
        MatchTier::RelocationHashAndInstructionCount,
    ];
    let mut unmatched_baseline: HashSet<usize> = (0..baseline.len()).collect();
    let mut unused_current: HashSet<usize> = (0..current.len()).collect();
    let mut ambiguous_baseline = HashSet::new();
    let mut summary = MatchSummary::default();

    for tier in tiers {
        let mut baseline_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        let mut current_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        for index in unmatched_baseline.iter().copied() {
            baseline_buckets
                .entry(match_key(&baseline[index], tier))
                .or_default()
                .push(index);
        }
        for index in unused_current.iter().copied() {
            current_buckets
                .entry(match_key(&current[index], tier))
                .or_default()
                .push(index);
        }
        let mut accepted = Vec::new();
        for (key, baseline_indices) in baseline_buckets {
            let Some(current_indices) = current_buckets.get(&key) else {
                continue;
            };
            if baseline_indices.len() == 1 && current_indices.len() == 1 {
                accepted.push((baseline_indices[0], current_indices[0]));
            } else {
                ambiguous_baseline.extend(baseline_indices);
            }
        }
        accepted.sort_unstable();
        for (baseline_index, current_index) in accepted {
            unmatched_baseline.remove(&baseline_index);
            unused_current.remove(&current_index);
            ambiguous_baseline.remove(&baseline_index);
            summary.matches.push(Match {
                baseline: baseline_index,
                current: current_index,
                tier,
            });
            summary.tiers[tier as usize] += 1;
        }
    }
    summary.matches.sort_by_key(|matched| matched.baseline);
    summary.ambiguous = unmatched_baseline.intersection(&ambiguous_baseline).count();
    summary.unmatched = unmatched_baseline.len() - summary.ambiguous;
    summary
}

fn apply_metadata(
    baseline: &[FunctionRecord],
    current: &[FunctionRecord],
    comparison: &MatchSummary,
) -> ApplySummary {
    let mut summary = ApplySummary::default();
    for matched in &comparison.matches {
        let source = &baseline[matched.baseline];
        let target = &current[matched.current];
        if !source.name.is_empty() && name::is_auto_generated(target.address) {
            if name::force_set(target.address, &source.name).is_ok() {
                summary.renamed += 1;
            } else {
                summary.failures += 1;
            }
        } else if !source.name.is_empty() {
            summary.preserved += 1;
        }

        if !source.declaration.is_empty() {
            match function::declaration(target.address, Some(DECLARATION_PLACEHOLDER)) {
                Ok(existing) if !existing.is_empty() => summary.preserved += 1,
                Ok(_) => {
                    if function::apply_decl(target.address, &source.declaration).is_ok() {
                        summary.declarations += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
                Err(error) if error.category == ErrorCategory::NotFound => {
                    if function::apply_decl(target.address, &source.declaration).is_ok() {
                        summary.declarations += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
                Err(_) => summary.failures += 1,
            }
        }

        if !source.repeatable_comment.is_empty() {
            match function::comment(target.address, true) {
                Ok(existing) if !existing.is_empty() => summary.preserved += 1,
                Ok(_) => {
                    if function::set_comment(target.address, &source.repeatable_comment, true)
                        .is_ok()
                    {
                        summary.comments += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
                Err(error) if error.category == ErrorCategory::NotFound => {
                    if function::set_comment(target.address, &source.repeatable_comment, true)
                        .is_ok()
                    {
                        summary.comments += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
                Err(_) => summary.failures += 1,
            }
        }
    }
    summary
}

fn comparison_report(
    summary: &MatchSummary,
    baseline_count: usize,
    current_count: usize,
) -> String {
    format!(
        "Diaphora exact comparison\nBaseline functions: {baseline_count}\nCurrent functions: {current_count}\nUnique matches: {}\n  same RVA + both hashes: {}\n  both hashes: {}\n  full hash: {}\n  relocation hash + instruction count: {}\nAmbiguous baseline functions: {}\nUnmatched baseline functions: {}",
        summary.matches.len(),
        summary.tiers[0],
        summary.tiers[1],
        summary.tiers[2],
        summary.tiers[3],
        summary.ambiguous,
        summary.unmatched,
    )
}

fn run(options: &Options) -> Result<()> {
    let _session = DatabaseSession::open(&options.input, true)?;
    match options.mode {
        Mode::Export => {
            let records = extract_manifest()?;
            std::fs::write(&options.manifest, format_manifest(&records)).map_err(|error| {
                Error::internal(format!(
                    "failed writing manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            println!(
                "Exported {} exact function fingerprints to {}",
                records.len(),
                options.manifest
            );
        }
        Mode::Compare => {
            let text = std::fs::read_to_string(&options.manifest).map_err(|error| {
                Error::not_found(format!(
                    "failed reading manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            let mut baseline = parse_manifest(&text)?;
            let image_base = database::image_base()?;
            for record in &mut baseline {
                record.address = image_base
                    .checked_add(record.rva)
                    .ok_or_else(|| Error::validation("manifest RVA overflows address space"))?;
            }
            let current = extract_manifest()?;
            let comparison = compare_records(&baseline, &current);
            println!(
                "{}",
                comparison_report(&comparison, baseline.len(), current.len())
            );
            if options.apply {
                let applied = apply_metadata(&baseline, &current, &comparison);
                if applied.renamed + applied.declarations + applied.comments > 0 {
                    database::save()?;
                }
                println!(
                    "Renamed: {}\nDeclarations applied: {}\nRepeatable comments applied: {}\nExisting metadata preserved: {}\nMutation failures: {}",
                    applied.renamed,
                    applied.declarations,
                    applied.comments,
                    applied.preserved,
                    applied.failures,
                );
            }
        }
    }
    Ok(())
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            print_usage(
                "diaphora_exact_port",
                "<input> --export <manifest> | <input> --compare <manifest> [--apply]",
            );
            eprintln!("error: {}", format_error(&error));
            std::process::exit(2);
        }
    };
    if let Err(error) = run(&options) {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(index: usize, rva: u64, full: &str, relocation: &str) -> FunctionRecord {
        FunctionRecord {
            address: index as u64,
            ordinal: index,
            rva,
            segment_rva: rva,
            nodes: 1,
            edges: 0,
            complexity: 1,
            instructions: 2,
            byte_size: 3,
            full_md5: full.repeat(32 / full.len()),
            relocation_md5: relocation.repeat(32 / relocation.len()),
            name: format!("f{index}"),
            declaration: "int __idax_diaphora_function(void);".to_owned(),
            repeatable_comment: "comment\tline\nλ".to_owned(),
            mnemonics: "mov,ret".to_owned(),
        }
    }

    #[test]
    fn md5_rfc_1321_vectors() {
        for (input, expected) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ] {
            let mut hash = Md5::new();
            hash.update(input.as_bytes());
            assert_eq!(hash.finish_hex(), expected);
        }
    }

    #[test]
    fn manifest_roundtrip_preserves_encoded_text() {
        let mut expected = record(0, 0x123, "a", "b");
        expected.address = u64::MAX;
        let records = vec![expected];
        assert_eq!(parse_manifest(&format_manifest(&records)).unwrap(), records);
    }

    #[test]
    fn manifest_decoder_rejects_malformed_text() {
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("0g").is_err());
        assert!(hex_decode("λλ").is_err());
        assert!(hex_decode("ff").is_err());
    }

    #[test]
    fn canonical_cfg_metrics_are_single_counted() {
        assert_eq!(canonical_complexity(1, 0), 1);
        assert_eq!(canonical_complexity(2, 1), 1);
        assert_eq!(canonical_complexity(4, 4), 2);
    }

    #[test]
    fn normalized_prefix_matches_audited_subtraction_rule() {
        assert_eq!(
            normalized_prefix_size(7, &[(true, Some(2), None), (true, Some(4), None)]).unwrap(),
            1
        );
        assert_eq!(
            normalized_prefix_size(5, &[(false, None, None)]).unwrap(),
            5
        );
        assert!(normalized_prefix_size(4, &[(true, Some(4), None)]).is_err());
        assert!(normalized_prefix_size(4, &[(false, None, Some(5))]).is_err());
    }

    #[test]
    fn matching_is_tiered_and_unique_only() {
        let baseline = vec![
            record(0, 0x10, "a", "b"),
            record(1, 0x20, "c", "d"),
            record(2, 0x30, "e", "f"),
        ];
        let current = vec![
            record(0, 0x10, "a", "b"),
            record(1, 0x99, "c", "d"),
            record(2, 0x88, "e", "0"),
        ];
        let summary = compare_records(&baseline, &current);
        assert_eq!(summary.matches.len(), 3);
        assert_eq!(summary.tiers, [1, 1, 1, 0]);
        assert_eq!(summary.ambiguous, 0);
        assert_eq!(summary.unmatched, 0);
    }

    #[test]
    fn duplicate_implementations_remain_ambiguous() {
        let baseline = vec![record(0, 0x10, "a", "b"), record(1, 0x10, "a", "b")];
        let current = vec![record(0, 0x10, "a", "b"), record(1, 0x10, "a", "b")];
        let summary = compare_records(&baseline, &current);
        assert!(summary.matches.is_empty());
        assert_eq!(summary.ambiguous, 2);
        assert_eq!(summary.unmatched, 0);
    }
}
