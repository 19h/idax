#[allow(dead_code)]
#[path = "common/mod.rs"]
mod common;

// Adapted from Diaphora 3.4.0. Upstream copyright and AGPL-3.0-or-later
// notice are retained in examples/plugin/diaphora_port_LICENSE.txt.

use common::{DatabaseSession, format_error, print_usage};
use idax::error::ErrorCategory;
use idax::instruction::OperandType;
use idax::{
    Error, Result, comment, data, database, decompiler, function, graph, instruction, name,
    segment, types, xref,
};
use std::collections::{HashMap, HashSet};

const HEADER: &str = "IDAX_DIAPHORA_EXACT\t1\tcanonical-cfg";
const INSTRUCTION_METADATA_HEADER: &str =
    "IDAX_DIAPHORA_INSTRUCTION_METADATA\t1\texact-relative-offset";
const REFERENT_METADATA_HEADER: &str = "IDAX_DIAPHORA_REFERENT_METADATA\t1\tunique-reference-class";
const PSEUDOCODE_COMMENT_HEADER: &str = "IDAX_DIAPHORA_PSEUDOCODE_COMMENTS\t1\texact-tree-location";
const DECLARATION_PLACEHOLDER: &str = "__idax_diaphora_function";
const REFERENT_DECLARATION_PLACEHOLDER: &str = "__idax_diaphora_referent";

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
    ExportInstructionMetadata,
    CompareInstructionMetadata,
    ExportReferentMetadata,
    CompareReferentMetadata,
    ExportPseudocodeComments,
    ComparePseudocodeComments,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForcedOperandMetadata {
    index: usize,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstructionMetadataRecord {
    function_ordinal: usize,
    instruction_ordinal: usize,
    function_offset: i64,
    size: usize,
    full_md5: String,
    relocation_md5: String,
    mnemonic: String,
    comment: String,
    repeatable_comment: String,
    forced_operands: Vec<ForcedOperandMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstructionMetadataManifest {
    functions: Vec<FunctionRecord>,
    instructions: Vec<InstructionMetadataRecord>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct InstructionMetadataComparison {
    functions: MatchSummary,
    eligible: Vec<(usize, u64)>,
    unmatched_functions: usize,
    guard_failures: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct InstructionMetadataApplySummary {
    comments: usize,
    repeatable_comments: usize,
    forced_operands: usize,
    preserved: usize,
    failures: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReferentKind {
    Code,
    Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferentMetadataRecord {
    function_ordinal: usize,
    instruction_ordinal: usize,
    function_offset: i64,
    size: usize,
    full_md5: String,
    relocation_md5: String,
    mnemonic: String,
    kind: ReferentKind,
    name: String,
    declaration: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferentMetadataManifest {
    functions: Vec<FunctionRecord>,
    referents: Vec<ReferentMetadataRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligibleReferentMetadata {
    metadata_index: usize,
    instruction_address: u64,
    referent_address: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ReferentMetadataComparison {
    functions: MatchSummary,
    eligible: Vec<EligibleReferentMetadata>,
    unmatched_functions: usize,
    instruction_guard_failures: usize,
    reference_guard_failures: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ReferentMetadataApplySummary {
    names: usize,
    types: usize,
    preserved: usize,
    failures: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PseudocodePosition {
    Default,
    Argument(usize),
    ParenthesisOpen,
    Assembly,
    ElseLine,
    DoLine,
    Semicolon,
    OpenBrace,
    CloseBrace,
    ParenthesisClose,
    LabelColon,
    BlockBefore,
    BlockAfter,
    TryLine,
    SwitchCase(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PseudocodeCommentRecord {
    function_ordinal: usize,
    instruction_ordinal: usize,
    function_offset: i64,
    size: usize,
    full_md5: String,
    relocation_md5: String,
    mnemonic: String,
    position: PseudocodePosition,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PseudocodeCommentManifest {
    functions: Vec<FunctionRecord>,
    comments: Vec<PseudocodeCommentRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligiblePseudocodeComment {
    comment_index: usize,
    function_address: u64,
    comment_address: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PseudocodeCommentComparison {
    functions: MatchSummary,
    eligible: Vec<EligiblePseudocodeComment>,
    unmatched_functions: usize,
    guard_failures: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PseudocodeCommentApplySummary {
    comments: usize,
    preserved: usize,
    failures: usize,
    saved_functions: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct InstructionFingerprint {
    size: usize,
    full_md5: String,
    relocation_md5: String,
    mnemonic: String,
    operand_indices: Vec<usize>,
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
        "--export-instruction-metadata" => Mode::ExportInstructionMetadata,
        "--compare-instruction-metadata" => Mode::CompareInstructionMetadata,
        "--export-referent-metadata" => Mode::ExportReferentMetadata,
        "--compare-referent-metadata" => Mode::CompareReferentMetadata,
        "--export-pseudocode-comments" => Mode::ExportPseudocodeComments,
        "--compare-pseudocode-comments" => Mode::ComparePseudocodeComments,
        _ => {
            return Err(Error::validation(
                "expected an exact, instruction-metadata, referent-metadata, or pseudocode-comment export/compare mode",
            ));
        }
    };
    let mut apply = false;
    for argument in arguments {
        if argument == "--apply"
            && matches!(
                mode,
                Mode::Compare
                    | Mode::CompareInstructionMetadata
                    | Mode::CompareReferentMetadata
                    | Mode::ComparePseudocodeComments
            )
        {
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

fn format_forced_operands(operands: &[ForcedOperandMetadata]) -> String {
    let mut output = String::new();
    for operand in operands {
        output.push_str(&operand.index.to_string());
        output.push(':');
        output.push_str(&operand.text.len().to_string());
        output.push(':');
        output.push_str(&operand.text);
    }
    output
}

fn parse_prefixed_usize(payload: &[u8], cursor: &mut usize, label: &str) -> Result<usize> {
    let relative_end = payload[*cursor..]
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| Error::validation(format!("malformed {label}")))?;
    if relative_end == 0 {
        return Err(Error::validation(format!("malformed {label}")));
    }
    let end = *cursor + relative_end;
    let text = std::str::from_utf8(&payload[*cursor..end])
        .map_err(|_| Error::validation(format!("invalid {label}")))?;
    let value = text
        .parse::<usize>()
        .map_err(|_| Error::validation(format!("invalid {label}")))?;
    *cursor = end + 1;
    Ok(value)
}

fn parse_forced_operands(payload: &str) -> Result<Vec<ForcedOperandMetadata>> {
    let payload = payload.as_bytes();
    let mut cursor = 0usize;
    let mut previous_index = None;
    let mut operands = Vec::new();
    while cursor < payload.len() {
        let index = parse_prefixed_usize(payload, &mut cursor, "forced operand index")?;
        let text_size = parse_prefixed_usize(payload, &mut cursor, "forced operand length")?;
        if index > i32::MAX as usize {
            return Err(Error::validation("invalid forced operand index"));
        }
        if text_size == 0 || text_size > payload.len() - cursor {
            return Err(Error::validation("truncated forced operand text"));
        }
        if previous_index.is_some_and(|previous| index <= previous) {
            return Err(Error::validation(
                "forced operand indices are duplicate or unsorted",
            ));
        }
        let text = String::from_utf8(payload[cursor..cursor + text_size].to_vec())
            .map_err(|_| Error::validation("forced operand text is not UTF-8"))?;
        if text.contains('\0') {
            return Err(Error::validation("forced operand text contains NUL"));
        }
        operands.push(ForcedOperandMetadata { index, text });
        previous_index = Some(index);
        cursor += text_size;
    }
    Ok(operands)
}

fn format_instruction_metadata_record(record: &InstructionMetadataRecord) -> String {
    format!(
        "I\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.function_ordinal,
        record.instruction_ordinal,
        record.function_offset,
        record.size,
        record.full_md5,
        record.relocation_md5,
        hex_encode(&record.mnemonic),
        hex_encode(&record.comment),
        hex_encode(&record.repeatable_comment),
        hex_encode(&format_forced_operands(&record.forced_operands)),
    )
}

fn format_instruction_metadata_manifest(manifest: &InstructionMetadataManifest) -> String {
    let mut output = format!("{INSTRUCTION_METADATA_HEADER}\n");
    for function in &manifest.functions {
        output.push_str(&format_record(function));
        output.push('\n');
    }
    for instruction in &manifest.instructions {
        output.push_str(&format_instruction_metadata_record(instruction));
        output.push('\n');
    }
    output
}

fn parse_instruction_metadata_manifest(text: &str) -> Result<InstructionMetadataManifest> {
    let mut lines = text.lines();
    if lines.next() != Some(INSTRUCTION_METADATA_HEADER) {
        return Err(Error::validation(
            "unsupported Diaphora instruction metadata manifest header",
        ));
    }
    let mut function_text = format!("{HEADER}\n");
    let mut instructions = Vec::new();
    let mut instruction_keys = HashSet::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.first() == Some(&"F") {
            function_text.push_str(line);
            function_text.push('\n');
            continue;
        }
        if fields.len() != 11 || fields[0] != "I" {
            return Err(Error::validation(
                "malformed Diaphora instruction metadata record",
            ));
        }
        let parse_usize = |field: &str, label: &str| {
            field
                .parse::<usize>()
                .map_err(|_| Error::validation(format!("invalid {label}")))
        };
        let function_ordinal = parse_usize(fields[1], "function ordinal")?;
        let instruction_ordinal = parse_usize(fields[2], "instruction ordinal")?;
        let function_offset = fields[3]
            .parse::<i64>()
            .map_err(|_| Error::validation("invalid instruction function offset"))?;
        let size = parse_usize(fields[4], "instruction size")?;
        if size == 0 {
            return Err(Error::validation("invalid instruction size"));
        }
        let full_md5 = fields[5].to_ascii_lowercase();
        let relocation_md5 = fields[6].to_ascii_lowercase();
        if !valid_md5(&full_md5) || !valid_md5(&relocation_md5) {
            return Err(Error::validation("invalid instruction metadata MD5 field"));
        }
        let mnemonic = hex_decode(fields[7])?;
        let comment = hex_decode(fields[8])?;
        let repeatable_comment = hex_decode(fields[9])?;
        let forced_operands = parse_forced_operands(&hex_decode(fields[10])?)?;
        if mnemonic.contains('\0') || comment.contains('\0') || repeatable_comment.contains('\0') {
            return Err(Error::validation("instruction metadata text contains NUL"));
        }
        if comment.is_empty() && repeatable_comment.is_empty() && forced_operands.is_empty() {
            return Err(Error::validation(
                "instruction metadata record contains no metadata",
            ));
        }
        if !instruction_keys.insert((function_ordinal, instruction_ordinal)) {
            return Err(Error::validation("duplicate instruction metadata record"));
        }
        instructions.push(InstructionMetadataRecord {
            function_ordinal,
            instruction_ordinal,
            function_offset,
            size,
            full_md5,
            relocation_md5,
            mnemonic,
            comment,
            repeatable_comment,
            forced_operands,
        });
    }
    let functions = parse_manifest(&function_text)?;
    let ordinals: HashSet<_> = functions.iter().map(|function| function.ordinal).collect();
    if ordinals.len() != functions.len() {
        return Err(Error::validation("duplicate function ordinal"));
    }
    if instructions
        .iter()
        .any(|instruction| !ordinals.contains(&instruction.function_ordinal))
    {
        return Err(Error::validation(
            "instruction metadata references an unknown function",
        ));
    }
    Ok(InstructionMetadataManifest {
        functions,
        instructions,
    })
}

fn referent_kind_name(kind: ReferentKind) -> &'static str {
    match kind {
        ReferentKind::Code => "code",
        ReferentKind::Data => "data",
    }
}

fn parse_referent_kind(name: &str) -> Result<ReferentKind> {
    match name {
        "code" => Ok(ReferentKind::Code),
        "data" => Ok(ReferentKind::Data),
        _ => Err(Error::validation(format!(
            "unknown referent metadata class: {name}"
        ))),
    }
}

fn format_referent_metadata_record(record: &ReferentMetadataRecord) -> String {
    format!(
        "R\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.function_ordinal,
        record.instruction_ordinal,
        record.function_offset,
        record.size,
        record.full_md5,
        record.relocation_md5,
        hex_encode(&record.mnemonic),
        referent_kind_name(record.kind),
        hex_encode(&record.name),
        hex_encode(&record.declaration),
    )
}

fn format_referent_metadata_manifest(manifest: &ReferentMetadataManifest) -> String {
    let mut output = format!("{REFERENT_METADATA_HEADER}\n");
    for function in &manifest.functions {
        output.push_str(&format_record(function));
        output.push('\n');
    }
    for referent in &manifest.referents {
        output.push_str(&format_referent_metadata_record(referent));
        output.push('\n');
    }
    output
}

fn parse_referent_metadata_manifest(text: &str) -> Result<ReferentMetadataManifest> {
    let mut lines = text.lines();
    if lines.next() != Some(REFERENT_METADATA_HEADER) {
        return Err(Error::validation(
            "unsupported Diaphora referent metadata manifest header",
        ));
    }
    let mut function_text = format!("{HEADER}\n");
    let mut referents = Vec::new();
    let mut referent_keys = HashSet::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.first() == Some(&"F") {
            function_text.push_str(line);
            function_text.push('\n');
            continue;
        }
        if fields.len() != 11 || fields[0] != "R" {
            return Err(Error::validation(
                "malformed Diaphora referent metadata record",
            ));
        }
        let parse_usize = |field: &str, label: &str| {
            field
                .parse::<usize>()
                .map_err(|_| Error::validation(format!("invalid {label}")))
        };
        let function_ordinal = parse_usize(fields[1], "function ordinal")?;
        let instruction_ordinal = parse_usize(fields[2], "instruction ordinal")?;
        let function_offset = fields[3]
            .parse::<i64>()
            .map_err(|_| Error::validation("invalid referent function offset"))?;
        let size = parse_usize(fields[4], "instruction size")?;
        if size == 0 {
            return Err(Error::validation("invalid instruction size"));
        }
        let full_md5 = fields[5].to_ascii_lowercase();
        let relocation_md5 = fields[6].to_ascii_lowercase();
        if !valid_md5(&full_md5) || !valid_md5(&relocation_md5) {
            return Err(Error::validation("invalid referent metadata MD5 field"));
        }
        let mnemonic = hex_decode(fields[7])?;
        let kind = parse_referent_kind(fields[8])?;
        let name = hex_decode(fields[9])?;
        let declaration = hex_decode(fields[10])?;
        if mnemonic.contains('\0') || name.contains('\0') || declaration.contains('\0') {
            return Err(Error::validation("referent metadata text contains NUL"));
        }
        if name.is_empty() && declaration.is_empty() {
            return Err(Error::validation(
                "referent metadata record contains no metadata",
            ));
        }
        if !referent_keys.insert((function_ordinal, instruction_ordinal, kind)) {
            return Err(Error::validation("duplicate referent metadata record"));
        }
        referents.push(ReferentMetadataRecord {
            function_ordinal,
            instruction_ordinal,
            function_offset,
            size,
            full_md5,
            relocation_md5,
            mnemonic,
            kind,
            name,
            declaration,
        });
    }
    let functions = parse_manifest(&function_text)?;
    let ordinals: HashSet<_> = functions.iter().map(|function| function.ordinal).collect();
    if ordinals.len() != functions.len() {
        return Err(Error::validation("duplicate function ordinal"));
    }
    if referents
        .iter()
        .any(|referent| !ordinals.contains(&referent.function_ordinal))
    {
        return Err(Error::validation(
            "referent metadata references an unknown function",
        ));
    }
    Ok(ReferentMetadataManifest {
        functions,
        referents,
    })
}

fn pseudocode_position_name(position: PseudocodePosition) -> &'static str {
    match position {
        PseudocodePosition::Default => "default",
        PseudocodePosition::Argument(_) => "argument",
        PseudocodePosition::ParenthesisOpen => "parenthesis-open",
        PseudocodePosition::Assembly => "assembly",
        PseudocodePosition::ElseLine => "else-line",
        PseudocodePosition::DoLine => "do-line",
        PseudocodePosition::Semicolon => "semicolon",
        PseudocodePosition::OpenBrace => "open-brace",
        PseudocodePosition::CloseBrace => "close-brace",
        PseudocodePosition::ParenthesisClose => "parenthesis-close",
        PseudocodePosition::LabelColon => "label-colon",
        PseudocodePosition::BlockBefore => "block-before",
        PseudocodePosition::BlockAfter => "block-after",
        PseudocodePosition::TryLine => "try-line",
        PseudocodePosition::SwitchCase(_) => "switch-case",
    }
}

fn pseudocode_position_detail(position: PseudocodePosition) -> i64 {
    match position {
        PseudocodePosition::Argument(index) => index as i64,
        PseudocodePosition::SwitchCase(value) => value,
        _ => 0,
    }
}

fn parse_pseudocode_position(name: &str, detail: i64) -> Result<PseudocodePosition> {
    let simple = |position| {
        if detail == 0 {
            Ok(position)
        } else {
            Err(Error::validation(
                "simple pseudocode comment position detail must be zero",
            ))
        }
    };
    match name {
        "default" => simple(PseudocodePosition::Default),
        "argument" if (0..=63).contains(&detail) => {
            Ok(PseudocodePosition::Argument(detail as usize))
        }
        "argument" => Err(Error::validation(
            "pseudocode comment argument index must be in [0, 63]",
        )),
        "parenthesis-open" => simple(PseudocodePosition::ParenthesisOpen),
        "assembly" => simple(PseudocodePosition::Assembly),
        "else-line" => simple(PseudocodePosition::ElseLine),
        "do-line" => simple(PseudocodePosition::DoLine),
        "semicolon" => simple(PseudocodePosition::Semicolon),
        "open-brace" => simple(PseudocodePosition::OpenBrace),
        "close-brace" => simple(PseudocodePosition::CloseBrace),
        "parenthesis-close" => simple(PseudocodePosition::ParenthesisClose),
        "label-colon" => simple(PseudocodePosition::LabelColon),
        "block-before" => simple(PseudocodePosition::BlockBefore),
        "block-after" => simple(PseudocodePosition::BlockAfter),
        "try-line" => simple(PseudocodePosition::TryLine),
        "switch-case" if (-0x1fff_ffff..=0x1fff_ffff).contains(&detail) => {
            Ok(PseudocodePosition::SwitchCase(detail))
        }
        "switch-case" => Err(Error::validation(
            "pseudocode switch-case comment value exceeds the supported range",
        )),
        _ => Err(Error::validation(format!(
            "unknown pseudocode comment position: {name}"
        ))),
    }
}

fn to_manifest_position(position: decompiler::CommentPosition) -> Result<PseudocodePosition> {
    let value = match position {
        decompiler::CommentPosition::Default => PseudocodePosition::Default,
        decompiler::CommentPosition::Argument(index) => PseudocodePosition::Argument(index),
        decompiler::CommentPosition::ParenthesisOpen => PseudocodePosition::ParenthesisOpen,
        decompiler::CommentPosition::Assembly => PseudocodePosition::Assembly,
        decompiler::CommentPosition::ElseLine => PseudocodePosition::ElseLine,
        decompiler::CommentPosition::DoLine => PseudocodePosition::DoLine,
        decompiler::CommentPosition::Semicolon => PseudocodePosition::Semicolon,
        decompiler::CommentPosition::OpenBrace => PseudocodePosition::OpenBrace,
        decompiler::CommentPosition::CloseBrace => PseudocodePosition::CloseBrace,
        decompiler::CommentPosition::ParenthesisClose => PseudocodePosition::ParenthesisClose,
        decompiler::CommentPosition::LabelColon => PseudocodePosition::LabelColon,
        decompiler::CommentPosition::BlockBefore => PseudocodePosition::BlockBefore,
        decompiler::CommentPosition::BlockAfter => PseudocodePosition::BlockAfter,
        decompiler::CommentPosition::TryLine => PseudocodePosition::TryLine,
        decompiler::CommentPosition::SwitchCase(value) => PseudocodePosition::SwitchCase(value),
    };
    parse_pseudocode_position(
        pseudocode_position_name(value),
        pseudocode_position_detail(value),
    )
}

fn to_public_position(position: PseudocodePosition) -> decompiler::CommentPosition {
    match position {
        PseudocodePosition::Default => decompiler::CommentPosition::Default,
        PseudocodePosition::Argument(index) => decompiler::CommentPosition::Argument(index),
        PseudocodePosition::ParenthesisOpen => decompiler::CommentPosition::ParenthesisOpen,
        PseudocodePosition::Assembly => decompiler::CommentPosition::Assembly,
        PseudocodePosition::ElseLine => decompiler::CommentPosition::ElseLine,
        PseudocodePosition::DoLine => decompiler::CommentPosition::DoLine,
        PseudocodePosition::Semicolon => decompiler::CommentPosition::Semicolon,
        PseudocodePosition::OpenBrace => decompiler::CommentPosition::OpenBrace,
        PseudocodePosition::CloseBrace => decompiler::CommentPosition::CloseBrace,
        PseudocodePosition::ParenthesisClose => decompiler::CommentPosition::ParenthesisClose,
        PseudocodePosition::LabelColon => decompiler::CommentPosition::LabelColon,
        PseudocodePosition::BlockBefore => decompiler::CommentPosition::BlockBefore,
        PseudocodePosition::BlockAfter => decompiler::CommentPosition::BlockAfter,
        PseudocodePosition::TryLine => decompiler::CommentPosition::TryLine,
        PseudocodePosition::SwitchCase(value) => decompiler::CommentPosition::SwitchCase(value),
    }
}

fn format_pseudocode_comment_record(record: &PseudocodeCommentRecord) -> String {
    format!(
        "P\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.function_ordinal,
        record.instruction_ordinal,
        record.function_offset,
        record.size,
        record.full_md5,
        record.relocation_md5,
        hex_encode(&record.mnemonic),
        pseudocode_position_name(record.position),
        pseudocode_position_detail(record.position),
        hex_encode(&record.text),
    )
}

fn format_pseudocode_comment_manifest(manifest: &PseudocodeCommentManifest) -> String {
    let mut output = format!("{PSEUDOCODE_COMMENT_HEADER}\n");
    for function in &manifest.functions {
        output.push_str(&format_record(function));
        output.push('\n');
    }
    for comment in &manifest.comments {
        output.push_str(&format_pseudocode_comment_record(comment));
        output.push('\n');
    }
    output
}

fn parse_pseudocode_comment_manifest(text: &str) -> Result<PseudocodeCommentManifest> {
    let mut lines = text.lines();
    if lines.next() != Some(PSEUDOCODE_COMMENT_HEADER) {
        return Err(Error::validation(
            "unsupported Diaphora pseudocode comment manifest header",
        ));
    }
    let mut function_text = format!("{HEADER}\n");
    let mut comments = Vec::new();
    let mut comment_keys = HashSet::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.first() == Some(&"F") {
            function_text.push_str(line);
            function_text.push('\n');
            continue;
        }
        if fields.len() != 11 || fields[0] != "P" {
            return Err(Error::validation(
                "malformed Diaphora pseudocode comment record",
            ));
        }
        let parse_usize = |field: &str, label: &str| {
            field
                .parse::<usize>()
                .map_err(|_| Error::validation(format!("invalid {label}")))
        };
        let function_ordinal = parse_usize(fields[1], "function ordinal")?;
        let instruction_ordinal = parse_usize(fields[2], "instruction ordinal")?;
        let function_offset = fields[3]
            .parse::<i64>()
            .map_err(|_| Error::validation("invalid pseudocode comment function offset"))?;
        let size = parse_usize(fields[4], "instruction size")?;
        if size == 0 {
            return Err(Error::validation("invalid instruction size"));
        }
        let full_md5 = fields[5].to_ascii_lowercase();
        let relocation_md5 = fields[6].to_ascii_lowercase();
        if !valid_md5(&full_md5) || !valid_md5(&relocation_md5) {
            return Err(Error::validation("invalid pseudocode comment MD5 field"));
        }
        let mnemonic = hex_decode(fields[7])?;
        let position_detail = fields[9]
            .parse::<i64>()
            .map_err(|_| Error::validation("invalid pseudocode comment position detail"))?;
        let position = parse_pseudocode_position(fields[8], position_detail)?;
        let comment = hex_decode(fields[10])?;
        if mnemonic.contains('\0') || comment.is_empty() || comment.contains('\0') {
            return Err(Error::validation(
                "pseudocode comment text is empty or contains NUL",
            ));
        }
        if !comment_keys.insert((function_ordinal, instruction_ordinal, position)) {
            return Err(Error::validation(
                "duplicate pseudocode comment location record",
            ));
        }
        comments.push(PseudocodeCommentRecord {
            function_ordinal,
            instruction_ordinal,
            function_offset,
            size,
            full_md5,
            relocation_md5,
            mnemonic,
            position,
            text: comment,
        });
    }
    let functions = parse_manifest(&function_text)?;
    let ordinals: HashSet<_> = functions.iter().map(|function| function.ordinal).collect();
    if ordinals.len() != functions.len() {
        return Err(Error::validation("duplicate function ordinal"));
    }
    if comments
        .iter()
        .any(|comment| !ordinals.contains(&comment.function_ordinal))
    {
        return Err(Error::validation(
            "pseudocode comment references an unknown function",
        ));
    }
    Ok(PseudocodeCommentManifest {
        functions,
        comments,
    })
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

fn relative_offset(address: u64, function_start: u64) -> Result<i64> {
    let difference = i128::from(address) - i128::from(function_start);
    i64::try_from(difference)
        .map_err(|_| Error::validation("instruction offset exceeds signed manifest range"))
}

fn apply_relative_offset(function_start: u64, offset: i64) -> Result<u64> {
    if offset >= 0 {
        function_start
            .checked_add(offset as u64)
            .ok_or_else(|| Error::validation("instruction address overflow"))
    } else {
        function_start
            .checked_sub(offset.unsigned_abs())
            .ok_or_else(|| Error::validation("instruction address underflow"))
    }
}

fn extract_instruction_fingerprint(address: u64) -> Result<InstructionFingerprint> {
    let decoded = instruction::decode(address)?;
    let size = usize::try_from(decoded.size())
        .map_err(|_| Error::validation("instruction size overflows usize"))?;
    let bytes = data::read_bytes(address, decoded.size())?;
    if bytes.len() != size {
        return Err(Error::sdk("instruction byte read was truncated"));
    }
    let operands: Vec<_> = decoded
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
    let prefix_size = normalized_prefix_size(size, &operands)?;
    let mut full_hash = Md5::new();
    let mut relocation_hash = Md5::new();
    full_hash.update(&bytes);
    relocation_hash.update(&bytes[..prefix_size]);
    let operand_indices = decoded
        .operands()
        .iter()
        .map(|operand| {
            usize::try_from(operand.index())
                .map_err(|_| Error::validation("negative operand index"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(InstructionFingerprint {
        size,
        full_md5: full_hash.finish_hex(),
        relocation_md5: relocation_hash.finish_hex(),
        mnemonic: decoded.mnemonic().to_owned(),
        operand_indices,
    })
}

fn extract_instruction_metadata_manifest() -> Result<InstructionMetadataManifest> {
    let functions = extract_manifest()?;
    let mut instructions = Vec::new();
    for function_record in &functions {
        let mut addresses = function::code_addresses(function_record.address)?;
        addresses.sort_unstable();
        for (instruction_ordinal, address) in addresses.iter().copied().enumerate() {
            let decoded = instruction::decode(address)?;
            let comment = optional_text(comment::get(address, false))?;
            let repeatable_comment = optional_text(comment::get(address, true))?;
            let mut forced_operands = Vec::new();
            for operand in decoded.operands() {
                let index = usize::try_from(operand.index())
                    .map_err(|_| Error::validation("negative operand index"))?;
                let text =
                    optional_text(instruction::get_forced_operand(address, operand.index()))?;
                if !text.is_empty() {
                    forced_operands.push(ForcedOperandMetadata { index, text });
                }
            }
            forced_operands.sort_by_key(|operand| operand.index);
            if forced_operands
                .windows(2)
                .any(|pair| pair[0].index == pair[1].index)
            {
                return Err(Error::validation("duplicate decoded operand index"));
            }
            if comment.is_empty() && repeatable_comment.is_empty() && forced_operands.is_empty() {
                continue;
            }
            let fingerprint = extract_instruction_fingerprint(address)?;
            instructions.push(InstructionMetadataRecord {
                function_ordinal: function_record.ordinal,
                instruction_ordinal,
                function_offset: relative_offset(address, function_record.address)?,
                size: fingerprint.size,
                full_md5: fingerprint.full_md5,
                relocation_md5: fingerprint.relocation_md5,
                mnemonic: fingerprint.mnemonic,
                comment,
                repeatable_comment,
                forced_operands,
            });
        }
    }
    Ok(InstructionMetadataManifest {
        functions,
        instructions,
    })
}

fn unique_referent(references: &[xref::Reference], kind: ReferentKind) -> Option<u64> {
    let mut targets: Vec<_> = references
        .iter()
        .filter(|reference| match kind {
            ReferentKind::Code => {
                reference.is_code && reference.ref_type != xref::ReferenceType::Flow
            }
            ReferentKind::Data => !reference.is_code,
        })
        .map(|reference| reference.to)
        .collect();
    targets.sort_unstable();
    targets.dedup();
    (targets.len() == 1).then(|| targets[0])
}

fn referent_payload(address: u64) -> Result<(String, String)> {
    let referent_name = match name::get(address) {
        Ok(value) if !name::is_auto_generated(address) => value,
        Ok(_) => String::new(),
        Err(error) if error.category == ErrorCategory::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let declaration = match types::retrieve(address) {
        Ok(value) => value.declaration(Some(REFERENT_DECLARATION_PLACEHOLDER))?,
        Err(error) if error.category == ErrorCategory::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    if referent_name.contains('\0') || declaration.contains('\0') {
        return Err(Error::validation(
            "referent name or declaration contains NUL",
        ));
    }
    Ok((referent_name, declaration))
}

fn extract_referent_metadata_manifest() -> Result<ReferentMetadataManifest> {
    let functions = extract_manifest()?;
    let mut referents = Vec::new();
    for function_record in &functions {
        let mut addresses = function::code_addresses(function_record.address)?;
        addresses.sort_unstable();
        for (instruction_ordinal, address) in addresses.iter().copied().enumerate() {
            let references = xref::refs_from(address)?;
            let mut fingerprint = None;
            let mut offset = None;
            for kind in [ReferentKind::Code, ReferentKind::Data] {
                let Some(target) = unique_referent(&references, kind) else {
                    continue;
                };
                let (referent_name, declaration) = referent_payload(target)?;
                if referent_name.is_empty() && declaration.is_empty() {
                    continue;
                }
                if fingerprint.is_none() {
                    fingerprint = Some(extract_instruction_fingerprint(address)?);
                }
                if offset.is_none() {
                    offset = Some(relative_offset(address, function_record.address)?);
                }
                let fingerprint = fingerprint.as_ref().unwrap();
                referents.push(ReferentMetadataRecord {
                    function_ordinal: function_record.ordinal,
                    instruction_ordinal,
                    function_offset: offset.unwrap(),
                    size: fingerprint.size,
                    full_md5: fingerprint.full_md5.clone(),
                    relocation_md5: fingerprint.relocation_md5.clone(),
                    mnemonic: fingerprint.mnemonic.clone(),
                    kind,
                    name: referent_name,
                    declaration,
                });
            }
        }
    }
    Ok(ReferentMetadataManifest {
        functions,
        referents,
    })
}

fn extract_pseudocode_comment_manifest() -> Result<PseudocodeCommentManifest> {
    if !decompiler::available()? {
        return Err(Error::unsupported("Hex-Rays decompiler is unavailable"));
    }
    let functions = extract_manifest()?;
    let mut comments = Vec::new();
    for function_record in &functions {
        let mut addresses = function::code_addresses(function_record.address)?;
        addresses.sort_unstable();
        let ordinal_by_address: HashMap<_, _> = addresses
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, address)| (address, ordinal))
            .collect();
        let decompiled = match decompiler::decompile(function_record.address) {
            Ok(decompiled) => decompiled,
            Err(_) => continue,
        };
        for comment in decompiled.comments()? {
            let Some(instruction_ordinal) = ordinal_by_address.get(&comment.address).copied()
            else {
                continue;
            };
            if comment.text.is_empty() || comment.text.contains('\0') {
                return Err(Error::validation(
                    "persisted pseudocode comment is empty or contains NUL",
                ));
            }
            let fingerprint = extract_instruction_fingerprint(comment.address)?;
            comments.push(PseudocodeCommentRecord {
                function_ordinal: function_record.ordinal,
                instruction_ordinal,
                function_offset: relative_offset(comment.address, function_record.address)?,
                size: fingerprint.size,
                full_md5: fingerprint.full_md5,
                relocation_md5: fingerprint.relocation_md5,
                mnemonic: fingerprint.mnemonic,
                position: to_manifest_position(comment.position)?,
                text: comment.text,
            });
        }
    }
    Ok(PseudocodeCommentManifest {
        functions,
        comments,
    })
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

fn compare_instruction_metadata(
    baseline: &InstructionMetadataManifest,
    current: &[FunctionRecord],
) -> Result<InstructionMetadataComparison> {
    let functions = compare_records(&baseline.functions, current);
    let baseline_by_ordinal: HashMap<_, _> = baseline
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.ordinal, index))
        .collect();
    let current_by_baseline: HashMap<_, _> = functions
        .matches
        .iter()
        .map(|matched| (matched.baseline, matched.current))
        .collect();
    let mut address_cache: HashMap<usize, Vec<u64>> = HashMap::new();
    let mut eligible = Vec::new();
    let mut unmatched_functions = 0usize;
    let mut guard_failures = 0usize;

    for (metadata_index, metadata) in baseline.instructions.iter().enumerate() {
        let Some(baseline_index) = baseline_by_ordinal.get(&metadata.function_ordinal) else {
            unmatched_functions += 1;
            continue;
        };
        let Some(current_index) = current_by_baseline.get(baseline_index).copied() else {
            unmatched_functions += 1;
            continue;
        };
        let target_function = &current[current_index];
        let target_address =
            match apply_relative_offset(target_function.address, metadata.function_offset) {
                Ok(address) => address,
                Err(_) => {
                    guard_failures += 1;
                    continue;
                }
            };
        if let std::collections::hash_map::Entry::Vacant(entry) = address_cache.entry(current_index)
        {
            let mut addresses = function::code_addresses(target_function.address)?;
            addresses.sort_unstable();
            entry.insert(addresses);
        }
        let addresses = &address_cache[&current_index];
        if addresses.get(metadata.instruction_ordinal) != Some(&target_address) {
            guard_failures += 1;
            continue;
        }
        let fingerprint = extract_instruction_fingerprint(target_address)?;
        if fingerprint.size != metadata.size
            || fingerprint.mnemonic != metadata.mnemonic
            || fingerprint.relocation_md5 != metadata.relocation_md5
            || metadata
                .forced_operands
                .iter()
                .any(|forced| !fingerprint.operand_indices.contains(&forced.index))
        {
            guard_failures += 1;
            continue;
        }
        eligible.push((metadata_index, target_address));
    }

    Ok(InstructionMetadataComparison {
        functions,
        eligible,
        unmatched_functions,
        guard_failures,
    })
}

fn apply_instruction_metadata(
    baseline: &InstructionMetadataManifest,
    comparison: &InstructionMetadataComparison,
) -> InstructionMetadataApplySummary {
    let mut summary = InstructionMetadataApplySummary::default();
    for (metadata_index, target_address) in &comparison.eligible {
        let metadata = &baseline.instructions[*metadata_index];
        for (source, repeatable) in [
            (metadata.comment.as_str(), false),
            (metadata.repeatable_comment.as_str(), true),
        ] {
            if source.is_empty() {
                continue;
            }
            match comment::get(*target_address, repeatable) {
                Ok(existing) if !existing.is_empty() => summary.preserved += 1,
                Ok(_) => match comment::set(*target_address, source, repeatable) {
                    Ok(()) if repeatable => summary.repeatable_comments += 1,
                    Ok(()) => summary.comments += 1,
                    Err(_) => summary.failures += 1,
                },
                Err(error) if error.category == ErrorCategory::NotFound => {
                    match comment::set(*target_address, source, repeatable) {
                        Ok(()) if repeatable => summary.repeatable_comments += 1,
                        Ok(()) => summary.comments += 1,
                        Err(_) => summary.failures += 1,
                    }
                }
                Err(_) => summary.failures += 1,
            }
        }

        for forced in &metadata.forced_operands {
            let index = forced.index as i32;
            match instruction::get_forced_operand(*target_address, index) {
                Ok(existing) if !existing.is_empty() => summary.preserved += 1,
                Ok(_) => {
                    match instruction::set_forced_operand(*target_address, index, &forced.text) {
                        Ok(()) => summary.forced_operands += 1,
                        Err(_) => summary.failures += 1,
                    }
                }
                Err(error) if error.category == ErrorCategory::NotFound => {
                    match instruction::set_forced_operand(*target_address, index, &forced.text) {
                        Ok(()) => summary.forced_operands += 1,
                        Err(_) => summary.failures += 1,
                    }
                }
                Err(_) => summary.failures += 1,
            }
        }
    }
    summary
}

fn instruction_metadata_report(
    baseline: &InstructionMetadataManifest,
    current: &[FunctionRecord],
    comparison: &InstructionMetadataComparison,
) -> String {
    format!(
        "Diaphora exact instruction metadata comparison\nBaseline functions: {}\nCurrent functions: {}\nUnique function matches: {}\nAmbiguous baseline functions: {}\nUnmatched baseline functions: {}\nMetadata records: {}\nEligible instruction records: {}\nRecords with unmatched functions: {}\nInstruction guard failures: {}",
        baseline.functions.len(),
        current.len(),
        comparison.functions.matches.len(),
        comparison.functions.ambiguous,
        comparison.functions.unmatched,
        baseline.instructions.len(),
        comparison.eligible.len(),
        comparison.unmatched_functions,
        comparison.guard_failures,
    )
}

fn compare_referent_metadata(
    baseline: &ReferentMetadataManifest,
    current: &[FunctionRecord],
) -> Result<ReferentMetadataComparison> {
    let functions = compare_records(&baseline.functions, current);
    let baseline_by_ordinal: HashMap<_, _> = baseline
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.ordinal, index))
        .collect();
    let current_by_baseline: HashMap<_, _> = functions
        .matches
        .iter()
        .map(|matched| (matched.baseline, matched.current))
        .collect();
    let mut address_cache: HashMap<usize, Vec<u64>> = HashMap::new();
    let mut eligible = Vec::new();
    let mut unmatched_functions = 0usize;
    let mut instruction_guard_failures = 0usize;
    let mut reference_guard_failures = 0usize;

    for (metadata_index, metadata) in baseline.referents.iter().enumerate() {
        let Some(baseline_index) = baseline_by_ordinal.get(&metadata.function_ordinal) else {
            unmatched_functions += 1;
            continue;
        };
        let Some(current_index) = current_by_baseline.get(baseline_index).copied() else {
            unmatched_functions += 1;
            continue;
        };
        let target_function = &current[current_index];
        let target_address =
            match apply_relative_offset(target_function.address, metadata.function_offset) {
                Ok(address) => address,
                Err(_) => {
                    instruction_guard_failures += 1;
                    continue;
                }
            };
        if let std::collections::hash_map::Entry::Vacant(entry) = address_cache.entry(current_index)
        {
            let mut addresses = function::code_addresses(target_function.address)?;
            addresses.sort_unstable();
            entry.insert(addresses);
        }
        if address_cache[&current_index].get(metadata.instruction_ordinal) != Some(&target_address)
        {
            instruction_guard_failures += 1;
            continue;
        }
        let fingerprint = extract_instruction_fingerprint(target_address)?;
        if fingerprint.size != metadata.size
            || fingerprint.mnemonic != metadata.mnemonic
            || fingerprint.relocation_md5 != metadata.relocation_md5
        {
            instruction_guard_failures += 1;
            continue;
        }
        let references = xref::refs_from(target_address)?;
        let Some(referent_address) = unique_referent(&references, metadata.kind) else {
            reference_guard_failures += 1;
            continue;
        };
        eligible.push(EligibleReferentMetadata {
            metadata_index,
            instruction_address: target_address,
            referent_address,
        });
    }

    Ok(ReferentMetadataComparison {
        functions,
        eligible,
        unmatched_functions,
        instruction_guard_failures,
        reference_guard_failures,
    })
}

fn apply_referent_metadata(
    baseline: &ReferentMetadataManifest,
    comparison: &ReferentMetadataComparison,
) -> ReferentMetadataApplySummary {
    let mut summary = ReferentMetadataApplySummary::default();
    for eligible in &comparison.eligible {
        let source = &baseline.referents[eligible.metadata_index];
        if !source.name.is_empty() {
            let should_apply = match name::get(eligible.referent_address) {
                Ok(existing)
                    if !existing.is_empty()
                        && !name::is_auto_generated(eligible.referent_address) =>
                {
                    summary.preserved += 1;
                    false
                }
                Ok(_) => true,
                Err(error) if error.category == ErrorCategory::NotFound => true,
                Err(_) => {
                    summary.failures += 1;
                    false
                }
            };
            if should_apply {
                match name::set(eligible.referent_address, &source.name) {
                    Ok(()) => summary.names += 1,
                    Err(_) => summary.failures += 1,
                }
            }
        }

        if !source.declaration.is_empty() {
            match types::retrieve(eligible.referent_address) {
                Ok(_) => summary.preserved += 1,
                Err(error) if error.category == ErrorCategory::NotFound => {
                    match types::TypeInfo::from_declaration(&source.declaration)
                        .and_then(|value| value.apply(eligible.referent_address))
                    {
                        Ok(()) => summary.types += 1,
                        Err(_) => summary.failures += 1,
                    }
                }
                Err(_) => summary.failures += 1,
            }
        }
    }
    summary
}

fn referent_metadata_report(
    baseline: &ReferentMetadataManifest,
    current: &[FunctionRecord],
    comparison: &ReferentMetadataComparison,
) -> String {
    format!(
        "Diaphora exact referent metadata comparison\nBaseline functions: {}\nCurrent functions: {}\nUnique function matches: {}\nAmbiguous baseline functions: {}\nUnmatched baseline functions: {}\nReferent records: {}\nEligible referent records: {}\nRecords with unmatched functions: {}\nInstruction guard failures: {}\nReference guard failures: {}",
        baseline.functions.len(),
        current.len(),
        comparison.functions.matches.len(),
        comparison.functions.ambiguous,
        comparison.functions.unmatched,
        baseline.referents.len(),
        comparison.eligible.len(),
        comparison.unmatched_functions,
        comparison.instruction_guard_failures,
        comparison.reference_guard_failures,
    )
}

fn compare_pseudocode_comments(
    baseline: &PseudocodeCommentManifest,
    current: &[FunctionRecord],
) -> Result<PseudocodeCommentComparison> {
    let functions = compare_records(&baseline.functions, current);
    let baseline_by_ordinal: HashMap<_, _> = baseline
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.ordinal, index))
        .collect();
    let current_by_baseline: HashMap<_, _> = functions
        .matches
        .iter()
        .map(|matched| (matched.baseline, matched.current))
        .collect();
    let mut address_cache: HashMap<usize, Vec<u64>> = HashMap::new();
    let mut eligible = Vec::new();
    let mut unmatched_functions = 0usize;
    let mut guard_failures = 0usize;

    for (comment_index, comment) in baseline.comments.iter().enumerate() {
        let Some(baseline_index) = baseline_by_ordinal.get(&comment.function_ordinal) else {
            unmatched_functions += 1;
            continue;
        };
        let Some(current_index) = current_by_baseline.get(baseline_index).copied() else {
            unmatched_functions += 1;
            continue;
        };
        let target_function = &current[current_index];
        let target_address =
            match apply_relative_offset(target_function.address, comment.function_offset) {
                Ok(address) => address,
                Err(_) => {
                    guard_failures += 1;
                    continue;
                }
            };
        if let std::collections::hash_map::Entry::Vacant(entry) = address_cache.entry(current_index)
        {
            let mut addresses = function::code_addresses(target_function.address)?;
            addresses.sort_unstable();
            entry.insert(addresses);
        }
        if address_cache[&current_index].get(comment.instruction_ordinal) != Some(&target_address) {
            guard_failures += 1;
            continue;
        }
        let fingerprint = extract_instruction_fingerprint(target_address)?;
        if fingerprint.size != comment.size
            || fingerprint.mnemonic != comment.mnemonic
            || fingerprint.relocation_md5 != comment.relocation_md5
        {
            guard_failures += 1;
            continue;
        }
        eligible.push(EligiblePseudocodeComment {
            comment_index,
            function_address: target_function.address,
            comment_address: target_address,
        });
    }

    Ok(PseudocodeCommentComparison {
        functions,
        eligible,
        unmatched_functions,
        guard_failures,
    })
}

fn apply_pseudocode_comments(
    baseline: &PseudocodeCommentManifest,
    comparison: &PseudocodeCommentComparison,
) -> PseudocodeCommentApplySummary {
    let mut summary = PseudocodeCommentApplySummary::default();
    let mut functions = HashMap::new();
    let mut failed_functions = HashSet::new();
    let mut modified_functions = HashSet::new();

    for eligible in &comparison.eligible {
        if failed_functions.contains(&eligible.function_address) {
            summary.failures += 1;
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) =
            functions.entry(eligible.function_address)
        {
            match decompiler::decompile(eligible.function_address) {
                Ok(decompiled) => {
                    entry.insert(decompiled);
                }
                Err(_) => {
                    failed_functions.insert(eligible.function_address);
                    summary.failures += 1;
                    continue;
                }
            }
        }
        let decompiled = &functions[&eligible.function_address];
        let source = &baseline.comments[eligible.comment_index];
        let position = to_public_position(source.position);
        match decompiled.get_comment(eligible.comment_address, position) {
            Ok(existing) if !existing.is_empty() => summary.preserved += 1,
            Ok(_) => match decompiled.set_comment(eligible.comment_address, &source.text, position)
            {
                Ok(()) => {
                    summary.comments += 1;
                    modified_functions.insert(eligible.function_address);
                }
                Err(_) => summary.failures += 1,
            },
            Err(_) => summary.failures += 1,
        }
    }

    for function_address in modified_functions {
        match functions[&function_address].save_comments() {
            Ok(()) => summary.saved_functions += 1,
            Err(_) => summary.failures += 1,
        }
    }
    summary
}

fn pseudocode_comment_report(
    baseline: &PseudocodeCommentManifest,
    current: &[FunctionRecord],
    comparison: &PseudocodeCommentComparison,
) -> String {
    format!(
        "Diaphora exact pseudocode comment comparison\nBaseline functions: {}\nCurrent functions: {}\nUnique function matches: {}\nAmbiguous baseline functions: {}\nUnmatched baseline functions: {}\nPseudocode comment records: {}\nEligible comment records: {}\nRecords with unmatched functions: {}\nInstruction guard failures: {}",
        baseline.functions.len(),
        current.len(),
        comparison.functions.matches.len(),
        comparison.functions.ambiguous,
        comparison.functions.unmatched,
        baseline.comments.len(),
        comparison.eligible.len(),
        comparison.unmatched_functions,
        comparison.guard_failures,
    )
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
        Mode::ExportInstructionMetadata => {
            let manifest = extract_instruction_metadata_manifest()?;
            std::fs::write(
                &options.manifest,
                format_instruction_metadata_manifest(&manifest),
            )
            .map_err(|error| {
                Error::internal(format!(
                    "failed writing instruction metadata manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            println!(
                "Exported {} instruction metadata records for {} functions to {}",
                manifest.instructions.len(),
                manifest.functions.len(),
                options.manifest
            );
        }
        Mode::CompareInstructionMetadata => {
            let text = std::fs::read_to_string(&options.manifest).map_err(|error| {
                Error::not_found(format!(
                    "failed reading instruction metadata manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            let baseline = parse_instruction_metadata_manifest(&text)?;
            let current = extract_manifest()?;
            let comparison = compare_instruction_metadata(&baseline, &current)?;
            println!(
                "{}",
                instruction_metadata_report(&baseline, &current, &comparison)
            );
            if options.apply {
                let applied = apply_instruction_metadata(&baseline, &comparison);
                if applied.comments + applied.repeatable_comments + applied.forced_operands > 0 {
                    database::save()?;
                }
                println!(
                    "Ordinary comments applied: {}\nRepeatable comments applied: {}\nForced operands applied: {}\nExisting metadata preserved: {}\nMutation failures: {}",
                    applied.comments,
                    applied.repeatable_comments,
                    applied.forced_operands,
                    applied.preserved,
                    applied.failures,
                );
            }
        }
        Mode::ExportReferentMetadata => {
            let manifest = extract_referent_metadata_manifest()?;
            std::fs::write(
                &options.manifest,
                format_referent_metadata_manifest(&manifest),
            )
            .map_err(|error| {
                Error::internal(format!(
                    "failed writing referent metadata manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            println!(
                "Exported {} unique referent metadata records for {} functions to {}",
                manifest.referents.len(),
                manifest.functions.len(),
                options.manifest
            );
        }
        Mode::CompareReferentMetadata => {
            let text = std::fs::read_to_string(&options.manifest).map_err(|error| {
                Error::not_found(format!(
                    "failed reading referent metadata manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            let baseline = parse_referent_metadata_manifest(&text)?;
            let current = extract_manifest()?;
            let comparison = compare_referent_metadata(&baseline, &current)?;
            println!(
                "{}",
                referent_metadata_report(&baseline, &current, &comparison)
            );
            if options.apply {
                let applied = apply_referent_metadata(&baseline, &comparison);
                if applied.names + applied.types > 0 {
                    database::save()?;
                }
                println!(
                    "Referent names applied: {}\nReferent types applied: {}\nExisting metadata preserved: {}\nMutation failures: {}",
                    applied.names, applied.types, applied.preserved, applied.failures,
                );
            }
        }
        Mode::ExportPseudocodeComments => {
            let manifest = extract_pseudocode_comment_manifest()?;
            std::fs::write(
                &options.manifest,
                format_pseudocode_comment_manifest(&manifest),
            )
            .map_err(|error| {
                Error::internal(format!(
                    "failed writing pseudocode comment manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            println!(
                "Exported {} exact pseudocode comment records for {} functions to {}",
                manifest.comments.len(),
                manifest.functions.len(),
                options.manifest
            );
        }
        Mode::ComparePseudocodeComments => {
            let text = std::fs::read_to_string(&options.manifest).map_err(|error| {
                Error::not_found(format!(
                    "failed reading pseudocode comment manifest '{}': {error}",
                    options.manifest
                ))
            })?;
            let baseline = parse_pseudocode_comment_manifest(&text)?;
            let current = extract_manifest()?;
            let comparison = compare_pseudocode_comments(&baseline, &current)?;
            println!(
                "{}",
                pseudocode_comment_report(&baseline, &current, &comparison)
            );
            if options.apply {
                let applied = apply_pseudocode_comments(&baseline, &comparison);
                if applied.comments > 0 {
                    database::save()?;
                }
                println!(
                    "Pseudocode comments applied: {}\nExisting locations preserved: {}\nFunctions with comments saved: {}\nMutation failures: {}",
                    applied.comments, applied.preserved, applied.saved_functions, applied.failures,
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
                "<input> --export <manifest> | <input> --compare <manifest> [--apply] | <input> --export-instruction-metadata <manifest> | <input> --compare-instruction-metadata <manifest> [--apply] | <input> --export-referent-metadata <manifest> | <input> --compare-referent-metadata <manifest> [--apply] | <input> --export-pseudocode-comments <manifest> | <input> --compare-pseudocode-comments <manifest> [--apply]",
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
#[allow(dead_code)]
pub(crate) mod tests {
    use super::*;
    use idax::analysis;

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

    struct RuntimeFixture {
        root: std::path::PathBuf,
        input: std::path::PathBuf,
    }

    impl RuntimeFixture {
        fn copy_from(source: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "idax-diaphora-referent-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            let input = root.join("fixture");
            std::fs::copy(source, &input).unwrap();
            Self { root, input }
        }
    }

    impl Drop for RuntimeFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    struct RuntimeSession {
        open: bool,
    }

    impl RuntimeSession {
        fn close(&mut self, save: bool) {
            database::close(save).unwrap();
            self.open = false;
        }

        fn reopen(&mut self, path: &str) {
            database::open(path, true).unwrap();
            analysis::wait().unwrap();
            self.open = true;
        }
    }

    impl Drop for RuntimeSession {
        fn drop(&mut self) {
            if self.open {
                let _ = database::close(false);
            }
        }
    }

    fn runtime_candidate(
        manifest: &ReferentMetadataManifest,
        comparison: &ReferentMetadataComparison,
        require_name: bool,
        require_type: bool,
        excluded: Option<u64>,
    ) -> Option<EligibleReferentMetadata> {
        comparison.eligible.iter().copied().find(|eligible| {
            let source = &manifest.referents[eligible.metadata_index];
            excluded != Some(eligible.referent_address)
                && (!require_name || !source.name.is_empty())
                && (!require_type || !source.declaration.is_empty())
        })
    }

    fn remove_runtime_name(address: u64) {
        match name::get(address) {
            Ok(_) => name::remove(address).unwrap(),
            Err(error) => assert_eq!(error.category, ErrorCategory::NotFound),
        }
    }

    fn remove_runtime_type(address: u64) {
        match types::retrieve(address) {
            Ok(_) => types::remove_type(address).unwrap(),
            Err(error) => assert_eq!(error.category, ErrorCategory::NotFound),
        }
    }

    fn assert_runtime_type(address: u64, expected_declaration: &str) {
        let actual = types::retrieve(address).unwrap().to_string().unwrap();
        let expected = types::TypeInfo::from_declaration(expected_declaration)
            .unwrap()
            .to_string()
            .unwrap();
        assert_eq!(actual, expected);
    }

    pub(crate) fn initialized_referent_runtime_applies_preserves_reopens_and_rejects_ambiguity() {
        let source = std::env::var("IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE")
            .expect("set IDAX_DIAPHORA_REFERENT_RUNTIME_FIXTURE");
        let fixture = RuntimeFixture::copy_from(&source);
        let input = fixture.input.to_str().unwrap();

        eprintln!("[diaphora-referent-rust] init");
        database::init().unwrap();
        eprintln!("[diaphora-referent-rust] open");
        database::open(input, true).unwrap();
        eprintln!("[diaphora-referent-rust] wait");
        analysis::wait().unwrap();
        let mut session = RuntimeSession { open: true };

        eprintln!("[diaphora-referent-rust] extract");
        let baseline = extract_referent_metadata_manifest().unwrap();
        let encoded = format_referent_metadata_manifest(&baseline);
        let parsed = parse_referent_metadata_manifest(&encoded).unwrap();
        assert_eq!(format_referent_metadata_manifest(&parsed), encoded);
        let current = extract_manifest().unwrap();
        let initial = compare_referent_metadata(&baseline, &current).unwrap();
        assert!(!initial.eligible.is_empty());
        assert_eq!(initial.instruction_guard_failures, 0);
        assert_eq!(initial.reference_guard_failures, 0);

        let mut tampered = baseline.clone();
        let tampered_index = initial.eligible[0].metadata_index;
        let replacement = if &tampered.referents[tampered_index].relocation_md5[0..1] == "0" {
            "1"
        } else {
            "0"
        };
        tampered.referents[tampered_index]
            .relocation_md5
            .replace_range(0..1, replacement);
        let rejected = compare_referent_metadata(&tampered, &current).unwrap();
        assert_eq!(rejected.eligible.len() + 1, initial.eligible.len());
        assert_eq!(rejected.instruction_guard_failures, 1);
        assert_eq!(rejected.reference_guard_failures, 0);

        let ambiguous = initial
            .eligible
            .iter()
            .copied()
            .find(|eligible| baseline.referents[eligible.metadata_index].kind == ReferentKind::Data)
            .expect("fixture needs one eligible data referent");
        let alternate = ambiguous.referent_address + 1;
        xref::add_data(
            ambiguous.instruction_address,
            alternate,
            xref::DataType::Informational,
        )
        .unwrap();
        let rejected = compare_referent_metadata(&baseline, &current).unwrap();
        assert_eq!(rejected.eligible.len() + 1, initial.eligible.len());
        assert_eq!(rejected.instruction_guard_failures, 0);
        assert_eq!(rejected.reference_guard_failures, 1);
        xref::remove_data(ambiguous.instruction_address, alternate).unwrap();

        let absent_name = runtime_candidate(&baseline, &initial, true, false, None)
            .expect("fixture needs a named referent");
        let preserved_name = runtime_candidate(
            &baseline,
            &initial,
            true,
            false,
            Some(absent_name.referent_address),
        )
        .expect("fixture needs a second named referent");
        let absent_type = runtime_candidate(&baseline, &initial, false, true, None)
            .expect("fixture needs a typed referent");
        let preserved_type = runtime_candidate(
            &baseline,
            &initial,
            false,
            true,
            Some(absent_type.referent_address),
        )
        .expect("fixture needs a second typed referent");

        remove_runtime_name(absent_name.referent_address);
        remove_runtime_type(absent_type.referent_address);
        const PRESERVED_NAME: &str = "idax_phase53_rust_target_owned";
        const PRESERVED_DECLARATION: &str = "unsigned char __idax_diaphora_referent;";
        name::set(preserved_name.referent_address, PRESERVED_NAME).unwrap();
        types::TypeInfo::from_declaration(PRESERVED_DECLARATION)
            .unwrap()
            .apply(preserved_type.referent_address)
            .unwrap();

        let comparison = compare_referent_metadata(&baseline, &current).unwrap();
        let applied = apply_referent_metadata(&baseline, &comparison);
        assert!(applied.names > 0);
        assert!(applied.types > 0);
        assert!(applied.preserved >= 2);
        assert_eq!(applied.failures, 0);
        let absent_name_source = &baseline.referents[absent_name.metadata_index];
        let absent_type_source = &baseline.referents[absent_type.metadata_index];
        assert_eq!(
            name::get(absent_name.referent_address).unwrap(),
            absent_name_source.name
        );
        assert_runtime_type(
            absent_type.referent_address,
            &absent_type_source.declaration,
        );
        assert_eq!(
            name::get(preserved_name.referent_address).unwrap(),
            PRESERVED_NAME
        );
        assert_runtime_type(preserved_type.referent_address, PRESERVED_DECLARATION);

        session.close(true);
        session.reopen(input);
        assert_eq!(
            name::get(absent_name.referent_address).unwrap(),
            absent_name_source.name
        );
        assert_runtime_type(
            absent_type.referent_address,
            &absent_type_source.declaration,
        );
        assert_eq!(
            name::get(preserved_name.referent_address).unwrap(),
            PRESERVED_NAME
        );
        assert_runtime_type(preserved_type.referent_address, PRESERVED_DECLARATION);
        let reopened_current = extract_manifest().unwrap();
        let reopened = compare_referent_metadata(&baseline, &reopened_current).unwrap();
        let reapplied = apply_referent_metadata(&baseline, &reopened);
        assert_eq!(reapplied.names, 0);
        assert_eq!(reapplied.types, 0);
        assert_eq!(reapplied.failures, 0);
        session.close(false);
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
    fn instruction_metadata_manifest_roundtrip_is_byte_stable() {
        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let expected = InstructionMetadataManifest {
            functions: vec![function],
            instructions: vec![InstructionMetadataRecord {
                function_ordinal: 0,
                instruction_ordinal: 2,
                function_offset: 7,
                size: 5,
                full_md5: "c".repeat(32),
                relocation_md5: "d".repeat(32),
                mnemonic: "mov".to_owned(),
                comment: "ordinary\tcomment".to_owned(),
                repeatable_comment: "repeatable\nλ".to_owned(),
                forced_operands: vec![
                    ForcedOperandMetadata {
                        index: 0,
                        text: "forced one".to_owned(),
                    },
                    ForcedOperandMetadata {
                        index: 2,
                        text: "forced λ".to_owned(),
                    },
                ],
            }],
        };
        let encoded = format_instruction_metadata_manifest(&expected);
        assert!(encoded.starts_with(&format!("{INSTRUCTION_METADATA_HEADER}\nF\t")));
        let expected_instruction_line = concat!(
            "I\t0\t2\t7\t5\tcccccccccccccccccccccccccccccccc\t",
            "dddddddddddddddddddddddddddddddd\t6d6f76\t",
            "6f7264696e61727909636f6d6d656e74\t72657065617461626c650acebb\t",
            "303a31303a666f72636564206f6e65323a393a666f7263656420cebb\n",
        );
        assert!(encoded.contains(expected_instruction_line));
        let decoded = parse_instruction_metadata_manifest(&encoded).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(format_instruction_metadata_manifest(&decoded), encoded);
    }

    #[test]
    fn instruction_metadata_decoder_rejects_malformed_or_duplicate_operands() {
        assert!(parse_forced_operands("0:0:").is_err());
        assert!(parse_forced_operands("0:2:x").is_err());
        assert!(parse_forced_operands("0:1:\0").is_err());
        assert!(parse_forced_operands("1:1:x1:1:y").is_err());
        assert!(parse_forced_operands("2:1:x1:1:y").is_err());

        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let manifest = InstructionMetadataManifest {
            functions: vec![function],
            instructions: vec![InstructionMetadataRecord {
                function_ordinal: 0,
                instruction_ordinal: 0,
                function_offset: 0,
                size: 1,
                full_md5: "c".repeat(32),
                relocation_md5: "d".repeat(32),
                mnemonic: "ret".to_owned(),
                comment: "comment".to_owned(),
                repeatable_comment: String::new(),
                forced_operands: Vec::new(),
            }],
        };
        let encoded = format_instruction_metadata_manifest(&manifest);
        let record_start = encoded.find("I\t").unwrap();
        let duplicate = format!("{encoded}{}", &encoded[record_start..]);
        assert!(parse_instruction_metadata_manifest(&duplicate).is_err());

        let mut unknown_function = encoded.clone();
        unknown_function.replace_range(record_start..record_start + 4, "I\t1\t");
        assert!(parse_instruction_metadata_manifest(&unknown_function).is_err());

        let mut invalid_hash = encoded.clone();
        let hash_start = invalid_hash[record_start..]
            .find(&"c".repeat(32))
            .map(|offset| record_start + offset)
            .unwrap();
        invalid_hash.replace_range(hash_start..hash_start + 1, "g");
        assert!(parse_instruction_metadata_manifest(&invalid_hash).is_err());

        let mut empty_metadata = manifest.clone();
        empty_metadata.instructions[0].comment.clear();
        assert!(
            parse_instruction_metadata_manifest(&format_instruction_metadata_manifest(
                &empty_metadata
            ))
            .is_err()
        );

        let mut nul_metadata = manifest;
        nul_metadata.instructions[0].comment = "x\0y".to_owned();
        assert!(
            parse_instruction_metadata_manifest(&format_instruction_metadata_manifest(
                &nul_metadata
            ))
            .is_err()
        );
    }

    #[test]
    fn referent_metadata_manifest_is_cpp_byte_compatible() {
        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let expected = ReferentMetadataManifest {
            functions: vec![function],
            referents: vec![ReferentMetadataRecord {
                function_ordinal: 0,
                instruction_ordinal: 2,
                function_offset: 7,
                size: 5,
                full_md5: "c".repeat(32),
                relocation_md5: "d".repeat(32),
                mnemonic: "mov".to_owned(),
                kind: ReferentKind::Data,
                name: "global_λ".to_owned(),
                declaration: "int __idax_diaphora_referent;".to_owned(),
            }],
        };
        let encoded = format_referent_metadata_manifest(&expected);
        assert!(encoded.starts_with(&format!("{REFERENT_METADATA_HEADER}\nF\t")));
        assert!(encoded.contains(concat!(
            "R\t0\t2\t7\t5\tcccccccccccccccccccccccccccccccc\t",
            "dddddddddddddddddddddddddddddddd\t6d6f76\tdata\t",
            "676c6f62616c5fcebb\t696e74205f5f696461785f64696170686f72615f",
            "7265666572656e743b\n",
        )));
        let decoded = parse_referent_metadata_manifest(&encoded).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(format_referent_metadata_manifest(&decoded), encoded);
    }

    #[test]
    fn referent_metadata_decoder_rejects_ambiguous_records() {
        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let manifest = ReferentMetadataManifest {
            functions: vec![function],
            referents: vec![ReferentMetadataRecord {
                function_ordinal: 0,
                instruction_ordinal: 0,
                function_offset: 0,
                size: 1,
                full_md5: "c".repeat(32),
                relocation_md5: "d".repeat(32),
                mnemonic: "ret".to_owned(),
                kind: ReferentKind::Code,
                name: "callee".to_owned(),
                declaration: String::new(),
            }],
        };
        let encoded = format_referent_metadata_manifest(&manifest);
        let record_start = encoded.find("R\t").unwrap();
        let duplicate = format!("{encoded}{}", &encoded[record_start..]);
        assert!(parse_referent_metadata_manifest(&duplicate).is_err());

        let mut unknown_function = encoded.clone();
        unknown_function.replace_range(record_start..record_start + 4, "R\t1\t");
        assert!(parse_referent_metadata_manifest(&unknown_function).is_err());

        let mut unknown_kind = encoded.clone();
        let kind_start = unknown_kind[record_start..]
            .find("\tcode\t")
            .map(|offset| record_start + offset)
            .unwrap();
        unknown_kind.replace_range(kind_start..kind_start + 6, "\tother\t");
        assert!(parse_referent_metadata_manifest(&unknown_kind).is_err());

        let mut invalid_hash = encoded.clone();
        let hash_start = invalid_hash[record_start..]
            .find(&"c".repeat(32))
            .map(|offset| record_start + offset)
            .unwrap();
        invalid_hash.replace_range(hash_start..hash_start + 1, "g");
        assert!(parse_referent_metadata_manifest(&invalid_hash).is_err());

        let mut empty = manifest.clone();
        empty.referents[0].name.clear();
        assert!(
            parse_referent_metadata_manifest(&format_referent_metadata_manifest(&empty)).is_err()
        );
        let mut nul = manifest;
        nul.referents[0].name = "x\0y".to_owned();
        assert!(
            parse_referent_metadata_manifest(&format_referent_metadata_manifest(&nul)).is_err()
        );
    }

    #[test]
    fn unique_referent_deduplicates_same_target_and_rejects_multiple_targets() {
        let mut references = vec![
            xref::Reference {
                from: 0x100,
                to: 0x101,
                is_code: true,
                ref_type: xref::ReferenceType::Flow,
                user_defined: false,
            },
            xref::Reference {
                from: 0x100,
                to: 0x200,
                is_code: true,
                ref_type: xref::ReferenceType::CallNear,
                user_defined: false,
            },
            xref::Reference {
                from: 0x100,
                to: 0x300,
                is_code: false,
                ref_type: xref::ReferenceType::Read,
                user_defined: false,
            },
            xref::Reference {
                from: 0x100,
                to: 0x300,
                is_code: false,
                ref_type: xref::ReferenceType::Offset,
                user_defined: true,
            },
        ];
        assert_eq!(
            unique_referent(&references, ReferentKind::Code),
            Some(0x200)
        );
        assert_eq!(
            unique_referent(&references, ReferentKind::Data),
            Some(0x300)
        );
        references.push(xref::Reference {
            from: 0x100,
            to: 0x301,
            is_code: false,
            ref_type: xref::ReferenceType::Write,
            user_defined: false,
        });
        assert_eq!(unique_referent(&references, ReferentKind::Data), None);
        references.push(xref::Reference {
            from: 0x100,
            to: 0x201,
            is_code: true,
            ref_type: xref::ReferenceType::JumpNear,
            user_defined: false,
        });
        assert_eq!(unique_referent(&references, ReferentKind::Code), None);
    }

    #[test]
    fn pseudocode_comment_manifest_preserves_multiple_locations_byte_stably() {
        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let first = PseudocodeCommentRecord {
            function_ordinal: 0,
            instruction_ordinal: 2,
            function_offset: 7,
            size: 5,
            full_md5: "c".repeat(32),
            relocation_md5: "d".repeat(32),
            mnemonic: "mov".to_owned(),
            position: PseudocodePosition::Default,
            text: "default\tcomment".to_owned(),
        };
        let mut second = first.clone();
        second.position = PseudocodePosition::Semicolon;
        second.text = "semicolon\nλ".to_owned();
        let expected = PseudocodeCommentManifest {
            functions: vec![function],
            comments: vec![first, second],
        };
        let encoded = format_pseudocode_comment_manifest(&expected);
        assert!(encoded.starts_with(&format!("{PSEUDOCODE_COMMENT_HEADER}\nF\t")));
        assert!(encoded.contains(concat!(
            "P\t0\t2\t7\t5\tcccccccccccccccccccccccccccccccc\t",
            "dddddddddddddddddddddddddddddddd\t6d6f76\tdefault\t0\t",
            "64656661756c7409636f6d6d656e74\n",
        )));
        assert!(encoded.contains("\tsemicolon\t0\t73656d69636f6c6f6e0acebb\n"));
        let decoded = parse_pseudocode_comment_manifest(&encoded).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.comments[0].instruction_ordinal, 2);
        assert_eq!(decoded.comments[1].instruction_ordinal, 2);
        assert_ne!(decoded.comments[0].position, decoded.comments[1].position);
        assert_eq!(format_pseudocode_comment_manifest(&decoded), encoded);
    }

    #[test]
    fn pseudocode_comment_decoder_rejects_malformed_locations_and_records() {
        assert_eq!(
            parse_pseudocode_position("argument", 63).unwrap(),
            PseudocodePosition::Argument(63)
        );
        assert!(parse_pseudocode_position("argument", 64).is_err());
        assert_eq!(
            parse_pseudocode_position("switch-case", -0x1fff_ffff).unwrap(),
            PseudocodePosition::SwitchCase(-0x1fff_ffff)
        );
        assert_eq!(
            parse_pseudocode_position("switch-case", 0x1fff_ffff).unwrap(),
            PseudocodePosition::SwitchCase(0x1fff_ffff)
        );
        assert!(parse_pseudocode_position("switch-case", -0x2000_0000).is_err());
        assert!(parse_pseudocode_position("switch-case", 0x2000_0000).is_err());
        assert!(parse_pseudocode_position("semicolon", 1).is_err());
        assert!(parse_pseudocode_position("unknown", 0).is_err());

        let mut function = record(0, 0x123, "a", "b");
        function.address = u64::MAX;
        let manifest = PseudocodeCommentManifest {
            functions: vec![function],
            comments: vec![PseudocodeCommentRecord {
                function_ordinal: 0,
                instruction_ordinal: 0,
                function_offset: 0,
                size: 1,
                full_md5: "c".repeat(32),
                relocation_md5: "d".repeat(32),
                mnemonic: "ret".to_owned(),
                position: PseudocodePosition::Default,
                text: "comment".to_owned(),
            }],
        };
        let encoded = format_pseudocode_comment_manifest(&manifest);
        let record_start = encoded.find("P\t").unwrap();
        let duplicate = format!("{encoded}{}", &encoded[record_start..]);
        assert!(parse_pseudocode_comment_manifest(&duplicate).is_err());

        let mut unknown_function = encoded.clone();
        unknown_function.replace_range(record_start..record_start + 4, "P\t1\t");
        assert!(parse_pseudocode_comment_manifest(&unknown_function).is_err());

        let mut invalid_hash = encoded.clone();
        let hash_start = invalid_hash[record_start..]
            .find(&"c".repeat(32))
            .map(|offset| record_start + offset)
            .unwrap();
        invalid_hash.replace_range(hash_start..hash_start + 1, "g");
        assert!(parse_pseudocode_comment_manifest(&invalid_hash).is_err());

        let mut empty = manifest.clone();
        empty.comments[0].text.clear();
        assert!(
            parse_pseudocode_comment_manifest(&format_pseudocode_comment_manifest(&empty)).is_err()
        );
        let mut nul = manifest;
        nul.comments[0].text = "x\0y".to_owned();
        assert!(
            parse_pseudocode_comment_manifest(&format_pseudocode_comment_manifest(&nul)).is_err()
        );
    }

    #[test]
    fn signed_instruction_offsets_roundtrip() {
        assert_eq!(relative_offset(0x120, 0x100).unwrap(), 0x20);
        assert_eq!(relative_offset(0xf0, 0x100).unwrap(), -0x10);
        assert_eq!(apply_relative_offset(0x100, 0x20).unwrap(), 0x120);
        assert_eq!(apply_relative_offset(0x100, -0x10).unwrap(), 0xf0);
        assert!(apply_relative_offset(0, -1).is_err());
        assert!(apply_relative_offset(u64::MAX, 1).is_err());
        assert_eq!(apply_relative_offset(1_u64 << 63, i64::MIN).unwrap(), 0);
        assert!(relative_offset(u64::MAX, 0).is_err());
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
