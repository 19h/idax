use idax::{loader, Error, Result};

#[derive(Debug, Clone)]
struct XbinHeader {
    version: u16,
    flags: u16,
    segment_count: u16,
    entry_count: u16,
    base_address: u32,
}

#[derive(Debug, Clone)]
struct XbinSegmentEntry {
    name: String,
    file_offset: u32,
    virtual_address: u32,
    raw_size: u32,
    virtual_size: u32,
    flags: u32,
}

const SEG_EXECUTE: u32 = 0x01;
const SEG_WRITE: u32 = 0x02;
const SEG_READ: u32 = 0x04;
const SEG_BSS: u32 = 0x08;
const SEG_EXTERN: u32 = 0x10;

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::validation("truncated u16 field"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::validation("truncated u32 field"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_header(data: &[u8]) -> Result<XbinHeader> {
    if data.len() < 0x10 {
        return Err(Error::validation("file too small for XBIN header"));
    }
    if data.get(0..4) != Some(b"XBIN") {
        return Err(Error::unsupported("input is not an XBIN file"));
    }
    Ok(XbinHeader {
        version: read_u16_le(data, 0x04)?,
        flags: read_u16_le(data, 0x06)?,
        segment_count: read_u16_le(data, 0x08)?,
        entry_count: read_u16_le(data, 0x0A)?,
        base_address: read_u32_le(data, 0x0C)?,
    })
}

fn parse_segments(data: &[u8], header: &XbinHeader) -> Result<Vec<XbinSegmentEntry>> {
    let mut segments = Vec::with_capacity(header.segment_count as usize);
    let table_start = 0x10usize;
    let stride = 24usize;

    for index in 0..header.segment_count as usize {
        let offset = table_start + index * stride;
        let entry = data
            .get(offset..offset + stride)
            .ok_or_else(|| Error::validation("truncated XBIN segment table"))?;
        let name_end = entry[0..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&entry[0..name_end]).to_string();
        segments.push(XbinSegmentEntry {
            name: if name.is_empty() {
                format!("seg_{index}")
            } else {
                name
            },
            file_offset: u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]),
            virtual_address: u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]),
            raw_size: u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]),
            virtual_size: u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]),
            flags: read_u32_le(entry, 20)?,
        });
    }

    Ok(segments)
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn permission_text(flags: u32) -> String {
    let r = if flags & SEG_READ != 0 { 'R' } else { '-' };
    let w = if flags & SEG_WRITE != 0 { 'W' } else { '-' };
    let x = if flags & SEG_EXECUTE != 0 { 'X' } else { '-' };
    format!("{r}{w}{x}")
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <xbin_file> [--emit-plan <output_file>]",
            args[0]
        );
        return Err(Error::validation("missing xbin_file argument"));
    }

    let input_path = &args[1];
    let data = std::fs::read(input_path)
        .map_err(|err| Error::internal(format!("failed reading '{input_path}': {err}")))?;
    let header = parse_header(&data)?;
    let segments = parse_segments(&data, &header)?;

    let mut report = String::new();
    report.push_str("XBIN advanced loader plan (Rust adaptation)\n");
    report.push_str(&format!("input: {input_path}\n"));
    report.push_str(&format!("version: {}\n", header.version));
    report.push_str(&format!("flags: 0x{:04x}\n", header.flags));
    report.push_str(&format!("segments: {}\n", header.segment_count));
    report.push_str(&format!("entries: {}\n", header.entry_count));
    report.push_str(&format!("base: 0x{:x}\n\n", header.base_address));

    report.push_str("Segments\n");
    report.push_str("Idx  Name      Start       End         RawSize    VirtSize   Perm  Kind\n");
    report.push_str("----------------------------------------------------------------------------\n");

    for (index, segment) in segments.iter().enumerate() {
        let start = header.base_address as u64 + segment.virtual_address as u64;
        let end = start + segment.virtual_size as u64;
        let kind = if segment.flags & SEG_BSS != 0 {
            "BSS"
        } else if segment.flags & SEG_EXTERN != 0 {
            "EXTERN"
        } else if segment.flags & SEG_EXECUTE != 0 {
            "CODE"
        } else {
            "DATA"
        };

        report.push_str(&format!(
            "{index:>3}  {:<8}  0x{start:08x}  0x{end:08x}  {:>8}  {:>8}  {:<4}  {kind}\n",
            segment.name,
            segment.raw_size,
            segment.virtual_size,
            permission_text(segment.flags),
        ));
    }

    let mut overlap_count = 0usize;
    for i in 0..segments.len() {
        for j in i + 1..segments.len() {
            let a_start = header.base_address as u64 + segments[i].virtual_address as u64;
            let a_end = a_start + segments[i].virtual_size as u64;
            let b_start = header.base_address as u64 + segments[j].virtual_address as u64;
            let b_end = b_start + segments[j].virtual_size as u64;
            if overlaps(a_start, a_end, b_start, b_end) {
                overlap_count += 1;
                report.push_str(&format!(
                    "warning: overlap {}({:#x}-{:#x}) with {}({:#x}-{:#x})\n",
                    segments[i].name, a_start, a_end, segments[j].name, b_start, b_end
                ));
            }
        }
    }

    let mut load_flags = loader::LoadFlags {
        create_segments: true,
        rename_entries: true,
        load_all_segments: true,
        ..loader::LoadFlags::default()
    };
    if header.flags & 0x0002 != 0 {
        load_flags.reload = true;
    }

    if let Ok(encoded) = loader::encode_load_flags(load_flags)
        && let Ok(decoded) = loader::decode_load_flags(encoded)
    {
        report.push_str(&format!(
            "\nload_flags: raw=0x{encoded:04x} create_segments={} rename_entries={} reload={}\n",
            decoded.create_segments, decoded.rename_entries, decoded.reload
        ));
    }

    report.push_str(&format!("segment_overlaps_detected={overlap_count}\n"));

    if let Some(index) = args.iter().position(|arg| arg == "--emit-plan") {
        let output_path = args
            .get(index + 1)
            .ok_or_else(|| Error::validation("--emit-plan requires an output path"))?;
        std::fs::write(output_path, &report).map_err(|err| {
            Error::internal(format!("failed writing '{output_path}': {err}"))
        })?;
    } else {
        print!("{report}");
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", error.message);
        std::process::exit(1);
    }
}
