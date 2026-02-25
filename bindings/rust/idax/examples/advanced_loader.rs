mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{loader, segment, Error, Result};

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

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<xbin_file>");
        return Err(Error::validation("missing xbin_file argument"));
    }

    let input_path = &args[1];
    let data = std::fs::read(input_path)
        .map_err(|err| Error::internal(format!("failed reading '{input_path}': {err}")))?;
    
    let header = parse_header(&data)?;
    let segments = parse_segments(&data, &header)?;

    // Validate for overlaps
    for i in 0..segments.len() {
        for j in i + 1..segments.len() {
            let a_start = header.base_address as u64 + segments[i].virtual_address as u64;
            let a_end = a_start + segments[i].virtual_size as u64;
            let b_start = header.base_address as u64 + segments[j].virtual_address as u64;
            let b_end = b_start + segments[j].virtual_size as u64;
            if overlaps(a_start, a_end, b_start, b_end) {
                return Err(Error::validation(format!(
                    "segment overlap detected: {} and {}",
                    segments[i].name, segments[j].name
                )));
            }
        }
    }

    // Open an empty database session (we will manually load everything)
    let _session = DatabaseSession::open(input_path, false)?;

    // Clear auto-created segments to emulate full control over the database layout.
    for seg in segment::all().collect::<Vec<_>>() {
        segment::remove(seg.start())?;
    }

    // Since this is a generic loader, default to metapc
    loader::set_processor("metapc")?;
    loader::create_filename_comment()?;

    // Map segments
    for seg_entry in &segments {
        let start = header.base_address as u64 + seg_entry.virtual_address as u64;
        let end = start + seg_entry.virtual_size as u64;
        
        let sclass = if seg_entry.flags & SEG_BSS != 0 {
            "BSS"
        } else if seg_entry.flags & SEG_EXTERN != 0 {
            "EXTERN"
        } else if seg_entry.flags & SEG_EXECUTE != 0 {
            "CODE"
        } else {
            "DATA"
        };

        let stype = if seg_entry.flags & SEG_BSS != 0 {
            segment::Type::Bss
        } else if seg_entry.flags & SEG_EXTERN != 0 {
            segment::Type::External
        } else if seg_entry.flags & SEG_EXECUTE != 0 {
            segment::Type::Code
        } else {
            segment::Type::Data
        };

        segment::create(start, end, &seg_entry.name, sclass, stype)?;
        
        let perm = segment::Permissions {
            read: (seg_entry.flags & SEG_READ) != 0,
            write: (seg_entry.flags & SEG_WRITE) != 0,
            execute: (seg_entry.flags & SEG_EXECUTE) != 0,
        };
        segment::set_permissions(start, perm)?;
        segment::set_bitness(start, 32)?;

        // Only load data if raw_size > 0 and it fits in the file
        if seg_entry.raw_size > 0 {
            let offset = seg_entry.file_offset as usize;
            let size = std::cmp::min(seg_entry.raw_size as usize, data.len().saturating_sub(offset));
            if size > 0 {
                loader::memory_to_database(&data[offset..offset+size], start, size as u64)?;
            }
        }
    }

    println!("XBIN advanced loader plan (Rust adaptation)");
    println!("input: {}", input_path);
    println!("version: {}", header.version);
    println!("mapped {} segments", segments.len());
    
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
