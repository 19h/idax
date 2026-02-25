mod common;

use common::{format_error, print_usage, DatabaseSession};
use idax::{
    address::BAD_ADDRESS, analysis, data, entry, loader, name, segment, storage, Error, Result,
};

const MAGIC_V1: u32 = 0x0043424a;
const MAGIC_V2: u32 = 0x0143424a;
const STATE_NODE_NAME: &str = "$ jbc";
const STATE_CODE_BASE_INDEX: u64 = 0;
const STATE_STRING_BASE_INDEX: u64 = 1;

fn read_be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::validation(format!("truncated u32 at offset {offset}")))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn align16(value: u64) -> u64 {
    (value + 0xF) & !0xF
}

fn string_at(table: &[u8], offset: usize) -> String {
    if offset >= table.len() {
        return String::new();
    }
    let mut end = offset;
    while end < table.len() && table[end] != 0 {
        end += 1;
    }
    if end == offset {
        return String::new();
    }
    String::from_utf8_lossy(&table[offset..end]).into_owned()
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0], "<jbc_file>");
        return Err(Error::validation("missing jbc_file argument"));
    }

    let input_path = &args[1];
    let file_data = std::fs::read(input_path)
        .map_err(|err| Error::internal(format!("failed reading '{input_path}': {err}")))?;

    if file_data.len() < 64 {
        return Err(Error::validation("file too small for JBC header"));
    }

    let magic = read_be_u32(&file_data, 0)?;
    if magic != MAGIC_V1 && magic != MAGIC_V2 {
        return Err(Error::unsupported(
            "input is not a JAM Byte-Code (JBC) file",
        ));
    }

    let _session = DatabaseSession::open(input_path, false)?;

    // Clear auto-created segments to emulate full control over the database layout.
    for seg in segment::all().collect::<Vec<_>>() {
        segment::remove(seg.start())?;
    }

    // Try setting a fallback processor since 'jbc' might not be installed or
    // might throw an uncaught C++ exception bypassing FFI if missing.
    loader::set_processor("metapc").ok();

    loader::create_filename_comment()?;

    let version = if magic == MAGIC_V2 { 2u32 } else { 1u32 };
    let delta = if version == 2 { 8usize } else { 0usize };

    let action_table = read_be_u32(&file_data, 4)? as usize;
    let proc_table = read_be_u32(&file_data, 8)? as usize;
    let string_table = read_be_u32(&file_data, 4 + delta)? as usize;
    let data_section = read_be_u32(&file_data, 20 + delta)? as usize;
    let code_section = read_be_u32(&file_data, 24 + delta)? as usize;
    let action_count = read_be_u32(&file_data, 40 + delta)? as usize;
    let proc_count = read_be_u32(&file_data, 44 + delta)? as usize;

    let mut string_size = if version == 1 {
        let symbol_table = read_be_u32(&file_data, 16 + delta)? as usize;
        if symbol_table > string_table {
            symbol_table - string_table
        } else if data_section > string_table {
            data_section - string_table
        } else {
            0
        }
    } else {
        let note_strings = read_be_u32(&file_data, 16)? as usize;
        if note_strings > string_table {
            note_strings - string_table
        } else {
            0
        }
    };

    println!(
        "[JBC full loader] version={version} action_count={action_count} proc_count={proc_count}"
    );

    let mut string_table_bytes = Vec::new();
    if string_size > 0 && string_table + string_size <= file_data.len() {
        if string_size > 1024 * 1024 {
            string_size = 1024 * 1024;
            println!("[JBC full loader] string table capped at 1MB");
        }
        string_table_bytes.extend_from_slice(&file_data[string_table..string_table + string_size]);
    }

    if code_section > file_data.len() {
        return Err(Error::validation("invalid JBC code section offset"));
    }

    let code_size = if data_section > code_section && data_section <= file_data.len() {
        data_section - code_section
    } else {
        file_data.len() - code_section
    };

    let data_size = if data_section > 0 && data_section < file_data.len() {
        file_data.len() - data_section
    } else {
        0
    };

    let mut current_ea = 0x10000u64;
    let mut string_base = BAD_ADDRESS;
    let mut code_base = BAD_ADDRESS;

    // Load STRINGS
    if !string_table_bytes.is_empty() {
        let start = align16(current_ea);
        let end = start + string_table_bytes.len() as u64;

        segment::create(start, end, "CONST", "CONST", segment::Type::Data)?;
        segment::set_permissions(
            start,
            segment::Permissions {
                read: true,
                write: false,
                execute: false,
            },
        )?;
        segment::set_bitness(start, 32)?;

        loader::memory_to_database(&string_table_bytes, start, string_table_bytes.len() as u64)?;
        string_base = start;

        // Define embedded strings
        let mut index = 0;
        while index < string_table_bytes.len() {
            if string_table_bytes[index] == 0 {
                index += 1;
                continue;
            }
            let mut end_str = index;
            while end_str < string_table_bytes.len() && string_table_bytes[end_str] != 0 {
                end_str += 1;
            }
            let length = end_str - index + 1;
            data::define_string(string_base + index as u64, length as u64, 0)?;
            index = end_str + 1;
        }
        current_ea = end;
    }

    // Load CODE
    if code_size > 0 {
        let start = align16(current_ea);
        let end = start + code_size as u64;

        segment::create(start, end, "CODE", "CODE", segment::Type::Code)?;
        segment::set_permissions(
            start,
            segment::Permissions {
                read: true,
                write: false,
                execute: true,
            },
        )?;
        segment::set_bitness(start, 32)?;

        loader::memory_to_database(
            &file_data[code_section..code_section + code_size],
            start,
            code_size as u64,
        )?;
        code_base = start;
        current_ea = end;
    }

    // Load DATA
    if data_size > 0 {
        let start = align16(current_ea);
        let end = start + data_size as u64;

        segment::create(start, end, "DATA", "DATA", segment::Type::Data)?;
        segment::set_permissions(
            start,
            segment::Permissions {
                read: true,
                write: true,
                execute: false,
            },
        )?;
        segment::set_bitness(start, 32)?;

        loader::memory_to_database(
            &file_data[data_section..data_section + data_size],
            start,
            data_size as u64,
        )?;
    }

    // Seed default CS/DS register values across all loaded segments.
    // Assuming register indices for jbc: CS=1, DS=2 (we use arbitrary ones if not exactly mapped, or just ignore errors).
    let _ = segment::set_default_segment_register_for_all(1, 0);
    let _ = segment::set_default_segment_register_for_all(2, 0);

    if code_base != BAD_ADDRESS
        && action_count > 0
        && action_count < 4096
        && action_table < file_data.len()
    {
        for i in 0..action_count {
            let entry_offset = action_table + i * 12;
            if entry_offset + 12 > file_data.len() {
                break;
            }
            if let Ok(name_offset) = read_be_u32(&file_data, entry_offset) {
                if let Ok(proc_index) = read_be_u32(&file_data, entry_offset + 8) {
                    if (proc_index as usize) < proc_count {
                        let action_name = string_at(&string_table_bytes, name_offset as usize);
                        if !action_name.is_empty() {
                            let proc_offset = proc_table + (proc_index as usize) * 13 + 9;
                            if proc_offset + 4 <= file_data.len() {
                                if let Ok(proc_code_offset) = read_be_u32(&file_data, proc_offset) {
                                    let entry_address = code_base + proc_code_offset as u64;
                                    entry::add(i as u64, entry_address, &action_name, true)?;
                                    name::force_set(entry_address, &action_name)?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if code_base != BAD_ADDRESS
        && proc_count > 0
        && proc_count < 100000
        && proc_table < file_data.len()
    {
        for i in 0..proc_count {
            let entry_offset = proc_table + i * 13;
            if entry_offset + 13 > file_data.len() {
                break;
            }
            if let Ok(name_offset) = read_be_u32(&file_data, entry_offset) {
                if let Ok(proc_code_offset) = read_be_u32(&file_data, entry_offset + 9) {
                    let procedure_address = code_base + proc_code_offset as u64;
                    let procedure_name = string_at(&string_table_bytes, name_offset as usize);
                    if !procedure_name.is_empty() {
                        name::force_set(procedure_address, &procedure_name)?;
                    }
                    analysis::schedule_function(procedure_address)?;
                }
            }
        }
    }

    if let Ok(state_node) = storage::Node::open(STATE_NODE_NAME, true) {
        state_node.set_alt_default(
            STATE_CODE_BASE_INDEX,
            if code_base == BAD_ADDRESS {
                0
            } else {
                code_base
            },
        )?;
        state_node.set_alt_default(
            STATE_STRING_BASE_INDEX,
            if string_base == BAD_ADDRESS {
                0
            } else {
                string_base
            },
        )?;
    }

    println!("[JBC full loader] load complete. Awaiting auto-analysis...");
    analysis::wait()?;
    println!("[JBC full loader] auto-analysis complete.");

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}
