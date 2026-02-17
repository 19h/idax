//! Color tag manipulation for IDA's tagged text format.
//!
//! Mirrors the `ida::lines` namespace from idax. IDA uses embedded color tags
//! in text output (pseudocode, disassembly, listing lines). This module
//! provides utilities for creating, parsing, and stripping these tags.

use crate::error::{self};
use std::ffi::CString;

/// Color constants corresponding to the SDK's `COLOR_*` / `SCOLOR_*` values.
///
/// Values match the SDK exactly so they can be used directly in tag bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Color {
    Default = 0x01,
    RegularComment = 0x02,
    RepeatableComment = 0x03,
    AutoComment = 0x04,
    Instruction = 0x05,
    DataName = 0x06,
    RegularDataName = 0x07,
    DemangledName = 0x08,
    Symbol = 0x09,
    CharLiteral = 0x0A,
    String = 0x0B,
    Number = 0x0C,
    Void = 0x0D,
    CodeReference = 0x0E,
    DataReference = 0x0F,
    CodeRefTail = 0x10,
    DataRefTail = 0x11,
    Error = 0x12,
    Prefix = 0x13,
    BinaryPrefix = 0x14,
    Extra = 0x15,
    AltOperand = 0x16,
    HiddenName = 0x17,
    LibraryName = 0x18,
    LocalName = 0x19,
    DummyCodeName = 0x1A,
    AsmDirective = 0x1B,
    Macro = 0x1C,
    DataString = 0x1D,
    DataChar = 0x1E,
    DataNumber = 0x1F,
    Keyword = 0x20,
    Register = 0x21,
    ImportedName = 0x22,
    SegmentName = 0x23,
    UnknownName = 0x24,
    CodeName = 0x25,
    UserName = 0x26,
    Collapsed = 0x27,
}

/// `COLOR_ON` escape byte — begins a color span.
pub const COLOR_ON: char = '\x01';
/// `COLOR_OFF` escape byte — ends a color span.
pub const COLOR_OFF: char = '\x02';
/// `COLOR_ESC` escape byte — quotes the next character.
pub const COLOR_ESC: char = '\x03';
/// `COLOR_INV` escape byte — toggles inverse video (no OFF pair).
pub const COLOR_INV: char = '\x04';
/// `COLOR_ADDR` tag byte value — marks an address/anchor tag.
pub const COLOR_ADDR: u8 = 0x28;
/// Size (in hex characters) of a `COLOR_ADDR` encoded item reference.
pub const COLOR_ADDR_SIZE: i32 = 16;

/// Wrap a string in color tags. Equivalent to IDA's `COLSTR()` macro.
///
/// The returned string has the form: `COLOR_ON + color + text + COLOR_OFF + color`.
/// This can be inserted into raw pseudocode/listing lines.
pub fn colstr(text: &str, color: Color) -> String {
    let c = color as u8 as char;
    let mut s = String::with_capacity(text.len() + 4);
    s.push(COLOR_ON);
    s.push(c);
    s.push_str(text);
    s.push(COLOR_OFF);
    s.push(c);
    s
}

/// Remove all color tags from a tagged string, returning plain text.
///
/// This is useful for getting the visible text length or display text.
pub fn tag_remove(tagged_text: &str) -> String {
    let c_text = match CString::new(tagged_text) {
        Ok(c) => c,
        Err(_) => return tagged_text.to_string(),
    };
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_lines_tag_remove(c_text.as_ptr(), &mut out) };
    if rc != 0 || out.is_null() {
        return tagged_text.to_string();
    }
    let s = unsafe { error::consume_c_string(out) };
    s
}

/// Advance past a color tag at the given position.
///
/// Returns the number of bytes to skip past the tag at `tagged_text[pos]`.
/// If there is no tag at that position, returns 1 (advance one character).
pub fn tag_advance(tagged_text: &str, pos: usize) -> usize {
    let c_text = match CString::new(tagged_text) {
        Ok(c) => c,
        Err(_) => return 1,
    };
    let result = unsafe { idax_sys::idax_lines_tag_advance(c_text.as_ptr(), pos as i32) };
    result.max(1) as usize
}

/// Get the visible (non-tag) character length of a tagged string.
///
/// Equivalent to `tag_remove(s).len()` but avoids allocating a new string.
pub fn tag_strlen(tagged_text: &str) -> usize {
    let c_text = match CString::new(tagged_text) {
        Ok(c) => c,
        Err(_) => return tagged_text.len(),
    };
    unsafe { idax_sys::idax_lines_tag_strlen(c_text.as_ptr()) }
}

/// Build a `COLOR_ADDR` item reference tag.
///
/// This creates the encoded tag string that references a ctree item by
/// its index. Used by filters that insert annotations at specific items.
pub fn make_addr_tag(item_index: i32) -> String {
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_lines_make_addr_tag(item_index, &mut out) };
    if rc != 0 || out.is_null() {
        return String::new();
    }
    unsafe { error::consume_c_string(out) }
}

/// Decode a `COLOR_ADDR` tag at the given position in a tagged string.
///
/// Returns the decoded item index, or `None` if no valid tag at that position.
pub fn decode_addr_tag(tagged_text: &str, pos: usize) -> Option<i32> {
    let c_text = match CString::new(tagged_text) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let result = unsafe { idax_sys::idax_lines_decode_addr_tag(c_text.as_ptr(), pos) };
    if result < 0 {
        None
    } else {
        Some(result)
    }
}
