//! Text, binary, and immediate value searches.
//!
//! Mirrors the C++ `ida::search` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Error, Result};
use std::ffi::CString;

/// Search direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Forward,
    Backward,
}

impl Direction {
    /// Convert to the C `forward` parameter (1 = forward, 0 = backward).
    fn as_forward_int(self) -> i32 {
        match self {
            Direction::Forward => 1,
            Direction::Backward => 0,
        }
    }
}

/// Search for a text string in the disassembly listing.
pub fn text(query: &str, start: Address, dir: Direction, case_sensitive: bool) -> Result<Address> {
    let c_q = CString::new(query).map_err(|_| Error::validation("invalid query"))?;
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe {
        idax_sys::idax_search_text(
            c_q.as_ptr(),
            start,
            dir.as_forward_int(),
            case_sensitive as i32,
            &mut out,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error("search::text not found"))
    } else {
        Ok(out)
    }
}

/// Search for an immediate value in instruction operands.
pub fn immediate(value: u64, start: Address, dir: Direction) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret =
        unsafe { idax_sys::idax_search_immediate(value, start, dir.as_forward_int(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("search::immediate not found"))
    } else {
        Ok(out)
    }
}

/// Search for a binary byte pattern (hex string like "90 90 CC").
pub fn binary_pattern(hex_pattern: &str, start: Address, dir: Direction) -> Result<Address> {
    let c_p = CString::new(hex_pattern).map_err(|_| Error::validation("invalid pattern"))?;
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe {
        idax_sys::idax_search_binary_pattern(c_p.as_ptr(), start, dir.as_forward_int(), &mut out)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "search::binary_pattern not found",
        ))
    } else {
        Ok(out)
    }
}

/// Find the next address containing code.
pub fn next_code(address: Address) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_search_next_code(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_code not found"))
    } else {
        Ok(out)
    }
}

/// Find the next address containing data.
pub fn next_data(address: Address) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_search_next_data(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_data not found"))
    } else {
        Ok(out)
    }
}

/// Find the next unexplored byte.
pub fn next_unknown(address: Address) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_search_next_unknown(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_unknown not found"))
    } else {
        Ok(out)
    }
}

/// Find the next address containing an analyzer error/problem marker.
pub fn next_error(address: Address) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_search_next_error(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_error not found"))
    } else {
        Ok(out)
    }
}

/// Find the next defined item address.
pub fn next_defined(address: Address) -> Result<Address> {
    let mut out: u64 = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_search_next_defined(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_defined not found"))
    } else {
        Ok(out)
    }
}
