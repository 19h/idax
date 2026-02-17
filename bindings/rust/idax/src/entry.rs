//! Program entry points.
//!
//! Mirrors the C++ `ida::entry` namespace.

use crate::address::Address;
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

/// Entry point descriptor.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub ordinal: u64,
    pub address: Address,
    pub name: String,
    pub forwarder: String,
}

/// Total number of entry points.
pub fn count() -> Result<usize> {
    let mut n: usize = 0;
    let ret = unsafe { idax_sys::idax_entry_count(&mut n) };
    if ret != 0 {
        Err(error::consume_last_error("entry::count failed"))
    } else {
        Ok(n)
    }
}

/// Get entry point by index.
pub fn by_index(index: usize) -> Result<EntryPoint> {
    unsafe {
        let mut raw = idax_sys::IdaxEntryPoint::default();
        let ret = idax_sys::idax_entry_by_index(index, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("entry::by_index failed"));
        }
        let ep = EntryPoint {
            ordinal: raw.ordinal,
            address: raw.address,
            name: error::cstr_to_string(raw.name, "entry name").unwrap_or_default(),
            forwarder: error::cstr_to_string(raw.forwarder, "entry forwarder").unwrap_or_default(),
        };
        idax_sys::idax_entry_free(&mut raw);
        Ok(ep)
    }
}

/// Get entry point by ordinal.
pub fn by_ordinal(ordinal: u64) -> Result<EntryPoint> {
    unsafe {
        let mut raw = idax_sys::IdaxEntryPoint::default();
        let ret = idax_sys::idax_entry_by_ordinal(ordinal, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("entry::by_ordinal failed"));
        }
        let ep = EntryPoint {
            ordinal: raw.ordinal,
            address: raw.address,
            name: error::cstr_to_string(raw.name, "entry name").unwrap_or_default(),
            forwarder: error::cstr_to_string(raw.forwarder, "entry forwarder").unwrap_or_default(),
        };
        idax_sys::idax_entry_free(&mut raw);
        Ok(ep)
    }
}

/// Add an entry point.
pub fn add(ordinal: u64, address: Address, name: &str, make_code: bool) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let ret =
        unsafe { idax_sys::idax_entry_add(ordinal, address, c_name.as_ptr(), make_code as i32) };
    error::int_to_status(ret, "entry::add failed")
}

/// Rename an entry point.
pub fn rename(ordinal: u64, name: &str) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let ret = unsafe { idax_sys::idax_entry_rename(ordinal, c_name.as_ptr()) };
    error::int_to_status(ret, "entry::rename failed")
}

/// Get entry forwarder text by ordinal.
pub fn forwarder(ordinal: u64) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_entry_forwarder(ordinal, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("entry::forwarder failed"));
        }
        error::cstr_to_string_free(out, "entry::forwarder returned null")
    }
}

/// Set entry forwarder text by ordinal.
pub fn set_forwarder(ordinal: u64, target: &str) -> Status {
    let c_target = CString::new(target).map_err(|_| Error::validation("invalid target"))?;
    let ret = unsafe { idax_sys::idax_entry_set_forwarder(ordinal, c_target.as_ptr()) };
    error::int_to_status(ret, "entry::set_forwarder failed")
}

/// Clear entry forwarder text by ordinal.
pub fn clear_forwarder(ordinal: u64) -> Status {
    let ret = unsafe { idax_sys::idax_entry_clear_forwarder(ordinal) };
    error::int_to_status(ret, "entry::clear_forwarder failed")
}
