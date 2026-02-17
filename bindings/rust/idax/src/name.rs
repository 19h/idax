//! Naming, demangling, and name property operations.
//!
//! Mirrors the C++ `ida::name` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

/// Demangle form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DemangleForm {
    Short = 0,
    Long = 1,
    Full = 2,
}

/// Enumerated name entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub address: Address,
    pub name: String,
    pub user_defined: bool,
    pub auto_generated: bool,
}

/// Options for name inventory enumeration.
#[derive(Debug, Clone)]
pub struct ListOptions {
    pub start: Address,
    pub end: Address,
    pub include_user_defined: bool,
    pub include_auto_generated: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            start: BAD_ADDRESS,
            end: BAD_ADDRESS,
            include_user_defined: true,
            include_auto_generated: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Core naming
// ---------------------------------------------------------------------------

/// Set or replace the name at `address`.
pub fn set(address: Address, name: &str) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let ret = unsafe { idax_sys::idax_name_set(address, c_name.as_ptr()) };
    error::int_to_status(ret, "name::set failed")
}

/// Force-set a name, appending a numeric suffix if the name is taken.
pub fn force_set(address: Address, name: &str) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let ret = unsafe { idax_sys::idax_name_force_set(address, c_name.as_ptr()) };
    error::int_to_status(ret, "name::force_set failed")
}

/// Remove the name at `address`.
pub fn remove(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_name_remove(address) };
    error::int_to_status(ret, "name::remove failed")
}

/// Get the name at `address`.
pub fn get(address: Address) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_name_get(address, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("name::get failed"));
        }
        error::cstr_to_string_free(out, "name::get returned null")
    }
}

/// Get the demangled name at `address`.
pub fn demangled(address: Address, form: DemangleForm) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_name_demangled(address, form as i32, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("name::demangled failed"));
        }
        error::cstr_to_string_free(out, "name::demangled returned null")
    }
}

/// Resolve a name to an address.
pub fn resolve(name: &str, context: Address) -> Result<Address> {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_name_resolve(c_name.as_ptr(), context, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("name::resolve failed"))
    } else {
        Ok(out)
    }
}

/// Enumerate only user-defined names, optionally in `[start, end)`.
pub fn all_user_defined(start: Address, end: Address) -> Result<Vec<Entry>> {
    unsafe {
        let mut entries_ptr: *mut idax_sys::IdaxNameEntry = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_name_all_user_defined(start, end, &mut entries_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("name::all_user_defined failed"));
        }
        if entries_ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        let entries = std::slice::from_raw_parts(entries_ptr, count);
        for entry in entries {
            out.push(Entry {
                address: entry.address,
                name: if entry.name.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(entry.name)
                        .to_string_lossy()
                        .into_owned()
                },
                user_defined: entry.user_defined != 0,
                auto_generated: entry.auto_generated != 0,
            });
        }
        idax_sys::idax_name_entries_free(entries_ptr, count);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Name properties
// ---------------------------------------------------------------------------

/// Is the name at `address` public?
pub fn is_public(address: Address) -> bool {
    unsafe { idax_sys::idax_name_is_public(address) != 0 }
}

/// Is the name at `address` weak?
pub fn is_weak(address: Address) -> bool {
    unsafe { idax_sys::idax_name_is_weak(address) != 0 }
}

/// Is the name at `address` user-defined?
pub fn is_user_defined(address: Address) -> bool {
    unsafe { idax_sys::idax_name_is_user_defined(address) != 0 }
}

/// Is the name at `address` auto-generated?
pub fn is_auto_generated(address: Address) -> bool {
    unsafe { idax_sys::idax_name_is_auto_generated(address) != 0 }
}

/// Validate a user-facing identifier according to IDA naming rules.
pub fn is_valid_identifier(text: &str) -> Result<bool> {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid identifier text"))?;
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_name_is_valid_identifier(c_text.as_ptr(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "name::is_valid_identifier failed",
        ))
    } else {
        Ok(out != 0)
    }
}

/// Normalize an identifier by replacing invalid characters where possible.
pub fn sanitize_identifier(text: &str) -> Result<String> {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid identifier text"))?;
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_name_sanitize_identifier(c_text.as_ptr(), &mut out);
        if ret != 0 {
            return Err(error::consume_last_error(
                "name::sanitize_identifier failed",
            ));
        }
        error::cstr_to_string_free(out, "name::sanitize_identifier returned null")
    }
}

/// Set or clear the public flag.
pub fn set_public(address: Address, value: bool) -> Status {
    let ret = unsafe { idax_sys::idax_name_set_public(address, value as i32) };
    error::int_to_status(ret, "name::set_public failed")
}

/// Set or clear the weak flag.
pub fn set_weak(address: Address, value: bool) -> Status {
    let ret = unsafe { idax_sys::idax_name_set_weak(address, value as i32) };
    error::int_to_status(ret, "name::set_weak failed")
}
