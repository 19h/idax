//! Comment access and mutation (regular, repeatable, anterior/posterior).
//!
//! Mirrors the C++ `ida::comment` namespace.

use crate::address::Address;
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

fn lines_to_cstring_array(lines: &[&str]) -> Result<Vec<CString>> {
    lines
        .iter()
        .map(|line| CString::new(*line).map_err(|_| Error::validation("invalid text")))
        .collect()
}

fn collect_line_array(lines: *mut *mut std::ffi::c_char, count: usize) -> Vec<String> {
    if lines.is_null() || count == 0 {
        return Vec::new();
    }
    unsafe {
        let slice = std::slice::from_raw_parts(lines, count);
        let out = slice
            .iter()
            .map(|line| {
                if (*line).is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(*line)
                        .to_string_lossy()
                        .into_owned()
                }
            })
            .collect();
        idax_sys::idax_comment_lines_free(lines, count);
        out
    }
}

// ---------------------------------------------------------------------------
// Regular comments
// ---------------------------------------------------------------------------

/// Get comment at address.
pub fn get(address: Address, repeatable: bool) -> Result<String> {
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_comment_get(address, repeatable as i32, &mut out) };
    if ret != 0 {
        return Err(error::consume_last_error("comment::get failed"));
    }
    if out.is_null() {
        Ok(String::new())
    } else {
        Ok(unsafe { error::consume_c_string(out) })
    }
}

/// Set comment at address.
pub fn set(address: Address, text: &str, repeatable: bool) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_set(address, c_text.as_ptr(), repeatable as i32) };
    error::int_to_status(ret, "comment::set failed")
}

/// Append text to existing comment at address.
pub fn append(address: Address, text: &str, repeatable: bool) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_append(address, c_text.as_ptr(), repeatable as i32) };
    error::int_to_status(ret, "comment::append failed")
}

/// Remove comment at address.
pub fn remove(address: Address, repeatable: bool) -> Status {
    let ret = unsafe { idax_sys::idax_comment_remove(address, repeatable as i32) };
    error::int_to_status(ret, "comment::remove failed")
}

// ---------------------------------------------------------------------------
// Anterior / posterior lines
// ---------------------------------------------------------------------------

/// Add an anterior line at address.
pub fn add_anterior(address: Address, text: &str) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_add_anterior(address, c_text.as_ptr()) };
    error::int_to_status(ret, "add_anterior failed")
}

/// Add a posterior line at address.
pub fn add_posterior(address: Address, text: &str) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_add_posterior(address, c_text.as_ptr()) };
    error::int_to_status(ret, "add_posterior failed")
}

/// Get an anterior line by index.
pub fn get_anterior(address: Address, line_index: i32) -> Result<String> {
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_comment_get_anterior(address, line_index, &mut out) };
    if ret != 0 {
        return Err(error::consume_last_error("get_anterior failed"));
    }
    if out.is_null() {
        Ok(String::new())
    } else {
        Ok(unsafe { error::consume_c_string(out) })
    }
}

/// Get a posterior line by index.
pub fn get_posterior(address: Address, line_index: i32) -> Result<String> {
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_comment_get_posterior(address, line_index, &mut out) };
    if ret != 0 {
        return Err(error::consume_last_error("get_posterior failed"));
    }
    if out.is_null() {
        Ok(String::new())
    } else {
        Ok(unsafe { error::consume_c_string(out) })
    }
}

/// Replace an existing anterior line at index.
pub fn set_anterior(address: Address, line_index: i32, text: &str) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_set_anterior(address, line_index, c_text.as_ptr()) };
    error::int_to_status(ret, "set_anterior failed")
}

/// Replace an existing posterior line at index.
pub fn set_posterior(address: Address, line_index: i32, text: &str) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_comment_set_posterior(address, line_index, c_text.as_ptr()) };
    error::int_to_status(ret, "set_posterior failed")
}

/// Clear all anterior lines.
pub fn clear_anterior(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_comment_clear_anterior(address) };
    error::int_to_status(ret, "clear_anterior failed")
}

/// Clear all posterior lines.
pub fn clear_posterior(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_comment_clear_posterior(address) };
    error::int_to_status(ret, "clear_posterior failed")
}

/// Remove an anterior line at index.
pub fn remove_anterior_line(address: Address, line_index: i32) -> Status {
    let ret = unsafe { idax_sys::idax_comment_remove_anterior_line(address, line_index) };
    error::int_to_status(ret, "remove_anterior_line failed")
}

/// Remove a posterior line at index.
pub fn remove_posterior_line(address: Address, line_index: i32) -> Status {
    let ret = unsafe { idax_sys::idax_comment_remove_posterior_line(address, line_index) };
    error::int_to_status(ret, "remove_posterior_line failed")
}

/// Replace all anterior lines.
pub fn set_anterior_lines(address: Address, lines: &[&str]) -> Status {
    let c_lines = lines_to_cstring_array(lines)?;
    let line_ptrs: Vec<*const std::ffi::c_char> = c_lines.iter().map(|s| s.as_ptr()).collect();
    let ret = unsafe {
        idax_sys::idax_comment_set_anterior_lines(address, line_ptrs.as_ptr(), line_ptrs.len())
    };
    error::int_to_status(ret, "set_anterior_lines failed")
}

/// Replace all posterior lines.
pub fn set_posterior_lines(address: Address, lines: &[&str]) -> Status {
    let c_lines = lines_to_cstring_array(lines)?;
    let line_ptrs: Vec<*const std::ffi::c_char> = c_lines.iter().map(|s| s.as_ptr()).collect();
    let ret = unsafe {
        idax_sys::idax_comment_set_posterior_lines(address, line_ptrs.as_ptr(), line_ptrs.len())
    };
    error::int_to_status(ret, "set_posterior_lines failed")
}

/// Get all anterior lines.
pub fn anterior_lines(address: Address) -> Result<Vec<String>> {
    let mut lines: *mut *mut std::ffi::c_char = std::ptr::null_mut();
    let mut count: usize = 0;
    let ret = unsafe { idax_sys::idax_comment_anterior_lines(address, &mut lines, &mut count) };
    if ret != 0 {
        Err(error::consume_last_error("anterior_lines failed"))
    } else {
        Ok(collect_line_array(lines, count))
    }
}

/// Get all posterior lines.
pub fn posterior_lines(address: Address) -> Result<Vec<String>> {
    let mut lines: *mut *mut std::ffi::c_char = std::ptr::null_mut();
    let mut count: usize = 0;
    let ret = unsafe { idax_sys::idax_comment_posterior_lines(address, &mut lines, &mut count) };
    if ret != 0 {
        Err(error::consume_last_error("posterior_lines failed"))
    } else {
        Ok(collect_line_array(lines, count))
    }
}

/// Render comments at an address into one normalized text block.
pub fn render(
    address: Address,
    include_repeatable: bool,
    include_extra_lines: bool,
) -> Result<String> {
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let ret = unsafe {
        idax_sys::idax_comment_render(
            address,
            include_repeatable as i32,
            include_extra_lines as i32,
            &mut out,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error("render failed"))
    } else {
        unsafe { error::cstr_to_string_free(out, "render returned null") }
    }
}
