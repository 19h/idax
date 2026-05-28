//! Portable path helpers.
//!
//! These mirror `ida::path` so Rust callers can use the same helper surface as
//! C++ plugins when porting SDK `qbasename` / `qdirname` / `qisdir` use.

use std::ffi::{CString, c_char};

use crate::error::{self, Error, Result};

fn string_path_call(
    path: &str,
    fallback: &str,
    f: unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> i32,
) -> Result<String> {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path"))?;
    unsafe {
        let mut ptr: *mut c_char = std::ptr::null_mut();
        let ret = f(c_path.as_ptr(), &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error(fallback));
        }
        error::cstr_to_string_free(ptr, fallback)
    }
}

/// Return the final path component.
pub fn basename(path: &str) -> Result<String> {
    string_path_call(path, "path::basename failed", idax_sys::idax_path_basename)
}

/// Return the parent path component.
pub fn dirname(path: &str) -> Result<String> {
    string_path_call(path, "path::dirname failed", idax_sys::idax_path_dirname)
}

/// Return whether the path currently names an existing directory.
pub fn is_directory(path: &str) -> Result<bool> {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path"))?;
    unsafe {
        let mut out = 0;
        let ret = idax_sys::idax_path_is_directory(c_path.as_ptr(), &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("path::is_directory failed"));
        }
        Ok(out != 0)
    }
}
