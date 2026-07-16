//! Opaque named restore points and undo/redo state.

use std::ffi::{CString, c_char};

use crate::error::{self, Error, Result};

/// Create a named restore point before a database mutation.
///
/// Returns `false` when the host is not currently recording undo history.
pub fn create_point(action_name: &str, label: &str) -> Result<bool> {
    let action_name = CString::new(action_name)
        .map_err(|_| Error::validation("undo action name contains an embedded NUL byte"))?;
    let label = CString::new(label)
        .map_err(|_| Error::validation("undo action label contains an embedded NUL byte"))?;
    let mut out = 0;
    let status =
        unsafe { idax_sys::idax_undo_create_point(action_name.as_ptr(), label.as_ptr(), &mut out) };
    if status != 0 {
        return Err(error::consume_last_error("undo::create_point failed"));
    }
    Ok(out != 0)
}

fn action_label(
    function: unsafe extern "C" fn(*mut *mut c_char) -> i32,
    fallback: &str,
) -> Result<Option<String>> {
    let mut out = std::ptr::null_mut();
    let status = unsafe { function(&mut out) };
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    if out.is_null() {
        return Ok(None);
    }
    unsafe { error::cstr_to_string_free(out, fallback).map(Some) }
}

/// Display label of the next undo action, or `None` when none is available.
pub fn undo_action_label() -> Result<Option<String>> {
    action_label(
        idax_sys::idax_undo_undo_action_label,
        "undo::undo_action_label failed",
    )
}

/// Display label of the next redo action, or `None` when none is available.
pub fn redo_action_label() -> Result<Option<String>> {
    action_label(
        idax_sys::idax_undo_redo_action_label,
        "undo::redo_action_label failed",
    )
}

fn perform(function: unsafe extern "C" fn(*mut i32) -> i32, fallback: &str) -> Result<bool> {
    let mut out = 0;
    let status = unsafe { function(&mut out) };
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    Ok(out != 0)
}

/// Perform the next undo action. Returns `false` when none is available.
pub fn perform_undo() -> Result<bool> {
    perform(
        idax_sys::idax_undo_perform_undo,
        "undo::perform_undo failed",
    )
}

/// Perform the next redo action. Returns `false` when none is available.
pub fn perform_redo() -> Result<bool> {
    perform(
        idax_sys::idax_undo_perform_redo,
        "undo::perform_redo failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let error = create_point("bad\0action", "label").unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);

        let error = create_point("action", "bad\0label").unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }

    #[test]
    fn signatures_preserve_optional_and_boolean_state() {
        let _: fn(&str, &str) -> Result<bool> = create_point;
        let _: fn() -> Result<Option<String>> = undo_action_label;
        let _: fn() -> Result<Option<String>> = redo_action_label;
        let _: fn() -> Result<bool> = perform_undo;
        let _: fn() -> Result<bool> = perform_redo;
    }
}
