//! Typed analysis-problem lists.

use std::ffi::CString;

use crate::address::Address;
use crate::error::{self, Error, Result, Status};

/// A closed semantic analysis-problem category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Kind {
    MissingOffsetBase = 1,
    MissingName = 2,
    MissingForcedOperand = 3,
    MissingComment = 4,
    MissingReferences = 5,
    IgnoredJumpTable = 6,
    DisassemblyFailure = 7,
    AlreadyItemHead = 8,
    FlowBeyondLimits = 9,
    TooManyLines = 10,
    StackTraceFailure = 11,
    Attention = 12,
    AnalysisDecision = 13,
    RolledBackDecision = 14,
    FlairCollision = 15,
    FlairIndecision = 16,
}

/// Return a copied problem description, or `None` when none is recorded.
pub fn description(kind: Kind, address: Address) -> Result<Option<String>> {
    let mut out = std::ptr::null_mut();
    let status = unsafe { idax_sys::idax_problem_description(kind as i32, address, &mut out) };
    if status != 0 {
        return Err(error::consume_last_error("problem::description failed"));
    }
    if out.is_null() {
        return Ok(None);
    }
    unsafe {
        error::cstr_to_string_free(out, "problem::description returned invalid UTF-8").map(Some)
    }
}

/// Record a typed problem. `None` preserves the SDK default-message behavior.
pub fn remember(kind: Kind, address: Address, message: Option<&str>) -> Status {
    let message = message
        .map(|value| {
            CString::new(value)
                .map_err(|_| Error::validation("problem message contains an embedded NUL byte"))
        })
        .transpose()?;
    let pointer = message
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    let status = unsafe { idax_sys::idax_problem_remember(kind as i32, address, pointer) };
    error::int_to_status(status, "problem::remember failed")
}

/// Return the first problem address at or after the bound, or `None`.
pub fn next(kind: Kind, at_or_after: Address) -> Result<Option<Address>> {
    let mut out = 0;
    let mut has_value = 0;
    let status =
        unsafe { idax_sys::idax_problem_next(kind as i32, at_or_after, &mut out, &mut has_value) };
    if status != 0 {
        return Err(error::consume_last_error("problem::next failed"));
    }
    Ok((has_value != 0).then_some(out))
}

/// Remove a problem marker, returning whether it existed.
pub fn remove(kind: Kind, address: Address) -> Result<bool> {
    bool_result(
        |out| unsafe { idax_sys::idax_problem_remove(kind as i32, address, out) },
        "problem::remove failed",
    )
}

/// Return the copied short or long display name of a problem kind.
pub fn name(kind: Kind, long_form: bool) -> Result<String> {
    let mut out = std::ptr::null_mut();
    let status = unsafe { idax_sys::idax_problem_name(kind as i32, long_form as i32, &mut out) };
    if status != 0 {
        return Err(error::consume_last_error("problem::name failed"));
    }
    unsafe { error::cstr_to_string_free(out, "problem::name returned a null string") }
}

/// Return whether a typed problem exists at an address.
pub fn contains(kind: Kind, address: Address) -> Result<bool> {
    bool_result(
        |out| unsafe { idax_sys::idax_problem_contains(kind as i32, address, out) },
        "problem::contains failed",
    )
}

fn bool_result(function: impl FnOnce(*mut i32) -> i32, fallback: &str) -> Result<bool> {
    let mut out = 0;
    let status = function(&mut out);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    Ok(out != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_match_the_pinned_sdk() {
        assert_eq!(Kind::MissingOffsetBase as i32, 1);
        assert_eq!(Kind::Attention as i32, 12);
        assert_eq!(Kind::FlairIndecision as i32, 16);
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let error = remember(Kind::Attention, 0, Some("bad\0message")).unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }

    #[test]
    fn signatures_preserve_optional_and_boolean_state() {
        let _: fn(Kind, Address) -> Result<Option<String>> = description;
        let _: fn(Kind, Address, Option<&str>) -> Status = remember;
        let _: fn(Kind, Address) -> Result<Option<Address>> = next;
        let _: fn(Kind, Address) -> Result<bool> = remove;
        let _: fn(Kind, bool) -> Result<String> = name;
        let _: fn(Kind, Address) -> Result<bool> = contains;
    }
}
