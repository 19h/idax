//! Opaque address bookmark management.

use std::ffi::{CStr, CString};

use crate::address::Address;
use crate::error::{self, Error, Result};

/// Exact number of address-bookmark slots supported by IDA.
pub const MAX_SLOTS: u32 = idax_sys::IDAX_BOOKMARK_MAX_SLOTS;

/// Owned snapshot of one address bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Bookmark {
    pub address: Address,
    pub slot: u32,
    pub description: String,
}

unsafe fn copy_raw(raw: &idax_sys::IdaxBookmark) -> Result<Bookmark> {
    if raw.description.is_null() {
        return Err(Error::internal("bookmark description pointer is null"));
    }
    let description = unsafe { CStr::from_ptr(raw.description) }
        .to_str()
        .map_err(|_| Error::internal("bookmark description is not valid UTF-8"))?
        .to_owned();
    Ok(Bookmark {
        address: raw.address,
        slot: raw.slot,
        description,
    })
}

/// Copy every address bookmark in ascending slot order.
pub fn all() -> Result<Vec<Bookmark>> {
    let mut out = std::ptr::null_mut();
    let mut count = 0;
    let status = unsafe { idax_sys::idax_bookmark_all(&mut out, &mut count) };
    if status != 0 {
        return Err(error::consume_last_error("bookmark::all failed"));
    }
    if count != 0 && out.is_null() {
        return Err(Error::internal("bookmark array pointer is null"));
    }
    let mut values = Vec::with_capacity(count);
    if !out.is_null() {
        let raw = unsafe { std::slice::from_raw_parts(out, count) };
        for value in raw {
            match unsafe { copy_raw(value) } {
                Ok(value) => values.push(value),
                Err(failure) => {
                    unsafe { idax_sys::idax_bookmarks_free(out, count) };
                    return Err(failure);
                }
            }
        }
        unsafe { idax_sys::idax_bookmarks_free(out, count) };
    }
    Ok(values)
}

fn optional_result(
    function: impl FnOnce(*mut idax_sys::IdaxBookmark, *mut i32) -> i32,
    fallback: &str,
) -> Result<Option<Bookmark>> {
    let mut raw = idax_sys::IdaxBookmark {
        address: 0,
        slot: 0,
        description: std::ptr::null_mut(),
    };
    let mut has_value = 0;
    let status = function(&mut raw, &mut has_value);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    if has_value == 0 {
        return Ok(None);
    }
    let result = unsafe { copy_raw(&raw) };
    unsafe { idax_sys::idax_bookmark_free(&mut raw) };
    result.map(Some)
}

/// Find the bookmark at an address, or `None`.
pub fn at(address: Address) -> Result<Option<Bookmark>> {
    optional_result(
        |out, has_value| unsafe { idax_sys::idax_bookmark_at(address, out, has_value) },
        "bookmark::at failed",
    )
}

/// Find the bookmark occupying a slot, or `None`.
pub fn at_slot(slot: u32) -> Result<Option<Bookmark>> {
    optional_result(
        |out, has_value| unsafe { idax_sys::idax_bookmark_at_slot(slot, out, has_value) },
        "bookmark::at_slot failed",
    )
}

/// Create or update a bookmark; `None` selects the lowest free slot.
pub fn set(address: Address, description: &str, slot: Option<u32>) -> Result<Bookmark> {
    let description = CString::new(description)
        .map_err(|_| Error::validation("bookmark description contains an embedded NUL byte"))?;
    let mut raw = idax_sys::IdaxBookmark {
        address: 0,
        slot: 0,
        description: std::ptr::null_mut(),
    };
    let status = unsafe {
        idax_sys::idax_bookmark_set(
            address,
            description.as_ptr(),
            slot.is_some() as i32,
            slot.unwrap_or(0),
            &mut raw,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error("bookmark::set failed"));
    }
    let result = unsafe { copy_raw(&raw) };
    unsafe { idax_sys::idax_bookmark_free(&mut raw) };
    result
}

fn bool_result(function: impl FnOnce(*mut i32) -> i32, fallback: &str) -> Result<bool> {
    let mut out = 0;
    let status = function(&mut out);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    Ok(out != 0)
}

/// Remove the bookmark at an address, returning whether it existed.
pub fn remove(address: Address) -> Result<bool> {
    bool_result(
        |out| unsafe { idax_sys::idax_bookmark_remove(address, out) },
        "bookmark::remove failed",
    )
}

/// Remove the bookmark occupying a slot, returning whether it existed.
pub fn remove_slot(slot: u32) -> Result<bool> {
    bool_result(
        |out| unsafe { idax_sys::idax_bookmark_remove_slot(slot, out) },
        "bookmark::remove_slot failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_matches_the_pinned_sdk() {
        assert_eq!(MAX_SLOTS, 1024);
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let error = set(0, "bad\0description", None).unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }

    #[test]
    fn signatures_preserve_owned_and_optional_state() {
        let _: fn() -> Result<Vec<Bookmark>> = all;
        let _: fn(Address) -> Result<Option<Bookmark>> = at;
        let _: fn(u32) -> Result<Option<Bookmark>> = at_slot;
        let _: fn(Address, &str, Option<u32>) -> Result<Bookmark> = set;
        let _: fn(Address) -> Result<bool> = remove;
        let _: fn(u32) -> Result<bool> = remove_slot;
    }
}
