//! Cross-reference enumeration and mutation.
//!
//! Mirrors the C++ `ida::xref` namespace.

use crate::address::Address;
use crate::error::{self, Result, Status};

unsafe extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

/// Code cross-reference type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CodeType {
    CallFar = 0,
    CallNear = 1,
    JumpFar = 2,
    JumpNear = 3,
    Flow = 4,
}

/// Data cross-reference type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DataType {
    Offset = 0,
    Write = 1,
    Read = 2,
    Text = 3,
    Informational = 4,
}

/// High-level classification of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ReferenceType {
    Unknown = 0,
    Flow = 1,
    CallNear = 2,
    CallFar = 3,
    JumpNear = 4,
    JumpFar = 5,
    Offset = 6,
    Read = 7,
    Write = 8,
    Text = 9,
    Informational = 10,
}

/// Unified cross-reference descriptor.
#[derive(Debug, Clone)]
pub struct Reference {
    pub from: Address,
    pub to: Address,
    pub is_code: bool,
    pub ref_type: ReferenceType,
    pub user_defined: bool,
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

/// Add a code cross-reference.
pub fn add_code(from: Address, to: Address, code_type: CodeType) -> Status {
    let ret = unsafe { idax_sys::idax_xref_add_code(from, to, code_type as i32) };
    error::int_to_status(ret, "xref::add_code failed")
}

/// Add a data cross-reference.
pub fn add_data(from: Address, to: Address, data_type: DataType) -> Status {
    let ret = unsafe { idax_sys::idax_xref_add_data(from, to, data_type as i32) };
    error::int_to_status(ret, "xref::add_data failed")
}

/// Remove a code cross-reference.
pub fn remove_code(from: Address, to: Address) -> Status {
    let ret = unsafe { idax_sys::idax_xref_remove_code(from, to) };
    error::int_to_status(ret, "xref::remove_code failed")
}

/// Remove a data cross-reference.
pub fn remove_data(from: Address, to: Address) -> Status {
    let ret = unsafe { idax_sys::idax_xref_remove_data(from, to) };
    error::int_to_status(ret, "xref::remove_data failed")
}

// ---------------------------------------------------------------------------
// Helpers to decode references from FFI
// ---------------------------------------------------------------------------

fn ref_type_from_i32(v: i32) -> ReferenceType {
    match v {
        0 => ReferenceType::Unknown,
        1 => ReferenceType::Flow,
        2 => ReferenceType::CallNear,
        3 => ReferenceType::CallFar,
        4 => ReferenceType::JumpNear,
        5 => ReferenceType::JumpFar,
        6 => ReferenceType::Offset,
        7 => ReferenceType::Read,
        8 => ReferenceType::Write,
        9 => ReferenceType::Text,
        10 => ReferenceType::Informational,
        _ => ReferenceType::Unknown,
    }
}

unsafe fn refs_from_ffi(refs_ptr: *mut idax_sys::IdaxXref, count: usize) -> Vec<Reference> {
    if refs_ptr.is_null() || count == 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(refs_ptr, count) };
    let result = slice
        .iter()
        .map(|r| Reference {
            from: r.from,
            to: r.to,
            is_code: r.is_code != 0,
            ref_type: ref_type_from_i32(r.type_),
            user_defined: r.user_defined != 0,
        })
        .collect();
    unsafe {
        free(refs_ptr as *mut std::ffi::c_void);
    }
    result
}

unsafe fn addresses_from_ffi(addrs: *mut Address, count: usize) -> Vec<Address> {
    if addrs.is_null() || count == 0 {
        return Vec::new();
    }
    let result = unsafe { std::slice::from_raw_parts(addrs, count).to_vec() };
    unsafe {
        idax_sys::idax_free_addresses(addrs);
    }
    result
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// All references originating from `address`.
pub fn refs_from(address: Address) -> Result<Vec<Reference>> {
    unsafe {
        let mut count: usize = 0;
        let mut refs_ptr: *mut idax_sys::IdaxXref = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_refs_from(address, &mut refs_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::refs_from failed"));
        }
        Ok(refs_from_ffi(refs_ptr, count))
    }
}

/// All references targeting `address`.
pub fn refs_to(address: Address) -> Result<Vec<Reference>> {
    unsafe {
        let mut count: usize = 0;
        let mut refs_ptr: *mut idax_sys::IdaxXref = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_refs_to(address, &mut refs_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::refs_to failed"));
        }
        Ok(refs_from_ffi(refs_ptr, count))
    }
}

/// Only code reference addresses from `address`.
pub fn code_refs_from(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_code_refs_from(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::code_refs_from failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only code reference addresses to `address`.
pub fn code_refs_to(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_code_refs_to(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::code_refs_to failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only data reference addresses from `address`.
pub fn data_refs_from(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_data_refs_from(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::data_refs_from failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only data reference addresses to `address`.
pub fn data_refs_to(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_data_refs_to(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::data_refs_to failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// All references originating from `address` as a range-style snapshot.
pub fn refs_from_range(address: Address) -> Result<Vec<Reference>> {
    unsafe {
        let mut count: usize = 0;
        let mut refs_ptr: *mut idax_sys::IdaxXref = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_refs_from_range(address, &mut refs_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::refs_from_range failed"));
        }
        Ok(refs_from_ffi(refs_ptr, count))
    }
}

/// All references targeting `address` as a range-style snapshot.
pub fn refs_to_range(address: Address) -> Result<Vec<Reference>> {
    unsafe {
        let mut count: usize = 0;
        let mut refs_ptr: *mut idax_sys::IdaxXref = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_refs_to_range(address, &mut refs_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::refs_to_range failed"));
        }
        Ok(refs_from_ffi(refs_ptr, count))
    }
}

/// Only code reference addresses from `address` via range wrapper.
pub fn code_refs_from_range(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_code_refs_from_range(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error(
                "xref::code_refs_from_range failed",
            ));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only code reference addresses to `address` via range wrapper.
pub fn code_refs_to_range(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_code_refs_to_range(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::code_refs_to_range failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only data reference addresses from `address` via range wrapper.
pub fn data_refs_from_range(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_data_refs_from_range(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error(
                "xref::data_refs_from_range failed",
            ));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

/// Only data reference addresses to `address` via range wrapper.
pub fn data_refs_to_range(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut Address = std::ptr::null_mut();
        let ret = idax_sys::idax_xref_data_refs_to_range(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("xref::data_refs_to_range failed"));
        }
        Ok(addresses_from_ffi(addrs, count))
    }
}

// ---------------------------------------------------------------------------
// Typed filter helpers
// ---------------------------------------------------------------------------

/// Is the reference type a call?
pub fn is_call(ref_type: ReferenceType) -> bool {
    matches!(ref_type, ReferenceType::CallNear | ReferenceType::CallFar)
}

/// Is the reference type a jump?
pub fn is_jump(ref_type: ReferenceType) -> bool {
    matches!(ref_type, ReferenceType::JumpNear | ReferenceType::JumpFar)
}

/// Is the reference type a flow?
pub fn is_flow(ref_type: ReferenceType) -> bool {
    ref_type == ReferenceType::Flow
}

/// Is the reference type a data reference?
pub fn is_data(ref_type: ReferenceType) -> bool {
    matches!(
        ref_type,
        ReferenceType::Offset
            | ReferenceType::Read
            | ReferenceType::Write
            | ReferenceType::Text
            | ReferenceType::Informational
    )
}

/// Is the reference type a data read?
pub fn is_data_read(ref_type: ReferenceType) -> bool {
    ref_type == ReferenceType::Read
}

/// Is the reference type a data write?
pub fn is_data_write(ref_type: ReferenceType) -> bool {
    ref_type == ReferenceType::Write
}
