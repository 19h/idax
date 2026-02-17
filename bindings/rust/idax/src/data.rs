//! Byte-level read, write, patch, and define operations.
//!
//! Mirrors the C++ `ida::data` namespace.

use crate::address::{Address, AddressSize, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use crate::types::TypeInfo;
use std::ffi::CString;

/// Semantic typed value used by `read_typed` and `write_typed`.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    UnsignedInteger(u64),
    SignedInteger(i64),
    FloatingPoint(f64),
    Pointer(Address),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<TypedValue>),
}

struct OwnedTypedValue {
    raw: idax_sys::IdaxDataTypedValue,
    string_value: Option<CString>,
    bytes: Vec<u8>,
    element_owners: Vec<OwnedTypedValue>,
    element_raws: Vec<idax_sys::IdaxDataTypedValue>,
}

fn build_owned_typed_value(value: &TypedValue) -> Result<OwnedTypedValue> {
    let mut owned = OwnedTypedValue {
        raw: idax_sys::IdaxDataTypedValue::default(),
        string_value: None,
        bytes: Vec::new(),
        element_owners: Vec::new(),
        element_raws: Vec::new(),
    };

    match value {
        TypedValue::UnsignedInteger(v) => {
            owned.raw.kind = 0;
            owned.raw.unsigned_value = *v;
        }
        TypedValue::SignedInteger(v) => {
            owned.raw.kind = 1;
            owned.raw.signed_value = *v;
        }
        TypedValue::FloatingPoint(v) => {
            owned.raw.kind = 2;
            owned.raw.floating_value = *v;
        }
        TypedValue::Pointer(v) => {
            owned.raw.kind = 3;
            owned.raw.pointer_value = *v;
        }
        TypedValue::String(v) => {
            owned.raw.kind = 4;
            let c = CString::new(v.as_str())
                .map_err(|_| Error::validation("typed string contains interior null"))?;
            owned.raw.string_value = c.as_ptr() as *mut std::ffi::c_char;
            owned.string_value = Some(c);
        }
        TypedValue::Bytes(v) => {
            owned.raw.kind = 5;
            owned.bytes = v.clone();
            if !owned.bytes.is_empty() {
                owned.raw.bytes = owned.bytes.as_mut_ptr();
                owned.raw.byte_count = owned.bytes.len();
            }
        }
        TypedValue::Array(values) => {
            owned.raw.kind = 6;
            owned.element_owners.reserve(values.len());
            owned.element_raws.reserve(values.len());
            for item in values {
                let child = build_owned_typed_value(item)?;
                owned.element_raws.push(child.raw);
                owned.element_owners.push(child);
            }
            if !owned.element_raws.is_empty() {
                owned.raw.elements = owned.element_raws.as_mut_ptr();
                owned.raw.element_count = owned.element_raws.len();
            }
        }
    }

    Ok(owned)
}

fn raw_typed_value_to_rust(raw: &idax_sys::IdaxDataTypedValue) -> Result<TypedValue> {
    match raw.kind {
        0 => Ok(TypedValue::UnsignedInteger(raw.unsigned_value)),
        1 => Ok(TypedValue::SignedInteger(raw.signed_value)),
        2 => Ok(TypedValue::FloatingPoint(raw.floating_value)),
        3 => Ok(TypedValue::Pointer(raw.pointer_value)),
        4 => {
            let s = if raw.string_value.is_null() {
                String::new()
            } else {
                unsafe {
                    std::ffi::CStr::from_ptr(raw.string_value)
                        .to_string_lossy()
                        .into_owned()
                }
            };
            Ok(TypedValue::String(s))
        }
        5 => {
            let bytes = if raw.bytes.is_null() || raw.byte_count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(raw.bytes, raw.byte_count).to_vec() }
            };
            Ok(TypedValue::Bytes(bytes))
        }
        6 => {
            if raw.element_count > 0 && raw.elements.is_null() {
                return Err(Error::internal("typed value array pointer is null"));
            }
            let mut values = Vec::with_capacity(raw.element_count);
            for i in 0..raw.element_count {
                let child = unsafe { &*raw.elements.add(i) };
                values.push(raw_typed_value_to_rust(child)?);
            }
            Ok(TypedValue::Array(values))
        }
        k => Err(Error::validation(format!(
            "invalid typed value kind: {}",
            k
        ))),
    }
}

// ---------------------------------------------------------------------------
// Read family
// ---------------------------------------------------------------------------

/// Read a single byte from the database.
pub fn read_byte(address: Address) -> Result<u8> {
    let mut value: u8 = 0;
    let ret = unsafe { idax_sys::idax_data_read_byte(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("read_byte failed"))
    } else {
        Ok(value)
    }
}

/// Read a 16-bit word from the database.
pub fn read_word(address: Address) -> Result<u16> {
    let mut value: u16 = 0;
    let ret = unsafe { idax_sys::idax_data_read_word(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("read_word failed"))
    } else {
        Ok(value)
    }
}

/// Read a 32-bit dword from the database.
pub fn read_dword(address: Address) -> Result<u32> {
    let mut value: u32 = 0;
    let ret = unsafe { idax_sys::idax_data_read_dword(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("read_dword failed"))
    } else {
        Ok(value)
    }
}

/// Read a 64-bit qword from the database.
pub fn read_qword(address: Address) -> Result<u64> {
    let mut value: u64 = 0;
    let ret = unsafe { idax_sys::idax_data_read_qword(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("read_qword failed"))
    } else {
        Ok(value)
    }
}

/// Read `count` bytes from the database starting at `address`.
pub fn read_bytes(address: Address, count: AddressSize) -> Result<Vec<u8>> {
    unsafe {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let ret = idax_sys::idax_data_read_bytes(address, count, &mut ptr, &mut out_len);
        if ret != 0 {
            return Err(error::consume_last_error("read_bytes failed"));
        }
        let result = if ptr.is_null() || out_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(ptr, out_len).to_vec()
        };
        if !ptr.is_null() {
            idax_sys::idax_free_bytes(ptr);
        }
        Ok(result)
    }
}

/// Read a string literal as UTF-8 text.
pub fn read_string(address: Address, max_length: AddressSize) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_data_read_string(address, max_length, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("read_string failed"));
        }
        error::cstr_to_string_free(out, "read_string returned null")
    }
}

/// Read a value at `address` interpreted using `ty` semantics.
pub fn read_typed(address: Address, ty: &TypeInfo) -> Result<TypedValue> {
    unsafe {
        let mut raw = idax_sys::IdaxDataTypedValue::default();
        let ret = idax_sys::idax_data_read_typed(address, ty.as_raw(), &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("read_typed failed"));
        }
        let value = raw_typed_value_to_rust(&raw);
        idax_sys::idax_data_typed_value_free(&mut raw);
        value
    }
}

// ---------------------------------------------------------------------------
// Write family
// ---------------------------------------------------------------------------

/// Write a single byte to the database.
pub fn write_byte(address: Address, value: u8) -> Status {
    let ret = unsafe { idax_sys::idax_data_write_byte(address, value) };
    error::int_to_status(ret, "write_byte failed")
}

/// Write a 16-bit word to the database.
pub fn write_word(address: Address, value: u16) -> Status {
    let ret = unsafe { idax_sys::idax_data_write_word(address, value) };
    error::int_to_status(ret, "write_word failed")
}

/// Write a 32-bit dword to the database.
pub fn write_dword(address: Address, value: u32) -> Status {
    let ret = unsafe { idax_sys::idax_data_write_dword(address, value) };
    error::int_to_status(ret, "write_dword failed")
}

/// Write a 64-bit qword to the database.
pub fn write_qword(address: Address, value: u64) -> Status {
    let ret = unsafe { idax_sys::idax_data_write_qword(address, value) };
    error::int_to_status(ret, "write_qword failed")
}

/// Write bytes to the database.
pub fn write_bytes(address: Address, bytes: &[u8]) -> Status {
    let ret = unsafe { idax_sys::idax_data_write_bytes(address, bytes.as_ptr(), bytes.len()) };
    error::int_to_status(ret, "write_bytes failed")
}

/// Write a semantic typed value at `address` using `ty`.
pub fn write_typed(address: Address, ty: &TypeInfo, value: &TypedValue) -> Status {
    let owned = build_owned_typed_value(value)?;
    let ret = unsafe { idax_sys::idax_data_write_typed(address, ty.as_raw(), &owned.raw) };
    error::int_to_status(ret, "write_typed failed")
}

// ---------------------------------------------------------------------------
// Patch family
// ---------------------------------------------------------------------------

/// Patch a single byte (original value preserved for revert).
pub fn patch_byte(address: Address, value: u8) -> Status {
    let ret = unsafe { idax_sys::idax_data_patch_byte(address, value) };
    error::int_to_status(ret, "patch_byte failed")
}

/// Patch a 16-bit word.
pub fn patch_word(address: Address, value: u16) -> Status {
    let ret = unsafe { idax_sys::idax_data_patch_word(address, value) };
    error::int_to_status(ret, "patch_word failed")
}

/// Patch a 32-bit dword.
pub fn patch_dword(address: Address, value: u32) -> Status {
    let ret = unsafe { idax_sys::idax_data_patch_dword(address, value) };
    error::int_to_status(ret, "patch_dword failed")
}

/// Patch a 64-bit qword.
pub fn patch_qword(address: Address, value: u64) -> Status {
    let ret = unsafe { idax_sys::idax_data_patch_qword(address, value) };
    error::int_to_status(ret, "patch_qword failed")
}

/// Patch bytes.
pub fn patch_bytes(address: Address, bytes: &[u8]) -> Status {
    let ret = unsafe { idax_sys::idax_data_patch_bytes(address, bytes.as_ptr(), bytes.len()) };
    error::int_to_status(ret, "patch_bytes failed")
}

/// Revert a patched byte back to its original value.
pub fn revert_patch(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_data_revert_patch(address) };
    error::int_to_status(ret, "revert_patch failed")
}

/// Revert patched bytes in `[address, address + count)`.
pub fn revert_patches(address: Address, count: AddressSize) -> Result<AddressSize> {
    let mut reverted: AddressSize = 0;
    let ret = unsafe { idax_sys::idax_data_revert_patches(address, count, &mut reverted) };
    if ret != 0 {
        Err(error::consume_last_error("revert_patches failed"))
    } else {
        Ok(reverted)
    }
}

// ---------------------------------------------------------------------------
// Original (pre-patch) values
// ---------------------------------------------------------------------------

/// Read the original (pre-patch) byte value.
pub fn original_byte(address: Address) -> Result<u8> {
    let mut value: u8 = 0;
    let ret = unsafe { idax_sys::idax_data_original_byte(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("original_byte failed"))
    } else {
        Ok(value)
    }
}

/// Read the original (pre-patch) word value.
pub fn original_word(address: Address) -> Result<u16> {
    let mut value: u16 = 0;
    let ret = unsafe { idax_sys::idax_data_original_word(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("original_word failed"))
    } else {
        Ok(value)
    }
}

/// Read the original (pre-patch) dword value.
pub fn original_dword(address: Address) -> Result<u32> {
    let mut value: u32 = 0;
    let ret = unsafe { idax_sys::idax_data_original_dword(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("original_dword failed"))
    } else {
        Ok(value)
    }
}

/// Read the original (pre-patch) qword value.
pub fn original_qword(address: Address) -> Result<u64> {
    let mut value: u64 = 0;
    let ret = unsafe { idax_sys::idax_data_original_qword(address, &mut value) };
    if ret != 0 {
        Err(error::consume_last_error("original_qword failed"))
    } else {
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Define / undefine items
// ---------------------------------------------------------------------------

/// Define byte item(s) at address.
pub fn define_byte(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_byte(address, count) };
    error::int_to_status(ret, "define_byte failed")
}

/// Define word item(s) at address.
pub fn define_word(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_word(address, count) };
    error::int_to_status(ret, "define_word failed")
}

/// Define dword item(s) at address.
pub fn define_dword(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_dword(address, count) };
    error::int_to_status(ret, "define_dword failed")
}

/// Define qword item(s) at address.
pub fn define_qword(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_qword(address, count) };
    error::int_to_status(ret, "define_qword failed")
}

/// Define oword item(s) at address.
pub fn define_oword(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_oword(address, count) };
    error::int_to_status(ret, "define_oword failed")
}

/// Define tbyte item(s) at address.
pub fn define_tbyte(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_tbyte(address, count) };
    error::int_to_status(ret, "define_tbyte failed")
}

/// Define float item(s) at address.
pub fn define_float(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_float(address, count) };
    error::int_to_status(ret, "define_float failed")
}

/// Define double item(s) at address.
pub fn define_double(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_double(address, count) };
    error::int_to_status(ret, "define_double failed")
}

/// Define a string literal at address.
pub fn define_string(address: Address, length: AddressSize, string_type: i32) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_string(address, length, string_type) };
    error::int_to_status(ret, "define_string failed")
}

/// Define a structure item at address.
pub fn define_struct(address: Address, length: AddressSize, structure_id: u64) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_struct(address, length, structure_id) };
    error::int_to_status(ret, "define_struct failed")
}

/// Undefine items at address.
pub fn undefine(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_undefine(address, count) };
    error::int_to_status(ret, "undefine failed")
}

// ---------------------------------------------------------------------------
// Binary pattern search
// ---------------------------------------------------------------------------

/// Search for an IDA binary pattern string (e.g. "55 48 89 E5").
pub fn find_binary_pattern(
    start: Address,
    end: Address,
    pattern: &str,
    forward: bool,
) -> Result<Address> {
    let c_pattern = CString::new(pattern).map_err(|_| Error::validation("invalid pattern"))?;
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe {
        idax_sys::idax_data_find_binary_pattern(
            start,
            end,
            c_pattern.as_ptr(),
            forward as i32,
            &mut out,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error("find_binary_pattern: not found"))
    } else {
        Ok(out)
    }
}
