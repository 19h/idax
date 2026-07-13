//! Byte-level read, write, patch, and define operations.
//!
//! Mirrors the C++ `ida::data` namespace.
//! Integer and floating-point definition functions accept positive element
//! counts. Extended-real widths are resolved from active processor metadata;
//! structure definitions and `undefine` retain explicit byte units.

use crate::address::{Address, AddressSize, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use crate::types::TypeInfo;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Define 256-bit yword item(s) at address.
pub fn define_yword(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_yword(address, count) };
    error::int_to_status(ret, "define_yword failed")
}

/// Define 512-bit zword item(s) at address.
pub fn define_zword(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_zword(address, count) };
    error::int_to_status(ret, "define_zword failed")
}

/// Return the active processor's tbyte element size in bytes.
pub fn tbyte_element_size() -> Result<AddressSize> {
    let mut size = 0;
    let ret = unsafe { idax_sys::idax_data_tbyte_element_size(&mut size) };
    if ret != 0 {
        Err(error::consume_last_error("tbyte_element_size failed"))
    } else {
        Ok(size)
    }
}

/// Define active-processor-sized tbyte item(s) at address.
pub fn define_tbyte(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_tbyte(address, count) };
    error::int_to_status(ret, "define_tbyte failed")
}

/// Return the active processor's packed-real element size in bytes.
pub fn packed_real_element_size() -> Result<AddressSize> {
    let mut size = 0;
    let ret = unsafe { idax_sys::idax_data_packed_real_element_size(&mut size) };
    if ret != 0 {
        Err(error::consume_last_error("packed_real_element_size failed"))
    } else {
        Ok(size)
    }
}

/// Define active-processor-sized packed-real item(s) at address.
pub fn define_packed_real(address: Address, count: AddressSize) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_packed_real(address, count) };
    error::int_to_status(ret, "define_packed_real failed")
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

/// Define a string literal using an explicit byte length.
pub fn define_string(address: Address, length: AddressSize, string_type: i32) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_string(address, length, string_type) };
    error::int_to_status(ret, "define_string failed")
}

/// Define a structure item using an explicit byte length.
pub fn define_struct(address: Address, length: AddressSize, structure_id: u64) -> Status {
    let ret = unsafe { idax_sys::idax_data_define_struct(address, length, structure_id) };
    error::int_to_status(ret, "define_struct failed")
}

/// Opaque registered custom-data type identifier (`1..=0xFFFE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomDataTypeId(pub u16);

/// Opaque registered custom-data format identifier (`1..=0xFFFE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustomDataFormatId(pub u16);

/// Context supplied to custom format callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomDataFormatContext {
    pub address: Address,
    pub operand_index: i32,
    /// Zero means a standard or unknown type.
    pub type_id: CustomDataTypeId,
}

impl Default for CustomDataFormatContext {
    fn default() -> Self {
        Self {
            address: BAD_ADDRESS,
            operand_index: -1,
            type_id: CustomDataTypeId(0),
        }
    }
}

pub type CustomDataCreationFilter =
    Arc<dyn Fn(Address, AddressSize) -> bool + Send + Sync + 'static>;
pub type CustomDataSizeCallback =
    Arc<dyn Fn(Address, AddressSize) -> AddressSize + Send + Sync + 'static>;
pub type CustomDataRenderCallback =
    Arc<dyn Fn(&[u8], &CustomDataFormatContext) -> Result<String> + Send + Sync + 'static>;
pub type CustomDataScanCallback =
    Arc<dyn Fn(&str, &CustomDataFormatContext) -> Result<Vec<u8>> + Send + Sync + 'static>;
pub type CustomDataAnalyzeCallback = Arc<dyn Fn(&CustomDataFormatContext) + Send + Sync + 'static>;

/// Owned custom-data type registration definition.
#[derive(Clone)]
pub struct CustomDataTypeDefinition {
    pub name: String,
    pub menu_name: String,
    pub hotkey: String,
    pub assembler_keyword: String,
    /// Exact fixed width, or minimum width when `calculate_size` is present.
    pub value_size: AddressSize,
    pub allow_duplicates: bool,
    pub may_create_at: Option<CustomDataCreationFilter>,
    pub calculate_size: Option<CustomDataSizeCallback>,
}

impl Default for CustomDataTypeDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            menu_name: String::new(),
            hotkey: String::new(),
            assembler_keyword: String::new(),
            value_size: 0,
            allow_duplicates: true,
            may_create_at: None,
            calculate_size: None,
        }
    }
}

/// Copied custom-data type metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataTypeInfo {
    pub id: CustomDataTypeId,
    pub name: String,
    pub menu_name: String,
    pub hotkey: String,
    pub assembler_keyword: String,
    pub value_size: AddressSize,
    pub allow_duplicates: bool,
    pub visible_in_menu: bool,
    pub has_creation_filter: bool,
    pub variable_size: bool,
}

/// Owned custom-data format registration definition.
#[derive(Clone, Default)]
pub struct CustomDataFormatDefinition {
    pub name: String,
    pub menu_name: String,
    pub hotkey: String,
    /// Zero accepts any value width.
    pub value_size: AddressSize,
    pub text_width: i32,
    pub render: Option<CustomDataRenderCallback>,
    pub scan: Option<CustomDataScanCallback>,
    pub analyze: Option<CustomDataAnalyzeCallback>,
}

/// Copied custom-data format metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomDataFormatInfo {
    pub id: CustomDataFormatId,
    pub name: String,
    pub menu_name: String,
    pub hotkey: String,
    pub value_size: AddressSize,
    pub text_width: i32,
    pub visible_in_menu: bool,
    pub can_render: bool,
    pub can_scan: bool,
    pub can_analyze: bool,
}

/// Custom type/format identity stored on an existing item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomDataItemInfo {
    pub type_id: CustomDataTypeId,
    pub format_id: CustomDataFormatId,
    pub byte_length: AddressSize,
}

struct TypeCallbackContext {
    may_create_at: Option<CustomDataCreationFilter>,
    calculate_size: Option<CustomDataSizeCallback>,
}

struct FormatCallbackContext {
    render: Option<CustomDataRenderCallback>,
    scan: Option<CustomDataScanCallback>,
    analyze: Option<CustomDataAnalyzeCallback>,
}

fn type_callback_contexts() -> &'static Mutex<HashMap<u16, Arc<TypeCallbackContext>>> {
    static CONTEXTS: OnceLock<Mutex<HashMap<u16, Arc<TypeCallbackContext>>>> = OnceLock::new();
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn format_callback_contexts() -> &'static Mutex<HashMap<u16, Arc<FormatCallbackContext>>> {
    static CONTEXTS: OnceLock<Mutex<HashMap<u16, Arc<FormatCallbackContext>>>> = OnceLock::new();
    CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn retain_callback_context<T>(user_data: *mut c_void) -> Option<Arc<T>> {
    if user_data.is_null() {
        return None;
    }
    let pointer = user_data.cast::<T>();
    unsafe { Arc::increment_strong_count(pointer) };
    Some(unsafe { Arc::from_raw(pointer) })
}

unsafe extern "C" fn custom_type_may_create_trampoline(
    user_data: *mut c_void,
    address: u64,
    byte_length: u64,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(context) = (unsafe { retain_callback_context::<TypeCallbackContext>(user_data) })
        else {
            return 0;
        };
        context
            .may_create_at
            .as_ref()
            .is_some_and(|callback| callback(address, byte_length)) as i32
    }))
    .unwrap_or(0)
}

unsafe extern "C" fn custom_type_size_trampoline(
    user_data: *mut c_void,
    address: u64,
    maximum_size: u64,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(context) = (unsafe { retain_callback_context::<TypeCallbackContext>(user_data) })
        else {
            return 0;
        };
        context
            .calculate_size
            .as_ref()
            .map_or(0, |callback| callback(address, maximum_size))
    }))
    .unwrap_or(0)
}

unsafe fn set_callback_buffer(
    output: *mut idax_sys::IdaxCustomDataCallbackBuffer,
    bytes: Vec<u8>,
) -> bool {
    if output.is_null() {
        return false;
    }
    if bytes.is_empty() {
        unsafe {
            (*output).data = std::ptr::null_mut();
            (*output).length = 0;
        }
        return true;
    }
    let mut boxed = bytes.into_boxed_slice();
    unsafe {
        (*output).data = boxed.as_mut_ptr();
        (*output).length = boxed.len();
    }
    std::mem::forget(boxed);
    true
}

unsafe extern "C" fn custom_data_release_buffer_trampoline(
    _user_data: *mut c_void,
    data: *mut u8,
    length: usize,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if data.is_null() {
            return;
        }
        let slice = std::ptr::slice_from_raw_parts_mut(data, length);
        drop(unsafe { Box::<[u8]>::from_raw(slice) });
    }));
}

unsafe extern "C" fn custom_format_render_trampoline(
    user_data: *mut c_void,
    value: *const u8,
    value_length: usize,
    address: u64,
    operand_index: i32,
    type_id: u16,
    output: *mut idax_sys::IdaxCustomDataCallbackBuffer,
    error_output: *mut idax_sys::IdaxCustomDataCallbackBuffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(context) =
            (unsafe { retain_callback_context::<FormatCallbackContext>(user_data) })
        else {
            return 0;
        };
        let Some(callback) = context.render.as_ref() else {
            return 0;
        };
        if value.is_null() && value_length != 0 {
            unsafe { set_callback_buffer(error_output, b"render value pointer is null".to_vec()) };
            return 0;
        }
        let bytes = if value_length == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(value, value_length) }
        };
        let context = CustomDataFormatContext {
            address,
            operand_index,
            type_id: CustomDataTypeId(type_id),
        };
        match callback(bytes, &context) {
            Ok(text) => unsafe { set_callback_buffer(output, text.into_bytes()) as i32 },
            Err(error) => {
                unsafe { set_callback_buffer(error_output, error.message.into_bytes()) };
                0
            }
        }
    }))
    .unwrap_or(0)
}

unsafe extern "C" fn custom_format_scan_trampoline(
    user_data: *mut c_void,
    text: *const std::ffi::c_char,
    address: u64,
    operand_index: i32,
    output: *mut idax_sys::IdaxCustomDataCallbackBuffer,
    error_output: *mut idax_sys::IdaxCustomDataCallbackBuffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(context) =
            (unsafe { retain_callback_context::<FormatCallbackContext>(user_data) })
        else {
            return 0;
        };
        let Some(callback) = context.scan.as_ref() else {
            return 0;
        };
        if text.is_null() {
            unsafe { set_callback_buffer(error_output, b"scan text pointer is null".to_vec()) };
            return 0;
        }
        let text = unsafe { CStr::from_ptr(text) }.to_string_lossy();
        let context = CustomDataFormatContext {
            address,
            operand_index,
            type_id: CustomDataTypeId(0),
        };
        match callback(&text, &context) {
            Ok(bytes) => unsafe { set_callback_buffer(output, bytes) as i32 },
            Err(error) => {
                unsafe { set_callback_buffer(error_output, error.message.into_bytes()) };
                0
            }
        }
    }))
    .unwrap_or(0)
}

unsafe extern "C" fn custom_format_analyze_trampoline(
    user_data: *mut c_void,
    address: u64,
    operand_index: i32,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(context) =
            (unsafe { retain_callback_context::<FormatCallbackContext>(user_data) })
        else {
            return;
        };
        if let Some(callback) = context.analyze.as_ref() {
            callback(&CustomDataFormatContext {
                address,
                operand_index,
                type_id: CustomDataTypeId(0),
            });
        }
    }));
}

fn ffi_string(value: *const std::ffi::c_char) -> String {
    if value.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

fn convert_custom_type_info(raw: &idax_sys::IdaxCustomDataTypeInfo) -> CustomDataTypeInfo {
    CustomDataTypeInfo {
        id: CustomDataTypeId(raw.id),
        name: ffi_string(raw.name),
        menu_name: ffi_string(raw.menu_name),
        hotkey: ffi_string(raw.hotkey),
        assembler_keyword: ffi_string(raw.assembler_keyword),
        value_size: raw.value_size,
        allow_duplicates: raw.allow_duplicates != 0,
        visible_in_menu: raw.visible_in_menu != 0,
        has_creation_filter: raw.has_creation_filter != 0,
        variable_size: raw.variable_size != 0,
    }
}

fn convert_custom_format_info(raw: &idax_sys::IdaxCustomDataFormatInfo) -> CustomDataFormatInfo {
    CustomDataFormatInfo {
        id: CustomDataFormatId(raw.id),
        name: ffi_string(raw.name),
        menu_name: ffi_string(raw.menu_name),
        hotkey: ffi_string(raw.hotkey),
        value_size: raw.value_size,
        text_width: raw.text_width,
        visible_in_menu: raw.visible_in_menu != 0,
        can_render: raw.can_render != 0,
        can_scan: raw.can_scan != 0,
        can_analyze: raw.can_analyze != 0,
    }
}

fn required_c_string(value: &str, field: &str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::validation(format!("{field} contains an interior null")))
}

fn optional_c_string(value: &str, field: &str) -> Result<Option<CString>> {
    if value.is_empty() {
        Ok(None)
    } else {
        required_c_string(value, field).map(Some)
    }
}

/// Register a custom data type. Explicit unregister is required before unload.
pub fn register_custom_data_type(
    definition: &CustomDataTypeDefinition,
) -> Result<CustomDataTypeId> {
    let name = required_c_string(&definition.name, "custom type name")?;
    let menu_name = optional_c_string(&definition.menu_name, "custom type menu name")?;
    let hotkey = optional_c_string(&definition.hotkey, "custom type hotkey")?;
    let assembler_keyword = optional_c_string(
        &definition.assembler_keyword,
        "custom type assembler keyword",
    )?;
    let context = Arc::new(TypeCallbackContext {
        may_create_at: definition.may_create_at.clone(),
        calculate_size: definition.calculate_size.clone(),
    });
    let raw = idax_sys::IdaxCustomDataTypeDefinition {
        name: name.as_ptr(),
        menu_name: menu_name.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
        hotkey: hotkey.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
        assembler_keyword: assembler_keyword
            .as_ref()
            .map_or(std::ptr::null(), |v| v.as_ptr()),
        value_size: definition.value_size,
        allow_duplicates: definition.allow_duplicates as i32,
        user_data: Arc::as_ptr(&context).cast_mut().cast(),
        may_create_at: definition
            .may_create_at
            .as_ref()
            .map(|_| custom_type_may_create_trampoline as _),
        calculate_size: definition
            .calculate_size
            .as_ref()
            .map(|_| custom_type_size_trampoline as _),
    };
    let mut id = 0u16;
    let ret = unsafe { idax_sys::idax_data_register_custom_type(&raw, &mut id) };
    if ret != 0 {
        return Err(error::consume_last_error(
            "register_custom_data_type failed",
        ));
    }
    type_callback_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id, context);
    Ok(CustomDataTypeId(id))
}

pub fn unregister_custom_data_type(type_id: CustomDataTypeId) -> Status {
    let ret = unsafe { idax_sys::idax_data_unregister_custom_type(type_id.0) };
    type_callback_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&type_id.0);
    error::int_to_status(ret, "unregister_custom_data_type failed")
}

pub fn custom_data_type(type_id: CustomDataTypeId) -> Result<CustomDataTypeInfo> {
    let mut raw = idax_sys::IdaxCustomDataTypeInfo::default();
    let ret = unsafe { idax_sys::idax_data_custom_type(type_id.0, &mut raw) };
    if ret != 0 {
        return Err(error::consume_last_error("custom_data_type failed"));
    }
    let info = convert_custom_type_info(&raw);
    unsafe { idax_sys::idax_data_custom_type_info_free(&mut raw) };
    Ok(info)
}

pub fn find_custom_data_type(name: &str) -> Result<CustomDataTypeId> {
    let name = required_c_string(name, "custom type name")?;
    let mut id = 0u16;
    let ret = unsafe { idax_sys::idax_data_find_custom_type(name.as_ptr(), &mut id) };
    if ret != 0 {
        Err(error::consume_last_error("find_custom_data_type failed"))
    } else {
        Ok(CustomDataTypeId(id))
    }
}

pub fn custom_data_types(
    minimum_size: AddressSize,
    maximum_size: AddressSize,
) -> Result<Vec<CustomDataTypeInfo>> {
    let mut raw = std::ptr::null_mut();
    let mut count = 0usize;
    let ret = unsafe {
        idax_sys::idax_data_custom_types(minimum_size, maximum_size, &mut raw, &mut count)
    };
    if ret != 0 {
        return Err(error::consume_last_error("custom_data_types failed"));
    }
    let infos = if raw.is_null() || count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(raw, count) }
            .iter()
            .map(convert_custom_type_info)
            .collect()
    };
    unsafe { idax_sys::idax_data_custom_type_infos_free(raw, count) };
    Ok(infos)
}

/// Register a custom data format. Explicit unregister is required before unload.
pub fn register_custom_data_format(
    definition: &CustomDataFormatDefinition,
) -> Result<CustomDataFormatId> {
    let name = required_c_string(&definition.name, "custom format name")?;
    let menu_name = optional_c_string(&definition.menu_name, "custom format menu name")?;
    let hotkey = optional_c_string(&definition.hotkey, "custom format hotkey")?;
    let context = Arc::new(FormatCallbackContext {
        render: definition.render.clone(),
        scan: definition.scan.clone(),
        analyze: definition.analyze.clone(),
    });
    let raw = idax_sys::IdaxCustomDataFormatDefinition {
        name: name.as_ptr(),
        menu_name: menu_name.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
        hotkey: hotkey.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
        value_size: definition.value_size,
        text_width: definition.text_width,
        user_data: Arc::as_ptr(&context).cast_mut().cast(),
        render: definition
            .render
            .as_ref()
            .map(|_| custom_format_render_trampoline as _),
        scan: definition
            .scan
            .as_ref()
            .map(|_| custom_format_scan_trampoline as _),
        analyze: definition
            .analyze
            .as_ref()
            .map(|_| custom_format_analyze_trampoline as _),
        release_buffer: Some(custom_data_release_buffer_trampoline),
    };
    let mut id = 0u16;
    let ret = unsafe { idax_sys::idax_data_register_custom_format(&raw, &mut id) };
    if ret != 0 {
        return Err(error::consume_last_error(
            "register_custom_data_format failed",
        ));
    }
    format_callback_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id, context);
    Ok(CustomDataFormatId(id))
}

pub fn unregister_custom_data_format(format_id: CustomDataFormatId) -> Status {
    let ret = unsafe { idax_sys::idax_data_unregister_custom_format(format_id.0) };
    format_callback_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&format_id.0);
    error::int_to_status(ret, "unregister_custom_data_format failed")
}

pub fn custom_data_format(format_id: CustomDataFormatId) -> Result<CustomDataFormatInfo> {
    let mut raw = idax_sys::IdaxCustomDataFormatInfo::default();
    let ret = unsafe { idax_sys::idax_data_custom_format(format_id.0, &mut raw) };
    if ret != 0 {
        return Err(error::consume_last_error("custom_data_format failed"));
    }
    let info = convert_custom_format_info(&raw);
    unsafe { idax_sys::idax_data_custom_format_info_free(&mut raw) };
    Ok(info)
}

pub fn find_custom_data_format(name: &str) -> Result<CustomDataFormatId> {
    let name = required_c_string(name, "custom format name")?;
    let mut id = 0u16;
    let ret = unsafe { idax_sys::idax_data_find_custom_format(name.as_ptr(), &mut id) };
    if ret != 0 {
        Err(error::consume_last_error("find_custom_data_format failed"))
    } else {
        Ok(CustomDataFormatId(id))
    }
}

fn custom_format_list(
    call: impl FnOnce(*mut *mut idax_sys::IdaxCustomDataFormatInfo, *mut usize) -> i32,
) -> Result<Vec<CustomDataFormatInfo>> {
    let mut raw = std::ptr::null_mut();
    let mut count = 0usize;
    let ret = call(&mut raw, &mut count);
    if ret != 0 {
        return Err(error::consume_last_error("custom data format list failed"));
    }
    let infos = if raw.is_null() || count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(raw, count) }
            .iter()
            .map(convert_custom_format_info)
            .collect()
    };
    unsafe { idax_sys::idax_data_custom_format_infos_free(raw, count) };
    Ok(infos)
}

pub fn custom_data_formats(type_id: CustomDataTypeId) -> Result<Vec<CustomDataFormatInfo>> {
    custom_format_list(|out, count| unsafe {
        idax_sys::idax_data_custom_formats(type_id.0, out, count)
    })
}

pub fn standard_custom_data_formats() -> Result<Vec<CustomDataFormatInfo>> {
    custom_format_list(|out, count| unsafe {
        idax_sys::idax_data_standard_custom_formats(out, count)
    })
}

pub fn attach_custom_data_format(
    type_id: CustomDataTypeId,
    format_id: CustomDataFormatId,
) -> Status {
    let ret = unsafe { idax_sys::idax_data_attach_custom_format(type_id.0, format_id.0) };
    error::int_to_status(ret, "attach_custom_data_format failed")
}

pub fn detach_custom_data_format(
    type_id: CustomDataTypeId,
    format_id: CustomDataFormatId,
) -> Status {
    let ret = unsafe { idax_sys::idax_data_detach_custom_format(type_id.0, format_id.0) };
    error::int_to_status(ret, "detach_custom_data_format failed")
}

pub fn is_custom_data_format_attached(
    type_id: CustomDataTypeId,
    format_id: CustomDataFormatId,
) -> Result<bool> {
    let mut attached = 0;
    let ret = unsafe {
        idax_sys::idax_data_is_custom_format_attached(type_id.0, format_id.0, &mut attached)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "is_custom_data_format_attached failed",
        ))
    } else {
        Ok(attached != 0)
    }
}

pub fn attach_custom_data_format_to_standard_types(format_id: CustomDataFormatId) -> Status {
    let ret = unsafe { idax_sys::idax_data_attach_custom_format_to_standard_types(format_id.0) };
    error::int_to_status(ret, "attach custom format to standard types failed")
}

pub fn detach_custom_data_format_from_standard_types(format_id: CustomDataFormatId) -> Status {
    let ret = unsafe { idax_sys::idax_data_detach_custom_format_from_standard_types(format_id.0) };
    error::int_to_status(ret, "detach custom format from standard types failed")
}

pub fn is_custom_data_format_attached_to_standard_types(
    format_id: CustomDataFormatId,
) -> Result<bool> {
    let mut attached = 0;
    let ret = unsafe {
        idax_sys::idax_data_is_custom_format_attached_to_standard_types(format_id.0, &mut attached)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "standard custom format attachment query failed",
        ))
    } else {
        Ok(attached != 0)
    }
}

pub fn custom_data_item_size(
    type_id: CustomDataTypeId,
    address: Address,
    maximum_size: AddressSize,
) -> Result<AddressSize> {
    let mut size = 0;
    let ret = unsafe {
        idax_sys::idax_data_custom_item_size(type_id.0, address, maximum_size, &mut size)
    };
    if ret != 0 {
        Err(error::consume_last_error("custom_data_item_size failed"))
    } else {
        Ok(size)
    }
}

pub fn define_custom(
    address: Address,
    byte_length: AddressSize,
    type_id: CustomDataTypeId,
    format_id: CustomDataFormatId,
) -> Status {
    let ret =
        unsafe { idax_sys::idax_data_define_custom(address, byte_length, type_id.0, format_id.0) };
    error::int_to_status(ret, "define_custom failed")
}

pub fn define_custom_inferred(
    address: Address,
    type_id: CustomDataTypeId,
    format_id: CustomDataFormatId,
    maximum_size: AddressSize,
) -> Status {
    let ret = unsafe {
        idax_sys::idax_data_define_custom_inferred(address, type_id.0, format_id.0, maximum_size)
    };
    error::int_to_status(ret, "define_custom_inferred failed")
}

pub fn custom_data_at(address: Address) -> Result<CustomDataItemInfo> {
    let mut raw = idax_sys::IdaxCustomDataItemInfo::default();
    let ret = unsafe { idax_sys::idax_data_custom_at(address, &mut raw) };
    if ret != 0 {
        Err(error::consume_last_error("custom_data_at failed"))
    } else {
        Ok(CustomDataItemInfo {
            type_id: CustomDataTypeId(raw.type_id),
            format_id: CustomDataFormatId(raw.format_id),
            byte_length: raw.byte_length,
        })
    }
}

pub fn render_custom_data(
    format_id: CustomDataFormatId,
    value: &[u8],
    context: CustomDataFormatContext,
) -> Result<String> {
    let mut output = std::ptr::null_mut();
    let ret = unsafe {
        idax_sys::idax_data_render_custom(
            format_id.0,
            value.as_ptr(),
            value.len(),
            context.address,
            context.operand_index,
            context.type_id.0,
            &mut output,
        )
    };
    if ret != 0 {
        return Err(error::consume_last_error("render_custom_data failed"));
    }
    let text = ffi_string(output);
    unsafe { idax_sys::idax_free_string(output) };
    Ok(text)
}

pub fn scan_custom_data(
    format_id: CustomDataFormatId,
    text: &str,
    context: CustomDataFormatContext,
) -> Result<Vec<u8>> {
    let text = required_c_string(text, "custom scan text")?;
    let mut output = std::ptr::null_mut();
    let mut length = 0usize;
    let ret = unsafe {
        idax_sys::idax_data_scan_custom(
            format_id.0,
            text.as_ptr(),
            context.address,
            context.operand_index,
            &mut output,
            &mut length,
        )
    };
    if ret != 0 {
        return Err(error::consume_last_error("scan_custom_data failed"));
    }
    let bytes = if output.is_null() || length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output, length).to_vec() }
    };
    unsafe { idax_sys::idax_free_bytes(output) };
    Ok(bytes)
}

pub fn analyze_custom_data(
    format_id: CustomDataFormatId,
    context: CustomDataFormatContext,
) -> Status {
    let ret = unsafe {
        idax_sys::idax_data_analyze_custom(
            format_id.0,
            context.address,
            context.operand_index,
            context.type_id.0,
        )
    };
    error::int_to_status(ret, "analyze_custom_data failed")
}

/// Undefine a byte count beginning at address.
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
