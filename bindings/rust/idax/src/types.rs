//! Type system: construction, introspection, and application.
//!
//! Mirrors the C++ `ida::type` namespace. `TypeInfo` uses `Drop` for RAII cleanup.

use crate::address::Address;
use crate::error::{self, Error, Result, Status};
use std::ffi::{c_char, c_void, CStr, CString};

/// Calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CallingConvention {
    Unknown = 0,
    Cdecl = 1,
    Stdcall = 2,
    Pascal = 3,
    Fastcall = 4,
    Thiscall = 5,
    Swift = 6,
    Golang = 7,
    UserDefined = 8,
}

fn calling_convention_from_i32(value: i32) -> Result<CallingConvention> {
    match value {
        0 => Ok(CallingConvention::Unknown),
        1 => Ok(CallingConvention::Cdecl),
        2 => Ok(CallingConvention::Stdcall),
        3 => Ok(CallingConvention::Pascal),
        4 => Ok(CallingConvention::Fastcall),
        5 => Ok(CallingConvention::Thiscall),
        6 => Ok(CallingConvention::Swift),
        7 => Ok(CallingConvention::Golang),
        8 => Ok(CallingConvention::UserDefined),
        _ => Err(Error::validation("invalid calling convention value")),
    }
}

/// Enum member descriptor.
#[derive(Debug, Clone)]
pub struct EnumMember {
    pub name: String,
    pub value: u64,
    pub comment: String,
}

/// A struct/union member descriptor.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub r#type: TypeInfo,
    pub byte_offset: usize,
    pub bit_size: usize,
    pub comment: String,
}

/// Opaque handle representing a type in the IDA database.
///
/// Implements `Drop` to free the underlying SDK resources.
pub struct TypeInfo {
    handle: *mut c_void,
}

impl TypeInfo {
    /// Create from a raw handle. Takes ownership (will free on drop).
    #[allow(dead_code)]
    pub(crate) fn from_raw(handle: *mut c_void) -> Self {
        Self { handle }
    }

    fn from_out_handle(ret: i32, out: *mut c_void, context: &str) -> Result<Self> {
        if ret != 0 || out.is_null() {
            Err(error::consume_last_error(context))
        } else {
            Ok(Self { handle: out })
        }
    }

    /// Create an empty/void type.
    pub fn void_type() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_void() },
        }
    }

    pub fn int8() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_int8() },
        }
    }

    pub fn int16() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_int16() },
        }
    }

    pub fn int32() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_int32() },
        }
    }

    pub fn int64() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_int64() },
        }
    }

    pub fn uint8() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_uint8() },
        }
    }

    pub fn uint16() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_uint16() },
        }
    }

    pub fn uint32() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_uint32() },
        }
    }

    pub fn uint64() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_uint64() },
        }
    }

    pub fn float32() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_float32() },
        }
    }

    pub fn float64() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_float64() },
        }
    }

    /// Create a pointer type to `target`.
    pub fn pointer_to(target: &TypeInfo) -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_pointer_to(target.handle) },
        }
    }

    /// Create an array type.
    pub fn array_of(element: &TypeInfo, count: usize) -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_array_of(element.handle, count) },
        }
    }

    /// Create an empty struct type.
    pub fn create_struct() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_create_struct() },
        }
    }

    /// Create an empty union type.
    pub fn create_union() -> Self {
        Self {
            handle: unsafe { idax_sys::idax_type_create_union() },
        }
    }

    /// Create a function type.
    pub fn function_type(
        return_type: &TypeInfo,
        argument_types: &[TypeInfo],
        calling_convention: CallingConvention,
        has_varargs: bool,
    ) -> Result<Self> {
        let arg_handles: Vec<*mut c_void> = argument_types.iter().map(|a| a.handle).collect();
        let arg_ptr = if arg_handles.is_empty() {
            std::ptr::null()
        } else {
            arg_handles.as_ptr()
        };
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe {
            idax_sys::idax_type_function_type(
                return_type.handle,
                arg_ptr,
                arg_handles.len(),
                calling_convention as i32,
                has_varargs as i32,
                &mut out,
            )
        };
        Self::from_out_handle(ret, out, "function_type failed")
    }

    /// Create an enum type.
    pub fn enum_type(members: &[EnumMember], byte_width: usize, bitmask: bool) -> Result<Self> {
        let names: Result<Vec<CString>> = members
            .iter()
            .map(|m| {
                CString::new(m.name.as_str())
                    .map_err(|_| Error::validation("invalid enum member name"))
            })
            .collect();
        let names = names?;

        let comments: Result<Vec<CString>> = members
            .iter()
            .map(|m| {
                CString::new(m.comment.as_str())
                    .map_err(|_| Error::validation("invalid enum member comment"))
            })
            .collect();
        let comments = comments?;

        let mut raw_members = Vec::with_capacity(members.len());
        for i in 0..members.len() {
            raw_members.push(idax_sys::IdaxTypeEnumMemberInput {
                name: names[i].as_ptr(),
                value: members[i].value,
                comment: comments[i].as_ptr(),
            });
        }

        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe {
            idax_sys::idax_type_enum_type(
                if raw_members.is_empty() {
                    std::ptr::null()
                } else {
                    raw_members.as_ptr()
                },
                raw_members.len(),
                byte_width,
                bitmask as i32,
                &mut out,
            )
        };
        Self::from_out_handle(ret, out, "enum_type failed")
    }

    /// Create a type from C declaration.
    pub fn from_declaration(c_decl: &str) -> Result<Self> {
        let c = CString::new(c_decl).map_err(|_| Error::validation("invalid declaration"))?;
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_from_declaration(c.as_ptr(), &mut out) };
        Self::from_out_handle(ret, out, "from_declaration failed")
    }

    /// Lookup a named type.
    pub fn by_name(name: &str) -> Result<Self> {
        let c = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_by_name(c.as_ptr(), &mut out) };
        Self::from_out_handle(ret, out, "by_name failed")
    }

    // Introspection
    pub fn is_void(&self) -> bool {
        unsafe { idax_sys::idax_type_is_void(self.handle) != 0 }
    }

    pub fn is_integer(&self) -> bool {
        unsafe { idax_sys::idax_type_is_integer(self.handle) != 0 }
    }

    pub fn is_floating_point(&self) -> bool {
        unsafe { idax_sys::idax_type_is_floating_point(self.handle) != 0 }
    }

    pub fn is_pointer(&self) -> bool {
        unsafe { idax_sys::idax_type_is_pointer(self.handle) != 0 }
    }

    pub fn is_array(&self) -> bool {
        unsafe { idax_sys::idax_type_is_array(self.handle) != 0 }
    }

    pub fn is_function(&self) -> bool {
        unsafe { idax_sys::idax_type_is_function(self.handle) != 0 }
    }

    pub fn is_struct(&self) -> bool {
        unsafe { idax_sys::idax_type_is_struct(self.handle) != 0 }
    }

    pub fn is_union(&self) -> bool {
        unsafe { idax_sys::idax_type_is_union(self.handle) != 0 }
    }

    pub fn is_enum(&self) -> bool {
        unsafe { idax_sys::idax_type_is_enum(self.handle) != 0 }
    }

    pub fn is_typedef(&self) -> bool {
        unsafe { idax_sys::idax_type_is_typedef(self.handle) != 0 }
    }

    /// Size of the type in bytes.
    pub fn size(&self) -> Result<usize> {
        let mut sz: usize = 0;
        let ret = unsafe { idax_sys::idax_type_size(self.handle, &mut sz) };
        if ret != 0 {
            Err(error::consume_last_error("type::size failed"))
        } else {
            Ok(sz)
        }
    }

    /// String representation of the type.
    pub fn to_string(&self) -> Result<String> {
        let mut out: *mut c_char = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_to_string(self.handle, &mut out) };
        if ret != 0 || out.is_null() {
            Err(error::consume_last_error("type::to_string failed"))
        } else {
            unsafe { error::cstr_to_string_free(out, "type::to_string failed") }
        }
    }

    pub fn pointee_type(&self) -> Result<Self> {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_pointee_type(self.handle, &mut out) };
        Self::from_out_handle(ret, out, "pointee_type failed")
    }

    pub fn array_element_type(&self) -> Result<Self> {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_array_element_type(self.handle, &mut out) };
        Self::from_out_handle(ret, out, "array_element_type failed")
    }

    pub fn array_length(&self) -> Result<usize> {
        let mut out: usize = 0;
        let ret = unsafe { idax_sys::idax_type_array_length(self.handle, &mut out) };
        if ret != 0 {
            Err(error::consume_last_error("array_length failed"))
        } else {
            Ok(out)
        }
    }

    pub fn resolve_typedef(&self) -> Result<Self> {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_resolve_typedef(self.handle, &mut out) };
        Self::from_out_handle(ret, out, "resolve_typedef failed")
    }

    pub fn function_return_type(&self) -> Result<Self> {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_function_return_type(self.handle, &mut out) };
        Self::from_out_handle(ret, out, "function_return_type failed")
    }

    pub fn function_argument_types(&self) -> Result<Vec<Self>> {
        let mut handles: *mut *mut c_void = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = unsafe {
            idax_sys::idax_type_function_argument_types(self.handle, &mut handles, &mut count)
        };
        if ret != 0 {
            return Err(error::consume_last_error("function_argument_types failed"));
        }

        if handles.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        unsafe {
            let slice = std::slice::from_raw_parts_mut(handles, count);
            for handle in slice.iter_mut() {
                out.push(Self { handle: *handle });
                *handle = std::ptr::null_mut();
            }
            idax_sys::idax_type_handle_array_free(handles, count);
        }
        Ok(out)
    }

    pub fn calling_convention(&self) -> Result<CallingConvention> {
        let mut raw: i32 = 0;
        let ret = unsafe { idax_sys::idax_type_calling_convention(self.handle, &mut raw) };
        if ret != 0 {
            return Err(error::consume_last_error("calling_convention failed"));
        }
        calling_convention_from_i32(raw)
    }

    pub fn is_variadic_function(&self) -> Result<bool> {
        let mut out: i32 = 0;
        let ret = unsafe { idax_sys::idax_type_is_variadic_function(self.handle, &mut out) };
        if ret != 0 {
            Err(error::consume_last_error("is_variadic_function failed"))
        } else {
            Ok(out != 0)
        }
    }

    pub fn enum_members(&self) -> Result<Vec<EnumMember>> {
        let mut raw_members: *mut idax_sys::IdaxTypeEnumMember = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret =
            unsafe { idax_sys::idax_type_enum_members(self.handle, &mut raw_members, &mut count) };
        if ret != 0 {
            return Err(error::consume_last_error("enum_members failed"));
        }

        if raw_members.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        unsafe {
            let slice = std::slice::from_raw_parts(raw_members, count);
            for member in slice {
                out.push(EnumMember {
                    name: c_ptr_to_string(member.name as *const c_char),
                    value: member.value,
                    comment: c_ptr_to_string(member.comment as *const c_char),
                });
            }
            idax_sys::idax_type_enum_members_free(raw_members, count);
        }
        Ok(out)
    }

    /// Number of struct/union members.
    pub fn member_count(&self) -> Result<usize> {
        let mut n: usize = 0;
        let ret = unsafe { idax_sys::idax_type_member_count(self.handle, &mut n) };
        if ret != 0 {
            Err(error::consume_last_error("member_count failed"))
        } else {
            Ok(n)
        }
    }

    pub fn members(&self) -> Result<Vec<Member>> {
        let mut raw_members: *mut idax_sys::IdaxTypeMember = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = unsafe { idax_sys::idax_type_members(self.handle, &mut raw_members, &mut count) };
        if ret != 0 {
            return Err(error::consume_last_error("members failed"));
        }

        if raw_members.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        unsafe {
            let slice = std::slice::from_raw_parts_mut(raw_members, count);
            for member in slice.iter_mut() {
                let ty = TypeInfo {
                    handle: member.type_,
                };
                member.type_ = std::ptr::null_mut();
                out.push(Member {
                    name: c_ptr_to_string(member.name as *const c_char),
                    r#type: ty,
                    byte_offset: member.byte_offset,
                    bit_size: member.bit_size,
                    comment: c_ptr_to_string(member.comment as *const c_char),
                });
            }
            idax_sys::idax_type_members_free(raw_members, count);
        }
        Ok(out)
    }

    pub fn member_by_name(&self, name: &str) -> Result<Member> {
        let c = CString::new(name).map_err(|_| Error::validation("invalid member name"))?;
        let mut raw = idax_sys::IdaxTypeMember::default();
        let ret = unsafe { idax_sys::idax_type_member_by_name(self.handle, c.as_ptr(), &mut raw) };
        if ret != 0 {
            return Err(error::consume_last_error("member_by_name failed"));
        }

        let member = Member {
            name: c_ptr_to_string(raw.name as *const c_char),
            r#type: TypeInfo { handle: raw.type_ },
            byte_offset: raw.byte_offset,
            bit_size: raw.bit_size,
            comment: c_ptr_to_string(raw.comment as *const c_char),
        };
        raw.type_ = std::ptr::null_mut();
        unsafe {
            idax_sys::idax_type_member_free(&mut raw);
        }
        Ok(member)
    }

    pub fn member_by_offset(&self, byte_offset: usize) -> Result<Member> {
        let mut raw = idax_sys::IdaxTypeMember::default();
        let ret =
            unsafe { idax_sys::idax_type_member_by_offset(self.handle, byte_offset, &mut raw) };
        if ret != 0 {
            return Err(error::consume_last_error("member_by_offset failed"));
        }

        let member = Member {
            name: c_ptr_to_string(raw.name as *const c_char),
            r#type: TypeInfo { handle: raw.type_ },
            byte_offset: raw.byte_offset,
            bit_size: raw.bit_size,
            comment: c_ptr_to_string(raw.comment as *const c_char),
        };
        raw.type_ = std::ptr::null_mut();
        unsafe {
            idax_sys::idax_type_member_free(&mut raw);
        }
        Ok(member)
    }

    pub fn add_member(&self, name: &str, member_type: &TypeInfo, byte_offset: usize) -> Status {
        let c = CString::new(name).map_err(|_| Error::validation("invalid member name"))?;
        let ret = unsafe {
            idax_sys::idax_type_add_member(self.handle, c.as_ptr(), member_type.handle, byte_offset)
        };
        error::int_to_status(ret, "add_member failed")
    }

    /// Apply this type at the given address.
    pub fn apply(&self, ea: Address) -> Status {
        let ret = unsafe { idax_sys::idax_type_apply(self.handle, ea) };
        error::int_to_status(ret, "type::apply failed")
    }

    /// Save to the local type library under the given name.
    pub fn save_as(&self, name: &str) -> Status {
        let c = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
        let ret = unsafe { idax_sys::idax_type_save_as(self.handle, c.as_ptr()) };
        error::int_to_status(ret, "type::save_as failed")
    }

    /// Get the raw handle for FFI interop.
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> *mut c_void {
        self.handle
    }
}

impl Clone for TypeInfo {
    fn clone(&self) -> Self {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_type_clone(self.handle, &mut out) };
        if ret != 0 || out.is_null() {
            let err = error::consume_last_error("type::clone failed");
            panic!("TypeInfo clone failed: {}", err);
        }
        Self { handle: out }
    }
}

impl Drop for TypeInfo {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                idax_sys::idax_type_free(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for TypeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.to_string().unwrap_or_else(|_| "<unknown>".into());
        write!(f, "TypeInfo({})", s)
    }
}

fn c_ptr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Retrieve the type applied at an address.
pub fn retrieve(ea: Address) -> Result<TypeInfo> {
    let mut out: *mut c_void = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_type_retrieve(ea, &mut out) };
    TypeInfo::from_out_handle(ret, out, "type::retrieve failed")
}

/// Retrieve the type of an operand at an address.
pub fn retrieve_operand(ea: Address, operand_index: i32) -> Result<TypeInfo> {
    let mut out: *mut c_void = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_type_retrieve_operand(ea, operand_index, &mut out) };
    TypeInfo::from_out_handle(ret, out, "type::retrieve_operand failed")
}

/// Remove type information at an address.
pub fn remove_type(ea: Address) -> Status {
    let ret = unsafe { idax_sys::idax_type_remove(ea) };
    error::int_to_status(ret, "type::remove_type failed")
}

/// Load a type library (.til file).
pub fn load_type_library(til_name: &str) -> Result<bool> {
    let c = CString::new(til_name).map_err(|_| Error::validation("invalid til name"))?;
    let mut ok: std::ffi::c_int = 0;
    let ret = unsafe { idax_sys::idax_type_load_library(c.as_ptr(), &mut ok) };
    if ret != 0 {
        Err(error::consume_last_error("load_type_library failed"))
    } else {
        Ok(ok != 0)
    }
}

/// Unload a previously loaded type library.
pub fn unload_type_library(til_name: &str) -> Status {
    let c = CString::new(til_name).map_err(|_| Error::validation("invalid til name"))?;
    let ret = unsafe { idax_sys::idax_type_unload_library(c.as_ptr()) };
    error::int_to_status(ret, "unload_type_library failed")
}

/// Get the number of local types.
pub fn local_type_count() -> Result<usize> {
    let mut n: usize = 0;
    let ret = unsafe { idax_sys::idax_type_local_type_count(&mut n) };
    if ret != 0 {
        Err(error::consume_last_error("local_type_count failed"))
    } else {
        Ok(n)
    }
}

/// Get the name of a local type by ordinal.
pub fn local_type_name(ordinal: usize) -> Result<String> {
    let mut out: *mut c_char = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_type_local_type_name(ordinal, &mut out) };
    if ret != 0 || out.is_null() {
        Err(error::consume_last_error("local_type_name failed"))
    } else {
        unsafe { error::cstr_to_string_free(out, "local_type_name failed") }
    }
}

/// Import a named type from a source TIL into local types.
pub fn import_type(source_til_name: &str, type_name: &str) -> Result<usize> {
    let source = CString::new(source_til_name)
        .map_err(|_| Error::validation("invalid source type library name"))?;
    let ty = CString::new(type_name).map_err(|_| Error::validation("invalid type name"))?;
    let mut ordinal: usize = 0;
    let ret = unsafe { idax_sys::idax_type_import(source.as_ptr(), ty.as_ptr(), &mut ordinal) };
    if ret != 0 {
        Err(error::consume_last_error("import_type failed"))
    } else {
        Ok(ordinal)
    }
}

/// Ensure a named type exists in local types and return it.
pub fn ensure_named_type(type_name: &str, source_til_name: Option<&str>) -> Result<TypeInfo> {
    if let Ok(existing) = TypeInfo::by_name(type_name) {
        return Ok(existing);
    }

    let source = source_til_name.unwrap_or("");
    import_type(source, type_name)?;
    TypeInfo::by_name(type_name)
}

/// Apply a named type at an address.
pub fn apply_named_type(ea: Address, type_name: &str) -> Status {
    let c = CString::new(type_name).map_err(|_| Error::validation("invalid type name"))?;
    let ret = unsafe { idax_sys::idax_type_apply_named(ea, c.as_ptr()) };
    error::int_to_status(ret, "apply_named_type failed")
}
