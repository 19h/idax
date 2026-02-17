//! Loader module development helpers.
//!
//! Mirrors the C++ `ida::loader` namespace.

use crate::address::{Address, AddressSize};
use crate::error::{self, Error, Result, Status};
use std::ffi::{c_void, CString};

/// Decoded load-file flags (`NEF_*`) as typed booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoadFlags {
    pub create_segments: bool,
    pub load_resources: bool,
    pub rename_entries: bool,
    pub manual_load: bool,
    pub fill_gaps: bool,
    pub create_import_segment: bool,
    pub first_file: bool,
    pub binary_code_segment: bool,
    pub reload: bool,
    pub auto_flat_group: bool,
    pub mini_database: bool,
    pub loader_options_dialog: bool,
    pub load_all_segments: bool,
}

impl LoadFlags {
    fn from_ffi(raw: &idax_sys::IdaxLoaderLoadFlags) -> Self {
        Self {
            create_segments: raw.create_segments != 0,
            load_resources: raw.load_resources != 0,
            rename_entries: raw.rename_entries != 0,
            manual_load: raw.manual_load != 0,
            fill_gaps: raw.fill_gaps != 0,
            create_import_segment: raw.create_import_segment != 0,
            first_file: raw.first_file != 0,
            binary_code_segment: raw.binary_code_segment != 0,
            reload: raw.reload != 0,
            auto_flat_group: raw.auto_flat_group != 0,
            mini_database: raw.mini_database != 0,
            loader_options_dialog: raw.loader_options_dialog != 0,
            load_all_segments: raw.load_all_segments != 0,
        }
    }

    fn to_ffi(self) -> idax_sys::IdaxLoaderLoadFlags {
        idax_sys::IdaxLoaderLoadFlags {
            create_segments: self.create_segments as i32,
            load_resources: self.load_resources as i32,
            rename_entries: self.rename_entries as i32,
            manual_load: self.manual_load as i32,
            fill_gaps: self.fill_gaps as i32,
            create_import_segment: self.create_import_segment as i32,
            first_file: self.first_file as i32,
            binary_code_segment: self.binary_code_segment as i32,
            reload: self.reload as i32,
            auto_flat_group: self.auto_flat_group as i32,
            mini_database: self.mini_database as i32,
            loader_options_dialog: self.loader_options_dialog as i32,
            load_all_segments: self.load_all_segments as i32,
        }
    }
}

/// Decode raw SDK `NEF_*` bits into typed load flags.
pub fn decode_load_flags(raw_flags: u16) -> Result<LoadFlags> {
    unsafe {
        let mut raw = std::mem::MaybeUninit::<idax_sys::IdaxLoaderLoadFlags>::uninit();
        let ret = idax_sys::idax_loader_decode_load_flags(raw_flags, raw.as_mut_ptr());
        error::int_to_status(ret, "loader::decode_load_flags failed")?;
        Ok(LoadFlags::from_ffi(&raw.assume_init()))
    }
}

/// Encode typed load flags into raw SDK `NEF_*` bits.
pub fn encode_load_flags(flags: LoadFlags) -> Result<u16> {
    let mut raw_flags: u16 = 0;
    let ffi = flags.to_ffi();
    let ret = unsafe { idax_sys::idax_loader_encode_load_flags(&ffi, &mut raw_flags) };
    error::int_to_status(ret, "loader::encode_load_flags failed")?;
    Ok(raw_flags)
}

/// Opaque loader input handle wrapper.
///
/// Handles are supplied by loader callbacks on the C++ side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputFileHandle {
    raw: *mut c_void,
}

impl InputFileHandle {
    /// Create a wrapper from an opaque loader input handle.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid `linput_t*` handle supplied by IDA loader callbacks.
    pub const unsafe fn from_raw(raw: *mut c_void) -> Self {
        Self { raw }
    }

    /// Validate and create a wrapper from a raw handle.
    pub fn from_raw_checked(raw: *mut c_void) -> Result<Self> {
        if raw.is_null() {
            Err(Error::validation("loader input handle is null"))
        } else {
            Ok(Self { raw })
        }
    }

    /// Borrow the underlying raw handle.
    pub fn as_raw(self) -> *mut c_void {
        self.raw
    }

    /// Total size of the input file in bytes.
    pub fn size(&self) -> Result<i64> {
        let mut out: i64 = 0;
        let ret = unsafe { idax_sys::idax_loader_input_size(self.raw, &mut out) };
        error::int_to_status(ret, "loader::input_size failed")?;
        Ok(out)
    }

    /// Current read position in the input file.
    pub fn tell(&self) -> Result<i64> {
        let mut out: i64 = 0;
        let ret = unsafe { idax_sys::idax_loader_input_tell(self.raw, &mut out) };
        error::int_to_status(ret, "loader::input_tell failed")?;
        Ok(out)
    }

    /// Seek to an absolute position; returns the new position.
    pub fn seek(&self, offset: i64) -> Result<i64> {
        let mut out: i64 = 0;
        let ret = unsafe { idax_sys::idax_loader_input_seek(self.raw, offset, &mut out) };
        error::int_to_status(ret, "loader::input_seek failed")?;
        Ok(out)
    }

    /// Read up to `count` bytes from the current input position.
    pub fn read_bytes(&self, count: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            let ret =
                idax_sys::idax_loader_input_read_bytes(self.raw, count, &mut out_ptr, &mut out_len);
            error::int_to_status(ret, "loader::input_read_bytes failed")?;
            if out_ptr.is_null() || out_len == 0 {
                return Ok(Vec::new());
            }
            let out = std::slice::from_raw_parts(out_ptr, out_len).to_vec();
            idax_sys::idax_free_bytes(out_ptr);
            Ok(out)
        }
    }

    /// Read up to `count` bytes from an absolute file offset.
    pub fn read_bytes_at(&self, offset: i64, count: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            let ret = idax_sys::idax_loader_input_read_bytes_at(
                self.raw,
                offset,
                count,
                &mut out_ptr,
                &mut out_len,
            );
            error::int_to_status(ret, "loader::input_read_bytes_at failed")?;
            if out_ptr.is_null() || out_len == 0 {
                return Ok(Vec::new());
            }
            let out = std::slice::from_raw_parts(out_ptr, out_len).to_vec();
            idax_sys::idax_free_bytes(out_ptr);
            Ok(out)
        }
    }

    /// Read a null-terminated string at `offset`, bounded by `max_len`.
    pub fn read_string(&self, offset: i64, max_len: usize) -> Result<String> {
        unsafe {
            let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_loader_input_read_string(self.raw, offset, max_len, &mut out);
            error::int_to_status(ret, "loader::input_read_string failed")?;
            error::cstr_to_string_free(out, "loader::input_read_string returned null")
        }
    }

    /// Input filename if available from this handle.
    pub fn filename(&self) -> Result<String> {
        unsafe {
            let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_loader_input_filename(self.raw, &mut out);
            error::int_to_status(ret, "loader::input_filename failed")?;
            error::cstr_to_string_free(out, "loader::input_filename returned null")
        }
    }
}

/// Wrap a loader input handle with runtime validation.
pub fn input_file(raw_handle: *mut c_void) -> Result<InputFileHandle> {
    InputFileHandle::from_raw_checked(raw_handle)
}

/// Copy bytes from a loader input handle into the database.
pub fn file_to_database(
    li_handle: *mut c_void,
    file_offset: i64,
    ea: Address,
    size: AddressSize,
    patchable: bool,
) -> Status {
    let ret = unsafe {
        idax_sys::idax_loader_file_to_database(li_handle, file_offset, ea, size, patchable as i32)
    };
    error::int_to_status(ret, "loader::file_to_database failed")
}

/// Copy bytes from memory into the database.
pub fn memory_to_database(data: &[u8], ea: Address, size: AddressSize) -> Status {
    if size > data.len() as u64 {
        return Err(Error::validation("size exceeds data length"));
    }
    let ret = unsafe { idax_sys::idax_loader_memory_to_database(data.as_ptr(), ea, size) };
    error::int_to_status(ret, "loader::memory_to_database failed")
}

/// Abort loading with an error message. Does not return.
pub fn abort_load(message: &str) -> ! {
    let sanitized = message.replace('\0', " ");
    let c = CString::new(sanitized).expect("CString::new must succeed after null stripping");
    unsafe { idax_sys::idax_loader_abort_load(c.as_ptr()) };
    unreachable!("loader::abort_load returned unexpectedly")
}

/// Set the processor type for the new database.
pub fn set_processor(processor_name: &str) -> Status {
    let c =
        CString::new(processor_name).map_err(|_| Error::validation("invalid processor name"))?;
    let ret = unsafe { idax_sys::idax_loader_set_processor(c.as_ptr()) };
    error::int_to_status(ret, "loader::set_processor failed")
}

/// Add a standard filename comment.
pub fn create_filename_comment() -> Status {
    let ret = unsafe { idax_sys::idax_loader_create_filename_comment() };
    error::int_to_status(ret, "loader::create_filename_comment failed")
}
