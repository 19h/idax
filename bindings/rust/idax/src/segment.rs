//! Segment operations: creation, query, traversal, properties.
//!
//! Mirrors the C++ `ida::segment` namespace. Every segment is represented
//! by an opaque `Segment` value object.

use crate::address::{Address, AddressSize};
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Segment type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Type {
    Normal = 0,
    External = 1,
    Code = 2,
    Data = 3,
    Bss = 4,
    AbsoluteSymbols = 5,
    Common = 6,
    Null = 7,
    Undefined = 8,
    Import = 9,
    InternalMemory = 10,
    Group = 11,
}

/// Readable permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

// ---------------------------------------------------------------------------
// Segment value object
// ---------------------------------------------------------------------------

/// Opaque snapshot of a segment.
#[derive(Debug, Clone)]
pub struct Segment {
    start: Address,
    end: Address,
    bitness: i32,
    seg_type: Type,
    perm: Permissions,
    seg_name: String,
    class_name: String,
    visible: bool,
}

impl Segment {
    pub fn start(&self) -> Address {
        self.start
    }
    pub fn end(&self) -> Address {
        self.end
    }
    pub fn size(&self) -> AddressSize {
        self.end.saturating_sub(self.start)
    }
    pub fn bitness(&self) -> i32 {
        self.bitness
    }
    pub fn seg_type(&self) -> Type {
        self.seg_type
    }
    pub fn permissions(&self) -> Permissions {
        self.perm
    }
    pub fn name(&self) -> &str {
        &self.seg_name
    }
    pub fn class_name(&self) -> &str {
        &self.class_name
    }
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Re-read this segment from the database to pick up any changes.
    pub fn refresh(&mut self) -> Status {
        let refreshed = at(self.start)?;
        *self = refreshed;
        Ok(())
    }
}

/// Helper to construct a Segment from a filled-in IdaxSegment struct.
unsafe fn segment_from_raw(s: &idax_sys::IdaxSegment) -> Segment {
    let seg_name = unsafe { error::consume_c_string(s.name) };
    let class_name = unsafe { error::consume_c_string(s.class_name) };

    let seg_type = match s.type_ {
        0 => Type::Normal,
        1 => Type::External,
        2 => Type::Code,
        3 => Type::Data,
        4 => Type::Bss,
        5 => Type::AbsoluteSymbols,
        6 => Type::Common,
        7 => Type::Null,
        8 => Type::Undefined,
        9 => Type::Import,
        10 => Type::InternalMemory,
        11 => Type::Group,
        _ => Type::Undefined,
    };

    Segment {
        start: s.start,
        end: s.end,
        bitness: s.bitness,
        seg_type,
        perm: Permissions {
            read: s.perm_read != 0,
            write: s.perm_write != 0,
            execute: s.perm_exec != 0,
        },
        seg_name,
        class_name,
        visible: s.visible != 0,
    }
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Create a new segment.
pub fn create(
    start: Address,
    end: Address,
    name: &str,
    class_name: &str,
    seg_type: Type,
) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid segment name"))?;
    let c_class = CString::new(class_name).map_err(|_| Error::validation("invalid class name"))?;
    let ret = unsafe {
        idax_sys::idax_segment_create(
            start,
            end,
            c_name.as_ptr(),
            c_class.as_ptr(),
            seg_type as i32,
        )
    };
    error::int_to_status(ret, "segment::create failed")
}

/// Remove the segment containing `address`.
pub fn remove(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_segment_remove(address) };
    error::int_to_status(ret, "segment::remove failed")
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Segment containing the given address.
pub fn at(address: Address) -> Result<Segment> {
    unsafe {
        let mut raw = idax_sys::IdaxSegment::default();
        let ret = idax_sys::idax_segment_at(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("segment::at failed"));
        }
        Ok(segment_from_raw(&raw))
    }
}

/// Segment with the given name.
pub fn by_name(name: &str) -> Result<Segment> {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid segment name"))?;
    unsafe {
        let mut raw = idax_sys::IdaxSegment::default();
        let ret = idax_sys::idax_segment_by_name(c_name.as_ptr(), &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("segment::by_name failed"));
        }
        Ok(segment_from_raw(&raw))
    }
}

/// Segment by its positional index (0-based).
pub fn by_index(index: usize) -> Result<Segment> {
    unsafe {
        let mut raw = idax_sys::IdaxSegment::default();
        let ret = idax_sys::idax_segment_by_index(index, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("segment::by_index failed"));
        }
        Ok(segment_from_raw(&raw))
    }
}

/// Total number of segments.
pub fn count() -> Result<usize> {
    let mut n: usize = 0;
    let ret = unsafe { idax_sys::idax_segment_count(&mut n) };
    if ret != 0 {
        Err(error::consume_last_error("segment::count failed"))
    } else {
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Property mutation
// ---------------------------------------------------------------------------

/// Set segment name.
pub fn set_name(address: Address, name: &str) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid name"))?;
    let ret = unsafe { idax_sys::idax_segment_set_name(address, c_name.as_ptr()) };
    error::int_to_status(ret, "segment::set_name failed")
}

/// Set segment class.
pub fn set_class(address: Address, class_name: &str) -> Status {
    let c_class = CString::new(class_name).map_err(|_| Error::validation("invalid class"))?;
    let ret = unsafe { idax_sys::idax_segment_set_class(address, c_class.as_ptr()) };
    error::int_to_status(ret, "segment::set_class failed")
}

/// Set segment type.
pub fn set_type(address: Address, seg_type: Type) -> Status {
    let ret = unsafe { idax_sys::idax_segment_set_type(address, seg_type as i32) };
    error::int_to_status(ret, "segment::set_type failed")
}

/// Set segment permissions.
pub fn set_permissions(address: Address, perm: Permissions) -> Status {
    let ret = unsafe {
        idax_sys::idax_segment_set_permissions(
            address,
            perm.read as i32,
            perm.write as i32,
            perm.execute as i32,
        )
    };
    error::int_to_status(ret, "segment::set_permissions failed")
}

/// Set segment bitness.
pub fn set_bitness(address: Address, bits: i32) -> Status {
    let ret = unsafe { idax_sys::idax_segment_set_bitness(address, bits) };
    error::int_to_status(ret, "segment::set_bitness failed")
}

/// Seed default value of one segment register for the segment containing `address`.
pub fn set_default_segment_register(address: Address, register_index: i32, value: u64) -> Status {
    let ret = unsafe {
        idax_sys::idax_segment_set_default_segment_register(address, register_index, value)
    };
    error::int_to_status(ret, "segment::set_default_segment_register failed")
}

/// Seed default value of one segment register for all segments.
pub fn set_default_segment_register_for_all(register_index: i32, value: u64) -> Status {
    let ret = unsafe {
        idax_sys::idax_segment_set_default_segment_register_for_all(register_index, value)
    };
    error::int_to_status(ret, "segment::set_default_segment_register_for_all failed")
}

/// Get segment comment.
pub fn comment(address: Address, repeatable: bool) -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_segment_comment(address, repeatable as i32, &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("segment::comment failed"));
        }
        error::cstr_to_string_free(ptr, "segment::comment null")
    }
}

/// Set segment comment.
pub fn set_comment(address: Address, text: &str, repeatable: bool) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid comment text"))?;
    let ret =
        unsafe { idax_sys::idax_segment_set_comment(address, c_text.as_ptr(), repeatable as i32) };
    error::int_to_status(ret, "segment::set_comment failed")
}

/// Resize the segment containing `address` to `[new_start, new_end)`.
pub fn resize(address: Address, new_start: Address, new_end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_segment_resize(address, new_start, new_end) };
    error::int_to_status(ret, "segment::resize failed")
}

/// Move the segment containing `address` so it starts at `new_start`.
pub fn move_segment(address: Address, new_start: Address) -> Status {
    let ret = unsafe { idax_sys::idax_segment_move(address, new_start) };
    error::int_to_status(ret, "segment::move_segment failed")
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

/// Iterator over all segments.
pub struct SegmentIter {
    index: usize,
    total: usize,
}

impl Iterator for SegmentIter {
    type Item = Segment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        let seg = by_index(self.index).ok()?;
        self.index += 1;
        Some(seg)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for SegmentIter {}

/// Iterable range of all segments.
pub fn all() -> SegmentIter {
    let total = count().unwrap_or(0);
    SegmentIter { index: 0, total }
}

/// First segment in database order.
pub fn first() -> Result<Segment> {
    by_index(0)
}

/// Last segment in database order.
pub fn last() -> Result<Segment> {
    let n = count()?;
    if n == 0 {
        Err(Error::not_found("no segments"))
    } else {
        by_index(n - 1)
    }
}

/// Segment immediately after the one containing `address`.
pub fn next(address: Address) -> Result<Segment> {
    unsafe {
        let mut raw = idax_sys::IdaxSegment::default();
        let ret = idax_sys::idax_segment_next(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("segment::next failed"));
        }
        Ok(segment_from_raw(&raw))
    }
}

/// Segment immediately before the one containing `address`.
pub fn prev(address: Address) -> Result<Segment> {
    unsafe {
        let mut raw = idax_sys::IdaxSegment::default();
        let ret = idax_sys::idax_segment_prev(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("segment::prev failed"));
        }
        Ok(segment_from_raw(&raw))
    }
}
