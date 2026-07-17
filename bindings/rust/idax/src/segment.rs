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

/// Origin of one segment-register range value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SegmentRegisterSource {
    Inherited = 0,
    User = 1,
    Analysis = 2,
    AnalysisAtSegmentStart = 3,
}

/// Owned semantic description of one processor segment register.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SegmentRegisterDescriptor {
    pub name: String,
    pub bit_width: usize,
    pub is_code: bool,
    pub is_data: bool,
}

/// Owned half-open range over which one segment-register value is stable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SegmentRegisterRange {
    pub start: Address,
    pub end: Address,
    pub value: Option<u64>,
    pub source: SegmentRegisterSource,
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

fn register_name(name: &str) -> Result<CString> {
    CString::new(name)
        .map_err(|_| Error::validation("segment-register name contains an embedded NUL byte"))
}

fn source_from_raw(source: i32) -> Result<SegmentRegisterSource> {
    match source {
        0 => Ok(SegmentRegisterSource::Inherited),
        1 => Ok(SegmentRegisterSource::User),
        2 => Ok(SegmentRegisterSource::Analysis),
        3 => Ok(SegmentRegisterSource::AnalysisAtSegmentStart),
        _ => Err(Error::internal("unknown segment-register range source")),
    }
}

fn range_from_raw(raw: &idax_sys::IdaxSegmentRegisterRange) -> Result<SegmentRegisterRange> {
    Ok(SegmentRegisterRange {
        start: raw.start,
        end: raw.end,
        value: (raw.has_value != 0).then_some(raw.value),
        source: source_from_raw(raw.source)?,
    })
}

fn empty_register_range() -> idax_sys::IdaxSegmentRegisterRange {
    idax_sys::IdaxSegmentRegisterRange {
        start: 0,
        end: 0,
        has_value: 0,
        value: 0,
        source: 0,
    }
}

/// Discover the active processor's semantic segment registers.
pub fn segment_registers() -> Result<Vec<SegmentRegisterDescriptor>> {
    let mut raw = std::ptr::null_mut();
    let mut count = 0;
    let status = unsafe { idax_sys::idax_segment_registers(&mut raw, &mut count) };
    if status != 0 {
        return Err(error::consume_last_error(
            "segment::segment_registers failed",
        ));
    }
    if count != 0 && raw.is_null() {
        return Err(Error::internal(
            "segment-register descriptor array is null for a nonempty result",
        ));
    }
    let mut result = Vec::with_capacity(count);
    if !raw.is_null() {
        let values = unsafe { std::slice::from_raw_parts(raw, count) };
        for value in values {
            if value.name.is_null() {
                unsafe { idax_sys::idax_segment_register_descriptors_free(raw, count) };
                return Err(Error::internal("segment-register name pointer is null"));
            }
            let name = match unsafe { std::ffi::CStr::from_ptr(value.name) }.to_str() {
                Ok(value) => value.to_owned(),
                Err(_) => {
                    unsafe { idax_sys::idax_segment_register_descriptors_free(raw, count) };
                    return Err(Error::internal("segment-register name is not valid UTF-8"));
                }
            };
            result.push(SegmentRegisterDescriptor {
                name,
                bit_width: value.bit_width,
                is_code: value.is_code != 0,
                is_data: value.is_data != 0,
            });
        }
        unsafe { idax_sys::idax_segment_register_descriptors_free(raw, count) };
    }
    Ok(result)
}

fn optional_register_value(
    call: impl FnOnce(*mut i32, *mut u64) -> i32,
    fallback: &str,
) -> Result<Option<u64>> {
    let mut has_value = 0;
    let mut value = 0;
    let status = call(&mut has_value, &mut value);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    Ok((has_value != 0).then_some(value))
}

/// Effective value at an address, or `None` when unknown.
pub fn segment_register_value(address: Address, name: &str) -> Result<Option<u64>> {
    let name = register_name(name)?;
    optional_register_value(
        |has_value, out| unsafe {
            idax_sys::idax_segment_register_value(address, name.as_ptr(), has_value, out)
        },
        "segment::segment_register_value failed",
    )
}

/// Segment default value, or `None` when unknown.
pub fn default_segment_register_value(address: Address, name: &str) -> Result<Option<u64>> {
    let name = register_name(name)?;
    optional_register_value(
        |has_value, out| unsafe {
            idax_sys::idax_segment_default_register_value(address, name.as_ptr(), has_value, out)
        },
        "segment::default_segment_register_value failed",
    )
}

/// Copied range containing an address.
pub fn segment_register_range(address: Address, name: &str) -> Result<SegmentRegisterRange> {
    let name = register_name(name)?;
    let mut raw = empty_register_range();
    let status = unsafe { idax_sys::idax_segment_register_range(address, name.as_ptr(), &mut raw) };
    if status != 0 {
        return Err(error::consume_last_error(
            "segment::segment_register_range failed",
        ));
    }
    range_from_raw(&raw)
}

/// Copied range preceding the containing range, or `None`.
pub fn previous_segment_register_range(
    address: Address,
    name: &str,
) -> Result<Option<SegmentRegisterRange>> {
    let name = register_name(name)?;
    let mut raw = empty_register_range();
    let mut has_value = 0;
    let status = unsafe {
        idax_sys::idax_segment_previous_register_range(
            address,
            name.as_ptr(),
            &mut raw,
            &mut has_value,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error(
            "segment::previous_segment_register_range failed",
        ));
    }
    if has_value == 0 {
        Ok(None)
    } else {
        range_from_raw(&raw).map(Some)
    }
}

/// All copied ranges for one named segment register.
pub fn segment_register_ranges(name: &str) -> Result<Vec<SegmentRegisterRange>> {
    let name = register_name(name)?;
    let mut raw = std::ptr::null_mut();
    let mut count = 0;
    let status =
        unsafe { idax_sys::idax_segment_register_ranges(name.as_ptr(), &mut raw, &mut count) };
    if status != 0 {
        return Err(error::consume_last_error(
            "segment::segment_register_ranges failed",
        ));
    }
    if count != 0 && raw.is_null() {
        return Err(Error::internal(
            "segment-register range array is null for a nonempty result",
        ));
    }
    let result = if raw.is_null() {
        Ok(Vec::new())
    } else {
        unsafe { std::slice::from_raw_parts(raw, count) }
            .iter()
            .map(range_from_raw)
            .collect()
    };
    unsafe { idax_sys::idax_segment_register_ranges_free(raw) };
    result
}

/// Index of the range containing an address, or `None`.
pub fn segment_register_range_index(address: Address, name: &str) -> Result<Option<usize>> {
    let name = register_name(name)?;
    let mut value = 0;
    let mut has_value = 0;
    let status = unsafe {
        idax_sys::idax_segment_register_range_index(
            address,
            name.as_ptr(),
            &mut value,
            &mut has_value,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error(
            "segment::segment_register_range_index failed",
        ));
    }
    Ok((has_value != 0).then_some(value))
}

/// Start or replace a range and verify its exact post-state.
pub fn split_segment_register_range(
    address: Address,
    name: &str,
    value: Option<u64>,
    source: SegmentRegisterSource,
) -> Status {
    let name = register_name(name)?;
    let status = unsafe {
        idax_sys::idax_segment_split_register_range(
            address,
            name.as_ptr(),
            value.is_some() as i32,
            value.unwrap_or(0),
            source as i32,
        )
    };
    error::int_to_status(status, "segment::split_segment_register_range failed")
}

/// Remove the range that starts exactly at an address.
pub fn remove_segment_register_range(address: Address, name: &str) -> Status {
    let name = register_name(name)?;
    let status = unsafe { idax_sys::idax_segment_remove_register_range(address, name.as_ptr()) };
    error::int_to_status(status, "segment::remove_segment_register_range failed")
}

/// Set or clear a named default for one segment.
pub fn set_segment_register_default(address: Address, name: &str, value: Option<u64>) -> Status {
    let name = register_name(name)?;
    let status = unsafe {
        idax_sys::idax_segment_set_default_segment_register_named(
            address,
            name.as_ptr(),
            value.is_some() as i32,
            value.unwrap_or(0),
        )
    };
    error::int_to_status(status, "segment::set_segment_register_default failed")
}

/// Set or clear a named default for every segment.
pub fn set_segment_register_default_for_all(name: &str, value: Option<u64>) -> Status {
    let name = register_name(name)?;
    let status = unsafe {
        idax_sys::idax_segment_set_default_segment_register_for_all_named(
            name.as_ptr(),
            value.is_some() as i32,
            value.unwrap_or(0),
        )
    };
    error::int_to_status(
        status,
        "segment::set_segment_register_default_for_all failed",
    )
}

/// Set or clear the active processor's semantic data-register default.
pub fn set_default_data_segment(value: Option<u64>) -> Status {
    let status = unsafe {
        idax_sys::idax_segment_set_default_data_segment(value.is_some() as i32, value.unwrap_or(0))
    };
    error::int_to_status(status, "segment::set_default_data_segment failed")
}

/// Assign a value at the next instruction within the inclusive bound.
pub fn set_segment_register_at_next_code(
    search_start: Address,
    maximum: Address,
    name: &str,
    value: Option<u64>,
) -> Status {
    let name = register_name(name)?;
    let status = unsafe {
        idax_sys::idax_segment_set_register_at_next_code(
            search_start,
            maximum,
            name.as_ptr(),
            value.is_some() as i32,
            value.unwrap_or(0),
        )
    };
    error::int_to_status(status, "segment::set_segment_register_at_next_code failed")
}

/// Replace destination ranges with copied source ranges.
pub fn copy_segment_register_ranges(
    destination: &str,
    source: &str,
    map_selectors_to_addresses: bool,
) -> Status {
    let destination = register_name(destination)?;
    let source = register_name(source)?;
    let status = unsafe {
        idax_sys::idax_segment_copy_register_ranges(
            destination.as_ptr(),
            source.as_ptr(),
            map_selectors_to_addresses as i32,
        )
    };
    error::int_to_status(status, "segment::copy_segment_register_ranges failed")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_register_source_values_are_closed() {
        assert_eq!(SegmentRegisterSource::Inherited as i32, 0);
        assert_eq!(SegmentRegisterSource::User as i32, 1);
        assert_eq!(SegmentRegisterSource::Analysis as i32, 2);
        assert_eq!(SegmentRegisterSource::AnalysisAtSegmentStart as i32, 3);
    }

    #[test]
    fn embedded_nul_register_names_are_rejected_before_ffi() {
        let error = segment_register_value(0, "e\0s").unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }

    #[test]
    fn segment_register_signatures_preserve_owned_optional_state() {
        let _: fn() -> Result<Vec<SegmentRegisterDescriptor>> = segment_registers;
        let _: fn(Address, &str) -> Result<Option<u64>> = segment_register_value;
        let _: fn(Address, &str) -> Result<Option<u64>> = default_segment_register_value;
        let _: fn(Address, &str) -> Result<SegmentRegisterRange> = segment_register_range;
        let _: fn(Address, &str) -> Result<Option<SegmentRegisterRange>> =
            previous_segment_register_range;
        let _: fn(&str) -> Result<Vec<SegmentRegisterRange>> = segment_register_ranges;
        let _: fn(Address, &str) -> Result<Option<usize>> = segment_register_range_index;
        let _: fn(Address, &str, Option<u64>, SegmentRegisterSource) -> Status =
            split_segment_register_range;
        let _: fn(Address, &str) -> Status = remove_segment_register_range;
        let _: fn(Address, &str, Option<u64>) -> Status = set_segment_register_default;
        let _: fn(&str, Option<u64>) -> Status = set_segment_register_default_for_all;
        let _: fn(Option<u64>) -> Status = set_default_data_segment;
        let _: fn(Address, Address, &str, Option<u64>) -> Status =
            set_segment_register_at_next_code;
        let _: fn(&str, &str, bool) -> Status = copy_segment_register_ranges;
    }
}
