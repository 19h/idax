//! Fixup / relocation information.
//!
//! Mirrors the C++ `ida::fixup` namespace.

use crate::address::{Address, AddressDelta, BAD_ADDRESS};
use crate::error::{self, Result, Status};

/// Fixup type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Type {
    Off8 = 0,
    Off16 = 1,
    Seg16 = 2,
    Ptr16 = 3,
    Off32 = 4,
    Ptr32 = 5,
    Hi8 = 6,
    Hi16 = 7,
    Low8 = 8,
    Low16 = 9,
    Off64 = 10,
    Off8Signed = 11,
    Off16Signed = 12,
    Off32Signed = 13,
    Custom = 14,
}

fn type_from_i32(v: i32) -> Type {
    match v {
        0 => Type::Off8,
        1 => Type::Off16,
        2 => Type::Seg16,
        3 => Type::Ptr16,
        4 => Type::Off32,
        5 => Type::Ptr32,
        6 => Type::Hi8,
        7 => Type::Hi16,
        8 => Type::Low8,
        9 => Type::Low16,
        10 => Type::Off64,
        11 => Type::Off8Signed,
        12 => Type::Off16Signed,
        13 => Type::Off32Signed,
        _ => Type::Custom,
    }
}

/// Fixup descriptor.
#[derive(Debug, Clone)]
pub struct Descriptor {
    pub source: Address,
    pub fixup_type: Type,
    pub flags: u32,
    pub base: Address,
    pub target: Address,
    pub selector: u16,
    pub offset: Address,
    pub displacement: AddressDelta,
}

/// Configuration for registering a custom fixup handler.
#[derive(Debug, Clone)]
pub struct CustomHandler {
    pub name: String,
    pub properties: u32,
    pub size: u8,
    pub width: u8,
    pub shift: u8,
    pub reference_type: u32,
}

/// Get fixup at address.
pub fn at(source: Address) -> Result<Descriptor> {
    unsafe {
        let mut raw = idax_sys::IdaxFixup::default();
        let ret = idax_sys::idax_fixup_at(source, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("fixup::at failed"));
        }
        Ok(Descriptor {
            source: raw.source,
            fixup_type: type_from_i32(raw.type_),
            flags: raw.flags,
            base: raw.base,
            target: raw.target,
            selector: raw.selector,
            offset: raw.offset,
            displacement: raw.displacement,
        })
    }
}

/// Check whether a fixup exists at the given address.
pub fn exists(source: Address) -> bool {
    unsafe { idax_sys::idax_fixup_exists(source) != 0 }
}

/// Check whether an address range contains any fixups.
pub fn contains(start: Address, size: u64) -> bool {
    unsafe { idax_sys::idax_fixup_contains(start, size) != 0 }
}

/// Collect fixup descriptors in `[start, end)`.
pub fn in_range(start: Address, end: Address) -> Result<Vec<Descriptor>> {
    unsafe {
        let mut ptr: *mut idax_sys::IdaxFixup = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_fixup_in_range(start, end, &mut ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("fixup::in_range failed"));
        }
        if ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        let raws = std::slice::from_raw_parts(ptr, count);
        for raw in raws {
            out.push(Descriptor {
                source: raw.source,
                fixup_type: type_from_i32(raw.type_),
                flags: raw.flags,
                base: raw.base,
                target: raw.target,
                selector: raw.selector,
                offset: raw.offset,
                displacement: raw.displacement,
            });
        }
        idax_sys::idax_free_bytes(ptr.cast::<u8>());
        Ok(out)
    }
}

/// Register a custom fixup handler and return its type id.
pub fn register_custom(handler: &CustomHandler) -> Result<u16> {
    let c_name = std::ffi::CString::new(handler.name.as_str())
        .map_err(|_| error::Error::validation("invalid custom handler name"))?;
    let raw = idax_sys::IdaxFixupCustomHandler {
        name: c_name.as_ptr(),
        properties: handler.properties,
        size: handler.size,
        width: handler.width,
        shift: handler.shift,
        reference_type: handler.reference_type,
    };
    let mut out: u16 = 0;
    let ret = unsafe { idax_sys::idax_fixup_register_custom(&raw, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("fixup::register_custom failed"))
    } else {
        Ok(out)
    }
}

/// Unregister a custom fixup handler.
pub fn unregister_custom(custom_type: u16) -> Status {
    let ret = unsafe { idax_sys::idax_fixup_unregister_custom(custom_type) };
    error::int_to_status(ret, "fixup::unregister_custom failed")
}

/// Find a custom fixup handler by name.
pub fn find_custom(name: &str) -> Result<u16> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| error::Error::validation("invalid custom handler name"))?;
    let mut out: u16 = 0;
    let ret = unsafe { idax_sys::idax_fixup_find_custom(c_name.as_ptr(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("fixup::find_custom failed"))
    } else {
        Ok(out)
    }
}

/// Remove a fixup.
pub fn remove(source: Address) -> Status {
    let ret = unsafe { idax_sys::idax_fixup_remove(source) };
    error::int_to_status(ret, "fixup::remove failed")
}

/// First fixup address.
pub fn first() -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_fixup_first(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("fixup::first failed"))
    } else {
        Ok(out)
    }
}

/// Next fixup address.
pub fn next(address: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_fixup_next(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("fixup::next failed"))
    } else {
        Ok(out)
    }
}

/// Previous fixup address.
pub fn prev(address: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_fixup_prev(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("fixup::prev failed"))
    } else {
        Ok(out)
    }
}

/// Iterator over all fixups.
pub struct FixupIter {
    current: Option<Address>,
}

impl Iterator for FixupIter {
    type Item = Descriptor;
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.current?;
        let desc = at(cur).ok()?;
        let mut next_addr: Address = BAD_ADDRESS;
        let ret = unsafe { idax_sys::idax_fixup_next(cur, &mut next_addr) };
        if ret != 0 {
            self.current = None;
        } else {
            self.current = Some(next_addr);
        }
        Some(desc)
    }
}

/// Iterable range of all fixups.
pub fn all() -> FixupIter {
    let mut first_addr: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_fixup_first(&mut first_addr) };
    FixupIter {
        current: if ret != 0 { None } else { Some(first_addr) },
    }
}
