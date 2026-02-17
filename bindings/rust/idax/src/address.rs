//! Address primitives, predicates, and range iteration for idax.
//!
//! Mirrors the C++ `ida::address` namespace: address types, navigation,
//! predicates, and Rust iterators over item heads and predicate-matching
//! addresses.

use crate::error::{self, Result};

/// Effective address (64-bit unsigned).
pub type Address = u64;

/// Signed address difference.
pub type AddressDelta = i64;

/// Unsigned address / size quantity.
pub type AddressSize = u64;

/// Sentinel: invalid address.
pub const BAD_ADDRESS: Address = !0u64;

// ---------------------------------------------------------------------------
// Range
// ---------------------------------------------------------------------------

/// Half-open address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    pub start: Address,
    pub end: Address,
}

impl Range {
    /// Create a new range.
    pub fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Size of the range in bytes.
    pub fn size(&self) -> AddressSize {
        if self.end > self.start {
            self.end - self.start
        } else {
            0
        }
    }

    /// Whether the range contains `ea`.
    pub fn contains(&self, ea: Address) -> bool {
        ea >= self.start && ea < self.end
    }

    /// Whether the range is empty.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

impl Default for Range {
    fn default() -> Self {
        Self {
            start: BAD_ADDRESS,
            end: BAD_ADDRESS,
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate enum
// ---------------------------------------------------------------------------

/// Address classification predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Predicate {
    Mapped = 0,
    Loaded = 1,
    Code = 2,
    Data = 3,
    Unknown = 4,
    Head = 5,
    Tail = 6,
}

// ---------------------------------------------------------------------------
// Navigation functions
// ---------------------------------------------------------------------------

/// Start address of the item containing `ea`, or the item itself if head.
pub fn item_start(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_item_start(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("item_start failed"))
    } else {
        Ok(out)
    }
}

/// First address past the end of the item containing `ea`.
pub fn item_end(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_item_end(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("item_end failed"))
    } else {
        Ok(out)
    }
}

/// Size of the item at `ea` in bytes.
pub fn item_size(ea: Address) -> Result<AddressSize> {
    let mut out: AddressSize = 0;
    let ret = unsafe { idax_sys::idax_address_item_size(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("item_size failed"))
    } else {
        Ok(out)
    }
}

/// Start of the next defined item after `ea` (within `limit`).
pub fn next_head(ea: Address, limit: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_next_head(ea, limit, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_head failed"))
    } else {
        Ok(out)
    }
}

/// Start of the previous defined item before `ea` (down to `limit`).
pub fn prev_head(ea: Address, limit: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_prev_head(ea, limit, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("prev_head failed"))
    } else {
        Ok(out)
    }
}

/// Alias for `next_head` with discoverable naming.
pub fn next_defined(ea: Address, limit: Address) -> Result<Address> {
    next_head(ea, limit)
}

/// Alias for `prev_head` with discoverable naming.
pub fn prev_defined(ea: Address, limit: Address) -> Result<Address> {
    prev_head(ea, limit)
}

/// Next address that is not a tail byte.
pub fn next_not_tail(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_next_not_tail(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_not_tail failed"))
    } else {
        Ok(out)
    }
}

/// Previous address that is not a tail byte.
pub fn prev_not_tail(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_prev_not_tail(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("prev_not_tail failed"))
    } else {
        Ok(out)
    }
}

/// Next mapped address (any address that has flags).
pub fn next_mapped(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_next_mapped(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("next_mapped failed"))
    } else {
        Ok(out)
    }
}

/// Previous mapped address.
pub fn prev_mapped(ea: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_prev_mapped(ea, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("prev_mapped failed"))
    } else {
        Ok(out)
    }
}

/// Find first address in `[start, end)` matching a predicate.
pub fn find_first(start: Address, end: Address, predicate: Predicate) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_find_first(start, end, predicate as i32, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("find_first failed"))
    } else {
        Ok(out)
    }
}

/// Find next address after `ea` matching a predicate.
///
/// If `end` is [`BAD_ADDRESS`], searches to the end of address space.
pub fn find_next(ea: Address, predicate: Predicate, end: Address) -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let ret = unsafe { idax_sys::idax_address_find_next(ea, predicate as i32, end, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("find_next failed"))
    } else {
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Is the address mapped (has flag bytes in the database)?
pub fn is_mapped(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_mapped(ea) != 0 }
}

/// Is the address loaded from the input file?
pub fn is_loaded(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_loaded(ea) != 0 }
}

/// Is the address the start of a code item (instruction)?
pub fn is_code(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_code(ea) != 0 }
}

/// Is the address the start of a data item?
pub fn is_data(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_data(ea) != 0 }
}

/// Is the address unexplored (not code or data)?
pub fn is_unknown(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_unknown(ea) != 0 }
}

/// Is the address a head byte (start of an item)?
pub fn is_head(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_head(ea) != 0 }
}

/// Is the address a tail byte (continuation of an item)?
pub fn is_tail(ea: Address) -> bool {
    unsafe { idax_sys::idax_address_is_tail(ea) != 0 }
}

// ---------------------------------------------------------------------------
// Item-range iterator
// ---------------------------------------------------------------------------

/// Forward iterator over item head addresses in a range.
///
/// This is the Rust equivalent of C++ `ida::address::ItemIterator` /
/// `ida::address::ItemRange`.
pub struct ItemIter {
    current: Address,
    end: Address,
}

impl Iterator for ItemIter {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end || self.current == BAD_ADDRESS {
            return None;
        }
        let addr = self.current;
        // Advance to the next head
        match next_head(self.current, self.end) {
            Ok(next) => self.current = next,
            Err(_) => self.current = BAD_ADDRESS,
        }
        Some(addr)
    }
}

/// Return an iterator over all item head addresses in `[start, end)`.
pub fn items(start: Address, end: Address) -> ItemIter {
    // Find the first head at or after start
    let first = if is_head(start) {
        start
    } else {
        next_head(start, end).unwrap_or(BAD_ADDRESS)
    };
    ItemIter {
        current: if first < end { first } else { BAD_ADDRESS },
        end,
    }
}

// ---------------------------------------------------------------------------
// Predicate range iterator
// ---------------------------------------------------------------------------

/// Forward iterator over addresses matching a predicate in a range.
pub struct PredicateIter {
    current: Address,
    end: Address,
    predicate: Predicate,
}

impl PredicateIter {
    fn test(&self, ea: Address) -> bool {
        match self.predicate {
            Predicate::Mapped => is_mapped(ea),
            Predicate::Loaded => is_loaded(ea),
            Predicate::Code => is_code(ea),
            Predicate::Data => is_data(ea),
            Predicate::Unknown => is_unknown(ea),
            Predicate::Head => is_head(ea),
            Predicate::Tail => is_tail(ea),
        }
    }
}

impl Iterator for PredicateIter {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end || self.current == BAD_ADDRESS {
            return None;
        }
        let addr = self.current;
        // Advance: find the next head and check predicate
        match next_head(self.current, self.end) {
            Ok(next) => {
                // Scan forward for a matching predicate
                let mut candidate = next;
                while candidate < self.end && candidate != BAD_ADDRESS {
                    if self.test(candidate) {
                        break;
                    }
                    candidate = next_head(candidate, self.end).unwrap_or(BAD_ADDRESS);
                }
                self.current = if candidate < self.end {
                    candidate
                } else {
                    BAD_ADDRESS
                };
            }
            Err(_) => self.current = BAD_ADDRESS,
        }
        Some(addr)
    }
}

/// Find the first address in `[start, end)` matching a predicate.
fn find_first_predicate(start: Address, end: Address, predicate: Predicate) -> Address {
    let test = |ea: Address| -> bool {
        match predicate {
            Predicate::Mapped => is_mapped(ea),
            Predicate::Loaded => is_loaded(ea),
            Predicate::Code => is_code(ea),
            Predicate::Data => is_data(ea),
            Predicate::Unknown => is_unknown(ea),
            Predicate::Head => is_head(ea),
            Predicate::Tail => is_tail(ea),
        }
    };

    // Check start itself
    if start < end && test(start) {
        return start;
    }
    // Scan forward
    let mut candidate = next_head(start, end).unwrap_or(BAD_ADDRESS);
    while candidate < end && candidate != BAD_ADDRESS {
        if test(candidate) {
            return candidate;
        }
        candidate = next_head(candidate, end).unwrap_or(BAD_ADDRESS);
    }
    BAD_ADDRESS
}

/// Iterate addresses classified as code in `[start, end)`.
pub fn code_items(start: Address, end: Address) -> PredicateIter {
    let first = find_first_predicate(start, end, Predicate::Code);
    PredicateIter {
        current: first,
        end,
        predicate: Predicate::Code,
    }
}

/// Iterate addresses classified as data in `[start, end)`.
pub fn data_items(start: Address, end: Address) -> PredicateIter {
    let first = find_first_predicate(start, end, Predicate::Data);
    PredicateIter {
        current: first,
        end,
        predicate: Predicate::Data,
    }
}

/// Iterate addresses classified as unknown in `[start, end)`.
pub fn unknown_bytes(start: Address, end: Address) -> PredicateIter {
    let first = find_first_predicate(start, end, Predicate::Unknown);
    PredicateIter {
        current: first,
        end,
        predicate: Predicate::Unknown,
    }
}
