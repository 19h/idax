//! Opaque persistent address navigation history.

use std::ffi::{CStr, CString, c_char, c_void};

use crate::address::Address;
use crate::error::{self, Error, Result, Status};

/// Owned snapshot of one semantic navigation location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry {
    pub address: Address,
    pub channel: String,
    pub metadata: String,
}

impl Entry {
    #[must_use]
    pub fn new(address: Address, channel: impl Into<String>, metadata: impl Into<String>) -> Self {
        Self {
            address,
            channel: channel.into(),
            metadata: metadata.into(),
        }
    }
}

struct RawEntry {
    raw: idax_sys::IdaxNavigationEntry,
    _channel: CString,
    _metadata: CString,
}

fn cstring(value: &str, field: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation(format!("{field} contains an embedded NUL byte")))
}

fn raw_entry(entry: &Entry) -> Result<RawEntry> {
    let channel = cstring(&entry.channel, "navigation channel")?;
    let metadata = cstring(&entry.metadata, "navigation metadata")?;
    let raw = idax_sys::IdaxNavigationEntry {
        address: entry.address,
        channel: channel.as_ptr().cast_mut(),
        metadata: metadata.as_ptr().cast_mut(),
    };
    Ok(RawEntry {
        raw,
        _channel: channel,
        _metadata: metadata,
    })
}

fn empty_raw_entry() -> idax_sys::IdaxNavigationEntry {
    idax_sys::IdaxNavigationEntry {
        address: 0,
        channel: std::ptr::null_mut(),
        metadata: std::ptr::null_mut(),
    }
}

unsafe fn copy_raw_entry(raw: &idax_sys::IdaxNavigationEntry) -> Result<Entry> {
    if raw.channel.is_null() || raw.metadata.is_null() {
        return Err(Error::internal(
            "navigation entry contains a null string pointer",
        ));
    }
    let channel = unsafe { CStr::from_ptr(raw.channel) }
        .to_str()
        .map_err(|_| Error::internal("navigation channel is not valid UTF-8"))?
        .to_owned();
    let metadata = unsafe { CStr::from_ptr(raw.metadata) }
        .to_str()
        .map_err(|_| Error::internal("navigation metadata is not valid UTF-8"))?
        .to_owned();
    Ok(Entry {
        address: raw.address,
        channel,
        metadata,
    })
}

fn entry_result(
    call: impl FnOnce(*mut idax_sys::IdaxNavigationEntry) -> i32,
    fallback: &str,
) -> Result<Entry> {
    let mut raw = empty_raw_entry();
    let status = call(&mut raw);
    if status != 0 {
        unsafe { idax_sys::idax_navigation_entry_free(&mut raw) };
        return Err(error::consume_last_error(fallback));
    }
    let result = unsafe { copy_raw_entry(&raw) };
    unsafe { idax_sys::idax_navigation_entry_free(&mut raw) };
    result
}

fn optional_entry_result(
    call: impl FnOnce(*mut idax_sys::IdaxNavigationEntry, *mut i32) -> i32,
    fallback: &str,
) -> Result<Option<Entry>> {
    let mut raw = empty_raw_entry();
    let mut has_value = 0;
    let status = call(&mut raw, &mut has_value);
    if status != 0 {
        unsafe { idax_sys::idax_navigation_entry_free(&mut raw) };
        return Err(error::consume_last_error(fallback));
    }
    if has_value == 0 {
        return Ok(None);
    }
    let result = unsafe { copy_raw_entry(&raw) };
    unsafe { idax_sys::idax_navigation_entry_free(&mut raw) };
    result.map(Some)
}

fn entries_result(
    call: impl FnOnce(*mut *mut idax_sys::IdaxNavigationEntry, *mut usize) -> i32,
    fallback: &str,
) -> Result<Vec<Entry>> {
    let mut raw = std::ptr::null_mut();
    let mut count = 0;
    let status = call(&mut raw, &mut count);
    if status != 0 {
        unsafe { idax_sys::idax_navigation_entries_free(raw, count) };
        return Err(error::consume_last_error(fallback));
    }
    if count != 0 && raw.is_null() {
        return Err(Error::internal(
            "navigation entry array pointer is null for a nonempty result",
        ));
    }
    let mut result = Vec::with_capacity(count);
    if !raw.is_null() {
        let values = unsafe { std::slice::from_raw_parts(raw, count) };
        for value in values {
            match unsafe { copy_raw_entry(value) } {
                Ok(value) => result.push(value),
                Err(failure) => {
                    unsafe { idax_sys::idax_navigation_entries_free(raw, count) };
                    return Err(failure);
                }
            }
        }
        unsafe { idax_sys::idax_navigation_entries_free(raw, count) };
    }
    Ok(result)
}

/// Owned opaque handle to one persistent, IDAX-private history stream.
#[derive(Debug)]
pub struct History {
    handle: *mut c_void,
}

impl History {
    /// Open or create a logical stream with one initial tip.
    pub fn open(name: &str, initial: &Entry) -> Result<Self> {
        let name = cstring(name, "navigation history name")?;
        let initial = raw_entry(initial)?;
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            idax_sys::idax_navigation_history_open(name.as_ptr(), &initial.raw, &mut handle)
        };
        if status != 0 {
            return Err(error::consume_last_error(
                "navigation::History::open failed",
            ));
        }
        if handle.is_null() {
            return Err(Error::internal(
                "navigation history open returned a null handle",
            ));
        }
        Ok(Self { handle })
    }

    /// Return the caller-visible logical stream name.
    pub fn name(&self) -> Result<String> {
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe { idax_sys::idax_navigation_history_name(self.handle, &mut out) };
        if status != 0 {
            return Err(error::consume_last_error(
                "navigation::History::name failed",
            ));
        }
        unsafe { error::cstr_to_string_free(out, "navigation history name is null") }
    }

    /// Report whether this handle's open call created the stream.
    pub fn created(&self) -> Result<bool> {
        let mut out = 0;
        let status = unsafe { idax_sys::idax_navigation_history_created(self.handle, &mut out) };
        if status != 0 {
            return Err(error::consume_last_error(
                "navigation::History::created failed",
            ));
        }
        Ok(out != 0)
    }

    /// Copy every stack entry in index order.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        entries_result(
            |out, count| unsafe {
                idax_sys::idax_navigation_history_entries(self.handle, out, count)
            },
            "navigation::History::entries failed",
        )
    }

    /// Copy the number of stack entries.
    pub fn size(&self) -> Result<usize> {
        let mut out = 0;
        let status = unsafe { idax_sys::idax_navigation_history_size(self.handle, &mut out) };
        if status != 0 {
            return Err(error::consume_last_error(
                "navigation::History::size failed",
            ));
        }
        Ok(out)
    }

    /// Copy the current stack index.
    pub fn index(&self) -> Result<usize> {
        let mut out = 0;
        let status = unsafe { idax_sys::idax_navigation_history_index(self.handle, &mut out) };
        if status != 0 {
            return Err(error::consume_last_error(
                "navigation::History::index failed",
            ));
        }
        Ok(out)
    }

    /// Copy the entry at the current stack index.
    pub fn current(&self) -> Result<Entry> {
        entry_result(
            |out| unsafe { idax_sys::idax_navigation_history_current(self.handle, out) },
            "navigation::History::current failed",
        )
    }

    /// Copy one channel's current location, or absence.
    pub fn current_for(&self, channel: &str) -> Result<Option<Entry>> {
        let channel = cstring(channel, "navigation channel")?;
        optional_entry_result(
            |out, has_value| unsafe {
                idax_sys::idax_navigation_history_current_for(
                    self.handle,
                    channel.as_ptr(),
                    out,
                    has_value,
                )
            },
            "navigation::History::current_for failed",
        )
    }

    /// Copy every channel-current location; ordering is host-defined.
    pub fn all_current(&self) -> Result<Vec<Entry>> {
        entries_result(
            |out, count| unsafe {
                idax_sys::idax_navigation_history_all_current(self.handle, out, count)
            },
            "navigation::History::all_current failed",
        )
    }

    /// Update one channel's current location, optionally replacing the cursor.
    pub fn set_current(&self, entry: &Entry, record_in_history: bool) -> Status {
        let entry = raw_entry(entry)?;
        let status = unsafe {
            idax_sys::idax_navigation_history_set_current(
                self.handle,
                &entry.raw,
                record_in_history as i32,
            )
        };
        error::int_to_status(status, "navigation::History::set_current failed")
    }

    /// Append after the cursor, truncating forward entries.
    pub fn push(&self, entry: &Entry) -> Result<Entry> {
        let entry = raw_entry(entry)?;
        entry_result(
            |out| unsafe { idax_sys::idax_navigation_history_push(self.handle, &entry.raw, out) },
            "navigation::History::push failed",
        )
    }

    /// Move the cursor to an exact existing index.
    pub fn seek(&self, index: usize) -> Result<Entry> {
        entry_result(
            |out| unsafe { idax_sys::idax_navigation_history_seek(self.handle, index, out) },
            "navigation::History::seek failed",
        )
    }

    /// Move backward, or return absence at the boundary.
    pub fn back(&self, count: usize) -> Result<Option<Entry>> {
        optional_entry_result(
            |out, has_value| unsafe {
                idax_sys::idax_navigation_history_back(self.handle, count, out, has_value)
            },
            "navigation::History::back failed",
        )
    }

    /// Move forward, or return absence at the boundary.
    pub fn forward(&self, count: usize) -> Result<Option<Entry>> {
        optional_entry_result(
            |out, has_value| unsafe {
                idax_sys::idax_navigation_history_forward(self.handle, count, out, has_value)
            },
            "navigation::History::forward failed",
        )
    }

    /// Replace one indexed entry without changing size or cursor.
    pub fn replace(&self, index: usize, entry: &Entry) -> Status {
        let entry = raw_entry(entry)?;
        let status =
            unsafe { idax_sys::idax_navigation_history_replace(self.handle, index, &entry.raw) };
        error::int_to_status(status, "navigation::History::replace failed")
    }

    /// Replace the complete stack with one tip at index zero.
    pub fn clear(&self, new_tip: &Entry) -> Status {
        let new_tip = raw_entry(new_tip)?;
        let status = unsafe { idax_sys::idax_navigation_history_clear(self.handle, &new_tip.raw) };
        error::int_to_status(status, "navigation::History::clear failed")
    }

    /// Move one channel to another distinct history.
    pub fn transfer_channel_to(
        &self,
        destination: &History,
        channel: &str,
        retain_history: bool,
    ) -> Status {
        let channel = cstring(channel, "navigation channel")?;
        let status = unsafe {
            idax_sys::idax_navigation_history_transfer_channel_to(
                self.handle,
                destination.handle,
                channel.as_ptr(),
                retain_history as i32,
            )
        };
        error::int_to_status(status, "navigation::History::transfer_channel_to failed")
    }
}

impl Drop for History {
    fn drop(&mut self) {
        unsafe { idax_sys::idax_navigation_history_free(self.handle) };
        self.handle = std::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_constructor_preserves_owned_state() {
        let entry = Entry::new(0x401000, "disassembly", "cursor");
        assert_eq!(entry.address, 0x401000);
        assert_eq!(entry.channel, "disassembly");
        assert_eq!(entry.metadata, "cursor");
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let invalid_channel = Entry::new(0x401000, "bad\0channel", "metadata");
        assert!(raw_entry(&invalid_channel).is_err());
        let invalid_metadata = Entry::new(0x401000, "channel", "bad\0metadata");
        assert!(raw_entry(&invalid_metadata).is_err());
    }

    #[test]
    fn signatures_preserve_owned_and_optional_state() {
        let _: fn(&str, &Entry) -> Result<History> = History::open;
        let _: fn(&History) -> Result<Vec<Entry>> = History::entries;
        let _: fn(&History, &str) -> Result<Option<Entry>> = History::current_for;
        let _: fn(&History, usize) -> Result<Option<Entry>> = History::back;
        let _: fn(&History, usize) -> Result<Option<Entry>> = History::forward;
        let _: fn(&History, &History, &str, bool) -> Status = History::transfer_channel_to;
    }
}
