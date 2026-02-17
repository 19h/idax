//! Low-level persistent key-value storage (advanced).
//!
//! Mirrors the C++ `ida::storage` namespace. Provides an opaque `Node`
//! abstraction for persistent database storage with alt/sup/hash/blob
//! operations.
//!
//! `Node` implements `Drop` for RAII cleanup.

use crate::address::Address;
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

/// Opaque node abstraction for persistent database storage.
///
/// A `Node` wraps IDA's `netnode` — the fundamental key/value storage
/// primitive in the IDA database. Each node has a unique 64-bit ID and
/// an optional name, and supports multiple data-store layers:
///
/// - **alt**: 64-bit integer values indexed by address.
/// - **sup**: arbitrary byte blobs indexed by address.
/// - **hash**: string key/value pairs.
/// - **blob**: arbitrary binary data indexed by address.
///
/// Implements `Drop` to free the underlying SDK resources.
pub struct Node {
    handle: *mut std::ffi::c_void,
}

impl Node {
    /// Open (or optionally create) a node by name.
    ///
    /// If `create` is `true`, a new node is created when one with the given
    /// name does not already exist.
    pub fn open(name: &str, create: bool) -> Result<Self> {
        let c_name = CString::new(name).map_err(|_| Error::validation("invalid node name"))?;
        let mut h: *mut std::ffi::c_void = std::ptr::null_mut();
        let ret =
            unsafe { idax_sys::idax_storage_node_open(c_name.as_ptr(), create as i32, &mut h) };
        if ret != 0 {
            Err(error::consume_last_error("storage::Node::open failed"))
        } else {
            Ok(Self { handle: h })
        }
    }

    /// Open a node by its numeric ID.
    pub fn open_by_id(node_id: u64) -> Result<Self> {
        let mut h: *mut std::ffi::c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_storage_node_open_by_id(node_id, &mut h) };
        if ret != 0 {
            Err(error::consume_last_error(
                "storage::Node::open_by_id failed",
            ))
        } else {
            Ok(Self { handle: h })
        }
    }

    /// Get the numeric ID of this node.
    pub fn id(&self) -> Result<u64> {
        let mut val: u64 = 0;
        let ret = unsafe { idax_sys::idax_storage_node_id(self.handle, &mut val) };
        if ret != 0 {
            Err(error::consume_last_error("Node::id failed"))
        } else {
            Ok(val)
        }
    }

    /// Get the name of this node.
    pub fn name(&self) -> Result<String> {
        unsafe {
            let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_storage_node_name(self.handle, &mut out);
            if ret != 0 {
                return Err(error::consume_last_error("Node::name failed"));
            }
            error::cstr_to_string_free(out, "Node::name returned null")
        }
    }

    // ── Alt operations (64-bit integer values by address) ───────────────

    /// Get a 64-bit alt value at the given index.
    pub fn alt(&self, index: Address, tag: u8) -> Result<u64> {
        let mut val: u64 = 0;
        let ret = unsafe { idax_sys::idax_storage_node_alt_get(self.handle, index, tag, &mut val) };
        if ret != 0 {
            Err(error::consume_last_error("Node::alt failed"))
        } else {
            Ok(val)
        }
    }

    /// Get a 64-bit alt value with the default tag ('A').
    pub fn alt_default(&self, index: Address) -> Result<u64> {
        self.alt(index, b'A')
    }

    /// Set a 64-bit alt value at the given index.
    pub fn set_alt(&self, index: Address, value: u64, tag: u8) -> Status {
        let ret = unsafe { idax_sys::idax_storage_node_alt_set(self.handle, index, value, tag) };
        error::int_to_status(ret, "Node::set_alt failed")
    }

    /// Set a 64-bit alt value with the default tag ('A').
    pub fn set_alt_default(&self, index: Address, value: u64) -> Status {
        self.set_alt(index, value, b'A')
    }

    /// Remove an alt value at the given index.
    pub fn remove_alt(&self, index: Address, tag: u8) -> Status {
        let ret = unsafe { idax_sys::idax_storage_node_alt_remove(self.handle, index, tag) };
        error::int_to_status(ret, "Node::remove_alt failed")
    }

    /// Remove an alt value with the default tag ('A').
    pub fn remove_alt_default(&self, index: Address) -> Status {
        self.remove_alt(index, b'A')
    }

    // ── Sup operations (arbitrary byte blobs by address) ────────────────

    /// Get a sup blob at the given index.
    pub fn sup(&self, index: Address, tag: u8) -> Result<Vec<u8>> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let ret = unsafe {
            idax_sys::idax_storage_node_sup_get(self.handle, index, tag, &mut ptr, &mut len)
        };
        if ret != 0 {
            return Err(error::consume_last_error("Node::sup failed"));
        }
        if ptr.is_null() || len == 0 {
            return Ok(Vec::new());
        }
        let data = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        unsafe {
            idax_sys::idax_free_bytes(ptr);
        }
        Ok(data)
    }

    /// Get a sup blob with the default tag ('S').
    pub fn sup_default(&self, index: Address) -> Result<Vec<u8>> {
        self.sup(index, b'S')
    }

    /// Set a sup blob at the given index.
    pub fn set_sup(&self, index: Address, data: &[u8], tag: u8) -> Status {
        let ret = unsafe {
            idax_sys::idax_storage_node_sup_set(self.handle, index, data.as_ptr(), data.len(), tag)
        };
        error::int_to_status(ret, "Node::set_sup failed")
    }

    /// Set a sup blob with the default tag ('S').
    pub fn set_sup_default(&self, index: Address, data: &[u8]) -> Status {
        self.set_sup(index, data, b'S')
    }

    // ── Hash operations (string key/value pairs) ────────────────────────

    /// Get a hash string value by key.
    pub fn hash(&self, key: &str, tag: u8) -> Result<String> {
        let c_key = CString::new(key).map_err(|_| Error::validation("invalid hash key"))?;
        unsafe {
            let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
            let ret =
                idax_sys::idax_storage_node_hash_get(self.handle, c_key.as_ptr(), tag, &mut out);
            if ret != 0 {
                return Err(error::consume_last_error("Node::hash failed"));
            }
            error::cstr_to_string_free(out, "Node::hash returned null")
        }
    }

    /// Get a hash string value with the default tag ('H').
    pub fn hash_default(&self, key: &str) -> Result<String> {
        self.hash(key, b'H')
    }

    /// Set a hash string value by key.
    pub fn set_hash(&self, key: &str, value: &str, tag: u8) -> Status {
        let c_key = CString::new(key).map_err(|_| Error::validation("invalid hash key"))?;
        let c_val = CString::new(value).map_err(|_| Error::validation("invalid hash value"))?;
        let ret = unsafe {
            idax_sys::idax_storage_node_hash_set(self.handle, c_key.as_ptr(), c_val.as_ptr(), tag)
        };
        error::int_to_status(ret, "Node::set_hash failed")
    }

    /// Set a hash string value with the default tag ('H').
    pub fn set_hash_default(&self, key: &str, value: &str) -> Status {
        self.set_hash(key, value, b'H')
    }

    // ── Blob operations (arbitrary binary data by address) ──────────────

    /// Get the size of a blob at the given index. Returns 0 if no blob exists.
    pub fn blob_size(&self, index: Address, tag: u8) -> Result<usize> {
        let mut size: usize = 0;
        let ret =
            unsafe { idax_sys::idax_storage_node_blob_size(self.handle, index, tag, &mut size) };
        if ret != 0 {
            Err(error::consume_last_error("Node::blob_size failed"))
        } else {
            Ok(size)
        }
    }

    /// Get the size of a blob with the default tag ('B').
    pub fn blob_size_default(&self, index: Address) -> Result<usize> {
        self.blob_size(index, b'B')
    }

    /// Read a blob from the node.
    pub fn blob(&self, index: Address, tag: u8) -> Result<Vec<u8>> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let ret = unsafe {
            idax_sys::idax_storage_node_blob_get(self.handle, index, tag, &mut ptr, &mut len)
        };
        if ret != 0 {
            return Err(error::consume_last_error("Node::blob failed"));
        }
        if ptr.is_null() || len == 0 {
            return Ok(Vec::new());
        }
        let data = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        unsafe {
            idax_sys::idax_free_bytes(ptr);
        }
        Ok(data)
    }

    /// Read a blob with the default tag ('B').
    pub fn blob_default(&self, index: Address) -> Result<Vec<u8>> {
        self.blob(index, b'B')
    }

    /// Write a blob to the node.
    pub fn set_blob(&self, index: Address, data: &[u8], tag: u8) -> Status {
        let ret = unsafe {
            idax_sys::idax_storage_node_blob_set(self.handle, index, data.as_ptr(), data.len(), tag)
        };
        error::int_to_status(ret, "Node::set_blob failed")
    }

    /// Write a blob with the default tag ('B').
    pub fn set_blob_default(&self, index: Address, data: &[u8]) -> Status {
        self.set_blob(index, data, b'B')
    }

    /// Remove a blob.
    pub fn remove_blob(&self, index: Address, tag: u8) -> Status {
        let ret = unsafe { idax_sys::idax_storage_node_blob_remove(self.handle, index, tag) };
        error::int_to_status(ret, "Node::remove_blob failed")
    }

    /// Remove a blob with the default tag ('B').
    pub fn remove_blob_default(&self, index: Address) -> Status {
        self.remove_blob(index, b'B')
    }

    /// Read a blob as a string (null-terminated).
    pub fn blob_string(&self, index: Address, tag: u8) -> Result<String> {
        unsafe {
            let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_storage_node_blob_string(self.handle, index, tag, &mut out);
            if ret != 0 {
                return Err(error::consume_last_error("Node::blob_string failed"));
            }
            error::cstr_to_string_free(out, "Node::blob_string returned null")
        }
    }

    /// Read a blob as a string with the default tag ('B').
    pub fn blob_string_default(&self, index: Address) -> Result<String> {
        self.blob_string(index, b'B')
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                idax_sys::idax_storage_node_free(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node({:p})", self.handle)
    }
}
