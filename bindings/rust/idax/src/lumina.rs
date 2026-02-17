//! Lumina metadata pull/push wrappers.
//!
//! Mirrors the C++ `ida::lumina` namespace.

use crate::address::Address;
use crate::error::{self, Result, Status};

/// Lumina feature channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Feature {
    PrimaryMetadata = 0,
    Decompiler = 1,
    Telemetry = 2,
    SecondaryMetadata = 3,
}

/// Push conflict-resolution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PushMode {
    PreferBetterOrDifferent = 0,
    Override = 1,
    KeepExisting = 2,
    Merge = 3,
}

/// Per-function operation status reported by Lumina.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OperationCode {
    BadPattern = -3,
    NotFound = -2,
    Error = -1,
    Ok = 0,
    Added = 1,
}

/// Pull/push batch result summary.
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub requested: usize,
    pub completed: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub codes: Vec<OperationCode>,
}

/// Whether a Lumina connection is already open.
pub fn has_connection(feature: Feature) -> Result<bool> {
    let mut has: i32 = 0;
    let ret = unsafe { idax_sys::idax_lumina_has_connection(feature as i32, &mut has) };
    if ret != 0 {
        Err(error::consume_last_error("lumina::has_connection failed"))
    } else {
        Ok(has != 0)
    }
}

/// Close a Lumina connection for one feature channel.
pub fn close_connection(feature: Feature) -> Status {
    let ret = unsafe { idax_sys::idax_lumina_close_connection(feature as i32) };
    error::int_to_status(ret, "lumina::close_connection failed")
}

/// Close all Lumina connections.
pub fn close_all_connections() -> Status {
    let ret = unsafe { idax_sys::idax_lumina_close_all_connections() };
    error::int_to_status(ret, "lumina::close_all_connections failed")
}

/// Pull metadata for the provided function addresses.
pub fn pull(addresses: &[Address], auto_apply: bool, feature: Feature) -> Result<BatchResult> {
    unsafe {
        let mut result = std::mem::zeroed::<idax_sys::IdaxLuminaBatchResult>();
        let ret = idax_sys::idax_lumina_pull(
            addresses.as_ptr(),
            addresses.len(),
            auto_apply as i32,
            feature as i32,
            &mut result,
        );
        if ret != 0 {
            return Err(error::consume_last_error("lumina::pull failed"));
        }
        Ok(BatchResult {
            requested: result.requested,
            completed: result.completed,
            succeeded: result.succeeded,
            failed: result.failed,
            codes: Vec::new(),
        })
    }
}

/// Push metadata for the provided function addresses.
pub fn push(addresses: &[Address], mode: PushMode, feature: Feature) -> Result<BatchResult> {
    unsafe {
        let mut result = std::mem::zeroed::<idax_sys::IdaxLuminaBatchResult>();
        let ret = idax_sys::idax_lumina_push(
            addresses.as_ptr(),
            addresses.len(),
            mode as i32,
            feature as i32,
            &mut result,
        );
        if ret != 0 {
            return Err(error::consume_last_error("lumina::push failed"));
        }
        Ok(BatchResult {
            requested: result.requested,
            completed: result.completed,
            succeeded: result.succeeded,
            failed: result.failed,
            codes: Vec::new(),
        })
    }
}
