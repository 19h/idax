//! Auto-analysis control: scheduling, waiting, enable/disable.
//!
//! Mirrors the C++ `ida::analysis` namespace.

use crate::address::Address;
use crate::error::{self, Status};

/// Is the auto-analyser enabled?
pub fn is_enabled() -> bool {
    unsafe { idax_sys::idax_analysis_is_enabled() != 0 }
}
/// Enable or disable the auto-analyser.
pub fn set_enabled(enabled: bool) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_set_enabled(enabled as i32) };
    error::int_to_status(ret, "analysis::set_enabled failed")
}
/// Is the auto-analyser idle?
pub fn is_idle() -> bool {
    unsafe { idax_sys::idax_analysis_is_idle() != 0 }
}
/// Block until the auto-analyser finishes all pending work.
pub fn wait() -> Status {
    let ret = unsafe { idax_sys::idax_analysis_wait() };
    error::int_to_status(ret, "analysis::wait failed")
}
/// Block until analysis finishes in `[start, end)`.
pub fn wait_range(start: Address, end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_wait_range(start, end) };
    error::int_to_status(ret, "analysis::wait_range failed")
}
/// Schedule reanalysis of the byte at `address`.
pub fn schedule(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule(address) };
    error::int_to_status(ret, "analysis::schedule failed")
}
/// Schedule reanalysis of `[start, end)`.
pub fn schedule_range(start: Address, end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule_range(start, end) };
    error::int_to_status(ret, "analysis::schedule_range failed")
}
/// Schedule conversion to code at `address`.
pub fn schedule_code(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule_code(address) };
    error::int_to_status(ret, "analysis::schedule_code failed")
}
/// Schedule function creation at `address`.
pub fn schedule_function(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule_function(address) };
    error::int_to_status(ret, "analysis::schedule_function failed")
}
/// Schedule reanalysis at `address`.
pub fn schedule_reanalysis(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule_reanalysis(address) };
    error::int_to_status(ret, "analysis::schedule_reanalysis failed")
}
/// Schedule reanalysis in `[start, end)`.
pub fn schedule_reanalysis_range(start: Address, end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_schedule_reanalysis_range(start, end) };
    error::int_to_status(ret, "analysis::schedule_reanalysis_range failed")
}
/// Remove pending queue entries in `[start, end)`.
pub fn cancel(start: Address, end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_cancel(start, end) };
    error::int_to_status(ret, "analysis::cancel failed")
}

/// Revert analyzer-generated decisions in `[start, end)`.
pub fn revert_decisions(start: Address, end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_analysis_revert_decisions(start, end) };
    error::int_to_status(ret, "analysis::revert_decisions failed")
}
