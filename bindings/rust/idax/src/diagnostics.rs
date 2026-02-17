//! Shared diagnostics, logging, and lightweight counters.
//!
//! Mirrors the `ida::diagnostics` namespace from idax.

use crate::error::{self, Error, Status};
use std::ffi::CString;

/// Logging severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// Cumulative performance counters for the diagnostics subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerformanceCounters {
    pub log_messages: u64,
    pub invariant_failures: u64,
}

/// Set the global log level.
pub fn set_log_level(level: LogLevel) -> Status {
    let rc = unsafe { idax_sys::idax_diagnostics_set_log_level(level as i32) };
    error::int_to_status(rc, "diagnostics::set_log_level failed")
}

/// Get the current global log level.
pub fn log_level() -> LogLevel {
    let level = unsafe { idax_sys::idax_diagnostics_log_level() };
    match level {
        0 => LogLevel::Error,
        1 => LogLevel::Warning,
        2 => LogLevel::Info,
        3 => LogLevel::Debug,
        4 => LogLevel::Trace,
        _ => LogLevel::Info,
    }
}

/// Emit a log message at the given level and domain.
pub fn log(level: LogLevel, domain: &str, message: &str) {
    let c_domain = match CString::new(domain) {
        Ok(c) => c,
        Err(_) => return,
    };
    let c_message = match CString::new(message) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        idax_sys::idax_diagnostics_log(level as i32, c_domain.as_ptr(), c_message.as_ptr());
    }
}

/// Enrich an existing error with additional context text.
pub fn enrich(mut base: Error, context_suffix: &str) -> Error {
    if base.context.is_empty() {
        base.context = context_suffix.to_string();
    } else {
        base.context.push_str("; ");
        base.context.push_str(context_suffix);
    }
    base
}

/// Assertion-like invariant helper for non-obvious runtime expectations.
///
/// Returns `Ok(())` if the condition is true, or an error with the
/// given message if it is false.
pub fn assert_invariant(condition: bool, message: &str) -> Status {
    if condition {
        Ok(())
    } else {
        Err(Error::internal(format!("invariant violation: {message}")))
    }
}

/// Reset the global performance counters.
pub fn reset_performance_counters() {
    unsafe { idax_sys::idax_diagnostics_reset_performance_counters() };
}

/// Read the current global performance counters.
pub fn performance_counters() -> PerformanceCounters {
    let mut out = idax_sys::IdaxPerformanceCounters {
        log_messages: 0,
        invariant_failures: 0,
    };
    unsafe {
        idax_sys::idax_diagnostics_performance_counters(&mut out);
    }
    PerformanceCounters {
        log_messages: out.log_messages,
        invariant_failures: out.invariant_failures,
    }
}
