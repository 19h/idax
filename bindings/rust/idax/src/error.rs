//! Core error and result types for idax.
//!
//! Mirrors `ida::Error`, `ida::Result<T>`, and `ida::Status` as the canonical
//! error model used throughout every idax module.

use thiserror::Error as ThisError;

/// Broad classification of an error's origin.
///
/// Maps directly to C++ `ida::ErrorCategory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCategory {
    /// Caller-supplied argument was invalid.
    Validation = 0,
    /// The requested object does not exist.
    NotFound = 1,
    /// Operation conflicts with existing state.
    Conflict = 2,
    /// The operation is not supported in the current context.
    Unsupported = 3,
    /// The underlying IDA SDK call failed.
    SdkFailure = 4,
    /// Bug inside idax itself.
    Internal = 5,
}

/// Structured error value carried through every `Result` / `Status`.
///
/// Maps directly to C++ `ida::Error`.
#[derive(Debug, Clone, ThisError)]
#[error("[{category:?}] {message}")]
pub struct Error {
    /// Error classification.
    pub category: ErrorCategory,
    /// Numeric error code (0 for unspecified).
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Additional context (e.g., the function that failed).
    pub context: String,
}

impl Error {
    /// Create a validation error.
    pub fn validation(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Validation,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create a not-found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::NotFound,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create a conflict error.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Conflict,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create an unsupported error.
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Unsupported,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create an SDK failure error.
    pub fn sdk(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::SdkFailure,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create an internal error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            category: ErrorCategory::Internal,
            code: 0,
            message: msg.into(),
            context: String::new(),
        }
    }

    /// Create an error with context.
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = ctx.into();
        self
    }

    /// Create an error with a specific code.
    pub fn with_code(mut self, code: i32) -> Self {
        self.code = code;
        self
    }
}

/// A value-or-error return type, mirroring `ida::Result<T>`.
pub type Result<T> = std::result::Result<T, Error>;

/// A void-or-error return type, mirroring `ida::Status`.
pub type Status = std::result::Result<(), Error>;

/// Read the last error from the idax-sys thread-local error state.
///
/// Returns `None` if no error is pending.
pub fn last_error() -> Option<Error> {
    unsafe {
        let cat = idax_sys::idax_last_error_category();
        if cat < 0 {
            return None;
        }
        let code = idax_sys::idax_last_error_code();
        let msg_ptr = idax_sys::idax_last_error_message();

        let message = if msg_ptr.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(msg_ptr)
                .to_string_lossy()
                .into_owned()
        };

        let category = match cat {
            0 => ErrorCategory::Validation,
            1 => ErrorCategory::NotFound,
            2 => ErrorCategory::Conflict,
            3 => ErrorCategory::Unsupported,
            4 => ErrorCategory::SdkFailure,
            5 => ErrorCategory::Internal,
            _ => ErrorCategory::Internal,
        };

        Some(Error {
            category,
            code,
            message,
            context: String::new(),
        })
    }
}

/// Helper: consume the last FFI error or create a generic SDK failure.
pub(crate) fn consume_last_error(fallback_msg: &str) -> Error {
    last_error().unwrap_or_else(|| Error::sdk(fallback_msg))
}

/// Helper: check a boolean FFI return and convert to Status.
#[allow(dead_code)]
pub(crate) fn bool_to_status(ok: bool, fallback_msg: &str) -> Status {
    if ok {
        Ok(())
    } else {
        Err(consume_last_error(fallback_msg))
    }
}

/// Helper: check a C int return (0 = success) and convert to Status.
pub(crate) fn int_to_status(ret: i32, fallback_msg: &str) -> Status {
    if ret == 0 {
        Ok(())
    } else {
        Err(consume_last_error(fallback_msg))
    }
}

/// Helper: read a C string pointer into an owned String, returning an error on null.
///
/// Does NOT free the pointer — use for borrowed / thread-local strings.
pub(crate) unsafe fn cstr_to_string(
    ptr: *const std::ffi::c_char,
    fallback_msg: &str,
) -> Result<String> {
    if ptr.is_null() {
        Err(consume_last_error(fallback_msg))
    } else {
        unsafe { Ok(std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()) }
    }
}

/// Helper: read a C string pointer into an owned String, freeing it after.
pub(crate) unsafe fn cstr_to_string_free(
    ptr: *mut std::ffi::c_char,
    fallback_msg: &str,
) -> Result<String> {
    if ptr.is_null() {
        Err(consume_last_error(fallback_msg))
    } else {
        unsafe {
            let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned();
            idax_sys::idax_free_string(ptr);
            Ok(s)
        }
    }
}

/// Helper: consume a malloc'd C string into an owned String, freeing it.
///
/// Returns `String` unconditionally (empty if null).
pub(crate) unsafe fn consume_c_string(ptr: *mut std::ffi::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe {
            let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned();
            idax_sys::idax_free_string(ptr);
            s
        }
    }
}
