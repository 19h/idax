//! Opaque IDC values and synchronous script execution.

use std::ffi::{CStr, CString, c_char, c_void};

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};

/// Stable semantic kind retained by an IDC value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ValueKind {
    Integer = 0,
    FloatingPoint = 1,
    Object = 2,
    Function = 3,
    String = 4,
    OpaquePointer = 5,
    Reference = 6,
}

/// Reference traversal policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum DereferenceMode {
    Once = 0,
    #[default]
    Recursive = 1,
}

/// One compile-time name resolved to an unsigned IDC constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedName {
    pub name: String,
    pub value: u64,
}

impl ResolvedName {
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Options shared by in-memory compilation and execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompileOptions {
    pub only_safe_functions: bool,
    pub resolved_names: Vec<ResolvedName>,
}

/// IDC file-compilation options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCompileOptions {
    pub delete_macros_after_compilation: bool,
    pub allow_program_labels: bool,
    pub only_safe_functions: bool,
}

impl Default for FileCompileOptions {
    fn default() -> Self {
        Self {
            delete_macros_after_compilation: true,
            allow_program_labels: true,
            only_safe_functions: false,
        }
    }
}

/// Boolean compilation outcome with copied diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilationResult {
    pub succeeded: bool,
    pub error: String,
}

/// Boolean execution outcome. `value` retains an exception object on failure.
#[derive(Debug)]
pub struct ExecutionResult {
    pub succeeded: bool,
    pub value: Value,
    pub error: String,
}

/// Numeric expression outcome from the SDK integer entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegerExecutionResult {
    pub succeeded: bool,
    pub value: i64,
    pub error: String,
}

/// Copyable owned IDC value with no public SDK representation.
pub struct Value {
    handle: *mut c_void,
}

impl Value {
    fn from_handle(handle: *mut c_void, fallback: &str) -> Result<Self> {
        if handle.is_null() {
            Err(error::consume_last_error(fallback))
        } else {
            Ok(Self { handle })
        }
    }

    fn handle_result(call: impl FnOnce(*mut *mut c_void) -> i32, fallback: &str) -> Result<Self> {
        let mut handle = std::ptr::null_mut();
        let status = call(&mut handle);
        if status != 0 {
            return Err(error::consume_last_error(fallback));
        }
        Self::from_handle(handle, fallback)
    }

    /// Construct integer zero.
    pub fn zero() -> Self {
        Self::integer(0)
    }

    /// Construct an integer IDC value.
    pub fn integer(value: i64) -> Self {
        Self::try_integer(value)
            .unwrap_or_else(|failure| panic!("script::Value::integer failed: {failure}"))
    }

    /// Fallible integer constructor for allocation-aware code.
    pub fn try_integer(value: i64) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_integer(value, out) },
            "script::Value::integer failed",
        )
    }

    /// Construct a UTF-8 IDC string, preserving embedded NUL bytes.
    pub fn string(value: &str) -> Self {
        Self::try_string(value)
            .unwrap_or_else(|failure| panic!("script::Value::string failed: {failure}"))
    }

    /// Fallible string constructor for allocation-aware code.
    pub fn try_string(value: &str) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_string(value.as_ptr(), value.len(), out) },
            "script::Value::string failed",
        )
    }

    /// Construct an IDC floating-point value.
    pub fn floating(value: f64) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_floating(value, out) },
            "script::Value::floating failed",
        )
    }

    /// Construct an instance of the default IDC object class.
    pub fn object() -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_object(out) },
            "script::Value::object failed",
        )
    }

    /// Return the exact retained value kind.
    pub fn kind(&self) -> Result<ValueKind> {
        let mut out = -1;
        let status = unsafe { idax_sys::idax_script_value_kind(self.handle, &mut out) };
        if status != 0 {
            return Err(error::consume_last_error("script::Value::kind failed"));
        }
        match out {
            0 => Ok(ValueKind::Integer),
            1 => Ok(ValueKind::FloatingPoint),
            2 => Ok(ValueKind::Object),
            3 => Ok(ValueKind::Function),
            4 => Ok(ValueKind::String),
            5 => Ok(ValueKind::OpaquePointer),
            6 => Ok(ValueKind::Reference),
            _ => Err(Error::internal(format!(
                "script::Value::kind returned unknown kind {out}"
            ))),
        }
    }

    /// Exact kind-checked integer access; never invokes IDC coercion.
    pub fn as_integer(&self) -> Result<i64> {
        integer_result(
            |out| unsafe { idax_sys::idax_script_value_as_integer(self.handle, out) },
            "script::Value::as_integer failed",
        )
    }

    /// Exact kind-checked floating access; never invokes IDC coercion.
    pub fn as_floating(&self) -> Result<f64> {
        let mut out = 0.0;
        let status = unsafe { idax_sys::idax_script_value_as_floating(self.handle, &mut out) };
        if status == 0 {
            Ok(out)
        } else {
            Err(error::consume_last_error(
                "script::Value::as_floating failed",
            ))
        }
    }

    /// Exact kind-checked string access; never invokes IDC coercion.
    pub fn as_string(&self) -> Result<String> {
        byte_string_result(
            |out, length| unsafe {
                idax_sys::idax_script_value_as_string(self.handle, out, length)
            },
            "script::Value::as_string failed",
        )
    }

    /// Apply IDC integer coercion.
    pub fn coerce_integer(&self) -> Result<i64> {
        integer_result(
            |out| unsafe { idax_sys::idax_script_value_coerce_integer(self.handle, out) },
            "script::Value::coerce_integer failed",
        )
    }

    /// Apply IDC floating-point coercion.
    pub fn coerce_floating(&self) -> Result<f64> {
        let mut out = 0.0;
        let status = unsafe { idax_sys::idax_script_value_coerce_floating(self.handle, &mut out) };
        if status == 0 {
            Ok(out)
        } else {
            Err(error::consume_last_error(
                "script::Value::coerce_floating failed",
            ))
        }
    }

    /// Apply IDC string coercion.
    pub fn coerce_string(&self) -> Result<String> {
        byte_string_result(
            |out, length| unsafe {
                idax_sys::idax_script_value_coerce_string(self.handle, out, length)
            },
            "script::Value::coerce_string failed",
        )
    }

    /// Produce an IDC textual representation.
    pub fn render(&self, name: Option<&str>, indent: usize) -> Result<String> {
        let name = name
            .map(|value| cstring(value, "IDC render name"))
            .transpose()?;
        let mut out = std::ptr::null_mut();
        let status = unsafe {
            idax_sys::idax_script_value_render(
                self.handle,
                name.as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                indent,
                &mut out,
            )
        };
        if status != 0 {
            return Err(error::consume_last_error("script::Value::render failed"));
        }
        unsafe { error::cstr_to_string_free(out, "script value rendering is null") }
    }

    /// Deep-copy an object; non-object values use ordinary copy semantics.
    pub fn deep_copy(&self) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_deep_copy(self.handle, out) },
            "script::Value::deep_copy failed",
        )
    }

    /// Return the copied IDC object class name.
    pub fn class_name(&self) -> Result<String> {
        string_result(
            |out| unsafe { idax_sys::idax_script_value_class_name(self.handle, out) },
            "script::Value::class_name failed",
        )
    }

    /// Read one copied object attribute.
    pub fn attribute(&self, name: &str, use_handler: bool) -> Result<Self> {
        let name = cstring(name, "IDC attribute name")?;
        Self::handle_result(
            |out| unsafe {
                idax_sys::idax_script_value_attribute(
                    self.handle,
                    name.as_ptr(),
                    use_handler as i32,
                    out,
                )
            },
            "script::Value::attribute failed",
        )
    }

    /// Assign one object attribute.
    pub fn set_attribute(&mut self, name: &str, value: &Self, use_handler: bool) -> Status {
        let name = cstring(name, "IDC attribute name")?;
        let status = unsafe {
            idax_sys::idax_script_value_set_attribute(
                self.handle,
                name.as_ptr(),
                value.handle,
                use_handler as i32,
            )
        };
        error::int_to_status(status, "script::Value::set_attribute failed")
    }

    /// Enumerate copied object attribute names.
    pub fn attribute_names(&self) -> Result<Vec<String>> {
        string_array_result(
            |out, count| unsafe {
                idax_sys::idax_script_value_attribute_names(self.handle, out, count)
            },
            "script::Value::attribute_names failed",
        )
    }

    /// Remove one object attribute, returning whether it existed.
    pub fn remove_attribute(&mut self, name: &str) -> Result<bool> {
        let name = cstring(name, "IDC attribute name")?;
        boolean_result(
            |out| unsafe {
                idax_sys::idax_script_value_remove_attribute(self.handle, name.as_ptr(), out)
            },
            "script::Value::remove_attribute failed",
        )
    }

    /// Read a half-open string/object slice `[begin, end)`.
    pub fn slice(&self, begin: usize, end: usize) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_slice(self.handle, begin, end, out) },
            "script::Value::slice failed",
        )
    }

    /// Replace a half-open string/object slice `[begin, end)`.
    pub fn replace_slice(&mut self, begin: usize, end: usize, replacement: &Self) -> Status {
        let status = unsafe {
            idax_sys::idax_script_value_replace_slice(self.handle, begin, end, replacement.handle)
        };
        error::int_to_status(status, "script::Value::replace_slice failed")
    }

    /// Copy the value reached through an IDC reference.
    pub fn dereference(&self, mode: DereferenceMode) -> Result<Self> {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_dereference(self.handle, mode as i32, out) },
            "script::Value::dereference failed",
        )
    }

    fn as_raw(&self) -> *mut c_void {
        self.handle
    }
}

impl Default for Value {
    fn default() -> Self {
        Self::zero()
    }
}

impl Clone for Value {
    fn clone(&self) -> Self {
        Self::handle_result(
            |out| unsafe { idax_sys::idax_script_value_clone(self.handle, out) },
            "script::Value::clone failed",
        )
        .unwrap_or_else(|failure| panic!("script::Value::clone failed: {failure}"))
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { idax_sys::idax_script_value_free(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind(), self.render(None, 0)) {
            (Ok(kind), Ok(rendered)) => formatter
                .debug_struct("Value")
                .field("kind", &kind)
                .field("rendered", &rendered)
                .finish(),
            _ => formatter.debug_struct("Value").finish_non_exhaustive(),
        }
    }
}

struct RawResolvedNames {
    names: Vec<CString>,
    entries: Vec<idax_sys::IdaxScriptResolvedName>,
}

impl RawResolvedNames {
    fn new(values: &[ResolvedName]) -> Result<Self> {
        let names = values
            .iter()
            .map(|entry| cstring(&entry.name, "resolved name"))
            .collect::<Result<Vec<_>>>()?;
        let entries = values
            .iter()
            .zip(names.iter())
            .map(|(entry, name)| idax_sys::IdaxScriptResolvedName {
                name: name.as_ptr(),
                value: entry.value,
            })
            .collect();
        Ok(Self { names, entries })
    }

    fn pointer(&self) -> *const idax_sys::IdaxScriptResolvedName {
        if self.entries.is_empty() {
            std::ptr::null()
        } else {
            self.entries.as_ptr()
        }
    }

    fn count(&self) -> usize {
        debug_assert_eq!(self.names.len(), self.entries.len());
        self.entries.len()
    }
}

struct RawCompileOptions {
    _resolved: RawResolvedNames,
    native: idax_sys::IdaxScriptCompileOptions,
}

impl RawCompileOptions {
    fn new(options: &CompileOptions) -> Result<Self> {
        let resolved = RawResolvedNames::new(&options.resolved_names)?;
        let native = idax_sys::IdaxScriptCompileOptions {
            only_safe_functions: options.only_safe_functions as i32,
            resolved_names: resolved.pointer(),
            resolved_name_count: resolved.count(),
        };
        Ok(Self {
            _resolved: resolved,
            native,
        })
    }
}

fn raw_file_options(options: &FileCompileOptions) -> idax_sys::IdaxScriptFileCompileOptions {
    idax_sys::IdaxScriptFileCompileOptions {
        delete_macros_after_compilation: options.delete_macros_after_compilation as i32,
        allow_program_labels: options.allow_program_labels as i32,
        only_safe_functions: options.only_safe_functions as i32,
    }
}

fn cstring(value: &str, field: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation(format!("{field} contains an embedded NUL byte")))
}

fn integer_result(call: impl FnOnce(*mut i64) -> i32, fallback: &str) -> Result<i64> {
    let mut out = 0;
    let status = call(&mut out);
    if status == 0 {
        Ok(out)
    } else {
        Err(error::consume_last_error(fallback))
    }
}

fn boolean_result(call: impl FnOnce(*mut i32) -> i32, fallback: &str) -> Result<bool> {
    let mut out = 0;
    let status = call(&mut out);
    if status == 0 {
        Ok(out != 0)
    } else {
        Err(error::consume_last_error(fallback))
    }
}

fn string_result(call: impl FnOnce(*mut *mut c_char) -> i32, fallback: &str) -> Result<String> {
    let mut out = std::ptr::null_mut();
    let status = call(&mut out);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    unsafe { error::cstr_to_string_free(out, fallback) }
}

fn byte_string_result(
    call: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    fallback: &str,
) -> Result<String> {
    let mut out = std::ptr::null_mut();
    let mut length = 0;
    let status = call(&mut out, &mut length);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    if length != 0 && out.is_null() {
        return Err(Error::internal(format!(
            "{fallback}: null byte pointer for nonempty result"
        )));
    }
    let bytes = if length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(out, length) }.to_vec()
    };
    unsafe { idax_sys::idax_free_bytes(out) };
    String::from_utf8(bytes)
        .map_err(|_| Error::internal(format!("{fallback}: result is not valid UTF-8")))
}

fn string_array_result(
    call: impl FnOnce(*mut *mut *mut c_char, *mut usize) -> i32,
    fallback: &str,
) -> Result<Vec<String>> {
    let mut out = std::ptr::null_mut();
    let mut count = 0;
    let status = call(&mut out, &mut count);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    let result = if count == 0 {
        Ok(Vec::new())
    } else if out.is_null() {
        Err(Error::internal(format!(
            "{fallback}: null array pointer for nonempty result"
        )))
    } else {
        unsafe { std::slice::from_raw_parts(out, count) }
            .iter()
            .map(|pointer| {
                if pointer.is_null() {
                    Err(Error::internal(format!("{fallback}: null string pointer")))
                } else {
                    unsafe { CStr::from_ptr(*pointer) }
                        .to_str()
                        .map(str::to_owned)
                        .map_err(|_| {
                            Error::internal(format!("{fallback}: result is not valid UTF-8"))
                        })
                }
            })
            .collect()
    };
    unsafe { idax_sys::idax_script_string_array_free(out, count) };
    result
}

fn consume_error(pointer: *mut c_char, fallback: &str) -> Result<String> {
    if pointer.is_null() {
        return Err(Error::internal(format!("{fallback}: error string is null")));
    }
    let result = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| Error::internal(format!("{fallback}: error is not valid UTF-8")));
    unsafe { idax_sys::idax_free_string(pointer) };
    result
}

fn compilation_result(
    call: impl FnOnce(*mut idax_sys::IdaxScriptCompilationResult) -> i32,
    fallback: &str,
) -> Result<CompilationResult> {
    let mut raw = idax_sys::IdaxScriptCompilationResult {
        succeeded: 0,
        error: std::ptr::null_mut(),
    };
    let status = call(&mut raw);
    if status != 0 {
        unsafe { idax_sys::idax_script_compilation_result_free(&mut raw) };
        return Err(error::consume_last_error(fallback));
    }
    let message = consume_error(raw.error, fallback);
    raw.error = std::ptr::null_mut();
    unsafe { idax_sys::idax_script_compilation_result_free(&mut raw) };
    Ok(CompilationResult {
        succeeded: raw.succeeded != 0,
        error: message?,
    })
}

fn execution_result(
    call: impl FnOnce(*mut idax_sys::IdaxScriptExecutionResult) -> i32,
    fallback: &str,
) -> Result<ExecutionResult> {
    let mut raw = idax_sys::IdaxScriptExecutionResult {
        succeeded: 0,
        value: std::ptr::null_mut(),
        error: std::ptr::null_mut(),
    };
    let status = call(&mut raw);
    if status != 0 {
        unsafe { idax_sys::idax_script_execution_result_free(&mut raw) };
        return Err(error::consume_last_error(fallback));
    }
    let succeeded = raw.succeeded != 0;
    let value = Value::from_handle(raw.value, fallback);
    if value.is_ok() {
        raw.value = std::ptr::null_mut();
    }
    let message = consume_error(raw.error, fallback);
    raw.error = std::ptr::null_mut();
    unsafe { idax_sys::idax_script_execution_result_free(&mut raw) };
    Ok(ExecutionResult {
        succeeded,
        value: value?,
        error: message?,
    })
}

fn integer_execution_result(
    call: impl FnOnce(*mut idax_sys::IdaxScriptIntegerExecutionResult) -> i32,
    fallback: &str,
) -> Result<IntegerExecutionResult> {
    let mut raw = idax_sys::IdaxScriptIntegerExecutionResult {
        succeeded: 0,
        value: 0,
        error: std::ptr::null_mut(),
    };
    let status = call(&mut raw);
    if status != 0 {
        unsafe { idax_sys::idax_script_integer_execution_result_free(&mut raw) };
        return Err(error::consume_last_error(fallback));
    }
    let message = consume_error(raw.error, fallback);
    raw.error = std::ptr::null_mut();
    unsafe { idax_sys::idax_script_integer_execution_result_free(&mut raw) };
    Ok(IntegerExecutionResult {
        succeeded: raw.succeeded != 0,
        value: raw.value,
        error: message?,
    })
}

/// Evaluate using the selected expression language.
pub fn evaluate(expression: &str, where_: Address) -> Result<ExecutionResult> {
    let expression = cstring(expression, "script expression")?;
    execution_result(
        |out| unsafe { idax_sys::idax_script_evaluate(expression.as_ptr(), where_, out) },
        "script::evaluate failed",
    )
}

/// Evaluate without an address context.
pub fn evaluate_current(expression: &str) -> Result<ExecutionResult> {
    evaluate(expression, BAD_ADDRESS)
}

/// Evaluate using IDC even when another expression language is selected.
pub fn evaluate_idc(expression: &str, where_: Address) -> Result<ExecutionResult> {
    let expression = cstring(expression, "IDC expression")?;
    execution_result(
        |out| unsafe { idax_sys::idax_script_evaluate_idc(expression.as_ptr(), where_, out) },
        "script::evaluate_idc failed",
    )
}

/// Evaluate IDC without an address context.
pub fn evaluate_idc_current(expression: &str) -> Result<ExecutionResult> {
    evaluate_idc(expression, BAD_ADDRESS)
}

/// Evaluate through the selected language's integer entry point.
pub fn evaluate_integer(expression: &str, where_: Address) -> Result<IntegerExecutionResult> {
    let expression = cstring(expression, "integer expression")?;
    integer_execution_result(
        |out| unsafe { idax_sys::idax_script_evaluate_integer(expression.as_ptr(), where_, out) },
        "script::evaluate_integer failed",
    )
}

/// Evaluate an integer without an address context.
pub fn evaluate_integer_current(expression: &str) -> Result<IntegerExecutionResult> {
    evaluate_integer(expression, BAD_ADDRESS)
}

/// Compile IDC definitions from a file.
pub fn compile_file(path: &str, options: &FileCompileOptions) -> Result<CompilationResult> {
    let path = cstring(path, "IDC file path")?;
    let options = raw_file_options(options);
    compilation_result(
        |out| unsafe { idax_sys::idax_script_compile_file(path.as_ptr(), &options, out) },
        "script::compile_file failed",
    )
}

/// Compile IDC definitions from source text.
pub fn compile_text(source: &str, options: &CompileOptions) -> Result<CompilationResult> {
    let source = cstring(source, "IDC source text")?;
    let options = RawCompileOptions::new(options)?;
    compilation_result(
        |out| unsafe { idax_sys::idax_script_compile_text(source.as_ptr(), &options.native, out) },
        "script::compile_text failed",
    )
}

/// Compile one named IDC snippet.
pub fn compile_snippet(
    function_name: &str,
    body: &str,
    options: &CompileOptions,
) -> Result<CompilationResult> {
    let function_name = cstring(function_name, "IDC snippet function name")?;
    let body = cstring(body, "IDC snippet body")?;
    let options = RawCompileOptions::new(options)?;
    compilation_result(
        |out| unsafe {
            idax_sys::idax_script_compile_snippet(
                function_name.as_ptr(),
                body.as_ptr(),
                &options.native,
                out,
            )
        },
        "script::compile_snippet failed",
    )
}

fn raw_value_handles(arguments: &[Value]) -> Vec<*mut c_void> {
    arguments.iter().map(Value::as_raw).collect()
}

/// Invoke a compiled, built-in, or plugin-defined IDC function.
pub fn call(
    function_name: &str,
    arguments: &[Value],
    resolved_names: &[ResolvedName],
) -> Result<ExecutionResult> {
    let function_name = cstring(function_name, "IDC function name")?;
    let arguments = raw_value_handles(arguments);
    let resolved = RawResolvedNames::new(resolved_names)?;
    execution_result(
        |out| unsafe {
            idax_sys::idax_script_call(
                function_name.as_ptr(),
                if arguments.is_empty() {
                    std::ptr::null()
                } else {
                    arguments.as_ptr()
                },
                arguments.len(),
                resolved.pointer(),
                resolved.count(),
                out,
            )
        },
        "script::call failed",
    )
}

/// Compile an IDC file and invoke one function when compilation succeeds.
pub fn execute_script(
    path: &str,
    function_name: &str,
    arguments: &[Value],
    options: &FileCompileOptions,
) -> Result<ExecutionResult> {
    let path = cstring(path, "IDC file path")?;
    let function_name = cstring(function_name, "IDC function name")?;
    let arguments = raw_value_handles(arguments);
    let options = raw_file_options(options);
    execution_result(
        |out| unsafe {
            idax_sys::idax_script_execute_script(
                path.as_ptr(),
                function_name.as_ptr(),
                if arguments.is_empty() {
                    std::ptr::null()
                } else {
                    arguments.as_ptr()
                },
                arguments.len(),
                &options,
                out,
            )
        },
        "script::execute_script failed",
    )
}

/// Compile and execute IDC statements or expressions.
pub fn evaluate_snippet(source: &str, resolved_names: &[ResolvedName]) -> Result<ExecutionResult> {
    let source = cstring(source, "IDC snippet source")?;
    let resolved = RawResolvedNames::new(resolved_names)?;
    execution_result(
        |out| unsafe {
            idax_sys::idax_script_evaluate_snippet(
                source.as_ptr(),
                resolved.pointer(),
                resolved.count(),
                out,
            )
        },
        "script::evaluate_snippet failed",
    )
}

struct RawStrings {
    values: Vec<CString>,
    pointers: Vec<*const c_char>,
}

impl RawStrings {
    fn new(values: &[String], field: &str) -> Result<Self> {
        let values = values
            .iter()
            .map(|value| cstring(value, field))
            .collect::<Result<Vec<_>>>()?;
        let pointers = values.iter().map(|value| value.as_ptr()).collect();
        Ok(Self { values, pointers })
    }

    fn pointer(&self) -> *const *const c_char {
        debug_assert_eq!(self.values.len(), self.pointers.len());
        if self.pointers.is_empty() {
            std::ptr::null()
        } else {
            self.pointers.as_ptr()
        }
    }
}

/// Replace IDC include-search path components.
pub fn set_include_paths(paths: &[String]) -> Status {
    let paths = RawStrings::new(paths, "IDC include path")?;
    let status =
        unsafe { idax_sys::idax_script_set_include_paths(paths.pointer(), paths.pointers.len()) };
    error::int_to_status(status, "script::set_include_paths failed")
}

/// Append IDC include-search path components.
pub fn append_include_paths(paths: &[String]) -> Status {
    let paths = RawStrings::new(paths, "IDC include path")?;
    let status = unsafe {
        idax_sys::idax_script_append_include_paths(paths.pointer(), paths.pointers.len())
    };
    error::int_to_status(status, "script::append_include_paths failed")
}

/// Resolve one IDC filename through the interpreter search path.
pub fn resolve_file(file: &str) -> Result<Option<String>> {
    let file = cstring(file, "IDC filename")?;
    let mut out = std::ptr::null_mut();
    let mut has_value = 0;
    let status =
        unsafe { idax_sys::idax_script_resolve_file(file.as_ptr(), &mut out, &mut has_value) };
    if status != 0 {
        return Err(error::consume_last_error("script::resolve_file failed"));
    }
    if has_value == 0 {
        return Ok(None);
    }
    unsafe { error::cstr_to_string_free(out, "resolved IDC filename is null") }.map(Some)
}

/// Compile and execute `main` from an IDC system script.
pub fn execute_system_script(file: &str, complain_if_missing: bool) -> Status {
    let file = cstring(file, "IDC system script filename")?;
    let status = unsafe {
        idax_sys::idax_script_execute_system_script(file.as_ptr(), complain_if_missing as i32)
    };
    error::int_to_status(status, "script::execute_system_script failed")
}

/// Enumerate registered and built-in IDC function names matching a prefix.
pub fn function_names(prefix: &str, maximum: usize) -> Result<Vec<String>> {
    let prefix = cstring(prefix, "IDC function prefix")?;
    string_array_result(
        |out, count| unsafe {
            idax_sys::idax_script_function_names(prefix.as_ptr(), maximum, out, count)
        },
        "script::function_names failed",
    )
}

/// Read one copied IDC global.
pub fn global(name: &str) -> Result<Option<Value>> {
    let name = cstring(name, "IDC global name")?;
    let mut handle = std::ptr::null_mut();
    let mut has_value = 0;
    let status =
        unsafe { idax_sys::idax_script_global(name.as_ptr(), &mut handle, &mut has_value) };
    if status != 0 {
        return Err(error::consume_last_error("script::global failed"));
    }
    if has_value == 0 {
        return Ok(None);
    }
    Value::from_handle(handle, "script::global returned a null handle").map(Some)
}

/// Assign or create one IDC global; return whether it was created.
pub fn set_global(name: &str, value: &Value) -> Result<bool> {
    let name = cstring(name, "IDC global name")?;
    boolean_result(
        |out| unsafe { idax_sys::idax_script_set_global(name.as_ptr(), value.handle, out) },
        "script::set_global failed",
    )
}

/// Create an IDC reference to an existing global.
pub fn reference_global(name: &str) -> Result<Value> {
    let name = cstring(name, "IDC global name")?;
    Value::handle_result(
        |out| unsafe { idax_sys::idax_script_reference_global(name.as_ptr(), out) },
        "script::reference_global failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_cpp_contract() {
        let file = FileCompileOptions::default();
        assert!(file.delete_macros_after_compilation);
        assert!(file.allow_program_labels);
        assert!(!file.only_safe_functions);
        assert_eq!(DereferenceMode::default(), DereferenceMode::Recursive);
    }

    #[test]
    fn c_string_fields_reject_embedded_nul() {
        let failure = function_names("bad\0prefix", 1).unwrap_err();
        assert_eq!(failure.category, crate::error::ErrorCategory::Validation);
    }
}
