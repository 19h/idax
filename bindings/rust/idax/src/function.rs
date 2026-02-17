//! Function operations: creation, query, traversal, chunks, frames.
//!
//! Mirrors the C++ `ida::function` namespace. All functions are represented
//! by opaque `Function` value objects.

use crate::address::{Address, AddressDelta, AddressSize};
use crate::error::{self, Error, Result, Status};
use crate::types::TypeInfo;
use std::ffi::CString;

unsafe extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

// ---------------------------------------------------------------------------
// Chunk
// ---------------------------------------------------------------------------

/// A contiguous address range belonging to a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub start: Address,
    pub end: Address,
    pub is_tail: bool,
    pub owner: Address,
}

impl Chunk {
    pub fn size(&self) -> AddressSize {
        self.end.saturating_sub(self.start)
    }
}

// ---------------------------------------------------------------------------
// Frame variable
// ---------------------------------------------------------------------------

/// Describes a single stack variable in a function's frame.
#[derive(Debug, Clone)]
pub struct FrameVariable {
    pub name: String,
    pub byte_offset: usize,
    pub byte_size: usize,
    pub comment: String,
    pub is_special: bool,
}

/// Describes a register variable alias over an address range.
#[derive(Debug, Clone)]
pub struct RegisterVariable {
    pub range_start: Address,
    pub range_end: Address,
    pub canonical_name: String,
    pub user_name: String,
    pub comment: String,
}

// ---------------------------------------------------------------------------
// Stack frame
// ---------------------------------------------------------------------------

/// Snapshot of a function's stack frame layout.
#[derive(Debug, Clone)]
pub struct StackFrame {
    local_size: AddressSize,
    regs_size: AddressSize,
    args_size: AddressSize,
    total_size: AddressSize,
    vars: Vec<FrameVariable>,
}

impl StackFrame {
    pub fn local_variables_size(&self) -> AddressSize {
        self.local_size
    }
    pub fn saved_registers_size(&self) -> AddressSize {
        self.regs_size
    }
    pub fn arguments_size(&self) -> AddressSize {
        self.args_size
    }
    pub fn total_size(&self) -> AddressSize {
        self.total_size
    }
    pub fn variables(&self) -> &[FrameVariable] {
        &self.vars
    }
}

// ---------------------------------------------------------------------------
// Function value object
// ---------------------------------------------------------------------------

/// Opaque snapshot of a function.
#[derive(Debug, Clone)]
pub struct Function {
    start: Address,
    end: Address,
    func_name: String,
    bitness: i32,
    returns: bool,
    library: bool,
    thunk: bool,
    visible: bool,
    frsize: AddressSize,
    frregs: AddressSize,
    argsize: AddressSize,
}

impl Function {
    pub fn start(&self) -> Address {
        self.start
    }
    pub fn end(&self) -> Address {
        self.end
    }
    pub fn size(&self) -> AddressSize {
        self.end.saturating_sub(self.start)
    }
    pub fn name(&self) -> &str {
        &self.func_name
    }
    pub fn bitness(&self) -> i32 {
        self.bitness
    }
    pub fn returns(&self) -> bool {
        self.returns
    }
    pub fn is_library(&self) -> bool {
        self.library
    }
    pub fn is_thunk(&self) -> bool {
        self.thunk
    }
    pub fn is_visible(&self) -> bool {
        self.visible
    }
    pub fn frame_local_size(&self) -> AddressSize {
        self.frsize
    }
    pub fn frame_regs_size(&self) -> AddressSize {
        self.frregs
    }
    pub fn frame_args_size(&self) -> AddressSize {
        self.argsize
    }

    /// Re-read from database.
    pub fn refresh(&mut self) -> Status {
        let refreshed = at(self.start)?;
        *self = refreshed;
        Ok(())
    }
}

/// Helper to construct a Function from an IdaxFunction struct.
unsafe fn function_from_raw(f: &idax_sys::IdaxFunction) -> Function {
    let func_name = unsafe { error::consume_c_string(f.name) };
    Function {
        start: f.start,
        end: f.end,
        func_name,
        bitness: f.bitness,
        returns: f.returns != 0,
        library: f.is_library != 0,
        thunk: f.is_thunk != 0,
        visible: f.is_visible != 0,
        frsize: f.frame_local_size,
        frregs: f.frame_regs_size,
        argsize: f.frame_args_size,
    }
}

unsafe fn frame_variable_from_raw(raw: &idax_sys::IdaxFrameVariable) -> FrameVariable {
    FrameVariable {
        name: unsafe { error::consume_c_string(raw.name) },
        byte_offset: raw.byte_offset,
        byte_size: raw.byte_size,
        comment: unsafe { error::consume_c_string(raw.comment) },
        is_special: raw.is_special != 0,
    }
}

unsafe fn register_variable_from_raw(raw: &idax_sys::IdaxRegisterVariable) -> RegisterVariable {
    RegisterVariable {
        range_start: raw.range_start,
        range_end: raw.range_end,
        canonical_name: unsafe { error::consume_c_string(raw.canonical_name) },
        user_name: unsafe { error::consume_c_string(raw.user_name) },
        comment: unsafe { error::consume_c_string(raw.comment) },
    }
}

fn register_variable_from_raw_borrowed(
    raw: &idax_sys::IdaxRegisterVariable,
) -> Result<RegisterVariable> {
    Ok(RegisterVariable {
        range_start: raw.range_start,
        range_end: raw.range_end,
        canonical_name: unsafe {
            error::cstr_to_string(raw.canonical_name, "canonical register name")?
        },
        user_name: unsafe { error::cstr_to_string(raw.user_name, "register user name")? },
        comment: unsafe { error::cstr_to_string(raw.comment, "register variable comment")? },
    })
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Create a function. If `end` is `BAD_ADDRESS`, IDA determines the bounds.
pub fn create(start: Address, end: Address) -> Result<Function> {
    unsafe {
        let mut raw = idax_sys::IdaxFunction::default();
        let ret = idax_sys::idax_function_create(start, end, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("function::create failed"));
        }
        Ok(function_from_raw(&raw))
    }
}

/// Delete the function containing `address`.
pub fn remove(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_remove(address) };
    error::int_to_status(ret, "function::remove failed")
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Function containing the given address.
pub fn at(address: Address) -> Result<Function> {
    unsafe {
        let mut raw = idax_sys::IdaxFunction::default();
        let ret = idax_sys::idax_function_at(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("function::at failed"));
        }
        Ok(function_from_raw(&raw))
    }
}

/// Function by positional index (0-based).
pub fn by_index(index: usize) -> Result<Function> {
    unsafe {
        let mut raw = idax_sys::IdaxFunction::default();
        let ret = idax_sys::idax_function_by_index(index, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("function::by_index failed"));
        }
        Ok(function_from_raw(&raw))
    }
}

/// Total number of functions.
pub fn count() -> Result<usize> {
    let mut n: usize = 0;
    let ret = unsafe { idax_sys::idax_function_count(&mut n) };
    if ret != 0 {
        Err(error::consume_last_error("function::count failed"))
    } else {
        Ok(n)
    }
}

/// Get the name of the function containing `address`.
pub fn name_at(address: Address) -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_function_name_at(address, &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("function::name_at failed"));
        }
        error::cstr_to_string_free(ptr, "function::name_at null")
    }
}

// ---------------------------------------------------------------------------
// Boundary mutation
// ---------------------------------------------------------------------------

/// Set function start address.
pub fn set_start(address: Address, new_start: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_set_start(address, new_start) };
    error::int_to_status(ret, "function::set_start failed")
}

/// Set function end address.
pub fn set_end(address: Address, new_end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_set_end(address, new_end) };
    error::int_to_status(ret, "function::set_end failed")
}

/// Persist in-memory function metadata to the database.
pub fn update(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_update(address) };
    error::int_to_status(ret, "function::update failed")
}

/// Schedule reanalysis for all items belonging to the function.
pub fn reanalyze(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_reanalyze(address) };
    error::int_to_status(ret, "function::reanalyze failed")
}

/// Return true if the function is marked as outlined.
pub fn is_outlined(address: Address) -> Result<bool> {
    let mut outlined: i32 = 0;
    let ret = unsafe { idax_sys::idax_function_is_outlined(address, &mut outlined) };
    if ret != 0 {
        Err(error::consume_last_error("function::is_outlined failed"))
    } else {
        Ok(outlined != 0)
    }
}

/// Set or clear the outlined marker on a function.
pub fn set_outlined(address: Address, outlined: bool) -> Status {
    let ret = unsafe { idax_sys::idax_function_set_outlined(address, outlined as i32) };
    error::int_to_status(ret, "function::set_outlined failed")
}

// ---------------------------------------------------------------------------
// Comment access
// ---------------------------------------------------------------------------

/// Get function comment.
pub fn comment(address: Address, repeatable: bool) -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_function_comment(address, repeatable as i32, &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("function::comment failed"));
        }
        error::cstr_to_string_free(ptr, "function::comment null")
    }
}

/// Set function comment.
pub fn set_comment(address: Address, text: &str, repeatable: bool) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid comment text"))?;
    let ret =
        unsafe { idax_sys::idax_function_set_comment(address, c_text.as_ptr(), repeatable as i32) };
    error::int_to_status(ret, "function::set_comment failed")
}

// ---------------------------------------------------------------------------
// Relationship helpers
// ---------------------------------------------------------------------------

/// Addresses of all functions that call `address`.
pub fn callers(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_function_callers(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("function::callers failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// Addresses of all functions called from the function at `address`.
pub fn callees(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_function_callees(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("function::callees failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Chunk operations
// ---------------------------------------------------------------------------

/// Get all chunks (entry + tails) for the function containing `address`.
pub fn chunks(address: Address) -> Result<Vec<Chunk>> {
    unsafe {
        let mut count: usize = 0;
        let mut chunks_ptr: *mut idax_sys::IdaxChunk = std::ptr::null_mut();
        let ret = idax_sys::idax_function_chunks(address, &mut chunks_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("function::chunks failed"));
        }
        let result = if chunks_ptr.is_null() || count == 0 {
            Vec::new()
        } else {
            let slice = std::slice::from_raw_parts(chunks_ptr, count);
            slice
                .iter()
                .map(|c| Chunk {
                    start: c.start,
                    end: c.end,
                    is_tail: c.is_tail != 0,
                    owner: c.owner,
                })
                .collect()
        };
        if !chunks_ptr.is_null() {
            free(chunks_ptr as *mut std::ffi::c_void);
        }
        Ok(result)
    }
}

/// Get only tail chunks for the function containing `address`.
pub fn tail_chunks(address: Address) -> Result<Vec<Chunk>> {
    let all = chunks(address)?;
    Ok(all.into_iter().filter(|c| c.is_tail).collect())
}

/// Number of chunks (entry + tails) for the function at `address`.
pub fn chunk_count(address: Address) -> Result<usize> {
    let mut n: usize = 0;
    let ret = unsafe { idax_sys::idax_function_chunk_count(address, &mut n) };
    if ret != 0 {
        Err(error::consume_last_error("function::chunk_count failed"))
    } else {
        Ok(n)
    }
}

/// Append a tail chunk to the function at `function_address`.
pub fn add_tail(function_address: Address, tail_start: Address, tail_end: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_add_tail(function_address, tail_start, tail_end) };
    error::int_to_status(ret, "function::add_tail failed")
}

/// Remove a tail chunk starting at `tail_address`.
pub fn remove_tail(function_address: Address, tail_address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_function_remove_tail(function_address, tail_address) };
    error::int_to_status(ret, "function::remove_tail failed")
}

// ---------------------------------------------------------------------------
// Frame operations
// ---------------------------------------------------------------------------

/// Retrieve a snapshot of the stack frame for the function at `address`.
pub fn frame(address: Address) -> Result<StackFrame> {
    unsafe {
        let mut raw = idax_sys::IdaxStackFrame::default();
        let ret = idax_sys::idax_function_frame(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("function::frame failed"));
        }

        let vars = if raw.variables.is_null() || raw.variable_count == 0 {
            Vec::new()
        } else {
            let slice = std::slice::from_raw_parts(raw.variables, raw.variable_count);
            slice
                .iter()
                .map(|v| FrameVariable {
                    name: error::consume_c_string(v.name),
                    byte_offset: v.byte_offset,
                    byte_size: v.byte_size,
                    comment: error::consume_c_string(v.comment),
                    is_special: v.is_special != 0,
                })
                .collect()
        };

        // Free the stack frame (frees variables array + their strings)
        // Note: we already consumed the strings, so just free the array
        if !raw.variables.is_null() {
            // The variables' strings are already consumed. Just free the array.
            free(raw.variables as *mut std::ffi::c_void);
        }

        Ok(StackFrame {
            local_size: raw.local_variables_size,
            regs_size: raw.saved_registers_size,
            args_size: raw.arguments_size,
            total_size: raw.total_size,
            vars,
        })
    }
}

/// Get the cumulative SP delta before the instruction at `address`.
pub fn sp_delta_at(address: Address) -> Result<AddressDelta> {
    let mut delta: AddressDelta = 0;
    let ret = unsafe { idax_sys::idax_function_sp_delta_at(address, &mut delta) };
    if ret != 0 {
        Err(error::consume_last_error("function::sp_delta_at failed"))
    } else {
        Ok(delta)
    }
}

/// Find a frame variable by exact name.
pub fn frame_variable_by_name(address: Address, name: &str) -> Result<FrameVariable> {
    let c_name =
        CString::new(name).map_err(|_| Error::validation("invalid frame variable name"))?;
    unsafe {
        let mut raw = idax_sys::IdaxFrameVariable::default();
        let ret =
            idax_sys::idax_function_frame_variable_by_name(address, c_name.as_ptr(), &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error(
                "function::frame_variable_by_name failed",
            ));
        }
        Ok(frame_variable_from_raw(&raw))
    }
}

/// Find a frame variable by byte offset in the frame.
pub fn frame_variable_by_offset(address: Address, byte_offset: usize) -> Result<FrameVariable> {
    unsafe {
        let mut raw = idax_sys::IdaxFrameVariable::default();
        let ret = idax_sys::idax_function_frame_variable_by_offset(address, byte_offset, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error(
                "function::frame_variable_by_offset failed",
            ));
        }
        Ok(frame_variable_from_raw(&raw))
    }
}

/// Define a stack variable in the function frame.
pub fn define_stack_variable(
    function_address: Address,
    name: &str,
    frame_offset: i32,
    ty: &TypeInfo,
) -> Status {
    let c_name =
        CString::new(name).map_err(|_| Error::validation("invalid stack variable name"))?;
    let ret = unsafe {
        idax_sys::idax_function_define_stack_variable(
            function_address,
            c_name.as_ptr(),
            frame_offset,
            ty.as_raw(),
        )
    };
    error::int_to_status(ret, "function::define_stack_variable failed")
}

/// Add a register variable alias for a range in the function.
pub fn add_register_variable(
    function_address: Address,
    range_start: Address,
    range_end: Address,
    register_name: &str,
    user_name: &str,
    comment: &str,
) -> Status {
    let c_register_name =
        CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let c_user_name =
        CString::new(user_name).map_err(|_| Error::validation("invalid register user name"))?;
    let c_comment = CString::new(comment).map_err(|_| Error::validation("invalid comment"))?;
    let ret = unsafe {
        idax_sys::idax_function_add_register_variable(
            function_address,
            range_start,
            range_end,
            c_register_name.as_ptr(),
            c_user_name.as_ptr(),
            c_comment.as_ptr(),
        )
    };
    error::int_to_status(ret, "function::add_register_variable failed")
}

/// Find a register variable alias at an address by canonical register name.
pub fn find_register_variable(
    function_address: Address,
    address: Address,
    register_name: &str,
) -> Result<RegisterVariable> {
    let c_register_name =
        CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    unsafe {
        let mut raw = idax_sys::IdaxRegisterVariable::default();
        let ret = idax_sys::idax_function_find_register_variable(
            function_address,
            address,
            c_register_name.as_ptr(),
            &mut raw,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "function::find_register_variable failed",
            ));
        }
        Ok(register_variable_from_raw(&raw))
    }
}

/// Remove a register variable alias.
pub fn remove_register_variable(
    function_address: Address,
    range_start: Address,
    range_end: Address,
    register_name: &str,
) -> Status {
    let c_register_name =
        CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let ret = unsafe {
        idax_sys::idax_function_remove_register_variable(
            function_address,
            range_start,
            range_end,
            c_register_name.as_ptr(),
        )
    };
    error::int_to_status(ret, "function::remove_register_variable failed")
}

/// Rename an existing register variable alias.
pub fn rename_register_variable(
    function_address: Address,
    address: Address,
    register_name: &str,
    new_user_name: &str,
) -> Status {
    let c_register_name =
        CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let c_new_user_name =
        CString::new(new_user_name).map_err(|_| Error::validation("invalid register user name"))?;
    let ret = unsafe {
        idax_sys::idax_function_rename_register_variable(
            function_address,
            address,
            c_register_name.as_ptr(),
            c_new_user_name.as_ptr(),
        )
    };
    error::int_to_status(ret, "function::rename_register_variable failed")
}

/// Return true if any register variable aliases exist at the address.
pub fn has_register_variables(function_address: Address, address: Address) -> Result<bool> {
    let mut out: i32 = 0;
    let ret = unsafe {
        idax_sys::idax_function_has_register_variables(function_address, address, &mut out)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "function::has_register_variables failed",
        ))
    } else {
        Ok(out != 0)
    }
}

/// List all register variable aliases defined for the function.
pub fn register_variables(function_address: Address) -> Result<Vec<RegisterVariable>> {
    unsafe {
        let mut count: usize = 0;
        let mut raw_vars: *mut idax_sys::IdaxRegisterVariable = std::ptr::null_mut();
        let ret =
            idax_sys::idax_function_register_variables(function_address, &mut raw_vars, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error(
                "function::register_variables failed",
            ));
        }
        let result = if raw_vars.is_null() || count == 0 {
            Ok(Vec::new())
        } else {
            let slice = std::slice::from_raw_parts(raw_vars, count);
            slice
                .iter()
                .map(register_variable_from_raw_borrowed)
                .collect()
        };
        if !raw_vars.is_null() {
            idax_sys::idax_register_variables_free(raw_vars, count);
        }
        result
    }
}

/// Enumerate all item head addresses in the function body.
pub fn item_addresses(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_function_item_addresses(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("item_addresses failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// Enumerate only code item addresses in the function body.
pub fn code_addresses(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_function_code_addresses(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("code_addresses failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

/// Iterator over all functions.
pub struct FunctionIter {
    index: usize,
    total: usize,
}

impl Iterator for FunctionIter {
    type Item = Function;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        let func = by_index(self.index).ok()?;
        self.index += 1;
        Some(func)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FunctionIter {}

/// Iterable range of all functions.
pub fn all() -> FunctionIter {
    let total = count().unwrap_or(0);
    FunctionIter { index: 0, total }
}
