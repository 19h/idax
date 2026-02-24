//! Debugger control: process/thread lifecycle, breakpoints, memory, appcall, and events.
//!
//! Mirrors the C++ `ida::debugger` namespace.

use crate::address::{Address, AddressSize, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use crate::types::TypeInfo;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};

pub type Token = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ProcessState {
    NoProcess = 0,
    Running = 1,
    Suspended = 2,
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: String,
    pub display_name: String,
    pub remote: bool,
    pub supports_appcall: bool,
    pub supports_attach: bool,
    pub loaded: bool,
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub id: i32,
    pub name: String,
    pub is_current: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub read_only: bool,
    pub instruction_pointer: bool,
    pub stack_pointer: bool,
    pub frame_pointer: bool,
    pub may_contain_address: bool,
    pub custom_format: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(i32)]
pub enum AppcallValueKind {
    SignedInteger = 0,
    UnsignedInteger = 1,
    FloatingPoint = 2,
    String = 3,
    Address = 4,
    Boolean = 5,
}

#[derive(Debug, Clone)]
pub struct AppcallValue {
    pub kind: AppcallValueKind,
    pub signed_value: i64,
    pub unsigned_value: u64,
    pub floating_value: f64,
    pub string_value: String,
    pub address_value: Address,
    pub boolean_value: bool,
}

impl Default for AppcallValue {
    fn default() -> Self {
        Self {
            kind: AppcallValueKind::SignedInteger,
            signed_value: 0,
            unsigned_value: 0,
            floating_value: 0.0,
            string_value: String::new(),
            address_value: BAD_ADDRESS,
            boolean_value: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AppcallOptions {
    pub thread_id: Option<i32>,
    pub manual: bool,
    pub include_debug_event: bool,
    pub timeout_milliseconds: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AppcallRequest {
    pub function_address: Address,
    pub function_type: TypeInfo,
    pub arguments: Vec<AppcallValue>,
    pub options: AppcallOptions,
}

#[derive(Debug, Clone)]
pub struct AppcallResult {
    pub return_value: AppcallValue,
    pub diagnostics: String,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base: Address,
    pub size: AddressSize,
}

#[derive(Debug, Clone)]
pub struct ExceptionInfo {
    pub ea: Address,
    pub code: u32,
    pub can_continue: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BreakpointChange {
    Added = 0,
    Removed = 1,
    Changed = 2,
}

fn parse_process_state(raw: i32) -> ProcessState {
    match raw {
        0 => ProcessState::NoProcess,
        1 => ProcessState::Running,
        _ => ProcessState::Suspended,
    }
}

fn parse_appcall_kind(raw: i32) -> Result<AppcallValueKind> {
    match raw {
        x if x == AppcallValueKind::SignedInteger as i32 => Ok(AppcallValueKind::SignedInteger),
        x if x == AppcallValueKind::UnsignedInteger as i32 => Ok(AppcallValueKind::UnsignedInteger),
        x if x == AppcallValueKind::FloatingPoint as i32 => Ok(AppcallValueKind::FloatingPoint),
        x if x == AppcallValueKind::String as i32 => Ok(AppcallValueKind::String),
        x if x == AppcallValueKind::Address as i32 => Ok(AppcallValueKind::Address),
        x if x == AppcallValueKind::Boolean as i32 => Ok(AppcallValueKind::Boolean),
        _ => Err(Error::validation("invalid appcall value kind")),
    }
}

fn parse_breakpoint_change(raw: i32) -> BreakpointChange {
    match raw {
        x if x == BreakpointChange::Added as i32 => BreakpointChange::Added,
        x if x == BreakpointChange::Removed as i32 => BreakpointChange::Removed,
        _ => BreakpointChange::Changed,
    }
}

fn cstr_opt(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

unsafe fn backend_from_raw(raw: &idax_sys::IdaxBackendInfo) -> BackendInfo {
    BackendInfo {
        name: cstr_opt(raw.name),
        display_name: cstr_opt(raw.display_name),
        remote: raw.remote != 0,
        supports_appcall: raw.supports_appcall != 0,
        supports_attach: raw.supports_attach != 0,
        loaded: raw.loaded != 0,
    }
}

unsafe fn thread_from_raw(raw: &idax_sys::IdaxThreadInfo) -> ThreadInfo {
    ThreadInfo {
        id: raw.id,
        name: cstr_opt(raw.name),
        is_current: raw.is_current != 0,
    }
}

unsafe fn register_from_raw(raw: &idax_sys::IdaxDebuggerRegisterInfo) -> RegisterInfo {
    RegisterInfo {
        name: cstr_opt(raw.name),
        read_only: raw.read_only != 0,
        instruction_pointer: raw.instruction_pointer != 0,
        stack_pointer: raw.stack_pointer != 0,
        frame_pointer: raw.frame_pointer != 0,
        may_contain_address: raw.may_contain_address != 0,
        custom_format: raw.custom_format != 0,
    }
}

unsafe fn appcall_value_from_raw(raw: &idax_sys::IdaxDebuggerAppcallValue) -> Result<AppcallValue> {
    Ok(AppcallValue {
        kind: parse_appcall_kind(raw.kind)?,
        signed_value: raw.signed_value,
        unsigned_value: raw.unsigned_value,
        floating_value: raw.floating_value,
        string_value: cstr_opt(raw.string_value),
        address_value: raw.address_value,
        boolean_value: raw.boolean_value != 0,
    })
}

fn to_raw_appcall_options(options: &AppcallOptions) -> idax_sys::IdaxDebuggerAppcallOptions {
    idax_sys::IdaxDebuggerAppcallOptions {
        has_thread_id: if options.thread_id.is_some() { 1 } else { 0 },
        thread_id: options.thread_id.unwrap_or(0),
        manual: if options.manual { 1 } else { 0 },
        include_debug_event: if options.include_debug_event { 1 } else { 0 },
        has_timeout_milliseconds: if options.timeout_milliseconds.is_some() {
            1
        } else {
            0
        },
        timeout_milliseconds: options.timeout_milliseconds.unwrap_or(0),
    }
}

struct RawAppcallRequest {
    raw: idax_sys::IdaxDebuggerAppcallRequest,
    _arg_strings: Vec<CString>,
    _args: Vec<idax_sys::IdaxDebuggerAppcallValue>,
}

fn to_raw_appcall_request(req: &AppcallRequest) -> Result<RawAppcallRequest> {
    let mut arg_strings: Vec<CString> = Vec::new();
    let mut args: Vec<idax_sys::IdaxDebuggerAppcallValue> = Vec::with_capacity(req.arguments.len());

    for arg in &req.arguments {
        let mut raw = idax_sys::IdaxDebuggerAppcallValue {
            kind: arg.kind as i32,
            signed_value: arg.signed_value,
            unsigned_value: arg.unsigned_value,
            floating_value: arg.floating_value,
            string_value: std::ptr::null_mut(),
            address_value: arg.address_value,
            boolean_value: if arg.boolean_value { 1 } else { 0 },
        };
        if matches!(arg.kind, AppcallValueKind::String) {
            let c = CString::new(arg.string_value.as_str())
                .map_err(|_| Error::validation("invalid appcall string argument"))?;
            raw.string_value = c.as_ptr() as *mut c_char;
            arg_strings.push(c);
        }
        args.push(raw);
    }

    let raw = idax_sys::IdaxDebuggerAppcallRequest {
        function_address: req.function_address,
        function_type: req.function_type.as_raw(),
        arguments: if args.is_empty() {
            std::ptr::null_mut()
        } else {
            args.as_mut_ptr()
        },
        argument_count: args.len(),
        options: to_raw_appcall_options(&req.options),
    };

    Ok(RawAppcallRequest {
        raw,
        _arg_strings: arg_strings,
        _args: args,
    })
}

unsafe fn appcall_result_from_raw(
    raw: &idax_sys::IdaxDebuggerAppcallResult,
) -> Result<AppcallResult> {
    unsafe {
        Ok(AppcallResult {
            return_value: appcall_value_from_raw(&raw.return_value)?,
            diagnostics: cstr_opt(raw.diagnostics),
        })
    }
}

pub fn available_backends() -> Result<Vec<BackendInfo>> {
    unsafe {
        let mut ptr: *mut idax_sys::IdaxBackendInfo = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_debugger_available_backends(&mut ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error(
                "debugger::available_backends failed",
            ));
        }
        if ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(count);
        let slice = std::slice::from_raw_parts(ptr, count);
        for entry in slice {
            out.push(backend_from_raw(entry));
        }
        for i in 0..count {
            idax_sys::idax_backend_info_free(ptr.add(i));
        }
        idax_sys::idax_free_addresses(ptr as *mut u64);
        Ok(out)
    }
}

pub fn current_backend() -> Result<BackendInfo> {
    unsafe {
        let mut raw: idax_sys::IdaxBackendInfo = std::mem::zeroed();
        let ret = idax_sys::idax_debugger_current_backend(&mut raw);
        if ret != 0 {
            return Err(error::consume_last_error(
                "debugger::current_backend failed",
            ));
        }
        let out = backend_from_raw(&raw);
        idax_sys::idax_backend_info_free(&mut raw);
        Ok(out)
    }
}

pub fn load_backend(name: &str, use_remote: bool) -> Status {
    let c = CString::new(name).map_err(|_| Error::validation("invalid backend name"))?;
    let ret =
        unsafe { idax_sys::idax_debugger_load_backend(c.as_ptr(), if use_remote { 1 } else { 0 }) };
    error::int_to_status(ret, "debugger::load_backend failed")
}

pub fn start(path: &str, args: &str, working_dir: &str) -> Status {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path"))?;
    let c_args = CString::new(args).map_err(|_| Error::validation("invalid args"))?;
    let c_wd = CString::new(working_dir).map_err(|_| Error::validation("invalid working dir"))?;
    let ret =
        unsafe { idax_sys::idax_debugger_start(c_path.as_ptr(), c_args.as_ptr(), c_wd.as_ptr()) };
    error::int_to_status(ret, "debugger::start failed")
}

pub fn request_start(path: &str, args: &str, working_dir: &str) -> Status {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path"))?;
    let c_args = CString::new(args).map_err(|_| Error::validation("invalid args"))?;
    let c_wd = CString::new(working_dir).map_err(|_| Error::validation("invalid working dir"))?;
    let ret = unsafe {
        idax_sys::idax_debugger_request_start(c_path.as_ptr(), c_args.as_ptr(), c_wd.as_ptr())
    };
    error::int_to_status(ret, "debugger::request_start failed")
}

pub fn attach(pid: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_attach(pid) };
    error::int_to_status(ret, "debugger::attach failed")
}

pub fn request_attach(pid: i32, event_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_attach(pid, event_id) };
    error::int_to_status(ret, "debugger::request_attach failed")
}

pub fn detach() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_detach() };
    error::int_to_status(ret, "debugger::detach failed")
}

pub fn terminate() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_terminate() };
    error::int_to_status(ret, "debugger::terminate failed")
}

pub fn suspend() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_suspend() };
    error::int_to_status(ret, "debugger::suspend failed")
}

pub fn resume() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_resume() };
    error::int_to_status(ret, "debugger::resume failed")
}

pub fn step_into() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_step_into() };
    error::int_to_status(ret, "debugger::step_into failed")
}

pub fn step_over() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_step_over() };
    error::int_to_status(ret, "debugger::step_over failed")
}

pub fn step_out() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_step_out() };
    error::int_to_status(ret, "debugger::step_out failed")
}

pub fn run_to(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_run_to(address) };
    error::int_to_status(ret, "debugger::run_to failed")
}

pub fn state() -> Result<ProcessState> {
    let mut s: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_state(&mut s) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::state failed"))
    } else {
        Ok(parse_process_state(s))
    }
}

pub fn instruction_pointer() -> Result<Address> {
    let mut ip: Address = 0;
    let ret = unsafe { idax_sys::idax_debugger_instruction_pointer(&mut ip) };
    if ret != 0 {
        Err(error::consume_last_error(
            "debugger::instruction_pointer failed",
        ))
    } else {
        Ok(ip)
    }
}

pub fn stack_pointer() -> Result<Address> {
    let mut sp: Address = 0;
    let ret = unsafe { idax_sys::idax_debugger_stack_pointer(&mut sp) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::stack_pointer failed"))
    } else {
        Ok(sp)
    }
}

pub fn register_value(reg_name: &str) -> Result<u64> {
    let c = CString::new(reg_name).map_err(|_| Error::validation("invalid register name"))?;
    let mut val: u64 = 0;
    let ret = unsafe { idax_sys::idax_debugger_register_value(c.as_ptr(), &mut val) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::register_value failed"))
    } else {
        Ok(val)
    }
}

pub fn set_register(reg_name: &str, value: u64) -> Status {
    let c = CString::new(reg_name).map_err(|_| Error::validation("invalid register name"))?;
    let ret = unsafe { idax_sys::idax_debugger_set_register(c.as_ptr(), value) };
    error::int_to_status(ret, "debugger::set_register failed")
}

pub fn add_breakpoint(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_add_breakpoint(address) };
    error::int_to_status(ret, "debugger::add_breakpoint failed")
}

pub fn remove_breakpoint(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_remove_breakpoint(address) };
    error::int_to_status(ret, "debugger::remove_breakpoint failed")
}

pub fn has_breakpoint(address: Address) -> Result<bool> {
    let mut has: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_has_breakpoint(address, &mut has) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::has_breakpoint failed"))
    } else {
        Ok(has != 0)
    }
}

pub fn read_memory(address: Address, size: AddressSize) -> Result<Vec<u8>> {
    unsafe {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let ret = idax_sys::idax_debugger_read_memory(address, size, &mut ptr, &mut out_len);
        if ret != 0 {
            return Err(error::consume_last_error("debugger::read_memory failed"));
        }
        let result = if ptr.is_null() || out_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(ptr, out_len).to_vec()
        };
        if !ptr.is_null() {
            idax_sys::idax_free_bytes(ptr);
        }
        Ok(result)
    }
}

pub fn write_memory(address: Address, bytes: &[u8]) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_write_memory(address, bytes.as_ptr(), bytes.len()) };
    error::int_to_status(ret, "debugger::write_memory failed")
}

pub fn is_request_running() -> bool {
    unsafe { idax_sys::idax_debugger_is_request_running() != 0 }
}

pub fn run_requests() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_run_requests() };
    error::int_to_status(ret, "debugger::run_requests failed")
}

pub fn request_suspend() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_suspend() };
    error::int_to_status(ret, "debugger::request_suspend failed")
}

pub fn request_resume() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_resume() };
    error::int_to_status(ret, "debugger::request_resume failed")
}

pub fn request_step_into() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_step_into() };
    error::int_to_status(ret, "debugger::request_step_into failed")
}

pub fn request_step_over() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_step_over() };
    error::int_to_status(ret, "debugger::request_step_over failed")
}

pub fn request_step_out() -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_step_out() };
    error::int_to_status(ret, "debugger::request_step_out failed")
}

pub fn request_run_to(address: Address) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_run_to(address) };
    error::int_to_status(ret, "debugger::request_run_to failed")
}

pub fn thread_count() -> Result<usize> {
    let mut out: usize = 0;
    let ret = unsafe { idax_sys::idax_debugger_thread_count(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::thread_count failed"))
    } else {
        Ok(out)
    }
}

pub fn thread_id_at(index: usize) -> Result<i32> {
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_thread_id_at(index, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("debugger::thread_id_at failed"))
    } else {
        Ok(out)
    }
}

pub fn thread_name_at(index: usize) -> Result<String> {
    unsafe {
        let mut ptr: *mut c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_debugger_thread_name_at(index, &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("debugger::thread_name_at failed"));
        }
        error::cstr_to_string_free(ptr, "debugger::thread_name_at failed")
    }
}

pub fn current_thread_id() -> Result<i32> {
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_current_thread_id(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "debugger::current_thread_id failed",
        ))
    } else {
        Ok(out)
    }
}

pub fn threads() -> Result<Vec<ThreadInfo>> {
    unsafe {
        let mut ptr: *mut idax_sys::IdaxThreadInfo = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_debugger_threads(&mut ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("debugger::threads failed"));
        }
        if ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(count);
        let slice = std::slice::from_raw_parts(ptr, count);
        for entry in slice {
            out.push(thread_from_raw(entry));
        }
        for i in 0..count {
            idax_sys::idax_thread_info_free(ptr.add(i));
        }
        idax_sys::idax_free_addresses(ptr as *mut u64);
        Ok(out)
    }
}

pub fn select_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_select_thread(thread_id) };
    error::int_to_status(ret, "debugger::select_thread failed")
}

pub fn request_select_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_select_thread(thread_id) };
    error::int_to_status(ret, "debugger::request_select_thread failed")
}

pub fn suspend_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_suspend_thread(thread_id) };
    error::int_to_status(ret, "debugger::suspend_thread failed")
}

pub fn request_suspend_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_suspend_thread(thread_id) };
    error::int_to_status(ret, "debugger::request_suspend_thread failed")
}

pub fn resume_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_resume_thread(thread_id) };
    error::int_to_status(ret, "debugger::resume_thread failed")
}

pub fn request_resume_thread(thread_id: i32) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_request_resume_thread(thread_id) };
    error::int_to_status(ret, "debugger::request_resume_thread failed")
}

pub fn register_info(register_name: &str) -> Result<RegisterInfo> {
    let c = CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    unsafe {
        let mut raw: idax_sys::IdaxDebuggerRegisterInfo = std::mem::zeroed();
        let ret = idax_sys::idax_debugger_register_info(c.as_ptr(), &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("debugger::register_info failed"));
        }
        let out = register_from_raw(&raw);
        idax_sys::idax_debugger_register_info_free(&mut raw);
        Ok(out)
    }
}

pub fn is_integer_register(register_name: &str) -> Result<bool> {
    let c = CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_is_integer_register(c.as_ptr(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "debugger::is_integer_register failed",
        ))
    } else {
        Ok(out != 0)
    }
}

pub fn is_floating_register(register_name: &str) -> Result<bool> {
    let c = CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_is_floating_register(c.as_ptr(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "debugger::is_floating_register failed",
        ))
    } else {
        Ok(out != 0)
    }
}

pub fn is_custom_register(register_name: &str) -> Result<bool> {
    let c = CString::new(register_name).map_err(|_| Error::validation("invalid register name"))?;
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_debugger_is_custom_register(c.as_ptr(), &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "debugger::is_custom_register failed",
        ))
    } else {
        Ok(out != 0)
    }
}

pub fn appcall(request: &AppcallRequest) -> Result<AppcallResult> {
    let raw_req = to_raw_appcall_request(request)?;
    unsafe {
        let mut raw_out: idax_sys::IdaxDebuggerAppcallResult = std::mem::zeroed();
        let ret = idax_sys::idax_debugger_appcall(&raw_req.raw, &mut raw_out);
        if ret != 0 {
            return Err(error::consume_last_error("debugger::appcall failed"));
        }
        let out = appcall_result_from_raw(&raw_out)?;
        idax_sys::idax_debugger_appcall_result_free(&mut raw_out);
        Ok(out)
    }
}

pub fn cleanup_appcall(thread_id: Option<i32>) -> Status {
    let (has_thread_id, tid) = match thread_id {
        Some(tid) => (1, tid),
        None => (0, 0),
    };
    let ret = unsafe { idax_sys::idax_debugger_cleanup_appcall(has_thread_id, tid) };
    error::int_to_status(ret, "debugger::cleanup_appcall failed")
}

struct ExecutorContext {
    callback: Box<dyn FnMut(&AppcallRequest) -> Result<AppcallResult> + Send>,
}

static EXECUTOR_CONTEXTS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

unsafe fn clone_type_from_handle(handle: *mut c_void) -> Result<TypeInfo> {
    unsafe {
        if handle.is_null() {
            return Err(Error::validation(
                "null function_type handle in appcall request",
            ));
        }
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = idax_sys::idax_type_clone(handle, &mut out);
        if ret != 0 || out.is_null() {
            Err(error::consume_last_error(
                "debugger::executor type clone failed",
            ))
        } else {
            Ok(TypeInfo::from_raw(out))
        }
    }
}

unsafe fn appcall_request_from_raw_for_executor(
    raw: &idax_sys::IdaxDebuggerAppcallRequest,
) -> Result<AppcallRequest> {
    unsafe {
        let function_type = clone_type_from_handle(raw.function_type)?;
        let mut arguments = Vec::with_capacity(raw.argument_count);
        if !raw.arguments.is_null() && raw.argument_count > 0 {
            let slice = std::slice::from_raw_parts(raw.arguments, raw.argument_count);
            for arg in slice {
                arguments.push(appcall_value_from_raw(arg)?);
            }
        }
        Ok(AppcallRequest {
            function_address: raw.function_address,
            function_type,
            arguments,
            options: AppcallOptions {
                thread_id: if raw.options.has_thread_id != 0 {
                    Some(raw.options.thread_id)
                } else {
                    None
                },
                manual: raw.options.manual != 0,
                include_debug_event: raw.options.include_debug_event != 0,
                timeout_milliseconds: if raw.options.has_timeout_milliseconds != 0 {
                    Some(raw.options.timeout_milliseconds)
                } else {
                    None
                },
            },
        })
    }
}

unsafe extern "C" fn executor_trampoline(
    context: *mut c_void,
    request: *const idax_sys::IdaxDebuggerAppcallRequest,
    out_result: *mut idax_sys::IdaxDebuggerAppcallResult,
) -> i32 {
    unsafe {
        if context.is_null() || request.is_null() || out_result.is_null() {
            return -1;
        }
        let ctx = &mut *(context as *mut ExecutorContext);
        let req = match appcall_request_from_raw_for_executor(&*request) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let result = match (ctx.callback)(&req) {
            Ok(v) => v,
            Err(_) => return -1,
        };

        std::ptr::write(out_result, std::mem::zeroed());
        (*out_result).return_value.kind = result.return_value.kind as i32;
        (*out_result).return_value.signed_value = result.return_value.signed_value;
        (*out_result).return_value.unsigned_value = result.return_value.unsigned_value;
        (*out_result).return_value.floating_value = result.return_value.floating_value;
        (*out_result).return_value.address_value = result.return_value.address_value;
        (*out_result).return_value.boolean_value = if result.return_value.boolean_value {
            1
        } else {
            0
        };

        if matches!(result.return_value.kind, AppcallValueKind::String) {
            let c = match CString::new(result.return_value.string_value) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            (*out_result).return_value.string_value = c.into_raw();
        }

        let c_diag = match CString::new(result.diagnostics) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        (*out_result).diagnostics = c_diag.into_raw();
        0
    }
}

unsafe extern "C" fn executor_cleanup_trampoline(context: *mut c_void) {
    unsafe {
        if context.is_null() {
            return;
        }
        drop(Box::from_raw(context as *mut ExecutorContext));
    }
}

pub fn register_executor<F>(name: &str, callback: F) -> Status
where
    F: FnMut(&AppcallRequest) -> Result<AppcallResult> + Send + 'static,
{
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid executor name"))?;
    let raw = Box::into_raw(Box::new(ExecutorContext {
        callback: Box::new(callback),
    }));
    let ret = unsafe {
        idax_sys::idax_debugger_register_executor(
            c_name.as_ptr(),
            Some(executor_trampoline),
            Some(executor_cleanup_trampoline),
            raw as *mut c_void,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::register_executor failed",
        ));
    }
    EXECUTOR_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("executor context mutex poisoned")
        .insert(name.to_string(), raw as usize);
    Ok(())
}

pub fn unregister_executor(name: &str) -> Status {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid executor name"))?;
    let ret = unsafe { idax_sys::idax_debugger_unregister_executor(c_name.as_ptr()) };
    let status = error::int_to_status(ret, "debugger::unregister_executor failed");
    if status.is_ok() {
        EXECUTOR_CONTEXTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("executor context mutex poisoned")
            .remove(name);
    }
    status
}

pub fn appcall_with_executor(name: &str, request: &AppcallRequest) -> Result<AppcallResult> {
    let c_name = CString::new(name).map_err(|_| Error::validation("invalid executor name"))?;
    let raw_req = to_raw_appcall_request(request)?;
    unsafe {
        let mut raw_out: idax_sys::IdaxDebuggerAppcallResult = std::mem::zeroed();
        let ret = idax_sys::idax_debugger_appcall_with_executor(
            c_name.as_ptr(),
            &raw_req.raw,
            &mut raw_out,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "debugger::appcall_with_executor failed",
            ));
        }
        let out = appcall_result_from_raw(&raw_out)?;
        idax_sys::idax_debugger_appcall_result_free(&mut raw_out);
        Ok(out)
    }
}

struct ErasedContext {
    ptr: usize,
    drop_fn: unsafe fn(*mut c_void),
}

unsafe fn drop_as<T>(ptr: *mut c_void) {
    unsafe {
        drop(Box::from_raw(ptr as *mut T));
    }
}

static SUB_CONTEXTS: OnceLock<Mutex<HashMap<Token, ErasedContext>>> = OnceLock::new();

fn save_context<T>(token: Token, raw: *mut T) {
    SUB_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("debugger context mutex poisoned")
        .insert(
            token,
            ErasedContext {
                ptr: raw as usize,
                drop_fn: drop_as::<T>,
            },
        );
}

struct ProcessStartedContext {
    callback: Box<dyn FnMut(ModuleInfo) + Send>,
}

unsafe extern "C" fn process_started_trampoline(
    context: *mut c_void,
    module_info: *const idax_sys::IdaxDebuggerModuleInfo,
) {
    unsafe {
        if context.is_null() || module_info.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ProcessStartedContext);
        let m = &*module_info;
        (ctx.callback)(ModuleInfo {
            name: cstr_opt(m.name),
            base: m.base,
            size: m.size,
        });
    }
}

pub fn on_process_started<F>(callback: F) -> Result<Token>
where
    F: FnMut(ModuleInfo) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ProcessStartedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_process_started(
            Some(process_started_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_process_started failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct ProcessExitedContext {
    callback: Box<dyn FnMut(i32) + Send>,
}

unsafe extern "C" fn process_exited_trampoline(context: *mut c_void, exit_code: i32) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ProcessExitedContext);
        (ctx.callback)(exit_code);
    }
}

pub fn on_process_exited<F>(callback: F) -> Result<Token>
where
    F: FnMut(i32) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ProcessExitedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_process_exited(
            Some(process_exited_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_process_exited failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct ProcessSuspendedContext {
    callback: Box<dyn FnMut(Address) + Send>,
}

unsafe extern "C" fn process_suspended_trampoline(context: *mut c_void, address: u64) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ProcessSuspendedContext);
        (ctx.callback)(address);
    }
}

pub fn on_process_suspended<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ProcessSuspendedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_process_suspended(
            Some(process_suspended_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_process_suspended failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct BreakpointHitContext {
    callback: Box<dyn FnMut(i32, Address) + Send>,
}

unsafe extern "C" fn breakpoint_hit_trampoline(context: *mut c_void, thread_id: i32, address: u64) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut BreakpointHitContext);
        (ctx.callback)(thread_id, address);
    }
}

pub fn on_breakpoint_hit<F>(callback: F) -> Result<Token>
where
    F: FnMut(i32, Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(BreakpointHitContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_breakpoint_hit(
            Some(breakpoint_hit_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_breakpoint_hit failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct TraceContext {
    callback: Box<dyn FnMut(i32, Address) -> bool + Send>,
}

unsafe extern "C" fn trace_trampoline(context: *mut c_void, thread_id: i32, ip: u64) -> i32 {
    unsafe {
        if context.is_null() {
            return 0;
        }
        let ctx = &mut *(context as *mut TraceContext);
        if (ctx.callback)(thread_id, ip) {
            1
        } else {
            0
        }
    }
}

pub fn on_trace<F>(callback: F) -> Result<Token>
where
    F: FnMut(i32, Address) -> bool + Send + 'static,
{
    let raw = Box::into_raw(Box::new(TraceContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_trace(Some(trace_trampoline), raw as *mut c_void, &mut token)
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("debugger::on_trace failed"));
    }
    save_context(token, raw);
    Ok(token)
}

struct ExceptionContext {
    callback: Box<dyn FnMut(ExceptionInfo) + Send>,
}

unsafe extern "C" fn exception_trampoline(
    context: *mut c_void,
    exception_info: *const idax_sys::IdaxDebuggerExceptionInfo,
) {
    unsafe {
        if context.is_null() || exception_info.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ExceptionContext);
        let e = &*exception_info;
        (ctx.callback)(ExceptionInfo {
            ea: e.ea,
            code: e.code,
            can_continue: e.can_continue != 0,
            message: cstr_opt(e.message),
        });
    }
}

pub fn on_exception<F>(callback: F) -> Result<Token>
where
    F: FnMut(ExceptionInfo) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ExceptionContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_exception(
            Some(exception_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("debugger::on_exception failed"));
    }
    save_context(token, raw);
    Ok(token)
}

struct ThreadStartedContext {
    callback: Box<dyn FnMut(i32, String) + Send>,
}

unsafe extern "C" fn thread_started_trampoline(
    context: *mut c_void,
    thread_id: i32,
    thread_name: *const c_char,
) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ThreadStartedContext);
        (ctx.callback)(thread_id, cstr_opt(thread_name));
    }
}

pub fn on_thread_started<F>(callback: F) -> Result<Token>
where
    F: FnMut(i32, String) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ThreadStartedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_thread_started(
            Some(thread_started_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_thread_started failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct ThreadExitedContext {
    callback: Box<dyn FnMut(i32, i32) + Send>,
}

unsafe extern "C" fn thread_exited_trampoline(
    context: *mut c_void,
    thread_id: i32,
    exit_code: i32,
) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut ThreadExitedContext);
        (ctx.callback)(thread_id, exit_code);
    }
}

pub fn on_thread_exited<F>(callback: F) -> Result<Token>
where
    F: FnMut(i32, i32) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(ThreadExitedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_thread_exited(
            Some(thread_exited_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_thread_exited failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct LibraryLoadedContext {
    callback: Box<dyn FnMut(ModuleInfo) + Send>,
}

unsafe extern "C" fn library_loaded_trampoline(
    context: *mut c_void,
    module_info: *const idax_sys::IdaxDebuggerModuleInfo,
) {
    unsafe {
        if context.is_null() || module_info.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut LibraryLoadedContext);
        let m = &*module_info;
        (ctx.callback)(ModuleInfo {
            name: cstr_opt(m.name),
            base: m.base,
            size: m.size,
        });
    }
}

pub fn on_library_loaded<F>(callback: F) -> Result<Token>
where
    F: FnMut(ModuleInfo) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(LibraryLoadedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_library_loaded(
            Some(library_loaded_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_library_loaded failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct LibraryUnloadedContext {
    callback: Box<dyn FnMut(String) + Send>,
}

unsafe extern "C" fn library_unloaded_trampoline(
    context: *mut c_void,
    library_name: *const c_char,
) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut LibraryUnloadedContext);
        (ctx.callback)(cstr_opt(library_name));
    }
}

pub fn on_library_unloaded<F>(callback: F) -> Result<Token>
where
    F: FnMut(String) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(LibraryUnloadedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_library_unloaded(
            Some(library_unloaded_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_library_unloaded failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

struct BreakpointChangedContext {
    callback: Box<dyn FnMut(BreakpointChange, Address) + Send>,
}

unsafe extern "C" fn breakpoint_changed_trampoline(
    context: *mut c_void,
    change: i32,
    address: u64,
) {
    unsafe {
        if context.is_null() {
            return;
        }
        let ctx = &mut *(context as *mut BreakpointChangedContext);
        (ctx.callback)(parse_breakpoint_change(change), address);
    }
}

pub fn on_breakpoint_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(BreakpointChange, Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(BreakpointChangedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_debugger_on_breakpoint_changed(
            Some(breakpoint_changed_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "debugger::on_breakpoint_changed failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn unsubscribe(token: Token) -> Status {
    let ret = unsafe { idax_sys::idax_debugger_unsubscribe(token) };
    let status = error::int_to_status(ret, "debugger::unsubscribe failed");
    if status.is_ok() {
        if let Some(ctx) = SUB_CONTEXTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("debugger context mutex poisoned")
            .remove(&token)
        {
            unsafe { (ctx.drop_fn)(ctx.ptr as *mut c_void) };
        }
    }
    status
}

pub struct ScopedSubscription {
    token: Token,
}

impl ScopedSubscription {
    pub fn new(token: Token) -> Self {
        Self { token }
    }

    pub fn token(&self) -> Token {
        self.token
    }
}

impl Drop for ScopedSubscription {
    fn drop(&mut self) {
        if self.token != 0 {
            let _ = unsubscribe(self.token);
            self.token = 0;
        }
    }
}
