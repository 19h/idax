//! Typed event subscription and RAII scoped subscriptions.
//!
//! Mirrors the C++ `ida::event` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Result, Status};
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::sync::{Mutex, OnceLock};

/// Opaque subscription handle.
pub type Token = u64;

/// Event kind for generic event routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EventKind {
    SegmentAdded = 0,
    SegmentDeleted = 1,
    FunctionAdded = 2,
    FunctionDeleted = 3,
    Renamed = 4,
    BytePatched = 5,
    CommentChanged = 6,
}

/// Generic IDB event payload.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    pub address: Address,
    pub secondary_address: Address,
    pub new_name: String,
    pub old_name: String,
    pub old_value: u32,
    pub repeatable: bool,
}

fn parse_event_kind(kind: i32) -> EventKind {
    match kind {
        0 => EventKind::SegmentAdded,
        1 => EventKind::SegmentDeleted,
        2 => EventKind::FunctionAdded,
        3 => EventKind::FunctionDeleted,
        4 => EventKind::Renamed,
        5 => EventKind::BytePatched,
        6 => EventKind::CommentChanged,
        _ => EventKind::SegmentAdded,
    }
}

fn cstr_opt(ptr: *const std::ffi::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

fn from_ffi_event(ev: &idax_sys::IdaxEvent) -> Event {
    Event {
        kind: parse_event_kind(ev.kind),
        address: ev.address,
        secondary_address: ev.secondary_address,
        new_name: cstr_opt(ev.new_name),
        old_name: cstr_opt(ev.old_name),
        old_value: ev.old_value,
        repeatable: ev.repeatable != 0,
    }
}

struct SegmentAddedContext {
    callback: Box<dyn FnMut(Address) + Send>,
}

struct SegmentDeletedContext {
    callback: Box<dyn FnMut(Address, Address) + Send>,
}

struct FunctionAddedContext {
    callback: Box<dyn FnMut(Address) + Send>,
}

struct FunctionDeletedContext {
    callback: Box<dyn FnMut(Address) + Send>,
}

struct RenamedContext {
    callback: Box<dyn FnMut(Address, String, String) + Send>,
}

struct BytePatchedContext {
    callback: Box<dyn FnMut(Address, u32) + Send>,
}

struct CommentChangedContext {
    callback: Box<dyn FnMut(Address, bool) + Send>,
}

struct EventContext {
    callback: Box<dyn FnMut(Event) + Send>,
}

struct FilteredEventContext {
    filter: Box<dyn FnMut(&Event) -> bool + Send>,
    callback: Box<dyn FnMut(Event) + Send>,
}

struct ErasedContext {
    ptr: usize,
    drop_fn: unsafe fn(*mut c_void),
}

unsafe fn drop_as<T>(ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut T)) };
}

static SUB_CONTEXTS: OnceLock<Mutex<HashMap<Token, ErasedContext>>> = OnceLock::new();

fn save_context<T>(token: Token, raw: *mut T) {
    SUB_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("event context mutex poisoned")
        .insert(
            token,
            ErasedContext {
                ptr: raw as usize,
                drop_fn: drop_as::<T>,
            },
        );
}

unsafe extern "C" fn segment_added_trampoline(context: *mut c_void, start: u64) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut SegmentAddedContext) };
    (ctx.callback)(start);
}

unsafe extern "C" fn segment_deleted_trampoline(context: *mut c_void, start: u64, end: u64) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut SegmentDeletedContext) };
    (ctx.callback)(start, end);
}

unsafe extern "C" fn function_added_trampoline(context: *mut c_void, entry: u64) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut FunctionAddedContext) };
    (ctx.callback)(entry);
}

unsafe extern "C" fn function_deleted_trampoline(context: *mut c_void, entry: u64) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut FunctionDeletedContext) };
    (ctx.callback)(entry);
}

unsafe extern "C" fn renamed_trampoline(
    context: *mut c_void,
    address: u64,
    new_name: *const std::ffi::c_char,
    old_name: *const std::ffi::c_char,
) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut RenamedContext) };
    (ctx.callback)(address, cstr_opt(new_name), cstr_opt(old_name));
}

unsafe extern "C" fn byte_patched_trampoline(context: *mut c_void, address: u64, old_value: u32) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut BytePatchedContext) };
    (ctx.callback)(address, old_value);
}

unsafe extern "C" fn comment_changed_trampoline(
    context: *mut c_void,
    address: u64,
    repeatable: i32,
) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut CommentChangedContext) };
    (ctx.callback)(address, repeatable != 0);
}

unsafe extern "C" fn event_trampoline(context: *mut c_void, event: *const idax_sys::IdaxEvent) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut EventContext) };
    (ctx.callback)(unsafe { from_ffi_event(&*event) });
}

unsafe extern "C" fn event_filter_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxEvent,
) -> i32 {
    if context.is_null() || event.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut FilteredEventContext) };
    let ev = unsafe { from_ffi_event(&*event) };
    if (ctx.filter)(&ev) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn filtered_event_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut FilteredEventContext) };
    (ctx.callback)(unsafe { from_ffi_event(&*event) });
}

/// Subscribe to a generic event kind.
///
/// This legacy callback ABI remains available for compatibility.
pub fn subscribe(
    kind: EventKind,
    callback: idax_sys::IdaxEventCallback,
    context: *mut c_void,
) -> Result<Token> {
    let mut token: Token = 0;
    let ret = unsafe { idax_sys::idax_event_subscribe(kind as i32, callback, context, &mut token) };
    if ret != 0 {
        Err(error::consume_last_error("event::subscribe failed"))
    } else {
        Ok(token)
    }
}

pub fn on_segment_added<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(SegmentAddedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_segment_added(
            Some(segment_added_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_segment_added failed"));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_segment_deleted<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address, Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(SegmentDeletedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_segment_deleted(
            Some(segment_deleted_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "event::on_segment_deleted failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_function_added<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(FunctionAddedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_function_added(
            Some(function_added_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_function_added failed"));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_function_deleted<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(FunctionDeletedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_function_deleted(
            Some(function_deleted_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "event::on_function_deleted failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_renamed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address, String, String) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(RenamedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_renamed(Some(renamed_trampoline), raw as *mut c_void, &mut token)
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_renamed failed"));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_byte_patched<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address, u32) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(BytePatchedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_byte_patched(
            Some(byte_patched_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_byte_patched failed"));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_comment_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address, bool) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(CommentChangedContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_comment_changed(
            Some(comment_changed_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "event::on_comment_changed failed",
        ));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_event<F>(callback: F) -> Result<Token>
where
    F: FnMut(Event) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(EventContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_event(Some(event_trampoline), raw as *mut c_void, &mut token)
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_event failed"));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_event_filtered<Flt, Cb>(filter: Flt, callback: Cb) -> Result<Token>
where
    Flt: FnMut(&Event) -> bool + Send + 'static,
    Cb: FnMut(Event) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(FilteredEventContext {
        filter: Box::new(filter),
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_event_on_event_filtered(
            Some(event_filter_trampoline),
            Some(filtered_event_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("event::on_event_filtered failed"));
    }
    save_context(token, raw);
    Ok(token)
}

/// Unsubscribe a previously registered callback.
pub fn unsubscribe(token: Token) -> Status {
    let ret = unsafe { idax_sys::idax_event_unsubscribe(token) };
    let status = error::int_to_status(ret, "event::unsubscribe failed");
    if status.is_ok() {
        if let Some(ctx) = SUB_CONTEXTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("event context mutex poisoned")
            .remove(&token)
        {
            unsafe { (ctx.drop_fn)(ctx.ptr as *mut c_void) };
        }
    }
    status
}

/// RAII subscription guard: unsubscribes on destruction.
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

impl Default for Event {
    fn default() -> Self {
        Self {
            kind: EventKind::SegmentAdded,
            address: BAD_ADDRESS,
            secondary_address: BAD_ADDRESS,
            new_name: String::new(),
            old_name: String::new(),
            old_value: 0,
            repeatable: false,
        }
    }
}
