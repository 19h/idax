//! Typed event subscription and RAII scoped subscriptions.
//!
//! Mirrors the C++ `ida::event` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Result, Status};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{CStr, c_void};
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
    SegmentMoved = 7,
    FunctionUpdated = 8,
    ItemTypeChanged = 9,
    OperandTypeChanged = 10,
    CodeCreated = 11,
    DataCreated = 12,
    ItemsDestroyed = 13,
    ExtraCommentChanged = 14,
    LocalTypesChanged = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExtraCommentPlacement {
    Unknown = 0,
    Anterior = 1,
    Posterior = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum LocalTypeChangeKind {
    None = 0,
    Added = 1,
    Deleted = 2,
    Edited = 3,
    Aliased = 4,
    CompilerChanged = 5,
    LibraryLoaded = 6,
    LibraryUnloaded = 7,
    OrdinalsCompacted = 8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMovedEvent {
    pub from: Address,
    pub to: Address,
    pub size: u64,
    pub address_mapping_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemCreatedEvent {
    pub address: Address,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemsDestroyedEvent {
    pub start: Address,
    pub end: Address,
    pub will_disable_range: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraCommentChangedEvent {
    pub address: Address,
    pub placement: ExtraCommentPlacement,
    pub line_index: i32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTypesChangedEvent {
    pub change: LocalTypeChangeKind,
    pub ordinal: u32,
    pub name: String,
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
    pub size: u64,
    pub operand_index: i32,
    pub line_index: i32,
    pub text: String,
    pub will_disable_range: bool,
    pub address_mapping_changed: bool,
    pub extra_comment_placement: ExtraCommentPlacement,
    pub local_type_change: LocalTypeChangeKind,
    pub type_ordinal: u32,
    pub type_name: String,
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
        7 => EventKind::SegmentMoved,
        8 => EventKind::FunctionUpdated,
        9 => EventKind::ItemTypeChanged,
        10 => EventKind::OperandTypeChanged,
        11 => EventKind::CodeCreated,
        12 => EventKind::DataCreated,
        13 => EventKind::ItemsDestroyed,
        14 => EventKind::ExtraCommentChanged,
        15 => EventKind::LocalTypesChanged,
        _ => EventKind::SegmentAdded,
    }
}

fn parse_extra_comment_placement(value: i32) -> ExtraCommentPlacement {
    match value {
        1 => ExtraCommentPlacement::Anterior,
        2 => ExtraCommentPlacement::Posterior,
        _ => ExtraCommentPlacement::Unknown,
    }
}

fn parse_local_type_change(value: i32) -> LocalTypeChangeKind {
    match value {
        1 => LocalTypeChangeKind::Added,
        2 => LocalTypeChangeKind::Deleted,
        3 => LocalTypeChangeKind::Edited,
        4 => LocalTypeChangeKind::Aliased,
        5 => LocalTypeChangeKind::CompilerChanged,
        6 => LocalTypeChangeKind::LibraryLoaded,
        7 => LocalTypeChangeKind::LibraryUnloaded,
        8 => LocalTypeChangeKind::OrdinalsCompacted,
        _ => LocalTypeChangeKind::None,
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
        size: ev.size,
        operand_index: ev.operand_index,
        line_index: ev.line_index,
        text: cstr_opt(ev.text),
        will_disable_range: ev.will_disable_range != 0,
        address_mapping_changed: ev.address_mapping_changed != 0,
        extra_comment_placement: parse_extra_comment_placement(ev.extra_comment_placement),
        local_type_change: parse_local_type_change(ev.local_type_change),
        type_ordinal: ev.type_ordinal,
        type_name: cstr_opt(ev.type_name),
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

thread_local! {
    static CALLBACK_DEPTH: Cell<usize> = const { Cell::new(0) };
    static DEFERRED_CONTEXT_DROPS: RefCell<Vec<ErasedContext>> = const { RefCell::new(Vec::new()) };
}

struct CallbackScope;

impl CallbackScope {
    fn enter() -> Self {
        CALLBACK_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for CallbackScope {
    fn drop(&mut self) {
        let should_drain = CALLBACK_DEPTH.with(|depth| {
            let current = depth.get();
            debug_assert!(current > 0);
            depth.set(current - 1);
            current == 1
        });
        if should_drain {
            let pending =
                DEFERRED_CONTEXT_DROPS.with(|deferred| std::mem::take(&mut *deferred.borrow_mut()));
            for context in pending {
                unsafe { (context.drop_fn)(context.ptr as *mut c_void) };
            }
        }
    }
}

fn release_context(context: ErasedContext) {
    let in_callback = CALLBACK_DEPTH.with(|depth| depth.get() != 0);
    if in_callback {
        DEFERRED_CONTEXT_DROPS.with(|deferred| deferred.borrow_mut().push(context));
    } else {
        unsafe { (context.drop_fn)(context.ptr as *mut c_void) };
    }
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
    let _scope = CallbackScope::enter();
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut SegmentAddedContext) };
    (ctx.callback)(start);
}

unsafe extern "C" fn segment_deleted_trampoline(context: *mut c_void, start: u64, end: u64) {
    let _scope = CallbackScope::enter();
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut SegmentDeletedContext) };
    (ctx.callback)(start, end);
}

unsafe extern "C" fn function_added_trampoline(context: *mut c_void, entry: u64) {
    let _scope = CallbackScope::enter();
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut FunctionAddedContext) };
    (ctx.callback)(entry);
}

unsafe extern "C" fn function_deleted_trampoline(context: *mut c_void, entry: u64) {
    let _scope = CallbackScope::enter();
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
    let _scope = CallbackScope::enter();
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut RenamedContext) };
    (ctx.callback)(address, cstr_opt(new_name), cstr_opt(old_name));
}

unsafe extern "C" fn byte_patched_trampoline(context: *mut c_void, address: u64, old_value: u32) {
    let _scope = CallbackScope::enter();
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
    let _scope = CallbackScope::enter();
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut CommentChangedContext) };
    (ctx.callback)(address, repeatable != 0);
}

unsafe extern "C" fn event_trampoline(context: *mut c_void, event: *const idax_sys::IdaxEvent) {
    let _scope = CallbackScope::enter();
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
    let _scope = CallbackScope::enter();
    if context.is_null() || event.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut FilteredEventContext) };
    let ev = unsafe { from_ffi_event(&*event) };
    if (ctx.filter)(&ev) { 1 } else { 0 }
}

unsafe extern "C" fn filtered_event_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxEvent,
) {
    let _scope = CallbackScope::enter();
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

type EventRegisterFn =
    unsafe extern "C" fn(idax_sys::IdaxEventExCallback, *mut c_void, *mut u64) -> std::ffi::c_int;

fn register_event_route<F>(
    register: EventRegisterFn,
    callback: F,
    label: &'static str,
) -> Result<Token>
where
    F: FnMut(Event) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(EventContext {
        callback: Box::new(callback),
    }));
    let mut token = 0;
    let ret = unsafe { register(Some(event_trampoline), raw as *mut c_void, &mut token) };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(label));
    }
    save_context(token, raw);
    Ok(token)
}

pub fn on_segment_moved<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(SegmentMovedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_segment_moved,
        move |event| {
            callback(SegmentMovedEvent {
                from: event.address,
                to: event.secondary_address,
                size: event.size,
                address_mapping_changed: event.address_mapping_changed,
            });
        },
        "event::on_segment_moved failed",
    )
}

pub fn on_function_updated<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_function_updated,
        move |event| callback(event.address),
        "event::on_function_updated failed",
    )
}

pub fn on_item_type_changed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_item_type_changed,
        move |event| callback(event.address),
        "event::on_item_type_changed failed",
    )
}

pub fn on_operand_type_changed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(Address, i32) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_operand_type_changed,
        move |event| callback(event.address, event.operand_index),
        "event::on_operand_type_changed failed",
    )
}

pub fn on_code_created<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(ItemCreatedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_code_created,
        move |event| {
            callback(ItemCreatedEvent {
                address: event.address,
                size: event.size,
            });
        },
        "event::on_code_created failed",
    )
}

pub fn on_data_created<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(ItemCreatedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_data_created,
        move |event| {
            callback(ItemCreatedEvent {
                address: event.address,
                size: event.size,
            });
        },
        "event::on_data_created failed",
    )
}

pub fn on_items_destroyed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(ItemsDestroyedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_items_destroyed,
        move |event| {
            callback(ItemsDestroyedEvent {
                start: event.address,
                end: event.secondary_address,
                will_disable_range: event.will_disable_range,
            });
        },
        "event::on_items_destroyed failed",
    )
}

pub fn on_extra_comment_changed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(ExtraCommentChangedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_extra_comment_changed,
        move |event| {
            callback(ExtraCommentChangedEvent {
                address: event.address,
                placement: event.extra_comment_placement,
                line_index: event.line_index,
                text: event.text,
            });
        },
        "event::on_extra_comment_changed failed",
    )
}

pub fn on_local_types_changed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(LocalTypesChangedEvent) + Send + 'static,
{
    register_event_route(
        idax_sys::idax_event_on_local_types_changed,
        move |event| {
            callback(LocalTypesChangedEvent {
                change: event.local_type_change,
                ordinal: event.type_ordinal,
                name: event.type_name,
            });
        },
        "event::on_local_types_changed failed",
    )
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
        let context = {
            SUB_CONTEXTS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .expect("event context mutex poisoned")
                .remove(&token)
        };
        if let Some(ctx) = context {
            release_context(ctx);
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
            size: 0,
            operand_index: -1,
            line_index: -1,
            text: String::new(),
            will_disable_range: false,
            address_mapping_changed: false,
            extra_comment_placement: ExtraCommentPlacement::Unknown,
            local_type_change: LocalTypeChangeKind::None,
            type_ordinal: 0,
            type_name: String::new(),
        }
    }
}
