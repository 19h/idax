//! UI utilities: messages, warnings, dialogs, navigation, widgets,
//! timers, event subscriptions, and view refresh.
//!
//! Mirrors the C++ `ida::ui` namespace.

use crate::address::{Address, Range, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};

// ── Widget type constants ───────────────────────────────────────────────

/// Well-known widget types (corresponds to IDA's `BWN_*` constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum WidgetType {
    Unknown = -1,
    Exports = 0,
    Imports = 1,
    Names = 2,
    Functions = 3,
    Strings = 4,
    Segments = 5,
    Segregs = 6,
    Selectors = 7,
    Signatures = 8,
    TypeLibraries = 9,
    LocalTypes = 10,
    Problems = 12,
    Breakpoints = 13,
    Threads = 14,
    Modules = 15,
    TraceLog = 16,
    CallStack = 17,
    CrossRefs = 18,
    SearchResults = 19,
    StackFrame = 25,
    NavBand = 26,
    Disassembly = 27,
    HexView = 28,
    Notepad = 29,
    Output = 30,
    CommandLine = 31,
    Chooser = 35,
    Pseudocode = 46,
    Microcode = 61,
}

/// Convert a raw `i32` widget type value to [`WidgetType`].
fn widget_type_from_i32(v: i32) -> WidgetType {
    match v {
        0 => WidgetType::Exports,
        1 => WidgetType::Imports,
        2 => WidgetType::Names,
        3 => WidgetType::Functions,
        4 => WidgetType::Strings,
        5 => WidgetType::Segments,
        6 => WidgetType::Segregs,
        7 => WidgetType::Selectors,
        8 => WidgetType::Signatures,
        9 => WidgetType::TypeLibraries,
        10 => WidgetType::LocalTypes,
        12 => WidgetType::Problems,
        13 => WidgetType::Breakpoints,
        14 => WidgetType::Threads,
        15 => WidgetType::Modules,
        16 => WidgetType::TraceLog,
        17 => WidgetType::CallStack,
        18 => WidgetType::CrossRefs,
        19 => WidgetType::SearchResults,
        25 => WidgetType::StackFrame,
        26 => WidgetType::NavBand,
        27 => WidgetType::Disassembly,
        28 => WidgetType::HexView,
        29 => WidgetType::Notepad,
        30 => WidgetType::Output,
        31 => WidgetType::CommandLine,
        35 => WidgetType::Chooser,
        46 => WidgetType::Pseudocode,
        61 => WidgetType::Microcode,
        _ => WidgetType::Unknown,
    }
}

/// Preferred docking position when showing a widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DockPosition {
    Left = 0,
    Right = 1,
    Top = 2,
    Bottom = 3,
    Floating = 4,
    Tab = 5,
}

/// Options controlling how a widget is displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShowWidgetOptions {
    pub position: DockPosition,
    pub restore_previous: bool,
}

impl Default for ShowWidgetOptions {
    fn default() -> Self {
        Self {
            position: DockPosition::Right,
            restore_previous: true,
        }
    }
}

// ── Messages ────────────────────────────────────────────────────────────

/// Print a message to the IDA output window.
pub fn message(text: &str) {
    if let Ok(c_text) = CString::new(text) {
        unsafe { idax_sys::idax_ui_message(c_text.as_ptr()) };
    }
}

/// Show a warning dialog.
pub fn warning(text: &str) {
    if let Ok(c_text) = CString::new(text) {
        unsafe { idax_sys::idax_ui_warning(c_text.as_ptr()) };
    }
}

/// Show an info dialog.
pub fn info(text: &str) {
    if let Ok(c_text) = CString::new(text) {
        unsafe { idax_sys::idax_ui_info(c_text.as_ptr()) };
    }
}

// ── Simple Dialogs ──────────────────────────────────────────────────────

/// Ask the user a yes/no question. Returns `true` for yes.
pub fn ask_yn(question: &str, default_yes: bool) -> Result<bool> {
    let c_q = CString::new(question).map_err(|_| Error::validation("invalid question string"))?;
    let mut out: i32 = 0;
    let rc = unsafe { idax_sys::idax_ui_ask_yn(c_q.as_ptr(), default_yes as i32, &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_yn failed"));
    }
    Ok(out != 0)
}

/// Ask the user for a text string.
pub fn ask_string(prompt: &str, default_value: &str) -> Result<String> {
    let c_prompt = CString::new(prompt).map_err(|_| Error::validation("invalid prompt"))?;
    let c_default =
        CString::new(default_value).map_err(|_| Error::validation("invalid default value"))?;
    let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc =
        unsafe { idax_sys::idax_ui_ask_string(c_prompt.as_ptr(), c_default.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_string failed"));
    }
    Ok(unsafe { error::consume_c_string(out) })
}

/// Ask the user for a file path.
///
/// If `for_saving` is `true`, shows a "save" dialog; otherwise "open".
pub fn ask_file(for_saving: bool, default_path: &str, prompt: &str) -> Result<String> {
    let c_default =
        CString::new(default_path).map_err(|_| Error::validation("invalid default path"))?;
    let c_prompt = CString::new(prompt).map_err(|_| Error::validation("invalid prompt"))?;
    let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe {
        idax_sys::idax_ui_ask_file(
            for_saving as i32,
            c_default.as_ptr(),
            c_prompt.as_ptr(),
            &mut out,
        )
    };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_file failed"));
    }
    Ok(unsafe { error::consume_c_string(out) })
}

/// Ask the user for an address.
pub fn ask_address(prompt: &str, default_value: Address) -> Result<Address> {
    let c_prompt = CString::new(prompt).map_err(|_| Error::validation("invalid prompt"))?;
    let mut out: Address = BAD_ADDRESS;
    let rc = unsafe { idax_sys::idax_ui_ask_address(c_prompt.as_ptr(), default_value, &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_address failed"));
    }
    Ok(out)
}

/// Ask the user for a long integer value.
pub fn ask_long(prompt: &str, default_value: i64) -> Result<i64> {
    let c_prompt = CString::new(prompt).map_err(|_| Error::validation("invalid prompt"))?;
    let mut out: i64 = 0;
    let rc = unsafe { idax_sys::idax_ui_ask_long(c_prompt.as_ptr(), default_value, &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_long failed"));
    }
    Ok(out)
}

/// Show an IDA form and return whether it was accepted.
pub fn ask_form(markup: &str) -> Result<bool> {
    let c_markup = CString::new(markup).map_err(|_| Error::validation("invalid form markup"))?;
    let mut out: i32 = 0;
    let rc = unsafe { idax_sys::idax_ui_ask_form(c_markup.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::ask_form failed"));
    }
    Ok(out != 0)
}

// ── Navigation ──────────────────────────────────────────────────────────

/// Navigate the active disassembly view to the given address.
///
/// Equivalent to double-clicking an address or pressing G and entering it.
pub fn jump_to(address: Address) -> Status {
    let rc = unsafe { idax_sys::idax_ui_jump_to(address) };
    error::int_to_status(rc, "ui::jump_to failed")
}

// ── Screen/cursor queries ───────────────────────────────────────────────

/// Get the current effective address in the IDA view.
pub fn screen_address() -> Result<Address> {
    let mut out: Address = BAD_ADDRESS;
    let rc = unsafe { idax_sys::idax_ui_screen_address(&mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::screen_address failed"));
    }
    Ok(out)
}

/// Get the current selection range, if any.
pub fn selection() -> Result<Range> {
    let mut start: Address = BAD_ADDRESS;
    let mut end: Address = BAD_ADDRESS;
    let rc = unsafe { idax_sys::idax_ui_selection(&mut start, &mut end) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::selection failed"));
    }
    Ok(Range { start, end })
}

// ── Widget handle ───────────────────────────────────────────────────────

/// Opaque handle to a docked widget panel.
///
/// A `Widget` wraps IDA's internal widget pointer without exposing it.
/// Widget instances are lightweight handles — copying is cheap but both
/// copies refer to the same underlying panel.
#[derive(Clone)]
pub struct Widget {
    handle: *mut c_void,
}

impl Widget {
    /// Whether this handle refers to a live widget.
    pub fn valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Create a null/empty widget handle.
    pub(crate) fn null() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }

    /// Create a widget handle from a raw pointer.
    #[allow(dead_code)]
    pub(crate) fn from_raw(handle: *mut c_void) -> Self {
        Self { handle }
    }

    /// Widget title.
    pub fn title(&self) -> Result<String> {
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { idax_sys::idax_ui_widget_title(self.handle, &mut out) };
        if rc != 0 {
            return Err(error::consume_last_error("ui::widget_title failed"));
        }
        Ok(unsafe { error::consume_c_string(out) })
    }

    /// Stable widget identity token.
    pub fn id(&self) -> Result<u64> {
        let mut out: u64 = 0;
        let rc = unsafe { idax_sys::idax_ui_widget_id(self.handle, &mut out) };
        if rc != 0 {
            return Err(error::consume_last_error("ui::widget_id failed"));
        }
        Ok(out)
    }
}

impl Default for Widget {
    fn default() -> Self {
        Self::null()
    }
}

impl std::fmt::Debug for Widget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Widget(valid={})", self.valid())
    }
}

impl PartialEq for Widget {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl Eq for Widget {}

/// Get the widget type for a widget handle.
pub fn widget_type(widget: &Widget) -> WidgetType {
    let val = unsafe { idax_sys::idax_ui_widget_type(widget.handle) };
    widget_type_from_i32(val)
}

/// Create a new empty docked widget with the given title.
///
/// The widget is not yet visible — call [`show_widget()`] to display it.
pub fn create_widget(title: &str) -> Result<Widget> {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid title"))?;
    let mut handle: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_ui_create_widget(c_title.as_ptr(), &mut handle) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::create_widget failed"));
    }
    Ok(Widget { handle })
}

/// Display (or re-display) a widget in IDA's docking system.
pub fn show_widget(widget: &mut Widget, position: DockPosition) -> Status {
    let opts = ShowWidgetOptions {
        position,
        restore_previous: true,
    };
    show_widget_with_options(widget, opts)
}

/// Display (or re-display) a widget with explicit options.
pub fn show_widget_with_options(widget: &mut Widget, options: ShowWidgetOptions) -> Status {
    let ffi_options = idax_sys::IdaxShowWidgetOptions {
        position: options.position as i32,
        restore_previous: if options.restore_previous { 1 } else { 0 },
    };
    let rc = unsafe { idax_sys::idax_ui_show_widget_ex(widget.handle, &ffi_options) };
    error::int_to_status(rc, "ui::show_widget failed")
}

/// Bring an already-visible widget to the foreground.
pub fn activate_widget(widget: &mut Widget) -> Status {
    let rc = unsafe { idax_sys::idax_ui_activate_widget(widget.handle) };
    error::int_to_status(rc, "ui::activate_widget failed")
}

/// Find an existing widget by its title.
///
/// Returns an empty `Widget` (`valid() == false`) if not found.
pub fn find_widget(title: &str) -> Widget {
    let c_title = match CString::new(title) {
        Ok(c) => c,
        Err(_) => return Widget::null(),
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_ui_find_widget(c_title.as_ptr(), &mut handle) };
    if rc != 0 {
        return Widget::null();
    }
    Widget { handle }
}

/// Close and destroy a widget.
///
/// After this call the handle becomes invalid.
pub fn close_widget(widget: &mut Widget) -> Status {
    let rc = unsafe { idax_sys::idax_ui_close_widget(widget.handle) };
    if rc == 0 {
        widget.handle = std::ptr::null_mut();
    }
    error::int_to_status(rc, "ui::close_widget failed")
}

/// Check whether a widget is currently visible on screen.
pub fn is_widget_visible(widget: &Widget) -> bool {
    let rc = unsafe { idax_sys::idax_ui_is_widget_visible(widget.handle) };
    rc != 0
}

/// Opaque toolkit-native widget host pointer.
pub type WidgetHost = *mut c_void;

/// Get the native host pointer for a widget.
pub fn widget_host(widget: &Widget) -> Result<WidgetHost> {
    let mut out: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_ui_widget_host(widget.handle, &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::widget_host failed"));
    }
    Ok(out)
}

/// Execute a callback with the widget host pointer.
pub fn with_widget_host<F>(widget: &Widget, callback: F) -> Status
where
    F: FnOnce(WidgetHost) -> Status,
{
    let host = widget_host(widget)?;
    callback(host)
}

/// Create a custom text viewer backed by line content.
pub fn create_custom_viewer(title: &str, lines: &[String]) -> Result<Widget> {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid viewer title"))?;
    let c_lines: std::result::Result<Vec<CString>, _> = lines
        .iter()
        .map(|line| CString::new(line.as_str()))
        .collect();
    let c_lines = c_lines.map_err(|_| Error::validation("line contains interior NUL"))?;
    let line_ptrs: Vec<*const c_char> = c_lines.iter().map(|line| line.as_ptr()).collect();

    let mut out: *mut c_void = std::ptr::null_mut();
    let rc = unsafe {
        idax_sys::idax_ui_create_custom_viewer(
            c_title.as_ptr(),
            line_ptrs.as_ptr(),
            line_ptrs.len(),
            &mut out,
        )
    };
    if rc != 0 {
        return Err(error::consume_last_error("ui::create_custom_viewer failed"));
    }
    Ok(Widget { handle: out })
}

/// Replace all lines in an existing custom text viewer.
pub fn set_custom_viewer_lines(viewer: &mut Widget, lines: &[String]) -> Status {
    let c_lines: std::result::Result<Vec<CString>, _> = lines
        .iter()
        .map(|line| CString::new(line.as_str()))
        .collect();
    let c_lines = c_lines.map_err(|_| Error::validation("line contains interior NUL"))?;
    let line_ptrs: Vec<*const c_char> = c_lines.iter().map(|line| line.as_ptr()).collect();
    let rc = unsafe {
        idax_sys::idax_ui_set_custom_viewer_lines(
            viewer.handle,
            line_ptrs.as_ptr(),
            line_ptrs.len(),
        )
    };
    error::int_to_status(rc, "ui::set_custom_viewer_lines failed")
}

/// Get the number of lines in a custom viewer.
pub fn custom_viewer_line_count(viewer: &Widget) -> Result<usize> {
    let mut out: usize = 0;
    let rc = unsafe { idax_sys::idax_ui_custom_viewer_line_count(viewer.handle, &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error(
            "ui::custom_viewer_line_count failed",
        ));
    }
    Ok(out)
}

/// Jump to a specific line in a custom viewer.
pub fn custom_viewer_jump_to_line(
    viewer: &mut Widget,
    line_index: usize,
    x: i32,
    y: i32,
) -> Status {
    let rc =
        unsafe { idax_sys::idax_ui_custom_viewer_jump_to_line(viewer.handle, line_index, x, y) };
    error::int_to_status(rc, "ui::custom_viewer_jump_to_line failed")
}

/// Read the current line text from a custom viewer.
pub fn custom_viewer_current_line(viewer: &Widget, mouse: bool) -> Result<String> {
    let mut out: *mut c_char = std::ptr::null_mut();
    let rc = unsafe {
        idax_sys::idax_ui_custom_viewer_current_line(
            viewer.handle,
            if mouse { 1 } else { 0 },
            &mut out,
        )
    };
    if rc != 0 {
        return Err(error::consume_last_error(
            "ui::custom_viewer_current_line failed",
        ));
    }
    Ok(unsafe { error::consume_c_string(out) })
}

/// Refresh/repaint custom viewer contents.
pub fn refresh_custom_viewer(viewer: &mut Widget) -> Status {
    let rc = unsafe { idax_sys::idax_ui_refresh_custom_viewer(viewer.handle) };
    error::int_to_status(rc, "ui::refresh_custom_viewer failed")
}

/// Close and destroy a custom viewer.
pub fn close_custom_viewer(viewer: &mut Widget) -> Status {
    let rc = unsafe { idax_sys::idax_ui_close_custom_viewer(viewer.handle) };
    if rc == 0 {
        viewer.handle = std::ptr::null_mut();
    }
    error::int_to_status(rc, "ui::close_custom_viewer failed")
}

// ── Chooser infrastructure ──────────────────────────────────────────────

/// Column data type hint for a chooser column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ColumnFormat {
    /// Free-form string.
    Plain = 0,
    /// File path (truncated from start).
    Path = 1,
    /// Hex number.
    Hex = 2,
    /// Decimal number.
    Decimal = 3,
    /// Effective address.
    Address = 4,
    /// Function name (auto-colored).
    FunctionName = 5,
}

/// Describes a single column in a chooser.
#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub width: i32,
    pub format: ColumnFormat,
}

/// Per-row styling for a chooser item.
#[derive(Debug, Clone, Default)]
pub struct RowStyle {
    pub bold: bool,
    pub italic: bool,
    pub strikethrough: bool,
    pub gray: bool,
    /// Background color (0 = default).
    pub background_color: u32,
}

/// A single row of data in a chooser.
#[derive(Debug, Clone)]
pub struct Row {
    pub columns: Vec<String>,
    pub icon: i32,
    pub style: RowStyle,
}

impl Default for Row {
    fn default() -> Self {
        Self {
            columns: Vec::new(),
            icon: -1,
            style: RowStyle::default(),
        }
    }
}

/// Options for constructing a chooser.
#[derive(Debug, Clone)]
pub struct ChooserOptions {
    pub title: String,
    pub columns: Vec<Column>,
    pub modal: bool,
    pub can_insert: bool,
    pub can_delete: bool,
    pub can_edit: bool,
    pub can_refresh: bool,
}

impl Default for ChooserOptions {
    fn default() -> Self {
        Self {
            title: String::new(),
            columns: Vec::new(),
            modal: false,
            can_insert: false,
            can_delete: false,
            can_edit: false,
            can_refresh: true,
        }
    }
}

/// Base trait for custom choosers (list dialogs).
///
/// Implement [`count()`](ChooserImpl::count) and [`row()`](ChooserImpl::row)
/// at minimum. Optionally override callbacks for insert/delete/edit/enter/close.
///
/// # Example
///
/// ```ignore
/// struct MyChooser { items: Vec<(String, String)> }
///
/// impl ida::ui::ChooserImpl for MyChooser {
///     fn count(&self) -> usize { self.items.len() }
///     fn row(&self, index: usize) -> ida::ui::Row {
///         ida::ui::Row {
///             columns: vec![self.items[index].0.clone(), self.items[index].1.clone()],
///             ..Default::default()
///         }
///     }
/// }
/// ```
pub trait ChooserImpl {
    /// Number of items in the list.
    fn count(&self) -> usize;

    /// Get row data for item at `index`.
    fn row(&self, index: usize) -> Row;

    /// Get the address associated with row `index` (for Enter-to-jump).
    /// Return `BAD_ADDRESS` if no associated address.
    fn address_for(&self, _index: usize) -> Address {
        BAD_ADDRESS
    }

    /// Called when the user wants to insert a new item.
    fn on_insert(&mut self, _before_index: usize) {}

    /// Called when the user wants to delete an item.
    fn on_delete(&mut self, _index: usize) {}

    /// Called when the user wants to edit an item.
    fn on_edit(&mut self, _index: usize) {}

    /// Called when the user presses Enter on an item.
    fn on_enter(&mut self, _index: usize) {}

    /// Called when the chooser is refreshed.
    fn on_refresh(&mut self) {}

    /// Called when the chooser is about to close.
    fn on_close(&mut self) {}
}

// ── Timer ───────────────────────────────────────────────────────────────

struct TimerCallbackContext {
    callback: Box<dyn FnMut() -> i32 + Send>,
}

struct EventCallbackContext {
    callback: Box<dyn FnMut(Event) + Send>,
}

struct FilteredEventCallbackContext {
    filter: Box<dyn FnMut(&Event) -> bool + Send>,
    callback: Box<dyn FnMut(Event) + Send>,
}

struct PopupCallbackContext {
    callback: Box<dyn FnMut(PopupEvent) + Send>,
}

struct RenderingCallbackContext {
    callback: Box<dyn FnMut(RenderingEvent) + Send>,
}

struct ActionCallbackContext {
    callback: Box<dyn FnMut() + Send>,
}

struct ErasedContext {
    ptr: usize,
    drop_fn: unsafe fn(*mut c_void),
}

unsafe fn drop_as<T>(ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut T)) };
}

static TIMER_CONTEXTS: OnceLock<Mutex<HashMap<u64, usize>>> = OnceLock::new();
static SUB_CONTEXTS: OnceLock<Mutex<HashMap<u64, ErasedContext>>> = OnceLock::new();
static ACTION_CONTEXTS: OnceLock<Mutex<HashMap<String, ErasedContext>>> = OnceLock::new();

unsafe extern "C" fn timer_callback_trampoline(context: *mut c_void) -> i32 {
    let ctx = unsafe { &mut *(context as *mut TimerCallbackContext) };
    (ctx.callback)()
}

/// Register a periodic timer callback.
pub fn register_timer_with_callback<F>(interval_ms: i32, callback: F) -> Result<u64>
where
    F: FnMut() -> i32 + Send + 'static,
{
    let boxed = Box::new(TimerCallbackContext {
        callback: Box::new(callback),
    });
    let raw = Box::into_raw(boxed);

    let mut token: u64 = 0;
    let rc = unsafe {
        idax_sys::idax_ui_register_timer_with_callback(
            interval_ms,
            Some(timer_callback_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("ui::register_timer failed"));
    }

    TIMER_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("timer context mutex poisoned")
        .insert(token, raw as usize);

    Ok(token)
}

/// Register a periodic timer without a Rust callback.
pub fn register_timer(interval_ms: i32) -> Result<u64> {
    let mut token: u64 = 0;
    let rc = unsafe { idax_sys::idax_ui_register_timer(interval_ms, &mut token) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::register_timer failed"));
    }
    Ok(token)
}

/// Unregister a timer.
pub fn unregister_timer(token: u64) -> Status {
    let rc = unsafe { idax_sys::idax_ui_unregister_timer(token) };
    let status = error::int_to_status(rc, "ui::unregister_timer failed");
    if status.is_ok() {
        if let Some(raw) = TIMER_CONTEXTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("timer context mutex poisoned")
            .remove(&token)
        {
            unsafe { drop(Box::from_raw(raw as *mut TimerCallbackContext)) };
        }
    }
    status
}

// ── UI event subscriptions ──────────────────────────────────────────────

/// UI event subscription token.
pub type Token = u64;

/// Generic UI/view event kind for broad routing subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EventKind {
    DatabaseInited = 0,
    DatabaseClosed = 1,
    ReadyToRun = 2,
    CurrentWidgetChanged = 3,
    ScreenAddressChanged = 4,
    WidgetVisible = 5,
    WidgetInvisible = 6,
    WidgetClosing = 7,
    ViewActivated = 8,
    ViewDeactivated = 9,
    ViewCreated = 10,
    ViewClosed = 11,
    CursorChanged = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WidgetRef {
    pub raw: *mut c_void,
    pub id: u64,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    pub address: Address,
    pub previous_address: Address,
    pub widget: Option<WidgetRef>,
    pub previous_widget: Option<WidgetRef>,
    pub is_new_database: bool,
    pub startup_script: String,
    pub widget_title: String,
}

#[derive(Debug, Clone)]
pub struct PopupEvent {
    pub widget: Option<WidgetRef>,
    pub popup: *mut c_void,
    pub r#type: WidgetType,
    pub widget_title: String,
}

#[derive(Debug, Clone, Copy)]
pub struct LineRenderEntry {
    pub line_number: i32,
    pub bg_color: u32,
    pub start_column: i32,
    pub length: i32,
    pub character_range: bool,
}

pub struct RenderingEvent {
    pub widget: Option<WidgetRef>,
    pub r#type: WidgetType,
    opaque: *mut idax_sys::IdaxRenderingEvent,
}

impl RenderingEvent {
    pub fn add_entry(&mut self, entry: LineRenderEntry) {
        if self.opaque.is_null() {
            return;
        }
        let ffi = idax_sys::IdaxLineRenderEntry {
            line_number: entry.line_number,
            bg_color: entry.bg_color,
            start_column: entry.start_column,
            length: entry.length,
            character_range: if entry.character_range { 1 } else { 0 },
        };
        unsafe {
            idax_sys::idax_ui_rendering_event_add_entry(self.opaque, &ffi);
        }
    }
}

fn parse_event_kind(kind: i32) -> EventKind {
    match kind {
        0 => EventKind::DatabaseInited,
        1 => EventKind::DatabaseClosed,
        2 => EventKind::ReadyToRun,
        3 => EventKind::CurrentWidgetChanged,
        4 => EventKind::ScreenAddressChanged,
        5 => EventKind::WidgetVisible,
        6 => EventKind::WidgetInvisible,
        7 => EventKind::WidgetClosing,
        8 => EventKind::ViewActivated,
        9 => EventKind::ViewDeactivated,
        10 => EventKind::ViewCreated,
        11 => EventKind::ViewClosed,
        12 => EventKind::CursorChanged,
        _ => EventKind::DatabaseClosed,
    }
}

fn from_ffi_event(ev: &idax_sys::IdaxUIEvent) -> Event {
    let startup_script = if ev.startup_script.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ev.startup_script) }
            .to_string_lossy()
            .into_owned()
    };
    let widget_title = if ev.widget_title.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ev.widget_title) }
            .to_string_lossy()
            .into_owned()
    };
    Event {
        kind: parse_event_kind(ev.kind),
        address: ev.address,
        previous_address: ev.previous_address,
        widget: if ev.widget.is_null() {
            None
        } else {
            Some(WidgetRef {
                raw: ev.widget,
                id: ev.widget_id,
            })
        },
        previous_widget: if ev.previous_widget.is_null() {
            None
        } else {
            Some(WidgetRef {
                raw: ev.previous_widget,
                id: ev.previous_widget_id,
            })
        },
        is_new_database: ev.is_new_database != 0,
        startup_script,
        widget_title,
    }
}

unsafe extern "C" fn event_callback_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxUIEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut EventCallbackContext) };
    let ev = unsafe { from_ffi_event(&*event) };
    (ctx.callback)(ev);
}

unsafe extern "C" fn event_filter_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxUIEvent,
) -> i32 {
    if context.is_null() || event.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut FilteredEventCallbackContext) };
    let ev = unsafe { from_ffi_event(&*event) };
    if (ctx.filter)(&ev) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn filtered_event_callback_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxUIEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut FilteredEventCallbackContext) };
    let ev = unsafe { from_ffi_event(&*event) };
    (ctx.callback)(ev);
}

unsafe extern "C" fn popup_callback_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxPopupEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut PopupCallbackContext) };
    let ev = unsafe { &*event };
    let widget_title = if ev.widget_title.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ev.widget_title) }
            .to_string_lossy()
            .into_owned()
    };
    let popup_event = PopupEvent {
        widget: if ev.widget.is_null() {
            None
        } else {
            Some(WidgetRef {
                raw: ev.widget,
                id: ev.widget_id,
            })
        },
        popup: ev.popup,
        r#type: widget_type_from_i32(ev.widget_type),
        widget_title,
    };
    (ctx.callback)(popup_event);
}

unsafe extern "C" fn rendering_callback_trampoline(
    context: *mut c_void,
    event: *mut idax_sys::IdaxRenderingEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut RenderingCallbackContext) };
    let ev = unsafe { &*event };
    let rendering_event = RenderingEvent {
        widget: if ev.widget.is_null() {
            None
        } else {
            Some(WidgetRef {
                raw: ev.widget,
                id: ev.widget_id,
            })
        },
        r#type: widget_type_from_i32(ev.widget_type),
        opaque: event,
    };
    (ctx.callback)(rendering_event);
}

unsafe extern "C" fn action_callback_trampoline(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut ActionCallbackContext) };
    (ctx.callback)();
}

fn save_subscription_context<T>(token: Token, raw: *mut T) {
    SUB_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("subscription context mutex poisoned")
        .insert(
            token,
            ErasedContext {
                ptr: raw as usize,
                drop_fn: drop_as::<T>,
            },
        );
}

fn subscribe_event_with<F>(
    ffi_subscribe: F,
    callback: Box<dyn FnMut(Event) + Send>,
) -> Result<Token>
where
    F: FnOnce(idax_sys::IdaxUIEventExCallback, *mut c_void, *mut u64) -> i32,
{
    let raw = Box::into_raw(Box::new(EventCallbackContext { callback }));
    let mut token: Token = 0;
    let rc = ffi_subscribe(
        Some(event_callback_trampoline),
        raw as *mut c_void,
        &mut token,
    );
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("ui event subscription failed"));
    }
    save_subscription_context(token, raw);
    Ok(token)
}

/// Subscribe to a UI event using the legacy low-level callback ABI.
pub fn subscribe(
    event_kind: EventKind,
    callback: idax_sys::IdaxUIEventCallback,
    context: *mut c_void,
) -> Result<Token> {
    let mut token: Token = 0;
    let rc =
        unsafe { idax_sys::idax_ui_subscribe(event_kind as i32, callback, context, &mut token) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::subscribe failed"));
    }
    Ok(token)
}

pub fn on_database_closed<F>(mut callback: F) -> Result<Token>
where
    F: FnMut() + Send + 'static,
{
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_database_closed(cb, ctx, token) },
        Box::new(move |_| callback()),
    )
}

pub fn on_database_inited<F>(mut callback: F) -> Result<Token>
where
    F: FnMut(bool, String) + Send + 'static,
{
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_database_inited(cb, ctx, token) },
        Box::new(move |ev| callback(ev.is_new_database, ev.startup_script)),
    )
}

pub fn on_ready_to_run<F>(mut callback: F) -> Result<Token>
where
    F: FnMut() + Send + 'static,
{
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_ready_to_run(cb, ctx, token) },
        Box::new(move |_| callback()),
    )
}

pub fn on_screen_ea_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address, Address) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_screen_ea_changed(cb, ctx, token) },
        Box::new(move |ev| callback(ev.address, ev.previous_address)),
    )
}

pub fn on_current_widget_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>, Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_current_widget_changed(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget, ev.previous_widget)),
    )
}

pub fn on_widget_visible<F>(callback: F) -> Result<Token>
where
    F: FnMut(String) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_widget_visible(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget_title)),
    )
}

pub fn on_widget_invisible<F>(callback: F) -> Result<Token>
where
    F: FnMut(String) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_widget_invisible(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget_title)),
    )
}

pub fn on_widget_closing<F>(callback: F) -> Result<Token>
where
    F: FnMut(String) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_widget_closing(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget_title)),
    )
}

pub fn on_widget_visible_for_widget<F>(widget: &Widget, callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe {
            idax_sys::idax_ui_on_widget_visible_for_widget(widget.handle, cb, ctx, token)
        },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_widget_invisible_for_widget<F>(widget: &Widget, callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe {
            idax_sys::idax_ui_on_widget_invisible_for_widget(widget.handle, cb, ctx, token)
        },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_widget_closing_for_widget<F>(widget: &Widget, callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe {
            idax_sys::idax_ui_on_widget_closing_for_widget(widget.handle, cb, ctx, token)
        },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_cursor_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Address) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_cursor_changed(cb, ctx, token) },
        Box::new(move |ev| callback(ev.address)),
    )
}

pub fn on_view_activated<F>(callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_view_activated(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_view_deactivated<F>(callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_view_deactivated(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_view_created<F>(callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_view_created(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_view_closed<F>(callback: F) -> Result<Token>
where
    F: FnMut(Option<WidgetRef>) + Send + 'static,
{
    let mut callback = callback;
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_view_closed(cb, ctx, token) },
        Box::new(move |ev| callback(ev.widget)),
    )
}

pub fn on_event<F>(callback: F) -> Result<Token>
where
    F: FnMut(Event) + Send + 'static,
{
    subscribe_event_with(
        |cb, ctx, token| unsafe { idax_sys::idax_ui_on_event(cb, ctx, token) },
        Box::new(callback),
    )
}

pub fn on_event_filtered<Flt, Cb>(filter: Flt, callback: Cb) -> Result<Token>
where
    Flt: FnMut(&Event) -> bool + Send + 'static,
    Cb: FnMut(Event) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(FilteredEventCallbackContext {
        filter: Box::new(filter),
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let rc = unsafe {
        idax_sys::idax_ui_on_event_filtered(
            Some(event_filter_trampoline),
            Some(filtered_event_callback_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("ui::on_event_filtered failed"));
    }
    save_subscription_context(token, raw);
    Ok(token)
}

pub fn on_popup_ready<F>(callback: F) -> Result<Token>
where
    F: FnMut(PopupEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(PopupCallbackContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let rc = unsafe {
        idax_sys::idax_ui_on_popup_ready(
            Some(popup_callback_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("ui::on_popup_ready failed"));
    }
    save_subscription_context(token, raw);
    Ok(token)
}

pub fn attach_dynamic_action<F>(
    popup: *mut c_void,
    widget: &Widget,
    action_id: &str,
    label: &str,
    callback: F,
    menu_path: &str,
    icon: i32,
) -> Status
where
    F: FnMut() + Send + 'static,
{
    let c_action_id =
        CString::new(action_id).map_err(|_| Error::validation("invalid action_id"))?;
    let c_label = CString::new(label).map_err(|_| Error::validation("invalid label"))?;
    let c_menu_path =
        CString::new(menu_path).map_err(|_| Error::validation("invalid menu path"))?;

    let raw = Box::into_raw(Box::new(ActionCallbackContext {
        callback: Box::new(callback),
    }));

    let rc = unsafe {
        idax_sys::idax_ui_attach_dynamic_action(
            popup,
            widget.handle,
            c_action_id.as_ptr(),
            c_label.as_ptr(),
            Some(action_callback_trampoline),
            raw as *mut c_void,
            c_menu_path.as_ptr(),
            icon,
        )
    };
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return error::int_to_status(rc, "ui::attach_dynamic_action failed");
    }

    let mut action_map = ACTION_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("action context mutex poisoned");
    if let Some(previous) = action_map.insert(
        action_id.to_string(),
        ErasedContext {
            ptr: raw as usize,
            drop_fn: drop_as::<ActionCallbackContext>,
        },
    ) {
        unsafe { (previous.drop_fn)(previous.ptr as *mut c_void) };
    }

    Ok(())
}

pub fn on_rendering_info<F>(callback: F) -> Result<Token>
where
    F: FnMut(RenderingEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(RenderingCallbackContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let rc = unsafe {
        idax_sys::idax_ui_on_rendering_info(
            Some(rendering_callback_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if rc != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error("ui::on_rendering_info failed"));
    }
    save_subscription_context(token, raw);
    Ok(token)
}

/// Unsubscribe from a UI or view event.
pub fn unsubscribe(token: Token) -> Status {
    let rc = unsafe { idax_sys::idax_ui_unsubscribe(token) };
    let status = error::int_to_status(rc, "ui::unsubscribe failed");
    if status.is_ok() {
        if let Some(erased) = SUB_CONTEXTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("subscription context mutex poisoned")
            .remove(&token)
        {
            unsafe { (erased.drop_fn)(erased.ptr as *mut c_void) };
        }
    }
    status
}

/// RAII guard that unsubscribes a UI event on destruction.
pub struct ScopedSubscription {
    token: Token,
}

impl ScopedSubscription {
    /// Create a new scoped subscription from a token.
    pub fn new(token: Token) -> Self {
        Self { token }
    }

    /// Get the underlying token.
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

// ── Miscellaneous utilities ─────────────────────────────────────────────

/// Get the user's IDA configuration directory (e.g., `~/.idapro` on Linux).
pub fn user_directory() -> Result<String> {
    let mut out: *mut c_char = std::ptr::null_mut();
    let rc = unsafe { idax_sys::idax_ui_user_directory(&mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("ui::user_directory failed"));
    }
    Ok(unsafe { error::consume_c_string(out) })
}

/// Force all IDA views to repaint immediately.
pub fn refresh_all_views() {
    unsafe { idax_sys::idax_ui_refresh_all_views() };
}
