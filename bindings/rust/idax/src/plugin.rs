//! Plugin lifecycle, action registration, and export helpers.
//!
//! Mirrors the C++ `ida::plugin` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};

/// Plugin metadata.
#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub hotkey: String,
    pub comment: String,
    pub help: String,
    pub icon: i32,
}

/// Action context.
#[derive(Debug, Clone)]
pub struct ActionContext {
    pub action_id: String,
    pub widget_title: String,
    pub widget_type: i32,
    pub current_address: Address,
    pub current_value: u64,
    pub has_selection: bool,
    pub is_external_address: bool,
    pub register_name: String,
    pub widget_handle: *mut c_void,
    pub focused_widget_handle: *mut c_void,
    pub decompiler_view_handle: *mut c_void,
}

/// Action descriptor.
#[derive(Debug, Clone)]
pub struct Action {
    pub id: String,
    pub label: String,
    pub hotkey: String,
    pub tooltip: String,
    pub icon: i32,
}

/// Opaque host pointer for a widget.
pub type WidgetHost = *mut c_void;

/// Opaque host pointer for a decompiler view.
pub type DecompilerViewHost = *mut c_void;

fn c_ptr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

fn from_ffi_action_context(ctx: &idax_sys::IdaxPluginActionContext) -> ActionContext {
    ActionContext {
        action_id: c_ptr_to_string(ctx.action_id),
        widget_title: c_ptr_to_string(ctx.widget_title),
        widget_type: ctx.widget_type,
        current_address: ctx.current_address,
        current_value: ctx.current_value,
        has_selection: ctx.has_selection != 0,
        is_external_address: ctx.is_external_address != 0,
        register_name: c_ptr_to_string(ctx.register_name),
        widget_handle: ctx.widget_handle,
        focused_widget_handle: ctx.focused_widget_handle,
        decompiler_view_handle: ctx.decompiler_view_handle,
    }
}

fn with_ffi_action_context<T, F>(context: &ActionContext, f: F) -> Result<T>
where
    F: FnOnce(&idax_sys::IdaxPluginActionContext) -> Result<T>,
{
    let action_id = CString::new(context.action_id.as_str())
        .map_err(|_| Error::validation("invalid action_id"))?;
    let widget_title = CString::new(context.widget_title.as_str())
        .map_err(|_| Error::validation("invalid widget_title"))?;
    let register_name = CString::new(context.register_name.as_str())
        .map_err(|_| Error::validation("invalid register_name"))?;

    let ffi = idax_sys::IdaxPluginActionContext {
        action_id: action_id.as_ptr(),
        widget_title: widget_title.as_ptr(),
        widget_type: context.widget_type,
        current_address: context.current_address,
        current_value: context.current_value,
        has_selection: if context.has_selection { 1 } else { 0 },
        is_external_address: if context.is_external_address { 1 } else { 0 },
        register_name: register_name.as_ptr(),
        widget_handle: context.widget_handle,
        focused_widget_handle: context.focused_widget_handle,
        decompiler_view_handle: context.decompiler_view_handle,
    };

    f(&ffi)
}

struct ActionHandlerContext {
    callback: Box<dyn FnMut(ActionContext) + Send>,
}

struct ActionEnabledContext {
    callback: Box<dyn FnMut(&ActionContext) -> bool + Send>,
}

struct ErasedContext {
    ptr: usize,
    drop_fn: unsafe fn(*mut c_void),
}

struct ActionContextPair {
    handler: Option<ErasedContext>,
    enabled: Option<ErasedContext>,
}

unsafe fn drop_as<T>(ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut T)) };
}

static ACTION_CONTEXTS: OnceLock<Mutex<HashMap<String, ActionContextPair>>> = OnceLock::new();

fn clear_action_context(action_id: &str) {
    if let Some(pair) = ACTION_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("plugin action context mutex poisoned")
        .remove(action_id)
    {
        if let Some(handler) = pair.handler {
            unsafe { (handler.drop_fn)(handler.ptr as *mut c_void) };
        }
        if let Some(enabled) = pair.enabled {
            unsafe { (enabled.drop_fn)(enabled.ptr as *mut c_void) };
        }
    }
}

unsafe extern "C" fn action_handler_ex_trampoline(
    context: *mut c_void,
    action_context: *const idax_sys::IdaxPluginActionContext,
) {
    if context.is_null() || action_context.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut ActionHandlerContext) };
    let action_ctx = unsafe { from_ffi_action_context(&*action_context) };
    (ctx.callback)(action_ctx);
}

unsafe extern "C" fn action_enabled_ex_trampoline(
    context: *mut c_void,
    action_context: *const idax_sys::IdaxPluginActionContext,
) -> i32 {
    if context.is_null() || action_context.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut ActionEnabledContext) };
    let action_ctx = unsafe { from_ffi_action_context(&*action_context) };
    if (ctx.callback)(&action_ctx) {
        1
    } else {
        0
    }
}

/// Register a UI action.
pub fn register_action(action: &Action) -> Status {
    let c_id = CString::new(action.id.as_str()).map_err(|_| Error::validation("invalid id"))?;
    let c_label =
        CString::new(action.label.as_str()).map_err(|_| Error::validation("invalid label"))?;
    let c_hotkey =
        CString::new(action.hotkey.as_str()).map_err(|_| Error::validation("invalid hotkey"))?;
    let c_tooltip =
        CString::new(action.tooltip.as_str()).map_err(|_| Error::validation("invalid tooltip"))?;
    let ret = unsafe {
        idax_sys::idax_plugin_register_action(
            c_id.as_ptr(),
            c_label.as_ptr(),
            c_hotkey.as_ptr(),
            c_tooltip.as_ptr(),
            action.icon,
            None,
            std::ptr::null_mut(),
            None,
            std::ptr::null_mut(),
        )
    };
    let status = error::int_to_status(ret, "plugin::register_action failed");
    if status.is_ok() {
        clear_action_context(action.id.as_str());
    }
    status
}

/// Register a UI action with typed action context callbacks.
pub fn register_action_with_context<H, E>(
    action: &Action,
    handler: H,
    enabled_check: Option<E>,
) -> Status
where
    H: FnMut(ActionContext) + Send + 'static,
    E: FnMut(&ActionContext) -> bool + Send + 'static,
{
    let c_id = CString::new(action.id.as_str()).map_err(|_| Error::validation("invalid id"))?;
    let c_label =
        CString::new(action.label.as_str()).map_err(|_| Error::validation("invalid label"))?;
    let c_hotkey =
        CString::new(action.hotkey.as_str()).map_err(|_| Error::validation("invalid hotkey"))?;
    let c_tooltip =
        CString::new(action.tooltip.as_str()).map_err(|_| Error::validation("invalid tooltip"))?;

    let raw_handler = Box::into_raw(Box::new(ActionHandlerContext {
        callback: Box::new(handler),
    }));
    let raw_enabled = enabled_check.map(|cb| {
        Box::into_raw(Box::new(ActionEnabledContext {
            callback: Box::new(cb),
        }))
    });
    let enabled_cb = if raw_enabled.is_some() {
        Some(
            action_enabled_ex_trampoline
                as unsafe extern "C" fn(
                    *mut c_void,
                    *const idax_sys::IdaxPluginActionContext,
                ) -> i32,
        )
    } else {
        None
    };
    let enabled_ctx = raw_enabled
        .map(|p| p as *mut c_void)
        .unwrap_or(std::ptr::null_mut());

    let ret = unsafe {
        idax_sys::idax_plugin_register_action_ex(
            c_id.as_ptr(),
            c_label.as_ptr(),
            c_hotkey.as_ptr(),
            c_tooltip.as_ptr(),
            action.icon,
            None,
            Some(action_handler_ex_trampoline),
            raw_handler as *mut c_void,
            None,
            enabled_cb,
            enabled_ctx,
        )
    };

    if ret != 0 {
        unsafe { drop(Box::from_raw(raw_handler)) };
        if let Some(ptr) = raw_enabled {
            unsafe { drop(Box::from_raw(ptr)) };
        }
        return Err(error::consume_last_error(
            "plugin::register_action_with_context failed",
        ));
    }

    let pair = ActionContextPair {
        handler: Some(ErasedContext {
            ptr: raw_handler as usize,
            drop_fn: drop_as::<ActionHandlerContext>,
        }),
        enabled: raw_enabled.map(|ptr| ErasedContext {
            ptr: ptr as usize,
            drop_fn: drop_as::<ActionEnabledContext>,
        }),
    };

    let mut map = ACTION_CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("plugin action context mutex poisoned");
    if let Some(previous) = map.insert(action.id.clone(), pair) {
        if let Some(handler_ctx) = previous.handler {
            unsafe { (handler_ctx.drop_fn)(handler_ctx.ptr as *mut c_void) };
        }
        if let Some(enabled_ctx) = previous.enabled {
            unsafe { (enabled_ctx.drop_fn)(enabled_ctx.ptr as *mut c_void) };
        }
    }

    Ok(())
}

/// Unregister a UI action.
pub fn unregister_action(action_id: &str) -> Status {
    let c = CString::new(action_id).map_err(|_| Error::validation("invalid id"))?;
    let ret = unsafe { idax_sys::idax_plugin_unregister_action(c.as_ptr()) };
    let status = error::int_to_status(ret, "plugin::unregister_action failed");
    if status.is_ok() {
        clear_action_context(action_id);
    }
    status
}

/// Attach an action to a menu path.
pub fn attach_to_menu(menu_path: &str, action_id: &str) -> Status {
    let c_menu = CString::new(menu_path).map_err(|_| Error::validation("invalid menu path"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_attach_to_menu(c_menu.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::attach_to_menu failed")
}

/// Attach an action to a toolbar.
pub fn attach_to_toolbar(toolbar: &str, action_id: &str) -> Status {
    let c_tb = CString::new(toolbar).map_err(|_| Error::validation("invalid toolbar"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_attach_to_toolbar(c_tb.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::attach_to_toolbar failed")
}

/// Attach an action to a widget popup/context menu.
pub fn attach_to_popup(widget_title: &str, action_id: &str) -> Status {
    let c_widget =
        CString::new(widget_title).map_err(|_| Error::validation("invalid widget title"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_attach_to_popup(c_widget.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::attach_to_popup failed")
}

/// Detach an action from a menu path.
pub fn detach_from_menu(menu_path: &str, action_id: &str) -> Status {
    let c_menu = CString::new(menu_path).map_err(|_| Error::validation("invalid menu path"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_detach_from_menu(c_menu.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::detach_from_menu failed")
}

/// Detach an action from a toolbar.
pub fn detach_from_toolbar(toolbar: &str, action_id: &str) -> Status {
    let c_tb = CString::new(toolbar).map_err(|_| Error::validation("invalid toolbar"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_detach_from_toolbar(c_tb.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::detach_from_toolbar failed")
}

/// Detach an action from a widget popup/context menu.
pub fn detach_from_popup(widget_title: &str, action_id: &str) -> Status {
    let c_widget =
        CString::new(widget_title).map_err(|_| Error::validation("invalid widget title"))?;
    let c_id = CString::new(action_id).map_err(|_| Error::validation("invalid action id"))?;
    let ret = unsafe { idax_sys::idax_plugin_detach_from_popup(c_widget.as_ptr(), c_id.as_ptr()) };
    error::int_to_status(ret, "plugin::detach_from_popup failed")
}

/// Get the widget host pointer from an action context.
pub fn widget_host(context: &ActionContext) -> Result<WidgetHost> {
    with_ffi_action_context(context, |ffi| {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { idax_sys::idax_plugin_action_context_widget_host(ffi, &mut out) };
        if ret != 0 {
            Err(error::consume_last_error("plugin::widget_host failed"))
        } else {
            Ok(out)
        }
    })
}

/// Execute a callback with a widget host pointer from an action context.
pub fn with_widget_host<F>(context: &ActionContext, callback: F) -> Status
where
    F: FnOnce(WidgetHost) -> Status,
{
    let host = widget_host(context)?;
    callback(host)
}

/// Get the decompiler-view host pointer from an action context.
pub fn decompiler_view_host(context: &ActionContext) -> Result<DecompilerViewHost> {
    with_ffi_action_context(context, |ffi| {
        let mut out: *mut c_void = std::ptr::null_mut();
        let ret =
            unsafe { idax_sys::idax_plugin_action_context_decompiler_view_host(ffi, &mut out) };
        if ret != 0 {
            Err(error::consume_last_error(
                "plugin::decompiler_view_host failed",
            ))
        } else {
            Ok(out)
        }
    })
}

/// Execute a callback with a decompiler-view host pointer from an action context.
pub fn with_decompiler_view_host<F>(context: &ActionContext, callback: F) -> Status
where
    F: FnOnce(DecompilerViewHost) -> Status,
{
    let host = decompiler_view_host(context)?;
    callback(host)
}

impl Default for ActionContext {
    fn default() -> Self {
        Self {
            action_id: String::new(),
            widget_title: String::new(),
            widget_type: -1,
            current_address: BAD_ADDRESS,
            current_value: 0,
            has_selection: false,
            is_external_address: false,
            register_name: String::new(),
            widget_handle: std::ptr::null_mut(),
            focused_widget_handle: std::ptr::null_mut(),
            decompiler_view_handle: std::ptr::null_mut(),
        }
    }
}
