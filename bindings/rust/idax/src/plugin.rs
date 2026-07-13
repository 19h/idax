//! Plugin lifecycle, action registration, and export helpers.
//!
//! Mirrors the C++ `ida::plugin` namespace.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::{self, Error, Result, Status};
use crate::types::TypeInfo;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
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
    pub type_ref: Option<TypeRef>,
}

/// Local Types reference carried by action contexts from type-listing widgets.
#[derive(Debug, Clone)]
pub struct TypeRef {
    pub name: String,
    pub r#type: TypeInfo,
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

static HOTKEY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Move-only shortcut registration that unregisters on drop.
#[derive(Debug)]
pub struct ScopedHotkey {
    action_id: String,
    hotkey: String,
}

impl ScopedHotkey {
    /// Whether this object currently owns a registered shortcut action.
    pub fn is_active(&self) -> bool {
        !self.action_id.is_empty()
    }

    /// The shortcut supplied at registration.
    pub fn hotkey(&self) -> &str {
        &self.hotkey
    }

    /// Invoke the shortcut action programmatically.
    pub fn activate(&self) -> Status {
        if !self.is_active() {
            return Err(Error::not_found("hotkey registration is inactive"));
        }
        activate_action(&self.action_id)
    }

    /// Unregister before drop. Returns `NotFound` when already inactive.
    pub fn release(&mut self) -> Status {
        if !self.is_active() {
            return Err(Error::not_found("hotkey registration is inactive"));
        }
        unregister_action(&self.action_id)?;
        self.action_id.clear();
        self.hotkey.clear();
        Ok(())
    }
}

impl Drop for ScopedHotkey {
    fn drop(&mut self) {
        if self.is_active() {
            let _ = self.release();
        }
    }
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
    let type_ref = if ctx.type_ref_type.is_null() {
        None
    } else {
        Some(TypeRef {
            name: c_ptr_to_string(ctx.type_ref_name),
            r#type: TypeInfo::from_raw(ctx.type_ref_type),
        })
    };

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
        type_ref,
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
    let type_ref_name = CString::new(
        context
            .type_ref
            .as_ref()
            .map(|type_ref| type_ref.name.as_str())
            .unwrap_or(""),
    )
    .map_err(|_| Error::validation("invalid type_ref name"))?;
    let type_ref_type = context
        .type_ref
        .as_ref()
        .map(|type_ref| type_ref.r#type.as_raw())
        .unwrap_or(std::ptr::null_mut());

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
        type_ref_name: if context.type_ref.is_some() {
            type_ref_name.as_ptr()
        } else {
            std::ptr::null()
        },
        type_ref_type,
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
    let _ = catch_unwind(AssertUnwindSafe(|| (ctx.callback)(action_ctx)));
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
    match catch_unwind(AssertUnwindSafe(|| (ctx.callback)(&action_ctx))) {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
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

/// Activate a registered action by its internal identifier.
pub fn activate_action(action_id: &str) -> Status {
    let c = CString::new(action_id).map_err(|_| Error::validation("invalid id"))?;
    let ret = unsafe { idax_sys::idax_plugin_activate_action(c.as_ptr()) };
    error::int_to_status(ret, "plugin::activate_action failed")
}

/// Register a shortcut-only callback and return its scoped owner.
pub fn register_hotkey<H>(hotkey: &str, mut handler: H) -> Result<ScopedHotkey>
where
    H: FnMut() + Send + 'static,
{
    if hotkey.is_empty() {
        return Err(Error::validation("hotkey cannot be empty"));
    }

    let module_identity = &HOTKEY_SEQUENCE as *const AtomicU64 as usize;
    let sequence = HOTKEY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let action_id = format!("idax:hotkey:{module_identity}:{sequence}");
    let action = Action {
        id: action_id.clone(),
        label: "idax shortcut".to_string(),
        hotkey: hotkey.to_string(),
        tooltip: String::new(),
        icon: -1,
    };
    register_action_with_context(
        &action,
        move |_| handler(),
        None::<fn(&ActionContext) -> bool>,
    )?;
    Ok(ScopedHotkey {
        action_id,
        hotkey: hotkey.to_string(),
    })
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
            type_ref: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn action_context_type_ref_is_exposed_in_ffi_shape() {
        let context = ActionContext {
            action_id: "idax:test:type_ref".to_string(),
            widget_title: "Local Types".to_string(),
            widget_type: 42,
            current_address: 0x401000,
            current_value: 7,
            has_selection: true,
            is_external_address: false,
            register_name: "rax".to_string(),
            type_ref: Some(TypeRef {
                name: "idax_test_type".to_string(),
                r#type: TypeInfo::from_raw(std::ptr::null_mut()),
            }),
            ..ActionContext::default()
        };

        with_ffi_action_context(&context, |ffi| {
            assert!(!ffi.type_ref_name.is_null());
            assert!(ffi.type_ref_type.is_null());
            assert_eq!(c_ptr_to_string(ffi.type_ref_name), "idax_test_type");
            assert_eq!(ffi.current_address, 0x401000);
            assert_eq!(ffi.has_selection, 1);
            Ok(())
        })
        .unwrap();

        let action_id = CString::new("idax:test:type_ref").unwrap();
        let widget_title = CString::new("Local Types").unwrap();
        let register_name = CString::new("rax").unwrap();
        let ffi = idax_sys::IdaxPluginActionContext {
            action_id: action_id.as_ptr(),
            widget_title: widget_title.as_ptr(),
            widget_type: 42,
            current_address: 0x401000,
            current_value: 7,
            has_selection: 1,
            is_external_address: 0,
            register_name: register_name.as_ptr(),
            widget_handle: std::ptr::null_mut(),
            focused_widget_handle: std::ptr::null_mut(),
            decompiler_view_handle: std::ptr::null_mut(),
            type_ref_name: std::ptr::null(),
            type_ref_type: std::ptr::null_mut(),
        };

        let safe = from_ffi_action_context(&ffi);
        assert_eq!(safe.action_id, "idax:test:type_ref");
        assert_eq!(safe.widget_title, "Local Types");
        assert_eq!(safe.current_address, 0x401000);
        assert!(safe.type_ref.is_none());
    }

    #[test]
    fn action_callback_panics_are_contained_at_ffi_boundary() {
        let handler_entered = Arc::new(AtomicBool::new(false));
        let handler_entered_from_callback = Arc::clone(&handler_entered);
        let raw_handler = Box::into_raw(Box::new(ActionHandlerContext {
            callback: Box::new(move |_| {
                handler_entered_from_callback.store(true, Ordering::Release);
                panic!("handler panic probe");
            }),
        }));
        let ffi = idax_sys::IdaxPluginActionContext::default();
        let outer = catch_unwind(AssertUnwindSafe(|| unsafe {
            action_handler_ex_trampoline(raw_handler.cast(), &ffi);
        }));
        assert!(outer.is_ok());
        assert!(handler_entered.load(Ordering::Acquire));
        unsafe { drop(Box::from_raw(raw_handler)) };

        let enabled_entered = Arc::new(AtomicBool::new(false));
        let enabled_entered_from_callback = Arc::clone(&enabled_entered);
        let raw_enabled = Box::into_raw(Box::new(ActionEnabledContext {
            callback: Box::new(move |_| {
                enabled_entered_from_callback.store(true, Ordering::Release);
                panic!("enabled panic probe");
            }),
        }));
        let state = unsafe { action_enabled_ex_trampoline(raw_enabled.cast(), &ffi) };
        assert_eq!(state, 0);
        assert!(enabled_entered.load(Ordering::Acquire));
        unsafe { drop(Box::from_raw(raw_enabled)) };
    }
}
