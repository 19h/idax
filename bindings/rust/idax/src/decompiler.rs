//! Decompiler facade: availability, decompilation, pseudocode access,
//! ctree traversal, and user comment management.
//!
//! Mirrors the C++ `ida::decompiler` namespace.

use crate::address::Address;
use crate::error::{self, Error, Result, Status};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};

pub type Token = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Maturity {
    Zero = 0,
    Built = 1,
    Trans1 = 2,
    Nice = 3,
    Trans2 = 4,
    Cpa = 5,
    Trans3 = 6,
    Casted = 7,
    Final = 8,
}

impl Maturity {
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => Self::Built,
            2 => Self::Trans1,
            3 => Self::Nice,
            4 => Self::Trans2,
            5 => Self::Cpa,
            6 => Self::Trans3,
            7 => Self::Casted,
            8 => Self::Final,
            _ => Self::Zero,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ItemType {
    ExprEmpty = 0,
    ExprComma = 1,
    ExprAssign = 2,
    ExprAdd = 35,
    ExprSub = 36,
    ExprMul = 37,
    ExprCall = 57,
    ExprNumber = 61,
    ExprVariable = 65,
    ExprLast = 69,
    StmtEmpty = 70,
    StmtBlock = 71,
    StmtExpr = 72,
    StmtIf = 73,
    StmtFor = 74,
    StmtWhile = 75,
    StmtDo = 76,
    StmtSwitch = 77,
    StmtBreak = 78,
    StmtContinue = 79,
    StmtReturn = 80,
    StmtGoto = 81,
}

impl ItemType {
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => Self::ExprComma,
            2 => Self::ExprAssign,
            35 => Self::ExprAdd,
            36 => Self::ExprSub,
            37 => Self::ExprMul,
            57 => Self::ExprCall,
            61 => Self::ExprNumber,
            65 => Self::ExprVariable,
            69 => Self::ExprLast,
            70 => Self::StmtEmpty,
            71 => Self::StmtBlock,
            72 => Self::StmtExpr,
            73 => Self::StmtIf,
            74 => Self::StmtFor,
            75 => Self::StmtWhile,
            76 => Self::StmtDo,
            77 => Self::StmtSwitch,
            78 => Self::StmtBreak,
            79 => Self::StmtContinue,
            80 => Self::StmtReturn,
            81 => Self::StmtGoto,
            _ => Self::ExprEmpty,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum VisitAction {
    Continue = 0,
    Stop = 1,
    SkipChildren = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum MicrocodeApplyResult {
    NotHandled = 0,
    Handled = 1,
    Error = 2,
}

#[derive(Debug, Clone)]
pub struct MaturityEvent {
    pub function_address: Address,
    pub new_maturity: Maturity,
}

#[derive(Debug, Clone, Copy)]
pub struct PseudocodeEvent {
    pub function_address: Address,
    pub cfunc_handle: *mut c_void,
}

#[derive(Debug, Clone, Copy)]
pub struct CursorPositionEvent {
    pub function_address: Address,
    pub cursor_address: Address,
    pub view_handle: *mut c_void,
}

#[derive(Debug, Clone, Copy)]
pub struct HintRequestEvent {
    pub function_address: Address,
    pub item_address: Address,
    pub view_handle: *mut c_void,
}

#[derive(Debug, Clone)]
pub struct HintResult {
    pub text: String,
    pub lines: i32,
}

#[derive(Debug, Clone)]
pub struct LocalVariable {
    pub name: String,
    pub type_name: String,
    pub is_argument: bool,
    pub width: i32,
    pub has_user_name: bool,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct ExpressionInfo {
    pub item_type: ItemType,
    pub address: Address,
}

#[derive(Debug, Clone)]
pub struct StatementInfo {
    pub item_type: ItemType,
    pub address: Address,
}

#[derive(Debug, Clone)]
pub struct ItemAtPosition {
    pub item_type: ItemType,
    pub address: Address,
    pub item_index: i32,
    pub is_expression: bool,
}

#[derive(Debug, Clone)]
pub struct DecompileFailure {
    pub request_address: Address,
    pub failure_address: Address,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub struct DecompilerView {
    function_address: Address,
}

impl DecompilerView {
    pub fn function_address(&self) -> Address {
        self.function_address
    }

    pub fn decompiled_function(&self) -> Result<DecompiledFunction> {
        decompile(self.function_address)
    }
}

pub struct DecompiledFunction {
    handle: *mut c_void,
}

impl DecompiledFunction {
    pub fn pseudocode(&self) -> Result<String> {
        unsafe {
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_pseudocode(self.handle, &mut ptr);
            if ret != 0 {
                return Err(error::consume_last_error("pseudocode failed"));
            }
            error::cstr_to_string_free(ptr, "pseudocode failed")
        }
    }

    pub fn microcode(&self) -> Result<String> {
        unsafe {
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_microcode(self.handle, &mut ptr);
            if ret != 0 {
                return Err(error::consume_last_error("microcode failed"));
            }
            error::cstr_to_string_free(ptr, "microcode failed")
        }
    }

    pub fn lines(&self) -> Result<Vec<String>> {
        unsafe {
            let mut count: usize = 0;
            let mut lines_ptr: *mut *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_lines(self.handle, &mut lines_ptr, &mut count);
            if ret != 0 {
                return Err(error::consume_last_error("lines failed"));
            }
            let result = consume_string_array(lines_ptr, count);
            idax_sys::idax_decompiled_lines_free(lines_ptr, count);
            Ok(result)
        }
    }

    pub fn raw_lines(&self) -> Result<Vec<String>> {
        unsafe {
            let mut count: usize = 0;
            let mut lines_ptr: *mut *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_raw_lines(self.handle, &mut lines_ptr, &mut count);
            if ret != 0 {
                return Err(error::consume_last_error("raw_lines failed"));
            }
            let result = consume_string_array(lines_ptr, count);
            idax_sys::idax_decompiled_lines_free(lines_ptr, count);
            Ok(result)
        }
    }

    pub fn set_raw_line(&self, line_index: usize, tagged_text: &str) -> Status {
        let c_text =
            CString::new(tagged_text).map_err(|_| Error::validation("invalid tagged_text"))?;
        let ret = unsafe {
            idax_sys::idax_decompiled_set_raw_line(self.handle, line_index, c_text.as_ptr())
        };
        error::int_to_status(ret, "set_raw_line failed")
    }

    pub fn header_line_count(&self) -> Result<i32> {
        let mut out: i32 = 0;
        let ret = unsafe { idax_sys::idax_decompiled_header_line_count(self.handle, &mut out) };
        if ret != 0 {
            Err(error::consume_last_error("header_line_count failed"))
        } else {
            Ok(out)
        }
    }

    pub fn declaration(&self) -> Result<String> {
        unsafe {
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_declaration(self.handle, &mut ptr);
            if ret != 0 {
                return Err(error::consume_last_error("declaration failed"));
            }
            error::cstr_to_string_free(ptr, "declaration failed")
        }
    }

    pub fn variable_count(&self) -> Result<usize> {
        let mut n: usize = 0;
        let ret = unsafe { idax_sys::idax_decompiled_variable_count(self.handle, &mut n) };
        if ret != 0 {
            Err(error::consume_last_error("variable_count failed"))
        } else {
            Ok(n)
        }
    }

    pub fn variables(&self) -> Result<Vec<LocalVariable>> {
        unsafe {
            let mut ptr: *mut idax_sys::IdaxLocalVariable = std::ptr::null_mut();
            let mut count: usize = 0;
            let ret = idax_sys::idax_decompiled_variables(self.handle, &mut ptr, &mut count);
            if ret != 0 {
                return Err(error::consume_last_error("variables failed"));
            }
            if ptr.is_null() || count == 0 {
                return Ok(Vec::new());
            }

            let mut out = Vec::with_capacity(count);
            let slice = std::slice::from_raw_parts(ptr, count);
            for raw in slice {
                out.push(LocalVariable {
                    name: cstr_opt(raw.name),
                    type_name: cstr_opt(raw.type_name),
                    is_argument: raw.is_argument != 0,
                    width: raw.width,
                    has_user_name: raw.has_user_name != 0,
                    comment: cstr_opt(raw.comment),
                });
            }
            idax_sys::idax_decompiled_variables_free(ptr, count);
            Ok(out)
        }
    }

    pub fn rename_variable(&self, old_name: &str, new_name: &str) -> Status {
        let c_old = CString::new(old_name).map_err(|_| Error::validation("invalid old name"))?;
        let c_new = CString::new(new_name).map_err(|_| Error::validation("invalid new name"))?;
        let ret = unsafe {
            idax_sys::idax_decompiled_rename_variable(self.handle, c_old.as_ptr(), c_new.as_ptr())
        };
        error::int_to_status(ret, "rename_variable failed")
    }

    pub fn set_comment(&self, ea: Address, text: &str, position: i32) -> Status {
        let c = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
        let ret =
            unsafe { idax_sys::idax_decompiled_set_comment(self.handle, ea, c.as_ptr(), position) };
        error::int_to_status(ret, "set_comment failed")
    }

    pub fn get_comment(&self, ea: Address, position: i32) -> Result<String> {
        unsafe {
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let ret = idax_sys::idax_decompiled_get_comment(self.handle, ea, position, &mut ptr);
            if ret != 0 {
                return Err(error::consume_last_error("get_comment failed"));
            }
            error::cstr_to_string_free(ptr, "get_comment failed")
        }
    }

    pub fn save_comments(&self) -> Status {
        let ret = unsafe { idax_sys::idax_decompiled_save_comments(self.handle) };
        error::int_to_status(ret, "save_comments failed")
    }

    pub fn entry_address(&self) -> Result<Address> {
        let mut ea: Address = 0;
        let ret = unsafe { idax_sys::idax_decompiled_entry_address(self.handle, &mut ea) };
        if ret != 0 {
            Err(error::consume_last_error("entry_address failed"))
        } else {
            Ok(ea)
        }
    }

    pub fn line_to_address(&self, line_number: i32) -> Result<Address> {
        let mut ea: Address = 0;
        let ret =
            unsafe { idax_sys::idax_decompiled_line_to_address(self.handle, line_number, &mut ea) };
        if ret != 0 {
            Err(error::consume_last_error("line_to_address failed"))
        } else {
            Ok(ea)
        }
    }

    pub fn for_each_expression<F>(&self, callback: F) -> Result<i32>
    where
        F: FnMut(ExpressionInfo) -> VisitAction + 'static,
    {
        let mut boxed = Box::new(ExpressionVisitorContext {
            callback: Box::new(callback),
        });
        let mut visited: i32 = 0;
        let ret = unsafe {
            idax_sys::idax_decompiler_for_each_expression(
                self.handle,
                Some(expression_visitor_trampoline),
                (&mut *boxed) as *mut ExpressionVisitorContext as *mut c_void,
                &mut visited,
            )
        };
        if ret != 0 {
            Err(error::consume_last_error("for_each_expression failed"))
        } else {
            Ok(visited)
        }
    }

    pub fn for_each_item<FE, FS>(&self, on_expr: FE, on_stmt: FS) -> Result<i32>
    where
        FE: FnMut(ExpressionInfo) -> VisitAction + 'static,
        FS: FnMut(StatementInfo) -> VisitAction + 'static,
    {
        let mut boxed = Box::new(ItemVisitorContext {
            on_expr: Box::new(on_expr),
            on_stmt: Box::new(on_stmt),
        });
        let mut visited: i32 = 0;
        let ret = unsafe {
            idax_sys::idax_decompiler_for_each_item(
                self.handle,
                Some(item_expr_visitor_trampoline),
                Some(item_stmt_visitor_trampoline),
                (&mut *boxed) as *mut ItemVisitorContext as *mut c_void,
                &mut visited,
            )
        };
        if ret != 0 {
            Err(error::consume_last_error("for_each_item failed"))
        } else {
            Ok(visited)
        }
    }
}

impl Drop for DecompiledFunction {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                idax_sys::idax_decompiled_free(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for DecompiledFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.entry_address() {
            Ok(ea) => write!(f, "DecompiledFunction({:#x})", ea),
            Err(_) => write!(f, "DecompiledFunction(<unknown>)"),
        }
    }
}

struct ErasedContext {
    ptr: usize,
    drop_fn: unsafe fn(*mut c_void),
}

unsafe fn drop_as<T>(ptr: *mut c_void) {
    unsafe { drop(Box::from_raw(ptr as *mut T)) };
}

static SUB_CONTEXTS: OnceLock<Mutex<HashMap<Token, ErasedContext>>> = OnceLock::new();
static FILTER_CONTEXTS: OnceLock<Mutex<HashMap<Token, ErasedContext>>> = OnceLock::new();

fn save_context<T>(
    storage: &OnceLock<Mutex<HashMap<Token, ErasedContext>>>,
    token: Token,
    raw: *mut T,
) {
    storage
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("decompiler context mutex poisoned")
        .insert(
            token,
            ErasedContext {
                ptr: raw as usize,
                drop_fn: drop_as::<T>,
            },
        );
}

fn drop_saved_context(storage: &OnceLock<Mutex<HashMap<Token, ErasedContext>>>, token: Token) {
    if let Some(ctx) = storage
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("decompiler context mutex poisoned")
        .remove(&token)
    {
        unsafe { (ctx.drop_fn)(ctx.ptr as *mut c_void) };
    }
}

struct MaturityContext {
    callback: Box<dyn FnMut(MaturityEvent) + Send>,
}

struct PseudocodeContext {
    callback: Box<dyn FnMut(PseudocodeEvent) + Send>,
}

struct CurposContext {
    callback: Box<dyn FnMut(CursorPositionEvent) + Send>,
}

struct HintContext {
    callback: Box<dyn FnMut(HintRequestEvent) -> Option<HintResult> + Send>,
    scratch: Option<CString>,
}

unsafe extern "C" fn maturity_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxDecompilerMaturityEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut MaturityContext) };
    let event = unsafe { &*event };
    (ctx.callback)(MaturityEvent {
        function_address: event.function_address,
        new_maturity: Maturity::from_raw(event.new_maturity),
    });
}

unsafe extern "C" fn pseudocode_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxDecompilerPseudocodeEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut PseudocodeContext) };
    let event = unsafe { &*event };
    (ctx.callback)(PseudocodeEvent {
        function_address: event.function_address,
        cfunc_handle: event.cfunc_handle,
    });
}

unsafe extern "C" fn curpos_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxDecompilerCursorPositionEvent,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(context as *mut CurposContext) };
    let event = unsafe { &*event };
    (ctx.callback)(CursorPositionEvent {
        function_address: event.function_address,
        cursor_address: event.cursor_address,
        view_handle: event.view_handle,
    });
}

unsafe extern "C" fn hint_trampoline(
    context: *mut c_void,
    event: *const idax_sys::IdaxDecompilerHintRequestEvent,
    out_text: *mut *const c_char,
    out_lines: *mut i32,
) -> i32 {
    if context.is_null() || event.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut HintContext) };
    let event = unsafe { &*event };

    let request = HintRequestEvent {
        function_address: event.function_address,
        item_address: event.item_address,
        view_handle: event.view_handle,
    };

    let Some(result) = (ctx.callback)(request) else {
        return 0;
    };

    let Ok(text) = CString::new(result.text) else {
        return 0;
    };
    ctx.scratch = Some(text);

    if !out_text.is_null() {
        unsafe {
            *out_text = ctx
                .scratch
                .as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr());
        }
    }
    if !out_lines.is_null() {
        unsafe {
            *out_lines = result.lines;
        }
    }
    1
}

struct ExpressionVisitorContext {
    callback: Box<dyn FnMut(ExpressionInfo) -> VisitAction>,
}

struct ItemVisitorContext {
    on_expr: Box<dyn FnMut(ExpressionInfo) -> VisitAction>,
    on_stmt: Box<dyn FnMut(StatementInfo) -> VisitAction>,
}

unsafe extern "C" fn expression_visitor_trampoline(
    context: *mut c_void,
    expression: *const idax_sys::IdaxDecompilerExpressionInfo,
) -> i32 {
    if context.is_null() || expression.is_null() {
        return VisitAction::Continue as i32;
    }
    let ctx = unsafe { &mut *(context as *mut ExpressionVisitorContext) };
    let raw = unsafe { &*expression };
    (ctx.callback)(ExpressionInfo {
        item_type: ItemType::from_raw(raw.type_),
        address: raw.address,
    }) as i32
}

unsafe extern "C" fn item_expr_visitor_trampoline(
    context: *mut c_void,
    expression: *const idax_sys::IdaxDecompilerExpressionInfo,
) -> i32 {
    if context.is_null() || expression.is_null() {
        return VisitAction::Continue as i32;
    }
    let ctx = unsafe { &mut *(context as *mut ItemVisitorContext) };
    let raw = unsafe { &*expression };
    (ctx.on_expr)(ExpressionInfo {
        item_type: ItemType::from_raw(raw.type_),
        address: raw.address,
    }) as i32
}

unsafe extern "C" fn item_stmt_visitor_trampoline(
    context: *mut c_void,
    statement: *const idax_sys::IdaxDecompilerStatementInfo,
) -> i32 {
    if context.is_null() || statement.is_null() {
        return VisitAction::Continue as i32;
    }
    let ctx = unsafe { &mut *(context as *mut ItemVisitorContext) };
    let raw = unsafe { &*statement };
    (ctx.on_stmt)(StatementInfo {
        item_type: ItemType::from_raw(raw.type_),
        address: raw.address,
    }) as i32
}

struct MicrocodeFilterContext {
    match_callback: Box<dyn FnMut(Address, i32) -> bool + Send>,
    apply_callback: Box<dyn FnMut(*mut c_void) -> MicrocodeApplyResult + Send>,
}

unsafe extern "C" fn microcode_match_trampoline(
    context: *mut c_void,
    address: u64,
    itype: i32,
) -> i32 {
    if context.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(context as *mut MicrocodeFilterContext) };
    if (ctx.match_callback)(address, itype) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn microcode_apply_trampoline(context: *mut c_void, mctx: *mut c_void) -> i32 {
    if context.is_null() {
        return MicrocodeApplyResult::Error as i32;
    }
    let ctx = unsafe { &mut *(context as *mut MicrocodeFilterContext) };
    (ctx.apply_callback)(mctx) as i32
}

pub fn available() -> Result<bool> {
    let mut avail: i32 = 0;
    let ret = unsafe { idax_sys::idax_decompiler_available(&mut avail) };
    if ret != 0 {
        Err(error::consume_last_error("decompiler::available failed"))
    } else {
        Ok(avail != 0)
    }
}

pub fn decompile(ea: Address) -> Result<DecompiledFunction> {
    let mut handle: *mut c_void = std::ptr::null_mut();
    let ret = unsafe { idax_sys::idax_decompiler_decompile(ea, &mut handle) };
    if ret != 0 || handle.is_null() {
        Err(error::consume_last_error("decompiler::decompile failed"))
    } else {
        Ok(DecompiledFunction { handle })
    }
}

pub fn mark_dirty(function_address: Address, close_views: bool) -> Status {
    let ret = unsafe {
        idax_sys::idax_decompiler_mark_dirty(function_address, if close_views { 1 } else { 0 })
    };
    error::int_to_status(ret, "decompiler::mark_dirty failed")
}

pub fn mark_dirty_with_callers(function_address: Address, close_views: bool) -> Status {
    let ret = unsafe {
        idax_sys::idax_decompiler_mark_dirty_with_callers(
            function_address,
            if close_views { 1 } else { 0 },
        )
    };
    error::int_to_status(ret, "decompiler::mark_dirty_with_callers failed")
}

pub fn view_from_host(view_host: *mut c_void) -> Result<DecompilerView> {
    let mut out: Address = 0;
    let ret = unsafe { idax_sys::idax_decompiler_view_from_host(view_host, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "decompiler::view_from_host failed",
        ))
    } else {
        Ok(DecompilerView {
            function_address: out,
        })
    }
}

pub fn view_for_function(address: Address) -> Result<DecompilerView> {
    let mut out: Address = 0;
    let ret = unsafe { idax_sys::idax_decompiler_view_for_function(address, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "decompiler::view_for_function failed",
        ))
    } else {
        Ok(DecompilerView {
            function_address: out,
        })
    }
}

pub fn current_view() -> Result<DecompilerView> {
    let mut out: Address = 0;
    let ret = unsafe { idax_sys::idax_decompiler_current_view(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("decompiler::current_view failed"))
    } else {
        Ok(DecompilerView {
            function_address: out,
        })
    }
}

pub fn raw_pseudocode_lines(cfunc_handle: *mut c_void) -> Result<Vec<String>> {
    unsafe {
        let mut count: usize = 0;
        let mut lines_ptr: *mut *mut c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_decompiler_raw_pseudocode_lines(
            cfunc_handle,
            &mut lines_ptr,
            &mut count,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "decompiler::raw_pseudocode_lines failed",
            ));
        }
        let result = consume_string_array(lines_ptr, count);
        idax_sys::idax_decompiler_pseudocode_lines_free(lines_ptr, count);
        Ok(result)
    }
}

pub fn set_pseudocode_line(
    cfunc_handle: *mut c_void,
    line_index: usize,
    tagged_text: &str,
) -> Status {
    let c_text = CString::new(tagged_text).map_err(|_| Error::validation("invalid tagged_text"))?;
    let ret = unsafe {
        idax_sys::idax_decompiler_set_pseudocode_line(cfunc_handle, line_index, c_text.as_ptr())
    };
    error::int_to_status(ret, "decompiler::set_pseudocode_line failed")
}

pub fn pseudocode_header_line_count(cfunc_handle: *mut c_void) -> Result<i32> {
    let mut out: i32 = 0;
    let ret =
        unsafe { idax_sys::idax_decompiler_pseudocode_header_line_count(cfunc_handle, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error(
            "decompiler::pseudocode_header_line_count failed",
        ))
    } else {
        Ok(out)
    }
}

pub fn item_at_position(
    cfunc_handle: *mut c_void,
    tagged_line: &str,
    char_index: i32,
) -> Result<ItemAtPosition> {
    let c_line = CString::new(tagged_line).map_err(|_| Error::validation("invalid tagged_line"))?;
    let mut raw: idax_sys::IdaxDecompilerItemAtPosition = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        idax_sys::idax_decompiler_item_at_position(
            cfunc_handle,
            c_line.as_ptr(),
            char_index,
            &mut raw,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "decompiler::item_at_position failed",
        ))
    } else {
        Ok(ItemAtPosition {
            item_type: ItemType::from_raw(raw.type_),
            address: raw.address,
            item_index: raw.item_index,
            is_expression: raw.is_expression != 0,
        })
    }
}

pub fn item_type_name(item_type: ItemType) -> Result<String> {
    unsafe {
        let mut ptr: *mut c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_decompiler_item_type_name(item_type as i32, &mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error(
                "decompiler::item_type_name failed",
            ));
        }
        error::cstr_to_string_free(ptr, "decompiler::item_type_name failed")
    }
}

pub fn on_maturity_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(MaturityEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(MaturityContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_on_maturity_changed(
            Some(maturity_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::on_maturity_changed failed",
        ));
    }
    save_context(&SUB_CONTEXTS, token, raw);
    Ok(token)
}

pub fn on_func_printed<F>(callback: F) -> Result<Token>
where
    F: FnMut(PseudocodeEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(PseudocodeContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_on_func_printed(
            Some(pseudocode_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::on_func_printed failed",
        ));
    }
    save_context(&SUB_CONTEXTS, token, raw);
    Ok(token)
}

pub fn on_refresh_pseudocode<F>(callback: F) -> Result<Token>
where
    F: FnMut(PseudocodeEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(PseudocodeContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_on_refresh_pseudocode(
            Some(pseudocode_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::on_refresh_pseudocode failed",
        ));
    }
    save_context(&SUB_CONTEXTS, token, raw);
    Ok(token)
}

pub fn on_curpos_changed<F>(callback: F) -> Result<Token>
where
    F: FnMut(CursorPositionEvent) + Send + 'static,
{
    let raw = Box::into_raw(Box::new(CurposContext {
        callback: Box::new(callback),
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_on_curpos_changed(
            Some(curpos_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::on_curpos_changed failed",
        ));
    }
    save_context(&SUB_CONTEXTS, token, raw);
    Ok(token)
}

pub fn on_create_hint<F>(callback: F) -> Result<Token>
where
    F: FnMut(HintRequestEvent) -> Option<HintResult> + Send + 'static,
{
    let raw = Box::into_raw(Box::new(HintContext {
        callback: Box::new(callback),
        scratch: None,
    }));
    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_on_create_hint(
            Some(hint_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::on_create_hint failed",
        ));
    }
    save_context(&SUB_CONTEXTS, token, raw);
    Ok(token)
}

pub fn unsubscribe(token: Token) -> Status {
    let ret = unsafe { idax_sys::idax_decompiler_unsubscribe(token) };
    let status = error::int_to_status(ret, "decompiler::unsubscribe failed");
    if status.is_ok() {
        drop_saved_context(&SUB_CONTEXTS, token);
    }
    status
}

pub fn register_microcode_filter<FM, FA>(match_callback: FM, apply_callback: FA) -> Result<Token>
where
    FM: FnMut(Address, i32) -> bool + Send + 'static,
    FA: FnMut(*mut c_void) -> MicrocodeApplyResult + Send + 'static,
{
    let raw = Box::into_raw(Box::new(MicrocodeFilterContext {
        match_callback: Box::new(match_callback),
        apply_callback: Box::new(apply_callback),
    }));

    let mut token: Token = 0;
    let ret = unsafe {
        idax_sys::idax_decompiler_register_microcode_filter(
            Some(microcode_match_trampoline),
            Some(microcode_apply_trampoline),
            raw as *mut c_void,
            &mut token,
        )
    };
    if ret != 0 {
        unsafe { drop(Box::from_raw(raw)) };
        return Err(error::consume_last_error(
            "decompiler::register_microcode_filter failed",
        ));
    }

    save_context(&FILTER_CONTEXTS, token, raw);
    Ok(token)
}

pub fn unregister_microcode_filter(token: Token) -> Status {
    let ret = unsafe { idax_sys::idax_decompiler_unregister_microcode_filter(token) };
    let status = error::int_to_status(ret, "decompiler::unregister_microcode_filter failed");
    if status.is_ok() {
        drop_saved_context(&FILTER_CONTEXTS, token);
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

pub fn is_expression(t: ItemType) -> bool {
    (t as i32) <= (ItemType::ExprLast as i32)
}

pub fn is_statement(t: ItemType) -> bool {
    (t as i32) > (ItemType::ExprLast as i32)
}

pub fn for_each_expression<F>(func: &DecompiledFunction, callback: F) -> Result<i32>
where
    F: FnMut(ExpressionInfo) -> VisitAction + 'static,
{
    func.for_each_expression(callback)
}

pub fn for_each_item<FE, FS>(func: &DecompiledFunction, on_expr: FE, on_stmt: FS) -> Result<i32>
where
    FE: FnMut(ExpressionInfo) -> VisitAction + 'static,
    FS: FnMut(StatementInfo) -> VisitAction + 'static,
{
    func.for_each_item(on_expr, on_stmt)
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

unsafe fn consume_string_array(ptr: *mut *mut c_char, count: usize) -> Vec<String> {
    if ptr.is_null() || count == 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, count) };
    slice
        .iter()
        .map(|&p| {
            if p.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
            }
        })
        .collect()
}
