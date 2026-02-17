//! Graph API: custom graphs, flow charts, node/edge manipulation.
//!
//! Mirrors the C++ `ida::graph` namespace. Provides an opaque `Graph` handle
//! for building interactive graphs and flow chart construction for
//! control-flow analysis.
//!
//! `Graph` implements `Drop` for RAII cleanup (move-only, not cloneable).

use crate::address::{Address, Range};
use crate::error::{self, Error, Result, Status};
use std::cell::RefCell;
use std::ffi::{c_char, c_void, CString};
use std::mem::ManuallyDrop;

// ── Node/edge primitives ────────────────────────────────────────────────

/// A node is identified by an integer index.
pub type NodeId = i32;

/// A directed edge connects two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub source: NodeId,
    pub target: NodeId,
}

/// Visual properties for a node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeInfo {
    pub background_color: u32,
    pub frame_color: u32,
    pub address: Address,
    pub text: String,
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            background_color: 0xFFFF_FFFF,
            frame_color: 0xFFFF_FFFF,
            address: crate::address::BAD_ADDRESS,
            text: String::new(),
        }
    }
}

/// Visual properties for an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdgeInfo {
    pub color: u32,
    pub width: i32,
    pub source_port: i32,
    pub target_port: i32,
}

impl Default for EdgeInfo {
    fn default() -> Self {
        Self {
            color: 0xFFFF_FFFF,
            width: 1,
            source_port: -1,
            target_port: -1,
        }
    }
}

/// Layout algorithm choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Layout {
    None = 0,
    /// Directed graph (default for flow charts).
    Digraph = 1,
    Tree = 2,
    Circle = 3,
    PolarTree = 4,
    Orthogonal = 5,
    RadialTree = 6,
}

// ── Graph object ────────────────────────────────────────────────────────

/// Opaque handle to an interactive graph.
///
/// Create with [`Graph::new()`]. The graph can be used programmatically
/// to build and inspect node/edge structures.
///
/// This type implements [`Drop`] to release the underlying SDK resource.
/// It is move-only (not cloneable).
pub struct Graph {
    handle: *mut std::ffi::c_void,
}

unsafe impl Send for Graph {}

impl Graph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        let handle = unsafe { idax_sys::idax_graph_create() };
        Graph { handle }
    }

    // ── Node operations ─────────────────────────────────────────────────

    /// Add a node to the graph. Returns the new node ID.
    pub fn add_node(&mut self) -> NodeId {
        unsafe { idax_sys::idax_graph_add_node(self.handle) }
    }

    /// Remove a node and all its incident edges.
    pub fn remove_node(&mut self, node: NodeId) -> Status {
        let rc = unsafe { idax_sys::idax_graph_remove_node(self.handle, node) };
        error::int_to_status(rc, "Graph::remove_node failed")
    }

    /// Total number of nodes (including group/hidden nodes).
    pub fn total_node_count(&self) -> i32 {
        unsafe { idax_sys::idax_graph_total_node_count(self.handle) }
    }

    /// Number of visible (non-hidden) nodes.
    pub fn visible_node_count(&self) -> i32 {
        unsafe { idax_sys::idax_graph_visible_node_count(self.handle) }
    }

    /// Check if a node exists and is visible.
    pub fn node_exists(&self, node: NodeId) -> bool {
        unsafe { idax_sys::idax_graph_node_exists(self.handle, node) != 0 }
    }

    // ── Edge operations ─────────────────────────────────────────────────

    /// Add a directed edge from `source` to `target`.
    pub fn add_edge(&mut self, source: NodeId, target: NodeId) -> Status {
        let rc = unsafe { idax_sys::idax_graph_add_edge(self.handle, source, target) };
        error::int_to_status(rc, "Graph::add_edge failed")
    }

    /// Add a directed edge with visual properties.
    pub fn add_edge_with_info(&mut self, source: NodeId, target: NodeId, info: EdgeInfo) -> Status {
        let raw = idax_sys::IdaxGraphEdgeInfo {
            color: info.color,
            width: info.width,
            source_port: info.source_port,
            target_port: info.target_port,
        };
        let rc =
            unsafe { idax_sys::idax_graph_add_edge_with_info(self.handle, source, target, &raw) };
        error::int_to_status(rc, "Graph::add_edge_with_info failed")
    }

    /// Remove a directed edge.
    pub fn remove_edge(&mut self, source: NodeId, target: NodeId) -> Status {
        let rc = unsafe { idax_sys::idax_graph_remove_edge(self.handle, source, target) };
        error::int_to_status(rc, "Graph::remove_edge failed")
    }

    /// Replace edge `(from, to)` with `(new_from, new_to)`.
    pub fn replace_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        new_from: NodeId,
        new_to: NodeId,
    ) -> Status {
        let rc =
            unsafe { idax_sys::idax_graph_replace_edge(self.handle, from, to, new_from, new_to) };
        error::int_to_status(rc, "Graph::replace_edge failed")
    }

    // ── Traversal ───────────────────────────────────────────────────────

    /// Get successor node IDs for a node.
    pub fn successors(&self, node: NodeId) -> Result<Vec<NodeId>> {
        collect_node_ids(
            |out, count| unsafe { idax_sys::idax_graph_successors(self.handle, node, out, count) },
            "Graph::successors failed",
        )
    }

    /// Get predecessor node IDs for a node.
    pub fn predecessors(&self, node: NodeId) -> Result<Vec<NodeId>> {
        collect_node_ids(
            |out, count| unsafe {
                idax_sys::idax_graph_predecessors(self.handle, node, out, count)
            },
            "Graph::predecessors failed",
        )
    }

    /// Get all visible node IDs.
    pub fn visible_nodes(&self) -> Result<Vec<NodeId>> {
        collect_node_ids(
            |out, count| unsafe { idax_sys::idax_graph_visible_nodes(self.handle, out, count) },
            "Graph::visible_nodes failed",
        )
    }

    /// Get all edges.
    pub fn edges(&self) -> Result<Vec<Edge>> {
        let mut ptr: *mut idax_sys::IdaxGraphEdge = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { idax_sys::idax_graph_edges(self.handle, &mut ptr, &mut count) };
        if rc != 0 {
            return Err(error::consume_last_error("Graph::edges failed"));
        }
        let out = if ptr.is_null() || count == 0 {
            Vec::new()
        } else {
            let raw = unsafe { std::slice::from_raw_parts(ptr, count) };
            raw.iter()
                .map(|e| Edge {
                    source: e.source,
                    target: e.target,
                })
                .collect()
        };
        if !ptr.is_null() {
            unsafe { idax_sys::idax_graph_free_edges(ptr) };
        }
        Ok(out)
    }

    /// Check if a path exists from `source` to `target`.
    pub fn path_exists(&self, source: NodeId, target: NodeId) -> bool {
        unsafe { idax_sys::idax_graph_path_exists(self.handle, source, target) != 0 }
    }

    // ── Group operations ────────────────────────────────────────────────

    /// Create a group containing the given nodes.
    pub fn create_group(&mut self, nodes: &[NodeId]) -> Result<NodeId> {
        let mut out: NodeId = -1;
        let rc = unsafe {
            idax_sys::idax_graph_create_group(self.handle, nodes.as_ptr(), nodes.len(), &mut out)
        };
        if rc != 0 {
            return Err(error::consume_last_error("Graph::create_group failed"));
        }
        Ok(out)
    }

    /// Delete a group node but keep its member nodes.
    pub fn delete_group(&mut self, group: NodeId) -> Status {
        let rc = unsafe { idax_sys::idax_graph_delete_group(self.handle, group) };
        error::int_to_status(rc, "Graph::delete_group failed")
    }

    /// Expand (show contents) or collapse (hide contents) a group.
    pub fn set_group_expanded(&mut self, group: NodeId, expanded: bool) -> Status {
        let rc =
            unsafe { idax_sys::idax_graph_set_group_expanded(self.handle, group, expanded as i32) };
        error::int_to_status(rc, "Graph::set_group_expanded failed")
    }

    /// Check if a node is a group node.
    pub fn is_group(&self, node: NodeId) -> bool {
        unsafe { idax_sys::idax_graph_is_group(self.handle, node) != 0 }
    }

    /// Check if a group node is collapsed.
    pub fn is_collapsed(&self, group: NodeId) -> bool {
        unsafe { idax_sys::idax_graph_is_collapsed(self.handle, group) != 0 }
    }

    /// Get the member nodes of a group.
    pub fn group_members(&self, group: NodeId) -> Result<Vec<NodeId>> {
        collect_node_ids(
            |out, count| unsafe {
                idax_sys::idax_graph_group_members(self.handle, group, out, count)
            },
            "Graph::group_members failed",
        )
    }

    // ── Layout ──────────────────────────────────────────────────────────

    /// Set the layout algorithm and recompute.
    pub fn set_layout(&mut self, layout: Layout) -> Status {
        let rc = unsafe { idax_sys::idax_graph_set_layout(self.handle, layout as i32) };
        error::int_to_status(rc, "Graph::set_layout failed")
    }

    /// Return the currently selected layout algorithm.
    pub fn current_layout(&self) -> Layout {
        layout_from_i32(unsafe { idax_sys::idax_graph_current_layout(self.handle) })
    }

    /// Recompute the current layout.
    pub fn redo_layout(&mut self) -> Status {
        let rc = unsafe { idax_sys::idax_graph_redo_layout(self.handle) };
        error::int_to_status(rc, "Graph::redo_layout failed")
    }

    /// Clear all nodes and edges.
    pub fn clear(&mut self) -> Status {
        let rc = unsafe { idax_sys::idax_graph_clear(self.handle) };
        error::int_to_status(rc, "Graph::clear failed")
    }

    /// Get the underlying opaque handle (for advanced interop).
    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Graph {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { idax_sys::idax_graph_free(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for Graph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Graph(nodes={}, visible={})",
            self.total_node_count(),
            self.visible_node_count()
        )
    }
}

fn layout_from_i32(v: i32) -> Layout {
    match v {
        0 => Layout::None,
        1 => Layout::Digraph,
        2 => Layout::Tree,
        3 => Layout::Circle,
        4 => Layout::PolarTree,
        5 => Layout::Orthogonal,
        6 => Layout::RadialTree,
        _ => Layout::Digraph,
    }
}

fn collect_node_ids<F>(mut f: F, fallback: &str) -> Result<Vec<NodeId>>
where
    F: FnMut(*mut *mut NodeId, *mut usize) -> i32,
{
    let mut ptr: *mut NodeId = std::ptr::null_mut();
    let mut count: usize = 0;
    let rc = f(&mut ptr, &mut count);
    if rc != 0 {
        return Err(error::consume_last_error(fallback));
    }
    let out = if ptr.is_null() || count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr, count) }.to_vec()
    };
    if !ptr.is_null() {
        unsafe { idax_sys::idax_graph_free_node_ids(ptr) };
    }
    Ok(out)
}

// ── Graph viewer ────────────────────────────────────────────────────────

/// Callback interface for graph events.
pub trait GraphCallback: Send {
    fn on_refresh(&mut self, _graph: &mut Graph) -> bool {
        false
    }
    fn on_node_text(&mut self, _node: NodeId) -> Option<String> {
        None
    }
    fn on_node_color(&mut self, _node: NodeId) -> u32 {
        0xFFFF_FFFF
    }
    fn on_clicked(&mut self, _node: NodeId) -> bool {
        false
    }
    fn on_double_clicked(&mut self, _node: NodeId) -> bool {
        false
    }
    fn on_hint(&mut self, _node: NodeId) -> Option<String> {
        None
    }
    fn on_creating_group(&mut self, _nodes: &[NodeId]) -> bool {
        true
    }
    fn on_destroyed(&mut self) {}
}

struct GraphCallbackContext {
    callback: Box<dyn GraphCallback>,
}

thread_local! {
    static NODE_TEXT_TLS: RefCell<Option<CString>> = const { RefCell::new(None) };
    static HINT_TLS: RefCell<Option<CString>> = const { RefCell::new(None) };
}

unsafe extern "C" fn cb_on_refresh(context: *mut c_void, graph: *mut c_void) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    let mut g = ManuallyDrop::new(Graph { handle: graph });
    if ctx.callback.on_refresh(&mut g) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn cb_on_node_text(
    context: *mut c_void,
    node: i32,
    out_text: *mut *mut c_char,
) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    match ctx.callback.on_node_text(node) {
        Some(text) => {
            let c_text = match CString::new(text) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            NODE_TEXT_TLS.with(|slot| {
                *slot.borrow_mut() = Some(c_text);
                if let Some(stored) = slot.borrow().as_ref() {
                    unsafe { *out_text = stored.as_ptr() as *mut c_char };
                }
            });
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn cb_on_node_color(context: *mut c_void, node: i32) -> u32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    ctx.callback.on_node_color(node)
}

unsafe extern "C" fn cb_on_clicked(context: *mut c_void, node: i32) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    if ctx.callback.on_clicked(node) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn cb_on_double_clicked(context: *mut c_void, node: i32) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    if ctx.callback.on_double_clicked(node) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn cb_on_hint(
    context: *mut c_void,
    node: i32,
    out_hint: *mut *mut c_char,
) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    match ctx.callback.on_hint(node) {
        Some(hint) => {
            let c_hint = match CString::new(hint) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            HINT_TLS.with(|slot| {
                *slot.borrow_mut() = Some(c_hint);
                if let Some(stored) = slot.borrow().as_ref() {
                    unsafe { *out_hint = stored.as_ptr() as *mut c_char };
                }
            });
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn cb_on_creating_group(
    context: *mut c_void,
    nodes: *const i32,
    count: usize,
) -> i32 {
    let ctx = unsafe { &mut *(context as *mut GraphCallbackContext) };
    let members = if nodes.is_null() || count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(nodes, count) }
    };
    if ctx.callback.on_creating_group(members) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn cb_on_destroyed(context: *mut c_void) {
    let mut boxed = unsafe { Box::from_raw(context as *mut GraphCallbackContext) };
    boxed.callback.on_destroyed();
}

/// Create and display a graph viewer window.
pub fn show_graph(
    title: &str,
    graph: &mut Graph,
    callback: Option<Box<dyn GraphCallback>>,
) -> Status {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;

    if let Some(callback) = callback {
        let ctx = Box::new(GraphCallbackContext { callback });
        let context_ptr = Box::into_raw(ctx) as *mut c_void;
        let callbacks = idax_sys::IdaxGraphCallbacks {
            context: context_ptr,
            on_refresh: Some(cb_on_refresh),
            on_node_text: Some(cb_on_node_text),
            on_node_color: Some(cb_on_node_color),
            on_clicked: Some(cb_on_clicked),
            on_double_clicked: Some(cb_on_double_clicked),
            on_hint: Some(cb_on_hint),
            on_creating_group: Some(cb_on_creating_group),
            on_destroyed: Some(cb_on_destroyed),
        };

        let rc =
            unsafe { idax_sys::idax_graph_show_graph(c_title.as_ptr(), graph.handle, &callbacks) };
        if rc != 0 {
            unsafe { drop(Box::from_raw(context_ptr as *mut GraphCallbackContext)) };
        }
        error::int_to_status(rc, "graph::show_graph failed")
    } else {
        let rc = unsafe {
            idax_sys::idax_graph_show_graph(c_title.as_ptr(), graph.handle, std::ptr::null())
        };
        error::int_to_status(rc, "graph::show_graph failed")
    }
}

/// Refresh a graph viewer by title.
pub fn refresh_graph(title: &str) -> Status {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;
    let rc = unsafe { idax_sys::idax_graph_refresh_graph(c_title.as_ptr()) };
    error::int_to_status(rc, "graph::refresh_graph failed")
}

/// Check whether a graph viewer with this title exists.
pub fn has_graph_viewer(title: &str) -> Result<bool> {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;
    let mut out: i32 = 0;
    let rc = unsafe { idax_sys::idax_graph_has_graph_viewer(c_title.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error("graph::has_graph_viewer failed"));
    }
    Ok(out != 0)
}

/// Check whether a graph viewer is currently visible.
pub fn is_graph_viewer_visible(title: &str) -> Result<bool> {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;
    let mut out: i32 = 0;
    let rc = unsafe { idax_sys::idax_graph_is_graph_viewer_visible(c_title.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(error::consume_last_error(
            "graph::is_graph_viewer_visible failed",
        ));
    }
    Ok(out != 0)
}

/// Activate/focus a graph viewer by title.
pub fn activate_graph_viewer(title: &str) -> Status {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;
    let rc = unsafe { idax_sys::idax_graph_activate_graph_viewer(c_title.as_ptr()) };
    error::int_to_status(rc, "graph::activate_graph_viewer failed")
}

/// Close a graph viewer by title.
pub fn close_graph_viewer(title: &str) -> Status {
    let c_title = CString::new(title).map_err(|_| Error::validation("invalid graph title"))?;
    let rc = unsafe { idax_sys::idax_graph_close_graph_viewer(c_title.as_ptr()) };
    error::int_to_status(rc, "graph::close_graph_viewer failed")
}

// ── Flow chart convenience ──────────────────────────────────────────────

/// Block type in a flow chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BlockType {
    Normal = 0,
    IndirectJump = 1,
    Return = 2,
    ConditionalReturn = 3,
    NoReturn = 4,
    ExternalNoReturn = 5,
    External = 6,
    Error = 7,
}

/// A basic block in a flow chart.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: Address,
    pub end: Address,
    pub block_type: BlockType,
    pub successors: Vec<i32>,
    pub predecessors: Vec<i32>,
}

/// Helper to convert a raw block type integer to [`BlockType`].
fn block_type_from_i32(v: i32) -> BlockType {
    match v {
        0 => BlockType::Normal,
        1 => BlockType::IndirectJump,
        2 => BlockType::Return,
        3 => BlockType::ConditionalReturn,
        4 => BlockType::NoReturn,
        5 => BlockType::ExternalNoReturn,
        6 => BlockType::External,
        7 => BlockType::Error,
        _ => BlockType::Normal,
    }
}

/// Create a flow chart for the function at the given address.
///
/// Returns a list of [`BasicBlock`] entries describing the function's
/// control flow graph.
pub fn flowchart(function_address: Address) -> Result<Vec<BasicBlock>> {
    let mut count: usize = 0;
    let mut blocks_ptr: *mut idax_sys::IdaxBasicBlock = std::ptr::null_mut();
    let rc =
        unsafe { idax_sys::idax_graph_flowchart(function_address, &mut blocks_ptr, &mut count) };
    if rc != 0 {
        return Err(error::consume_last_error("graph::flowchart failed"));
    }
    let mut blocks = Vec::with_capacity(count);
    if !blocks_ptr.is_null() && count > 0 {
        let raw_blocks = unsafe { std::slice::from_raw_parts(blocks_ptr, count) };
        for raw in raw_blocks {
            let successors = if raw.successors.is_null() || raw.successor_count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(raw.successors, raw.successor_count).to_vec() }
            };
            let predecessors = if raw.predecessors.is_null() || raw.predecessor_count == 0 {
                Vec::new()
            } else {
                unsafe {
                    std::slice::from_raw_parts(raw.predecessors, raw.predecessor_count).to_vec()
                }
            };
            blocks.push(BasicBlock {
                start: raw.start,
                end: raw.end,
                block_type: block_type_from_i32(raw.type_),
                successors,
                predecessors,
            });
        }
        unsafe { idax_sys::idax_graph_flowchart_free(blocks_ptr, count) };
    }
    Ok(blocks)
}

/// Create a flow chart for a set of address ranges.
pub fn flowchart_for_ranges(ranges: &[Range]) -> Result<Vec<BasicBlock>> {
    let raw_ranges: Vec<idax_sys::IdaxAddressRange> = ranges
        .iter()
        .map(|r| idax_sys::IdaxAddressRange {
            start: r.start,
            end: r.end,
        })
        .collect();

    let mut count: usize = 0;
    let mut blocks_ptr: *mut idax_sys::IdaxBasicBlock = std::ptr::null_mut();
    let rc = unsafe {
        idax_sys::idax_graph_flowchart_for_ranges(
            raw_ranges.as_ptr(),
            raw_ranges.len(),
            &mut blocks_ptr,
            &mut count,
        )
    };
    if rc != 0 {
        return Err(error::consume_last_error(
            "graph::flowchart_for_ranges failed",
        ));
    }

    let mut blocks = Vec::with_capacity(count);
    if !blocks_ptr.is_null() && count > 0 {
        let raw_blocks = unsafe { std::slice::from_raw_parts(blocks_ptr, count) };
        for raw in raw_blocks {
            let successors = if raw.successors.is_null() || raw.successor_count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(raw.successors, raw.successor_count).to_vec() }
            };
            let predecessors = if raw.predecessors.is_null() || raw.predecessor_count == 0 {
                Vec::new()
            } else {
                unsafe {
                    std::slice::from_raw_parts(raw.predecessors, raw.predecessor_count).to_vec()
                }
            };
            blocks.push(BasicBlock {
                start: raw.start,
                end: raw.end,
                block_type: block_type_from_i32(raw.type_),
                successors,
                predecessors,
            });
        }
        unsafe { idax_sys::idax_graph_flowchart_free(blocks_ptr, count) };
    }

    Ok(blocks)
}
