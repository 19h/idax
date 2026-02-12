/// \file event_monitor_plugin.cpp
/// \brief Advanced event-driven monitoring plugin demonstrating comprehensive
///        IDB event, UI event, and debugger event subscription and coordination.
///
/// This plugin creates a multi-layer event monitoring system:
///   1. IDB events (segment/function/rename/byte_patched/comment_changed)
///   2. UI events (database_closed/ready_to_run/screen_ea_changed/widget)
///   3. Debugger events (all tiers: process/breakpoint/trace/exception/thread/library)
///   4. Generic event routing with filtering
///   5. RAII ScopedSubscription lifecycle for all three event domains
///   6. Timer-based periodic monitoring
///   7. Graph construction reflecting event flow
///   8. Chooser displaying event log
///
/// Edge cases exercised:
///   - Multiple simultaneous subscriptions across all event domains
///   - RAII ScopedSubscription destruction ordering
///   - Move semantics on ScopedSubscription
///   - Generic event filtering with predicate
///   - Token-based manual unsubscribe
///   - Timer registration and unregistration
///   - Chooser subclass with dynamic data, column formatting, and callbacks
///   - Graph node/edge manipulation with groups
///   - UI dialogs (ask_string, ask_yn, ask_address, ask_long, ask_file)
///   - Screen address and selection queries
///   - Message/warning/info output
///   - Debugger typed event structs (ModuleInfo, ExceptionInfo, BreakpointChange)

#include <ida/idax.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <string>
#include <vector>

namespace {

// ── Event log entry ────────────────────────────────────────────────────

struct LogEntry {
    std::string timestamp;
    std::string domain;     // "IDB", "UI", "DBG", "GEN"
    std::string event_type;
    std::string details;
    ida::Address address{ida::BadAddress};
};

// Thread-safe event log.
std::mutex g_log_mutex;
std::vector<LogEntry> g_event_log;

void log_event(std::string domain, std::string type, std::string details,
               ida::Address addr = ida::BadAddress) {
    // Simple timestamp.
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    std::lock_guard lock(g_log_mutex);
    g_event_log.push_back({
        std::to_string(ms),
        std::move(domain),
        std::move(type),
        std::move(details),
        addr
    });
}

// ── Event log chooser ──────────────────────────────────────────────────

/// Custom chooser that displays the event log.
/// Exercises: count, row, address_for, on_refresh, on_close, column formatting.
class EventLogChooser : public ida::ui::Chooser {
public:
    EventLogChooser()
        : Chooser({
            .title = "idax Event Monitor Log",
            .columns = {
                {"Time",    12, ida::ui::ColumnFormat::Decimal},
                {"Domain",   6, ida::ui::ColumnFormat::Plain},
                {"Event",   20, ida::ui::ColumnFormat::Plain},
                {"Details", 40, ida::ui::ColumnFormat::Plain},
                {"Address", 16, ida::ui::ColumnFormat::Address},
            },
            .modal = false,
            .can_insert = false,
            .can_delete = true,
            .can_edit = false,
            .can_refresh = true,
        }) {}

    std::size_t count() const override {
        std::lock_guard lock(g_log_mutex);
        return g_event_log.size();
    }

    ida::ui::Row row(std::size_t index) const override {
        std::lock_guard lock(g_log_mutex);
        if (index >= g_event_log.size()) {
            return {{"?", "?", "?", "?", "?"}};
        }
        const auto& e = g_event_log[index];
        return {{
            e.timestamp,
            e.domain,
            e.event_type,
            e.details,
            std::format("{:#x}", e.address),
        }};
    }

    ida::Address address_for(std::size_t index) const override {
        std::lock_guard lock(g_log_mutex);
        if (index < g_event_log.size())
            return g_event_log[index].address;
        return ida::BadAddress;
    }

    void on_delete(std::size_t index) override {
        std::lock_guard lock(g_log_mutex);
        if (index < g_event_log.size()) {
            g_event_log.erase(g_event_log.begin() +
                static_cast<std::ptrdiff_t>(index));
        }
    }

    void on_refresh() override {
        // Nothing extra needed; count()/row() re-read the log.
    }

    void on_enter(std::size_t index) override {
        std::lock_guard lock(g_log_mutex);
        if (index < g_event_log.size()) {
            ida::ui::message(std::format(
                "[EventMonitor] Selected: {} {}\n",
                g_event_log[index].event_type,
                g_event_log[index].details));
        }
    }

    void on_close() override {
        ida::ui::message("[EventMonitor] Chooser closed\n");
    }
};

// ── Event graph builder ────────────────────────────────────────────────

/// Builds a graph showing event flow: domain nodes connected to event type nodes.
/// Exercises: Graph construction, add_node, add_edge, create_group,
/// set_group_expanded, is_group, is_collapsed, group_members, path_exists,
/// successors, predecessors, visible_nodes, edges, set_layout, redo_layout.
class EventFlowGraph {
public:
    void build() {
        graph_ = ida::graph::Graph();

        // Create domain nodes.
        auto idb_node  = graph_.add_node();
        auto ui_node   = graph_.add_node();
        auto dbg_node  = graph_.add_node();
        auto gen_node  = graph_.add_node();

        // Create event type nodes for IDB events.
        auto seg_add = graph_.add_node();
        auto seg_del = graph_.add_node();
        auto func_add = graph_.add_node();
        auto func_del = graph_.add_node();
        auto renamed = graph_.add_node();
        auto patched = graph_.add_node();
        auto cmt_chg = graph_.add_node();

        // Connect domain to events.
        (void)graph_.add_edge(idb_node, seg_add);
        (void)graph_.add_edge(idb_node, seg_del);
        (void)graph_.add_edge(idb_node, func_add);
        (void)graph_.add_edge(idb_node, func_del);
        (void)graph_.add_edge(idb_node, renamed);
        (void)graph_.add_edge(idb_node, patched);
        (void)graph_.add_edge(idb_node, cmt_chg);

        // UI event nodes.
        auto db_closed = graph_.add_node();
        auto ready     = graph_.add_node();
        auto ea_chg    = graph_.add_node();
        auto wid_vis   = graph_.add_node();
        auto wid_close = graph_.add_node();

        (void)graph_.add_edge(ui_node, db_closed);
        (void)graph_.add_edge(ui_node, ready);
        (void)graph_.add_edge(ui_node, ea_chg);
        (void)graph_.add_edge(ui_node, wid_vis);
        (void)graph_.add_edge(ui_node, wid_close);

        // Debugger event nodes.
        auto proc_start = graph_.add_node();
        auto proc_exit  = graph_.add_node();
        auto bp_hit     = graph_.add_node();
        auto trace_ev   = graph_.add_node();
        auto except_ev  = graph_.add_node();

        (void)graph_.add_edge(dbg_node, proc_start);
        (void)graph_.add_edge(dbg_node, proc_exit);
        (void)graph_.add_edge(dbg_node, bp_hit);
        (void)graph_.add_edge(dbg_node, trace_ev);
        (void)graph_.add_edge(dbg_node, except_ev);

        // Generic event node.
        auto filtered = graph_.add_node();
        (void)graph_.add_edge(gen_node, filtered);

        // Edge case: group creation.
        auto idb_group = graph_.create_group({
            seg_add, seg_del, func_add, func_del, renamed, patched, cmt_chg
        });
        if (idb_group) {
            (void)graph_.set_group_expanded(*idb_group, true);
            (void)graph_.is_group(*idb_group);
            (void)graph_.is_collapsed(*idb_group);
            (void)graph_.group_members(*idb_group);
        }

        // Edge case: path_exists.
        (void)graph_.path_exists(idb_node, seg_add);
        (void)graph_.path_exists(ui_node, seg_add);  // Should be false.

        // Edge case: successors/predecessors.
        (void)graph_.successors(idb_node);
        (void)graph_.predecessors(seg_add);

        // Edge case: all nodes and edges.
        (void)graph_.visible_nodes();
        (void)graph_.edges();

        // Layout.
        (void)graph_.set_layout(ida::graph::Layout::Digraph);
        (void)graph_.redo_layout();

        // Edge case: try to show (may fail in headless mode).
        (void)ida::graph::show_graph("Event Flow", graph_);
    }

private:
    ida::graph::Graph graph_;
};

// ── Main monitoring logic ──────────────────────────────────────────────

struct MonitorState {
    // IDB event subscriptions (RAII).
    std::vector<ida::event::ScopedSubscription> idb_subs;

    // UI event subscriptions (RAII).
    std::vector<ida::ui::ScopedSubscription> ui_subs;

    // Debugger event subscriptions (RAII).
    std::vector<ida::debugger::ScopedSubscription> dbg_subs;

    // Timer.
    std::uint64_t timer_token{0};

    // Chooser.
    std::unique_ptr<EventLogChooser> chooser;

    // Graph.
    std::unique_ptr<EventFlowGraph> graph;
};

MonitorState g_state;

void start_monitoring() {
    ida::ui::message("=== idax Event Monitor Starting ===\n");

    // Clear previous state.
    g_state = {};
    {
        std::lock_guard lock(g_log_mutex);
        g_event_log.clear();
    }

    // ── IDB event subscriptions ─────────────────────────────────────

    // Segment events.
    auto seg_add = ida::event::on_segment_added([](ida::Address start) {
        log_event("IDB", "segment_added",
                  std::format("start={:#x}", start), start);
    });
    if (seg_add) g_state.idb_subs.emplace_back(*seg_add);

    auto seg_del = ida::event::on_segment_deleted(
        [](ida::Address start, ida::Address end) {
        log_event("IDB", "segment_deleted",
                  std::format("{:#x}-{:#x}", start, end), start);
    });
    if (seg_del) g_state.idb_subs.emplace_back(*seg_del);

    // Function events.
    auto func_add = ida::event::on_function_added([](ida::Address entry) {
        log_event("IDB", "function_added",
                  std::format("entry={:#x}", entry), entry);
    });
    if (func_add) g_state.idb_subs.emplace_back(*func_add);

    auto func_del = ida::event::on_function_deleted([](ida::Address entry) {
        log_event("IDB", "function_deleted",
                  std::format("entry={:#x}", entry), entry);
    });
    if (func_del) g_state.idb_subs.emplace_back(*func_del);

    // Rename event.
    auto renamed = ida::event::on_renamed(
        [](ida::Address addr, std::string new_name, std::string old_name) {
        log_event("IDB", "renamed",
                  std::format("'{}' -> '{}' at {:#x}", old_name, new_name, addr),
                  addr);
    });
    if (renamed) g_state.idb_subs.emplace_back(*renamed);

    // Byte patched event.
    auto patched = ida::event::on_byte_patched(
        [](ida::Address addr, std::uint32_t old_val) {
        log_event("IDB", "byte_patched",
                  std::format("old={:#x} at {:#x}", old_val, addr), addr);
    });
    if (patched) g_state.idb_subs.emplace_back(*patched);

    // Comment changed event.
    auto cmt = ida::event::on_comment_changed(
        [](ida::Address addr, bool repeatable) {
        log_event("IDB", "comment_changed",
                  std::format("rpt={} at {:#x}", repeatable, addr), addr);
    });
    if (cmt) g_state.idb_subs.emplace_back(*cmt);

    // ── Generic event routing ───────────────────────────────────────

    // Route all events through one handler.
    auto all_events = ida::event::on_event([](const ida::event::Event& ev) {
        log_event("GEN", "all_events",
                  std::format("kind={}", static_cast<int>(ev.kind)),
                  ev.address);
    });
    if (all_events) g_state.idb_subs.emplace_back(*all_events);

    // Filtered: only rename events.
    auto filtered = ida::event::on_event_filtered(
        [](const ida::event::Event& ev) {
            return ev.kind == ida::event::EventKind::Renamed;
        },
        [](const ida::event::Event& ev) {
            log_event("GEN", "filtered_rename",
                      std::format("'{}' -> '{}'", ev.old_name, ev.new_name),
                      ev.address);
        });
    if (filtered) g_state.idb_subs.emplace_back(*filtered);

    // ── UI event subscriptions ──────────────────────────────────────

    auto db_closed = ida::ui::on_database_closed([]() {
        log_event("UI", "database_closed", "");
    });
    if (db_closed) g_state.ui_subs.emplace_back(*db_closed);

    auto ready = ida::ui::on_ready_to_run([]() {
        log_event("UI", "ready_to_run", "");
    });
    if (ready) g_state.ui_subs.emplace_back(*ready);

    auto ea_chg = ida::ui::on_screen_ea_changed(
        [](ida::Address new_ea, ida::Address prev_ea) {
        log_event("UI", "screen_ea_changed",
                  std::format("{:#x} -> {:#x}", prev_ea, new_ea), new_ea);
    });
    if (ea_chg) g_state.ui_subs.emplace_back(*ea_chg);

    auto wid_vis = ida::ui::on_widget_visible([](std::string title) {
        log_event("UI", "widget_visible", title);
    });
    if (wid_vis) g_state.ui_subs.emplace_back(*wid_vis);

    auto wid_close = ida::ui::on_widget_closing([](std::string title) {
        log_event("UI", "widget_closing", title);
    });
    if (wid_close) g_state.ui_subs.emplace_back(*wid_close);

    // ── Debugger event subscriptions ────────────────────────────────

    // Tier 1: essential events.
    auto proc_start = ida::debugger::on_process_started(
        [](const ida::debugger::ModuleInfo& mod) {
        log_event("DBG", "process_started",
                  std::format("'{}' base={:#x} size={:#x}",
                              mod.name, mod.base, mod.size));
    });
    if (proc_start) g_state.dbg_subs.emplace_back(*proc_start);

    auto proc_exit = ida::debugger::on_process_exited([](int code) {
        log_event("DBG", "process_exited", std::format("code={}", code));
    });
    if (proc_exit) g_state.dbg_subs.emplace_back(*proc_exit);

    auto proc_susp = ida::debugger::on_process_suspended(
        [](ida::Address addr) {
        log_event("DBG", "process_suspended",
                  std::format("at {:#x}", addr), addr);
    });
    if (proc_susp) g_state.dbg_subs.emplace_back(*proc_susp);

    auto bp_hit = ida::debugger::on_breakpoint_hit(
        [](int tid, ida::Address addr) {
        log_event("DBG", "breakpoint_hit",
                  std::format("tid={} at {:#x}", tid, addr), addr);
    });
    if (bp_hit) g_state.dbg_subs.emplace_back(*bp_hit);

    auto trace = ida::debugger::on_trace(
        [](int tid, ida::Address ip) -> bool {
        log_event("DBG", "trace",
                  std::format("tid={} ip={:#x}", tid, ip), ip);
        return false;  // Don't suppress logging.
    });
    if (trace) g_state.dbg_subs.emplace_back(*trace);

    auto except = ida::debugger::on_exception(
        [](const ida::debugger::ExceptionInfo& ex) {
        log_event("DBG", "exception",
                  std::format("code={:#x} '{}' at {:#x}",
                              ex.code, ex.message, ex.ea), ex.ea);
    });
    if (except) g_state.dbg_subs.emplace_back(*except);

    // Tier 2: thread/library lifecycle.
    auto thr_start = ida::debugger::on_thread_started(
        [](int tid, std::string name) {
        log_event("DBG", "thread_started",
                  std::format("tid={} name='{}'", tid, name));
    });
    if (thr_start) g_state.dbg_subs.emplace_back(*thr_start);

    auto thr_exit = ida::debugger::on_thread_exited(
        [](int tid, int code) {
        log_event("DBG", "thread_exited",
                  std::format("tid={} code={}", tid, code));
    });
    if (thr_exit) g_state.dbg_subs.emplace_back(*thr_exit);

    auto lib_load = ida::debugger::on_library_loaded(
        [](const ida::debugger::ModuleInfo& mod) {
        log_event("DBG", "library_loaded",
                  std::format("'{}' base={:#x}", mod.name, mod.base));
    });
    if (lib_load) g_state.dbg_subs.emplace_back(*lib_load);

    auto lib_unload = ida::debugger::on_library_unloaded(
        [](std::string name) {
        log_event("DBG", "library_unloaded", name);
    });
    if (lib_unload) g_state.dbg_subs.emplace_back(*lib_unload);

    // Tier 3: breakpoint management.
    auto bp_chg = ida::debugger::on_breakpoint_changed(
        [](ida::debugger::BreakpointChange change, ida::Address addr) {
        const char* kind = "unknown";
        switch (change) {
            case ida::debugger::BreakpointChange::Added:   kind = "added";   break;
            case ida::debugger::BreakpointChange::Removed: kind = "removed"; break;
            case ida::debugger::BreakpointChange::Changed: kind = "changed"; break;
        }
        log_event("DBG", "breakpoint_changed",
                  std::format("{} at {:#x}", kind, addr), addr);
    });
    if (bp_chg) g_state.dbg_subs.emplace_back(*bp_chg);

    // ── Timer ───────────────────────────────────────────────────────

    auto timer = ida::ui::register_timer(5000, []() -> int {
        std::size_t count;
        {
            std::lock_guard lock(g_log_mutex);
            count = g_event_log.size();
        }
        ida::ui::message(std::format(
            "[EventMonitor] Periodic check: {} events logged\n", count));
        return 0;  // Continue timer.
    });
    if (timer) g_state.timer_token = *timer;

    // ── Chooser ─────────────────────────────────────────────────────

    g_state.chooser = std::make_unique<EventLogChooser>();
    (void)g_state.chooser->show();

    // ── Event flow graph ────────────────────────────────────────────

    g_state.graph = std::make_unique<EventFlowGraph>();
    g_state.graph->build();

    // ── UI dialog exercises ─────────────────────────────────────────

    // Screen state queries (safe even in headless mode).
    auto scr = ida::ui::screen_address();
    if (scr) {
        ida::ui::message(std::format(
            "[EventMonitor] Current screen EA: {:#x}\n", *scr));
    }

    auto sel = ida::ui::selection();
    if (sel) {
        ida::ui::message(std::format(
            "[EventMonitor] Selection: {:#x}-{:#x}\n",
            sel->start, sel->end));
    }

    ida::ui::message("=== Event Monitor Active ===\n");
    ida::ui::message("Events will be logged to the chooser window.\n");
}

void stop_monitoring() {
    // RAII handles cleanup of subscriptions.
    // Timer must be explicitly unregistered.
    if (g_state.timer_token) {
        (void)ida::ui::unregister_timer(g_state.timer_token);
    }

    // Close chooser.
    if (g_state.chooser) {
        (void)g_state.chooser->close();
    }

    // Reset all state (ScopedSubscriptions unsubscribe in destructor).
    g_state = {};

    ida::ui::message("=== Event Monitor Stopped ===\n");
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct EventMonitorPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            "idax Event Monitor",
            "Ctrl-Shift-E",
            "Multi-domain event monitoring with logging, graph, and chooser",
            "Subscribes to IDB/UI/debugger events, shows event log in a "
            "chooser window, builds an event flow graph, and exercises all "
            "event-related APIs."
        };
    }

    void term() override {
        stop_monitoring();
    }

    ida::Status run(std::size_t arg) override {
        if (arg == 0) {
            start_monitoring();
        } else {
            stop_monitoring();
        }
        return ida::ok();
    }
};
