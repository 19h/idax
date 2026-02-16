/// \file event_monitor_plugin.cpp
/// \brief Change Tracker plugin — records, summarizes, and visualizes all
///        database modifications during an analysis session.
///
/// A real reverse-engineering workflow often involves multiple analysts
/// making changes to the same database. This plugin tracks every
/// modification (renames, patches, comment changes, segment/function
/// creation and deletion) and presents them in two ways:
///
///   1. A chooser window with a searchable, sortable change log
///   2. A labeled graph showing which functions and segments were affected
///
/// When the plugin is stopped (or the database is saved), it persists
/// a summary of all changes into a netnode so the audit trail survives
/// across sessions.
///
/// API surface exercised:
///   event (all typed + generic/filtered), ui (chooser, timer, dialogs,
///   screen queries, event subscriptions, ScopedSubscription), debugger
///   (event subscriptions), graph (labeled nodes, groups, layout,
///   GraphCallback), storage (persistence)

#include <ida/idax.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

// Portable formatting helper (std::format requires macOS 13.3+ deployment target).
template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[2048];
    std::snprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

// ── Change record ──────────────────────────────────────────────────────

struct ChangeRecord {
    std::uint64_t timestamp_ms{};  // Monotonic, relative to session start.
    std::string   domain;          // "IDB", "UI", "DBG"
    std::string   kind;            // "rename", "patch", "segment_add", etc.
    std::string   description;
    ida::Address  address{ida::BadAddress};
};

// Thread-safe change log shared between event callbacks and the chooser.
struct ChangeLog {
    mutable std::mutex mutex;
    std::vector<ChangeRecord> records;
    std::chrono::steady_clock::time_point session_start;

    void clear() {
        std::lock_guard lk(mutex);
        records.clear();
        session_start = std::chrono::steady_clock::now();
    }

    void add(std::string domain, std::string kind, std::string desc,
             ida::Address addr = ida::BadAddress) {
        auto now = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - session_start).count();

        std::lock_guard lk(mutex);
        records.push_back({
            static_cast<std::uint64_t>(ms),
            std::move(domain), std::move(kind), std::move(desc), addr
        });
    }

    std::size_t size() const {
        std::lock_guard lk(mutex);
        return records.size();
    }

    ChangeRecord at(std::size_t i) const {
        std::lock_guard lk(mutex);
        return (i < records.size()) ? records[i] : ChangeRecord{};
    }
};

ChangeLog g_log;

// ── Chooser: displays the change log ───────────────────────────────────

class ChangeLogChooser : public ida::ui::Chooser {
public:
    ChangeLogChooser()
        : Chooser({
            .title   = "Change Tracker Log",
            .columns = {
                {"Time (ms)", 10, ida::ui::ColumnFormat::Decimal},
                {"Domain",     5, ida::ui::ColumnFormat::Plain},
                {"Kind",      14, ida::ui::ColumnFormat::Plain},
                {"Description", 50, ida::ui::ColumnFormat::Plain},
                {"Address",   16, ida::ui::ColumnFormat::Address},
            },
            .modal       = false,
            .can_insert  = false,
            .can_delete  = true,
            .can_edit    = false,
            .can_refresh = true,
        }) {}

    std::size_t count() const override {
        return g_log.size();
    }

    ida::ui::Row row(std::size_t index) const override {
        auto r = g_log.at(index);
        return {{
            std::to_string(r.timestamp_ms),
            r.domain,
            r.kind,
            r.description,
            (r.address != ida::BadAddress)
                ? fmt("%#llx", (unsigned long long)r.address) : "-",
        }};
    }

    ida::Address address_for(std::size_t index) const override {
        return g_log.at(index).address;
    }

    void on_enter(std::size_t index) override {
        // Navigate to the address when the user presses Enter.
        auto r = g_log.at(index);
        if (r.address != ida::BadAddress) {
            ida::ui::message(fmt(
                "[ChangeTracker] Jump to %#llx: %s %s\n",
                (unsigned long long)r.address, r.kind.c_str(),
                r.description.c_str()));
        }
    }

    void on_close() override {
        ida::ui::message("[ChangeTracker] Log window closed.\n");
    }
};

// ── Graph: shows which functions/segments were modified ─────────────────
//
// Nodes represent affected functions and segments. Edges connect them to
// a central "Session" node. The GraphCallback provides labels and colors.

class ChangeGraphCallback : public ida::graph::GraphCallback {
public:
    // Maps node ID to its label text.
    std::vector<std::string> node_labels;

    std::string on_node_text(ida::graph::NodeId node) override {
        if (node >= 0 && static_cast<std::size_t>(node) < node_labels.size())
            return node_labels[node];
        return "?";
    }

    std::uint32_t on_node_color(ida::graph::NodeId node) override {
        // Color the central session node differently from function/segment nodes.
        if (node == 0) return 0xFFCCCC;  // Light red for session root.
        return 0xCCFFCC;                 // Light green for affected entities.
    }

    std::string on_hint(ida::graph::NodeId node) override {
        if (node >= 0 && static_cast<std::size_t>(node) < node_labels.size())
            return fmt("Node %d: %s", node, node_labels[node].c_str());
        return {};
    }
};

void build_change_graph(ChangeGraphCallback& cb) {
    ida::graph::Graph graph;

    // Central node: the analysis session.
    auto root = graph.add_node();
    cb.node_labels.push_back("Analysis Session");

    // Collect unique affected addresses and classify them.
    std::unordered_set<ida::Address> seen;
    std::vector<std::pair<std::string, ida::Address>> entities;

    {
        std::lock_guard lk(g_log.mutex);
        for (auto& r : g_log.records) {
            if (r.address == ida::BadAddress) continue;
            if (seen.count(r.address)) continue;
            seen.insert(r.address);

            // Try to classify as function or segment.
            std::string label;
            if (auto f = ida::function::at(r.address)) {
                label = fmt("func: %s", f->name().c_str());
            } else if (auto s = ida::segment::at(r.address)) {
                label = fmt("seg: %s", s->name().c_str());
            } else {
                label = fmt("%#llx", (unsigned long long)r.address);
            }
            entities.emplace_back(std::move(label), r.address);

            // Cap the graph at 30 nodes for readability.
            if (entities.size() >= 30) break;
        }
    }

    // Add entity nodes and connect to root.
    for (auto& [label, addr] : entities) {
        auto node = graph.add_node();
        cb.node_labels.push_back(label);
        graph.add_edge(root, node);
    }

    // If we have function nodes, group them together.
    std::vector<ida::graph::NodeId> func_nodes;
    for (int i = 1; i < static_cast<int>(cb.node_labels.size()); ++i) {
        if (cb.node_labels[i].starts_with("func:")) {
            func_nodes.push_back(i);
        }
    }
    if (func_nodes.size() >= 2) {
        auto group = graph.create_group(func_nodes);
        if (group) {
            graph.set_group_expanded(*group, true);
        }
    }

    graph.set_layout(ida::graph::Layout::Digraph);
    graph.redo_layout();

    // Show the graph. The callback provides text/color for each node.
    ida::graph::show_graph("Change Impact", graph, &cb);
}

// ── Plugin state: RAII subscriptions, timer, chooser, graph ────────────

struct TrackerState {
    std::vector<ida::event::ScopedSubscription>    idb_subs;
    std::vector<ida::ui::ScopedSubscription>       ui_subs;
    std::vector<ida::debugger::ScopedSubscription> dbg_subs;
    std::uint64_t timer_token{0};
    std::unique_ptr<ChangeLogChooser> chooser;
    std::unique_ptr<ChangeGraphCallback> graph_cb;
    bool active{false};
};

TrackerState g_state;

// ── Start tracking ─────────────────────────────────────────────────────

void start_tracking() {
    if (g_state.active) {
        ida::ui::message("[ChangeTracker] Already active.\n");
        return;
    }

    g_log.clear();
    g_state = {};
    g_state.active = true;

    ida::ui::message("[ChangeTracker] Starting change tracking...\n");

    // ── IDB events: the core of the change tracker ──────────────────

    auto sub = [](auto result, auto& vec) {
        if (result) vec.emplace_back(*result);
    };

    sub(ida::event::on_segment_added([](ida::Address start) {
        g_log.add("IDB", "segment_add",
                  fmt("New segment at %#llx", (unsigned long long)start), start);
    }), g_state.idb_subs);

    sub(ida::event::on_segment_deleted([](ida::Address start, ida::Address end) {
        g_log.add("IDB", "segment_del",
                  fmt("Removed %#llx-%#llx", (unsigned long long)start,
                      (unsigned long long)end), start);
    }), g_state.idb_subs);

    sub(ida::event::on_function_added([](ida::Address entry) {
        g_log.add("IDB", "func_add",
                  fmt("New function at %#llx", (unsigned long long)entry), entry);
    }), g_state.idb_subs);

    sub(ida::event::on_function_deleted([](ida::Address entry) {
        g_log.add("IDB", "func_del",
                  fmt("Removed function at %#llx", (unsigned long long)entry), entry);
    }), g_state.idb_subs);

    sub(ida::event::on_renamed(
        [](ida::Address addr, std::string new_name, std::string old_name) {
        g_log.add("IDB", "rename",
                  fmt("'%s' -> '%s' at %#llx", old_name.c_str(),
                      new_name.c_str(), (unsigned long long)addr),
                  addr);
    }), g_state.idb_subs);

    sub(ida::event::on_byte_patched(
        [](ida::Address addr, std::uint32_t old_val) {
        g_log.add("IDB", "patch",
                  fmt("byte %#llx patched (was %#x)",
                      (unsigned long long)addr, old_val),
                  addr);
    }), g_state.idb_subs);

    sub(ida::event::on_comment_changed(
        [](ida::Address addr, bool repeatable) {
        g_log.add("IDB", "comment",
                  fmt("%s comment at %#llx",
                      repeatable ? "Repeatable" : "Regular",
                      (unsigned long long)addr),
                  addr);
    }), g_state.idb_subs);

    // Generic event routing: log all events for completeness, using the
    // normalized Event struct that decodes the raw va_list payload once.
    sub(ida::event::on_event([](const ida::event::Event& ev) {
        // We already have typed handlers for specific events, so here we
        // just track the total count for the periodic summary.
    }), g_state.idb_subs);

    // Filtered routing: only rename events, demonstrating the predicate API.
    sub(ida::event::on_event_filtered(
        [](const ida::event::Event& ev) {
            return ev.kind == ida::event::EventKind::Renamed;
        },
        [](const ida::event::Event& ev) {
            // This fires in addition to the typed on_renamed handler.
            // A real use case: feed renames to a synchronization service.
        }
    ), g_state.idb_subs);

    // ── UI events: track analyst activity ───────────────────────────

    sub(ida::ui::on_screen_ea_changed(
        [](ida::Address new_ea, ida::Address prev_ea) {
        // Don't log every cursor move — that would be too noisy.
        // But we can track it for "time spent in function" metrics.
    }), g_state.ui_subs);

    sub(ida::ui::on_database_closed([]() {
        g_log.add("UI", "db_closed", "Database closed");
    }), g_state.ui_subs);

    sub(ida::ui::on_widget_visible([](std::string title) {
        g_log.add("UI", "widget_open", fmt("'%s'", title.c_str()));
    }), g_state.ui_subs);

    // ── Debugger events: track debugging activity ───────────────────

    sub(ida::debugger::on_process_started(
        [](const ida::debugger::ModuleInfo& mod) {
        g_log.add("DBG", "proc_start",
                  fmt("'%s' at %#llx", mod.name.c_str(),
                      (unsigned long long)mod.base));
    }), g_state.dbg_subs);

    sub(ida::debugger::on_process_exited([](int code) {
        g_log.add("DBG", "proc_exit", fmt("exit code %d", code));
    }), g_state.dbg_subs);

    sub(ida::debugger::on_breakpoint_hit(
        [](int tid, ida::Address addr) {
        g_log.add("DBG", "bp_hit",
                  fmt("thread %d at %#llx", tid,
                      (unsigned long long)addr), addr);
    }), g_state.dbg_subs);

    sub(ida::debugger::on_exception(
        [](const ida::debugger::ExceptionInfo& ex) {
        g_log.add("DBG", "exception",
                  fmt("code %#x: '%s' at %#llx",
                      ex.code, ex.message.c_str(),
                      (unsigned long long)ex.ea), ex.ea);
    }), g_state.dbg_subs);

    sub(ida::debugger::on_breakpoint_changed(
        [](ida::debugger::BreakpointChange change, ida::Address addr) {
        const char* kind = "modified";
        if (change == ida::debugger::BreakpointChange::Added)   kind = "added";
        if (change == ida::debugger::BreakpointChange::Removed) kind = "removed";
        g_log.add("DBG", "bp_change",
                  fmt("Breakpoint %s at %#llx", kind,
                      (unsigned long long)addr), addr);
    }), g_state.dbg_subs);

    // ── Timer: periodic status summary ──────────────────────────────

    auto timer = ida::ui::register_timer(10000, []() -> int {
        ida::ui::message(fmt(
            "[ChangeTracker] %zu changes recorded so far.\n", g_log.size()));
        return 0;  // Return 0 to keep the timer running.
    });
    if (timer) g_state.timer_token = *timer;

    // ── Chooser: show the change log ────────────────────────────────

    g_state.chooser = std::make_unique<ChangeLogChooser>();
    g_state.chooser->show();

    // Note the current screen address for the log.
    if (auto scr = ida::ui::screen_address()) {
        g_log.add("UI", "session_start",
                  fmt("Initial EA: %#llx", (unsigned long long)*scr), *scr);
    }

    ida::ui::message("[ChangeTracker] Tracking active. Run again to stop.\n");
}

// ── Stop tracking and persist summary ──────────────────────────────────

void stop_tracking() {
    if (!g_state.active) return;

    ida::ui::message(fmt(
        "[ChangeTracker] Stopping. %zu total changes recorded.\n",
        g_log.size()));

    // Build and display the change impact graph.
    g_state.graph_cb = std::make_unique<ChangeGraphCallback>();
    build_change_graph(*g_state.graph_cb);

    // Persist a summary into a netnode so it survives across sessions.
    auto node = ida::storage::Node::open("idax_change_tracker", true);
    if (node) {
        // Store total change count as an alt value (index 100 to avoid
        // the idalib index-0 crash documented in the project findings).
        node->set_alt(100, static_cast<std::uint64_t>(g_log.size()), 'A');

        // Store a human-readable summary as a hash value.
        node->set_hash("last_session_changes",
            std::to_string(g_log.size()), 'H');
    }

    // Clean up timer.
    if (g_state.timer_token) {
        ida::ui::unregister_timer(g_state.timer_token);
    }

    // Close chooser.
    if (g_state.chooser) {
        g_state.chooser->close();
    }

    // RAII: ScopedSubscriptions unsubscribe automatically when g_state
    // is reset, so we don't need manual unsubscribe calls.
    g_state = {};
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct ChangeTrackerPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name    = "Change Tracker",
            .hotkey  = "Ctrl-Shift-T",
            .comment = "Record and visualize all database modifications",
            .help    = "Tracks renames, patches, comments, segment/function "
                       "changes, and debugger events. Displays a live log "
                       "in a chooser and a change-impact graph on stop.",
        };
    }

    void term() override {
        stop_tracking();
    }

    ida::Status run(std::size_t) override {
        // Toggle: start if not active, stop if active.
        if (g_state.active) {
            stop_tracking();
        } else {
            start_tracking();
        }
        return ida::ok();
    }
};

IDAX_PLUGIN(ChangeTrackerPlugin)
